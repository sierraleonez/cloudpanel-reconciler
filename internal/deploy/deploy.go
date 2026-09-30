// Package deploy owns the per-site reconcile flow: provision if missing, ensure
// a certificate, materialise the pinned commit, and activate it atomically.
package deploy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/almerandika/reconciler/internal/cloudpanel"
	"github.com/almerandika/reconciler/internal/config"
	"github.com/almerandika/reconciler/internal/gitops"
	"github.com/almerandika/reconciler/internal/sh"
	"github.com/almerandika/reconciler/internal/state"
)

type Action string

const (
	ActionNoop        Action = "noop"
	ActionProvisioned Action = "provisioned"
	ActionDeployed    Action = "deployed"
	ActionRolledBack  Action = "rolled-back"
	ActionBlocked     Action = "blocked"
)

type Outcome struct {
	Domain  string
	Action  Action
	FromSHA string
	ToSHA   string
	Notes   []string
	Err     error
}

func (o Outcome) Changed() bool { return o.Action != ActionNoop }

type Deployer struct {
	cfg    *config.Config
	cp     *cloudpanel.Client
	store  *state.Store
	dryRun bool
}

func New(cfg *config.Config, cp *cloudpanel.Client, store *state.Store, dryRun bool) *Deployer {
	return &Deployer{cfg: cfg, cp: cp, store: store, dryRun: dryRun}
}

// Reconcile brings one site to its manifest state.
func (d *Deployer) Reconcile(ctx context.Context, site *config.Site) Outcome {
	out := Outcome{Domain: site.Domain, Action: ActionNoop}

	if !d.cp.SiteExists(site) {
		if d.dryRun {
			out.Action = ActionBlocked
			out.Notes = append(out.Notes, "would provision site")
			return out
		}
		if err := d.provision(ctx, site); err != nil {
			out.Action = ActionBlocked
			out.Err = err
			return out
		}
		out.Action = ActionProvisioned
		out.Notes = append(out.Notes, "site created")
	}

	// Widening the PHP jail is idempotent and cheap, and a CloudPanel upgrade
	// can silently revert it, so re-assert rather than trusting provision time.
	if err := d.cp.WidenOpenBasedir(ctx, site); err != nil {
		out.Err = fmt.Errorf("open_basedir: %w", err)
		out.Action = ActionBlocked
		return out
	}

	if note, err := d.ensureCertificate(ctx, site); err != nil {
		// A missing certificate must not block a deploy: the app can still
		// be served, and blocking would mean one un-pointed DNS record
		// freezes an unrelated release.
		out.Notes = append(out.Notes, "certificate: "+err.Error())
	} else if note != "" {
		out.Notes = append(out.Notes, note)
	}

	if err := gitops.EnsureMirror(ctx, site); err != nil {
		out.Action = ActionBlocked
		out.Err = err
		return out
	}
	sha, err := gitops.Resolve(ctx, site)
	if err != nil {
		out.Action = ActionBlocked
		out.Err = err
		return out
	}
	out.ToSHA = sha

	current, err := d.store.Current(site.Domain)
	if err != nil {
		out.Err = err
		out.Action = ActionBlocked
		return out
	}
	out.FromSHA = current

	if current == sha && d.activeReleaseIs(site, sha) {
		return out
	}

	if d.dryRun {
		out.Action = ActionBlocked
		out.Notes = append(out.Notes, fmt.Sprintf("would deploy %s → %s", short(current), short(sha)))
		return out
	}

	if err := d.deploy(ctx, site, sha); err != nil {
		out.Err = err
		if rbErr := d.rollback(ctx, site, current); rbErr != nil {
			out.Err = errors.Join(err, fmt.Errorf("rollback also failed: %w", rbErr))
			out.Action = ActionBlocked
		} else {
			out.Action = ActionRolledBack
		}
		return out
	}

	if err := d.store.SetCurrent(site.Domain, sha); err != nil {
		out.Notes = append(out.Notes, "state write failed: "+err.Error())
	}
	d.pruneReleases(site)
	out.Action = ActionDeployed
	return out
}

func (d *Deployer) provision(ctx context.Context, site *config.Site) error {
	if err := d.cp.ProvisionSite(ctx, site); err != nil {
		return err
	}
	if err := d.store.MarkProvisioned(site.Domain); err != nil {
		return err
	}
	return nil
}

// ensureCertificate issues a certificate when one is missing, guarded by a DNS
// precheck and a backoff marker.
//
// Both guards exist for the same reason: Let's Encrypt counts failed
// authorisations against a per-hostname hourly limit and certificates against a
// weekly per-domain limit. A reconcile loop running every two minutes will
// exhaust either within the hour and lock the domain out for days.
func (d *Deployer) ensureCertificate(ctx context.Context, site *config.Site) (string, error) {
	if _, err := os.Stat(d.cp.CertPath(site.Domain)); err == nil {
		return "", nil // present; drift.Check watches its expiry
	}

	last, err := d.store.LastCertAttempt(site.Domain)
	if err != nil {
		return "", err
	}
	if !last.IsZero() && time.Since(last) < d.cfg.CloudPanel.CertBackoff {
		return "", fmt.Errorf("backing off, last attempt %s ago", time.Since(last).Round(time.Minute))
	}

	ips, err := net.DefaultResolver.LookupHost(ctx, site.Domain)
	if err != nil {
		return "", fmt.Errorf("DNS does not resolve yet: %w", err)
	}
	pointed := false
	for _, ip := range ips {
		if d.cfg.CloudPanel.HasServerIP(ip) {
			pointed = true
			break
		}
	}
	if !pointed {
		return "", fmt.Errorf("DNS resolves to %v, not this host; not attempting issuance", ips)
	}

	if d.dryRun {
		return "would request certificate", nil
	}
	// Mark before the call: if we die mid-issuance, Let's Encrypt still
	// counted the attempt, so the backoff must survive our death.
	if err := d.store.MarkCertAttempt(site.Domain); err != nil {
		return "", err
	}
	if err := d.cp.InstallCertificate(ctx, site.Domain); err != nil {
		return "", err
	}
	return "certificate issued", nil
}

func (d *Deployer) deploy(ctx context.Context, site *config.Site, sha string) error {
	release := site.ReleaseDir(sha)

	if _, err := os.Stat(release); os.IsNotExist(err) {
		if err := gitops.Export(ctx, site, sha, release); err != nil {
			return err
		}
	}

	env := d.buildEnv(site)
	for _, cmd := range site.Build {
		if err := d.runIn(ctx, site, release, cmd, env); err != nil {
			return fmt.Errorf("build step %q: %w", cmd, err)
		}
	}
	for _, cmd := range site.Release {
		if err := d.runIn(ctx, site, release, cmd, env); err != nil {
			return fmt.Errorf("release step %q: %w", cmd, err)
		}
	}

	if err := d.activate(ctx, site, release); err != nil {
		return err
	}
	return d.healthcheck(ctx, site)
}

// buildEnv exposes the site's env file to build and release steps. Secrets are
// never stored in the infra repo; the operator maintains this file on the box.
func (d *Deployer) buildEnv(site *config.Site) []string {
	return []string{
		"APP_ENV_FILE=/etc/appenv/" + site.Domain,
		"RELEASE_DOMAIN=" + site.Domain,
	}
}

func (d *Deployer) runIn(ctx context.Context, site *config.Site, dir, cmd string, env []string) error {
	cctx, cancel := context.WithTimeout(ctx, d.cfg.Deploy.CommandTimeout)
	defer cancel()

	opts := []sh.Opt{sh.AsUser(site.SiteUser), sh.InDir(dir), sh.WithEnv(env...)}
	_, err := sh.Bash(cctx, opts, cmd)
	return err
}

// activate swaps the docroot symlink to point at the new release.
//
// The rename is atomic, so no request ever observes a partially-swapped tree —
// which is the whole reason for not rsyncing into a live docroot. On PHP this
// works because the pool jail was widened to cover releases/, and takes effect
// immediately because open_basedir disables the realpath cache.
func (d *Deployer) activate(ctx context.Context, site *config.Site, release string) error {
	link := site.DocRoot()

	// First deploy: CloudPanel created a real directory here. Move it aside
	// rather than deleting, in case it held something hand-placed.
	if fi, err := os.Lstat(link); err == nil && fi.Mode()&os.ModeSymlink == 0 {
		if fi.IsDir() {
			if err := os.Rename(link, link+".preexisting"); err != nil {
				return fmt.Errorf("move original docroot aside: %w", err)
			}
		}
	}

	tmp := link + ".swap"
	_ = os.Remove(tmp)
	if err := os.Symlink(release, tmp); err != nil {
		return fmt.Errorf("stage symlink: %w", err)
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("activate release: %w", err)
	}

	if site.SystemdUnit != "" {
		if _, err := sh.Run(ctx, nil, "systemctl", "restart", site.SystemdUnit); err != nil {
			return fmt.Errorf("restart %s: %w", site.SystemdUnit, err)
		}
	}
	return nil
}

func (d *Deployer) healthcheck(ctx context.Context, site *config.Site) error {
	if site.Healthcheck == "" {
		return nil
	}
	deadline := time.Now().Add(d.cfg.Deploy.HealthTimeout)
	client := &http.Client{Timeout: 10 * time.Second}

	var last error
	for time.Now().Before(deadline) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, site.Healthcheck, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				return nil
			}
			last = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	return fmt.Errorf("healthcheck %s failed after %s: %w",
		site.Healthcheck, d.cfg.Deploy.HealthTimeout, last)
}

// rollback returns the docroot to the previously serving release.
//
// This can only restore code. A release step that already ran a destructive
// migration is not undone here — which is why migrations belong in `release`
// and should be written to be backward compatible with the previous release.
func (d *Deployer) rollback(ctx context.Context, site *config.Site, sha string) error {
	if sha == "" {
		return fmt.Errorf("no previous release recorded")
	}
	prev := site.ReleaseDir(sha)
	if _, err := os.Stat(prev); err != nil {
		return fmt.Errorf("previous release %s is gone: %w", short(sha), err)
	}
	return d.activate(ctx, site, prev)
}

func (d *Deployer) activeReleaseIs(site *config.Site, sha string) bool {
	target, err := os.Readlink(site.DocRoot())
	if err != nil {
		return false
	}
	return filepath.Base(target) == sha
}

// pruneReleases keeps the most recent N release directories. Never removes the
// currently linked one, whatever the mtime ordering says.
func (d *Deployer) pruneReleases(site *config.Site) {
	keep := site.KeepReleases
	if keep <= 0 {
		keep = d.cfg.Deploy.KeepReleases
	}
	entries, err := os.ReadDir(site.ReleasesDir())
	if err != nil {
		return
	}
	active, _ := os.Readlink(site.DocRoot())
	activeName := filepath.Base(active)

	type rel struct {
		name string
		mod  time.Time
	}
	var rels []rel
	for _, e := range entries {
		if !e.IsDir() || e.Name() == activeName {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		rels = append(rels, rel{e.Name(), info.ModTime()})
	}
	sort.Slice(rels, func(i, j int) bool { return rels[i].mod.After(rels[j].mod) })

	for i, r := range rels {
		if i < keep-1 {
			continue
		}
		_ = os.RemoveAll(filepath.Join(site.ReleasesDir(), r.name))
	}
}

func short(sha string) string {
	if len(sha) < 8 {
		return "none"
	}
	return sha[:8]
}
