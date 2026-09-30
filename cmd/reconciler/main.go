// Command reconciler brings a CloudPanel host into line with the site manifests
// held in a git repository.
//
// It is a oneshot: it runs, converges, reports, and exits. Scheduling is
// systemd's job — a timer for convergence, a webhook receiver for latency. Both
// trigger the same unit, and systemd refuses to run two instances of a oneshot
// concurrently, so overlapping triggers collapse for free.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/almerandika/reconciler/internal/cloudpanel"
	"github.com/almerandika/reconciler/internal/config"
	"github.com/almerandika/reconciler/internal/deploy"
	"github.com/almerandika/reconciler/internal/drift"
	"github.com/almerandika/reconciler/internal/gitops"
	"github.com/almerandika/reconciler/internal/notify"
	"github.com/almerandika/reconciler/internal/state"
)

func main() {
	var (
		cfgPath = flag.String("config", "/etc/reconciler/config.yaml", "path to reconciler config")
		dryRun  = flag.Bool("dry-run", false, "plan only; make no changes")
		only    = flag.String("only", "", "reconcile a single domain")
		verbose = flag.Bool("v", false, "debug logging")
	)
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, *cfgPath, *dryRun, *only); err != nil {
		slog.Error("reconcile failed", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfgPath string, dryRun bool, only string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	if os.Geteuid() != 0 && !dryRun {
		return fmt.Errorf("must run as root: clpctl's site:add:* and lets-encrypt:* " +
			"commands are not defined for any other caller")
	}

	unlock, err := lock(cfg.LockFile)
	if err != nil {
		return err
	}
	defer unlock()

	store, err := state.New(cfg.StateDir)
	if err != nil {
		return err
	}
	cp := cloudpanel.New(cfg.CloudPanel, dryRun)
	notifier := notify.New(cfg.Telegram)
	deployer := deploy.New(cfg, cp, store, dryRun)
	checker := drift.NewChecker(cfg, cp)

	head, err := gitops.SyncInfra(ctx, cfg)
	if err != nil {
		// A failure to reach GitHub is transient and self-correcting on the
		// next tick. Notify, but do not act on a stale manifest set.
		_ = notifier.Send(ctx, "🔴 reconciler could not sync the infra repo:\n"+err.Error())
		return err
	}
	slog.Info("infra repo synced", "head", short(head))

	sitesDir := filepath.Join(cfg.Infra.Path, cfg.Infra.SitesDir)
	sites, err := config.LoadSites(sitesDir)
	if err != nil {
		_ = notifier.Send(ctx, "🔴 reconciler could not load manifests:\n"+err.Error())
		return err
	}

	var (
		outcomes []deploy.Outcome
		findings []drift.Finding
	)

	for _, site := range sites {
		if only != "" && site.Domain != only {
			continue
		}
		start := time.Now()
		out := deployer.Reconcile(ctx, site)
		outcomes = append(outcomes, out)

		switch {
		case out.Err != nil:
			slog.Error("site failed", "domain", site.Domain,
				"action", out.Action, "err", out.Err)
		case out.Changed():
			slog.Info("site changed", "domain", site.Domain,
				"action", out.Action, "sha", short(out.ToSHA),
				"took", time.Since(start).Round(time.Millisecond))
		default:
			slog.Debug("site unchanged", "domain", site.Domain)
		}

		// Drift is checked even when the deploy failed — a broken jail is
		// frequently the reason it failed.
		findings = append(findings, checker.Check(ctx, site)...)
	}

	if msg := report(outcomes, findings); msg != "" {
		if err := notifier.Send(ctx, msg); err != nil {
			slog.Warn("notification failed", "err", err)
		}
	}

	for _, o := range outcomes {
		if o.Err != nil {
			return fmt.Errorf("%d site(s) failed; first: %s: %w",
				countErrors(outcomes), o.Domain, o.Err)
		}
	}
	return nil
}

// report builds a notification, or returns "" when there is nothing worth
// waking someone for. A quiet run must stay quiet, or the channel becomes noise
// and stops being read.
func report(outcomes []deploy.Outcome, findings []drift.Finding) string {
	var b strings.Builder

	for _, o := range outcomes {
		switch {
		case o.Err != nil:
			fmt.Fprintf(&b, "🔴 %s (%s)\n%s\n\n", o.Domain, o.Action, o.Err)
		case o.Action == deploy.ActionDeployed:
			fmt.Fprintf(&b, "✅ %s deployed %s → %s\n", o.Domain, short(o.FromSHA), short(o.ToSHA))
		case o.Action == deploy.ActionProvisioned:
			fmt.Fprintf(&b, "🆕 %s provisioned\n", o.Domain)
		case o.Action == deploy.ActionBlocked:
			fmt.Fprintf(&b, "⏸ %s: %s\n", o.Domain, strings.Join(o.Notes, "; "))
		}
	}

	if s := drift.Summarise(findings); s != "" {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.WriteString("drift:\n")
		b.WriteString(s)
	}
	return strings.TrimSpace(b.String())
}

func countErrors(outcomes []deploy.Outcome) int {
	n := 0
	for _, o := range outcomes {
		if o.Err != nil {
			n++
		}
	}
	return n
}

// lock takes an exclusive, non-blocking flock. systemd already serialises the
// oneshot unit; this also covers a hand-run invocation racing the timer.
func lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another reconcile is already running (%s)", path)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

func short(sha string) string {
	if len(sha) < 8 {
		return "none"
	}
	return sha[:8]
}
