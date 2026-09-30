// Package gitops handles the two git interactions the reconciler needs: keeping
// the infra repo in sync, and materialising an application commit into a release
// directory.
package gitops

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/almerandika/reconciler/internal/config"
	"github.com/almerandika/reconciler/internal/sh"
)

func sshEnv(key string) []sh.Opt {
	if key == "" {
		return nil
	}
	return []sh.Opt{sh.WithEnv(
		"GIT_SSH_COMMAND=ssh -i " + key +
			" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new" +
			" -o BatchMode=yes",
	)}
}

// SyncInfra brings the local infra clone to the tip of the tracked branch.
//
// Hard reset rather than pull: the working tree is a cache of the remote, and a
// merge conflict on a box nobody logs into is a failure mode with no recovery
// path. If someone edited it by hand, their edit is what we want to discard.
func SyncInfra(ctx context.Context, cfg *config.Config) (string, error) {
	opts := sshEnv(cfg.Infra.SSHKey)

	if _, err := os.Stat(filepath.Join(cfg.Infra.Path, ".git")); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(cfg.Infra.Path), 0o750); err != nil {
			return "", err
		}
		if _, err := sh.Run(ctx, opts, "git", "clone",
			"--branch", cfg.Infra.Branch, cfg.Infra.Remote, cfg.Infra.Path); err != nil {
			return "", fmt.Errorf("clone infra repo: %w", err)
		}
	}

	dir := []sh.Opt{sh.InDir(cfg.Infra.Path)}
	dir = append(dir, opts...)

	if _, err := sh.Run(ctx, dir, "git", "fetch", "--prune", "origin"); err != nil {
		return "", fmt.Errorf("fetch infra repo: %w", err)
	}
	if _, err := sh.Run(ctx, dir, "git", "reset", "--hard",
		"origin/"+cfg.Infra.Branch); err != nil {
		return "", fmt.Errorf("reset infra repo: %w", err)
	}
	res, err := sh.Run(ctx, dir, "git", "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(res.Stdout), nil
}

// EnsureMirror creates or updates the bare clone of a site's application repo.
// It lives under the site user's home and every operation runs as that user, so
// a compromised build never touches root-owned state.
func EnsureMirror(ctx context.Context, site *config.Site) error {
	opts := append([]sh.Opt{sh.AsUser(site.SiteUser)}, sshEnv(site.SSHKey)...)

	if _, err := os.Stat(site.MirrorDir()); os.IsNotExist(err) {
		parent := filepath.Dir(site.MirrorDir())
		if _, err := sh.Run(ctx, []sh.Opt{sh.AsUser(site.SiteUser)},
			"mkdir", "-p", parent); err != nil {
			return fmt.Errorf("create mirror parent: %w", err)
		}
		if _, err := sh.Run(ctx, opts, "git", "clone", "--mirror",
			site.Repo, site.MirrorDir()); err != nil {
			return fmt.Errorf("mirror %s: %w", site.Repo, err)
		}
		return nil
	}

	inMirror := append([]sh.Opt{sh.AsUser(site.SiteUser), sh.InDir(site.MirrorDir())},
		sshEnv(site.SSHKey)...)
	// --prune keeps deleted tags from lingering; a stale tag that still
	// resolves would let a deleted release be redeployed.
	if _, err := sh.Run(ctx, inMirror, "git", "remote", "update", "--prune"); err != nil {
		return fmt.Errorf("update mirror for %s: %w", site.Domain, err)
	}
	return nil
}

// Resolve turns a manifest ref into a full commit SHA.
func Resolve(ctx context.Context, site *config.Site) (string, error) {
	opts := []sh.Opt{sh.AsUser(site.SiteUser), sh.InDir(site.MirrorDir())}
	res, err := sh.Run(ctx, opts, "git", "rev-parse", "--verify", site.Ref+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("resolve ref %q for %s: %w", site.Ref, site.Domain, err)
	}
	sha := strings.TrimSpace(res.Stdout)
	if len(sha) != 40 {
		return "", fmt.Errorf("resolve ref %q: unexpected output %q", site.Ref, sha)
	}
	return sha, nil
}

// Export extracts a commit into dest. Uses git archive rather than a clone so
// the release directory carries no .git — nothing in production should be able
// to change what commit it claims to be.
func Export(ctx context.Context, site *config.Site, sha, dest string) error {
	asUser := []sh.Opt{sh.AsUser(site.SiteUser)}

	if _, err := sh.Run(ctx, asUser, "mkdir", "-p", dest); err != nil {
		return fmt.Errorf("create release dir: %w", err)
	}
	script := fmt.Sprintf("set -o pipefail; git --git-dir=%s archive --format=tar %s | tar -x -C %s",
		shellQuote(site.MirrorDir()), shellQuote(sha), shellQuote(dest))
	if _, err := sh.Bash(ctx, asUser, script); err != nil {
		return fmt.Errorf("export %s to %s: %w", sha[:8], dest, err)
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
