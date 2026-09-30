// Package cloudpanel wraps the parts of clpctl we can rely on.
//
// The important constraint: clpctl can create and delete sites but cannot
// change them. There is no site:update. Everything here is therefore
// create-only, and callers must treat a mismatch on an existing site as drift to
// report rather than a difference to converge.
//
// clpctl also exposes different command sets depending on the caller — the root
// binary has site:add:*, db:add, lets-encrypt:* and user:*, while a site user
// gets only db:export, db:import and friends. Everything in this file must run
// as root.
package cloudpanel

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/almerandika/reconciler/internal/config"
	"github.com/almerandika/reconciler/internal/sh"
)

type Client struct {
	cfg    config.CloudPanel
	dryRun bool
}

func New(cfg config.CloudPanel, dryRun bool) *Client {
	return &Client{cfg: cfg, dryRun: dryRun}
}

// passwordAlphabet deliberately omits '$'. clpctl interpolates shell variables
// in password arguments, so a password containing '$' is reported as set
// successfully but stored wrong, and the account silently will not authenticate.
// Backtick, quote and backslash are dropped for the same class of reason.
const passwordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!%*+,-.:=?@^_~"

// GeneratePassword returns a cryptographically random password safe to hand to
// clpctl.
func GeneratePassword(n int) (string, error) {
	if n < 16 {
		n = 24
	}
	out := make([]byte, n)
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := range out {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		out[i] = passwordAlphabet[idx.Int64()]
	}
	return string(out), nil
}

// SiteExists reports whether CloudPanel already has this site.
//
// We check the filesystem rather than CloudPanel's SQLite database: the schema
// is undocumented, decoded from obfuscated source, and free to change on any
// upgrade. The vhost file plus the site user is a weaker signal but one that
// cannot silently start lying after a panel update.
func (c *Client) SiteExists(site *config.Site) bool {
	vhost := filepath.Join(c.cfg.NginxSitesDir, site.Domain+".conf")
	if _, err := os.Stat(vhost); err != nil {
		return false
	}
	if _, err := user.Lookup(site.SiteUser); err != nil {
		return false
	}
	return true
}

func (c *Client) clpctl(ctx context.Context, args ...string) error {
	if c.dryRun {
		fmt.Printf("[dry-run] clpctl %s\n", redact(args))
		return nil
	}
	_, err := sh.Run(ctx, nil, "clpctl", args...)
	return err
}

// ProvisionSite creates the site, and its database if the manifest asks for one.
// Safe to call only when SiteExists is false.
func (c *Client) ProvisionSite(ctx context.Context, site *config.Site) error {
	pw, err := GeneratePassword(28)
	if err != nil {
		return err
	}

	switch site.Type {
	case config.TypePHP:
		err = c.clpctl(ctx, "site:add:php",
			"--domainName="+site.Domain,
			"--phpVersion="+site.PHPVersion,
			"--vhostTemplate="+site.VhostTemplate,
			"--siteUser="+site.SiteUser,
			"--siteUserPassword="+pw,
		)
	case config.TypeNode:
		err = c.clpctl(ctx, "site:add:nodejs",
			"--domainName="+site.Domain,
			"--nodejsVersion="+site.NodeVersion,
			fmt.Sprintf("--appPort=%d", site.AppPort),
			"--siteUser="+site.SiteUser,
			"--siteUserPassword="+pw,
		)
	case config.TypeStatic:
		err = c.clpctl(ctx, "site:add:static",
			"--domainName="+site.Domain,
			"--siteUser="+site.SiteUser,
			"--siteUserPassword="+pw,
		)
	default:
		return fmt.Errorf("unsupported site type %q", site.Type)
	}
	if err != nil {
		return fmt.Errorf("create site %s: %w", site.Domain, err)
	}

	if site.Database != nil {
		dbPW, err := GeneratePassword(28)
		if err != nil {
			return err
		}
		if err := c.clpctl(ctx, "db:add",
			"--domainName="+site.Domain,
			"--databaseName="+site.Database.Name,
			"--databaseUserName="+site.Database.User,
			"--databaseUserPassword="+dbPW,
		); err != nil {
			return fmt.Errorf("create database for %s: %w", site.Domain, err)
		}
		// The reconciler never writes application secrets into the repo. The
		// operator wires the credential into /etc/appenv/<domain> by hand;
		// until then the site is provisioned but not runnable, which
		// EnsureEnvFile reports.
		fmt.Printf("database %s created for %s; set its password in the site env file\n",
			site.Database.Name, site.Domain)
	}
	return nil
}

var openBasedirRe = regexp.MustCompile(`(?m)^\s*php_admin_value\[open_basedir\]\s*=\s*(.*)$`)

// PoolPath returns the PHP-FPM pool file CloudPanel generates for a site.
func (c *Client) PoolPath(site *config.Site) string {
	return filepath.Join(fmt.Sprintf(c.cfg.FPMPoolDirTpl, site.PHPVersion), site.Domain+".conf")
}

// ReadOpenBasedir returns the jail currently configured for a site's pool.
func (c *Client) ReadOpenBasedir(site *config.Site) (string, error) {
	b, err := os.ReadFile(c.PoolPath(site))
	if err != nil {
		return "", err
	}
	m := openBasedirRe.FindSubmatch(b)
	if m == nil {
		return "", nil
	}
	return strings.TrimSpace(string(m[1])), nil
}

// WidenOpenBasedir rewrites the pool jail so it spans the site's home directory
// rather than just the docroot.
//
// Without this, a docroot symlinked into releases/ resolves outside the jail and
// PHP refuses to open a single file. With it, symlink swaps work — and because
// open_basedir disables the realpath cache to prevent symlink attacks, the flip
// takes effect on the very next request instead of lingering behind a stale
// cache the way symlink deploys usually do on PHP.
//
// This file is outside CloudPanel's management, so a panel upgrade may reset it.
// drift.Check asserts it on every pass for exactly that reason.
func (c *Client) WidenOpenBasedir(ctx context.Context, site *config.Site) error {
	if site.Type != config.TypePHP {
		return nil
	}
	path := c.PoolPath(site)
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read pool config %s: %w", path, err)
	}

	current := ""
	if m := openBasedirRe.FindSubmatch(b); m != nil {
		current = strings.TrimSpace(string(m[1]))
	}
	if HasPath(current, site.OpenBasedirRoot()) {
		return nil
	}

	want := site.OpenBasedirRoot() + ":/tmp/:/usr/share/php/"
	line := "php_admin_value[open_basedir] = " + want

	var updated []byte
	if openBasedirRe.Match(b) {
		updated = openBasedirRe.ReplaceAll(b, []byte(line))
	} else {
		updated = append(b, []byte("\n"+line+"\n")...)
	}

	if c.dryRun {
		fmt.Printf("[dry-run] would set open_basedir for %s to %s\n", site.Domain, want)
		return nil
	}
	if err := os.WriteFile(path+".tmp", updated, 0o644); err != nil {
		return err
	}
	if err := os.Rename(path+".tmp", path); err != nil {
		return err
	}
	// reload, not restart: draining workers finish their current request.
	_, err = sh.Run(ctx, nil, "systemctl", "reload", "php"+site.PHPVersion+"-fpm")
	return err
}

// HasPath reports whether a colon-separated open_basedir list already covers p.
func HasPath(list, p string) bool {
	for _, part := range strings.Split(list, ":") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.HasSuffix(part, "/") {
			part += "/"
		}
		if strings.HasPrefix(p, part) {
			return true
		}
	}
	return false
}

// InstallCertificate requests a Let's Encrypt certificate. Callers must apply
// backoff and a DNS precheck first; this does neither.
func (c *Client) InstallCertificate(ctx context.Context, domain string) error {
	return c.clpctl(ctx, "lets-encrypt:install:certificate", "--domainName="+domain)
}

// CertPath is where CloudPanel stores a site's certificate.
func (c *Client) CertPath(domain string) string {
	return filepath.Join(c.cfg.CertDir, domain+".crt")
}

func redact(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.Contains(a, "Password=") {
			out[i] = a[:strings.Index(a, "=")+1] + "***"
			continue
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}
