// Package drift reports divergence in the configuration CloudPanel owns.
//
// Nothing here repairs anything. clpctl cannot update an existing site, so the
// only "fix" available would be delete-and-recreate, which drops the database.
// Detect, report, let a human decide.
package drift

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/almerandika/reconciler/internal/cloudpanel"
	"github.com/almerandika/reconciler/internal/config"
	"github.com/almerandika/reconciler/internal/sh"
)

type Severity string

const (
	Warn     Severity = "warn"
	Critical Severity = "critical"
)

type Finding struct {
	Domain   string
	Check    string
	Severity Severity
	Detail   string
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s / %s: %s", f.Severity, f.Domain, f.Check, f.Detail)
}

type Checker struct {
	cfg *config.Config
	cp  *cloudpanel.Client
}

func NewChecker(cfg *config.Config, cp *cloudpanel.Client) *Checker {
	return &Checker{cfg: cfg, cp: cp}
}

func (c *Checker) Check(ctx context.Context, site *config.Site) []Finding {
	var out []Finding
	add := func(check string, sev Severity, format string, args ...any) {
		out = append(out, Finding{site.Domain, check, sev, fmt.Sprintf(format, args...)})
	}

	vhost := filepath.Join(c.cfg.CloudPanel.NginxSitesDir, site.Domain+".conf")
	vhostBody, err := os.ReadFile(vhost)
	if err != nil {
		add("vhost", Critical, "nginx config missing at %s", vhost)
		return out // everything downstream assumes the site exists
	}

	// The open_basedir jail is the single most important assertion here. If a
	// CloudPanel upgrade resets it to the docroot, the symlinked release
	// resolves outside the jail and every PHP site 500s on its next deploy —
	// silently, until someone ships.
	if site.Type == config.TypePHP {
		jail, err := c.cp.ReadOpenBasedir(site)
		switch {
		case err != nil:
			add("open_basedir", Critical, "cannot read pool config: %v", err)
		case jail == "":
			add("open_basedir", Warn, "no open_basedir set in pool config")
		case !cloudpanel.HasPath(jail, site.OpenBasedirRoot()):
			add("open_basedir", Critical,
				"jail %q no longer covers %s; next deploy will break this site",
				jail, site.OpenBasedirRoot())
		}
	}

	if site.Type == config.TypeNode {
		if port, ok := proxyPort(vhostBody); ok && port != site.AppPort {
			add("appPort", Warn,
				"vhost proxies to :%d but manifest says :%d (no CLI to change this; edit in the panel)",
				port, site.AppPort)
		}
		if site.SystemdUnit != "" {
			if _, err := sh.Run(ctx, nil, "systemctl", "is-active", "--quiet", site.SystemdUnit); err != nil {
				add("systemd", Critical, "unit %s is not active", site.SystemdUnit)
			}
		}
	}

	c.checkCertificate(site, add)

	// A docroot that is not a symlink means someone deployed by hand, or the
	// last activation half-finished.
	if fi, err := os.Lstat(site.DocRoot()); err == nil && fi.Mode()&os.ModeSymlink == 0 {
		add("docroot", Warn, "%s is not a symlink; releases are not being swapped atomically",
			site.DocRoot())
	}

	if _, err := os.Stat("/etc/appenv/" + site.Domain); os.IsNotExist(err) {
		add("env", Warn, "/etc/appenv/%s is missing", site.Domain)
	}

	return out
}

func (c *Checker) checkCertificate(site *config.Site, add func(string, Severity, string, ...any)) {
	path := c.cp.CertPath(site.Domain)
	raw, err := os.ReadFile(path)
	if err != nil {
		add("certificate", Warn, "no certificate at %s", path)
		return
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		add("certificate", Critical, "certificate at %s is not valid PEM", path)
		return
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		add("certificate", Critical, "cannot parse certificate: %v", err)
		return
	}
	left := time.Until(cert.NotAfter)
	switch {
	case left <= 0:
		add("certificate", Critical, "expired %s ago", (-left).Round(time.Hour))
	case left < c.cfg.CloudPanel.CertWarnBefore:
		add("certificate", Warn, "expires in %s (%s)",
			left.Round(time.Hour), cert.NotAfter.Format(time.DateOnly))
	}
}

var proxyPassRe = regexp.MustCompile(`proxy_pass\s+https?://(?:127\.0\.0\.1|localhost):(\d+)`)

func proxyPort(vhost []byte) (int, bool) {
	m := proxyPassRe.FindSubmatch(vhost)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0, false
	}
	return n, true
}

// Summarise renders findings for a notification, criticals first.
func Summarise(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}
	var crit, warn []string
	for _, f := range findings {
		line := fmt.Sprintf("%s / %s: %s", f.Domain, f.Check, f.Detail)
		if f.Severity == Critical {
			crit = append(crit, "🔴 "+line)
		} else {
			warn = append(warn, "🟡 "+line)
		}
	}
	return strings.Join(append(crit, warn...), "\n")
}
