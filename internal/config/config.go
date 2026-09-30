package config

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the reconciler's own configuration, distinct from the per-site
// manifests it reads out of the infra repo. This file lives on the prod box and
// is not managed by git — it holds the bot token and the paths CloudPanel uses.
type Config struct {
	StateDir string `yaml:"stateDir"`
	LockFile string `yaml:"lockFile"`

	Infra      Infra      `yaml:"infra"`
	CloudPanel CloudPanel `yaml:"cloudpanel"`
	Telegram   Telegram   `yaml:"telegram"`
	Deploy     DeployOpts `yaml:"deploy"`
}

type Infra struct {
	Path     string `yaml:"path"`     // local clone of the infra repo
	Remote   string `yaml:"remote"`   // git URL
	Branch   string `yaml:"branch"`   // protected branch to track
	SitesDir string `yaml:"sitesDir"` // manifest dir, relative to Path
	SSHKey   string `yaml:"sshKey"`   // read-only deploy key for the infra repo
}

type CloudPanel struct {
	// Paths CloudPanel owns. Defaults match a stock Debian/Ubuntu install;
	// verify them after any CloudPanel upgrade.
	NginxSitesDir string `yaml:"nginxSitesDir"`
	CertDir       string `yaml:"certDir"`
	FPMPoolDirTpl string `yaml:"fpmPoolDirTemplate"` // %s is the PHP version

	// ServerIPs is compared against a domain's A/AAAA records before any
	// Let's Encrypt call, so we never burn issuance rate limits on a domain
	// whose DNS has not been pointed here yet.
	ServerIPs []string `yaml:"serverIPs"`

	// CertBackoff is the minimum interval between issuance attempts for the
	// same domain after a failure. Keep this well above the reconcile
	// interval — LE rate limits are unforgiving and recover slowly.
	CertBackoff time.Duration `yaml:"certBackoff"`

	// CertWarnBefore controls when drift detection starts complaining about
	// an approaching expiry.
	CertWarnBefore time.Duration `yaml:"certWarnBefore"`
}

type Telegram struct {
	BotToken string `yaml:"botToken"`
	ChatID   string `yaml:"chatID"`
}

type DeployOpts struct {
	KeepReleases   int           `yaml:"keepReleases"`
	HealthTimeout  time.Duration `yaml:"healthTimeout"`
	CommandTimeout time.Duration `yaml:"commandTimeout"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.applyDefaults()
	return &c, c.validate()
}

func (c *Config) applyDefaults() {
	setStr(&c.StateDir, "/var/lib/reconciler")
	setStr(&c.LockFile, "/run/reconciler.lock")
	setStr(&c.Infra.Branch, "main")
	setStr(&c.Infra.SitesDir, "sites")
	setStr(&c.CloudPanel.NginxSitesDir, "/etc/nginx/sites-enabled")
	setStr(&c.CloudPanel.CertDir, "/etc/nginx/ssl-certificates")
	setStr(&c.CloudPanel.FPMPoolDirTpl, "/etc/php/%s/fpm/pool.d")

	if c.CloudPanel.CertBackoff == 0 {
		c.CloudPanel.CertBackoff = 6 * time.Hour
	}
	if c.CloudPanel.CertWarnBefore == 0 {
		c.CloudPanel.CertWarnBefore = 14 * 24 * time.Hour
	}
	if c.Deploy.KeepReleases == 0 {
		c.Deploy.KeepReleases = 5
	}
	if c.Deploy.HealthTimeout == 0 {
		c.Deploy.HealthTimeout = 60 * time.Second
	}
	if c.Deploy.CommandTimeout == 0 {
		c.Deploy.CommandTimeout = 15 * time.Minute
	}
}

func (c *Config) validate() error {
	if c.Infra.Path == "" {
		return fmt.Errorf("infra.path is required")
	}
	if c.Infra.Remote == "" {
		return fmt.Errorf("infra.remote is required")
	}
	if len(c.CloudPanel.serverIPSet()) == 0 {
		return fmt.Errorf("cloudpanel.serverIPs is required: without it we cannot " +
			"precheck DNS and would risk Let's Encrypt rate limits")
	}
	return nil
}

func (cp CloudPanel) serverIPSet() map[string]struct{} {
	set := make(map[string]struct{}, len(cp.ServerIPs))
	for _, ip := range cp.ServerIPs {
		if ip != "" {
			set[ip] = struct{}{}
		}
	}
	return set
}

// HasServerIP reports whether ip is one of this host's public addresses.
func (cp CloudPanel) HasServerIP(ip string) bool {
	_, ok := cp.serverIPSet()[ip]
	return ok
}

func setStr(dst *string, def string) {
	if *dst == "" {
		*dst = def
	}
}
