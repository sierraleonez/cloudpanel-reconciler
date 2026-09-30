package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type SiteType string

const (
	TypePHP    SiteType = "php"
	TypeNode   SiteType = "nodejs"
	TypeStatic SiteType = "static"
)

// Site is one manifest file in the infra repo. This is the desired state; the
// reconciler's whole job is making the box match it.
type Site struct {
	Domain   string   `yaml:"domain"`
	SiteUser string   `yaml:"siteUser"`
	Type     SiteType `yaml:"type"`

	Repo   string `yaml:"repo"`   // git URL of the application
	Ref    string `yaml:"ref"`    // tag or full SHA — never a branch
	SSHKey string `yaml:"sshKey"` // deploy key for Repo, on the prod box

	// Runtime, used at provision time only. CloudPanel has no CLI for
	// changing these afterwards, so edits here are reported as drift.
	PHPVersion    string `yaml:"phpVersion"`
	NodeVersion   string `yaml:"nodeVersion"`
	AppPort       int    `yaml:"appPort"`
	VhostTemplate string `yaml:"vhostTemplate"`

	Build       []string `yaml:"build"`       // run in the release dir, as SiteUser
	Release     []string `yaml:"release"`     // migrations etc., after build, before flip
	Healthcheck string   `yaml:"healthcheck"` // URL; empty disables

	Database *Database `yaml:"database"`

	// SystemdUnit is restarted after activation. Defaults to app@<siteUser>
	// for nodejs sites.
	SystemdUnit string `yaml:"systemdUnit"`

	// Recreate opts this site in to destroy-and-rebuild when immutable
	// CloudPanel fields drift. Off by default: it drops the database.
	Recreate bool `yaml:"recreate"`

	KeepReleases int `yaml:"keepReleases"`

	// Path of the manifest file, for error messages.
	SourceFile string `yaml:"-"`
}

type Database struct {
	Name string `yaml:"name"`
	User string `yaml:"user"`
}

var (
	domainRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	siteUserRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	shaRe      = regexp.MustCompile(`^[0-9a-f]{40}$`)

	// Refs we refuse outright. A moving ref defeats the whole point: the
	// promotion commit in the infra repo is the human gate, and pinning to a
	// branch hands that gate back to whoever can push the app repo.
	branchRefs = map[string]bool{
		"main": true, "master": true, "develop": true,
		"dev": true, "staging": true, "trunk": true, "HEAD": true,
	}
)

// LoadSites reads every *.yaml manifest in dir, sorted by domain.
func LoadSites(dir string) ([]*Site, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read manifest dir %s: %w", dir, err)
	}

	var sites []*Site
	seen := map[string]string{}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		s, err := loadSite(path)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[s.Domain]; dup {
			return nil, fmt.Errorf("%s: domain %s already declared in %s",
				path, s.Domain, prev)
		}
		seen[s.Domain] = path
		sites = append(sites, s)
	}

	sort.Slice(sites, func(i, j int) bool { return sites[i].Domain < sites[j].Domain })
	return sites, nil
}

func loadSite(path string) (*Site, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var s Site
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // typos in a manifest should fail loudly, not silently
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	s.SourceFile = path
	s.applyDefaults()
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

func (s *Site) applyDefaults() {
	if s.Type == TypeNode && s.SystemdUnit == "" {
		s.SystemdUnit = "app@" + s.SiteUser
	}
	if s.Type == TypePHP && s.VhostTemplate == "" {
		s.VhostTemplate = "Generic"
	}
}

func (s *Site) Validate() error {
	if !domainRe.MatchString(s.Domain) {
		return fmt.Errorf("domain %q is not a valid hostname", s.Domain)
	}
	if !siteUserRe.MatchString(s.SiteUser) {
		return fmt.Errorf("siteUser %q must be lowercase alphanumeric with dashes, 2-31 chars", s.SiteUser)
	}

	switch s.Type {
	case TypePHP:
		if s.PHPVersion == "" {
			return fmt.Errorf("phpVersion is required for php sites")
		}
	case TypeNode:
		if s.NodeVersion == "" {
			return fmt.Errorf("nodeVersion is required for nodejs sites")
		}
		if s.AppPort < 1024 || s.AppPort > 65535 {
			return fmt.Errorf("appPort %d is outside the unprivileged range", s.AppPort)
		}
	case TypeStatic:
	default:
		return fmt.Errorf("type %q must be one of php, nodejs, static", s.Type)
	}

	if s.Repo == "" {
		return fmt.Errorf("repo is required")
	}
	if err := s.validateRef(); err != nil {
		return err
	}
	if s.Database != nil {
		if s.Database.Name == "" || s.Database.User == "" {
			return fmt.Errorf("database requires both name and user")
		}
	}
	return nil
}

func (s *Site) validateRef() error {
	if s.Ref == "" {
		return fmt.Errorf("ref is required")
	}
	if branchRefs[s.Ref] {
		return fmt.Errorf("ref %q is a branch; pin a tag or full SHA so that "+
			"promotion stays an explicit commit in this repo", s.Ref)
	}
	if shaRe.MatchString(s.Ref) {
		return nil
	}
	if strings.ContainsAny(s.Ref, " \t~^:?*[\\") {
		return fmt.Errorf("ref %q contains characters not valid in a tag name", s.Ref)
	}
	return nil
}

// ReleasesDir is the parent of all extracted releases for this site.
func (s *Site) ReleasesDir() string { return filepath.Join(s.Home(), "releases") }

// Home is the site user's home directory as CloudPanel lays it out.
func (s *Site) Home() string { return filepath.Join("/home", s.SiteUser) }

// DocRoot is the path nginx serves, which we replace with a symlink into
// ReleasesDir so that activation is a single atomic rename.
func (s *Site) DocRoot() string { return filepath.Join(s.Home(), "htdocs", s.Domain) }

// MirrorDir holds the bare clone of the application repo. It lives under the
// site user's home so that fetch, export and build all run unprivileged.
func (s *Site) MirrorDir() string {
	return filepath.Join(s.Home(), ".cache", "reconciler", "repo.git")
}

// ReleaseDir is where a given commit is extracted to.
func (s *Site) ReleaseDir(sha string) string { return filepath.Join(s.ReleasesDir(), sha) }

// OpenBasedirRoot is the path that must appear in the site's PHP-FPM pool jail.
// CloudPanel scopes open_basedir to the docroot, which breaks the moment the
// docroot becomes a symlink into releases/ — so we widen it to the home dir at
// provision time and assert it on every pass.
func (s *Site) OpenBasedirRoot() string { return s.Home() + "/" }
