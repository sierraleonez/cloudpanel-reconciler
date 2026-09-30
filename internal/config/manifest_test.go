package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeManifest(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const validNode = `
domain: app.example.com
siteUser: app-example
type: nodejs
repo: git@github.com:me/app.git
ref: v1.4.2
nodeVersion: "20"
appPort: 3001
healthcheck: https://app.example.com/healthz
`

func TestLoadSitesValid(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "app.yaml", validNode)

	sites, err := LoadSites(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sites) != 1 {
		t.Fatalf("got %d sites, want 1", len(sites))
	}
	s := sites[0]
	if s.SystemdUnit != "app@app-example" {
		t.Errorf("default systemd unit = %q", s.SystemdUnit)
	}
	if got, want := s.DocRoot(), "/home/app-example/htdocs/app.example.com"; got != want {
		t.Errorf("DocRoot() = %q, want %q", got, want)
	}
	if got, want := s.OpenBasedirRoot(), "/home/app-example/"; got != want {
		t.Errorf("OpenBasedirRoot() = %q, want %q", got, want)
	}
}

func TestBranchRefsRejected(t *testing.T) {
	for _, ref := range []string{"main", "master", "develop", "HEAD"} {
		s := Site{
			Domain: "a.example.com", SiteUser: "a-example", Type: TypeStatic,
			Repo: "git@github.com:me/a.git", Ref: ref,
		}
		if err := s.Validate(); err == nil {
			t.Errorf("ref %q was accepted; branch refs must be rejected", ref)
		}
	}
}

func TestTagAndSHAAccepted(t *testing.T) {
	for _, ref := range []string{"v1.0.0", "release-2026-09-30", "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"} {
		s := Site{
			Domain: "a.example.com", SiteUser: "a-example", Type: TypeStatic,
			Repo: "git@github.com:me/a.git", Ref: ref,
		}
		if err := s.Validate(); err != nil {
			t.Errorf("ref %q rejected: %v", ref, err)
		}
	}
}

func TestUnknownFieldIsFatal(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "typo.yaml", validNode+"\nappProt: 3002\n")
	if _, err := LoadSites(dir); err == nil {
		t.Fatal("a misspelled key was silently ignored")
	}
}

func TestDuplicateDomainRejected(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "a.yaml", validNode)
	writeManifest(t, dir, "b.yaml", validNode)
	if _, err := LoadSites(dir); err == nil {
		t.Fatal("duplicate domain across two manifests was accepted")
	}
}

func TestNodeRequiresPort(t *testing.T) {
	s := Site{
		Domain: "a.example.com", SiteUser: "a-example", Type: TypeNode,
		Repo: "git@github.com:me/a.git", Ref: "v1", NodeVersion: "20",
	}
	if err := s.Validate(); err == nil {
		t.Fatal("nodejs site without appPort was accepted")
	}
}
