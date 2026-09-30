// Package state persists the small amount of information the reconciler needs
// to survive a restart: which commit each site is currently serving, what it was
// serving before, and when we last tried to issue a certificate.
//
// This is a cache, not a source of truth. Deleting it costs one redundant
// redeploy, nothing more.
package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Store struct{ root string }

func New(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	return &Store{root: root}, nil
}

func (s *Store) dir(domain string) string { return filepath.Join(s.root, domain) }

func (s *Store) read(domain, key string) (string, error) {
	b, err := os.ReadFile(filepath.Join(s.dir(domain), key))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func (s *Store) write(domain, key, val string) error {
	d := s.dir(domain)
	if err := os.MkdirAll(d, 0o750); err != nil {
		return err
	}
	// Write-then-rename so a crash mid-write cannot leave a truncated SHA.
	tmp := filepath.Join(d, "."+key+".tmp")
	if err := os.WriteFile(tmp, []byte(val+"\n"), 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(d, key))
}

// Current returns the SHA the site is believed to be serving, or "" if unknown.
func (s *Store) Current(domain string) (string, error) { return s.read(domain, "current") }

// Previous returns the SHA served before the last successful activation. This is
// what a failed healthcheck rolls back to.
func (s *Store) Previous(domain string) (string, error) { return s.read(domain, "previous") }

// SetCurrent records a successful activation, demoting the old value.
func (s *Store) SetCurrent(domain, sha string) error {
	prev, err := s.Current(domain)
	if err != nil {
		return err
	}
	if prev != "" && prev != sha {
		if err := s.write(domain, "previous", prev); err != nil {
			return err
		}
	}
	return s.write(domain, "current", sha)
}

// LastCertAttempt reports when issuance was last attempted for domain.
func (s *Store) LastCertAttempt(domain string) (time.Time, error) {
	v, err := s.read(domain, "cert-attempt")
	if err != nil || v == "" {
		return time.Time{}, err
	}
	unix, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}, nil // corrupt marker: treat as never attempted
	}
	return time.Unix(unix, 0), nil
}

// MarkCertAttempt records an issuance attempt. Call this *before* invoking
// clpctl, not after — if the process dies mid-issuance we still want the backoff
// to apply, since Let's Encrypt counts the attempt regardless of whether we
// lived to see the result.
func (s *Store) MarkCertAttempt(domain string) error {
	return s.write(domain, "cert-attempt", strconv.FormatInt(time.Now().Unix(), 10))
}

// Provisioned reports whether we have ever completed provisioning for domain.
func (s *Store) Provisioned(domain string) (bool, error) {
	v, err := s.read(domain, "provisioned")
	return v == "1", err
}

func (s *Store) MarkProvisioned(domain string) error { return s.write(domain, "provisioned", "1") }
