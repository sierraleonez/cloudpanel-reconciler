package cloudpanel

import (
	"strings"
	"testing"
)

func TestHasPath(t *testing.T) {
	cases := []struct {
		jail string
		want string
		ok   bool
	}{
		// CloudPanel's default: scoped to the docroot, which is exactly the
		// configuration that breaks a symlinked release.
		{"/home/app-example/htdocs/app.example.com:/tmp/", "/home/app-example/", false},
		// After widening.
		{"/home/app-example/:/tmp/:/usr/share/php/", "/home/app-example/", true},
		// Missing trailing slash must still match.
		{"/home/app-example:/tmp/", "/home/app-example/", true},
		// A different site's jail must not match.
		{"/home/other-site/:/tmp/", "/home/app-example/", false},
		{"", "/home/app-example/", false},
	}
	for _, c := range cases {
		if got := HasPath(c.jail, c.want); got != c.ok {
			t.Errorf("HasPath(%q, %q) = %v, want %v", c.jail, c.want, got, c.ok)
		}
	}
}

// clpctl interpolates shell variables in password arguments, so a '$' produces a
// password that reports success and then fails to authenticate. Automating
// provisioning makes this a live hazard rather than a curiosity.
func TestGeneratePasswordExcludesDollar(t *testing.T) {
	for i := 0; i < 500; i++ {
		pw, err := GeneratePassword(32)
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(pw, "$`'\"\\") {
			t.Fatalf("generated password contains a shell metacharacter: %q", pw)
		}
		if len(pw) != 32 {
			t.Fatalf("length = %d, want 32", len(pw))
		}
	}
}

func TestGeneratePasswordMinimumLength(t *testing.T) {
	pw, err := GeneratePassword(4)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) < 16 {
		t.Fatalf("short length request produced %d chars; should be floored", len(pw))
	}
}

func TestRedactHidesPasswords(t *testing.T) {
	got := redact([]string{"site:add:php", "--siteUser=x", "--siteUserPassword=hunter2"})
	if strings.Contains(got, "hunter2") {
		t.Fatalf("password leaked into log output: %s", got)
	}
	if !strings.Contains(got, "--siteUser=x") {
		t.Fatalf("redaction ate a non-secret argument: %s", got)
	}
}
