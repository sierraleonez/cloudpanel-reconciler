// Package sh runs external commands, optionally dropping to an unprivileged
// user. The reconciler runs as root but does all build and release work as the
// site user, so every call site has to be explicit about which it wants.
package sh

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

type Result struct {
	Stdout string
	Stderr string
}

type opts struct {
	user string
	dir  string
	env  []string
}

// Opt configures a single command invocation.
type Opt func(*opts)

// AsUser drops privileges to the named account for the duration of the command.
func AsUser(u string) Opt { return func(o *opts) { o.user = u } }

// InDir sets the working directory.
func InDir(d string) Opt { return func(o *opts) { o.dir = d } }

// WithEnv appends KEY=VALUE pairs to the (deliberately minimal) environment.
func WithEnv(kv ...string) Opt { return func(o *opts) { o.env = append(o.env, kv...) } }

const basePath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Run executes a command and captures its output.
func Run(ctx context.Context, options []Opt, name string, args ...string) (Result, error) {
	o := &opts{}
	for _, f := range options {
		f(o)
	}

	cmd := exec.CommandContext(ctx, name, args...)
	if o.dir != "" {
		cmd.Dir = o.dir
	}

	// Start from an empty environment rather than inheriting the reconciler's.
	// Anything a build needs must be passed in deliberately.
	env := []string{"PATH=" + basePath, "LANG=C.UTF-8"}

	if o.user != "" {
		u, err := user.Lookup(o.user)
		if err != nil {
			return Result{}, fmt.Errorf("lookup user %q: %w", o.user, err)
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return Result{}, fmt.Errorf("parse uid for %q: %w", o.user, err)
		}
		gid, err := strconv.Atoi(u.Gid)
		if err != nil {
			return Result{}, fmt.Errorf("parse gid for %q: %w", o.user, err)
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)},
		}
		env = append(env,
			"HOME="+u.HomeDir,
			"USER="+u.Username,
			"LOGNAME="+u.Username,
		)
	}
	env = append(env, o.env...)
	cmd.Env = env

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return res, fmt.Errorf("%s timed out: %w", name, ctx.Err())
		}
		return res, fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, Truncate(stderr.String(), 1500))
	}
	return res, nil
}

// Bash runs a shell snippet. Reserve this for pipelines; prefer Run elsewhere so
// that arguments are never re-parsed by a shell.
func Bash(ctx context.Context, options []Opt, script string) (Result, error) {
	return Run(ctx, options, "/bin/bash", "-c", script)
}

// Truncate shortens s for log and notification output.
func Truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "… (truncated)"
}
