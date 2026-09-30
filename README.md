# reconciler

Pulls site manifests from a git repo and makes a CloudPanel host match them.

One-way. GitHub is the source of truth; nothing flows back. CloudPanel-owned
config that has drifted is reported, never repaired.

## Why it works this way

**CloudPanel can be created but not updated.** `clpctl` has `site:add:php`,
`site:add:nodejs`, `site:add:static`, `db:add` and `lets-encrypt:*`. It has no
`site:update`. So provisioning is fully automatic, and *mutating* an existing
site is the only manual step — because the only mechanism available would be
delete-and-recreate, which drops the database.

**Deploys are atomic, including PHP.** Releases are extracted to
`/home/<user>/releases/<sha>` and activated by renaming a symlink over the
docroot. On PHP this needs the FPM pool jail widened from the docroot to the home
directory, which the reconciler does at provision time and re-asserts on every
pass. The usual PHP symlink-deploy hazard — a stale realpath cache serving the
old path after the flip — does not apply, because `open_basedir` disables realpath
caching to prevent symlink attacks. CloudPanel's own hardening buys you correct
swaps.

**The pool file is outside CloudPanel's management**, so a panel upgrade may
reset it. `drift.Check` asserts it every run and reports `critical` if the jail
stops covering `releases/` — otherwise every PHP site would 500 on its next
deploy, silently, until someone shipped.

**Promotion is a commit.** `ref:` must be a tag or full SHA; branch names are
rejected at load time. The agent can push app repos freely; nothing reaches prod
until the `ref:` line moves in the branch-protected infra repo. Rollback is
`git revert` on that commit.

## Layout

```
cmd/reconciler        entrypoint: lock, sync, loop, report
internal/config       daemon config + site manifest schema and validation
internal/cloudpanel   clpctl wrapper, open_basedir widening, password safety
internal/gitops       infra sync, per-site bare mirrors, git archive export
internal/deploy       provision, cert, build, atomic activate, healthcheck, rollback
internal/drift        assertions over CloudPanel-owned config
internal/state        current/previous SHA, cert backoff markers
internal/sh           command execution with privilege dropping
```

## Install

```bash
go build -o /usr/local/bin/reconciler ./cmd/reconciler

install -d -m 0750 /etc/reconciler /var/lib/reconciler /etc/appenv
install -m 0600 examples/config.yaml /etc/reconciler/config.yaml
$EDITOR /etc/reconciler/config.yaml          # serverIPs and botToken are required

install -m 0644 deploy/reconciler.service deploy/reconciler.timer /etc/systemd/system/
install -m 0644 'deploy/app@.service' /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now reconciler.timer
```

Verify before letting it write anything:

```bash
reconciler --dry-run                     # plan only
reconciler --only app.example.com -v     # one site, debug logging
journalctl -u reconciler -f
```

## Operating it

Add a site: commit a manifest to `infra/sites/`. Next pass provisions it,
requests a certificate once DNS points here, and deploys the pinned ref.

Promote a release: bump `ref:`, push to the protected branch.

Roll back: revert that commit. If a healthcheck fails the reconciler rolls back
on its own, to the previous release directory.

Change PHP version or `appPort`: no CLI exists. The reconciler reports drift; do
it in the panel UI, or set `recreate: true` and accept the database loss.

## Things that will bite you

**Let's Encrypt rate limits.** A 2-minute loop plus unpointed DNS exhausts the
per-hostname hourly failure limit fast and locks the domain out for days. Guarded
two ways: DNS is resolved and compared against `serverIPs` before any issuance,
and `certBackoff` (6h default) gates retries. The attempt marker is written
*before* the clpctl call — if the process dies mid-issuance, LE counted it
anyway, so the backoff has to survive our death.

**`$` in passwords.** clpctl interpolates shell variables in password arguments:
a password containing `$` reports success and then silently fails to
authenticate. The generator excludes it, along with backtick, quote and
backslash. There is a test asserting this, because automating provisioning turns
it from a curiosity into a live hazard.

**clpctl's split command set.** Root gets `site:add:*`, `db:add`, `user:*`,
`lets-encrypt:*`. A site user gets `db:export`, `db:import` and friends. `su - clp`
first and you get the wrong set, with `site:add:php` reported as not defined for
a command that plainly exists. The reconciler refuses to start as non-root.

**Migrations are not rolled back.** `rollback` restores code only. Write `release`
steps to be backward compatible with the release before them — expand-then-contract,
never a destructive change in the same deploy that depends on it.

**Verify clpctl flags after a CloudPanel upgrade.** The option set was decoded
from obfuscated source; it is not a stable public interface. Pin the CloudPanel
version and hold updates.

## Secrets

None in the repo. `db:add` generates a password, prints it once, and the operator
writes it into `/etc/appenv/<domain>` — which build and release steps see via
`$APP_ENV_FILE`, and the `app@` unit loads with `EnvironmentFile=`. Drift reports
a missing env file as a warning. Move to sops+age with the key on prod only when
hand-maintaining these gets tedious.

## Adding a webhook later

The timer is the convergence loop and should stay. A webhook only buys latency —
average wait is 60s on a 2-minute poll. If you add one: verify HMAC, then
`systemctl start reconciler.service` and return 200. Read nothing from the
payload; it is a wake-up signal, and the reconciler re-reads git regardless.
Point it at the infra repo only — a webhook on an app repo quietly reintroduces
the agent-to-prod path the `ref:` gate exists to close.
