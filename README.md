# realliance/sso

Realliance SSO — Keycloak at <https://sso.realliance.net>, the neutral identity for Realliance
apps. Passkey-first, invite-only; Google, GitHub, Microsoft and Discord are optional linked logins.

**Design:** [luma-homeops/docs/superpowers/specs/2026-10-31-realliance-sso-design.md](https://github.com/ChristopherJMiller/luma-homeops/blob/main/docs/superpowers/specs/2026-10-31-realliance-sso-design.md)
**Runbook:** [docs/runbook.md](docs/runbook.md)

This repo is public and holds **no secrets, not even encrypted ones**. Secret values live in the
private `realliance/sso-secrets` repo (git-crypt), in GitHub Actions environment secrets, and in a
root-only file on the box.

## Layout

| Path | What | Applied by |
|------|------|-----------|
| `host/` | Ansible for the VPS (AlmaLinux 9): hardening, PostgreSQL, Keycloak, Caddy, backups | `ansible-pull` on the box (signed commits only); operators can push-run in an emergency |
| `realm/` | OpenTofu for the `realliance` realm: flows, linked logins, groups, apps, delegation | GitHub Actions (`plan` on PRs, approved `apply` on `main`) |
| `dns/` | OpenTofu for the `sso.realliance.net` record only | an operator, during a restore |
| `tests/` | pytest: `tests/host` (testinfra over SSH), `tests/realm` (Keycloak admin REST / OIDC) | operators |

## Tools

`nix develop` gives the pinned toolchain. Without Nix, install: OpenTofu ≥ 1.10, Ansible,
ansible-lint, git-crypt, GnuPG, jq, rclone, gh, Python 3 with pytest, pytest-testinfra, requests,
PyYAML.

## Contributing

Operators (Chris, Connor) work in branches and open PRs. Anyone else: fork and open a PR. Commits
to `main` must be signed.
