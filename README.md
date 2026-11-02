# realliance/sso

Realliance SSO — Keycloak at <https://sso.realliance.net>, the neutral identity for Realliance apps.
Everything here is applied from Git; nobody configures Keycloak by hand.

**Design:** [luma-homeops/docs/superpowers/specs/2026-10-31-realliance-sso-design.md](https://github.com/ChristopherJMiller/luma-homeops/blob/main/docs/superpowers/specs/2026-10-31-realliance-sso-design.md)
(read its 2026-11-02 amendment) · **Runbook:** [docs/runbook.md](docs/runbook.md)

This repo is public and holds **no secrets, not even encrypted ones**. Secret values live in the
private `realliance/sso-secrets` repo (git-crypt). People live in the private
`realliance/sso-people` repo (it holds email addresses and hidden-project groups).

## How it fits together

| Repo / path | What | Applied by |
|------|------|-----------|
| `host/` | Ansible for the VPS (AlmaLinux 9): hardening, PostgreSQL, Keycloak, Caddy, backups | the box itself (`ansible-pull`, signed commits only) |
| `realm/` | OpenTofu for the `realliance` realm: sign-in flow, MFA, user profile, groups, **apps**, enrolment | the box itself, after the playbook |
| `dns/` | OpenTofu for the `sso` record and Resend's mail records | an operator |
| `b2/` | OpenTofu for the Realliance Backblaze account (state + backup buckets, scoped keys) | an operator |
| `realliance/sso-people` (private) | `people.yaml`: who exists, their groups, active/inactive | the box itself |
| `tests/` | pytest against the live box and realm; `tests/forge/` checks git.realliance.net end to end | operators |

Change anything by PR. Operators (Chris, Connor) review and merge; within a few minutes the box
pulls, verifies the commit signature (an operator's key or GitHub's merge key) and applies.

## Signing in

Users go to an app (or <https://sso.realliance.net>, which opens their account page) and sign in
with **username or email + password**, then a **required second factor**:

- **WebAuthn** — a FIDO2 security key or a passkey (phone, laptop). The default at first sign-in.
- **TOTP** — an authenticator app. First sign-in uses this if their `people.yaml` entry says
  `mfa: totp`.
- **Recovery codes** — optional, generated from the account page.

Anyone can add further factors on their account page and pick between them at sign-in ("Try
another way"). Wrong passwords trigger temporary lockouts (10 failures, waits up to 15 min).
"Forgot password?" on the sign-in page emails a reset link.

> The `master` realm (`/admin/master/console/`) is **only** for the break-glass admins
> `chris-admin` / `connor-admin`. Everyday accounts live in the `realliance` realm.

## Adding a person

In `realliance/sso-people`, add an entry to `people.yaml` and open a PR:

```yaml
  - username: connor              # permanent; lowercase letters, digits, dashes
    active: true
    groups: [/realliance, /apps/forgejo]
    # mfa: totp                   # optional; default is webauthn
    bootstrap:                    # used only when the account is created
      email: connor@example.com
      first_name: Connor
      last_name: Example
```

`bootstrap` seeds the profile once. Afterwards people change their own email and name on their
account page and the box never reverts it; editing `bootstrap` later has no effect.

When applied, Keycloak emails them a one-time link (valid 72 h) to verify their email and set a
password; their first sign-in then sets up MFA. **Deactivate** with `active: false` (the account is
disabled, nothing is deleted). **Removing an entry is refused** — deactivate instead.

## Adding an app

An app is one `module "app"` block in [`realm/apps.tf`](realm/apps.tf). Forgejo (`git.realliance.net`) is the live example:

```hcl
module "forgejo" {
  source               = "./modules/app"
  realm_id             = keycloak_realm.realliance.id
  client_id            = "forgejo"                     # also the access group name: /apps/forgejo
  name                 = "Forgejo"
  redirect_uris        = ["https://git.realliance.net/user/oauth2/realliance/callback"]
  extra_default_scopes = [keycloak_openid_client_scope.groups.name]  # only if the app needs groups
  apps_parent_group_id = keycloak_group.apps.id
}
```

What the module creates:

- an OpenID Connect client `forgejo` (confidential by default, PKCE S256, standard flow only);
- a client role `forgejo.user` and an access group **`/apps/forgejo`** granted that role;
- a sign-in flow for this client that **refuses anyone without `forgejo.user`** — a Realliance
  account alone gets you into nothing.

Then:

1. **Give people access:** add `/apps/forgejo` to their `groups` in `realliance/sso-people`.
2. **Get the client secret** (confidential clients): add `forgejo = module.forgejo.client_secret`
   to the `app_client_secrets` output in [`realm/outputs.tf`](realm/outputs.tf); after the box
   applies, an operator runs `tofu -chdir=realm output -json app_client_secrets` (with
   `sso-secrets/realm/secrets.env` loaded) and hands the secret to the app's owner out of band.
3. **Configure the app** with issuer `https://sso.realliance.net/realms/realliance`, the client
   id, the secret, and scopes `openid profile email` (+ `groups` if requested above).

Options: `access_type = "PUBLIC"` for SPAs/CLIs without a secret; `roles = ["user", "admin"]`
for apps that map extra roles (grant them with more groups). The `groups` claim is a flat list of
group names and is only sent to apps that ask for the `groups` scope, so hidden-project names
never reach other apps.

**Hidden projects:** a hidden project's group and any app for it are declared in
`realliance/sso-people`, never here.

## Lockdown

- No account in the `realliance` realm holds an admin role; only the master-realm break-glass
  admins (password + TOTP) can change Keycloak by hand, and every admin change is logged.
- Password grants are disabled on `admin-cli` (they would skip MFA).
- The box applies Git every few minutes; the daily full run reverts drift.

## Tools

`nix develop` gives the pinned toolchain. Without Nix: OpenTofu ≥ 1.11, Ansible, ansible-lint,
git-crypt, GnuPG, jq, rclone, gh, Python 3 with pytest, pytest-testinfra, requests, PyYAML.
Run tests with `pytest tests --hosts=ssh://root@23.163.0.48` (needs the unlocked secrets repo).
