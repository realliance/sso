# Wish list

One line per wish, with its status. A researched wish links to its notes under the table.

| Wish | Status |
|---|---|
| Member invites: a member invites others; `realliance` members send unlimited invites, everyone else gets one ([notes](#member-invites)) | researched 2026-11-05; medium |

## Notes

### Member invites

Chris wants members to bring in people without a PR to `sso-people`.

- **Upstream.** The pinned Keycloak, 26.8.1, has Organizations with email invitations: existing users confirm,
  new addresses register through the invite link, even with realm registration off. Invitations can be
  listed, resent and revoked since 26.5 ([change](https://xata.io/blog/how-we-improved-organization-invites-to-keycloak)).
  Every call needs org-manage rights, so a member can't invite on their own
  ([source](https://github.com/keycloak/keycloak/blob/26.8.1/services/src/main/java/org/keycloak/organization/admin/resource/OrganizationInvitationResource.java)).
  Nothing counts quotas. Phase Two's [`keycloak-orgs`](https://github.com/p2-inc/keycloak-orgs) is
  Elastic-licensed and overlaps native Organizations.
- **Approach.** Turn Organizations back on with one guest org. A small bot holds the quota and calls the
  Keycloak API through a scoped client. Members send as many as they like, within a rate cap. Others get one invite for
  life. Invitees get none, so a chain can't grow. Invitees join the org only: no `realliance`, no app
  access. Promotion stays a PR to `sso-people`. The bot revokes a leaver's pending invites at
  offboarding.
- **Size.** Medium: realm change, bot, tests, runbook.
- **Open.** Lifetime or per-period quota? Does a revoked invite refund? Where do members click? What
  can a guest reach? Does the "no organizations" decision of 2026-11-02 still hold?

