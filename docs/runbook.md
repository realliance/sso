# Realliance SSO runbook

## Placing host secrets

The box reads every secret from `/etc/realliance-sso/secrets.yml` (root, 0600). Its source of
truth is `host/secrets.yml` in the private `realliance/sso-secrets` repo. Place it once on a new
box, and again after changing it:

```bash
cd ~/Repos/realliance-sso-secrets && git-crypt unlock   # if not already
ssh root@sso.realliance.net 'install -d -m 0700 /etc/realliance-sso'
scp host/secrets.yml root@sso.realliance.net:/etc/realliance-sso/secrets.yml
ssh root@sso.realliance.net 'chmod 0600 /etc/realliance-sso/secrets.yml'
```

The playbook refuses to run while the file is missing.
