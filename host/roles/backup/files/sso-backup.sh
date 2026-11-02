#!/usr/bin/env bash
# Nightly Keycloak dump to the object-locked B2 bucket. Managed by realliance/sso (host/roles/backup).
# Names carry a UTC timestamp: locked objects can never be rewritten, so names must never repeat.
set -euo pipefail
dir=/var/backups/sso
name="keycloak-$(date -u +%Y-%m-%dT%H%M%SZ).dump"
install -d -m 0700 -o postgres -g postgres "$dir"
sudo -u postgres pg_dump -Fc --file="$dir/$name.partial" keycloak
mv "$dir/$name.partial" "$dir/$name"
# Upload everything not yet in the bucket; --immutable refuses to modify an existing object.
rclone copy --immutable "$dir" b2:realliance-sso-backups/keycloak/ --include 'keycloak-*.dump'
# Keep the newest 7 locally.
ls -1t "$dir"/keycloak-*.dump | tail -n +8 | xargs -r rm -f --
echo "backup ok: $name"
