#!/usr/bin/env bash
# Restore a Keycloak dump. Managed by realliance/sso (host/roles/backup).
# Usage: sso-restore <local-dump-path | object name in b2:realliance-sso-backups/keycloak/> [--target-db NAME]
#   default target `keycloak`: stops keycloak, recreates the database, restores, starts keycloak.
#   --target-db NAME: restores into NAME without touching the running service (drills, tests).
set -euo pipefail
src=${1:?usage: sso-restore <dump> [--target-db NAME]}; shift
target=keycloak
if [ "${1:-}" = "--target-db" ]; then target=${2:?--target-db needs a name}; fi
if [ ! -f "$src" ]; then
  set -a; . /etc/realliance-sso/rclone.env; set +a
  install -d -m 0700 -o postgres -g postgres /var/backups/sso/restore
  rclone copyto "b2:realliance-sso-backups/keycloak/$(basename "$src")" "/var/backups/sso/restore/$(basename "$src")"
  src="/var/backups/sso/restore/$(basename "$src")"
  chown postgres:postgres "$src"
fi
if [ "$target" = keycloak ]; then systemctl stop keycloak; fi
sudo -u postgres dropdb --if-exists "$target"
sudo -u postgres createdb -O keycloak -E UTF8 "$target"
sudo -u postgres pg_restore --no-owner --role=keycloak -d "$target" "$src"
if [ "$target" = keycloak ]; then systemctl start keycloak; fi
echo "restored $src into $target"
