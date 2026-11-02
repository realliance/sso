"""Task 8 — nightly pg_dump to the object-locked B2 bucket, and sso-restore."""
from datetime import datetime, timezone

from conftest import SECRETS

RCLONE = "set -a; . /etc/realliance-sso/rclone.env; set +a; rclone"
REMOTE = "b2:realliance-sso-backups/keycloak/"


def test_timer_enabled(host):
    timer = host.service("sso-backup.timer")
    assert timer.is_enabled and timer.is_running


def test_backup_run_succeeds(host):
    host.run_expect([0], "systemctl start sso-backup.service")
    assert host.check_output("systemctl show sso-backup.service -p Result") == "Result=success"


def test_backup_newest_object_fresh(host):
    newest = host.check_output(f"{RCLONE} lsf --include 'keycloak-*.dump' {REMOTE} | sort | tail -1")
    assert newest.startswith(f"keycloak-{datetime.now(timezone.utc):%Y-%m-%d}T") and newest.endswith(".dump")


def test_local_retention_at_most_seven(host):
    count = int(host.check_output("ls /var/backups/sso/*.dump | wc -l"))
    assert 1 <= count <= 7


def test_restore_into_scratch_db_matches(host):
    host.run_expect([0], "sso-restore \"$(ls -t /var/backups/sso/*.dump | head -1)\" --target-db keycloak_restore_test")
    count = lambda db: host.check_output(f"sudo -u postgres psql -d {db} -tAc 'select count(*) from user_entity'")
    try:
        assert count("keycloak_restore_test") == count("keycloak")
    finally:
        host.run("sudo -u postgres dropdb --if-exists keycloak_restore_test")


def test_box_uses_restricted_backup_key(host):
    env = host.file("/etc/realliance-sso/rclone.env")
    assert env.mode == 0o600
    assert f"RCLONE_CONFIG_B2_ACCESS_KEY_ID={SECRETS['b2_backup_key_id']}" in env.content_string
