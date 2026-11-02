"""Forge (project 2) — off-site backups land in the Realliance B2 account."""
import time

from forge_helpers import b2_names


def test_db_dump_in_realliance_bucket():
    dumps = [f for f in b2_names("realliance-forge-backups", "spilo/acid-forgejo/") if f["name"].endswith(".sql.gz")]
    assert dumps, "no acid-forgejo logical backup in the Realliance bucket"
    newest = max(f["uploadTimestamp"] for f in dumps) / 1000
    assert time.time() - newest < 26 * 3600
