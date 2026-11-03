"""Forge (project 2) — off-site backups land in the Realliance B2 account."""
import os
import subprocess
import tarfile
import time

from conftest import SECRETS_DIR, _load_env
from forge_helpers import b2_names


def test_db_dump_in_realliance_bucket():
    dumps = [f for f in b2_names("realliance-forge-backups", "spilo/acid-forgejo/") if f["name"].endswith(".sql.gz")]
    assert dumps, "no acid-forgejo logical backup in the Realliance bucket"
    newest = max(f["uploadTimestamp"] for f in dumps) / 1000
    assert time.time() - newest < 26 * 3600


def _newest_dump():
    dumps = [f for f in b2_names("realliance-forge-backups", "dump/") if f["name"].endswith(".tar.gz")]
    return max(dumps, key=lambda f: f["uploadTimestamp"]) if dumps else None


def test_repo_dump_fresh():
    newest = _newest_dump()
    assert newest, "no forgejo dump in the Realliance bucket"
    assert time.time() - newest["uploadTimestamp"] / 1000 < 26 * 3600
    assert newest["size"] > 1024


def test_repo_dump_contents(tmp_path):
    """A dump is a self-contained restore: repos, the database, app.ini — and none of the B2 data."""
    newest = _newest_dump()
    assert newest, "no forgejo dump in the Realliance bucket"
    env = _load_env(SECRETS_DIR / "b2/secrets.env")
    rc = dict(os.environ, RCLONE_CONFIG_M_TYPE="b2", RCLONE_CONFIG_M_ACCOUNT=env["B2_APPLICATION_KEY_ID"],
              RCLONE_CONFIG_M_KEY=env["B2_APPLICATION_KEY"])
    got = subprocess.run(["rclone", "--config", "/dev/null", "copyto",
                          f"m:realliance-forge-backups/{newest['name']}", str(tmp_path / "dump.tar.gz")],
                         env=rc, capture_output=True, text=True, timeout=600)
    assert got.returncode == 0, got.stderr[-300:]
    with tarfile.open(tmp_path / "dump.tar.gz") as tar:
        names = tar.getnames()
    assert any(n.startswith("repos/") for n in names)
    assert any(n.endswith("-db.sql") for n in names) and any(n.endswith("app.ini") for n in names)
    assert not any(n.startswith(("data/lfs/", "data/attachments/", "data/packages/")) for n in names)
