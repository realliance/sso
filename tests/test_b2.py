"""B2 layer — buckets, lifecycle rules, object lock and key scopes in the Realliance account.

Key values never appear in assertion messages: every helper call is bound to a
variable first, and keys travel in environment variables, never in argv.
"""
import functools
import json
import os
import subprocess
import uuid

import pytest
import requests
import yaml

from conftest import REPO, SECRETS_DIR, _load_env

B2 = _load_env(SECRETS_DIR / "b2/secrets.env")
HOST = yaml.safe_load((SECRETS_DIR / "host/secrets.yml").read_text())
S3 = "https://s3.us-east-005.backblazeb2.com"


def _authorize(key_id_name, key_name, source):
    r = requests.get("https://api.backblazeb2.com/b2api/v4/b2_authorize_account",
                     auth=(source[key_id_name], source[key_name]), timeout=20)
    r.raise_for_status()
    return r.json()


@pytest.fixture(scope="module")
def master():
    return _authorize("B2_APPLICATION_KEY_ID", "B2_APPLICATION_KEY", B2)


@pytest.fixture(scope="module")
def backup_auth():
    return _authorize("b2_backup_key_id", "b2_backup_application_key", HOST)


def _api(auth, call, body):
    api = auth["apiInfo"]["storageApi"]["apiUrl"]
    return requests.post(f"{api}/b2api/v4/{call}", headers={"Authorization": auth["authorizationToken"]},
                         json=body, timeout=20)


@pytest.fixture(scope="module")
def buckets(master):
    r = _api(master, "b2_list_buckets", {"accountId": master["accountId"]}).json()
    return {b["bucketName"]: b for b in r["buckets"]}


@functools.cache
def _b2_outputs():
    """`tofu -chdir=b2 output -json`, parsed in memory; key values never reach argv or output."""
    r = subprocess.run(["bash", "-c", f"set -a; . {SECRETS_DIR}/b2/secrets.env; set +a; "
                        "tofu -chdir=b2 output -json"], cwd=REPO, capture_output=True, text=True)
    assert r.returncode == 0, "tofu output failed"
    return {k: v["value"] for k, v in json.loads(r.stdout).items()}


def _forge_key(name):
    out = _b2_outputs()
    return out[f"forge_{name}_key_id"], out[f"forge_{name}_key"]


def rclone(which, *args):
    if which.startswith("forge_"):
        key_id, key = _forge_key(which.removeprefix("forge_"))
    else:
        key_id, key = {"backup": (HOST["b2_backup_key_id"], HOST["b2_backup_application_key"]),
                       "tfstate": (B2["AWS_ACCESS_KEY_ID"], B2["AWS_SECRET_ACCESS_KEY"])}[which]
    env = dict(os.environ, RCLONE_CONFIG_T_TYPE="s3", RCLONE_CONFIG_T_PROVIDER="Other",
               RCLONE_CONFIG_T_ENDPOINT=S3, RCLONE_CONFIG_T_REGION="us-east-005",
               RCLONE_CONFIG_T_NO_CHECK_BUCKET="true",
               RCLONE_CONFIG_T_ACCESS_KEY_ID=key_id, RCLONE_CONFIG_T_SECRET_ACCESS_KEY=key)
    return subprocess.run(["rclone", "--config", "/dev/null", *args], env=env, capture_output=True, text=True)


def test_buckets_private_and_encrypted(buckets):
    for name in ("realliance-sso-tfstate", "realliance-sso-backups"):
        b = buckets[name]
        assert b["bucketType"] == "allPrivate"
        assert b["defaultServerSideEncryption"]["value"]["mode"] == "SSE-B2"


def test_backups_object_lock_30_days(buckets):
    lock = buckets["realliance-sso-backups"]["fileLockConfiguration"]["value"]
    assert lock["isFileLockEnabled"] is True
    assert lock["defaultRetention"]["mode"] == "governance"
    assert lock["defaultRetention"]["period"] == {"duration": 30, "unit": "days"}


def test_backups_lifecycle_keeps_30_dumps(buckets):
    rules = [{k: r.get(k) for k in ("fileNamePrefix", "daysFromUploadingToHiding", "daysFromHidingToDeleting")}
             for r in buckets["realliance-sso-backups"]["lifecycleRules"]]
    assert {"fileNamePrefix": "keycloak/", "daysFromUploadingToHiding": 30, "daysFromHidingToDeleting": 1} in rules


def test_tfstate_versions_kept_90_days(buckets):
    rules = buckets["realliance-sso-tfstate"]["lifecycleRules"]
    assert any(r["fileNamePrefix"] == "" and r["daysFromHidingToDeleting"] == 90 for r in rules)


def test_backup_key_cannot_destroy_a_dump(tmp_path, buckets, backup_auth, master):
    probe = tmp_path / "probe.txt"
    probe.write_text("probe")
    name = f"keycloak/test-probe-{uuid.uuid4().hex[:12]}.txt"  # locked objects are never rewritten
    upload = rclone("backup", "copyto", str(probe), f"t:realliance-sso-backups/{name}")
    assert upload.returncode == 0, upload.stderr
    bucket_id = buckets["realliance-sso-backups"]["bucketId"]
    versions = _api(master, "b2_list_file_versions",
                    {"bucketId": bucket_id, "prefix": name}).json()["files"]
    target = next(v for v in versions if v["action"] == "upload")
    attempt = _api(backup_auth, "b2_delete_file_version",
                   {"fileName": target["fileName"], "fileId": target["fileId"]})
    assert attempt.status_code in (401, 403)  # no deleteFiles capability
    still_there = _api(master, "b2_list_file_versions",
                       {"bucketId": bucket_id, "prefix": name}).json()["files"]
    assert any(v["fileId"] == target["fileId"] for v in still_there)


def test_backup_key_cannot_read_tfstate():
    listing = rclone("backup", "lsf", "t:realliance-sso-tfstate")
    assert listing.returncode != 0


def test_tfstate_key_can_write_and_delete(tmp_path):
    probe = tmp_path / "probe.txt"
    probe.write_text("probe")
    put = rclone("tfstate", "copyto", str(probe), "t:realliance-sso-tfstate/test-probe.txt")
    assert put.returncode == 0, put.stderr
    rm = rclone("tfstate", "deletefile", "t:realliance-sso-tfstate/test-probe.txt")
    assert rm.returncode == 0, rm.stderr


# --- forge (project 2): objects + backups buckets and their keys ------------------------------

def _authorize_forge(name):
    key_id, key = _forge_key(name)
    r = requests.get("https://api.backblazeb2.com/b2api/v4/b2_authorize_account", auth=(key_id, key), timeout=20)
    r.raise_for_status()
    return r.json()


def test_forge_buckets_private_and_encrypted(buckets):
    for name in ("realliance-forge-objects", "realliance-forge-backups"):
        assert buckets[name]["bucketType"] == "allPrivate"
        assert buckets[name]["defaultServerSideEncryption"]["value"]["mode"] == "SSE-B2"


def test_forge_backups_object_lock_30_days(buckets):
    lock = buckets["realliance-forge-backups"]["fileLockConfiguration"]["value"]
    assert lock["isFileLockEnabled"] is True
    assert lock["defaultRetention"]["mode"] == "governance"
    assert lock["defaultRetention"]["period"] == {"duration": 30, "unit": "days"}


def test_forge_backups_lifecycle(buckets):
    rules = {r["fileNamePrefix"]: (r["daysFromUploadingToHiding"], r["daysFromHidingToDeleting"])
             for r in buckets["realliance-forge-backups"]["lifecycleRules"]}
    assert rules == {"spilo/": (30, 1), "dump/": (30, 1)}


def test_forge_objects_hidden_versions_kept_30_days(buckets):
    rules = [(r["fileNamePrefix"], r["daysFromHidingToDeleting"])
             for r in buckets["realliance-forge-objects"]["lifecycleRules"]]
    assert rules == [("", 30)]


def test_forge_keys_scoped(master, buckets):
    expected = {
        "realliance-forge-objects": ("realliance-forge-objects", {"listBuckets", "listFiles", "readFiles", "writeFiles"}),
        "realliance-forge-objects-ro": ("realliance-forge-objects", {"listBuckets", "listFiles", "readFiles"}),
        "realliance-forge-backup": ("realliance-forge-backups", {"listBuckets", "listFiles", "readFiles", "writeFiles"}),
    }
    keys = {k["keyName"]: k for k in _api(master, "b2_list_keys", {"accountId": master["accountId"]}).json()["keys"]}
    for name, (bucket, caps) in expected.items():
        assert keys[name]["bucketIds"] == [buckets[bucket]["bucketId"]], name
        assert set(keys[name]["capabilities"]) == caps, name


def test_forge_objects_key_hides_but_cannot_destroy(tmp_path, buckets, master):
    probe = tmp_path / "probe.txt"
    probe.write_text("probe")
    name = f"test-probe-{uuid.uuid4().hex[:12]}.txt"
    put = rclone("forge_objects", "copyto", str(probe), f"t:realliance-forge-objects/{name}")
    assert put.returncode == 0, put.stderr
    bucket_id = buckets["realliance-forge-objects"]["bucketId"]
    try:
        hide = rclone("forge_objects", "deletefile", f"t:realliance-forge-objects/{name}")  # S3 DeleteObject = hide
        assert hide.returncode == 0, hide.stderr
        versions = _api(master, "b2_list_file_versions", {"bucketId": bucket_id, "prefix": name}).json()["files"]
        assert any(v["action"] == "hide" for v in versions)
        target = next(v for v in versions if v["action"] == "upload")
        attempt = _api(_authorize_forge("objects"), "b2_delete_file_version",
                       {"fileName": target["fileName"], "fileId": target["fileId"]})
        assert attempt.status_code in (401, 403)  # no deleteFiles capability
    finally:
        for v in _api(master, "b2_list_file_versions", {"bucketId": bucket_id, "prefix": name}).json()["files"]:
            _api(master, "b2_delete_file_version", {"fileName": v["fileName"], "fileId": v["fileId"]})


def test_forge_objects_ro_key_cannot_write(tmp_path):
    probe = tmp_path / "probe.txt"
    probe.write_text("probe")
    put = rclone("forge_objects_ro", "copyto", str(probe), "t:realliance-forge-objects/test-ro-probe.txt")
    assert put.returncode != 0


def test_forge_backup_key_cannot_destroy_a_dump(tmp_path, buckets, master):
    probe = tmp_path / "probe.txt"
    probe.write_text("probe")
    name = f"dump/test-probe-{uuid.uuid4().hex[:12]}.txt"  # locked objects are never rewritten
    put = rclone("forge_backup", "copyto", str(probe), f"t:realliance-forge-backups/{name}")
    assert put.returncode == 0, put.stderr
    bucket_id = buckets["realliance-forge-backups"]["bucketId"]
    versions = _api(master, "b2_list_file_versions", {"bucketId": bucket_id, "prefix": name}).json()["files"]
    target = next(v for v in versions if v["action"] == "upload")
    attempt = _api(_authorize_forge("backup"), "b2_delete_file_version",
                   {"fileName": target["fileName"], "fileId": target["fileId"]})
    assert attempt.status_code in (401, 403)
    still_there = _api(master, "b2_list_file_versions", {"bucketId": bucket_id, "prefix": name}).json()["files"]
    assert any(v["fileId"] == target["fileId"] for v in still_there)
