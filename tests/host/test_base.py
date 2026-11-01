"""Task 1 — base hardening of the SSO box."""
import subprocess
import time

from conftest import BOX, OPERATOR_SSH_KEYS


def test_password_auth_refused():
    r = subprocess.run(
        ["ssh", "-o", "ControlPath=none", "-o", "PubkeyAuthentication=no",
         "-o", "PreferredAuthentications=password", "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10", f"root@{BOX}", "true"],
        capture_output=True,
    )
    assert r.returncode != 0 and b"Permission denied (publickey)" in r.stderr


def test_firewall_services(host):
    out = host.check_output("firewall-cmd --list-services").split()
    assert sorted(out) == ["http", "https", "ssh"]


def test_template_extras_removed(host):
    for pkg in ["httpd", "sendmail", "cockpit"]:
        assert not host.package(pkg).is_installed


def test_journald_capped(host):
    f = host.file("/etc/systemd/journald.conf.d/realliance.conf")
    assert "SystemMaxUse=500M" in f.content_string


def test_operator_keys_installed(host):
    keys = host.file("/root/.ssh/authorized_keys").content_string
    assert all(k.split()[1] in keys for k in OPERATOR_SSH_KEYS)


def test_secrets_file_root_only(host):
    f = host.file("/etc/realliance-sso/secrets.yml")
    assert f.user == "root" and f.mode == 0o600


def test_clock_close_to_operator(host):
    assert abs(int(host.check_output("date +%s")) - int(time.time())) < 5
