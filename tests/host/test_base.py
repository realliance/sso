"""Task 1 — base hardening of the SSO box."""
import subprocess
import time

from conftest import BOX, GROUP_VARS, OPERATOR_SSH_KEYS

CLOUDFLARE_V4 = GROUP_VARS["cloudflare_ipv4_ranges"]


def test_password_auth_refused():
    r = subprocess.run(
        ["ssh", "-o", "ControlPath=none", "-o", "PubkeyAuthentication=no",
         "-o", "PreferredAuthentications=password", "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10", f"root@{BOX}", "true"],
        capture_output=True,
    )
    assert r.returncode != 0 and b"Permission denied (publickey)" in r.stderr


def test_firewall_services(host):
    # 80/443 are open only to Cloudflare's ranges (rich rules), so the only open service is ssh.
    out = host.check_output("firewall-cmd --list-services").split()
    assert out == ["ssh"]


def test_no_extra_port_rules(host):
    # Packages can open ports on their own (Caddy's left 80/tcp open); only rich rules may open web ports.
    assert host.check_output("firewall-cmd --list-ports").split() == []
    assert host.check_output("firewall-cmd --permanent --list-ports").split() == []


def test_web_ports_only_from_cloudflare(host):
    rules = host.check_output("firewall-cmd --list-rich-rules")
    for cidr in CLOUDFLARE_V4:
        for port in ("80", "443"):
            assert f'source address="{cidr}" port port="{port}" protocol="tcp" accept' in rules


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
