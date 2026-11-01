"""Task 4 — Keycloak 26.8.1 as a systemd service behind localhost."""


def test_service_running(host):
    svc = host.service("keycloak")
    assert svc.is_running and svc.is_enabled


def test_ready(host):
    assert '"status": "UP"' in host.check_output("curl -s http://127.0.0.1:9000/health/ready")


def test_http_bound_to_localhost(host):
    assert host.socket("tcp://127.0.0.1:8080").is_listening
    assert not host.socket("tcp://0.0.0.0:8080").is_listening


def test_heap(host):
    assert "-Xmx896m" in host.check_output("ps -o args= -C java")


def test_build_options_persisted(host):
    out = host.check_output("sudo -u keycloak /opt/keycloak/bin/kc.sh show-config")
    assert any(l.split()[:1] == ["kc.db"] and "postgres" in l for l in out.splitlines())


def test_env_file_private(host):
    f = host.file("/etc/keycloak/keycloak.env")
    assert f.mode == 0o600 and f.user == "keycloak"


def test_pinned_version_installed(host):
    assert host.file("/opt/keycloak").linked_to == "/opt/keycloak-26.8.1"
