"""Task 3 — PostgreSQL 16 for Keycloak, local-only."""


def test_pg16_running(host):
    assert host.service("postgresql").is_running
    assert host.check_output("sudo -u postgres psql -tAc 'show server_version'").startswith("16.")


def test_listens_localhost_only(host):
    assert host.socket("tcp://127.0.0.1:5432").is_listening
    assert not host.socket("tcp://0.0.0.0:5432").is_listening


def test_keycloak_role_can_connect(host, secrets):
    pw = secrets["postgres_keycloak_password"]
    host.run_expect([0], f"PGPASSWORD='{pw}' psql -h 127.0.0.1 -U keycloak -d keycloak -c 'select 1'")


def test_memory_settings(host):
    def q(setting):
        return host.check_output(f"sudo -u postgres psql -tAc 'show {setting}'")
    assert q("shared_buffers") == "128MB" and q("max_connections") == "40"
