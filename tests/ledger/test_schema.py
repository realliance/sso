"""The ledger's strict parse and the ledger key's rights: sso_ledger.parse_ledger and check_transition."""
import dataclasses
from pathlib import Path

import pytest
import yaml

import sso_ledger as L

VECTORS = Path(__file__).parent / "vectors"
CREATED = "2026-11-08T00:00:00Z"
SEVEN_DAYS = "2026-11-15T00:00:00Z"
DROP = object()  # a field value that removes the field

# One link in each state; tests edit this text to make exactly one thing wrong.
THREE = """\
version: 1
links:
  - id: l-00000000000000a1
    inviter: member-one
    created: '2026-11-08T00:00:00Z'
    expires: '2026-11-15T00:00:00Z'
    token_sha256: 'a100000000000000000000000000000000000000000000000000000000000001'
    state: pending
  - id: l-00000000000000a2
    inviter: member-one
    created: '2026-11-08T00:00:00Z'
    expires: '2026-11-15T00:00:00Z'
    token_sha256: 'a200000000000000000000000000000000000000000000000000000000000002'
    state: revoked
    revoked: '2026-11-08T01:00:00Z'
  - id: l-00000000000000a3
    inviter: member-two
    created: '2026-11-08T00:00:00Z'
    expires: '2026-11-15T00:00:00Z'
    token_sha256: 'a300000000000000000000000000000000000000000000000000000000000003'
    state: redeemed
    redeemed: '2026-11-09T00:00:00Z'
    guest:
      username: guest-one
      bootstrap:
        email: guest-one@example.invalid
        first_name: Guest
        last_name: One
      mfa: webauthn
      active: true
"""


def code_of(data: bytes | str) -> str:
    with pytest.raises(L.SchemaError) as e:
        L.parse_ledger(data.encode() if isinstance(data, str) else data)
    return e.value.code


def edit(old: str, new: str, text: str = THREE) -> str:
    assert text.count(old) == 1, old
    return text.replace(old, new)


def link(i: int = 1, **over) -> dict:
    d = {"id": f"l-{i:016x}", "inviter": "member-one", "created": CREATED, "expires": SEVEN_DAYS,
         "token_sha256": f"{i:064x}", "state": "pending"}
    d.update(over)
    return {k: v for k, v in d.items() if v is not DROP}


def guest(**over) -> dict:
    g = {"username": "guest-one", "mfa": "webauthn", "active": True,
         "bootstrap": {"email": "guest-one@example.invalid", "first_name": "Guest", "last_name": "One"}}
    g.update(over)
    return {k: v for k, v in g.items() if v is not DROP}


def redeemed(i: int = 2, **guest_over) -> dict:
    return link(i, state="redeemed", redeemed="2026-11-09T00:00:00Z", guest=guest(**guest_over))


def dump(*links: dict, **top) -> bytes:
    """yaml.safe_dump quotes every string that would read as another type, like the service's writer."""
    return yaml.safe_dump({"version": 1, "links": list(links), **top}, sort_keys=False).encode()


def test_minimal_ledger_parses():
    assert L.parse_ledger(b"version: 1\nlinks: []\n") == L.Ledger(1, ())


def test_parses_into_frozen_records():
    led = L.parse_ledger(THREE.encode())
    pending, revoked, done = led.links
    assert pending == L.Link("l-00000000000000a1", "member-one", CREATED, SEVEN_DAYS, "a1" + "0" * 61 + "1",
                             "pending", None, None, None)
    assert (revoked.state, revoked.revoked, revoked.redeemed, revoked.guest) == ("revoked", "2026-11-08T01:00:00Z",
                                                                                None, None)
    assert done.guest == L.Guest("guest-one", L.Bootstrap("guest-one@example.invalid", "Guest", "One"),
                                 "webauthn", True)
    assert done.redeemed == "2026-11-09T00:00:00Z"
    with pytest.raises(dataclasses.FrozenInstanceError):
        done.state = "revoked"
    assert isinstance(led.links, tuple)


def test_unknown_key_refused():
    assert code_of(dump(groups=["/realliance"])) == "unknown-key"
    assert code_of(dump(link(groups=["/realliance"]))) == "unknown-key"
    assert code_of(dump(redeemed(groups=["/realliance"]))) == "unknown-key"
    boot = {"email": "guest-one@example.invalid", "first_name": "Guest", "groups": ["/realliance"]}
    assert code_of(dump(redeemed(bootstrap=boot))) == "unknown-key"


def test_duplicate_key_refused():
    assert code_of("version: 1\nversion: 1\nlinks: []\n") == "duplicate-key"
    assert code_of(edit("      active: true\n", "      active: false\n      active: true\n")) == "duplicate-key"
    assert code_of(edit("        email: guest-one@example.invalid\n",
                        "        email: guest-one@example.invalid\n        'email': other@example.invalid\n")
                   ) == "duplicate-key"


def test_alias_refused():
    assert code_of("version: &v 1\nlinks: []\n") == "alias"                       # an anchor alone
    assert code_of(edit("    inviter: member-two\n", "    inviter: &who member-two\n")
                   .replace("      username: guest-one\n", "      username: *who\n")) == "alias"
    assert code_of("version: 1\nlinks: &l []\nextra: *l\n") == "alias"


def test_unquoted_timestamp_refused():
    assert code_of(edit("    created: '2026-11-08T00:00:00Z'\n    expires: '2026-11-15T00:00:00Z'\n"
                        "    token_sha256: 'a1", "    created: 2026-11-08T00:00:00Z\n"
                        "    expires: '2026-11-15T00:00:00Z'\n    token_sha256: 'a1")) == "type"
    assert code_of(edit("      active: true\n", "      active: yes\n")) == "type"
    assert code_of(edit("      active: true\n", "      active: 'true'\n")) == "type"


def test_other_ambiguous_scalars_refused():
    """Plain scalars that a YAML 1.1 or 1.2 reader takes as something other than a string are refused."""
    assert code_of(edit("    inviter: member-two\n", "    inviter: no\n")) == "type"            # 1.1 bool
    assert code_of(edit("        first_name: Guest\n", "        first_name: 1:20\n")) == "type"   # 1.1 base 60
    assert code_of(edit("'a100000000000000000000000000000000000000000000000000000000000001'",
                        "1000000000000000000000000000000000000000000000000000000000000001")) == "type"
    assert code_of("version: 1.0\nlinks: []\n") == "type"
    assert code_of("version: 0o1\nlinks: []\n") == "type"
    assert code_of("version: true\nlinks: []\n") == "type"
    assert code_of("<<: {version: 1}\nlinks: []\n") == "type"                                   # a merge key
    assert code_of("version: !!int '1'\nlinks: []\n") == "yaml"                                 # explicit tags
    assert code_of("version: 1\nlinks: !!seq []\n") == "yaml"


def test_oversize_refused():
    base = b"version: 1\nlinks: []\n#"
    assert code_of(base + b"x" * (1_048_577 - len(base))) == "too-large"
    assert L.parse_ledger(base + b"x" * (1_048_576 - len(base))) == L.Ledger(1, ())
    assert L.MAX_LEDGER_BYTES == 1_048_576


def test_long_integer_refused():
    """Python refuses to convert an int of more than 4300 digits; the loader must never try."""
    assert code_of(b"version: 1" + b"0" * 5000 + b"\nlinks: []\n") == "type"
    assert code_of(edit("      active: true\n", "      active: " + "9" * 5000 + "\n")) == "type"
    assert code_of(b"version: 1000000000000000000\nlinks: []\n") == "type"     # 19 digits: past the bound
    assert code_of(b"version: 100000000000000000\nlinks: []\n") == "value"     # 18 digits: an int, not 1


def test_expiry_arithmetic_cannot_overflow():
    assert code_of(dump(link(created="9999-12-25T00:00:00Z", expires="9999-12-31T00:00:00Z"))) == "value"
    assert code_of(dump(link(created="9999-12-30T00:00:00Z", expires="9999-12-31T23:59:59Z"))) == "value"
    assert L.parse_ledger(dump(link(created="9999-12-24T00:00:00Z", expires="9999-12-31T00:00:00Z")))


def _mutants(data: bytes, rng, n: int):
    pieces = [b":", b"-", b"? ", b"[", b"]", b"{", b"}", b",", b"&a", b"*a", b"!!", b"|", b">", b"'", b'"', b"%",
              b"@", b"#", b"\n", b"  ", b"\t", b"~", b".", b"0", b"9" * 5000, b"9999-12-31T23:59:59Z", b"<<",
              b"\\", b"\x00", b"\xff", b"\xc3", b"1e9999", b"0x", b"yes", b"null", b"active: true\n"]
    for _ in range(n):
        out = bytearray(data)
        for _ in range(rng.randint(1, 4)):
            at = rng.randrange(len(out) + 1)
            op = rng.randrange(4)
            if op == 0 and out:
                del out[at:at + rng.randint(1, 8)]
            elif op == 1:
                out[at:at] = rng.choice(pieces)
            elif op == 2:
                lines = bytes(out).split(b"\n")
                i = rng.randrange(len(lines))
                lines.insert(i, lines[i])
                out = bytearray(b"\n".join(lines))
            else:
                out[at:at + 1] = rng.choice(pieces)
        yield bytes(out)


def test_parse_raises_only_schema_error():
    """Crafted input either parses or raises SchemaError; never another exception (a seeded mutation sweep)."""
    import random
    rng = random.Random(20261108)
    seeds = [_vector_bytes(e) for e in INDEX if "pad_to" not in e]
    crashes = []
    for s, data in enumerate(seeds):
        for m, mutant in enumerate(_mutants(data, rng, 60)):
            try:
                L.parse_ledger(mutant)
            except L.SchemaError:
                pass
            except Exception as e:  # noqa: BLE001 - the point of the test
                crashes.append(f"seed {s} mutant {m}: {type(e).__name__}")
    assert crashes == []


def test_not_yaml_refused():
    assert code_of("version: 1\nlinks: [\n") == "yaml"
    assert code_of("version: 1\nlinks: []\n---\nversion: 1\nlinks: []\n") == "yaml"
    assert code_of(b"version: 1\nlinks: []\nx: \xff\xfe\n") == "yaml"
    assert code_of("[" * 5000 + "]" * 5000) == "yaml"
    assert code_of("") == "type"
    assert code_of("- version: 1\n") == "type"
    assert code_of("version: 1\nlinks: {}\n") == "type"


def test_mfa_required_and_enum():
    assert code_of(dump(redeemed(mfa=DROP))) == "missing-key"
    for bad in ("none", "", "sms", "WebAuthn"):
        assert code_of(dump(redeemed(mfa=bad))) == "value", bad
    assert code_of(edit("      mfa: webauthn\n", "      mfa: none\n")) == "value"
    assert code_of(edit("      mfa: webauthn\n", "      mfa:\n")) == "type"
    assert L.parse_ledger(dump(redeemed(mfa="totp"))).links[0].guest.mfa == "totp"


def test_expires_at_most_seven_days():
    assert L.parse_ledger(dump(link(expires="2026-11-15T00:00:00Z"))).links[0].expires == SEVEN_DAYS
    assert code_of(dump(link(expires="2026-11-15T00:00:01Z"))) == "value"
    assert code_of(dump(link(expires=CREATED))) == "value"
    assert code_of(dump(link(expires="2026-11-07T00:00:00Z"))) == "value"


def test_required_keys():
    for field in ("id", "inviter", "created", "expires", "token_sha256", "state"):
        assert code_of(dump(link(**{field: DROP}))) == "missing-key", field
    for field in ("username", "bootstrap", "active"):
        assert code_of(dump(redeemed(**{field: DROP}))) == "missing-key", field
    assert code_of(dump(redeemed(bootstrap={"first_name": "Guest"}))) == "missing-key"
    assert code_of(dump(redeemed(bootstrap={"email": "guest-one@example.invalid"}))) == "missing-key"
    assert code_of(b"links: []\n") == "missing-key"
    assert code_of(b"version: 1\n") == "missing-key"


def test_types():
    assert code_of(b"version: '1'\nlinks: []\n") == "type"
    assert code_of(dump(link(inviter=["member-one"]))) == "type"
    assert code_of(dump(link(created=None))) == "type"
    assert code_of(dump(redeemed(username=7))) == "type"
    assert code_of(dump(redeemed(bootstrap={"email": "g@example.invalid", "first_name": "G", "last_name": None}))
                   ) == "type"
    assert code_of(dump(redeemed(bootstrap="guest-one@example.invalid"))) == "type"
    assert code_of(dump(redeemed(active="true"))) == "type"
    assert code_of(dump(link(guest=None))) == "type"
    assert code_of(b"version: 1\nlinks: [l-0000000000000001]\n") == "type"


def test_formats():
    ok = L.parse_ledger(dump(link(1), link(2, state="revoked", revoked=CREATED), redeemed(3)))
    assert [x.state for x in ok.links] == ["pending", "revoked", "redeemed"]
    bad = [
        link(id="l-0000000000000001x"), link(id="l-000000000000001"), link(id="L-0000000000000001"),
        link(id="l-000000000000000G"), link(id="l-00000000000000A1"), link(id="x-0000000000000001"),
        link(token_sha256="a" * 63), link(token_sha256="a" * 65), link(token_sha256="A" * 64),
        link(token_sha256="g" * 64),
        link(state="expired"), link(state="Pending"), link(state=""),
        link(created="2026-11-08 00:00:00Z"), link(created="2026-11-08T00:00:00"),
        link(created="2026-11-08T00:00:00.5Z"), link(created="2026-11-08T00:00:00+00:00"),
        link(created="2026-02-30T00:00:00Z", expires="2026-03-01T00:00:00Z"),
        link(created="２０２６-11-08T00:00:00Z"),                                      # non-ASCII digits
        link(redeemed="2026-11-09T00:00:00Z"),                                         # pending, redeemed time
        link(revoked="2026-11-09T00:00:00Z"),
        link(guest=guest()),
        link(state="revoked"),                                                         # revoked, no time
        link(state="revoked", revoked=CREATED, redeemed=CREATED),
        link(state="revoked", revoked=CREATED, guest=guest()),
        link(state="redeemed", redeemed=CREATED),                                      # redeemed, no guest
        link(state="redeemed", guest=guest()),                                         # redeemed, no time
        link(state="redeemed", redeemed=CREATED, revoked=CREATED, guest=guest()),
        link(state="redeemed", redeemed="2026-11-09", guest=guest()),
    ]
    for i, b in enumerate(bad):
        assert code_of(dump(b)) == "value", i
    assert code_of(dump(link(1), link(1, token_sha256="b" * 64))) == "value"          # one id twice
    assert code_of(b"version: 2\nlinks: []\n") == "value"


def test_no_last_name():
    boot = {"email": "guest-one@example.invalid", "first_name": "Guest"}
    assert L.parse_ledger(dump(redeemed(bootstrap=boot))).links[0].guest.bootstrap == L.Bootstrap(
        "guest-one@example.invalid", "Guest", None)


def test_errors_never_echo_values():
    """SchemaError text reaches logs: it names keys, links and lines, never a value from the file."""
    for data in (dump(redeemed(mfa="guest-one@example.invalid")),
                 dump(redeemed(bootstrap={"email": "guest-one@example.invalid", "first_name": ["Guest"]})),
                 dump(redeemed(**{"guest-one@example.invalid": 1})),
                 b"version: 1\nlinks:\n  - id: guest-one@example.invalid\n",
                 b"version: 1\nlinks: [\n  guest-one@example.invalid: 'x\n"):
        with pytest.raises(L.SchemaError) as e:
            L.parse_ledger(data)
        text = str(e.value)
        assert "guest-one" not in text and "example" not in text, e.value.code


# --- the ledger key's rights -----------------------------------------------------------------------------

def led(*links: dict, version: int = 1) -> "L.Ledger":
    return L.parse_ledger(yaml.safe_dump({"version": version, "links": list(links)}).encode())


def refusal(before, after) -> tuple[str, str | None]:
    with pytest.raises(L.TransitionError) as e:
        L.check_transition(before, after)
    return e.value.code, e.value.link_id


PENDING = link(1)
REDEEMED = redeemed(2)
REVOKED = link(3, state="revoked", revoked="2026-11-08T01:00:00Z")
INACTIVE = redeemed(4, active=False, username="guest-two")
B = led(PENDING, REDEEMED, REVOKED, INACTIVE)
ID = {n: f"l-{n:016x}" for n in range(1, 6)}

ALLOWED = {
    "nothing changes": led(PENDING, REDEEMED, REVOKED, INACTIVE),
    "add a pending link": led(PENDING, REDEEMED, REVOKED, INACTIVE, link(5)),
    "pending to revoked": led(link(1, state="revoked", revoked="2026-11-09T00:00:00Z"), REDEEMED, REVOKED,
                              INACTIVE),
    "pending to redeemed, active": led(redeemed(1, username="guest-three"), REDEEMED, REVOKED, INACTIVE),
    "active true to false": led(PENDING, redeemed(2, active=False), REVOKED, INACTIVE),
    "links reordered": led(INACTIVE, REVOKED, REDEEMED, PENDING),
}

REFUSED = {
    "reactivate": (led(PENDING, REDEEMED, REVOKED, redeemed(4, username="guest-two")), ("reactivate", ID[4])),
    "drop a link": (led(PENDING, REDEEMED, INACTIVE), ("removal", ID[3])),
    "change an id": (led(link(5), REDEEMED, REVOKED, INACTIVE), ("removal", ID[1])),
    "change version": (dataclasses.replace(B, version=2), ("version", None)),
    "redeem inactive": (led(redeemed(1, active=False, username="guest-three"), REDEEMED, REVOKED, INACTIVE),
                        ("not-allowed", ID[1])),
    "revoked to pending": (led(PENDING, REDEEMED, link(3), INACTIVE), ("not-allowed", ID[3])),
    "revoked to redeemed": (led(PENDING, REDEEMED, redeemed(3), INACTIVE), ("not-allowed", ID[3])),
    "redeemed to revoked": (led(PENDING, link(2, state="revoked", revoked=CREATED), REVOKED, INACTIVE),
                            ("not-allowed", ID[2])),
    "redeemed to pending": (led(PENDING, link(2), REVOKED, INACTIVE), ("not-allowed", ID[2])),
    "add a redeemed link": (led(PENDING, REDEEMED, REVOKED, INACTIVE, redeemed(5)), ("not-allowed", ID[5])),
    "add a revoked link": (led(PENDING, REDEEMED, REVOKED, INACTIVE, link(5, state="revoked", revoked=CREATED)),
                           ("not-allowed", ID[5])),
}
IMMUTABLE = {
    "inviter": led(link(1, inviter="member-two"), REDEEMED, REVOKED, INACTIVE),
    "created": led(link(1, created="2026-11-08T00:00:01Z"), REDEEMED, REVOKED, INACTIVE),
    "expires": led(link(1, expires="2026-11-14T00:00:00Z"), REDEEMED, REVOKED, INACTIVE),
    "token_sha256": led(link(1, token_sha256="b" * 64), REDEEMED, REVOKED, INACTIVE),
    "redeemed": led(PENDING, link(2, state="redeemed", redeemed="2026-11-10T00:00:00Z", guest=guest()), REVOKED,
                    INACTIVE),
    "revoked": led(PENDING, REDEEMED, link(3, state="revoked", revoked="2026-11-10T00:00:00Z"), INACTIVE),
    "guest.username": led(PENDING, redeemed(2, username="guest-nine"), REVOKED, INACTIVE),
    "guest.mfa": led(PENDING, redeemed(2, mfa="totp"), REVOKED, INACTIVE),
    "guest.bootstrap.email": led(PENDING, redeemed(2, bootstrap={"email": "nine@example.invalid",
                                                                 "first_name": "Guest", "last_name": "One"}),
                                 REVOKED, INACTIVE),
    "guest.bootstrap.first_name": led(PENDING, redeemed(2, bootstrap={"email": "guest-one@example.invalid",
                                                                      "first_name": "Nine", "last_name": "One"}),
                                      REVOKED, INACTIVE),
    "guest.bootstrap.last_name": led(PENDING, redeemed(2, bootstrap={"email": "guest-one@example.invalid",
                                                                     "first_name": "Guest"}), REVOKED, INACTIVE),
}


@pytest.mark.parametrize("name", list(ALLOWED))
def test_ledger_key_transitions_allowed(name):
    assert L.check_transition(B, ALLOWED[name]) is None


@pytest.mark.parametrize("name", list(REFUSED))
def test_ledger_key_transitions_refused(name):
    after, expect = REFUSED[name]
    assert refusal(B, after) == expect


@pytest.mark.parametrize("field", list(IMMUTABLE))
def test_ledger_key_transitions_immutable(field):
    code, link_id = refusal(B, IMMUTABLE[field])
    assert code == "immutable"
    assert link_id in (ID[1], ID[2], ID[3])


def test_ledger_key_transitions():
    """The brief's table in one place: every allowed change passes and every refused one names its code."""
    assert all(L.check_transition(B, a) is None for a in ALLOWED.values())
    assert {n: refusal(B, a)[0] for n, (a, _) in REFUSED.items()} == {n: c for n, (_, (c, _)) in REFUSED.items()}
    assert {refusal(B, a)[0] for a in IMMUTABLE.values()} == {"immutable"}
    e = L.TransitionError("removal", "l-0000000000000001")
    assert (e.code, e.link_id) == ("removal", "l-0000000000000001")


# --- shared vectors ----------------------------------------------------------------------------------------

def _vector_bytes(entry: dict) -> bytes:
    data = (VECTORS / entry["file"]).read_bytes()
    if "pad_to" in entry:
        pad = entry["pad_to"] - len(data)
        assert pad >= 2, entry["file"]
        data += b"#" + b" " * (pad - 2) + b"\n"
        assert len(data) == entry["pad_to"]
    return data


INDEX = yaml.safe_load((VECTORS / "index.yaml").read_text())


@pytest.mark.parametrize("entry", INDEX, ids=[e["file"] for e in INDEX])
def test_vectors(entry):
    data = _vector_bytes(entry)
    if entry["expect"] == "ok":
        assert isinstance(L.parse_ledger(data), L.Ledger)
    else:
        assert code_of(data) == entry["expect"]


def test_vectors_cover_every_code():
    codes = {e["expect"] for e in INDEX}
    assert codes == {"ok"} | L.SchemaError.CODES
    files = {p.name for p in VECTORS.glob("*.yaml")} - {"index.yaml"}
    assert files == {e["file"] for e in INDEX}
