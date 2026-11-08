"""The box's command line: sso_ledger.main (walk, content, settle, seed, forget, fallback).

Real git and GnuPG as in the other ledger tests; Keycloak is a fake Directory and the clock is fixed. walk stores
what the walk returned and nothing when it raised; content writes the guests var-file, content.json and state."""
import ast
import dataclasses
import json
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import sso_ledger as L

from .conftest import SEED_PEOPLE, SRC, guest_doc, ledger_yaml, link_doc

NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
CONTENT_FIELDS = {"mode", "ledger", "admitted", "would_admit", "refused_entries", "deferred", "statuses"}


class FakeDirectory:
    def __init__(self):
        self.users, self.emails = set(), set()

    def username_taken(self, u):
        return u in self.users

    def email_taken(self, e):
        return e in self.emails


class Box:
    """One box: a people repo, its keyring and trust file, a state directory and a fixed clock."""

    def __init__(self, repo, keys, keyring, tmp_path, monkeypatch):
        self.repo, self.keyring = repo, keyring
        self.trust = tmp_path / "people-trust.json"
        self.trust.write_text(json.dumps({"operators": [keys["operator"].fpr], "ledger": [keys["ledger"].fpr]}))
        self.state = tmp_path / "state"
        self.secret = tmp_path / "ledger-lookup.secret"
        self.secret.write_text("not-a-real-secret\n")
        self.now = NOW
        self.directory = FakeDirectory()
        self.made = []
        monkeypatch.setattr(L, "_now", lambda: self.now)

        def directory(url, secret_file):
            self.made.append((url, Path(secret_file)))
            return self.directory
        monkeypatch.setattr(L, "KeycloakDirectory", directory)

    def walk(self, head, mode="apply", anchor=None, state=None, dry=False) -> int:
        return L.main(["walk", "--mode", mode, "--repo", str(self.repo.path), "--head", head,
                       "--state", str(state or self.state), "--keyring", str(self.keyring), "--trust", str(self.trust),
                       "--anchor", anchor or self.repo.seed] + (["--dry"] if dry else []))

    def content(self, mode="apply", state=None, dry=False) -> int:
        st = state or self.state
        return L.main(["content", "--mode", mode, "--repo", str(self.repo.path), "--walk", str(st / "walk.json"),
                       "--state", str(st), "--keycloak-url", "https://sso.example.invalid",
                       "--keycloak-secret-file", str(self.secret)] + (["--dry"] if dry else []))

    def run(self, head, mode="apply", **kw):
        assert self.walk(head, mode, **kw) == 0
        kw.pop("anchor", None)
        assert self.content(mode, **kw) == 0

    def read(self, name, state=None):
        return json.loads(((state or self.state) / name).read_text())


@pytest.fixture
def box(people_repo, keys, keyring, tmp_path, monkeypatch):
    return Box(people_repo, keys, keyring, tmp_path, monkeypatch)


def plain(v: L.WalkVerdict) -> dict:
    return json.loads(json.dumps(dataclasses.asdict(v)))


def redeem(box, i=1, **guest):
    """Two ledger-key commits, as the service makes them: a pending link, then its redemption."""
    links = [link_doc(j) for j in range(1, i)]
    box.repo.commit({"ledger.yaml": ledger_yaml(*links, link_doc(i))}, "ledger")
    g = guest_doc(**{"username": f"guest-{i:02d}", **guest})
    return box.repo.commit({"ledger.yaml": ledger_yaml(*links, link_doc(i, state="redeemed", guest=g))}, "ledger")


# --- walk --------------------------------------------------------------------------------------------------------

def test_walk_writes_verdict(box, keyring, trust, tmp_path):
    a = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1))}, "ledger")
    assert box.walk(a) == 0
    w = box.read("walk.json")
    v = L.walk(box.repo.path, a, box.repo.seed, keyring, trust)
    assert {k: w[k] for k in plain(v)} == plain(v)
    assert w["apply_commit"] == a and w["valid"] is True and w["mode"] == "apply"
    assert w["ledger_chain"] == [[a, "ledger"]]
    # A freeze: no apply in apply mode.
    bad = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web\n"}, "web-flow")
    assert box.walk(bad) == 0
    w = box.read("walk.json")
    assert w["valid"] is False and w["apply_commit"] is None and w["reason"] == f"invalid:untrusted-signer@{bad[:7]}"
    assert w["ledger_chain"] is None
    # Check mode applies people.yaml from newest_trusted.
    other = tmp_path / "check-state"
    assert box.walk(bad, mode="check", state=other) == 0
    w = box.read("walk.json", other)
    assert w["valid"] is False and w["apply_commit"] == w["newest_trusted"] == a and w["mode"] == "check"
    assert box.walk(a, mode="check", state=tmp_path / "check-2") == 0
    assert box.read("walk.json", tmp_path / "check-2")["apply_commit"] == a


def test_seen_heads_stored_empty_after_valid_walk(box):
    a = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1))}, "ledger")
    assert box.walk(a) == 0
    st = box.read("state.json")
    assert "seen_heads" in st and st["seen_heads"] == [] and st["last_good"] == a
    # Frozen, then recovered: the list is stored as [] again, the key never dropped.
    bad = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web\n"}, "web-flow")
    assert box.walk(bad) == 0 and box.read("state.json")["seen_heads"] == [bad]
    fix = box.repo.commit({"people.yaml": SEED_PEOPLE}, "operator",
                          message=f"Revert\n\nReviewed-Range: {a}..{bad}\n")
    assert box.walk(fix) == 0
    st = box.read("state.json")
    assert st["seen_heads"] == [] and st["last_good"] == fix


def test_seen_heads_stored_from_the_verdict_after_a_freeze(box, keyring, trust, monkeypatch):
    a = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1))}, "ledger")
    assert box.walk(a) == 0
    bad = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web\n"}, "web-flow")
    assert box.walk(bad) == 0
    assert box.read("state.json")["seen_heads"] == L.walk(box.repo.path, bad, a, keyring, trust).seen_heads == [bad]
    worse = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web 2\n"}, "web-flow")
    assert box.walk(worse) == 0
    assert box.read("state.json")["seen_heads"] == [bad, worse] == box.read("walk.json")["seen_heads"]
    # Whatever the walk returns is what is stored: the command never builds a list from the raw head.
    real = L.walk
    monkeypatch.setattr(L, "walk", lambda *a_, **kw: dataclasses.replace(real(*a_, **kw), seen_heads=[box.repo.seed]))
    later = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web 3\n"}, "web-flow")
    assert box.walk(later) == 0
    assert box.read("state.json")["seen_heads"] == [box.repo.seed] == box.read("walk.json")["seen_heads"]


@pytest.mark.parametrize("error", [L.GitError("git rev-list exited 128"), subprocess.TimeoutExpired(["git"], 30),
                                   ValueError("expected a full lowercase commit sha"), OSError("gone")])
def test_walk_exception_keeps_state(error, box, monkeypatch):
    a = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1))}, "ledger")
    assert box.walk(a) == 0
    bad = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web\n"}, "web-flow")
    assert box.walk(bad) == 0                                                   # a seen-heads list to keep
    before = (box.state / "state.json").read_bytes()

    def raising(*args, **kw):
        raise error
    monkeypatch.setattr(L, "walk", raising)
    head = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# next\n"}, "operator")
    assert box.walk(head) == 2
    assert (box.state / "state.json").read_bytes() == before
    assert not (box.state / "walk.json").exists()                               # content can't run on a stale walk
    assert box.content() == 2
    # With no state at all, a raising walk leaves none behind.
    fresh = box.state.parent / "fresh"
    assert box.walk(head, state=fresh) == 2 and not (fresh / "state.json").exists()


def test_walk_killed_writes_nothing(box, tmp_path):
    """A walk the caller's timeout kills (bash's `timeout`) leaves state.json as it was: nothing is written
    before the walk returns."""
    a = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1))}, "ledger")
    assert box.walk(a) == 0
    before = (box.state / "state.json").read_bytes()
    head = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# next\n"}, "operator")
    script = tmp_path / "slow_walk.py"
    script.write_text(
        "import importlib.util, sys, time\n"
        f"spec = importlib.util.spec_from_file_location('sso_ledger', {str(SRC)!r})\n"
        "m = importlib.util.module_from_spec(spec); sys.modules['sso_ledger'] = m; spec.loader.exec_module(m)\n"
        "m.walk = lambda *a, **k: time.sleep(60)\n"
        "sys.exit(m.main(sys.argv[1:]))\n")
    argv = [sys.executable, str(script), "walk", "--mode", "apply", "--repo", str(box.repo.path), "--head", head,
            "--state", str(box.state), "--keyring", str(box.keyring), "--trust", str(box.trust),
            "--anchor", box.repo.seed]
    with pytest.raises(subprocess.TimeoutExpired):
        subprocess.run(argv, capture_output=True, timeout=3)
    assert (box.state / "state.json").read_bytes() == before


def test_walk_command_reads_git_only(box, monkeypatch):
    """D2: the walk command, ledger_chain included, reads git objects and signatures and never parses YAML,
    so a ledger.yaml crafted to crash a parser can't stop it."""
    box.repo.commit({"ledger.yaml": b"&a x: *a\n"}, "ledger")
    head = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# operator\n"}, "operator")

    def no_yaml(*_args, **_kw):
        raise AssertionError("the walk command parsed YAML")
    for name in ("load", "safe_load"):
        monkeypatch.setattr(L.yaml, name, no_yaml)
    monkeypatch.setattr(L, "parse_ledger", no_yaml)
    monkeypatch.setattr(L._Loader, "get_single_data", no_yaml)
    assert box.walk(head) == 0
    w = box.read("walk.json")
    assert w["valid"] is True and [s for _c, s in w["ledger_chain"]] == ["ledger", "operator"]


def test_first_run_and_rebuild_seed_from_anchor_with_empty_list(box, monkeypatch):
    anchor = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# applied before the changeover\n"}, "web-flow")
    bad = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web\n"}, "web-flow")
    op = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# operator\n"}, "operator")
    calls, real = [], L.walk

    def recording(repo, head, last_good, keyring, trust, seen_heads=None):
        calls.append((head, last_good, list(seen_heads or [])))
        return real(repo, head, last_good, keyring, trust, seen_heads=seen_heads)
    monkeypatch.setattr(L, "walk", recording)
    # A first run: last good is the anchor itself, the list empty, even with an operator commit after it.
    assert box.walk(op, anchor=anchor) == 0
    assert calls == [(op, anchor, [])]
    st = box.read("state.json")
    assert (st["last_good"], st["last_good_ledger"]) == (anchor, anchor)        # frozen at bad: never op
    assert st["seen_heads"] == [op] and box.read("walk.json")["reason"] == f"invalid:untrusted-signer@{bad[:7]}"
    # A rebuild: state seeded with admitted guests but no last good starts the same way.
    rebuilt = box.state.parent / "rebuilt"
    out = box.state.parent / "guests-output.json"
    out.write_text(json.dumps({"guest-a": {"active": True, "mfa": "webauthn", "bootstrap": None}}))
    assert L.main(["seed", "--state", str(rebuilt), "--from", str(out)]) == 0
    assert box.walk(op, anchor=anchor, state=rebuilt) == 0
    assert calls[-1] == (op, anchor, [])
    st = box.read("state.json", rebuilt)
    assert (st["last_good"], st["last_good_ledger"], st["seen_heads"]) == (anchor, anchor, [op])
    assert set(st["admitted"]) == {"guest-a"}
    # At the anchor itself: last good the anchor, the list empty.
    at_anchor = box.state.parent / "at-anchor"
    assert box.walk(anchor, anchor=anchor, state=at_anchor) == 0
    st = box.read("state.json", at_anchor)
    assert (st["last_good"], st["last_good_ledger"], st["seen_heads"]) == (anchor, anchor, [])
    # Once state exists the anchor is never read again.
    assert box.walk(op, anchor=box.repo.seed, state=at_anchor) == 0
    assert calls[-1] == (op, anchor, [])


def test_drills_state_separate(box):
    r = redeem(box, 1)
    box.run(r)
    main_files = {p.name: p.read_bytes() for p in box.state.iterdir()}
    assert box.read("state.json")["admitted"].keys() == {"guest-01"}
    drills = box.state.parent / "drills"
    d1 = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1, state="redeemed", guest=guest_doc("guest-01")),
                                                     link_doc(2))}, "ledger", parents=[r])
    d2 = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1, state="redeemed", guest=guest_doc("guest-01")),
                                                     link_doc(2, state="redeemed", guest=guest_doc("guest-02")))},
                         "ledger")
    box.directory.users.add("guest-01")                                         # main's guest, in Keycloak
    assert box.walk(d2, anchor=r, state=drills, dry=True) == 0
    assert box.content(state=drills, dry=True) == 0
    st = box.read("state.json", drills)
    assert (st["last_good"], st["seen_heads"], st["last_good_ledger"]) == (d2, [], d2)
    assert st["admitted"] == {} and st["refused"] == {}
    assert not (drills / "guests.next.json").exists()
    c = box.read("content.json", drills)
    assert c["would_admit"] == ["guest-02"] and c["admitted"] == []
    assert c["refused_entries"] == {"l-0000000000000001": "username-taken"}
    # A deliberately bad drill commit freezes the drills state alone.
    d3 = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# drill\n"}, "web-flow")
    assert box.walk(d3, anchor=r, state=drills, dry=True) == 0 and box.content(state=drills, dry=True) == 0
    st = box.read("state.json", drills)
    assert (st["last_good"], st["seen_heads"]) == (d2, [d3])
    assert box.read("content.json", drills)["statuses"]["apply"]["state"] == "failure"
    assert {p.name: p.read_bytes() for p in box.state.iterdir()} == main_files
    assert d1


# --- statuses ------------------------------------------------------------------------------------------------

def test_status_prints_seen_list(box):
    a = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1))}, "ledger")
    box.run(a)
    w1 = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web 1\n"}, "web-flow")
    box.run(w1)
    w2 = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web 2\n"}, "web-flow")
    box.run(w2)
    apply = box.read("content.json")["statuses"]["apply"]
    assert apply == {"state": "failure",
                     "description": f"frozen: invalid:untrusted-signer@{w1[:7]}; seen: {w1[:7]},{w2[:7]}"}
    assert box.read("walk.json")["seen_heads"] == [w1, w2]
    # Thirty seen heads: as many as fit, then a count; walk.json keeps them all.
    st = box.read("state.json")
    st["seen_heads"] = [f"{i:040x}" for i in range(1, 31)]
    (box.state / "state.json").write_text(json.dumps(st))
    for mode in ("apply", "check"):
        box.run(w2, mode=mode)
        desc = box.read("content.json")["statuses"]["apply"]["description"]
        seen = box.read("walk.json")["seen_heads"]
        assert len(seen) == 31 and len(desc) <= 140
        shown = desc.rsplit("; seen: ", 1)[1]
        listed, more = shown.rsplit(" (+", 1)
        assert listed.split(",") == [s[:7] for s in seen][:len(listed.split(","))]
        assert int(more.rstrip(")")) == 31 - len(listed.split(","))
        assert desc.startswith("check: would be frozen: " if mode == "check" else "frozen: ")
        assert box.read("walk.json")["fallback_statuses"]["apply"]["description"] == desc


def test_descriptions_fit_a_status():
    reasons = ["not-first-parent-descendant@0123456", "recovery-misses@abcdef0", "x" * 300]
    seen = [f"{i:040x}" for i in range(30)]
    refused = {f"l-{i:016x}": "name-format" for i in range(30)}
    for mode in ("apply", "check"):
        for reason in reasons:
            frozen = L.WalkVerdict(head=seen[-1], last_good="a" * 40, valid=False, reason=reason, chain=[],
                                   invalid=[], recovery=None, newest_trusted="a" * 40, seen_heads=seen)
            st = L.statuses(mode, frozen, L.LedgerVerdict("a" * 40, False, None), L.Decision([], [], {}, {}, {}))
            assert all(len(s["description"]) <= 140 for s in st.values()), st
            valid = dataclasses.replace(frozen, valid=True, reason=None, last_good=seen[-1], seen_heads=[])
            for lv in (L.LedgerVerdict(seen[-1], False, None), L.LedgerVerdict("a" * 40, True, f"schema:{reason}")):
                d = L.Decision([f"guest-{i:02d}" for i in range(30)], [], refused, dict(refused), {})
                st = L.statuses(mode, valid, lv, d)
                assert all(len(s["description"]) <= 140 for s in st.values()), st
                assert all(s["state"] in ("success", "failure", "pending") for s in st.values())
    d = L.Decision(["g-1"], [], {"l-1": "quota", "l-2": "expired"}, {"l-3": "cap"}, {})
    v = L.WalkVerdict("b" * 40, "b" * 40, True, None, [], [], None, "b" * 40, [])
    assert L.statuses("apply", v, L.LedgerVerdict("b" * 40, False, None), d) == {
        "apply": {"state": "success", "description": "applied: 1 admitted, 2 refused, 1 deferred"},
        "ledger": {"state": "success", "description": "applied: 1 admitted, 2 refused, 1 deferred"}}
    assert L.statuses("check", v, L.LedgerVerdict("a" * 40, True, "transition:removal@1234567"),
                      dataclasses.replace(d, admitted_now=[], would_admit=["g-1"]))["ledger"] == \
        {"state": "failure", "description": "check: would be ledger refused: transition:removal@1234567"}


def test_descriptions_fit_with_thirty_refused_entries(box):
    """Through the command line: an operator adds thirty redemptions Keycloak would reject."""
    links = [link_doc(i, state="redeemed", guest=guest_doc(f"guest-{i:02d}", first_name=f"Bad<{i}"))
             for i in range(1, 31)]
    head = box.repo.commit({"ledger.yaml": ledger_yaml(*links)}, "operator")
    box.run(head)
    c = box.read("content.json")
    assert len(c["refused_entries"]) == 30 and set(c["refused_entries"].values()) == {"name-format"}
    assert all(len(s["description"]) <= 140 for s in c["statuses"].values())
    assert c["statuses"]["apply"]["description"] == "applied: 0 admitted, 30 refused, 0 deferred"


# --- content -----------------------------------------------------------------------------------------------------

def test_content_writes_outputs(box):
    a = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1))}, "ledger")
    box.run(a)
    assert box.read("guests.next.json") == {"guests": {}}
    r = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1, state="redeemed", guest=guest_doc("guest-01")))},
                        "ledger")
    box.now = NOW + timedelta(hours=1)
    box.run(r)
    for name in ("guests.next.json", "content.json", "state.json", "walk.json"):
        assert stat.S_IMODE((box.state / name).stat().st_mode) == 0o600, name
    assert box.read("guests.next.json") == {"guests": {"guest-01": {
        "active": True, "mfa": "webauthn",
        "bootstrap": {"email": "guest-01@guests.invalid", "first_name": "Guestname", "last_name": None}}}}
    c = box.read("content.json")
    assert set(c) == CONTENT_FIELDS
    assert c["mode"] == "apply" and c["ledger"] == {"effective": r, "refused": False, "reason": None}
    assert (c["admitted"], c["would_admit"], c["refused_entries"], c["deferred"]) == (["guest-01"], [], {}, {})
    assert c["statuses"] == {"apply": {"state": "success", "description": "applied: 1 admitted, 0 refused, 0 deferred"},
                             "ledger": {"state": "success", "description": "applied: 1 admitted, 0 refused, 0 deferred"}}
    st = box.read("state.json")
    assert st["last_good"] == st["last_good_ledger"] == r and set(st["admitted"]) == {"guest-01"}
    assert box.made == [("https://sso.example.invalid", box.secret)] * 2
    # Check mode: the same decision, prefixed, and no new guest handed.
    other = box.state.parent / "check"
    box.run(r, mode="check", state=other)
    c = box.read("content.json", other)
    assert c["mode"] == "check" and c["admitted"] == [] and c["would_admit"] == ["guest-01"]
    assert box.read("guests.next.json", other) == {"guests": {}} and box.read("state.json", other)["admitted"] == {}
    assert all(s["description"].startswith("check: would be ") for s in c["statuses"].values())
    # A refused ledger: people.yaml still applies, guests stay at the last good ledger.
    bad = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1, state="redeemed", guest=guest_doc("guest-01")),
                                                      dict(link_doc(2), groups=["/realliance"]))}, "ledger")
    box.run(bad)
    c = box.read("content.json")
    assert c["ledger"] == {"effective": r, "refused": True, "reason": f"schema:unknown-key@{bad[:7]}"}
    assert c["statuses"]["ledger"] == {"state": "failure", "description": f"ledger refused: schema:unknown-key@{bad[:7]}"}
    assert c["statuses"]["apply"]["state"] == "success"
    assert box.read("walk.json")["apply_commit"] == bad
    st = box.read("state.json")
    assert (st["last_good"], st["last_good_ledger"]) == (bad, r)
    assert set(box.read("guests.next.json")["guests"]) == {"guest-01"}
    # A freeze: content still runs, hands only the admitted guests and takes nothing new.
    web = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web\n"}, "web-flow")
    box.run(web)
    c = box.read("content.json")
    assert c["statuses"]["apply"]["state"] == "failure" and c["statuses"]["ledger"]["state"] == "pending"
    assert c["ledger"] == {"effective": r, "refused": False, "reason": None}
    assert set(box.read("guests.next.json")["guests"]) == {"guest-01"}


def test_content_refuses_a_walk_that_does_not_match(box):
    a = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1))}, "ledger")
    assert box.walk(a) == 0
    assert box.content(mode="check") == 2                                      # walked in apply
    st = box.read("state.json")
    st["last_good"] = box.repo.seed
    (box.state / "state.json").write_text(json.dumps(st))
    assert box.content() == 2                                                   # a walk.json from another run
    assert not (box.state / "content.json").exists() and not (box.state / "guests.next.json").exists()


def test_outputs_hold_ids_only(box, capsys):
    email, first, last = "Quintessa.Vale@Mail-Example.invalid", "Quintessa", "Valeworth"
    bad_email, bad_first = "zebulon.secretmail@mail-example.invalid", "Zebulon<"
    token = "7e57" * 16
    g1 = dict(guest_doc("guest-01", email=email, first_name=first))
    g1["bootstrap"]["last_name"] = last
    pending = [dict(link_doc(1), token_sha256=token), link_doc(2)]
    box.repo.commit({"ledger.yaml": ledger_yaml(*pending)}, "ledger")
    head = box.repo.commit({"ledger.yaml": ledger_yaml(
        dict(link_doc(1, state="redeemed", guest=g1), token_sha256=token),
        link_doc(2, state="redeemed", guest=guest_doc("guest-02", email=bad_email, first_name=bad_first)))},
        "ledger")
    box.run(head)
    assert box.read("content.json")["refused_entries"] == {"l-0000000000000002": "name-format"}
    assert L.main(["settle", "--state", str(box.state), "--applied"]) == 0
    assert L.main(["fallback", "--state", str(box.state)]) == 0
    web = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# web\n"}, "web-flow")
    box.run(web)
    box.run(web, mode="check")
    out = capsys.readouterr()
    needles = [email, email.split("@")[0], first, last, bad_email, bad_email.split("@")[0], "Zebulon", token[:12],
               "member-one@example.invalid", "member-two@example.invalid"]
    texts = {"stdout": out.out, "stderr": out.err}
    for p in box.state.iterdir():
        if p.name not in ("guests.next.json", "handed.json"):                  # the var-file: D7's one exception
            texts[p.name] = p.read_text()
    for name, text in texts.items():
        for needle in needles:
            assert needle.lower() not in text.lower(), f"{name} holds {needle!r}"
    assert out.out.count("\n") == 8                                             # one line a command
    for name in ("guests.next.json", "handed.json"):
        assert stat.S_IMODE((box.state / name).stat().st_mode) == 0o600


# --- settle, seed, forget, fallback ------------------------------------------------------------------------------

def test_settle_failed_new_refuses_them(box):
    r = redeem(box, 1)
    box.run(r)
    assert box.read("content.json")["admitted"] == ["guest-01"]
    assert L.main(["settle", "--state", str(box.state), "--failed-new"]) == 0
    st = box.read("state.json")
    assert st["admitted"] == {} and st["refused"]["l-0000000000000001"]["reason"] == "apply-failed"
    assert not (box.state / "guests.next.json").exists()
    # The refusal sticks until the entry changes.
    box.now = NOW + timedelta(hours=1)
    box.run(r)
    c = box.read("content.json")
    assert c["admitted"] == [] and c["refused_entries"] == {} and box.read("guests.next.json") == {"guests": {}}
    fixed = box.repo.commit({"ledger.yaml": ledger_yaml(link_doc(1, state="redeemed",
                                                                 guest=guest_doc("guest-01b")))}, "operator")
    box.run(fixed)
    assert box.read("content.json")["admitted"] == ["guest-01b"]
    # Admissions from an earlier run are never touched.
    assert L.main(["settle", "--state", str(box.state), "--applied"]) == 0
    r2 = box.repo.commit({"people.yaml": SEED_PEOPLE + b"# later\n"}, "operator")
    box.run(r2)
    assert L.main(["settle", "--state", str(box.state), "--failed-new"]) == 0
    assert set(box.read("state.json")["admitted"]) == {"guest-01b"}


def test_settle_applied_promotes_next_to_handed(box):
    r = redeem(box, 1)
    box.run(r)
    nxt = (box.state / "guests.next.json").read_bytes()
    assert L.main(["settle", "--state", str(box.state), "--applied"]) == 0
    assert (box.state / "handed.json").read_bytes() == nxt and not (box.state / "guests.next.json").exists()
    assert stat.S_IMODE((box.state / "handed.json").stat().st_mode) == 0o600
    assert L.main(["settle", "--state", str(box.state), "--applied"]) == 2       # nothing to promote
    assert L.main(["settle", "--state", str(box.state)]) == 2                    # one of the two flags
    assert L.main(["settle", "--state", str(box.state), "--applied", "--failed-new"]) == 2


def test_seed_from_output(box):
    out = box.state.parent / "guests-output.json"
    out.write_text(json.dumps({
        "guest-a": {"active": True, "mfa": "webauthn",
                    "bootstrap": {"email": "seed.person@example.invalid", "first_name": "Seedy", "last_name": None}},
        "guest-b": {"active": False, "mfa": "totp", "bootstrap": None}}))
    assert L.main(["seed", "--state", str(box.state), "--from", str(out)]) == 0
    st = box.read("state.json")
    assert st["admitted"] == {"guest-a": {"link": None, "at": None, "active": True},
                              "guest-b": {"link": None, "at": None, "active": False}}
    assert "seed.person" not in (box.state / "state.json").read_text()
    # An existing admission is kept as it is.
    st["admitted"]["guest-a"] = {"link": "l-00000000000000ff", "at": NOW.isoformat(), "active": True}
    (box.state / "state.json").write_text(json.dumps(st))
    assert L.main(["seed", "--state", str(box.state), "--from", str(out)]) == 0
    assert box.read("state.json")["admitted"]["guest-a"]["link"] == "l-00000000000000ff"
    # The ledger fills in a seeded guest's link; the guest is handed and never re-checked.
    box.directory.users.add("guest-c")
    out.write_text(json.dumps({"guest-c": {"active": True, "mfa": "webauthn", "bootstrap": None}}))
    assert L.main(["seed", "--state", str(box.state), "--from", str(out)]) == 0
    r = redeem(box, 1, username="guest-c")
    box.run(r)
    st = box.read("state.json")
    assert st["admitted"]["guest-c"]["link"] == "l-0000000000000001" and st["refused"] == {}
    assert box.read("guests.next.json")["guests"]["guest-c"]["bootstrap"]["first_name"] == "Guestname"
    for bad in ([], {"guest-x": {"mfa": "webauthn"}}, {"guest-x": {"active": "yes"}}):
        out.write_text(json.dumps(bad))
        assert L.main(["seed", "--state", str(box.state), "--from", str(out)]) == 2


def test_forget_removes_one(box):
    out = box.state.parent / "guests-output.json"
    out.write_text(json.dumps({"guest-a": {"active": True}, "guest-b": {"active": False}}))
    assert L.main(["seed", "--state", str(box.state), "--from", str(out)]) == 0
    assert L.main(["forget", "--state", str(box.state), "guest-a"]) == 0
    assert set(box.read("state.json")["admitted"]) == {"guest-b"}
    assert L.main(["forget", "--state", str(box.state), "guest-a"]) == 2           # not admitted
    assert set(box.read("state.json")["admitted"]) == {"guest-b"}


def test_fallback_copies_handed_or_empty(box):
    assert L.main(["fallback", "--state", str(box.state)]) == 0
    assert box.read("guests.next.json") == {"guests": {}}
    handed = {"guests": {"guest-a": {"active": True, "mfa": "webauthn", "bootstrap": None}}}
    (box.state / "handed.json").write_text(json.dumps(handed))
    assert L.main(["fallback", "--state", str(box.state)]) == 0
    assert box.read("guests.next.json") == handed
    assert stat.S_IMODE((box.state / "guests.next.json").stat().st_mode) == 0o600


def test_usage_errors_exit_2(box, capsys):
    assert L.main([]) == 2
    assert L.main(["bogus"]) == 2
    assert L.main(["walk", "--mode", "apply"]) == 2
    assert L.main(["walk", "--mode", "dry", "--repo", ".", "--head", "x", "--state", ".", "--keyring", ".",
                   "--trust", ".", "--anchor", "x"]) == 2
    assert box.walk("not-a-sha") == 2
    assert box.walk(box.repo.seed, anchor="0" * 40) == 2
    box.state.mkdir(parents=True, exist_ok=True)
    (box.state / "state.json").write_text("{not json")
    assert box.walk(box.repo.seed) == 2
    capsys.readouterr()


def test_parses_as_python_312():
    ast.parse(Path(SRC).read_text(), feature_version=(3, 12))
