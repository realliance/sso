"""The ledger verdict on a valid walk (sso_ledger.check_ledger) and what the box reads at a commit beside it
(ledger_at, load_people, load_reserved).

A ledger-key commit may only make the changes in the spec's transitions table; an operator's ledger.yaml change
is an operator edit that only the schema limits. A refused ledger keeps the last good ledger, later ledger
changes wait, and only an operator commit that changes ledger.yaml clears it."""
import pytest

import sso_ledger as L

from .conftest import EMPTY_LEDGER, SEED_PEOPLE, guest_doc, ledger_yaml, link_doc


@pytest.fixture
def repo(people_repo):
    return people_repo


@pytest.fixture
def verdict(repo, keyring, trust):
    def run(head, last_good):
        v = L.walk(repo.path, head, last_good, keyring, trust)
        assert v.valid, v.reason
        return v
    return run


@pytest.fixture
def judge(repo, verdict):
    """check_ledger after one valid walk from `last_good` to `head`."""
    return lambda head, last_good, last_good_ledger, **kw: L.check_ledger(repo.path, verdict(head, last_good),
                                                                          last_good_ledger, **kw)


P1, P2 = link_doc(1), link_doc(2)
R2 = link_doc(2, state="redeemed", guest=guest_doc("guest-two"))
R2_OFF = link_doc(2, state="redeemed", guest=guest_doc("guest-two", active=False))


def test_valid_ledger_moves_effective_to_head(repo, judge):
    a = repo.commit({"ledger.yaml": ledger_yaml(P1, P2)}, "ledger")
    b = repo.commit({"ledger.yaml": ledger_yaml(P1, R2)}, "ledger")
    assert judge(b, repo.seed, repo.seed) == L.LedgerVerdict(effective=b, refused=False, reason=None)
    assert judge(a, repo.seed, repo.seed).effective == a              # one run at a time, too
    assert judge(b, a, a) == L.LedgerVerdict(b, False, None)
    assert judge(b, b, b) == L.LedgerVerdict(b, False, None)          # nothing new
    assert L.ledger_at(repo.path, b).links[1].guest.username == "guest-two"


def test_refused_ledger_keeps_last_good_ledger(repo, judge):
    a = repo.commit({"ledger.yaml": ledger_yaml(P1)}, "ledger")
    bad = repo.commit({"ledger.yaml": ledger_yaml(P1, dict(P2, groups=["/realliance"]))}, "ledger")
    v = judge(bad, repo.seed, a)
    assert v.refused and v.reason.startswith("schema:unknown-key@") and v.effective == a
    assert v.reason == f"schema:unknown-key@{bad[:7]}"
    # A top-level groups key, and a transition the ledger key may not make (a removal), likewise.
    top = repo.commit({"ledger.yaml": ledger_yaml(P1) + b"groups: [/realliance]\n"}, "ledger", parents=[a])
    assert judge(top, a, a) == L.LedgerVerdict(a, True, f"schema:unknown-key@{top[:7]}")
    gone = repo.commit({"ledger.yaml": EMPTY_LEDGER}, "ledger", parents=[a])
    assert judge(gone, a, a) == L.LedgerVerdict(a, True, f"transition:removal@{gone[:7]}")
    added_redeemed = repo.commit({"ledger.yaml": ledger_yaml(P1, R2)}, "ledger", parents=[a])
    assert judge(added_redeemed, a, a) == L.LedgerVerdict(a, True, f"transition:not-allowed@{added_redeemed[:7]}")


def test_later_ledger_changes_wait(repo, judge, verdict):
    a = repo.commit({"ledger.yaml": ledger_yaml(P1, P2)}, "ledger")
    b = repo.commit({"ledger.yaml": ledger_yaml(P1, R2)}, "ledger")             # last good ledger
    bad = repo.commit({"ledger.yaml": ledger_yaml(R2)}, "ledger")                # removes P1: not the key's right
    off = repo.commit({"ledger.yaml": ledger_yaml(R2_OFF)}, "ledger")            # a valid deactivation after it
    new = repo.commit({"ledger.yaml": ledger_yaml(R2_OFF, link_doc(3))}, "ledger")
    refused = L.LedgerVerdict(b, True, f"transition:removal@{bad[:7]}")
    assert judge(off, a, b) == refused
    assert judge(new, a, b) == refused
    # Run by run, as the box meets them: last good moves past the bad commit while the ledger stays refused.
    # The later runs' walks no longer cover it, and with no class known for it the commit is held to the ledger
    # key's rights; with the class the walk command records (ledger_chain), the same.
    assert judge(bad, b, b) == refused
    assert judge(off, bad, b) == refused
    assert judge(new, off, b) == refused
    assert judge(new, off, b, signers={bad: "ledger", off: "ledger"}) == refused
    # A schema failure waits the same way: the later commit's parent no longer parses.
    side = repo.commit({"ledger.yaml": ledger_yaml(P1, R2, dict(link_doc(4), groups=[]))}, "ledger", parents=[b])
    later = repo.commit({"ledger.yaml": ledger_yaml(P1, R2_OFF, dict(link_doc(4), groups=[]))}, "ledger")
    assert judge(later, side, b) == L.LedgerVerdict(b, True, f"schema:unknown-key@{side[:7]}")
    assert verdict(later, side).valid


def test_operator_fix_clears_refusal(repo, judge):
    a = repo.commit({"ledger.yaml": ledger_yaml(P1)}, "ledger")
    bad = repo.commit({"ledger.yaml": ledger_yaml(P1, dict(P2, groups=["/x"]))}, "ledger")
    people_only = repo.commit({"people.yaml": SEED_PEOPLE + b"# an operator change beside it\n"}, "operator")
    assert judge(people_only, a, a) == L.LedgerVerdict(a, True, f"schema:unknown-key@{bad[:7]}")  # vouches nothing
    # Nor after a transition the key may not make, which the schema alone would let through.
    removal = repo.commit({"ledger.yaml": EMPTY_LEDGER}, "ledger", parents=[a])
    beside = repo.commit({"people.yaml": SEED_PEOPLE + b"# beside a removal\n"}, "operator")
    assert judge(beside, a, a) == L.LedgerVerdict(a, True, f"transition:removal@{removal[:7]}")
    repo.git("update-ref", "refs/heads/main", people_only)
    repo.tip = people_only
    fix = repo.commit({"ledger.yaml": ledger_yaml(P1)}, "operator")             # reverts ledger.yaml
    assert judge(fix, a, a) == L.LedgerVerdict(fix, False, None)
    assert judge(fix, people_only, a) == L.LedgerVerdict(fix, False, None)      # the next run, as the box meets it
    # After the fix, ledger-key commits are checked as usual again.
    ok = repo.commit({"ledger.yaml": ledger_yaml(P1, P2)}, "ledger")
    assert judge(ok, fix, fix) == L.LedgerVerdict(ok, False, None)
    worse = repo.commit({"ledger.yaml": ledger_yaml(P2)}, "ledger")
    assert judge(worse, ok, ok) == L.LedgerVerdict(ok, True, f"transition:removal@{worse[:7]}")
    assert bad


def test_operator_edit_may_break_transitions(repo, judge):
    a = repo.commit({"ledger.yaml": ledger_yaml(P1, R2_OFF)}, "operator")       # an operator may add it redeemed
    removed = repo.commit({"ledger.yaml": ledger_yaml(R2_OFF)}, "operator")     # removes a link
    back_on = repo.commit({"ledger.yaml": ledger_yaml(R2)}, "operator")         # reactivates a guest
    assert judge(back_on, repo.seed, repo.seed) == L.LedgerVerdict(back_on, False, None)
    assert judge(removed, a, a) == L.LedgerVerdict(removed, False, None)
    # The schema still applies to an operator's ledger.yaml.
    bad = repo.commit({"ledger.yaml": ledger_yaml(dict(R2, groups=["/realliance"]))}, "operator")
    assert judge(bad, back_on, back_on) == L.LedgerVerdict(back_on, True, f"schema:unknown-key@{bad[:7]}")
    yes = repo.commit({"ledger.yaml": b"version: 1\nlinks: []\nextra: yes\n"}, "operator", parents=[back_on])
    assert judge(yes, back_on, back_on).reason == f"schema:type@{yes[:7]}"


def test_missing_ledger_is_empty(repo, judge):
    gone = repo.commit({"ledger.yaml": None}, "operator")
    assert L.ledger_at(repo.path, gone) == L.Ledger(1, ())
    assert judge(gone, repo.seed, repo.seed) == L.LedgerVerdict(gone, False, None)
    assert judge(gone, gone, gone) == L.LedgerVerdict(gone, False, None)
    later = repo.commit({"people.yaml": SEED_PEOPLE + b"# later\n"}, "operator")
    assert judge(later, gone, gone) == L.LedgerVerdict(later, False, None)


def test_frozen_walk_takes_nothing(repo, keyring, trust):
    a = repo.commit({"ledger.yaml": ledger_yaml(P1)}, "ledger")
    w = repo.commit({"ledger.yaml": ledger_yaml(P1, P2)}, "web-flow")
    v = L.walk(repo.path, w, repo.seed, keyring, trust)
    assert not v.valid
    assert L.check_ledger(repo.path, v, a) == L.LedgerVerdict(a, False, None)


def test_operator_edit_before_the_walk_needs_its_class(repo, judge):
    """An operator ledger edit that last good already passed but the last good ledger hasn't (content didn't
    finish that run) counts as an operator edit only with its class, as the walk command records it in
    ledger_chain. Without it the box holds the commit to the ledger key's rights: closed, never open."""
    a = repo.commit({"ledger.yaml": ledger_yaml(P1, P2)}, "ledger")
    removed = repo.commit({"ledger.yaml": ledger_yaml(P2)}, "operator")
    assert judge(removed, a, a) == L.LedgerVerdict(removed, False, None)
    assert judge(removed, removed, a) == L.LedgerVerdict(a, True, f"transition:removal@{removed[:7]}")
    assert judge(removed, removed, a, signers={removed: "operator"}) == L.LedgerVerdict(removed, False, None)
    # A class the walk calls untrusted (a commit inside a reviewed range) is held to the key's rights too.
    assert judge(removed, removed, a, signers={removed: "untrusted"}).refused


def test_ledger_at_refuses_what_is_not_a_file(repo):
    link = repo.commit({"ledger.yaml": b"people.yaml"}, "operator", mode="120000")
    with pytest.raises(L.SchemaError) as e:
        L.ledger_at(repo.path, link)
    assert e.value.code == "type"
    big = repo.commit({"ledger.yaml": b"#" * (L.MAX_LEDGER_BYTES + 1)}, "operator")
    with pytest.raises(L.SchemaError) as e:
        L.ledger_at(repo.path, big)
    assert e.value.code == "too-large"


PEOPLE = b"""\
hidden_groups: []
people:
  - username: rally
    active: true
    groups: [/realliance, /apps/forgejo]
    bootstrap: {email: ' Rally.Person@Example.INVALID ', first_name: Rally}
  - username: mel
    active: true
    groups: []
    bootstrap: {email: mel@example.invalid, first_name: Mel}
  - username: gone
    active: false
    groups: [/realliance]
    bootstrap: {email: gone@example.invalid, first_name: Gone}
  - username: ovr
    active: true
    groups: [/guests]
  - username: ovr-off
    active: false
    groups: [/guests]
  - username: both
    active: true
    groups: [/realliance, /guests]
  - username: nested-guest
    active: true
    groups: [/x/guests]
  - username: nested-rally
    active: true
    groups: [/apps/forgejo, /team/realliance]
  - username: both-nested
    active: true
    groups: [/team/realliance, /x/guests]
  - username: near-miss
    active: true
    groups: [/realliance/team, /guests-old]
"""


def test_load_people_tiers(repo):
    sha = repo.commit({"people.yaml": PEOPLE}, "operator")
    p = L.load_people(repo.path, sha)
    # Groups match by their last path segment, as sso-people's main.tf maps them to Keycloak groups.
    assert p.tiers == {"rally": "realliance", "mel": "member", "gone": "inactive", "ovr": "guest",
                       "ovr-off": "inactive", "both": "guest", "nested-guest": "guest",
                       "nested-rally": "realliance", "both-nested": "guest", "near-miss": "member"}
    assert p.usernames == set(p.tiers)
    assert p.emails == {"rally.person@example.invalid", "mel@example.invalid", "gone@example.invalid"}
    with pytest.raises(ValueError):
        L.load_people(repo.path, repo.commit({"people.yaml": b"people: [{username: x}]\n"}, "operator"))
    broken = repo.commit({"people.yaml": b"people:\n  - username: secret-value\n   bad: [\n"}, "operator")
    with pytest.raises(ValueError) as e:
        L.load_people(repo.path, broken)
    assert "secret-value" not in str(e.value)                                   # a YAML error never quotes the file


def test_load_reserved(repo):
    names, prefixes = L.load_reserved(repo.path, repo.seed)                     # no reserved.yaml: built-ins only
    assert names == L.RESERVED_NAMES and prefixes == L.RESERVED_PREFIXES
    assert {"www", "forge-bot", "ghost", "realliance-ci"} <= names and prefixes == ("test-", "ci-", "admin-")
    sha = repo.commit({"reserved.yaml": b"reserved: [Hidden-Org]\nreserved_prefixes: [hide-]\n"}, "operator")
    names, prefixes = L.load_reserved(repo.path, sha)
    assert names == L.RESERVED_NAMES | {"hidden-org"} and prefixes == (*L.RESERVED_PREFIXES, "hide-")
    for bad in (b"other: []\n", b"reserved: hidden\n", b"reserved: [1]\n", b"- a\n"):
        with pytest.raises(ValueError):
            L.load_reserved(repo.path, repo.commit({"reserved.yaml": bad}, "operator"))
