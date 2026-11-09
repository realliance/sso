"""The box's commit check: signer classes, the ledger key's path rule, the first-parent walk and recovery
(sso_ledger.commit_signer, check_commit, walk, newest_trusted, parse_reviewed_range, load_trust).

On sso-people only operator keys and the path-limited ledger key are trusted. GitHub's web-flow key signs every
web-editor commit for anyone, in any repo, so a web-flow commit is as invalid there as an unsigned one; the
`web-flow` key in conftest stands in for it, outside the keyring and outside every class."""
import inspect
import itertools
import json

import pytest

import sso_ledger as L

from .conftest import EMPTY_LEDGER, GITHUB_COMMITTER, SEED_PEOPLE

_n = itertools.count(1)


def ledger_bytes() -> bytes:
    """A new ledger.yaml each call. The walk never parses it, so a comment is change enough."""
    return EMPTY_LEDGER + f"# change {next(_n)}\n".encode()


def people_bytes() -> bytes:
    return SEED_PEOPLE + f"# change {next(_n)}\n".encode()


def reviewed(last_good: str, tip: str) -> str:
    return f"Recover the ledger\n\nReviewed-Range: {last_good}..{tip}\n"


@pytest.fixture
def repo(people_repo):
    return people_repo


@pytest.fixture
def walk(repo, keyring, trust):
    return lambda head, last_good, seen_heads=None: L.walk(repo.path, head, last_good, keyring, trust,
                                                           seen_heads=seen_heads)


def signer(repo, sha, keyring, trust):
    return L.commit_signer(repo.path, sha, keyring, trust)


# --- trust and signers ----------------------------------------------------------------------------------------

def test_load_trust(tmp_path):
    a, c = "a" * 40, "c" * 40
    path = tmp_path / "people-trust.json"
    path.write_text(json.dumps({"operators": [a], "ledger": [c]}))
    assert L.load_trust(path) == L.Trust(frozenset({"A" * 40}), frozenset({"C" * 40}))
    assert [f.name for f in L.Trust.__dataclass_fields__.values()] == ["operators", "ledger"]
    for bad in ({"operators": [a]},                                                   # a class missing
                {"operators": [a], "ledger": [c], "extra": []},                       # an unknown class
                {"operators": [a], "ledger": [a]},                                    # one key in both classes
                {"operators": [a.lower()], "ledger": [a.upper()]},
                {"operators": ["a" * 39], "ledger": [c]},                             # not a fingerprint
                {"operators": "a" * 40, "ledger": [c]},
                [a, c]):
        path.write_text(json.dumps(bad))
        with pytest.raises(ValueError):
            L.load_trust(path)


def test_trust_file_refuses_web_flow_class(tmp_path):
    """A people-trust.json that still lists web-flow, the three-class format of before, is refused outright:
    the box never quietly ignores a class it no longer has, empty or not."""
    a, b, c = "a" * 40, "b" * 40, "c" * 40
    path = tmp_path / "people-trust.json"
    for bad in ({"operators": [a], "web_flow": [b], "ledger": [c]},
                {"operators": [a], "web_flow": [], "ledger": [c]},
                {"operators": [a, b], "web_flow": [b], "ledger": [c]}):
        path.write_text(json.dumps(bad))
        with pytest.raises(ValueError):
            L.load_trust(path)


def test_signer_classes(repo, keys, keyring, trust):
    made = {name: repo.commit({"ledger.yaml": ledger_bytes()}, name)
            for name in ("operator", "web-flow", "ledger", "untrusted", None, "expired")}
    got = {name: signer(repo, sha, keyring, trust) for name, sha in made.items()}
    assert got == {"operator": "operator", "web-flow": "untrusted", "ledger": "ledger", "untrusted": "untrusted",
                   None: "untrusted", "expired": "untrusted"}
    # The fixtures mean what they say: the operator signs with a subkey, so the class must come from the
    # primary (%GP); the expired key's signature is good but its key has expired (Y), not merely unknown; and
    # web-flow's key is not in the keyring at all (E), like the box's gnupg-people.
    assert repo.show("%G?|%GF", made["operator"], keyring) != f"G|{keys['operator'].fpr}"
    assert repo.show("%G?|%GP", made["operator"], keyring) == f"G|{keys['operator'].fpr}"
    assert repo.show("%G?", made["expired"], keyring) == "Y"
    assert repo.show("%G?", made["untrusted"], keyring) == "E"
    assert repo.show("%G?|%cn <%ce>", made["web-flow"], keyring) == "E|GitHub <noreply@github.com>"
    assert inspect.signature(L.commit_signer).return_annotation in ("Signer", L.Signer)
    assert set(L.Signer.__args__) == {"operator", "ledger", "untrusted"}


def test_signer_needs_a_class(repo, keys, keyring, trust):
    """A good signature from a key in the keyring but in no class of people-trust.json is untrusted."""
    sha = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    only_operators = L.Trust(trust.operators, frozenset())
    assert signer(repo, sha, keyring, only_operators) == "untrusted"


# --- the path rule --------------------------------------------------------------------------------------------

def _case(repo, name: str, who: str) -> str:
    """One commit of the path-rule table, signed by `who`, built on the seed."""
    base = repo.seed
    gitlink = b"0123456789abcdef0123456789abcdef01234567"
    if name == "ledger only":
        return repo.commit({"ledger.yaml": ledger_bytes()}, who, parents=[base])
    if name == "also people.yaml":
        return repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, who, parents=[base])
    if name == "people.yaml only":
        return repo.commit({"people.yaml": people_bytes()}, who, parents=[base])
    if name == "a ledger.yaml elsewhere":
        return repo.commit({"sub/ledger.yaml": ledger_bytes()}, who, parents=[base])
    if name == "rename":
        return repo.commit({"ledger.yaml": None, "ledger-old.yaml": EMPTY_LEDGER}, who, parents=[base])
    if name == "submodule beside":
        return repo.commit({"ledger.yaml": ledger_bytes(), "vendor": gitlink}, who, parents=[base],
                           mode={"vendor": "160000"})
    if name == "mode 100755":
        return repo.commit({"ledger.yaml": EMPTY_LEDGER}, who, parents=[base], mode="100755")
    if name == "symlink":
        return repo.commit({"ledger.yaml": b"people.yaml"}, who, parents=[base], mode="120000")
    if name == "submodule in place":
        return repo.commit({"ledger.yaml": gitlink}, who, parents=[base], mode="160000")
    if name == "creates":
        gone = repo.commit({"ledger.yaml": None}, "operator", parents=[base])
        return repo.commit({"ledger.yaml": EMPTY_LEDGER}, who, parents=[gone])
    if name == "deletes":
        return repo.commit({"ledger.yaml": None}, who, parents=[base])
    if name == "changes nothing":
        return repo.commit({}, who, parents=[base])
    if name == "two parents":
        side = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[base])
        return repo.commit({"ledger.yaml": ledger_bytes()}, who, parents=[base, side])
    if name == "no parent":
        return repo.commit({"ledger.yaml": EMPTY_LEDGER, "people.yaml": SEED_PEOPLE}, who, parents=[])
    raise AssertionError(name)


PATH_RULE = {
    "ledger only": None,
    "also people.yaml": "ledger-path",
    "people.yaml only": "ledger-path",
    "a ledger.yaml elsewhere": "ledger-path",
    "rename": "ledger-path",
    "submodule beside": "ledger-path",
    "mode 100755": "ledger-mode",
    "symlink": "ledger-mode",
    "submodule in place": "ledger-mode",
    "creates": "ledger-status",
    "deletes": "ledger-status",
    "changes nothing": "ledger-status",
    "two parents": "ledger-merge",
    "no parent": "ledger-merge",
}


@pytest.mark.parametrize("name", list(PATH_RULE))
def test_ledger_key_path_rule(name, repo, keyring, trust):
    sha = _case(repo, name, "ledger")
    assert signer(repo, sha, keyring, trust) == "ledger"
    assert L.check_commit(repo.path, sha, "ledger") == PATH_RULE[name]


@pytest.mark.parametrize("name", list(PATH_RULE))
def test_operator_may_change_any_path(name, repo, keyring, trust):
    sha = _case(repo, name, "operator")
    cls = signer(repo, sha, keyring, trust)
    assert cls == "operator"
    assert L.check_commit(repo.path, sha, cls) is None


@pytest.mark.parametrize("name", list(PATH_RULE))
def test_web_flow_may_change_no_path(name, repo, keyring, trust):
    """The table row "GitHub's web-flow key: nothing", for every shape the ledger key's rule knows."""
    sha = _case(repo, name, "web-flow")
    cls = signer(repo, sha, keyring, trust)
    assert cls == "untrusted"
    assert L.check_commit(repo.path, sha, cls) == "untrusted-signer"


@pytest.mark.parametrize("who,code", [(None, "unsigned"), ("untrusted", "untrusted-signer"),
                                      ("expired", "untrusted-signer"), ("web-flow", "untrusted-signer")])
def test_unsigned_or_unknown_key_invalid(who, code, repo, keyring, trust):
    sha = repo.commit({"ledger.yaml": ledger_bytes()}, who)
    assert L.check_commit(repo.path, sha, signer(repo, sha, keyring, trust)) == code


def test_check_commit_knows_no_web_flow_class(repo):
    """No caller can hand check_commit a class that would let a commit through unchecked."""
    sha = repo.commit({"people.yaml": people_bytes()}, "web-flow")
    for cls in ("web-flow", "web_flow", "github", ""):
        with pytest.raises(ValueError):
            L.check_commit(repo.path, sha, cls)


# --- the walk -------------------------------------------------------------------------------------------------

def test_a_merges_other_parents_are_off_the_chain_and_checked(repo, walk):
    """The chain is head's first-parent line; what a merge brings in on its other parents isn't on it, but each
    of those commits is checked by its own signer all the same."""
    base = repo.seed
    inner1 = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[base])
    inner2 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    merge = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[base, inner2])
    v = walk(merge, base)
    assert (v.valid, v.reason, v.invalid) == (True, None, [])
    assert v.chain == [(merge, "operator")]
    assert inner1 not in dict(v.chain) and inner2 not in dict(v.chain)
    stranger = repo.commit({"notes.md": b"x\n"}, "untrusted", parents=[inner2])
    merge2 = repo.commit({"notes.md": b"x\n"}, "operator", parents=[merge, stranger])
    v = walk(merge2, base)
    assert (v.valid, v.reason, v.invalid) == (False, f"invalid:untrusted-signer@{stranger[:7]}",
                                              [(stranger, "untrusted-signer")])
    assert v.chain == [(merge, "operator"), (merge2, "operator")]


def _pull_merge(repo, who="operator"):
    """The service pushed a ledger-key commit that also changed people.yaml; an operator's local `git pull`
    merged it as the second parent of a commit of their own, then pushed."""
    base = repo.seed
    people, led = people_bytes(), ledger_bytes()
    pushed = repo.commit({"ledger.yaml": led, "people.yaml": people}, "ledger", parents=[base])
    local = repo.commit({"notes.md": b"local\n"}, "operator", parents=[base])
    merge = repo.commit({"ledger.yaml": led, "people.yaml": people}, who, parents=[local, pushed])
    return base, pushed, local, merge


def test_ledger_key_commit_under_a_merge_freezes(repo, walk):
    """Every ledger-key commit in last_good..head is held to the path rule, whichever parent brings it in."""
    base, pushed, local, merge = _pull_merge(repo)
    v = walk(merge, base)
    assert (v.valid, v.reason, v.recovery) == (False, f"invalid:ledger-path@{pushed[:7]}", None)
    assert v.invalid == [(pushed, "ledger-path")]
    assert v.chain == [(local, "operator"), (merge, "operator")]


def test_ledger_key_commits_under_a_merge_obey_the_path_rule(repo, walk):
    base = repo.seed
    fine = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[base])
    local = repo.commit({"notes.md": b"local\n"}, "operator", parents=[base])
    merge = repo.commit({}, "operator", parents=[local, fine])
    assert walk(merge, base).valid                          # ledger.yaml alone, one parent: fine anywhere
    lmerge = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[fine, local])
    head = repo.commit({}, "operator", parents=[merge, lmerge])
    v = walk(head, base)
    assert (v.valid, v.reason, v.invalid) == (False, f"invalid:ledger-merge@{lmerge[:7]}", [(lmerge, "ledger-merge")])


def test_recovery_covers_a_ledger_key_commit_under_a_merge(repo, walk):
    base, pushed, local, merge = _pull_merge(repo)
    revert = repo.commit({"people.yaml": SEED_PEOPLE}, "operator")
    rec = repo.commit({}, "operator", message=reviewed(base, merge))
    v = walk(rec, base)
    assert (v.valid, v.recovery, v.invalid) == (True, rec, [])
    assert revert in dict(v.chain)
    short = repo.commit({}, "operator", parents=[revert], message=reviewed(base, local))
    v = walk(short, base)
    assert (v.valid, v.reason) == (False, f"recovery-misses@{pushed[:7]}")


# No merge brings anything in unchecked: every commit a merge brings in on its other parents gets the full
# check by its own signer, under an operator's local merge as under any other.

def test_unsigned_push_under_an_operator_pull_merge_freezes(repo, walk):
    """The service's deploy key pushes an unsigned commit (no ledger key needed); the box freezes; an
    operator's `git pull` merges it as the second parent of their own commit. That must not lift the freeze."""
    base = repo.seed
    pushed = repo.commit({"people.yaml": people_bytes()}, None, parents=[base])
    assert walk(pushed, base).reason == f"invalid:unsigned@{pushed[:7]}"
    local = repo.commit({"notes.md": b"local\n"}, "operator", parents=[base])
    merge = repo.commit({}, "operator", parents=[local, pushed])
    v = walk(merge, base)
    assert (v.valid, v.reason, v.invalid) == (False, f"invalid:unsigned@{pushed[:7]}", [(pushed, "unsigned")])
    assert v.chain == [(local, "operator"), (merge, "operator")]


@pytest.mark.parametrize("merger", ["operator", "web-flow", "ledger"])
def test_operator_local_merge_of_unsigned_work_freezes(merger, repo, walk):
    """No exemption under any merge: unsigned and unknown-key PR commits freeze whoever signed the merge, an
    operator's local merge included (a GitHub merge-button merge and a ledger-key merge are invalid besides)."""
    base = repo.seed
    pr1 = repo.commit({"people.yaml": people_bytes()}, None, parents=[base])
    side = repo.commit({"notes.md": b"side\n"}, None, parents=[base])
    inner = repo.commit({}, "operator", parents=[pr1, side])               # an operator merge inside the branch
    pr2 = repo.commit({"notes.md": b"pr\n"}, "untrusted")
    pr3 = repo.commit({"notes.md": b"pr, signed\n"}, "operator")
    merge = repo.commit({"people.yaml": people_bytes()}, merger, parents=[base, pr3])
    v = walk(merge, base)
    assert (v.valid, v.reason) == (False, f"invalid:unsigned@{v.invalid[0][0][:7]}")
    own = {"operator": [], "web-flow": [(merge, "untrusted-signer")], "ledger": [(merge, "ledger-merge")]}[merger]
    assert sorted(v.invalid) == sorted([(pr1, "unsigned"), (side, "unsigned"), (pr2, "untrusted-signer"), *own])
    assert v.invalid[0][0] in (pr1, side) and inner not in dict(v.invalid)
    if merger == "operator":
        # The operator who meant it reviews the range.
        rec = repo.commit({}, "operator", message=reviewed(base, merge))
        assert (walk(rec, base).valid, walk(rec, base).recovery) == (True, rec)


def test_valid_chain(repo, walk):
    base = repo.seed
    op = repo.commit({"people.yaml": people_bytes()}, "operator")
    l1 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    op2 = repo.commit({"people.yaml": people_bytes(), "ledger.yaml": ledger_bytes()}, "operator")
    l2 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    v = walk(l2, base)
    assert v == L.WalkVerdict(head=l2, last_good=l2, valid=True, reason=None,
                              chain=[(op, "operator"), (l1, "ledger"), (op2, "operator"), (l2, "ledger")],
                              invalid=[], recovery=None, newest_trusted=l2, seen_heads=[])


def test_head_is_last_good(repo, walk):
    v = walk(repo.seed, repo.seed)
    assert (v.valid, v.chain, v.last_good, v.newest_trusted) == (True, [], repo.seed, repo.seed)


def test_freeze_on_invalid_commit(repo, walk):
    base = repo.seed
    before = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    bad = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger")
    repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    repo.commit({"people.yaml": people_bytes()}, "operator")
    head = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    v = walk(head, base)
    assert v.valid is False
    assert v.reason == f"invalid:ledger-path@{bad[:7]}"
    assert v.invalid == [(bad, "ledger-path")]
    assert (v.last_good, v.recovery, v.newest_trusted) == (base, None, before)   # the last commit before bad
    assert len(v.chain) == 5


def test_freeze_lists_every_invalid_commit(repo, walk):
    base = repo.seed
    unsigned = repo.commit({"people.yaml": people_bytes()}, None)
    stranger = repo.commit({"ledger.yaml": ledger_bytes()}, "untrusted")
    merge = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[stranger, base])
    v = walk(merge, base)
    assert v.reason == f"invalid:unsigned@{unsigned[:7]}"
    assert v.invalid == [(unsigned, "unsigned"), (stranger, "untrusted-signer"), (merge, "ledger-merge")]
    assert v.newest_trusted == base


def test_freeze_on_non_fast_forward(repo, walk):
    a = repo.commit({"people.yaml": people_bytes()}, "operator")
    b = repo.commit({"people.yaml": people_bytes()}, "operator")
    c = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[a])
    v = walk(c, b)
    assert (v.valid, v.reason, v.invalid, v.last_good) == (False, "not-fast-forward", [], b)
    assert v.chain == [(c, "operator")]
    assert v.newest_trusted == b                 # c lacks last good: check mode stays at last good


# --- recovery -------------------------------------------------------------------------------------------------

def _frozen(repo):
    """last good, a ledger-key commit that also changed people.yaml, and an operator's revert of it."""
    last_good = repo.seed
    bad = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger")
    revert = repo.commit({"people.yaml": SEED_PEOPLE}, "operator")
    return last_good, bad, revert


def test_recovery_accepted(repo, walk):
    last_good, bad, revert = _frozen(repo)
    assert walk(revert, last_good).reason == f"invalid:ledger-path@{bad[:7]}"
    rec = repo.commit({}, "operator", message=reviewed(last_good, bad))
    v = walk(rec, last_good)
    assert (v.valid, v.reason, v.recovery, v.last_good, v.invalid) == (True, None, rec, rec, [])
    assert [c for c, _ in v.chain] == [bad, revert, rec]


def test_recovery_with_the_revert_as_tip(repo, walk):
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({}, "operator", message=reviewed(last_good, revert))
    assert (walk(rec, last_good).valid, walk(rec, last_good).recovery) == (True, rec)


def test_recovery_replayed_fails(repo, walk):
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({}, "operator", message=reviewed(last_good, bad))
    assert walk(rec, last_good).valid
    # Last good moves past it onto history `rec` is not part of (an erasure rewrite the box took) ...
    rewritten = repo.commit({"people.yaml": SEED_PEOPLE, "ledger.yaml": EMPTY_LEDGER}, None, parents=[])
    erasure = repo.commit({}, "operator", message=reviewed(rec, rewritten))
    assert walk(erasure, rec).valid
    # ... and the old recovery commit comes back as the head, or under a new one.
    v = walk(rec, erasure)
    assert (v.valid, v.reason, v.recovery) == (False, f"recovery-stale-last-good@{rec[:7]}", None)
    on_top = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[rec])
    assert walk(on_top, erasure).reason == f"recovery-stale-last-good@{rec[:7]}"


@pytest.mark.parametrize("who", ["web-flow", "ledger", "untrusted", "expired", None])
def test_recovery_must_be_operator_key(who, repo, walk):
    """Only an operator key recovers. A Reviewed-Range commit signed any other way is no recovery, and it is
    itself one more invalid commit."""
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({}, who, message=reviewed(last_good, bad))
    v = walk(rec, last_good)
    assert (v.valid, v.recovery, v.last_good) == (False, None, last_good)
    assert v.invalid[0] == (bad, "ledger-path")
    assert rec in dict(v.invalid)


def test_web_flow_recovery_rejected(repo, walk):
    """A Reviewed-Range commit written in GitHub's web UI is the mistake an operator can make: GitHub signs it
    with web-flow's key and commits it as GitHub. The reason says so, the box stays frozen, and the remedy is
    the same range signed locally."""
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({}, "web-flow", message=reviewed(last_good, bad))
    v = walk(rec, last_good)
    assert (v.valid, v.reason, v.recovery) == (False, f"recovery-not-operator-key@{rec[:7]}", None)
    assert v.invalid == [(bad, "ledger-path"), (rec, "untrusted-signer")]
    assert (v.last_good, v.newest_trusted, v.seen_heads) == (last_good, last_good, [rec])   # revert sits on bad
    # The name is a hint read from the commit, never trust: with no signature at all it isn't given, and with
    # or without it the commit stays invalid.
    plain = repo.commit({}, None, parents=[revert], message=reviewed(last_good, bad), committer=GITHUB_COMMITTER)
    v = walk(plain, last_good)
    assert (v.valid, v.reason) == (False, f"invalid:ledger-path@{bad[:7]}")
    assert (plain, "unsigned") in v.invalid
    # The operator signs the range locally, on top of the web-UI commit: the box takes it.
    fixed = repo.commit({}, "operator", parents=[rec], message=reviewed(last_good, rec))
    v = walk(fixed, last_good, seen_heads=[rec, plain])
    assert (v.valid, v.recovery, v.last_good, v.seen_heads) == (True, fixed, fixed, [])


@pytest.mark.parametrize("who", ["ledger", "untrusted", None])
def test_trailer_from_another_key_never_masks_the_freeze(who, repo, walk):
    """Recovery reasons come only from operator attempts and from commits GitHub's web UI made: a
    Reviewed-Range trailer on a ledger-key, unknown-key or unsigned commit is no attempt, and the reason keeps
    naming the first invalid commit."""
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({"ledger.yaml": ledger_bytes()}, who, message=reviewed(last_good, bad))
    v = walk(rec, last_good)
    assert (v.valid, v.reason, v.recovery) == (False, f"invalid:ledger-path@{bad[:7]}", None)
    assert v.invalid[0] == (bad, "ledger-path")


def test_ledger_key_trailer_does_not_hide_a_stale_recovery(repo, walk):
    last_good, bad, revert = _frozen(repo)
    stale = repo.commit({}, "operator", message=reviewed(revert, bad))
    repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", message=reviewed(last_good, bad))
    v = walk(repo.tip, last_good)
    assert (v.valid, v.reason) == (False, f"recovery-stale-last-good@{stale[:7]}")


def test_web_ui_attempt_does_not_hide_an_operator_attempt(repo, walk):
    """Anyone can mint a web-flow commit, so its wording ranks below an operator's own failed attempt, older or
    not: the operator sees what was wrong with the recovery they signed."""
    last_good, bad, revert = _frozen(repo)
    stale = repo.commit({}, "operator", message=reviewed(revert, bad))
    repo.commit({}, "web-flow", message=reviewed(last_good, bad))
    v = walk(repo.tip, last_good)
    assert (v.valid, v.reason) == (False, f"recovery-stale-last-good@{stale[:7]}")


def test_freeze_reason_names_the_first_invalid_commit(repo, walk):
    """On a history that doesn't fast-forward, an invalid commit is named before `not-fast-forward`."""
    a = repo.commit({"people.yaml": people_bytes()}, "operator")
    b = repo.commit({"people.yaml": people_bytes()}, "operator")
    first = repo.commit({"people.yaml": people_bytes()}, None, parents=[a])
    repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger")
    v = walk(repo.tip, b)
    assert (v.valid, v.reason) == (False, f"invalid:unsigned@{first[:7]}")
    assert [c for c, _ in v.invalid][0] == first


@pytest.mark.parametrize("form", ["both short", "tip short", "last good short", "two trailers", "no range",
                                  "three dots"])
def test_recovery_needs_full_shas(form, repo, walk):
    last_good, bad, revert = _frozen(repo)
    message = {
        "both short": f"Recover\n\nReviewed-Range: {last_good[:7]}..{bad[:7]}\n",
        "tip short": f"Recover\n\nReviewed-Range: {last_good}..{bad[:7]}\n",
        "last good short": f"Recover\n\nReviewed-Range: {last_good[:12]}..{bad}\n",
        "two trailers": f"Recover\n\nReviewed-Range: {last_good}..{bad}\nReviewed-Range: {last_good}..{revert}\n",
        "no range": f"Recover\n\nReviewed-Range: {bad}\n",
        "three dots": f"Recover\n\nReviewed-Range: {last_good}...{bad}\n",
    }[form]
    rec = repo.commit({}, "operator", message=message)
    v = walk(rec, last_good)
    assert (v.valid, v.reason) == (False, f"recovery-bad-trailer@{rec[:7]}")


def test_parse_reviewed_range():
    """It takes the trailer text git prints for %(trailers:key=Reviewed-Range,valueonly), not a message."""
    a, b = "a" * 40, "b" * 40
    assert list(inspect.signature(L.parse_reviewed_range).parameters) == ["trailer_values"]
    assert L.parse_reviewed_range(trailer_values=f"{a}..{b}\n") == (a, b)
    assert L.parse_reviewed_range(f"Recover\n\nReviewed-Range: {a}..{b}\n") is None   # a whole message
    assert L.parse_reviewed_range(f"{a.upper()}..{b}\n") == (a, b)
    for bad in ("", "\n", f"{a[:7]}..{b[:7]}\n", f"{a}..{b}\n{a}..{b}\n", f"{a}...{b}\n", f"{a}..{b} x\n",
                f"{a}..\n", f"{a}{b}\n", f"{a}..{b}0\n", "g" * 40 + f"..{b}\n"):
        assert L.parse_reviewed_range(bad) is None, bad


@pytest.mark.parametrize("tip", ["a side branch", "a missing commit"])
def test_recovery_tip_must_be_ancestor(tip, repo, walk):
    last_good, bad, revert = _frozen(repo)
    side = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[bad])
    named = side if tip == "a side branch" else "f" * 40
    rec = repo.commit({}, "operator", parents=[revert], message=reviewed(last_good, named))
    v = walk(rec, last_good)
    assert (v.valid, v.reason) == (False, f"recovery-tip-not-ancestor@{rec[:7]}")


def test_recovery_must_cover_every_invalid_commit(repo, walk):
    last_good, bad, revert = _frozen(repo)
    missed = repo.commit({"ledger.yaml": ledger_bytes()}, None)
    rec = repo.commit({}, "operator", message=reviewed(last_good, bad))
    v = walk(rec, last_good)
    assert (v.valid, v.reason, v.recovery) == (False, f"recovery-misses@{missed[:7]}", None)
    assert v.invalid == [(missed, "unsigned")]


def test_commits_after_recovery_checked_as_usual(repo, walk):
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({}, "operator", message=reviewed(last_good, bad))
    fine = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    assert (walk(fine, last_good).valid, walk(fine, last_good).recovery) == (True, rec)
    after = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger")
    v = walk(after, last_good)
    assert (v.valid, v.reason, v.recovery) == (False, f"invalid:ledger-path@{after[:7]}", None)
    assert v.invalid == [(after, "ledger-path")]
    # The operator's remedy: revert again and review the whole range from the same last good.
    again = repo.commit({"people.yaml": SEED_PEOPLE}, "operator")
    rec2 = repo.commit({}, "operator", message=reviewed(last_good, after))
    assert (walk(rec2, last_good).valid, walk(rec2, last_good).recovery) == (True, rec2)
    assert again in dict(walk(rec2, last_good).chain)


def test_newest_recovery_attempt_is_the_one_judged(repo, walk):
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({}, "operator", message=reviewed(last_good, bad))
    # A later operator commit quoting the trailer is the recovery the box takes.
    quoted = repo.commit({}, "operator", message=reviewed(last_good, bad))
    v = walk(quoted, last_good)
    assert (v.valid, v.recovery) == (True, quoted)
    # A later web-flow commit quoting it stands in for nothing: it is checked like any commit after the
    # recovery, and freezes on its own signature.
    web = repo.commit({}, "web-flow", parents=[rec], message=reviewed(last_good, bad))
    v = walk(web, last_good)
    assert (v.valid, v.reason, v.recovery) == (False, f"invalid:untrusted-signer@{web[:7]}", None)
    assert v.invalid == [(web, "untrusted-signer")]


def test_recovery_takes_non_fast_forward_history(repo, walk):
    """The erasure shape: filter-repo rewrites history (its commits come out unsigned) and an operator signs
    a head naming the box's last good and the rewritten tip, then force-pushes."""
    old = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    old_tip = repo.commit({"people.yaml": people_bytes()}, "operator")
    r1 = repo.commit({"people.yaml": SEED_PEOPLE, "ledger.yaml": EMPTY_LEDGER}, None, parents=[])
    r2 = repo.commit({"ledger.yaml": ledger_bytes()}, None)
    r3 = repo.commit({"people.yaml": people_bytes()}, None)
    assert walk(r3, old_tip).reason == f"invalid:unsigned@{r1[:7]}"    # an invalid commit is named first
    rec = repo.commit({}, "operator", message=reviewed(old_tip, r3))
    v = walk(rec, old_tip)
    assert (v.valid, v.reason, v.recovery, v.last_good, v.invalid) == (True, None, rec, rec, [])
    assert [c for c, _ in v.chain] == [r1, r2, r3, rec]
    assert old not in dict(v.chain)
    # Without the trailer the same rewrite stays frozen.
    plain = repo.commit({}, "operator", parents=[r3])
    assert walk(plain, old_tip).reason == f"invalid:unsigned@{r1[:7]}"


# --- rollback, clock skew and malformed trees ------------------------------------------------------------------

def test_rollback_to_an_ancestor(repo, walk):
    """A force-push back to an older commit (undoing a member's removal, say) doesn't fast-forward."""
    old = repo.commit({"people.yaml": people_bytes()}, "operator")
    repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    last_good = repo.commit({"people.yaml": people_bytes()}, "operator")
    v = walk(old, last_good)
    assert (v.valid, v.reason, v.chain, v.invalid, v.last_good) == (False, "not-fast-forward", [], [], last_good)
    on_top = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[old])
    assert walk(on_top, last_good).reason == "not-fast-forward"
    # An operator who means it signs a head on the old commit that reviews last good..old.
    rec = repo.commit({}, "operator", parents=[old], message=reviewed(last_good, old))
    v = walk(rec, last_good)
    assert (v.valid, v.recovery, v.chain) == (True, rec, [(rec, "operator")])


def _reference_chain(repo, head, last_good):
    """head's first-parent line down to the first ancestor of last good, by ancestry alone (no dates)."""
    out = []
    for c in repo.git("rev-list", "--first-parent", head).split():
        if repo.is_ancestor(c, last_good):
            break
        out.append(c)
    return list(reversed(out))


def test_committer_date_skew(repo, walk):
    """Commit dates are the signer's to set. The range must follow ancestry, not dates: last good dated in
    1970 with newer-dated history under it (including a reviewed bad commit), and a merge that reaches back
    into that history through its second parent."""
    def at(seconds: int) -> str:
        return f"@{seconds} +0000"

    future = 4_000_000_000                               # 2096; git refuses dates past 2099
    base = repo.seed
    line = [repo.commit({"people.yaml": people_bytes()}, "operator", date=at(future + i)) for i in range(10)]
    bad = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger", date=at(future + 11))
    revert = repo.commit({"people.yaml": SEED_PEOPLE}, "operator", date=at(future + 12))
    rec = repo.commit({}, "operator", message=reviewed(base, bad), date=at(future + 13))
    assert walk(rec, base).valid
    last_good = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", date=at(86_400 * 2))
    c1 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", date=at(2_500_000_000))
    c2 = repo.commit({"people.yaml": people_bytes()}, "operator", date=at(86_400))
    merge = repo.commit({}, "operator", parents=[c2, revert], date=at(future + 100))   # bad is under it
    head = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", date=at(86_400 * 3))
    v = walk(head, last_good)
    assert [c for c, _ in v.chain] == _reference_chain(repo, head, last_good) == [c1, c2, merge, head]
    assert (v.valid, v.reason, v.invalid) == (True, None, [])
    assert bad not in dict(v.chain) and revert not in dict(v.chain)


def test_committer_date_skew_past_gits_slop(repo, walk):
    """git's rev-list stops walking excluded history a few commits after only excluded commits are left (its
    SLOP). Old-dated commits, which the ledger key may make, between last good and newer history it already
    reviewed must not let that history back into the range, or a reviewed bad commit would freeze again."""
    def at(seconds: int) -> str:
        return f"@{seconds} +0000"

    future = 4_000_000_000
    base = repo.seed
    bad = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger", date=at(future))
    revert = repo.commit({"people.yaml": SEED_PEOPLE}, "operator", date=at(future + 1))
    rec = repo.commit({}, "operator", message=reviewed(base, bad), date=at(future + 2))
    assert walk(rec, base).valid
    for day in range(12, 2, -1):                         # ten ledger-key commits dated 1970, oldest last
        repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", date=at(86_400 * day))
    last_good = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", date=at(86_400 * 2))
    assert walk(last_good, rec).valid
    side = repo.commit({"notes.md": b"pr\n"}, "operator", parents=[revert], date=at(future + 3))   # off old main
    merge = repo.commit({}, "operator", parents=[last_good, side], date=at(future + 4))
    v = walk(merge, last_good)
    assert (v.valid, v.reason, v.invalid) == (True, None, [])
    assert v.chain == [(merge, "operator")]


def test_duplicate_tree_entries(repo, keyring, trust):
    """A tree git would never write, with one name twice, can't pass the ledger key's path rule."""
    seed_people = repo.git("rev-parse", f"{repo.seed}:people.yaml")
    seed_ledger = repo.git("rev-parse", f"{repo.seed}:ledger.yaml")
    new_ledger, evil_people = repo.blob(ledger_bytes()), repo.blob(people_bytes())
    shapes = {
        "people.yaml twice": [("100644", "ledger.yaml", new_ledger), ("100644", "people.yaml", seed_people),
                              ("100644", "people.yaml", evil_people)],
        "people.yaml twice, the new one first": [("100644", "ledger.yaml", new_ledger),
                                                 ("100644", "people.yaml", evil_people),
                                                 ("100644", "people.yaml", seed_people)],
        "ledger.yaml twice": [("100644", "ledger.yaml", seed_ledger), ("100644", "ledger.yaml", new_ledger),
                              ("100644", "people.yaml", seed_people)],
        "ledger.yaml twice, the new one first": [("100644", "ledger.yaml", new_ledger),
                                                 ("100644", "ledger.yaml", seed_ledger),
                                                 ("100644", "people.yaml", seed_people)],
        "people.yaml twice, the same blob": [("100644", "ledger.yaml", new_ledger),
                                             ("100644", "people.yaml", seed_people),
                                             ("100644", "people.yaml", seed_people)],
    }
    codes = {}
    for name, entries in shapes.items():
        sha = repo.commit({}, "ledger", parents=[repo.seed], tree=repo.raw_tree(entries))
        codes[name] = L.check_commit(repo.path, sha, signer(repo, sha, keyring, trust))
    assert None not in codes.values(), codes


# --- seen heads: every head the box saw since last good must stay on the new head's first-parent line ---------

def _update_branch(repo, merger="web-flow"):
    """The deploy key pushes unsigned X to main and the box freezes on it. Someone clicks GitHub's "Update
    branch" on an open operator PR, which makes the web-flow merge U = [pr tip, X] (or an operator does the
    same merge locally, `merger="operator"`); the deploy key fast-forwards main from X to U. X now sits on U's
    second parent."""
    g = repo.seed
    x = repo.commit({"people.yaml": people_bytes()}, None, parents=[g])
    e = repo.commit({"notes.md": b"pr\n"}, "operator", parents=[g])
    u = repo.commit({"people.yaml": people_bytes()}, merger, parents=[e, x])
    return g, x, e, u


@pytest.mark.parametrize("merger", ["web-flow", "operator"])
def test_update_branch_shape_freezes(merger, repo, walk):
    """No merge brings X in unchecked, with or without seen heads; a web-flow merge is invalid besides."""
    g, x, e, u = _update_branch(repo, merger)
    first = walk(x, g)
    assert (first.reason, first.seen_heads) == (f"invalid:unsigned@{x[:7]}", [x])
    for seen in (None, [x]):
        v = walk(u, g, seen_heads=seen)
        assert (v.valid, v.reason, v.last_good) == (False, f"invalid:unsigned@{x[:7]}", g)
        assert v.invalid == [(x, "unsigned")] + ([(u, "untrusted-signer")] if merger == "web-flow" else [])
    assert v.seen_heads == [x, u]                              # U is recorded, X is kept
    # The next push on U, even a valid ledger-key one, stays frozen on the same reason.
    k = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    v = walk(k, g, seen_heads=v.seen_heads)
    assert (v.valid, v.reason, v.seen_heads) == (False, f"invalid:unsigned@{x[:7]}", [x, u, k])


def test_update_branch_shape_signature_and_seen_head_each_freeze(repo, walk):
    """Each rule on its own. The merge's web-flow signature freezes an Update-branch merge even when what it
    brings in is history the box already took. And when every commit's signature is fine, the seen-heads rule
    still names the seen head that left the line: here a stale operator commit (Q, from an abandoned PR) that
    the deploy key force-pushed to main, then merged back as a second parent by an operator-signed merge."""
    g = repo.seed
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[g])
    assert walk(lg, g).valid
    e = repo.commit({"notes.md": b"pr\n"}, "operator", parents=[g])        # a PR opened before LG
    u = repo.commit({}, "web-flow", parents=[e, lg])                       # "Update branch", main moved to it
    v = walk(u, lg, seen_heads=[])
    assert (v.valid, v.reason, v.invalid) == (False, f"invalid:untrusted-signer@{u[:7]}", [(u, "untrusted-signer")])
    stale = people_bytes()
    q = repo.commit({"people.yaml": stale}, "operator", parents=[g])          # stale, never on main
    v = walk(q, lg, seen_heads=[])
    assert (v.valid, v.reason, v.seen_heads) == (False, "not-fast-forward", [q])
    p = repo.commit({"notes.md": b"pr\n"}, "operator", parents=[lg])
    m = repo.commit({"people.yaml": stale}, "operator", parents=[p, q])
    assert walk(m, lg, seen_heads=[]).valid                    # without the record, Q would ride in
    v = walk(m, lg, seen_heads=[q])
    assert (v.valid, v.reason, v.invalid, v.seen_heads) == (False, f"not-first-parent-descendant@{q[:7]}", [],
                                                            [q, m])
    # Under a recovery the seen head must be inside the range, though its own signature passes.
    narrow = repo.commit({}, "operator", parents=[m], message=reviewed(lg, p))
    v = walk(narrow, lg, seen_heads=[q, m])
    assert (v.valid, v.reason, v.invalid) == (False, f"recovery-misses@{q[:7]}", [])
    rec = repo.commit({}, "operator", parents=[m], message=reviewed(lg, m))
    v = walk(rec, lg, seen_heads=[q, m])
    assert (v.valid, v.recovery, v.seen_heads) == (True, rec, [])


def test_update_branch_shape_needs_a_recovery_that_reviews_the_seen_head(repo, walk):
    g, x, e, u = _update_branch(repo)
    revert = repo.commit({"people.yaml": SEED_PEOPLE}, "operator")
    narrow = repo.commit({}, "operator", message=reviewed(g, e))
    v = walk(narrow, g, seen_heads=[x])
    assert (v.valid, v.reason, v.seen_heads) == (False, f"recovery-misses@{x[:7]}", [x, narrow])
    rec = repo.commit({}, "operator", parents=[revert], message=reviewed(g, u))
    v = walk(rec, g, seen_heads=[x])
    assert (v.valid, v.recovery, v.last_good, v.seen_heads) == (True, rec, rec, [])


@pytest.mark.parametrize("x_signer, code", [(None, "unsigned"), ("untrusted", "untrusted-signer"),
                                            ("expired", "untrusted-signer")])
def test_recovery_outside_a_seen_heads_history_cannot_carry_it_in(x_signer, code, repo, walk):
    """Main sits frozen at X, a seen head. An operator pushes a recovery R = [G] with `Reviewed-Range: G..G`
    (nothing reviewed) on a PR branch; a merge U = [R, X] (signed by an operator, so that only X is in
    question) lands and the deploy key fast-forwards main to U. R overrides the line check, and X is outside
    R's own history, so "the range must hold the seen head" has nothing to say: X must fall to its own check."""
    g = repo.seed
    x = repo.commit({"people.yaml": people_bytes()}, x_signer, parents=[g])
    s = walk(x, g, seen_heads=[]).seen_heads
    assert s == [x]
    rec = repo.commit({}, "operator", parents=[g], message=reviewed(g, g))
    u = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[rec, x])
    v = walk(u, g, seen_heads=s)
    assert (v.valid, v.reason, v.last_good, v.seen_heads) == (False, f"invalid:{code}@{x[:7]}", g, [x, u])
    assert v.invalid == [(x, code)]
    # The same with PR work on top of the recovery, then a valid ledger push after the merge: still frozen.
    e = repo.commit({"notes.md": b"pr\n"}, "operator", parents=[rec])
    u2 = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[e, x])
    v = walk(u2, g, seen_heads=s)
    assert (v.valid, v.reason, v.seen_heads) == (False, f"invalid:{code}@{x[:7]}", [x, u2])
    k = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[u2])
    v = walk(k, g, seen_heads=s)
    assert (v.valid, v.reason, v.last_good, v.seen_heads) == (False, f"invalid:{code}@{x[:7]}", g, [x, k])
    # The remedy reviews X: the box takes it and moves on.
    rec2 = repo.commit({"people.yaml": SEED_PEOPLE}, "operator", parents=[k], message=reviewed(g, k))
    v = walk(rec2, g, seen_heads=s)
    assert (v.valid, v.recovery, v.last_good, v.seen_heads) == (True, rec2, rec2, [])


def test_a_force_pushed_head_is_recorded_and_a_narrow_recovery_misses_it(repo, walk):
    """The box saw unsigned X1 and froze; the attacker force-pushes X2 = [G], which the box sees and records
    beside X1. A merge U = [E, X2] (operator-signed, so that only X2 is in question) lands and main
    fast-forwards to it: X2 is checked under it, and as an invalid commit it is named ahead of the stray X1
    (gone from history). An operator recovery on U
    whose range leaves X2 out must not take X2; one that holds it does, and X1, gone from history, asks
    nothing."""
    g = repo.seed
    x1 = repo.commit({"people.yaml": people_bytes()}, None, parents=[g])
    s = walk(x1, g, seen_heads=[]).seen_heads
    assert s == [x1]
    x2 = repo.commit({"people.yaml": people_bytes()}, None, parents=[g])
    v = walk(x2, g, seen_heads=s)
    assert (v.valid, v.reason, v.seen_heads) == (False, f"invalid:unsigned@{x2[:7]}", [x1, x2])
    s = v.seen_heads
    e = repo.commit({"notes.md": b"pr\n"}, "operator", parents=[g])
    u = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[e, x2])
    v = walk(u, g, seen_heads=s)
    assert (v.valid, v.reason, v.seen_heads) == (False, f"invalid:unsigned@{x2[:7]}", [x1, x2, u])
    assert v.invalid == [(x2, "unsigned")]
    s = v.seen_heads
    for tip in (e, g):                                         # G..E and G..G both leave X2 unreviewed
        rec = repo.commit({}, "operator", parents=[u], message=reviewed(g, tip))
        v = walk(rec, g, seen_heads=s)
        assert (v.valid, v.reason, v.last_good, v.seen_heads) == (False, f"recovery-misses@{x2[:7]}", g, [*s, rec])
        assert v.invalid == [(x2, "unsigned")]
    rec = repo.commit({"people.yaml": SEED_PEOPLE}, "operator", parents=[u], message=reviewed(g, u))
    v = walk(rec, g, seen_heads=s)
    assert (v.valid, v.recovery, v.last_good, v.seen_heads) == (True, rec, rec, [])


def test_pr_work_under_a_merge_is_checked_with_or_without_a_recovery(repo, walk):
    """Unsigned PR work merged right after a recovery freezes in the walk that takes the recovery, and still
    freezes once the box has taken it: no merge exempts anything, under a recovery or not. Signed PR work, in
    the same shape, walks valid both ways."""
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({}, "operator", message=reviewed(last_good, bad))
    pr = repo.commit({"notes.md": b"pr\n"}, None, parents=[rec])
    merge = repo.commit({"notes.md": b"pr\n"}, "operator", parents=[rec, pr])
    v = walk(merge, last_good)
    assert (v.valid, v.reason, v.recovery, v.invalid) == (False, f"invalid:unsigned@{pr[:7]}", None, [(pr, "unsigned")])
    assert walk(rec, last_good).valid
    v = walk(merge, rec, seen_heads=[])
    assert (v.valid, v.reason, v.invalid) == (False, f"invalid:unsigned@{pr[:7]}", [(pr, "unsigned")])
    signed = repo.commit({"notes.md": b"pr, signed\n"}, "operator", parents=[rec])
    merge2 = repo.commit({"notes.md": b"pr, signed\n"}, "operator", parents=[rec, signed])
    assert (walk(merge2, last_good).valid, walk(merge2, last_good).recovery) == (True, rec)
    assert walk(merge2, rec, seen_heads=[]).valid


@pytest.mark.parametrize("x2_signer", [None, "ledger"])
def test_a_forced_sibling_the_box_saw_cannot_ride_under_update_branch_on_a_pr_based_on_last_good(x2_signer, repo,
                                                                                                   walk):
    """Main is valid at X1 (last good; the seen list is clear). An operator's PR branch P = [X1] is open, its
    commits signed. The attacker force-pushes main to X2 = [G]: the box sees it, freezes and records it. A
    merge M = [P, X2] lands (operator-signed here, so that only X2 is in question; GitHub's would be invalid
    anyway) and the deploy key fast-forwards main to M. X1 is on M's line and the walk takes no recovery. An
    unsigned X2 fails its own check under M; a path-valid ledger-key X2 passes it, and the record puts it off
    the line: freeze either way."""
    g = repo.seed
    x1 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[g])
    v = walk(x1, g, seen_heads=[])
    assert (v.valid, v.last_good, v.seen_heads) == (True, x1, [])
    p = repo.commit({"notes.md": b"pr\n"}, "operator", parents=[x1])
    x2 = repo.commit({"ledger.yaml" if x2_signer else "people.yaml": ledger_bytes() if x2_signer else people_bytes()},
                     x2_signer, parents=[g])
    v = walk(x2, x1, seen_heads=[])
    first = f"invalid:unsigned@{x2[:7]}" if x2_signer is None else "not-fast-forward"
    assert (v.valid, v.reason, v.seen_heads) == (False, first, [x2])
    m = repo.commit({"people.yaml": people_bytes(), "notes.md": b"pr\n"}, "operator", parents=[p, x2])
    v = walk(m, x1, seen_heads=[x2])
    reason = f"invalid:unsigned@{x2[:7]}" if x2_signer is None else f"not-first-parent-descendant@{x2[:7]}"
    assert (v.valid, v.reason, v.last_good, v.seen_heads) == (False, reason, x1, [x2, m])
    # The remedy reviews X2 (any range whose tip's history holds it).
    rec = repo.commit({"people.yaml": SEED_PEOPLE}, "operator", parents=[m], message=reviewed(x1, m))
    v = walk(rec, x1, seen_heads=v.seen_heads)
    assert (v.valid, v.recovery, v.last_good, v.seen_heads) == (True, rec, rec, [])


def test_seen_heads_clear_when_last_good_moves(repo, walk):
    """Frozen heads accumulate, in order and once each; a valid walk, by fast-forward or by recovery, clears
    them. Seen heads already in last good's history ask nothing."""
    g = repo.seed
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    assert (walk(lg, g).valid, walk(lg, g).seen_heads) == (True, [])
    v = walk(g, lg, seen_heads=[])                             # a rollback: frozen and recorded
    assert (v.valid, v.reason, v.seen_heads) == (False, "not-fast-forward", [g])
    assert walk(g, lg, seen_heads=[g]).seen_heads == [g]       # the same head again: recorded once
    k = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[lg])
    v = walk(k, lg, seen_heads=[g])                            # G is in done: no requirement; valid clears
    assert (v.valid, v.last_good, v.seen_heads) == (True, k, [])
    x = repo.commit({"people.yaml": people_bytes()}, None, parents=[k])
    y = repo.commit({"people.yaml": people_bytes()}, None, parents=[k])    # force-pushed over X
    s = walk(x, k, seen_heads=[]).seen_heads
    s = walk(y, k, seen_heads=s).seen_heads
    assert s == [x, y]
    rec = repo.commit({"people.yaml": SEED_PEOPLE}, "operator", parents=[y], message=reviewed(k, y))
    v = walk(rec, k, seen_heads=s)                             # X is gone from history: nothing to review
    assert (v.valid, v.recovery, v.last_good, v.seen_heads) == (True, rec, rec, [])


def test_a_recovery_covering_every_seen_head_takes_it(repo, walk):
    g = repo.seed
    x = repo.commit({"people.yaml": people_bytes()}, None, parents=[g])
    y = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[x])
    s = walk(x, g).seen_heads
    s = walk(y, g, seen_heads=s).seen_heads
    assert s == [x, y]
    e = repo.commit({"notes.md": b"pr\n"}, "operator", parents=[g])
    u = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[e, y])     # an Update-branch merge
    v = walk(u, g, seen_heads=s)
    assert (v.valid, v.reason, v.seen_heads) == (False, f"invalid:unsigned@{x[:7]}", [x, y, u])
    s = v.seen_heads
    narrow = repo.commit({"people.yaml": SEED_PEOPLE}, "operator", parents=[u], message=reviewed(g, e))
    v = walk(narrow, g, seen_heads=s)
    assert (v.valid, v.reason, v.seen_heads) == (False, f"recovery-misses@{x[:7]}", [*s, narrow])
    rec = repo.commit({"people.yaml": SEED_PEOPLE}, "operator", parents=[u], message=reviewed(g, y))
    v = walk(rec, g, seen_heads=s)                             # G..Y holds X and Y; U is the line
    assert (v.valid, v.recovery, v.last_good, v.seen_heads) == (True, rec, rec, [])


@pytest.mark.parametrize("signer_", ["web-flow", "operator"])
def test_pr_merged_into_a_non_main_base_freezes(signer_, repo, walk):
    """A PR branched from main at X, merged into another base branch; the deploy key fast-forwards main to
    that merge. Its first parent is the other branch, so X left the first-parent line. X is checked under the
    merge whatever the seen list holds; with every other commit operator-signed, it alone is named."""
    g = repo.seed
    x = repo.commit({"people.yaml": people_bytes()}, None, parents=[g])
    pr = repo.commit({"notes.md": b"pr\n"}, "operator", parents=[x])
    other = repo.commit({"notes.md": b"other base\n"}, signer_, parents=[g])
    w = repo.commit({}, signer_, parents=[other, pr])
    for seen in (None, [x]):
        v = walk(w, g, seen_heads=seen)
        first, code = v.invalid[0]
        assert (v.valid, v.reason) == (False, f"invalid:{code}@{first[:7]}")
        if signer_ == "operator":
            assert v.invalid == [(x, "unsigned")]
        else:
            assert sorted(v.invalid) == sorted([(x, "unsigned"), (other, "untrusted-signer"),
                                                (w, "untrusted-signer")])


@pytest.mark.parametrize("how", ["local squash", "fast-forward", "rebase and re-sign", "local merge of signed work",
                                 "service push", "two pushes between runs"])
def test_local_landings_keep_the_previous_tip_first(how, repo, walk):
    """Every way an operator lands a change on main (How changes land) keeps the previous tip on the
    first-parent line and walks valid, and a seen list that holds last good itself (as a caller might seed it)
    asks nothing."""
    g = repo.seed
    tip = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    assert walk(tip, g).valid
    if how == "local squash":
        repo.commit({"people.yaml": people_bytes()}, None, parents=[g])          # the PR branch, never on main
        head = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[tip])
    elif how == "fast-forward":
        repo.commit({"people.yaml": people_bytes()}, "operator", parents=[tip])
        head = repo.commit({"notes.md": b"pr\n"}, "operator")
    elif how == "rebase and re-sign":                         # work based on G, rebased onto tip and re-signed
        repo.commit({"people.yaml": people_bytes()}, None, parents=[g])
        repo.commit({"people.yaml": people_bytes()}, "operator", parents=[tip])
        head = repo.commit({"notes.md": b"pr\n"}, "operator")
    elif how == "local merge of signed work":
        p1 = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[tip])
        p2 = repo.commit({"notes.md": b"pr\n"}, "operator")
        head = repo.commit({"people.yaml": people_bytes(), "notes.md": b"pr\n"}, "operator", parents=[tip, p2])
        assert p1 not in dict(walk(head, tip, seen_heads=[tip]).chain)
    elif how == "service push":
        head = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[tip])
    else:
        repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[tip])
        head = repo.commit({"people.yaml": people_bytes()}, "operator")
    v = walk(head, tip, seen_heads=[tip])
    assert (v.valid, v.reason, v.seen_heads, v.last_good) == (True, None, [], head)


def test_a_frozen_head_on_the_line_is_recorded_too(repo, walk):
    """A head frozen for an invalid commit is recorded like any other, behind the earlier one."""
    g = repo.seed
    bad = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger")
    after = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    v = walk(after, g, seen_heads=[bad])
    assert (v.valid, v.reason, v.seen_heads) == (False, f"invalid:ledger-path@{bad[:7]}", [bad, after])


def test_erasure_with_seen_heads(repo, walk):
    """The erasure force-push leaves the box's seen heads out of the new history; the operator's Reviewed-Range
    takes it, and the gone heads ask nothing."""
    old_tip = repo.commit({"people.yaml": people_bytes()}, "web-flow")
    r1 = repo.commit({"people.yaml": SEED_PEOPLE, "ledger.yaml": EMPTY_LEDGER}, None, parents=[])
    r2 = repo.commit({"ledger.yaml": ledger_bytes()}, None)
    plain = repo.commit({}, "operator", parents=[r2])
    v = walk(plain, old_tip, seen_heads=[])
    assert (v.valid, v.seen_heads) == (False, [plain])
    rec = repo.commit({}, "operator", parents=[r2], message=reviewed(old_tip, r2))
    v = walk(rec, old_tip, seen_heads=v.seen_heads)
    assert (v.valid, v.recovery, v.seen_heads) == (True, rec, [])
    assert r1 in dict(v.chain)


def test_a_seen_head_not_in_the_checkout(repo, walk):
    v = walk(repo.seed, repo.seed, seen_heads=["e" * 40])
    assert (v.valid, v.reason, v.seen_heads) == (False, "not-first-parent-descendant@eeeeeee", ["e" * 40, repo.seed])
    for bad in (["HEAD"], "e" * 40, [repo.seed[:7]]):          # not a sha, a bare string, a short sha
        with pytest.raises(ValueError):
            walk(repo.seed, repo.seed, seen_heads=bad)


# --- no web-flow on sso-people: the web editor, GitHub's buttons, local landings, the changeover anchor -----------

def _tree_of(repo, sha: str) -> str:
    return repo.git("rev-parse", f"{sha}^{{tree}}")


@pytest.mark.parametrize("path", ["README.md", "people.yaml"])
def test_web_flow_commit_freezes(path, repo, walk, keyring, trust):
    """A web-flow commit is invalid whatever it changes: a README edit in the web UI freezes like a people.yaml
    edit does. Check mode keeps applying from last good."""
    base = repo.seed
    wf = repo.commit({path: people_bytes() if path == "people.yaml" else b"# sso-people\n"}, "web-flow",
                     parents=[base])
    assert signer(repo, wf, keyring, trust) == "untrusted"
    v = walk(wf, base, seen_heads=[])
    assert (v.valid, v.reason, v.invalid) == (False, f"invalid:untrusted-signer@{wf[:7]}", [(wf, "untrusted-signer")])
    assert (v.last_good, v.newest_trusted, v.chain, v.seen_heads) == (base, base, [(wf, "untrusted")], [wf])


def test_web_flow_editor_commit_from_another_repo_freezes(repo, walk, keyring, trust, tmp_path):
    """The Critical finding. Anyone can copy sso-people's history into a GitHub repo of their own and edit
    people.yaml there in the web editor; GitHub signs that commit with web-flow's key. With the service's deploy
    key the commit is then pushed to sso-people's main, on top of last good. It freezes: check mode doesn't apply
    it, a rebuilt box doesn't start from it, and a valid push on top of it doesn't lift the freeze."""
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    assert walk(lg, repo.seed).valid
    copy = repo.clone(tmp_path / "someone-elses-repo")
    copy.commit({"people.yaml": people_bytes()}, "web-flow", message="Update people.yaml")
    minted = repo.take(copy)
    assert repo.show("%P|%cn", minted, keyring) == f"{lg}|GitHub"
    v = walk(minted, lg, seen_heads=[])
    assert (v.valid, v.reason, v.invalid) == (False, f"invalid:untrusted-signer@{minted[:7]}",
                                              [(minted, "untrusted-signer")])
    assert (v.last_good, v.newest_trusted, v.recovery, v.seen_heads) == (lg, lg, None, [minted])
    k = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    v = walk(k, lg, seen_heads=v.seen_heads)
    assert (v.valid, v.reason, v.newest_trusted, v.seen_heads) == (False, f"invalid:untrusted-signer@{minted[:7]}",
                                                                   lg, [minted, k])


def test_merge_button_merge_freezes(repo, walk):
    """GitHub's merge button on a PR of operator-signed commits: the PR's commits pass their own check, the
    web-flow merge commit doesn't, and the reason names it. The way out is an operator's Reviewed-Range."""
    base = repo.seed
    repo.commit({"people.yaml": people_bytes()}, "operator", parents=[base])
    p2 = repo.commit({"notes.md": b"pr\n"}, "operator")
    merge = repo.commit({}, "web-flow", parents=[base, p2], tree=_tree_of(repo, p2), message="Merge pull request #1")
    v = walk(merge, base, seen_heads=[])
    assert (v.valid, v.reason, v.invalid) == (False, f"invalid:untrusted-signer@{merge[:7]}",
                                              [(merge, "untrusted-signer")])
    assert (v.chain, v.last_good, v.newest_trusted) == ([(merge, "untrusted")], base, base)
    k = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    assert walk(k, base, seen_heads=[merge]).reason == f"invalid:untrusted-signer@{merge[:7]}"
    rec = repo.commit({}, "operator", message=reviewed(base, merge))
    v = walk(rec, base, seen_heads=[merge, k])
    assert (v.valid, v.recovery, v.last_good, v.seen_heads) == (True, rec, rec, [])


def test_squash_button_freezes(repo, walk):
    base = repo.seed
    pr_people = people_bytes()
    repo.commit({"people.yaml": pr_people}, "operator", parents=[base])         # the PR branch, never on main
    squash = repo.commit({"people.yaml": pr_people}, "web-flow", parents=[base], message="Add a member (#2)")
    v = walk(squash, base, seen_heads=[])
    assert (v.valid, v.reason, v.invalid, v.chain) == (False, f"invalid:untrusted-signer@{squash[:7]}",
                                                       [(squash, "untrusted-signer")], [(squash, "untrusted")])


def test_rebase_button_freezes(repo, walk):
    """GitHub's rebase-and-merge re-creates each PR commit on main and signs every one with web-flow's key, the
    operator-signed originals included: each re-created commit is invalid, and the first one is named."""
    base = repo.seed
    pr_people = people_bytes()
    o1 = repo.commit({"people.yaml": pr_people}, "operator", parents=[base])
    o2 = repo.commit({"notes.md": b"pr\n"}, "operator")
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[base])     # main moved on meanwhile
    assert walk(lg, base).valid
    r1 = repo.commit({"people.yaml": pr_people}, "web-flow", parents=[lg])
    r2 = repo.commit({"notes.md": b"pr\n"}, "web-flow")
    v = walk(r2, lg, seen_heads=[])
    assert (v.valid, v.reason) == (False, f"invalid:untrusted-signer@{r1[:7]}")
    assert v.invalid == [(r1, "untrusted-signer"), (r2, "untrusted-signer")]
    assert not {o1, o2} & set(dict(v.chain))


def test_operator_local_squash_is_valid(repo, walk):
    """How changes land: a contributor's PR (unsigned and unknown-key commits, based on an older main) squashed
    locally into one commit the operator signs on main's tip, then pushed to main."""
    base = repo.seed
    pr_people = people_bytes()
    pr1 = repo.commit({"people.yaml": pr_people}, None, parents=[base])
    pr2 = repo.commit({"notes.md": b"pr\n"}, "untrusted")
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[base])
    assert walk(lg, base).valid
    squash = repo.commit({"people.yaml": pr_people, "notes.md": b"pr\n"}, "operator", parents=[lg])
    v = walk(squash, lg, seen_heads=[])
    assert (v.valid, v.reason, v.chain, v.last_good, v.newest_trusted) == (True, None, [(squash, "operator")],
                                                                          squash, squash)
    assert not {pr1, pr2} & set(dict(v.chain))


def test_operator_fast_forward_of_signed_commits_is_valid(repo, walk):
    """How changes land: a branch of commits the operator signed, on main's tip, fast-forwarded. One commit in
    such a branch that the operator didn't sign freezes the box: "commits you signed" is the rule."""
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    assert walk(lg, repo.seed).valid
    o1 = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[lg])
    o2 = repo.commit({"notes.md": b"pr\n"}, "operator")
    v = walk(o2, lg, seen_heads=[])
    assert (v.valid, v.chain, v.last_good) == (True, [(o1, "operator"), (o2, "operator")], o2)
    c1 = repo.commit({"people.yaml": people_bytes()}, None, parents=[lg])
    c2 = repo.commit({"notes.md": b"pr\n"}, "operator")
    v = walk(c2, lg, seen_heads=[])
    assert (v.valid, v.reason, v.invalid) == (False, f"invalid:unsigned@{c1[:7]}", [(c1, "unsigned")])


def test_a_rebuild_seeds_only_from_the_anchor(repo, walk):
    """D6 as ruled: a box with no state (a first run, a rebuild) takes last good from the anchor the operator
    recorded, and from nothing else. An operator commit on top of an invalid one vouches for nothing: the walk
    from the anchor still meets W, so W's people.yaml never lands unreviewed. There is no function that would
    pick a later operator commit as the seed."""
    assert not hasattr(L, "reanchor")
    anchor = repo.commit({"people.yaml": people_bytes()}, "web-flow")       # the last head the old code applied
    w = repo.commit({"people.yaml": people_bytes()}, "web-flow")            # a minted commit, pushed later
    o = repo.commit({"notes.md": b"o\n"}, "operator")                       # an operator commits on top of it
    v = walk(o, anchor, seen_heads=[])
    assert (v.valid, v.reason, v.last_good) == (False, f"invalid:untrusted-signer@{w[:7]}", anchor)
    assert v.invalid == [(w, "untrusted-signer")]
    # The way out is the usual one: an operator recovery naming the anchor.
    rec = repo.commit({"people.yaml": SEED_PEOPLE}, "operator", message=reviewed(anchor, o))
    v = walk(rec, anchor, seen_heads=[])
    assert (v.valid, v.recovery, v.last_good) == (True, rec, rec)
    # The anchor off head's line: the walk from it freezes, an operator commit on that line notwithstanding.
    repo.commit({"people.yaml": people_bytes()}, "operator", parents=[repo.seed])
    off = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    v = walk(off, anchor, seen_heads=[])
    assert (v.valid, v.reason, v.last_good) == (False, "not-fast-forward", anchor)


def test_a_rebuild_after_a_past_recovery_needs_a_new_one(repo, walk):
    """The price of seeding from the anchor alone. A rebuilt box walks everything since the anchor again, and a
    recovery the box took earlier named the last good of its day, not the anchor: stale. One operator recovery
    naming the anchor and the current tip takes it."""
    anchor = repo.seed
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    bad = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger")
    repo.commit({"people.yaml": SEED_PEOPLE}, "operator")
    rec = repo.commit({}, "operator", message=reviewed(lg, bad))
    assert walk(rec, lg).valid                                  # what the box did before it was rebuilt
    head = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    v = walk(head, anchor, seen_heads=[])                       # the rebuilt box
    assert (v.valid, v.reason) == (False, f"recovery-stale-last-good@{rec[:7]}")
    again = repo.commit({}, "operator", message=reviewed(anchor, head))
    v = walk(again, anchor, seen_heads=[])
    assert (v.valid, v.recovery) == (True, again)


def test_changeover_history_never_walked(repo, walk, keyring, trust):
    """The changeover: everything up to the anchor landed under the old rules (a GitHub merge of unsigned PR
    work, a squash button, a web-editor commit), and the anchor itself is web-flow's. With last good at the
    anchor that history is never walked, and operator and ledger-key commits after it walk valid. Walked from
    before the anchor, it would freeze."""
    g = repo.seed
    pr = repo.commit({"people.yaml": people_bytes()}, None, parents=[g])
    m = repo.commit({}, "web-flow", parents=[g, pr], tree=_tree_of(repo, pr))
    sq = repo.commit({"people.yaml": people_bytes()}, "web-flow")
    anchor = repo.commit({"README.md": b"# sso-people\n"}, "web-flow")
    l1 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    o1 = repo.commit({"people.yaml": people_bytes()}, "operator")
    l2 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    v = walk(l2, anchor, seen_heads=[])
    assert (v.valid, v.reason, v.invalid, v.last_good) == (True, None, [], l2)
    assert v.chain == [(l1, "ledger"), (o1, "operator"), (l2, "ledger")]
    old = walk(l2, g)
    assert old.valid is False and {pr, m, sq, anchor} <= set(dict(old.invalid))


# --- grafts and shallow checkouts -------------------------------------------------------------------------------

def test_grafts_cannot_hide_commits(repo, walk):
    base = repo.seed
    x = repo.commit({"people.yaml": people_bytes()}, None, parents=[base])
    o = repo.commit({"notes.md": b"o\n"}, "operator", parents=[x])
    assert walk(o, base).reason == f"invalid:unsigned@{x[:7]}"
    (repo.path / ".git/info").mkdir(exist_ok=True)
    (repo.path / ".git/info/grafts").write_text(f"{o} {base}\n")      # o's parent rewritten to base: x hidden
    assert walk(o, base).reason == f"invalid:unsigned@{x[:7]}"


def test_shallow_repository_refused(repo, walk):
    base = repo.seed
    head = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    assert walk(head, base).valid
    (repo.path / ".git/shallow").write_text(f"{head}\n")
    v = walk(head, base, seen_heads=[base])
    assert (v.valid, v.reason, v.last_good, v.seen_heads) == (False, "shallow-repository", base, [base, head])


# --- newest trusted, inputs, and how git is called --------------------------------------------------------------

def test_newest_trusted_skips_what_cannot_land(repo, walk, keyring, trust):
    """Where check mode applies people.yaml from. Web-flow, unsigned and expired-key commits are never it, and
    neither is an operator commit with one of them beneath it; last good counts whoever signed it, the
    web-flow-signed changeover anchor included."""
    def nt(head, last_good):
        return L.newest_trusted(repo.path, head, last_good, keyring, trust)

    assert list(inspect.signature(L.newest_trusted).parameters) == ["repo", "head", "last_good", "keyring", "trust"]
    op = repo.commit({"people.yaml": people_bytes()}, "operator")
    anchor = repo.commit({"people.yaml": people_bytes()}, "web-flow")       # applied before the changeover
    repo.commit({"people.yaml": people_bytes()}, "web-flow")
    repo.commit({"ledger.yaml": ledger_bytes()}, None)
    head = repo.commit({"ledger.yaml": ledger_bytes()}, "expired")
    assert nt(head, anchor) == anchor != op                    # not the operator commit under it
    assert walk(head, anchor).newest_trusted == anchor
    assert nt(anchor, anchor) == anchor
    # An operator commit on top vouches for nothing beneath it.
    op2 = repo.commit({"people.yaml": people_bytes()}, "operator")
    head2 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    assert nt(head2, anchor) == anchor
    assert walk(head2, anchor).newest_trusted == anchor != op2
    # Second parents don't count: only the first-parent line is searched.
    side = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[anchor])
    merge = repo.commit({}, None, parents=[head, side])
    assert nt(merge, anchor) == anchor
    # Last good off the line, or a history without it: last good itself, never None.
    sibling = repo.commit({"people.yaml": people_bytes()}, "web-flow", parents=[repo.seed])
    assert nt(sibling, anchor) == anchor
    lone = repo.commit({"ledger.yaml": EMPTY_LEDGER}, "web-flow", parents=[])
    assert nt(lone, anchor) == anchor
    with pytest.raises(ValueError):
        nt(head, anchor[:7])
    with pytest.raises(L.GitError):
        nt(head, "e" * 40)                       # a last good that isn't in the checkout


def test_newest_trusted_never_rolls_back_past_last_good(repo, walk, keyring, trust):
    """Check mode must never re-apply a people.yaml from before last good. O_old, then O_new (a deactivation),
    then LG, the last good. A head on O_old (an unsigned X), an unsigned merge M = [O_old, LG] and a plain
    force-push back to O_old all have O_old as the newest operator commit on their first-parent line, and O_old
    lacks LG: each gives LG. A commit counts only if last good is in its history, so an operator-signed merge
    of LG on O_old does count; the operator signed its tree."""
    def nt(head):
        return L.newest_trusted(repo.path, head, lg, keyring, trust)

    o_old = repo.commit({"people.yaml": people_bytes()}, "operator")
    repo.commit({"people.yaml": people_bytes()}, "operator")                # O_new: the deactivation
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    x = repo.commit({"notes.md": b"x\n"}, None, parents=[o_old])
    m = repo.commit({}, None, parents=[o_old, lg])
    for head in (x, m, o_old):
        assert nt(head) == lg
        v = walk(head, lg, seen_heads=[])
        assert (v.valid, v.newest_trusted) == (False, lg)
    om = repo.commit({}, "operator", parents=[o_old, lg])
    assert nt(om) == om
    above = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[x])
    assert nt(above) == lg


def test_newest_trusted_is_the_newest_commit_that_walks_valid(repo, walk, keyring, trust):
    """The ruling: the newest first-parent commit C that has last good in its history, is operator-signed or a
    path-valid ledger-key commit, and for which walk(C, last_good) is valid; else last good. So check mode
    applies exactly what apply mode would have taken, stopping before the first problem."""
    def nt(head, last_good):
        return L.newest_trusted(repo.path, head, last_good, keyring, trust)

    g = repo.seed
    # LG, a minted web-flow commit, an operator commit on top: last good, not O.
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[g])
    w = repo.commit({"people.yaml": people_bytes()}, "web-flow")
    o = repo.commit({"notes.md": b"o\n"}, "operator")
    assert nt(o, lg) == lg
    assert (walk(o, lg).valid, walk(o, lg).newest_trusted) == (False, lg)
    assert nt(w, lg) == lg
    # LG, a ledger commit, an operator commit: all valid, so O; a valid ledger push on top is newer still.
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[g])
    lc = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    o = repo.commit({"people.yaml": people_bytes()}, "operator")
    assert nt(o, lg) == o and walk(o, lg).newest_trusted == o
    top = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    assert nt(top, lg) == top and nt(lc, lg) == lc
    # Valid, then invalid, then valid again: the last commit before the first problem.
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[g])
    repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    o1 = repo.commit({"people.yaml": people_bytes()}, "operator")
    repo.commit({"people.yaml": people_bytes()}, None)
    repo.commit({"people.yaml": people_bytes()}, "operator")
    l2 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    assert nt(l2, lg) == o1
    assert (walk(l2, lg).valid, walk(l2, lg).newest_trusted) == (False, o1)
    # A recovery the walk takes makes the commits after it valid again.
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[g])
    bad = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger")
    revert = repo.commit({"people.yaml": SEED_PEOPLE}, "operator")
    assert nt(revert, lg) == lg
    repo.commit({}, "operator", message=reviewed(lg, bad))
    l3 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    assert nt(l3, lg) == l3 and walk(l3, lg).newest_trusted == l3
    # A path-invalid ledger commit is never it, whatever lies beneath.
    lp = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger")
    assert nt(lp, lg) == l3


def test_newest_trusted_fails_closed(repo, walk, keyring, trust, monkeypatch):
    """A candidate walk that errors gives last good, never a commit nearer the head: in newest_trusted on its
    own, and in the verdict of a walk whose own check still runs."""
    lg = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    head = repo.commit({"people.yaml": people_bytes()}, "operator")
    bad = repo.commit({"people.yaml": people_bytes()}, None)
    assert L.newest_trusted(repo.path, head, lg, keyring, trust) == head
    assert walk(bad, lg).newest_trusted == head
    real = L._judge

    def judge(repo_path, graph, tip, *args, **kw):     # the walk's own head passes; every candidate errors
        if tip != bad:
            raise L.GitError("a candidate walk failed")
        return real(repo_path, graph, tip, *args, **kw)

    monkeypatch.setattr(L, "_judge", judge)
    assert L.newest_trusted(repo.path, head, lg, keyring, trust) == lg
    v = walk(bad, lg)
    assert (v.valid, v.reason, v.newest_trusted) == (False, f"invalid:unsigned@{bad[:7]}", lg)


def test_walk_refuses_bad_input(repo, walk):
    for bad in (repo.seed[:7], "--all", "HEAD", "g" * 40, repo.seed.upper()):
        with pytest.raises(ValueError):
            walk(bad, repo.seed)
        with pytest.raises(ValueError):
            walk(repo.seed, bad)
    with pytest.raises(L.GitError):
        walk(repo.seed, "e" * 40)                # a last good that isn't in the checkout


def test_walk_reads_git_only(repo, walk, monkeypatch):
    """walk never parses YAML (D2), and every git call has a 30 s timeout and the C locale."""
    base = repo.seed
    repo.commit({"ledger.yaml": b"version: [\n"}, "ledger")
    bad = repo.commit({"ledger.yaml": b"&a x: *a\n", "people.yaml": people_bytes()}, "ledger")
    revert = repo.commit({"people.yaml": SEED_PEOPLE}, "operator")
    head = repo.commit({}, "operator", message=reviewed(base, bad))
    calls = []
    real_run = L.subprocess.run

    def run(cmd, *args, **kw):
        calls.append((cmd, kw.get("timeout"), (kw.get("env") or {}).get("LC_ALL")))
        return real_run(cmd, *args, **kw)

    def no_yaml(*_args, **_kw):
        raise AssertionError("walk parsed YAML")

    monkeypatch.setattr(L.subprocess, "run", run)
    monkeypatch.setattr(L, "parse_ledger", no_yaml)
    monkeypatch.setattr(L.yaml, "load", no_yaml)
    monkeypatch.setattr(L.yaml, "safe_load", no_yaml)
    monkeypatch.setattr(L._Loader, "get_single_data", no_yaml)
    v = walk(head, base)
    assert (v.valid, v.recovery) == (True, head)
    assert revert in dict(v.chain)
    assert calls
    assert {c[0][0] for c in calls} == {"git"}
    assert {(c[1], c[2]) for c in calls} == {(30, "C")}


def test_git_ignores_the_callers_git_environment(repo, walk, keyring, trust, tmp_path, monkeypatch):
    """Every GIT_* variable the box's environment holds is dropped: none may inject config (`-c` travels as
    GIT_CONFIG_PARAMETERS), point git at another repository or bring in a user or system gitconfig."""
    sha = repo.commit({"ledger.yaml": ledger_bytes()}, "operator")
    hostile = tmp_path / "gitconfig"
    hostile.write_text("[gpg]\n\tprogram = false\n[log]\n\tshowSignature = true\n")
    monkeypatch.setenv("GIT_CONFIG_PARAMETERS", "'gpg.program=false' 'log.showsignature=true'")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "gpg.program")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(hostile))
    monkeypatch.delenv("GIT_CONFIG_NOSYSTEM", raising=False)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "elsewhere"))
    monkeypatch.setenv("GIT_REPLACE_REF_BASE", "refs/elsewhere/")
    seen = []
    real_run = L.subprocess.run

    def run(cmd, *args, **kw):
        seen.append({k for k in kw["env"] if k.startswith("GIT_")})
        return real_run(cmd, *args, **kw)

    monkeypatch.setattr(L.subprocess, "run", run)
    assert signer(repo, sha, keyring, trust) == "operator"
    assert walk(sha, repo.seed).valid
    assert {frozenset(s) for s in seen} == {frozenset({"GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_GRAFT_FILE",
                                                       "GIT_NO_REPLACE_OBJECTS", "GIT_TERMINAL_PROMPT"})}
