"""The box's commit check: signer classes, the ledger key's path rule, the first-parent walk and recovery
(sso_ledger.commit_signer, check_commit, walk, newest_trusted, parse_reviewed_range, load_trust)."""
import inspect
import itertools
import json

import pytest

import sso_ledger as L

from .conftest import EMPTY_LEDGER, SEED_PEOPLE

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
    return lambda head, last_good: L.walk(repo.path, head, last_good, keyring, trust)


def signer(repo, sha, keyring, trust):
    return L.commit_signer(repo.path, sha, keyring, trust)


# --- trust and signers ----------------------------------------------------------------------------------------

def test_load_trust(tmp_path):
    a, b, c = "a" * 40, "B" * 40, "c" * 40
    path = tmp_path / "people-trust.json"
    path.write_text(json.dumps({"operators": [a], "web_flow": [b], "ledger": [c]}))
    assert L.load_trust(path) == L.Trust(frozenset({"A" * 40}), frozenset({"B" * 40}), frozenset({"C" * 40}))
    for bad in ({"operators": [a], "web_flow": [b]},                                  # a class missing
                {"operators": [a], "web_flow": [b], "ledger": [c], "extra": []},      # an unknown class
                {"operators": [a], "web_flow": [b], "ledger": [a]},                   # one key in two classes
                {"operators": [a.lower()], "web_flow": [b], "ledger": [a.upper()]},
                {"operators": ["a" * 39], "web_flow": [b], "ledger": [c]},            # not a fingerprint
                {"operators": "a" * 40, "web_flow": [b], "ledger": [c]},
                [a, b, c]):
        path.write_text(json.dumps(bad))
        with pytest.raises(ValueError):
            L.load_trust(path)


def test_signer_classes(repo, keys, keyring, trust):
    made = {name: repo.commit({"ledger.yaml": ledger_bytes()}, name)
            for name in ("operator", "web-flow", "ledger", "untrusted", None, "expired")}
    got = {name: signer(repo, sha, keyring, trust) for name, sha in made.items()}
    assert got == {"operator": "operator", "web-flow": "web-flow", "ledger": "ledger", "untrusted": "untrusted",
                   None: "untrusted", "expired": "untrusted"}
    # The fixtures mean what they say: the operator signs with a subkey, so the class must come from the
    # primary (%GP); the expired key's signature is good but its key has expired (Y), not merely unknown.
    assert repo.show("%G?|%GF", made["operator"], keyring) != f"G|{keys['operator'].fpr}"
    assert repo.show("%G?|%GP", made["operator"], keyring) == f"G|{keys['operator'].fpr}"
    assert repo.show("%G?", made["expired"], keyring) == "Y"
    assert repo.show("%G?", made["untrusted"], keyring) == "E"


def test_signer_needs_a_class(repo, keys, keyring, trust):
    """A good signature from a key in the keyring but in no class of people-trust.json is untrusted."""
    sha = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    only_operators = L.Trust(trust.operators, frozenset(), frozenset())
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


@pytest.mark.parametrize("who", ["operator", "web-flow"])
@pytest.mark.parametrize("name", list(PATH_RULE))
def test_operator_and_web_flow_may_change_any_path(name, who, repo, keyring, trust):
    sha = _case(repo, name, who)
    cls = signer(repo, sha, keyring, trust)
    assert cls == who
    assert L.check_commit(repo.path, sha, cls) is None


@pytest.mark.parametrize("who,code", [(None, "unsigned"), ("untrusted", "untrusted-signer"),
                                      ("expired", "untrusted-signer")])
def test_unsigned_or_unknown_key_invalid(who, code, repo, keyring, trust):
    sha = repo.commit({"ledger.yaml": ledger_bytes()}, who)
    assert L.check_commit(repo.path, sha, signer(repo, sha, keyring, trust)) == code


# --- the walk -------------------------------------------------------------------------------------------------

def test_merge_counts_against_first_parent(repo, walk):
    base = repo.seed
    inner1 = repo.commit({"people.yaml": people_bytes()}, None, parents=[base])
    inner2 = repo.commit({"ledger.yaml": ledger_bytes(), "notes.md": b"x\n"}, "untrusted")
    merge = repo.commit({"people.yaml": people_bytes(), "notes.md": b"x\n"}, "web-flow", parents=[base, inner2])
    v = walk(merge, base)
    assert (v.valid, v.reason, v.invalid) == (True, None, [])
    assert v.chain == [(merge, "web-flow")]
    assert inner1 not in dict(v.chain) and inner2 not in dict(v.chain)


def _pull_merge(repo, who="operator"):
    """The service pushed a ledger-key commit that also changed people.yaml; an operator's local `git pull`
    merged it as the second parent of a commit of their own, then pushed."""
    base = repo.seed
    people, led = people_bytes(), ledger_bytes()
    pushed = repo.commit({"ledger.yaml": led, "people.yaml": people}, "ledger", parents=[base])
    local = repo.commit({"notes.md": b"local\n"}, "operator", parents=[base])
    merge = repo.commit({"ledger.yaml": led, "people.yaml": people}, who, parents=[local, pushed])
    return base, pushed, local, merge


@pytest.mark.parametrize("who", ["operator", "web-flow"])
def test_ledger_key_commit_under_a_merge_freezes(who, repo, walk):
    """Every ledger-key commit in last_good..head is held to the path rule, whichever parent brings it in."""
    base, pushed, local, merge = _pull_merge(repo, who)
    v = walk(merge, base)
    assert (v.valid, v.reason, v.recovery) == (False, f"invalid:ledger-path@{pushed[:7]}", None)
    assert v.invalid == [(pushed, "ledger-path")]
    assert v.chain == [(local, "operator"), (merge, who)]


def test_ledger_key_commits_under_a_merge_obey_the_path_rule(repo, walk):
    base = repo.seed
    fine = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[base])
    local = repo.commit({"notes.md": b"local\n"}, "operator", parents=[base])
    merge = repo.commit({}, "operator", parents=[local, fine])
    assert walk(merge, base).valid                          # ledger.yaml alone, one parent: fine anywhere
    lmerge = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger", parents=[fine, local])
    head = repo.commit({}, "web-flow", parents=[merge, lmerge])
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


# Commits a merge brings in on its other parents go unchecked only under a web-flow merge: GitHub always keeps
# main's tip as the first parent, so a push that froze the box stays on the first-parent line. Under an
# operator's local merge every such commit gets the full check.

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


def test_operator_local_merge_of_unsigned_pr_work_freezes(repo, walk):
    base = repo.seed
    pr1 = repo.commit({"people.yaml": people_bytes()}, None, parents=[base])
    pr2 = repo.commit({"notes.md": b"pr\n"}, "untrusted")
    pr3 = repo.commit({"notes.md": b"pr, signed\n"}, "operator")
    merge = repo.commit({"people.yaml": people_bytes()}, "operator", parents=[base, pr3])
    v = walk(merge, base)
    assert (v.valid, v.reason) == (False, f"invalid:unsigned@{pr1[:7]}")
    assert v.invalid == [(pr1, "unsigned"), (pr2, "untrusted-signer")]
    # The operator who meant it reviews the range.
    rec = repo.commit({}, "operator", message=reviewed(base, merge))
    assert (walk(rec, base).valid, walk(rec, base).recovery) == (True, rec)


def test_web_flow_merge_of_unsigned_pr_work_walks_valid(repo, walk):
    """A GitHub merge of a PR branch: its commits need no signature, even one under an operator merge inside
    the branch. A ledger-key commit in the branch still obeys the path rule (round 1)."""
    base = repo.seed
    pr1 = repo.commit({"people.yaml": people_bytes()}, None, parents=[base])
    side = repo.commit({"notes.md": b"side\n"}, None, parents=[base])
    inner = repo.commit({}, "operator", parents=[pr1, side])
    pr2 = repo.commit({"notes.md": b"pr\n"}, "expired")
    merge = repo.commit({"people.yaml": people_bytes()}, "web-flow", parents=[base, pr2])
    v = walk(merge, base)
    assert (v.valid, v.reason, v.invalid, v.chain) == (True, None, [], [(merge, "web-flow")])
    assert inner not in dict(v.chain)
    bad = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger", parents=[pr2])
    merge2 = repo.commit({}, "web-flow", parents=[merge, bad])
    assert walk(merge2, base).reason == f"invalid:ledger-path@{bad[:7]}"


def test_valid_chain(repo, walk):
    base = repo.seed
    op = repo.commit({"people.yaml": people_bytes()}, "operator")
    l1 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    wf = repo.commit({"people.yaml": people_bytes(), "ledger.yaml": ledger_bytes()}, "web-flow")
    l2 = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    v = walk(l2, base)
    assert v == L.WalkVerdict(head=l2, last_good=l2, valid=True, reason=None,
                              chain=[(op, "operator"), (l1, "ledger"), (wf, "web-flow"), (l2, "ledger")],
                              invalid=[], recovery=None, newest_trusted=wf)


def test_head_is_last_good(repo, walk):
    v = walk(repo.seed, repo.seed)
    assert (v.valid, v.chain, v.last_good, v.newest_trusted) == (True, [], repo.seed, repo.seed)


def test_freeze_on_invalid_commit(repo, walk):
    base = repo.seed
    repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    bad = repo.commit({"ledger.yaml": ledger_bytes(), "people.yaml": people_bytes()}, "ledger")
    repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    wf = repo.commit({"people.yaml": people_bytes()}, "web-flow")
    head = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    v = walk(head, base)
    assert v.valid is False
    assert v.reason == f"invalid:ledger-path@{bad[:7]}"
    assert v.invalid == [(bad, "ledger-path")]
    assert (v.last_good, v.recovery, v.newest_trusted) == (base, None, wf)
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
    assert v.newest_trusted == c


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


def test_recovery_must_be_operator_key(repo, walk):
    """A Reviewed-Range commit made in GitHub's web UI (web-flow) is the mistake an operator can make."""
    last_good, bad, revert = _frozen(repo)
    rec = repo.commit({}, "web-flow", message=reviewed(last_good, bad))
    v = walk(rec, last_good)
    assert (v.valid, v.reason, v.recovery) == (False, f"recovery-not-operator-key@{rec[:7]}", None)
    assert v.invalid == [(bad, "ledger-path")]


@pytest.mark.parametrize("who", ["ledger", "untrusted", None])
def test_trailer_from_another_key_never_masks_the_freeze(who, repo, walk):
    """Recovery reasons come only from operator or web-flow attempts: a Reviewed-Range trailer on a ledger-key,
    unknown-key or unsigned commit is no attempt, and the reason keeps naming the first invalid commit."""
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
    # A later web-flow commit quoting the trailer neither breaks the accepted recovery nor stands in for one.
    quoted = repo.commit({}, "web-flow", message=reviewed(last_good, bad))
    v = walk(quoted, last_good)
    assert (v.valid, v.recovery) == (True, rec)


def test_recovery_takes_non_fast_forward_history(repo, walk):
    """The erasure shape: filter-repo rewrites history (its commits come out unsigned) and an operator signs
    a head naming the box's last good and the rewritten tip, then force-pushes."""
    old = repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    old_tip = repo.commit({"people.yaml": people_bytes()}, "web-flow")
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
    last_good = repo.commit({"people.yaml": people_bytes()}, "web-flow")
    v = walk(old, last_good)
    assert (v.valid, v.reason, v.chain, v.invalid, v.last_good) == (False, "not-fast-forward", [], [], last_good)
    on_top = repo.commit({"people.yaml": people_bytes()}, "web-flow", parents=[old])
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
    merge = repo.commit({}, "web-flow", parents=[c2, revert], date=at(future + 100))   # bad is under it
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
    side = repo.commit({"notes.md": b"pr\n"}, None, parents=[revert], date=at(future + 3))   # a PR off old main
    merge = repo.commit({}, "web-flow", parents=[last_good, side], date=at(future + 4))
    v = walk(merge, last_good)
    assert (v.valid, v.reason, v.invalid) == (True, None, [])
    assert v.chain == [(merge, "web-flow")]


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


# --- newest trusted, inputs, and how git is called --------------------------------------------------------------

def test_newest_trusted(repo, keyring, trust):
    op = repo.commit({"people.yaml": people_bytes()}, "operator")
    repo.commit({"ledger.yaml": ledger_bytes()}, "ledger")
    repo.commit({"ledger.yaml": ledger_bytes()}, None)
    head = repo.commit({"ledger.yaml": ledger_bytes()}, "expired")
    assert L.newest_trusted(repo.path, head, keyring, trust) == op
    # Second parents don't count: only the first-parent line is searched.
    side = repo.commit({"people.yaml": people_bytes()}, "web-flow", parents=[repo.seed])
    merge = repo.commit({}, None, parents=[head, side])
    assert L.newest_trusted(repo.path, merge, keyring, trust) == op
    lone = repo.commit({"ledger.yaml": EMPTY_LEDGER}, "ledger", parents=[])
    assert L.newest_trusted(repo.path, lone, keyring, trust) is None


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
    assert {frozenset(s) for s in seen} == {frozenset({"GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM",
                                                       "GIT_NO_REPLACE_OBJECTS", "GIT_TERMINAL_PROMPT"})}
