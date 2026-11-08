"""Admission: which redeemed links become guests, by the box's clock (sso_ledger.admit), and the Keycloak lookup
behind it (KeycloakDirectory). Pure Python: a fake Directory, synthetic people and a fixed clock. No test here
reaches the network; the Keycloak tests replace urlopen itself."""
import copy
import http.client
import io
import json
import urllib.error
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

import sso_ledger as L

NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
DAY, HOUR, MINUTE, SECOND = timedelta(days=1), timedelta(hours=1), timedelta(minutes=1), timedelta(seconds=1)
RESERVED = (L.RESERVED_NAMES | {"hidden-org"}, L.RESERVED_PREFIXES)


class FakeDirectory:
    """Keycloak as admit() sees it: taken usernames and emails, or every lookup failing."""

    def __init__(self, users=(), emails=(), fail=False):
        self.users, self.emails, self.fail, self.asked = set(users), set(emails), fail, []

    def username_taken(self, u):
        self.asked.append(u)
        if self.fail:
            raise L.LookupFailed("down")
        return u in self.users

    def email_taken(self, e):
        self.asked.append(e)
        if self.fail:
            raise L.LookupFailed("down")
        return e in self.emails


def people(emails=("bob@example.com", "mel@example.invalid")):
    tiers = {"rally": "realliance", "rally-two": "realliance", "rally-three": "realliance", "mel": "member",
             "gone": "inactive", "ovr": "guest"}
    return L.People(tiers=dict(tiers), usernames=set(tiers), emails=set(emails))


def link(i, inviter="rally", state="redeemed", username=None, email=None, first="Guestname", last=None,
         mfa="webauthn", active=True, created="2026-11-01T00:00:00Z", expires="2026-11-08T00:00:00Z"):
    guest = None
    if state == "redeemed":
        u = username if username is not None else f"guest-{i:02d}"
        guest = L.Guest(u, L.Bootstrap(email if email is not None else f"{u}@guests.invalid", first, last), mfa,
                        active)
    return L.Link(id=lid(i), inviter=inviter, created=created, expires=expires, token_sha256=f"{i:064x}",
                  state=state, redeemed="2026-11-02T00:00:00Z" if state == "redeemed" else None,
                  revoked="2026-11-02T00:00:00Z" if state == "revoked" else None, guest=guest)


def lid(i):
    return f"l-{i:016x}"


def run(state, *links, now=NOW, mode="apply", directory=None, who=None, reserved=RESERVED):
    return L.admit(L.Ledger(1, tuple(links)), who or people(), reserved, directory or FakeDirectory(), state, now,
                   mode)


def refusals(*links, **kw):
    return run(L.BoxState(), *links, **kw).refused_now


def at(state, username):
    return datetime.fromisoformat(state.admitted[username]["at"])


# --- admitting -------------------------------------------------------------------------------------------------

def test_admits_good_redemption():
    s = L.BoxState()
    d = run(s, link(1, last="Lastname"))
    assert d.admitted_now == ["guest-01"]
    assert (d.would_admit, d.refused_now, d.deferred) == ([], {}, {})
    assert d.guests == {"guest-01": {"active": True, "mfa": "webauthn",
                                     "bootstrap": {"email": "guest-01@guests.invalid", "first_name": "Guestname",
                                                   "last_name": "Lastname"}}}
    assert s.admitted == {"guest-01": {"link": lid(1), "at": s.admitted["guest-01"]["at"], "active": True}}
    assert at(s, "guest-01") == NOW
    assert "redeemed" in s.seen[lid(1)]
    # Handed again on every later run, never re-checked or re-admitted.
    again = run(s, link(1, last="Lastname"), now=NOW + DAY)
    assert again.admitted_now == [] and again.guests == d.guests and at(s, "guest-01") == NOW


def test_check_mode_hands_no_new_guests():
    s = L.BoxState()
    d = run(s, link(1), mode="check")
    assert d.would_admit == ["guest-01"] and d.admitted_now == [] and d.guests == {} and s.admitted == {}
    # A guest admitted earlier (in apply) is still handed in check mode, so no apply ever drops it.
    s = L.BoxState()
    run(s, link(1))
    before = copy.deepcopy(s.admitted)
    d = run(s, link(1), link(2), now=NOW + DAY, mode="check")
    assert d.would_admit == ["guest-02"] and set(d.guests) == {"guest-01"} and s.admitted == before


def test_username_rules():
    bad = ["Ab", "a", "a--b", "-ab", "ab-", "a" * 33, "ab", "a_b", "abc\n", "ünï", ""]
    assert refusals(*(link(i, username=u) for i, u in enumerate(bad, 1))) == \
        {lid(i): "username-format" for i in range(1, len(bad) + 1)}
    reserved = ["www", "forge-bot", "test-x", "hidden-org", "ci-runner", "admin-x", "ghost"]
    assert refusals(*(link(i, username=u) for i, u in enumerate(reserved, 1))) == \
        {lid(i): "username-reserved" for i in range(1, len(reserved) + 1)}
    # Taken: a people.yaml username, a Keycloak user and another ledger guest.
    s = L.BoxState()
    run(s, link(1))
    d = run(s, link(1), link(2, username="mel"), link(3, username="kc-taken"), link(4, username="guest-01"),
            now=NOW + HOUR, directory=FakeDirectory(users={"kc-taken"}))
    assert d.refused_now == {lid(2): "username-taken", lid(3): "username-taken", lid(4): "username-taken"}
    # The edges that pass: three characters, thirty-two, single dashes.
    ok = ["abc", "a" + "b" * 30 + "c", "a-b-c", "a1-2b"]
    d = run(L.BoxState(), *(link(i, username=u) for i, u in enumerate(ok, 1)))
    assert d.admitted_now == ok and d.refused_now == {}


def test_email_collision_case_insensitive():
    shouting = link(1, email="Bob@Example.COM ")
    assert refusals(shouting, directory=FakeDirectory(emails={"bob@example.com"}), who=people(emails=())) == \
        {lid(1): "email-taken"}
    assert refusals(shouting) == {lid(1): "email-taken"}                    # people.yaml holds bob@example.com
    # Another ledger guest's address, in another case.
    s = L.BoxState()
    run(s, link(1))
    assert run(s, link(1), link(2, email="GUEST-01@Guests.Invalid"), now=NOW + HOUR).refused_now == \
        {lid(2): "email-taken"}
    # Format: ASCII, at most 254 characters, one well-formed address.
    domain = "b" * 63 + "." + "c" * 63 + "." + "d" * 57 + ".org"
    longest, too_long = "a" * 64 + "@" + domain, "a" * 64 + "@" + domain.replace("d" * 57, "d" * 58)
    assert (len(longest), len(too_long)) == (254, 255)
    bad = ["not-an-email", "a@b", "x@", "@example.org", "a b@example.org", "ü@example.org", "a@@example.org",
           ".a@example.org", "a..b@example.org", "a" * 65 + "@example.org", too_long, ""]
    assert refusals(*(link(i, email=e) for i, e in enumerate(bad, 1))) == \
        {lid(i): "email-format" for i in range(1, len(bad) + 1)}
    d = run(L.BoxState(), link(1, email=longest), link(2, email=" New.Person+tag@Example.ORG "))
    assert d.refused_now == {} and d.admitted_now == ["guest-01", "guest-02"]
    assert d.guests["guest-02"]["bootstrap"]["email"] == "New.Person+tag@Example.ORG"     # handed trimmed


def test_same_username_twice_first_wins():
    s = L.BoxState()
    d = run(s, link(1, username="same-name"), link(2, inviter="rally-two", username="same-name"))
    assert d.admitted_now == ["same-name"] and d.refused_now == {lid(2): "username-taken"}
    assert s.admitted["same-name"]["link"] == lid(1)
    # The redemption the box saw first wins, whatever the ledger order: link 2's was seen in an earlier run (and
    # deferred), link 1's only now.
    s = L.BoxState()
    run(s, link(1, state="pending"), link(2, inviter="rally-two", username="same-name"),
        directory=FakeDirectory(fail=True))
    d = run(s, link(1, username="same-name"), link(2, inviter="rally-two", username="same-name"), now=NOW + HOUR)
    assert d.admitted_now == ["same-name"] and d.refused_now == {lid(1): "username-taken"}
    assert s.admitted["same-name"]["link"] == lid(2)
    # The same email twice in one run: the first wins as well.
    d = run(L.BoxState(), link(1, email="twice@example.org"), link(2, inviter="rally-two", email="Twice@example.org"))
    assert d.admitted_now == ["guest-01"] and d.refused_now == {lid(2): "email-taken"}


def test_entry_refused_for_keycloak_prohibited_name():
    firsts = ["Ann<", "$x", "a;b", "{x}", "An\tn", "x" * 65, "", "a\x00b", "a\x7fb", "a\u0085b", "(x)", "a=b",
              "a§b", "a/b", "a\\b", "a|b", "a^b", "a~b", "a*b", "a?b", "a#b", "a!b", "a%b", "a&b", 'a"b', "a>b"]
    assert refusals(*(link(i, first=f) for i, f in enumerate(firsts, 1))) == \
        {lid(i): "name-format" for i in range(1, len(firsts) + 1)}
    assert refusals(link(1, last="Smith{}"), link(2, last=""), link(3, last="y" * 65)) == \
        {lid(1): "name-format", lid(2): "name-format", lid(3): "name-format"}
    d = run(L.BoxState(), link(1, last=None), link(2, first="x" * 64, last="Zoë O'Neil-Ávila"), link(3, first="李"))
    assert d.refused_now == {} and d.admitted_now == ["guest-01", "guest-02", "guest-03"]
    assert d.guests["guest-01"]["bootstrap"]["last_name"] is None


def test_inviter_rules():
    s = L.BoxState()
    run(s, link(1))                                                            # guest-01, a ledger guest
    d = run(s, link(1), link(2, inviter="nobody"), link(3, inviter="gone"), link(4, inviter="ovr"),
            link(5, inviter="guest-01"), now=NOW + HOUR)
    assert d.refused_now == {lid(2): "inviter-not-member", lid(3): "inviter-inactive",
                             lid(4): "inviter-not-member", lid(5): "inviter-not-member"}


# --- quotas, caps and the box clock ----------------------------------------------------------------------------

def test_realliance_quota_five_per_seven_days():
    five = [link(i) for i in range(1, 6)]
    s = L.BoxState()
    assert run(s, *five, now=NOW - 2 * DAY).admitted_now == [f"guest-0{i}" for i in range(1, 6)]
    d = run(s, *five, link(6), now=NOW)
    assert d.refused_now == {lid(6): "quota"} and d.admitted_now == []
    # One of the five admitted 7 d and 1 s ago no longer holds a slot.
    s = L.BoxState()
    run(s, link(1), now=NOW - 7 * DAY - SECOND)
    assert run(s, *five, now=NOW - 2 * DAY).admitted_now == [f"guest-0{i}" for i in range(2, 6)]
    d = run(s, *five, link(6), now=NOW)
    assert d.admitted_now == ["guest-06"] and d.refused_now == {}
    # Pending links hold slots too, and other members' links never count.
    s = L.BoxState()
    run(s, *(link(i, state="pending") for i in range(1, 6)), now=NOW - HOUR)
    d = run(s, *(link(i, state="pending") for i in range(1, 6)), link(6), link(7, inviter="rally-two"), now=NOW)
    assert d.refused_now == {lid(6): "quota"} and d.admitted_now == ["guest-07"]


def test_member_quota_one_for_life():
    def mel(i, state="redeemed", **kw):
        return link(i, inviter="mel", state=state, **kw)

    # Refused: the first link admitted 400 d ago.
    s = L.BoxState()
    run(s, mel(1), now=NOW - 400 * DAY)
    assert run(s, mel(1), mel(2), now=NOW).refused_now == {lid(2): "quota"}
    # Refused: the first link pending and unexpired.
    s = L.BoxState()
    run(s, mel(1, "pending"), mel(2, "pending"), now=NOW - DAY)
    assert run(s, mel(1, "pending"), mel(2), now=NOW).refused_now == {lid(2): "quota"}
    # Refused: the first guest later deactivated.
    s = L.BoxState()
    run(s, mel(1), now=NOW - 10 * DAY)
    assert run(s, mel(1, active=False), mel(2), now=NOW).refused_now == {lid(2): "quota"}
    assert s.admitted["guest-01"]["active"] is False
    # Admitted: the first link revoked.
    s = L.BoxState()
    run(s, mel(1, "pending"), mel(2, "pending"), now=NOW - DAY)
    assert run(s, mel(1, "revoked"), mel(2), now=NOW).admitted_now == ["guest-02"]
    # Admitted: the first link expired by the box's clock.
    s = L.BoxState()
    run(s, mel(1, "pending"), now=NOW - 8 * DAY)
    run(s, mel(1, "pending"), mel(2, "pending"), now=NOW - HOUR)
    assert run(s, mel(1, "pending"), mel(2), now=NOW).admitted_now == ["guest-02"]


def test_pending_links_hold_slots_earlier_first():
    def mel(i, state="redeemed"):
        return link(i, inviter="mel", state=state)

    s = L.BoxState()
    run(s, mel(1, "pending"), mel(2, "pending"), now=NOW - DAY)
    d = run(s, mel(1), mel(2), now=NOW)
    assert d.admitted_now == ["guest-01"] and d.refused_now == {lid(2): "quota"}
    # The later link redeemed first is refused while the earlier one is pending, and the earlier one still wins.
    s = L.BoxState()
    run(s, mel(1, "pending"), mel(2, "pending"), now=NOW - DAY)
    assert run(s, mel(1, "pending"), mel(2), now=NOW - HOUR).refused_now == {lid(2): "quota"}
    d = run(s, mel(1), mel(2), now=NOW)
    assert d.admitted_now == ["guest-01"] and lid(2) in s.refused
    # Ledger order is not seen order (the ledger key may reorder links). Both redeem in one run and link 2 runs
    # first by ledger index: link 1, seen earlier and redeemed but not yet decided, still holds its slot, so a
    # member never ends up with two guests.
    s = L.BoxState()
    run(s, mel(1, "pending"), now=NOW - DAY)
    run(s, mel(2, "pending"), mel(1, "pending"), now=NOW - HOUR)
    d = run(s, mel(2), mel(1), now=NOW)
    assert d.admitted_now == ["guest-01"] and d.refused_now == {lid(2): "quota"}
    # An earlier redemption deferred by the cap holds its slot too; one refused, or late, or inactive frees it.
    s = L.BoxState()
    ten = [link(i, inviter="rally" if i <= 15 else "rally-two") for i in range(11, 21)]
    run(s, *ten, now=NOW - HOUR)
    run(s, *ten, mel(1), now=NOW)                                               # deferred: cap
    d = run(s, *ten, mel(1), mel(2), now=NOW + MINUTE)
    assert d.deferred == {lid(1): "cap"} and d.refused_now == {lid(2): "quota"}
    d = run(s, *ten, mel(1), mel(2), now=NOW + DAY)
    assert d.admitted_now == ["guest-01"] and d.refused_now == {}
    for first in (link(1, inviter="mel", first="Bad<"), link(1, inviter="mel", active=False)):
        s = L.BoxState()
        run(s, mel(1, "pending"), mel(2, "pending"), now=NOW - DAY)
        d = run(s, mel(2), first, now=NOW)
        assert d.admitted_now == ["guest-02"]


def test_global_cap_defers_eleventh():
    ten = [link(i, inviter="rally" if i <= 5 else "rally-two") for i in range(1, 11)]
    s = L.BoxState()
    assert len(run(s, *ten, now=NOW - HOUR).admitted_now) == 10
    eleventh = link(11, inviter="rally-three")
    d = run(s, *ten, eleventh, now=NOW)
    assert d.deferred == {lid(11): "cap"} and d.refused_now == {} and d.admitted_now == []
    assert lid(11) not in s.refused and "guest-11" not in s.admitted
    assert run(s, *ten, eleventh, now=NOW + 22 * HOUR).deferred == {lid(11): "cap"}
    d = run(s, *ten, eleventh, now=NOW + 24 * HOUR)
    assert d.admitted_now == ["guest-11"] and d.deferred == {}
    # One run counts its own admissions: twelve at once admit ten and defer two.
    twelve = [link(i, inviter=("rally", "rally-two", "rally-three")[(i - 1) // 4]) for i in range(1, 13)]
    d = run(L.BoxState(), *twelve)
    assert len(d.admitted_now) == 10 and d.deferred == {lid(11): "cap", lid(12): "cap"}


def test_expiry_uses_box_first_seen_plus_grace():
    t = NOW
    month_old = {"created": "2026-10-21T12:00:00Z", "expires": "2026-10-28T12:00:00Z"}   # T - 30 d, 7 days long
    for late, admitted in ((29 * MINUTE, True), (31 * MINUTE, False)):
        s = L.BoxState()
        run(s, link(1, state="pending", **month_old), now=t)
        d = run(s, link(1, **month_old), now=t + 7 * DAY + late)
        assert (d.admitted_now, d.refused_now) == ((["guest-01"], {}) if admitted else ([], {lid(1): "expired"}))
    # A shorter link counts its own lifetime from the box's first sight, plus the same grace.
    hour_long = {"created": "2026-10-21T12:00:00Z", "expires": "2026-10-21T13:00:00Z"}
    for late, admitted in ((HOUR + 29 * MINUTE, True), (HOUR + 31 * MINUTE, False)):
        s = L.BoxState()
        run(s, link(1, state="pending", **hour_long), now=t)
        d = run(s, link(1, **hour_long), now=t + late)
        assert d.admitted_now == (["guest-01"] if admitted else [])
    # First seen already redeemed (pushed between two runs) is on time; a deferral never makes it late.
    s = L.BoxState()
    run(s, *(link(i, inviter="rally" if i <= 5 else "rally-two") for i in range(1, 11)), now=t - HOUR)
    run(s, link(11, inviter="rally-three", **month_old), now=t)                  # deferred: cap
    d = run(s, link(11, inviter="rally-three", **month_old), now=t + 30 * DAY)
    assert d.admitted_now == ["guest-11"]


def test_inactive_new_guest_never_created():
    s = L.BoxState()
    d = run(s, link(1, active=False))
    assert d == L.Decision(admitted_now=[], would_admit=[], refused_now={}, deferred={}, guests={})
    assert s.admitted == {} and s.refused == {}
    assert run(s, link(1, active=False), mode="check").would_admit == []


def test_admitted_guest_never_dropped_or_rechecked():
    s = L.BoxState()
    run(s, link(1), link(2, mfa="totp"))
    kc = FakeDirectory(users={"guest-01", "guest-02"}, emails={"guest-01@guests.invalid", "guest-02@guests.invalid"})
    d = run(s, link(1), link(2, mfa="totp"), now=NOW + DAY, directory=kc)
    assert set(d.guests) == {"guest-01", "guest-02"} and d.refused_now == {} and kc.asked == []
    assert d.guests["guest-02"]["mfa"] == "totp"
    # Erased: the entry is gone from the ledger, and the guest is still handed, with no profile.
    d = run(s, link(2, mfa="totp"), now=NOW + 2 * DAY)
    assert d.guests["guest-01"] == {"active": True, "mfa": "webauthn", "bootstrap": None}
    assert set(s.admitted) == {"guest-01", "guest-02"}
    # Erased after a deactivation: the stored active.
    run(s, link(2, mfa="totp", active=False), now=NOW + 3 * DAY)
    assert run(s, now=NOW + 4 * DAY).guests == {"guest-01": {"active": True, "mfa": "webauthn", "bootstrap": None},
                                                "guest-02": {"active": False, "mfa": "webauthn", "bootstrap": None}}


def test_deactivation_reaches_admitted_guest():
    s = L.BoxState()
    run(s, link(1))
    d = run(s, link(1, active=False), now=NOW + DAY)
    assert d.guests["guest-01"]["active"] is False and s.admitted["guest-01"]["active"] is False
    # An operator's reactivation reaches it the same way.
    assert run(s, link(1), now=NOW + 2 * DAY).guests["guest-01"]["active"] is True
    assert s.admitted["guest-01"]["active"] is True
    # Check mode hands what the ledger says and leaves the state to apply.
    d = run(s, link(1, active=False), now=NOW + 3 * DAY, mode="check")
    assert d.guests["guest-01"]["active"] is False and s.admitted["guest-01"]["active"] is True


def test_refusal_persists_until_entry_changes():
    s = L.BoxState()
    d = run(s, link(1), directory=FakeDirectory(users={"guest-01"}))
    assert d.refused_now == {lid(1): "username-taken"} and s.refused[lid(1)]["reason"] == "username-taken"
    d = run(s, link(1), now=NOW + HOUR)                                       # Keycloak free now
    assert (d.refused_now, d.admitted_now, d.deferred) == ({}, [], {}) and lid(1) in s.refused
    d = run(s, link(1), now=NOW + 2 * HOUR, mode="check")
    assert d.would_admit == [] and lid(1) in s.refused
    d = run(s, link(1, username="guest-new"), now=NOW + 3 * HOUR)             # an operator changes the entry
    assert d.admitted_now == ["guest-new"] and lid(1) not in s.refused
    # Check mode never stores a refusal.
    s = L.BoxState()
    assert run(s, link(1), mode="check", directory=FakeDirectory(users={"guest-01"})).refused_now == \
        {lid(1): "username-taken"}
    assert s.refused == {}


def test_lookup_failure_defers():
    s = L.BoxState()
    down = FakeDirectory(fail=True)
    d = run(s, link(1), directory=down)
    assert d.deferred == {lid(1): "lookup-failed"} and d.refused_now == {} and s.refused == {} and s.admitted == {}
    # One failure defers the rest of the run without asking again, so a later link can't jump an earlier one.
    down = FakeDirectory(fail=True)
    d = run(s, link(1), link(2), link(3, username="Bad"), directory=down, now=NOW + MINUTE)
    assert d.deferred == {lid(1): "lookup-failed", lid(2): "lookup-failed"} and len(down.asked) == 1
    assert d.refused_now == {lid(3): "username-format"}
    d = run(s, link(1), link(2), now=NOW + HOUR)
    assert d.admitted_now == ["guest-01", "guest-02"]


def test_check_mode_persists_seen_not_admitted():
    s = L.BoxState()
    d = run(s, link(1), link(2, first="Bad<"), link(3, state="pending"), mode="check")
    assert set(s.seen) == {lid(1), lid(2), lid(3)}
    assert "redeemed" in s.seen[lid(1)] and "redeemed" not in s.seen[lid(3)]
    assert s.admitted == {} and s.refused == {}
    assert d.would_admit == ["guest-01"] and d.refused_now == {lid(2): "name-format"}
    # The clock check mode started holds when apply takes over.
    first = copy.deepcopy(s.seen)
    d = run(s, link(1), link(2, first="Bad<"), link(3, state="pending"), now=NOW + DAY)
    assert d.admitted_now == ["guest-01"]
    assert {k: {f: v[f] for f in ("link", "redeemed") if f in v} for k, v in s.seen.items()} == \
        {k: {f: v[f] for f in ("link", "redeemed") if f in v} for k, v in first.items()}


def test_admit_checks_its_input():
    with pytest.raises(ValueError):
        run(L.BoxState(), link(1), mode="dry")
    with pytest.raises(ValueError):
        run(L.BoxState(), link(1), now=NOW.replace(tzinfo=None))


# --- the Keycloak lookup ---------------------------------------------------------------------------------------

def test_keycloak_directory_construction(tmp_path, monkeypatch):
    def no_network(*a, **kw):
        raise AssertionError("constructing the directory must not reach the network")

    monkeypatch.setattr(L.urllib.request, "urlopen", no_network)
    d = L.KeycloakDirectory("https://sso.example.invalid/", tmp_path / "missing.secret")
    assert (d.client_id, d.timeout, d.base_url) == ("tofu-plan", 10, "https://sso.example.invalid")
    assert isinstance(d, L.Directory)


class _Response:
    def __init__(self, body: bytes):
        self.body = body

    def read(self, n=-1):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_keycloak_directory_queries(tmp_path, monkeypatch):
    secret = tmp_path / "ledger-lookup.secret"
    secret.write_text("s3cret-value\n")
    users = [{"username": "taken-name", "email": "bob@example.com"},
             {"username": "taken-name-2", "email": "bobby@example.com"}]
    calls, tokens, expire_once = [], iter(["t1", "t2"]), [True]

    def urlopen(req, timeout=None):
        calls.append((req.get_method(), req.full_url, req.data, req.get_header("Authorization"), timeout))
        if req.full_url.endswith("/token"):
            return _Response(json.dumps({"access_token": next(tokens), "expires_in": 60}).encode())
        if expire_once[0]:
            expire_once[0] = False
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b""))
        q = parse_qs(urlsplit(req.full_url).query)
        field = "username" if "username" in q else "email"
        # Like a Keycloak without exact search: a prefix match. The directory compares exactly itself.
        return _Response(json.dumps([u for u in users if u[field].startswith(q[field][0])]).encode())

    monkeypatch.setattr(L.urllib.request, "urlopen", urlopen)
    d = L.KeycloakDirectory("https://sso.example.invalid", secret)
    assert d.username_taken("taken-name") is True
    assert d.username_taken("taken") is False
    assert d.email_taken("Bob@Example.COM ") is True
    assert d.email_taken("bo@example.com") is False
    token = calls[0]
    assert token[:2] == ("POST", "https://sso.example.invalid/realms/master/protocol/openid-connect/token")
    assert parse_qs(token[2].decode()) == {"grant_type": ["client_credentials"], "client_id": ["tofu-plan"],
                                           "client_secret": ["s3cret-value"]}
    assert all(c[4] == 10 for c in calls)
    queries = [c for c in calls if "/users?" in c[1]]
    assert all(c[0] == "GET" and c[1].startswith("https://sso.example.invalid/admin/realms/realliance/users?")
               for c in queries)
    assert all(parse_qs(urlsplit(c[1]).query)["exact"] == ["true"] for c in queries)
    assert [c[3] for c in queries] == ["Bearer t1", "Bearer t2", "Bearer t2", "Bearer t2", "Bearer t2"]
    assert parse_qs(urlsplit(queries[3][1]).query)["email"] == ["bob@example.com"]          # trimmed, lower case
    assert sum(1 for c in calls if c[1].endswith("/token")) == 2                            # one retry after 401


@pytest.mark.parametrize("failure", ["unreachable", "timeout", "500", "not-json", "no-secret", "token-refused",
                                     "401-twice", "cut-short"])
def test_keycloak_directory_failures_raise_lookup_failed(failure, tmp_path, monkeypatch):
    secret = tmp_path / "ledger-lookup.secret"
    if failure != "no-secret":
        secret.write_text("s3cret-value\n")

    def urlopen(req, timeout=None):
        is_token = req.full_url.endswith("/token")
        if failure == "unreachable":
            raise urllib.error.URLError("connection refused")
        if failure == "timeout":
            raise TimeoutError("timed out")
        if failure == "cut-short":
            raise http.client.IncompleteRead(b"partial")
        if failure == "token-refused" and is_token:
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b""))
        if is_token:
            return _Response(b'{"access_token": "t"}')
        if failure == "500":
            raise urllib.error.HTTPError(req.full_url, 500, "Server Error", {}, io.BytesIO(b""))
        if failure == "401-twice":
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, io.BytesIO(b""))
        return _Response(b"<html>not json</html>")

    monkeypatch.setattr(L.urllib.request, "urlopen", urlopen)
    d = L.KeycloakDirectory("https://sso.example.invalid", secret)
    for ask in (lambda: d.email_taken("private.person@example.org"), lambda: d.username_taken("someone")):
        with pytest.raises(L.LookupFailed) as e:
            ask()
        assert "private.person" not in str(e.value) and "s3cret" not in str(e.value)
        assert e.value.__cause__ is None and e.value.__suppress_context__
