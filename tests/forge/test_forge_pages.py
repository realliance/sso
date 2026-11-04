"""Realliance Pages acceptance suite: static sites at <owner>.realliance.page, served by git-pages and
published by the pages-relay webhook relay (plan 2026-11-03-realliance-pages, Task 3).

Written first, so it is RED until the pieces land (it goes green task by task; Task 10 is the gate).
Until DNS, the namespace, the relay and the webhook secret exist, tests fail for exactly that reason.
Test users come from `forge_user` and are purged with their repos; sites are taken down by `published`
(purging a forge user does not remove its sites). Nothing here prints the webhook secret."""
import base64
import os
import re
import secrets
import time

import pytest
import requests

from forge_helpers import FORGE, forge_api, forge_login, forge_token, galaxy_only, kube
from pages_helpers import (DOMAIN, RELAY_URL, alert_active_since, branch_delete_payload, commit_files, freeze,
                           from_vps_head, git, git_env, git_pages_metrics, git_try, make_repo, manifest_status,
                           msum, outcome, post_git_pages, post_relay, push_payload, relay_metrics,
                           repo_deleted_payload, site_name, site_url, takedown, unfreeze, wait_for_body,
                           wait_for_outcome, wait_for_status)

pytestmark = galaxy_only

PUBLISH_WITHIN = 90      # git-pages caches a site for 60 s
GRACE = 20               # after a positive signal, how long a non-event is given to (not) happen


@pytest.fixture(scope="module")
def published():
    """Site names (`<domain>[/<project>]`) the tests published. Each is taken down at teardown; a site
    that is already gone is fine."""
    sites: list[str] = []
    yield sites
    for s in sites:
        try:
            takedown(s)
        except Exception as e:    # teardown must not mask the test result, but a leak is said out loud
            print(f"WARNING: takedown of {s} failed: {type(e).__name__}")
    # M4: one shared wait (the site cache is 60 s) to see that every site is really gone
    deadline = time.monotonic() + 90
    left = list(sites)
    while left and time.monotonic() < deadline:
        left = [s for s in left if _status(f"https://{s}/") not in (404, None)]
        if left:
            time.sleep(5)
    for s in left:
        print(f"WARNING: {s} still answers after takedown")


def _status(url: str) -> int | None:
    try:
        return requests.get(url, allow_redirects=False, timeout=10).status_code
    except requests.RequestException:
        return None      # unreachable counts as gone


def new_user(forge_user) -> str:
    """A Keycloak test user who has signed in to Forgejo once (which is what creates the forge account)."""
    u = forge_user()
    forge_login(u)
    return u.name


def nonce() -> str:
    return secrets.token_hex(4)


def publish(owner, repo, body, published, *, private=False, files=None):
    """Create `owner/repo` (public unless told), commit `files` (default an index.html holding `body`) to
    the pages branch and record the site for teardown."""
    make_repo(owner, repo, private=private)
    published.append(site_name(owner, repo))
    commit_files(owner, repo, files or {"index.html": body})


# --- D1 -------------------------------------------------------------------------------------------------
def test_system_webhook_present():
    """D1: exactly one system webhook, pointed at the relay, with the three events."""
    hooks = [h for h in forge_api("GET", "/api/v1/admin/hooks").json() if h["config"].get("url") == RELAY_URL]
    assert len(hooks) == 1 and hooks[0]["active"] and set(hooks[0]["events"]) == {"push", "delete", "repository"}
    # I1c: the branch filter is the only thing that keeps main/gh-pages pushes from the relay; without this
    # check a green Acceptance 3 could rest on a hook that forwards every branch
    assert hooks[0]["branch_filter"] == "pages"


# --- Acceptance 1 and 2 ---------------------------------------------------------------------------------
def test_push_publishes_and_updates(forge_user, published):
    """Acceptance 1: a push to `pages` of a public repo is live within 90 s, and so is the next one."""
    a, repo, n = new_user(forge_user), f"site-{nonce()}", nonce()
    publish(a, repo, f"v1-{n}", published)
    assert wait_for_body(site_url(a, repo), f"v1-{n}") <= PUBLISH_WITHIN
    commit_files(a, repo, {"index.html": f"v2-{n}"})
    assert wait_for_body(site_url(a, repo), f"v2-{n}") <= PUBLISH_WITHIN


def test_pages_repo_is_root_site(forge_user, published):
    """Acceptance 2: <owner>/pages is the owner's root site, https://<owner>.realliance.page/."""
    a, n = new_user(forge_user), nonce()
    publish(a, "pages", f"root-{n}", published)
    assert site_url(a, "pages") == f"https://{a.lower()}.{DOMAIN}/"
    assert wait_for_body(site_url(a, "pages"), f"root-{n}") <= PUBLISH_WITHIN


# --- Acceptance 3 ---------------------------------------------------------------------------------------
def test_other_branch_changes_nothing(forge_user, published):
    """Acceptance 3: pushes to main and gh-pages publish nothing. The forge's branch filter keeps them from
    the relay at all, so a signed push for refs/heads/main is also posted: the relay must count it
    ignored_ref (a positive signal that the relay is alive) and forward nothing."""
    a, repo, n = new_user(forge_user), f"site-{nonce()}", nonce()
    publish(a, repo, f"v1-{n}", published)
    assert wait_for_body(site_url(a, repo), f"v1-{n}") <= PUBLISH_WITHIN

    before_relay, before_gp = relay_metrics(), git_pages_metrics()
    # I1a: a git-pages metric that was renamed or never emitted sums to 0 both times and "unchanged" would
    # pass with nothing measured; v1 just published, so the series must exist and be positive
    assert msum(before_gp, "git_pages_site_updates") > 0, "git_pages_site_updates series is missing"
    commit_files(a, repo, {"index.html": f"v9-{n}"}, branch="main")
    commit_files(a, repo, {"index.html": f"v9-{n}"}, branch="gh-pages")
    resp = post_relay(push_payload(a, repo, ref="refs/heads/main"))
    assert resp.status_code == 200
    # I1b: git-pages serves a site from a 60 s cache, so a wrongly published v9 stays invisible for up to 60 s
    # after the fetch; look only after the whole window (PUBLISH_WITHIN), never after a short grace
    time.sleep(PUBLISH_WITHIN)

    after_relay, after_gp = relay_metrics(), git_pages_metrics()
    assert outcome(after_relay, "ignored_ref") >= outcome(before_relay, "ignored_ref") + 1
    assert outcome(after_relay, "forwarded") == outcome(before_relay, "forwarded")
    assert msum(after_gp, "git_pages_site_updates") == msum(before_gp, "git_pages_site_updates")
    assert f"v1-{n}" in requests.get(site_url(a, repo), timeout=10).text


# --- Acceptance 4 ---------------------------------------------------------------------------------------
def test_private_repo_publishes_nothing(forge_user, published):
    """Acceptance 4: a private repo's pages branch publishes nothing. The 404 alone would also be what a dead
    pipeline gives, so the relay's ignored_private counter must have moved."""
    a, priv = new_user(forge_user), f"priv-{nonce()}"
    before = outcome(relay_metrics(), "ignored_private")
    publish(a, priv, "secret-site", published, private=True)
    wait_for_outcome("ignored_private", before + 1)
    time.sleep(GRACE)
    assert requests.get(site_url(a, priv), timeout=10).status_code == 404
    assert outcome(relay_metrics(), "ignored_private") >= before + 1     # M2: other deliveries may share the counter


# --- Acceptance 5 (D3) and Review Focus 5 ---------------------------------------------------------------
@pytest.mark.slow
def test_oversize_site_refused_and_alerts(forge_user, published, tmp_path):
    """Acceptance 5: a publish past the 128 MB cap is refused, the site keeps its last content, and
    PagesSiteUpdateFailing fires (a failure git-pages only reports after answering 202)."""
    u = forge_user()
    s = forge_login(u)
    a, repo, n = u.name, f"site-{nonce()}", nonce()
    publish(a, repo, f"v1-{n}", published)
    assert wait_for_body(site_url(a, repo), f"v1-{n}") <= PUBLISH_WITHIN
    # I3: git-pages labels this counter by cause, not by site, so the strongest per-push evidence is the delta
    # on the same pod around THIS push (an alert already firing from another test proves nothing)
    errors_before = msum(git_pages_metrics(), "git_pages_site_update_error")
    pushed_at = time.time()

    tok = forge_token(s, "pages-oversize", ["write:repository"])
    env = git_env(tmp_path, a, tok)
    work = tmp_path / "w"
    work.mkdir()
    git(work, "init", "-q", "-b", "pages", env=env)
    (work / "index.html").write_text(f"v3-{n}")
    (work / "big.bin").write_bytes(os.urandom(140 * 1024 * 1024))   # random: compression cannot hide it
    git(work, "add", ".", env=env)
    git(work, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "oversize", env=env)
    git(work, "push", "-q", "--force", f"{FORGE}/{a}/{repo}.git", "pages", env=env)

    deadline = time.monotonic() + 300
    while msum(git_pages_metrics(), "git_pages_site_update_error") < errors_before + 1:
        assert time.monotonic() < deadline, "git-pages never reported the refused update"
        time.sleep(15)
    assert f"v1-{n}" in requests.get(site_url(a, repo), timeout=10).text
    assert f"v3-{n}" not in requests.get(site_url(a, repo), timeout=10).text

    deadline = time.monotonic() + 300
    while True:
        since = alert_active_since("PagesSiteUpdateFailing")
        # I3: firing is not enough: it must have become active after our push, or an earlier failure (another
        # test, a previous run) would satisfy this without the 140 MiB push causing anything
        if since is not None and since >= pushed_at - 5:
            break
        assert time.monotonic() < deadline, "PagesSiteUpdateFailing was not activated by this push within 5 min"
        time.sleep(15)


# --- Acceptance 6 (D2) ----------------------------------------------------------------------------------
def test_other_user_cannot_publish_on_alice_host(forge_user, published, tmp_path):
    """Acceptance 6: a user cannot publish, or be made to publish, on someone else's host."""
    alice, bob_user, repo = new_user(forge_user), forge_user(), f"site-{nonce()}"
    bob_session = forge_login(bob_user)
    bob = bob_user.name
    n = nonce()
    publish(alice, repo, f"v1-{n}", published)
    publish(bob, repo, f"bob-{n}", published)
    assert wait_for_body(site_url(alice, repo), f"v1-{n}") <= PUBLISH_WITHIN
    assert wait_for_body(site_url(bob, repo), f"bob-{n}") <= PUBLISH_WITHIN
    assert f"bob-{n}" not in requests.get(site_url(alice, repo), timeout=10).text

    payload = push_payload(alice, repo, clone_owner=bob)           # alice's host, bob's clone URL
    assert requests.post(site_url(alice, repo), json=payload, timeout=10,
                         headers={"X-Forgejo-Event": "push"}).status_code == 404       # D2: no POST at the edge
    assert post_relay(payload, sig="00" * 32).status_code == 401                         # bad signature
    assert post_git_pages(host=f"{alice.lower()}.{DOMAIN}", path=f"/{repo}/",
                          payload=payload).status_code == 401                            # git-pages refuses too
    # I2: the real attack. Without trying to write to Alice's repo, a forge that let Bob push her pages branch
    # would still pass every forged-delivery check above. Bob is refused through the API and through git.
    evil = base64.b64encode(f"evil-{n}".encode()).decode()
    r = forge_api("POST", f"/api/v1/repos/{alice}/{repo}/contents", sudo=bob,
                  json={"branch": "pages", "message": "x",
                        "files": [{"operation": "create", "path": "evil.html", "content": evil}]})
    assert r.status_code in (403, 404), f"Bob's API write to Alice's pages branch gave {r.status_code}"
    btok = forge_token(bob_session, "pages-attack", ["write:repository"])
    env = git_env(tmp_path, bob, btok)
    work = tmp_path / "w"
    work.mkdir()
    git(work, "init", "-q", "-b", "pages", env=env)
    (work / "index.html").write_text(f"evil-{n}")
    git(work, "add", ".", env=env)
    git(work, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-qm", "evil", env=env)
    pushed = git_try(work, "push", "--force", f"{FORGE}/{alice}/{repo}.git", "pages", env=env)
    assert pushed.returncode != 0, "Bob could push to Alice's pages branch"
    # refused for authorization, not for some unrelated git failure (bad URL, network, hook)
    assert re.search(r"403|denied|not allowed|permission", pushed.stderr, re.I), "push failed, but not as an authorization refusal"
    # M3: wait out the 60 s site cache before saying Alice's site is unchanged
    time.sleep(PUBLISH_WITHIN)
    body = requests.get(site_url(alice, repo), timeout=10).text
    assert f"v1-{n}" in body
    assert f"bob-{n}" not in body and f"evil-{n}" not in body


# --- Acceptance 7 ---------------------------------------------------------------------------------------
def test_no_set_cookie_anywhere(forge_user, published):
    """Acceptance 7: no Set-Cookie from realliance.page, whatever a site's _headers asks for, and the
    edge always sends nosniff, Referrer-Policy and HSTS. A site that sets Set-Cookie and a non-allowlisted
    X-Content-Type-Options in _headers must not get them through."""
    a, repo, n = new_user(forge_user), f"site-{nonce()}", nonce()
    hdrs = "Set-Cookie: x=1\n  X-Content-Type-Options: none\n"
    publish(a, "pages", f"root-{n}", published)
    publish(a, repo, f"v1-{n}", published)
    assert wait_for_body(site_url(a, repo), f"v1-{n}") <= PUBLISH_WITHIN
    # project-site _headers paths start with the project path; the root site's with /
    commit_files(a, "pages", {"index.html": f"root2-{n}", "_headers": f"/*\n  {hdrs}"})
    commit_files(a, repo, {"index.html": f"v2-{n}", "_headers": f"/{repo}/*\n  {hdrs}"})
    for url, needle in ((site_url(a, "pages"), f"root2-{n}"), (site_url(a, repo), f"v2-{n}")):
        try:
            wait_for_body(url, needle)
        except AssertionError:
            pytest.fail("the publish with a disallowed _headers did not land: git-pages may abort it (C8)")

    root, project = site_url(a, "pages"), site_url(a, repo)
    for u_ in (root, project, project + "missing", f"https://{DOMAIN}/", f"https://www.{DOMAIN}/"):
        for r in (requests.get(u_, allow_redirects=False, timeout=10), requests.head(u_, allow_redirects=False, timeout=10)):
            assert "set-cookie" not in {k.lower() for k in r.headers}, f"Set-Cookie from {u_}"
    r_proj = requests.get(project, timeout=10)
    assert r_proj.headers["X-Content-Type-Options"] == "nosniff"
    assert r_proj.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert r_proj.headers["Strict-Transport-Security"] == "max-age=31536000"
    vps = from_vps_head(project)       # the internet path, not just the LAN
    # M1: a 502 or a redirect page would also carry no cookie; require a real 200 answer
    assert vps.startswith("HTTP/") and " 200" in vps.splitlines()[0], "the VPS did not get a 200"
    assert "set-cookie" not in vps.lower()


# --- Acceptance 8 (D11) ---------------------------------------------------------------------------------
def test_realliance_net_hosts_unaffected():
    """Acceptance 8: realliance.net still answers and its ingress hosts are exactly the four known ones
    (green before and after pages lands)."""
    for h in ("git.realliance.net", "realliance.net", "www.realliance.net"):
        assert requests.get(f"https://{h}/", timeout=10).status_code in (200, 301, 302, 308)
    hosts = kube("get", "ingress", "-A", "-o", "jsonpath={..host}").stdout.split()
    assert sorted(h for h in hosts if h.endswith("realliance.net")) == \
        ["git.realliance.net", "legacy.realliance.net", "realliance.net", "www.realliance.net"]


# --- Review Focus ---------------------------------------------------------------------------------------
def test_mixed_case_repo_publishes_lowercased(forge_user, published):
    """RF1: a repo called My-Site-<hex> is served at the lower-cased URL."""
    a, n = new_user(forge_user), nonce()
    repo = f"My-Site-{nonce()}"
    publish(a, repo, f"v1-{n}", published)
    assert site_url(a, repo) == site_url(a, repo.lower()) and repo.lower() in site_url(a, repo)
    assert wait_for_body(site_url(a, repo), f"v1-{n}") <= PUBLISH_WITHIN


def test_dot_repo_publishes_nothing(forge_user, published):
    """RF2: a repo named .profile with a pages branch is ignored_name, and git-pages is never asked."""
    a = new_user(forge_user)
    before_relay, before_gp = relay_metrics(), git_pages_metrics()
    publish(a, ".profile", "dot", published)
    wait_for_outcome("ignored_name", outcome(before_relay, "ignored_name") + 1)
    time.sleep(GRACE)
    after_relay, after_gp = relay_metrics(), git_pages_metrics()
    assert outcome(after_relay, "ignored_name") >= outcome(before_relay, "ignored_name") + 1
    assert outcome(after_relay, "forwarded") == outcome(before_relay, "forwarded")
    assert msum(after_gp, "git_pages_site_update_error") == msum(before_gp, "git_pages_site_update_error")


def test_branch_delete_requests_takedown(forge_user, published):
    """RF3 (D8): deleting the pages branch leaves the site up and only asks an Owner to take it down."""
    a, repo, n = new_user(forge_user), f"site-{nonce()}", nonce()
    publish(a, repo, f"v1-{n}", published)
    assert wait_for_body(site_url(a, repo), f"v1-{n}") <= PUBLISH_WITHIN
    before = outcome(relay_metrics(), "unpublish_requested")
    assert forge_api("DELETE", f"/api/v1/repos/{a}/{repo}/branches/pages").status_code == 204
    wait_for_outcome("unpublish_requested", before + 1)
    # M3: the site is cached for 60 s, so a deletion that did happen would be invisible sooner; wait it out
    time.sleep(PUBLISH_WITHIN)
    assert f"v1-{n}" in requests.get(site_url(a, repo), timeout=10).text


def test_private_then_deleted_still_requests_takedown(forge_user, published):
    """R9: the unpublish rules run before the private check, so a repo that was public, went private and
    was then deleted still counts unpublish_requested (the site outlives the repo until an Owner acts)."""
    a, repo, n = new_user(forge_user), f"site-{nonce()}", nonce()
    publish(a, repo, f"v1-{n}", published)
    assert wait_for_body(site_url(a, repo), f"v1-{n}") <= PUBLISH_WITHIN
    before = outcome(relay_metrics(), "unpublish_requested")
    assert forge_api("PATCH", f"/api/v1/repos/{a}/{repo}", json={"private": True}).status_code == 200
    assert forge_api("DELETE", f"/api/v1/repos/{a}/{repo}").status_code == 204
    wait_for_outcome("unpublish_requested", before + 1)

    # the same rule, posted straight to the relay in the real Forgejo 15 shapes, for a repo that is private now
    for event, body in (("delete", branch_delete_payload(a, repo, private=True)),
                        ("repository", repo_deleted_payload(a, repo, private=True))):
        got = outcome(relay_metrics(), "unpublish_requested")
        assert post_relay(body, event=event).status_code == 200
        assert outcome(relay_metrics(), "unpublish_requested") == got + 1


def test_apex_and_www_redirect():
    """RF4 (S28): the apex and www redirect, path kept, to the realliance root site; a 302, never cached."""
    for u in (f"https://{DOMAIN}/x", f"https://www.{DOMAIN}/x"):
        r = requests.get(u, allow_redirects=False, timeout=10)
        assert (r.status_code, r.headers["Location"]) == (302, f"https://realliance.{DOMAIN}/x")


def test_takedown_and_freeze(forge_user, published):
    """Spec Operations: takedown removes the site (visible within the 60 s cache), and a frozen domain
    refuses a new publish. Delete first, then freeze; unfreeze always runs."""
    a, repo, n = new_user(forge_user), f"site-{nonce()}", nonce()
    publish(a, repo, f"v1-{n}", published)
    url = site_url(a, repo)
    assert wait_for_body(url, f"v1-{n}") <= PUBLISH_WITHIN

    # Positive control: the in-cluster manifest read must see the LIVE site before the takedown. If the manifest
    # path is wrong for project sites it 404s here, so the later 404 could never have meant "frozen"; fail loud now
    assert manifest_status(f"{a.lower()}.{DOMAIN}", f"/{repo}") == 200, "manifest read does not see a live site"
    takedown(site_name(a, repo))
    wait_for_status(url, 404)
    domain = f"{a.lower()}.{DOMAIN}"
    try:
        freeze(domain)      # M4: inside the try, so unfreeze runs whatever happens
        before = relay_metrics()
        commit_files(a, repo, {"index.html": f"v2-{n}"})
        wait_for_outcome("forwarded", outcome(before, "forwarded") + 1)    # the push reached git-pages ...
        # I4: the 404 we polled above is cached for 60 s; if the freeze did not hold, v2 would be invisible at the
        # edge for that long. Wait out the window, then also ask git-pages itself (a cached edge 404 cannot
        # answer for the manifest read in-cluster)
        time.sleep(PUBLISH_WITHIN)
        assert requests.get(url, timeout=10).status_code == 404            # ... which refused it
        assert manifest_status(domain, f"/{repo}") == 404, "git-pages holds a site on a frozen domain"
    finally:
        unfreeze(domain)


def test_pull_mirror_sync_publishes(forge_user, published):
    """Builder check: a pull mirror's sync (a push without a Pusher) publishes like any other push."""
    a, src, mirror, n = new_user(forge_user), f"src-{nonce()}", f"mir-{nonce()}", nonce()
    publish(a, src, f"v1-{n}", published)
    r = forge_api("POST", "/api/v1/repos/migrate", sudo=a,
                  json={"clone_addr": f"{FORGE}/{a}/{src}.git", "repo_name": mirror, "mirror": True,
                        "private": False, "service": "git"})
    assert r.status_code == 201, f"creating the mirror gave {r.status_code}"
    published.append(site_name(a, mirror))
    commit_files(a, src, {"index.html": f"v2-{n}"})
    assert forge_api("POST", f"/api/v1/repos/{a}/{mirror}/mirror-sync").status_code == 200
    assert wait_for_body(site_url(a, mirror), f"v2-{n}", timeout=120) <= 120


@pytest.mark.slow
@pytest.mark.skipif(os.environ.get("PAGES_DRILL") != "actions-token", reason="drill; F3")
def test_actions_token_pushes_pages():
    """Builder check (F3), Task 10 Step 4: a Forgejo Actions job's token can push the pages branch. Needs
    the galaxy runner, which is allow-listed for realliance/forge-bot only, so the body belongs to the
    Task 10 drill run; it fails loudly rather than pass empty."""
    pytest.fail("the Actions-token drill body is written in Task 10 Step 4", pytrace=False)
