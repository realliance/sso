"""Guard: pytest prints an assert's evaluated expressions on failure (call arguments, the values of names and
containers), so no assert may touch a credential. Two rules, both fixed by binding a plain result first
(`n = len(values)`, then `assert n >= 2`):

1. no call inside an assert is handed a credential-named argument or a `token=`/`password=`/`secret=` keyword;
2. no assert refers to a name that holds a secret: one bound (in the same function, through simple
   assignments, subscripts, comprehensions, containers and method calls on it) from a secret source such as
   `_load_env(...)`, `usage_token(...)` or `ci_token(...)`. A call that merely takes such a name as an argument
   (`r = usage_raw(uid, tok)`) does not taint its result.

Module-level holders count too: a name bound at module level from a secret source, an `os.environ` or
`os.getenv` read, or called/imported as SECRETS or `*_TOKEN`/`*_KEY`/`*_SECRET`/`*_PASSWORD` (any case; a plain
string constant is a key name, not a secret) is tainted in every function of that module.

Known gaps, left as Minor: closures (an assert in a nested function on an outer name), `.format()` on a
constant, attribute stores (`o.x = tok; assert o.x`), a bare credential-named fixture parameter in a plain
assert, and a helper's result bound to a name (`y = h(tok)`)."""
import ast
import re
from pathlib import Path

CRED_NAMES = {"tok", "token", "secret", "password", "pw"}
CRED_KW = {"token", "password", "secret"}
SECRET_SOURCES = {"getenv", "_load_env", "usage_token", "ci_token", "admin_token", "forge_token"}
SECRET_NAME = re.compile(r"^(secrets?|.*_(token|key|secret|password)s?)$", re.I)
CONTAINER_CALLS = {"list", "dict", "set", "tuple", "sorted", "reversed"}


def _leaks(call: ast.Call) -> bool:
    return (any(isinstance(a, ast.Name) and a.id in CRED_NAMES for a in call.args)
            or any(k.arg in CRED_KW for k in call.keywords))


def _call_name(call: ast.Call) -> str | None:
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _tainted(e: ast.AST | None, names: set[str]) -> bool:
    """Does the value of `e` hold (part of) a secret?"""
    if e is None:
        return False
    if isinstance(e, ast.Name):
        return e.id in names
    if isinstance(e, ast.Call):
        if _call_name(e) in SECRET_SOURCES:
            return True
        if isinstance(e.func, ast.Attribute) and _tainted(e.func.value, names):     # env.get(...), tok.strip()
            return True
        return _call_name(e) in CONTAINER_CALLS and any(_tainted(a, names) for a in e.args)
    if isinstance(e, ast.Attribute) and e.attr == "environ" and isinstance(e.value, ast.Name) and e.value.id == "os":
        return True
    if isinstance(e, (ast.Subscript, ast.Attribute, ast.Starred)):
        return _tainted(e.value, names)
    if isinstance(e, (ast.List, ast.Tuple, ast.Set)):
        return any(_tainted(x, names) for x in e.elts)
    if isinstance(e, ast.Dict):
        return any(_tainted(x, names) for x in [*e.keys, *e.values])
    if isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
        inner = set(names)                      # loop variables over a secret hold (part of) it
        for g in e.generators:
            if _tainted(g.iter, inner):
                inner.update(_targets(g.target))
        parts = [e.key, e.value] if isinstance(e, ast.DictComp) else [e.elt]
        return any(_tainted(x, inner) for x in parts)
    if isinstance(e, ast.BinOp):
        return _tainted(e.left, names) or _tainted(e.right, names)
    if isinstance(e, ast.IfExp):
        return _tainted(e.body, names) or _tainted(e.orelse, names)
    if isinstance(e, ast.JoinedStr):
        return any(_tainted(v, names) for v in e.values)
    if isinstance(e, ast.FormattedValue):
        return _tainted(e.value, names)
    return False


def _scope(node: ast.AST):
    """The nodes of one function body, not descending into nested functions or classes."""
    stack = list(ast.iter_child_nodes(node))
    while stack:
        n = stack.pop()
        yield n
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(n))


def _targets(t: ast.AST):
    if isinstance(t, ast.Name):
        yield t.id
    elif isinstance(t, (ast.Tuple, ast.List)):
        for x in t.elts:
            yield from _targets(x)
    elif isinstance(t, ast.Starred):
        yield from _targets(t.value)


def module_holders(tree: ast.AST) -> set[str]:
    """Module-level names that hold secrets by name: SECRETS and *_TOKEN/*_KEY/*_SECRET/*_PASSWORD, assigned
    from anything but a string constant, or imported."""
    out = set()
    for n in ast.iter_child_nodes(tree):
        if isinstance(n, ast.ImportFrom):
            out.update(a.asname or a.name for a in n.names if SECRET_NAME.match(a.asname or a.name))
        elif isinstance(n, (ast.Assign, ast.AnnAssign)) and not (
                isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            out.update(x for t in targets for x in _targets(t) if SECRET_NAME.match(x))
    return out


def secret_names(scope: ast.AST, seed: set[str] = frozenset()) -> set[str]:
    """Names bound from a secret source in one scope (a fixpoint over simple assignments), starting from
    `seed` (the module's holders)."""
    names: set[str] = set(seed)
    nodes = list(_scope(scope))
    while True:
        before = len(names)
        for n in nodes:
            if isinstance(n, ast.Assign) and _tainted(n.value, names):
                names.update(x for t in n.targets for x in _targets(t))
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) and _tainted(n.value, names):
                names.update(_targets(n.target))
            elif isinstance(n, (ast.For, ast.comprehension)) and _tainted(n.iter, names):
                names.update(_targets(n.target))
        if len(names) == before:
            return names


def bad_asserts(tree: ast.AST) -> list[int]:
    """Line numbers of the asserts that break either rule."""
    bad = []
    scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    holders = module_holders(tree)
    module_names = secret_names(tree, holders)
    for scope in scopes:
        names = secret_names(scope, module_names) if scope is not tree else module_names
        for node in _scope(scope):
            if not isinstance(node, ast.Assert):
                continue
            parts = [node.test] + ([node.msg] if node.msg else [])
            if any(isinstance(n, ast.Call) and _leaks(n) for p in parts for n in ast.walk(p)) or any(
                    (isinstance(n, ast.Name) and n.id in names) or (isinstance(n, ast.Call) and _call_name(n) in SECRET_SOURCES)
                    or (isinstance(n, ast.Attribute) and _tainted(n, set()))
                    for p in parts for n in ast.walk(p)):
                bad.append(node.lineno)
    return sorted(set(bad))


def test_no_credential_in_assert_expressions():
    bad = []
    for path in sorted(Path(__file__).parent.rglob("*.py")):
        rel = path.relative_to(Path(__file__).parent.parent)
        bad += [f"{rel}:{n}" for n in bad_asserts(ast.parse(path.read_text(), str(path)))]
    assert not bad, "credential in an assert expression at: " + ", ".join(bad)


def test_guard_catches_the_known_leaks():
    """The guard itself: `len(values)` over tokens (the Task 16 leak) and friends are flagged, harmless
    asserts are not."""
    leak = ("def t():\n    env = {**_load_env(P), **os.environ}\n    values = [env[n] for n in NAMES if env.get(n)]\n"
            "    assert len(values) >= 2\n")
    assert bad_asserts(ast.parse(leak)) == [4]
    assert bad_asserts(ast.parse("def t():\n    t1 = usage_token()\n    assert t1\n")) == [3]
    assert bad_asserts(ast.parse("def t():\n    k = ci_token()\n    z = k.strip()\n    assert z == 'x', 'm'\n")) == [4]
    assert bad_asserts(ast.parse("def t():\n    assert ci_token()\n")) == [2]
    fine = ("def t():\n    env = _load_env(P)\n    values = [env[n] for n in NAMES]\n    n = len(values)\n"
            "    assert n >= 2\n    tok = usage_token()\n    r = usage_raw(1, tok)\n    assert r.status_code == 200\n")
    assert bad_asserts(ast.parse(fine)) == []
    mod = ("from conftest import SECRETS\nimport os\nRESEND = _load_env(P)\nHOST = 'h'\n"
           "def t(env):\n    assert f\"K={SECRETS['b']}\" in env.text\n"
           "def u():\n    assert RESEND['k']\n"
           "def v():\n    assert os.environ['X'] == 'y'\n"
           "def w():\n    e = os.environ.get('X')\n    assert e\n"
           "def x():\n    assert os.getenv('X')\n"
           "API_TOKEN = load()\ndef y():\n    assert API_TOKEN\n"
           "def z():\n    assert HOST == 'h'\n")
    assert bad_asserts(ast.parse(mod)) == [6, 8, 10, 13, 15, 18]
    assert bad_asserts(ast.parse("TOKEN_KEY = 'NAME_OF_KEY'\ndef t():\n    assert TOKEN_KEY\n")) == []
