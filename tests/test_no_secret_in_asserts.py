"""Guard: pytest prints an assert's evaluated calls (arguments included) on failure, so no assert
expression may contain a call that is handed a credential. Bind the result first, then assert."""
import ast
from pathlib import Path

CRED_NAMES = {"tok", "token", "secret", "password", "pw"}
CRED_KW = {"token", "password", "secret"}


def _leaks(call: ast.Call) -> bool:
    return (any(isinstance(a, ast.Name) and a.id in CRED_NAMES for a in call.args)
            or any(k.arg in CRED_KW for k in call.keywords))


def test_no_credential_in_assert_expressions():
    bad = []
    for path in sorted(Path(__file__).parent.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(), str(path))):
            if isinstance(node, ast.Assert) and any(
                    isinstance(n, ast.Call) and _leaks(n) for n in ast.walk(node.test)):
                bad.append(f"{path.relative_to(Path(__file__).parent.parent)}:{node.lineno}")
    assert not bad, "credential passed to a call inside an assert at: " + ", ".join(bad)
