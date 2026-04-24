from dataclasses import dataclass

from oauthive.runner import _order_for_session_mode


@dataclass
class _C:
    id: str
    name: str = ""
    parallel_safe: bool = True
    requires_fresh_auth: bool = False
    requires_capabilities: frozenset = frozenset()


def test_isolated_mode_preserves_order():
    checks = [_C(id="a"), _C(id="refresh_token"), _C(id="b")]
    assert [c.id for c in _order_for_session_mode(checks, "isolated")] == ["a", "refresh_token", "b"]


def test_fast_mode_pushes_mutating_checks_last():
    checks = [_C(id="a"), _C(id="logout"), _C(id="b"), _C(id="refresh_token")]
    ordered = [c.id for c in _order_for_session_mode(checks, "fast")]
    assert ordered[:2] == ["a", "b"]
    assert set(ordered[2:]) == {"logout", "refresh_token"}


def test_fast_mode_respects_requires_fresh_auth_flag():
    checks = [
        _C(id="needs_fresh", requires_fresh_auth=True),
        _C(id="quiet"),
    ]
    ordered = [c.id for c in _order_for_session_mode(checks, "fast")]
    assert ordered == ["quiet", "needs_fresh"]
