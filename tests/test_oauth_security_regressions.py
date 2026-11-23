"""OAuth 回调校验的对抗性回归测试。

每个用例对应题目里描述的一类真实缺陷，修复前必然失败。
"""

import base64
import hashlib
import time

import pytest

from security.oauth_redirect_pkce import (
    audit,
    client_bind,
    code_ttl,
    error_map,
    exact_redirect,
    fallback,
    logging,
    pkce_verify,
    redirect_parse,
    replay_guard,
    scope_check,
    session_bind,
    state_once,
    token_exchange,
    validation,
)

REGISTERED = "https://app.example.com/oauth/callback"


def s256(verifier):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# --- redirect_uri 精确匹配 -------------------------------------------------


@pytest.mark.parametrize(
    "attack",
    [
        "https://app.example.com.evil.com/oauth/callback",   # 后缀冒充
        "https://evil.com/https://app.example.com/oauth/callback",
        "https://app.example.com/oauth/callback/extra",       # 前缀扩展
        "https://app.example.com/oauth/callbac",              # 截断
        "https://app.example.com/oauth/callback#x",           # fragment
        "https://app.example.com/oauth/callback?",            # 空 query
        "https://app.example.com:8443/oauth/callback",        # 端口变化
        "http://app.example.com/oauth/callback",              # scheme 降级
        "https://app.example.com@evil.com/oauth/callback",    # userinfo 伪装
        "https://app.example.com\\@evil.com/oauth/callback",  # 反斜杠
        "https://app.example.com/oauth/callback\n",           # 控制字符
    ],
)
def test_exact_redirect_rejects_lookalikes(attack):
    assert not exact_redirect(attack, [REGISTERED])


def test_exact_redirect_accepts_only_true_match_and_equivalents():
    assert exact_redirect(REGISTERED, [REGISTERED])
    # RFC 3986 等价形式（大小写、默认端口）可以接受。
    assert exact_redirect(
        "HTTPS://APP.EXAMPLE.COM:443/oauth/callback", [REGISTERED]
    )
    assert exact_redirect("https://app.example.com/oauth/callback", REGISTERED)
    assert not exact_redirect(REGISTERED, [])


def test_redirect_parse_static_rules():
    assert not redirect_parse("https://app.example.com/cb#frag")
    assert not redirect_parse("https://app.example.com/cb#")        # 空 fragment 也拒绝
    assert not redirect_parse("http://app.example.com/cb")          # 非回环 http
    assert redirect_parse("http://127.0.0.1:8000/cb")["valid"]
    assert redirect_parse("http://localhost:8000/cb")["valid"]


# --- PKCE ------------------------------------------------------------------


def test_pkce_actually_compares_verifier():
    verifier = "a" * 64
    challenge = s256(verifier)
    assert pkce_verify(verifier, challenge)
    assert not pkce_verify("b" * 64, challenge)      # 不能收了不比对
    assert not pkce_verify(verifier, s256("c" * 64))
    assert not pkce_verify(verifier, challenge, method="S512")


def test_pkce_rejects_malformed_inputs():
    assert not pkce_verify("short", s256("short"))
    assert not pkce_verify(None, "x" * 43)
    assert not pkce_verify("a" * 64, None)


# --- state 一次性 + 会话绑定 -----------------------------------------------


def test_state_single_use():
    store = {"s-1": {"session_id": "sess-1", "issued_at": time.time(), "ttl": 600}}
    first = state_once("s-1", store)
    assert first
    assert session_bind(first["record"], "sess-1")
    assert not session_bind(first["record"], "sess-2")
    # 第二次必然失败，且不能因失败而"回滚"可用性。
    assert not state_once("s-1", store)
    assert "s-1" not in store


def test_state_cannot_be_consumed_from_wrong_session():
    store = {"s-2": {"session_id": "sess-1", "issued_at": time.time(), "ttl": 600}}
    record = state_once("s-2", store)
    assert record and not session_bind(record["record"], "attacker-session")


def test_state_expired():
    store = {"s-3": {"issued_at": time.time() - 3600, "ttl": 60}}
    assert not state_once("s-3", store)


def test_redirect_trailing_query_marker_is_not_normalized_away():
    # 按 RFC 6749 简单字符串比较，"/cb?" 与 "/cb" 不是同一个地址。
    assert not exact_redirect(REGISTERED + "?", [REGISTERED])
    assert exact_redirect(REGISTERED + "?a=1", [REGISTERED + "?a=1"])


def test_unicode_input_never_raises_and_compares_exactly():
    # hmac.compare_digest 对非 ASCII str 会抛 TypeError；入口必须 fail-closed 而非崩溃。
    assert session_bind({"session_id": "会话-1"}, "会话-1")
    assert not session_bind({"session_id": "会话-1"}, "会话-2")
    assert client_bind({"client_id": "客户端"}, "客户端")
    assert not client_bind({"client_id": "客户端"}, "别的客户端")
    assert not session_bind({"session_id": 1}, "1")
    assert not replay_guard(123, {})


# --- 授权码时效与绑定 ------------------------------------------------------


def test_code_ttl_short_lived():
    assert code_ttl(1000.0, now=1030.0, ttl=60)
    assert not code_ttl(1000.0, now=1000.0 + 61, ttl=60)
    assert not code_ttl(2000.0, now=1000.0, ttl=60)     # 来自未来
    assert not code_ttl("not-a-time", now=1000.0, ttl=60)


def test_client_bind():
    record = {"client_id": "client-a"}
    assert client_bind(record, "client-a")
    assert not client_bind(record, "client-b")
    assert not client_bind({}, "client-a")


# --- 完整兑换流程 ----------------------------------------------------------


def make_record(code="code-1", client="client-a", verifier="v" * 64, issued_at=None,
                redirect=REGISTERED, scope="openid profile", ttl=60):
    import time as _t
    return {
        "client_id": client,
        "redirect_uri": redirect,
        "issued_at": _t.time() if issued_at is None else issued_at,
        "ttl": ttl,
        "code_challenge": s256(verifier),
        "code_challenge_method": "S256",
        "scope": scope,
        "allowed_scope": scope,
    }


def exchange_ok(store, code="code-1", **kwargs):
    req = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REGISTERED,
        "client_id": "client-a",
        "code_verifier": "v" * 64,
    }
    req.update(kwargs)
    return token_exchange(req, store)


def test_token_exchange_happy_path_then_replay():
    store = {"code-1": make_record()}
    ok = exchange_ok(store)
    assert ok and ok["access_token"]
    assert ok["expires_in"] > 0
    # 同一授权码再次兑换 -> 重放拒绝。
    replay = exchange_ok(store)
    assert not replay and replay["reason"] == "replay_detected"


def test_token_exchange_enforces_bindings():
    # 错误 client
    store = {"code-1": make_record()}
    r = exchange_ok(store, client_id="client-b")
    assert not r and r["reason"] == "client_mismatch"

    # 错误 redirect_uri（域名后缀冒充）
    store = {"code-1": make_record()}
    r = exchange_ok(store, redirect_uri="https://app.example.com.evil.com/oauth/callback")
    assert not r

    # 错误 code_verifier
    store = {"code-1": make_record()}
    r = exchange_ok(store, code_verifier="w" * 64)
    assert not r


def test_token_exchange_rejects_expired_and_missing_pkce():
    store = {"code-1": make_record(issued_at=0.0)}
    assert not exchange_ok(store)

    expired = make_record()
    expired.pop("code_challenge")
    store = {"code-1": expired}
    assert not exchange_ok(store)


def test_token_exchange_is_atomic_under_concurrency():
    import threading

    store = {"code-1": make_record()}
    results = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        results.append(bool(exchange_ok(store)))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(True) == 1
    assert results.count(False) == 7


def test_token_exchange_requires_pkce_parameters():
    req = {"grant_type": "authorization_code", "code": "c"}
    r = token_exchange(req, {})
    assert not r and r["reason"] == "missing_parameters"


# --- 授权请求校验 ----------------------------------------------------------


def test_validation_requires_pkce_and_exact_redirect():
    base = {
        "response_type": "code",
        "client_id": "client-a",
        "redirect_uri": REGISTERED,
        "state": "s-1",
        "code_challenge": s256("v" * 64),
        "code_challenge_method": "S256",
    }
    config = {"registered_redirects": {"client-a": [REGISTERED]}}
    assert validation(base, config)

    bad = dict(base, redirect_uri="https://app.example.com.evil.com/oauth/callback")
    assert not validation(bad, config)

    no_pkce = {k: v for k, v in base.items() if k != "code_challenge"}
    assert not validation(no_pkce, config)


# --- scope / 重放 / 错误映射 / fail-closed ---------------------------------


def test_scope_check():
    assert scope_check("openid profile", "openid profile email")
    assert not scope_check("openid admin", "openid profile")
    assert not scope_check("openid", None)


def test_replay_guard():
    store = {}
    assert replay_guard("jti-1", store)
    second = replay_guard("jti-1", store)
    assert not second and second["reason"] == "replay_detected"


def test_error_map_and_fallback_never_echo_secrets():
    mapped = error_map("redirect_mismatch")
    assert mapped["error"] == "invalid_request"
    assert "app.example.com" not in mapped["error_description"]

    denied = fallback()
    assert not denied and denied["allow"] is False and denied["redirect"] is None


# --- 审计与日志脱敏 --------------------------------------------------------


def test_audit_and_logging_redact_secrets():
    entry = audit(
        "token_exchange",
        {"code": "SECRET-CODE", "code_verifier": "SECRET-VERIFIER", "client_id": "client-a"},
    )["entry"]
    assert entry["details"]["code"] == "[REDACTED]"
    assert entry["details"]["code_verifier"] == "[REDACTED]"
    assert entry["details"]["client_id"] == "client-a"

    record = logging("info", "exchange", access_token="SECRET-TOKEN")["record"]
    assert record["fields"]["access_token"] == "[REDACTED]"
    assert record["level"] == "info"

    # 非法 level 回落，非法事件名归一化，均不抛异常。
    assert logging("nonsense")["record"]["level"] == "info"
    assert audit("bad event name!")["entry"]["event"] == "unknown_event"
