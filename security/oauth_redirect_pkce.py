"""OAuth 2.0 回调校验：精确 redirect、PKCE、state 一次性与授权码绑定。

本模块修复的核心问题（对应初始 ``NotImplementedError`` 实现）：

1. ``redirect_uri`` 必须与注册地址 **精确匹配**。任何前缀/子串比较都会让
   ``https://app.example.com.evil.com`` 通过，因此这里只做 "规范化后整体相等"，
   绝不使用 ``startswith`` / ``in``。
2. PKCE 的 ``code_challenge`` 必须真正与 ``code_verifier`` 比对（S256 优先）。
3. ``state`` 一次性、绑定会话：读取即消费，消费与校验之间不存在重放窗口。
4. 授权码短时效、绑定 ``client_id``、单次使用；检测到重放时直接拒绝。
5. 所有失败路径默认拒绝（fail-closed），错误与日志中不泄漏 code / verifier / token。

设计约定：所有入口都返回 :class:`Result`（``Mapping`` + ``__bool__``），
绝不向上抛异常；非法输入一律返回 ``valid=False`` 且带 ``reason``。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import re
import secrets
import threading
import time
from collections import deque
from collections.abc import Mapping, MutableMapping, MutableSet
from datetime import datetime, timezone
from urllib.parse import urlsplit

__all__ = [
    "Result",
    "exact_redirect",
    "pkce_verify",
    "state_once",
    "client_bind",
    "code_ttl",
    "redirect_parse",
    "session_bind",
    "validation",
    "audit",
    "error_map",
    "fallback",
    "token_exchange",
    "scope_check",
    "replay_guard",
    "logging",
]

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

#: 授权码最长存活时间（秒）。RFC 6749 建议不超过 10 分钟，这里收紧到 60 秒。
MAX_CODE_TTL_SECONDS = 600
DEFAULT_CODE_TTL_SECONDS = 60
#: 允许的时钟偏移（秒），避免因机器间微小误差误杀刚签发的授权码。
CLOCK_SKEW_SECONDS = 5
#: access_token 返回给客户端的有效期（秒）。
ACCESS_TOKEN_TTL_SECONDS = 3600
#: state / 授权码等不透明串的长度上限，防止内存滥用。
MAX_OPAQUE_LENGTH = 512

#: PKCE code_verifier / code_challenge 的 RFC 7636 字符集。
_VERIFIER_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
_CHALLENGE_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
#: URI 中出现任何 ASCII 控制字符或空白都视为非法。
_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
#: 事件名白名单，避免把任意用户输入写进审计日志。
_EVENT_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
_DEFAULT_PORTS = {"https": 443, "http": 80}

#: 日志/审计中需要脱敏的字段名（子串匹配）。
_SENSITIVE_KEY_PARTS = (
    "code_verifier",
    "verifier",
    "code",
    "token",
    "secret",
    "password",
    "authorization",
    "cookie",
    "challenge",
)

_LOG_LEVELS = frozenset({"debug", "info", "warning", "error", "critical"})

#: 单次使用的 OAuth 错误 -> (error code, 通用描述, HTTP 状态码)。
#: 描述保持通用，绝不回显 redirect_uri / code / verifier 等敏感值。
_OAUTH_ERRORS = {
    "client_mismatch": ("invalid_grant", "authorization code was not issued to this client", 400),
    "code_expired": ("invalid_grant", "authorization code expired", 400),
    "code_unknown_or_used": ("invalid_grant", "authorization code is invalid or already used", 400),
    "replay_detected": ("invalid_grant", "authorization code replay detected", 400),
    "pkce_mismatch": ("invalid_grant", "PKCE verification failed", 400),
    "invalid_code_verifier": ("invalid_grant", "PKCE code_verifier is malformed", 400),
    "missing_code_challenge": ("invalid_request", "PKCE code_challenge is required", 400),
    "invalid_code_challenge": ("invalid_request", "PKCE code_challenge is malformed", 400),
    "unsupported_code_challenge_method": ("invalid_request", "unsupported PKCE method", 400),
    "redirect_mismatch": ("invalid_request", "redirect_uri does not match a registered URI", 400),
    "redirect_not_registered": ("invalid_request", "redirect_uri is not registered for this client", 400),
    "no_registered_redirect": ("invalid_request", "client has no registered redirect URI", 400),
    "redirect_uri_bad_scheme": ("invalid_request", "redirect_uri scheme is not allowed", 400),
    "redirect_uri_insecure_scheme": ("invalid_request", "redirect_uri must use https", 400),
    "redirect_uri_has_userinfo": ("invalid_request", "redirect_uri must not contain userinfo", 400),
    "redirect_uri_has_fragment": ("invalid_request", "redirect_uri must not contain a fragment", 400),
    "state_unknown_or_used": ("invalid_request", "state is unknown or already used", 400),
    "state_expired": ("invalid_request", "state has expired", 400),
    "state_not_bound_to_session": ("invalid_request", "state is not bound to a session", 400),
    "state_session_mismatch": ("invalid_request", "state does not belong to this session", 400),
    "state_mismatch": ("invalid_request", "state does not match", 400),
    "invalid_state": ("invalid_request", "state is malformed", 400),
    "invalid_scope": ("invalid_scope", "requested scope is not allowed", 400),
    "unsupported_grant_type": ("unsupported_grant_type", "grant_type is not supported", 400),
    "unsupported_response_type": ("unsupported_response_type", "response_type is not supported", 400),
    "invalid_client": ("invalid_client", "client authentication failed", 401),
    "missing_parameters": ("invalid_request", "a required parameter is missing", 400),
    "invalid_request": ("invalid_request", "the request is invalid", 400),
    "access_denied": ("access_denied", "request denied", 403),
    "replay_detected_registration": ("invalid_request", "request was already used", 400),
}

_MISSING = object()


# ---------------------------------------------------------------------------
# 返回值与内部工具
# ---------------------------------------------------------------------------


class Result(Mapping):
    """同时是 Mapping 和真值判断的结果对象。

    ``bool(result)`` 表示校验是否通过；``result["reason"]`` 给出机器可读原因。
    这样既方便 ``if exact_redirect(...):``，也保留结构化细节。
    """

    __slots__ = ("_data",)

    def __init__(self, ok=False, reason="", **data):
        merged = dict(data)
        merged["valid"] = bool(ok)
        merged["ok"] = bool(ok)
        merged["reason"] = reason
        object.__setattr__(self, "_data", merged)

    # Mapping 接口 ---------------------------------------------------------
    def __getitem__(self, key):
        return object.__getattribute__(self, "_data")[key]

    def __iter__(self):
        return iter(object.__getattribute__(self, "_data"))

    def __len__(self):
        return len(object.__getattribute__(self, "_data"))

    # 便捷属性访问 ---------------------------------------------------------
    def __getattr__(self, name):
        try:
            data = object.__getattribute__(self, "_data")
        except AttributeError:
            raise AttributeError(name) from None
        try:
            return data[name]
        except KeyError:
            raise AttributeError(name) from None

    def __bool__(self):
        return object.__getattribute__(self, "_data")["valid"]

    def __eq__(self, other):
        if isinstance(other, bool):
            return bool(self) is other
        if isinstance(other, Mapping):
            return dict(self) == dict(other)
        return NotImplemented

    __hash__ = None

    def __repr__(self):
        return f"Result({dict(self)!r})"

    def to_dict(self):
        return dict(self)


def _safe_token(value):
    """校验不透明串（state / code）的形态，拒绝控制字符与超长输入。"""
    return (
        isinstance(value, str)
        and 0 < len(value) <= MAX_OPAQUE_LENGTH
        and not _CONTROL_RE.search(value)
    )


def _const_eq(left, right):
    """恒定时间比较两个串；非 ASCII 输入（compare_digest 会抛 TypeError）按不等处理。"""
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
    except (UnicodeError, TypeError):
        return False


def _as_uri_list(value):
    """把注册地址参数规范成字符串列表；字符串视为单个 URI（绝不按字符拆分）。"""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [item for item in value if isinstance(item, str)]
    return []


def _as_epoch(value):
    """把时间参数转成 epoch 秒；无法确定时返回 None（调用方按失败处理）。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    return None


def _as_ttl(value):
    """TTL 必须为正的有限数；超过上限时向下收紧（fail-closed）。"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        return None
    return min(number, float(MAX_CODE_TTL_SECONDS))


def _redirect_static_check(uri):
    """返回拒绝原因；``None`` 表示 URI 形态合法。"""
    if not isinstance(uri, str):
        return "redirect_uri_must_be_string"
    if not uri:
        return "redirect_uri_empty"
    if len(uri) > 2048:
        return "redirect_uri_too_long"
    if _CONTROL_RE.search(uri):
        return "redirect_uri_has_control_chars"
    if "\\" in uri:
        # 反斜杠在部分浏览器里会被当作 "/"，可用于绕过路径校验。
        return "redirect_uri_has_backslash"
    try:
        parts = urlsplit(uri)
    except ValueError:
        return "redirect_uri_unparseable"

    if "#" in uri:
        # 按字符判断，连空 fragment（"...#"）也拒绝；RFC 6749 禁止 fragment。
        return "redirect_uri_has_fragment"
    # userinfo（user@host）既能伪装主机也能绕过精确匹配，直接拒绝。
    if parts.username is not None or parts.password is not None:
        return "redirect_uri_has_userinfo"

    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        return "redirect_uri_bad_scheme"
    host = (parts.hostname or "").lower()
    if not host:
        return "redirect_uri_missing_host"
    # 明文 http 仅允许回环地址（本机开发）。
    if scheme == "http" and host not in _LOOPBACK_HOSTS:
        return "redirect_uri_insecure_scheme"
    try:
        port = parts.port
    except ValueError:
        return "redirect_uri_bad_port"
    if port is not None and not (0 < port < 65536):
        return "redirect_uri_bad_port"
    return None


def _canonical(uri):
    """返回用于 **整体相等** 比较的元组。

    只做 RFC 3986 6.2.2/6.2.3 允许的无损规范化：scheme/host 小写、省略默认
    端口、http(s) 的空路径视为 "/"。query 的 **存在性** 也纳入比较，
    因此 ``/cb?`` 与 ``/cb`` 不相等——这是阻止
    ``app.example.com.evil.com`` 之类冒充、以及宽松"前缀匹配"的关键。
    """
    parts = urlsplit(uri)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port
    host_part = f"[{host}]" if ":" in host else host
    netloc = host_part
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        netloc = f"{host_part}:{port}"
    # 区分"没有 ?"与"空 query"：urlsplit 对两者都返回空串。
    query = parts.query if "?" in uri else None
    return (scheme, netloc, parts.path or "/", query)


def _mapping_key_seen(store, key):
    try:
        return key in store
    except TypeError:
        return False


def _pop_key(store, key):
    """原子地取出并删除 key。

    返回 ``("ok", value)`` / ``("missing", None)`` / ``("unsupported", None)``。
    出队在校验之前完成，因此并发请求中只有一个能成功，杜绝重放窗口。
    """
    pop_once = getattr(store, "pop_once", None)
    if callable(pop_once):
        try:
            value = pop_once(key)
        except Exception:  # 自定义 store 故障 -> fail-closed
            return "unsupported", None
        if value is _MISSING or value is None:
            return "missing", None
        return "ok", value

    if isinstance(store, MutableMapping):
        with _STORE_LOCK:
            if _mapping_key_seen(store, key):
                return "ok", store.pop(key)
        return "missing", None

    if isinstance(store, MutableSet):
        with _STORE_LOCK:
            if key in store:
                store.discard(key)
                return "ok", True
        return "missing", None

    return "unsupported", None


def _redact(value, depth=0):
    """递归脱敏，避免 code / verifier / token 进入日志与审计。"""
    if depth > 4:
        return "<max-depth>"
    if isinstance(value, Mapping):
        cleaned = {}
        for key, item in value.items():
            name = str(key)
            lowered = name.lower()
            if any(part in lowered for part in _SENSITIVE_KEY_PARTS):
                cleaned[name] = "[REDACTED]"
            else:
                cleaned[name] = _redact(item, depth + 1)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [_redact(item, depth + 1) for item in list(value)[:50]]
    if isinstance(value, str):
        return value[:256]
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return repr(value)[:256]


def _normalize_scopes(value):
    """把 scope 规范成有序、去重的列表；非法输入返回 None。"""
    if value is None:
        return []
    if isinstance(value, str):
        items = value.split()
    elif isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
    else:
        return None
    scopes = []
    for item in items:
        if not isinstance(item, str):
            return None
        token = item.strip()
        if not token or _CONTROL_RE.search(token):
            return None
        if token not in scopes:
            scopes.append(token)
    return scopes


# 进程内的原子化锁与有界缓存。生产环境应替换为 Redis 等共享存储的
# ``pop_once`` / ``SETNX`` 原语，但语义保持一致。
_STORE_LOCK = threading.Lock()
_AUDIT_LOCK = threading.Lock()
_LOG_LOCK = threading.Lock()

_AUDIT_LOG = deque(maxlen=1024)
_LOG_RECORDS = deque(maxlen=1024)
_REPLAY_SEEN = {}  # code 摘要 -> 首次消费时间
_REPLAY_SEEN_MAX = 4096
_DEFAULT_CODE_STORE = {}
_DEFAULT_REPLAY_STORE = {}
_ISSUED_TOKENS = {}


def _digest(value):
    return hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()


def _mark_seen(value):
    with _STORE_LOCK:
        _REPLAY_SEEN[_digest(value)] = time.time()
        if len(_REPLAY_SEEN) > _REPLAY_SEEN_MAX:
            # 丢弃最旧的四分之一，保持内存有界。
            for stale in list(_REPLAY_SEEN)[: _REPLAY_SEEN_MAX // 4]:
                _REPLAY_SEEN.pop(stale, None)


def _was_seen(value):
    with _STORE_LOCK:
        return _digest(value) in _REPLAY_SEEN


def _consume_code(store, code):
    """消费授权码：返回 ``("ok", record)`` / ``("replay", None)`` / ..."""
    status, record = _pop_key(store, code)
    if status == "ok":
        _mark_seen(code)
        return status, record
    if status == "missing" and _was_seen(code):
        return "replay", None
    return status, record


# ---------------------------------------------------------------------------
# 1. redirect_uri 解析与精确匹配
# ---------------------------------------------------------------------------


def redirect_parse(redirect_uri, registered=None):
    """解析并静态校验 redirect URI。

    拒绝 userinfo、fragment、控制字符、反斜杠，以及非 https（回环地址除外）。
    ``registered`` 仅作为附加上下文回显，不参与放行判断。
    """
    reason = _redirect_static_check(redirect_uri)
    if reason is not None:
        return Result(False, reason)

    parts = urlsplit(redirect_uri)
    try:
        port = parts.port
    except ValueError:  # pragma: no cover - 静态检查已覆盖
        return Result(False, "redirect_uri_bad_port")

    info = {
        "scheme": parts.scheme.lower(),
        "host": (parts.hostname or "").lower(),
        "port": port,
        "path": parts.path,
        "query": parts.query,
        "netloc": parts.netloc,
        "has_registered_hint": registered is not None,
    }
    return Result(True, "redirect_parsed", **info)


def exact_redirect(redirect_uri, registered_uris):
    """要求 ``redirect_uri`` 与某个注册地址 **整体相等**。

    这里刻意只比较规范化后的完整元组，不做前缀、通配或子域匹配，
    所以 ``https://app.example.com.evil.com`` 无法冒充
    ``https://app.example.com``。
    """
    candidates = _as_uri_list(registered_uris)
    if not candidates:
        return Result(False, "no_registered_redirect")

    reason = _redirect_static_check(redirect_uri)
    if reason is not None:
        return Result(False, reason)

    try:
        target = _canonical(redirect_uri)
    except ValueError:
        return Result(False, "redirect_uri_unparseable")

    for candidate in candidates:
        if _redirect_static_check(candidate) is not None:
            # 非法注册项直接跳过，绝不放宽为前缀匹配。
            continue
        try:
            if _canonical(candidate) == target:
                return Result(True, "exact_redirect_match", matched=candidate)
        except ValueError:
            continue

    return Result(False, "redirect_mismatch")


# ---------------------------------------------------------------------------
# 2. PKCE
# ---------------------------------------------------------------------------


def pkce_verify(code_verifier, code_challenge, method="S256"):
    """真正比对 ``code_verifier`` 与 ``code_challenge``（用恒定时间比较）。"""
    if not isinstance(code_verifier, str) or not _VERIFIER_RE.match(code_verifier):
        return Result(False, "invalid_code_verifier")
    if not isinstance(code_challenge, str) or not code_challenge:
        return Result(False, "missing_code_challenge")
    if not _CHALLENGE_RE.match(code_challenge):
        return Result(False, "invalid_code_challenge")

    normalized = method.upper() if isinstance(method, str) else ""
    if normalized == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        ok = _const_eq(expected, code_challenge)
        return Result(ok, "pkce_ok" if ok else "pkce_mismatch", method="S256")

    if normalized == "PLAIN":
        # RFC 7636 允许，但 S256 优先；仍然做真正的比对而不是直接放行。
        ok = _const_eq(code_verifier, code_challenge)
        return Result(
            ok,
            "pkce_ok" if ok else "pkce_mismatch",
            method="PLAIN",
            warning="plain_method_discouraged",
        )

    return Result(False, "unsupported_code_challenge_method", method=normalized or None)


# ---------------------------------------------------------------------------
# 3. state / session / client 绑定
# ---------------------------------------------------------------------------


def state_once(state, store):
    """state 一次性消费：先原子取出，再谈是否有效。

    ``store`` 可以是 ``MutableMapping``（state -> record）、``MutableSet``，
    或提供 ``pop_once(key)`` 的共享存储。已经用过的 state 无法再次通过。
    """
    if not _safe_token(state):
        return Result(False, "invalid_state")

    status, record = _pop_key(store, state)
    if status == "unsupported":
        return Result(False, "state_store_unavailable")
    if status == "missing":
        return Result(False, "state_unknown_or_used")

    # state 已消费；若记录带有签发时间，则额外检查年龄。
    if isinstance(record, Mapping) and record.get("issued_at") is not None:
        ttl = record.get("ttl", DEFAULT_CODE_TTL_SECONDS)
        freshness = code_ttl(record.get("issued_at"), ttl=ttl)
        if not freshness:
            return Result(False, "state_expired")

    return Result(True, "state_consumed", record=record)


def session_bind(state_record, session_id):
    """校验 state 记录确实绑定到当前会话。"""
    if not isinstance(state_record, Mapping):
        return Result(False, "invalid_state_record")
    bound = state_record.get("session_id")
    if not isinstance(bound, str) or not bound:
        return Result(False, "state_not_bound_to_session")
    if not isinstance(session_id, str) or not session_id:
        return Result(False, "state_session_mismatch")
    ok = _const_eq(bound, session_id)
    return Result(ok, "state_session_match" if ok else "state_session_mismatch")


def client_bind(code_record, client_id):
    """校验授权码只对签发它的 ``client_id`` 有效（防止跨客户端兑换）。"""
    if not isinstance(code_record, Mapping):
        return Result(False, "invalid_code_record")
    bound = code_record.get("client_id")
    if not isinstance(bound, str) or not bound:
        return Result(False, "code_not_bound_to_client")
    if not isinstance(client_id, str) or not client_id:
        return Result(False, "missing_client_id")
    ok = _const_eq(bound, client_id)
    return Result(ok, "client_match" if ok else "client_mismatch")


# ---------------------------------------------------------------------------
# 4. 授权码时效
# ---------------------------------------------------------------------------


def code_ttl(issued_at, now=None, ttl=DEFAULT_CODE_TTL_SECONDS):
    """授权码必须在短 TTL 内使用，且不能来自"未来"。"""
    issued = _as_epoch(issued_at)
    current = _as_epoch(now) if now is not None else time.time()
    limit = _as_ttl(ttl)

    if issued is None or current is None or limit is None:
        return Result(False, "invalid_timestamp")

    age = current - issued
    if age < -CLOCK_SKEW_SECONDS:
        return Result(False, "code_issued_in_future", age=age, ttl=limit)
    if age > limit:
        return Result(False, "code_expired", age=age, ttl=limit)
    return Result(True, "code_fresh", age=max(age, 0.0), ttl=limit)


# ---------------------------------------------------------------------------
# 5. 完整授权请求校验
# ---------------------------------------------------------------------------


def _registered_for(config, client_id):
    """从 config 中取出该 client 的注册 redirect 列表。"""
    registered = (
        config.get("registered_redirects")
        or config.get("redirect_uris")
        or config.get("registered_uris")
    )
    if isinstance(registered, Mapping):
        return registered.get(client_id) or []
    return registered or []


def validation(payload, config=None):
    """校验授权请求（authorize 端点），不消费 state。

    要求：response_type=code、client_id 存在、redirect_uri 精确匹配注册地址、
    必须携带 PKCE 且方法受支持、state 存在。
    """
    if not isinstance(payload, Mapping):
        return Result(False, "invalid_request")

    config = config if isinstance(config, Mapping) else {}
    required = ("response_type", "client_id", "redirect_uri", "state")
    missing = [name for name in required if not payload.get(name)]
    if not payload.get("code_challenge") or not payload.get("code_challenge_method"):
        missing.append("code_challenge")
    if missing:
        return Result(False, "missing_parameters", missing=missing)

    if payload.get("response_type") != "code":
        return Result(False, "unsupported_response_type")

    client_id = payload.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        return Result(False, "invalid_client")

    registered = _registered_for(config, client_id)
    if not _as_uri_list(registered):
        return Result(False, "redirect_not_registered")

    redirect = exact_redirect(payload.get("redirect_uri"), registered)
    if not redirect:
        return Result(False, redirect.reason)

    method = payload.get("code_challenge_method")
    if not isinstance(method, str) or method.upper() not in {"S256", "PLAIN"}:
        return Result(False, "unsupported_code_challenge_method")

    challenge = payload.get("code_challenge")
    if not isinstance(challenge, str) or not _CHALLENGE_RE.match(challenge):
        return Result(False, "invalid_code_challenge")

    state = payload.get("state")
    if not _safe_token(state):
        return Result(False, "invalid_state")

    # 若配置提供了 state store，确认 state 存在且（可选）绑定会话，但不消费。
    state_store = config.get("state_store")
    if state_store is not None:
        try:
            present = _mapping_key_seen(state_store, state)
        except Exception:
            present = False
        if not present:
            return Result(False, "state_unknown_or_used")
        try:
            record = state_store.get(state) if isinstance(state_store, MutableMapping) else None
        except Exception:
            record = None
        if isinstance(record, Mapping) and config.get("session_id") is not None:
            bound = session_bind(record, config.get("session_id"))
            if not bound:
                return Result(False, bound.reason)

    return Result(
        True,
        "request_valid",
        client_id=client_id,
        redirect_uri=payload.get("redirect_uri"),
        code_challenge_method=method.upper(),
    )


# ---------------------------------------------------------------------------
# 6. scope
# ---------------------------------------------------------------------------


def scope_check(requested, granted=None):
    """请求的 scope 必须是已授权 scope 的子集。"""
    requested_scopes = _normalize_scopes(requested)
    if requested_scopes is None:
        return Result(False, "invalid_scope")
    granted_scopes = _normalize_scopes(granted)
    if granted_scopes is None:
        return Result(False, "invalid_scope")

    missing = [scope for scope in requested_scopes if scope not in granted_scopes]
    if missing:
        return Result(False, "invalid_scope", missing=missing, granted_scopes=granted_scopes)
    return Result(True, "scope_allowed", granted_scopes=requested_scopes)


# ---------------------------------------------------------------------------
# 7. 授权码兑换
# ---------------------------------------------------------------------------


def token_exchange(request, store=None):
    """用授权码兑换 token；完成全部绑定与一次性检查。

    顺序很重要：先原子消费授权码（含重放检测），再做 client / redirect /
    TTL / PKCE / scope 校验。任何一步失败都拒绝，且授权码不会被"退回"。
    """
    if not isinstance(request, Mapping):
        return Result(False, "invalid_request")
    if request.get("grant_type") != "authorization_code":
        return Result(False, "unsupported_grant_type")

    required = ("code", "redirect_uri", "client_id", "code_verifier")
    missing = [
        name
        for name in required
        if not isinstance(request.get(name), str) or not request.get(name)
    ]
    if missing:
        return Result(False, "missing_parameters", missing=missing)

    code = request.get("code")
    if not _safe_token(code):
        return Result(False, "code_unknown_or_used")

    target_store = store if store is not None else _DEFAULT_CODE_STORE
    status, record = _consume_code(target_store, code)
    if status == "replay":
        return Result(False, "replay_detected")
    if status == "missing":
        return Result(False, "code_unknown_or_used")
    if status == "unsupported":
        return Result(False, "code_store_unavailable")
    if not isinstance(record, Mapping):
        return Result(False, "invalid_grant")

    bound = client_bind(record, request.get("client_id"))
    if not bound:
        return Result(False, bound.reason)

    registered_redirect = record.get("redirect_uri")
    redirect = exact_redirect(
        request.get("redirect_uri"),
        _as_uri_list(registered_redirect),
    )
    if not redirect:
        return Result(False, "redirect_mismatch")

    issued_at = record.get("issued_at")
    if issued_at is None:
        return Result(False, "code_expired")
    freshness = code_ttl(issued_at, ttl=record.get("ttl", DEFAULT_CODE_TTL_SECONDS))
    if not freshness:
        return Result(False, freshness.reason)

    challenge = record.get("code_challenge")
    if not isinstance(challenge, str) or not challenge:
        # 签发时缺少 challenge 的记录不允许兑换，避免降级成无 PKCE。
        return Result(False, "missing_code_challenge")
    pkce = pkce_verify(
        request.get("code_verifier"),
        challenge,
        record.get("code_challenge_method", "S256"),
    )
    if not pkce:
        return Result(False, pkce.reason)

    # 授权码记录里携带的 scope 必须落在该 client 获准的 scope 之内。
    # 若记录没有 allowed_scope，则只能以记录自身 scope 为准。
    granted_by_client = record.get("allowed_scope")
    if granted_by_client is None:
        granted_by_client = record.get("scope", "")
    scope = scope_check(record.get("scope", ""), granted_by_client)
    if not scope:
        return Result(False, scope.reason)

    access_token = secrets.token_urlsafe(32)
    with _STORE_LOCK:
        if len(_ISSUED_TOKENS) >= _REPLAY_SEEN_MAX:
            now = time.time()
            for stale, meta in list(_ISSUED_TOKENS.items()):
                if meta["expires_at"] <= now:
                    _ISSUED_TOKENS.pop(stale, None)
            # 仍然超限则丢弃最旧的一批，保持内存有界。
            if len(_ISSUED_TOKENS) >= _REPLAY_SEEN_MAX:
                for stale in list(_ISSUED_TOKENS)[: _REPLAY_SEEN_MAX // 4]:
                    _ISSUED_TOKENS.pop(stale, None)
        _ISSUED_TOKENS[access_token] = {
            "client_id": request.get("client_id"),
            "scope": " ".join(scope["granted_scopes"]),
            "expires_at": time.time() + ACCESS_TOKEN_TTL_SECONDS,
        }
    audit(
        "token_issued",
        {
            "client_id": request.get("client_id"),
            "grant_type": "authorization_code",
            "scope": " ".join(scope["granted_scopes"]),
        },
    )

    return Result(
        True,
        "token_issued",
        access_token=access_token,
        token_type="Bearer",
        expires_in=ACCESS_TOKEN_TTL_SECONDS,
        scope=" ".join(scope["granted_scopes"]),
        client_id=request.get("client_id"),
    )


# ---------------------------------------------------------------------------
# 8. 重放防护
# ---------------------------------------------------------------------------


def replay_guard(key, store=None, ttl=None):
    """登记一次性 key（nonce/jti/授权码摘要），重复出现即判定重放。

    首次登记返回 ``True``；重复返回 ``False`` 且 reason=``replay_detected``。
    若提供 ``ttl``，超过窗口的旧记录允许重新登记。
    """
    if not _safe_token(key):
        return Result(False, "invalid_replay_key")

    target = store if store is not None else _DEFAULT_REPLAY_STORE
    try:
        window = _as_ttl(ttl) if ttl is not None else None
    except Exception:
        window = None
    now = time.time()

    if isinstance(target, MutableMapping):
        with _STORE_LOCK:
            existing = target.get(key)
            if existing is not None:
                first_seen = _as_epoch(existing)
                if (
                    window is not None
                    and first_seen is not None
                    and now - first_seen > window
                ):
                    target[key] = now
                    return Result(True, "replay_window_expired")
                return Result(False, "replay_detected")
            target[key] = now
            if len(target) > _REPLAY_SEEN_MAX:
                for stale in list(target)[: _REPLAY_SEEN_MAX // 4]:
                    target.pop(stale, None)
            return Result(True, "replay_guard_registered")

    put_if_absent = getattr(target, "put_if_absent", None)
    if callable(put_if_absent):
        try:
            inserted = put_if_absent(key, now)
        except Exception:
            return Result(False, "replay_store_unavailable")
        ok = bool(inserted)
        return Result(ok, "replay_guard_registered" if ok else "replay_detected")

    return Result(False, "replay_store_unavailable")


# ---------------------------------------------------------------------------
# 9. 错误映射 / 默认拒绝 / 审计 / 日志
# ---------------------------------------------------------------------------


def _classify_error(reason):
    lowered = reason.lower()
    if lowered in _OAUTH_ERRORS:
        return _OAUTH_ERRORS[lowered]
    if "scope" in lowered:
        return _OAUTH_ERRORS["invalid_scope"]
    if "client" in lowered and "mismatch" in lowered:
        return _OAUTH_ERRORS["client_mismatch"]
    if "redirect" in lowered:
        return _OAUTH_ERRORS["redirect_mismatch"]
    if "state" in lowered or "session" in lowered:
        return _OAUTH_ERRORS["state_unknown_or_used"]
    if "verifier" in lowered or "challenge" in lowered or "pkce" in lowered:
        return _OAUTH_ERRORS["pkce_mismatch"]
    if "expired" in lowered or "replay" in lowered or "code" in lowered:
        return _OAUTH_ERRORS["code_unknown_or_used"]
    return _OAUTH_ERRORS["invalid_request"]


def error_map(error, config=None):
    """把内部失败原因映射成标准 OAuth 错误，且不回显敏感输入。"""
    if isinstance(error, Result):
        source = error.get("reason", "invalid_request")
    elif isinstance(error, Mapping):
        source = error.get("reason") or error.get("error") or "invalid_request"
    elif isinstance(error, BaseException):
        source = type(error).__name__.lower()
    elif isinstance(error, str):
        source = error
    else:
        source = "invalid_request"

    if not isinstance(source, str) or not source:
        source = "invalid_request"

    code, description, status = _classify_error(source)
    return Result(
        True,
        "error_mapped",
        error=code,
        error_description=description,
        http_status=status,
        source=source[:128],
    )


def fallback(reason="access_denied", config=None):
    """默认拒绝（fail-closed）：任何不确定路径都不得放行或重定向。"""
    label = reason if isinstance(reason, str) and reason else "access_denied"
    error = error_map(label if label in _OAUTH_ERRORS else "access_denied")
    return Result(
        False,
        label,
        allow=False,
        redirect=None,
        error=error["error"],
        error_description=error["error_description"],
    )


def audit(event, details=None):
    """写入脱敏审计日志；永不抛出。"""
    if isinstance(event, Mapping):
        merged = dict(event)
        label = merged.pop("event", "unknown_event")
        details = merged if details is None else details
    else:
        label = event

    if not isinstance(label, str) or not _EVENT_RE.match(label):
        label = "unknown_event"

    entry = {
        "event": label,
        "at": time.time(),
        "details": _redact(details if details is not None else {}),
    }
    try:
        with _AUDIT_LOCK:
            _AUDIT_LOG.append(entry)
    except Exception:  # pragma: no cover - 日志不应影响主流程
        pass
    return Result(True, "audited", entry=entry)


def logging(level="info", message=None, **fields):
    """结构化脱敏日志；level 走白名单，消息不记录原始敏感值。"""
    if isinstance(level, Mapping) and message is None:
        merged = dict(level)
        level = merged.pop("level", "info")
        message = merged.pop("message", None)
        fields = {**merged, **fields}

    normalized_level = level.lower() if isinstance(level, str) else "info"
    if normalized_level not in _LOG_LEVELS:
        normalized_level = "info"

    safe_message = message[:256] if isinstance(message, str) else None
    record = {
        "level": normalized_level,
        "message": safe_message,
        "fields": _redact(fields),
        "at": time.time(),
    }
    try:
        with _LOG_LOCK:
            _LOG_RECORDS.append(record)
    except Exception:  # pragma: no cover
        pass
    return Result(True, "logged", record=record)
