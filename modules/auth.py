"""
Accounts, sessions and scan allowances.

The dashboard used to be open because it was bound to loopback. Once it is
published behind a proxy that reasoning stops holding: "anyone who can reach the
port" becomes the whole internet. This module is what stands in front of it.

Everything lives in one file, `key.json` (path in config.KEY_FILE):

    {
      "version": 1,
      "secret": "<random · signs session tokens>",
      "created_at": "...",
      "users": {
        "<name>": {
          "role": "admin" | "user",
          "salt": "...", "hash": "...", "rounds": 240000,
          "pwv": 1,                     password version · bumping it kills tokens
          "enabled": true,
          "limits": {"daily_scans": 10, "concurrent": 1, "see_all": false,
                     "portscan": true, "tor": true, "wayback": true, "deep": true},
          "usage": {"day": "2026-08-02", "scans": 3},
          "created_at": "...", "created_by": "...",
          "last_login": "...", "failures": 0, "locked_until": 0
        }
      }
    }

Design notes that matter for the security of it:

  * passwords are never stored · PBKDF2-HMAC-SHA256 with a per-user random salt
    and a high round count, compared in constant time,
  * the file is written 0600 and atomically (temp file + rename), so a crashed
    write cannot leave a half-parsed account store that locks everyone out,
  * session tokens are signed JWTs (HS256) carrying nothing secret: subject,
    role, issue/expiry, the password version and a CSRF value. Changing a
    password bumps `pwv`, which invalidates every token already handed out,
  * sign-in failures are counted per account and lock it for a cool-off, so the
    login form is not an oracle you can grind,
  * no file at all means "not configured yet" and the dashboard stays open · a
    fresh checkout that has not been through ./install.sh is still usable. The
    installer creates the admin, and from that moment authentication is on.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config

VERSION = 1
ROLES = ("admin", "user")
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
MIN_PASSWORD = 8

_LOCK = threading.RLock()
_CACHE: dict = {"mtime": None, "data": None}

# Everything an account is allowed to do. `see_all` is the one that decides
# whether the scan library shows only your own runs or everybody's.
DEFAULT_LIMITS = {
    "daily_scans": config.AUTH_DEFAULT_DAILY_SCANS,
    "concurrent": config.AUTH_DEFAULT_CONCURRENT,
    "see_all": False,
    "portscan": True,
    "tor": True,
    "wayback": True,
    "deep": True,
    "delete": False,        # may remove scans from the library
}
ADMIN_LIMITS = {**DEFAULT_LIMITS, "daily_scans": 0, "concurrent": 0,
                "see_all": True, "delete": True}


class AuthError(Exception):
    """A refusal a human should read: bad credentials, quota, permission."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# --------------------------------------------------------------------------- #
# Store I/O
# --------------------------------------------------------------------------- #
def _blank() -> dict:
    return {"version": VERSION, "secret": secrets.token_urlsafe(48),
            "created_at": _now_iso(), "users": {}}


def _read() -> dict | None:
    """The account store, or None when it does not exist yet. Cached on mtime so
    the per-request auth check is not a file parse."""
    path = config.KEY_FILE
    try:
        st = path.stat()
    except OSError:
        _CACHE.update(mtime=None, data=None)
        return None
    if _CACHE["data"] is not None and _CACHE["mtime"] == st.st_mtime_ns:
        return _CACHE["data"]
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return _CACHE["data"]          # keep serving the last good copy
    if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
        return None
    _CACHE.update(mtime=st.st_mtime_ns, data=data)
    return data


def _write(data: dict) -> None:
    """Atomic, 0600. A half-written account store would lock everyone out, so it
    is built beside the real file and renamed over it."""
    path = config.KEY_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + f".tmp{os.getpid()}")
    payload = json.dumps(data, indent=2, ensure_ascii=False)
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(str(tmp), str(path))
        os.chmod(str(path), 0o600)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
    try:
        _CACHE.update(mtime=path.stat().st_mtime_ns, data=data)
    except OSError:
        _CACHE.update(mtime=None, data=None)


def configured() -> bool:
    """Is authentication in force? True once key.json holds at least one admin."""
    data = _read()
    if not data:
        return False
    return any(u.get("role") == "admin" for u in data["users"].values())


def store_path() -> Path:
    return config.KEY_FILE


# --------------------------------------------------------------------------- #
# Password hashing
# --------------------------------------------------------------------------- #
def _hash_password(password: str, salt: bytes, rounds: int) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return base64.b64encode(dk).decode()


def _set_password_fields(rec: dict, password: str) -> None:
    if len(password or "") < MIN_PASSWORD:
        raise AuthError(f"password must be at least {MIN_PASSWORD} characters")
    salt = secrets.token_bytes(16)
    rounds = config.AUTH_HASH_ROUNDS
    rec["salt"] = base64.b64encode(salt).decode()
    rec["rounds"] = rounds
    rec["hash"] = _hash_password(password, salt, rounds)
    rec["pwv"] = int(rec.get("pwv", 0)) + 1      # invalidates issued tokens


def _password_ok(rec: dict, password: str) -> bool:
    try:
        salt = base64.b64decode(rec.get("salt", ""))
        rounds = int(rec.get("rounds") or config.AUTH_HASH_ROUNDS)
    except Exception:
        return False
    if not salt or not rec.get("hash"):
        return False
    candidate = _hash_password(password or "", salt, rounds)
    return hmac.compare_digest(candidate, rec["hash"])


# --------------------------------------------------------------------------- #
# Tokens (HS256 JWT, no third-party dependency)
# --------------------------------------------------------------------------- #
def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64u_dec(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _sign(secret: str, signing_input: bytes) -> str:
    return _b64u(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())


def issue_token(username: str, *, ttl: int | None = None) -> tuple[str, str, int]:
    """Sign a session token for `username`. Returns (token, csrf, expires_at).

    The CSRF value is part of the signed payload, so a state-changing request has
    to echo a value only a holder of the token could know · a cross-site form
    post carrying just the cookie cannot produce it.
    """
    with _LOCK:
        data = _read()
        if not data:
            raise AuthError("no account store")
        rec = data["users"].get(username)
        if not rec:
            raise AuthError("unknown account")
        secret = data["secret"]
        pwv = int(rec.get("pwv", 1))
        role = rec.get("role", "user")
    now = int(time.time())
    exp = now + int(ttl or config.AUTH_TOKEN_TTL)
    header = {"alg": "HS256", "typ": "JWT"}
    csrf = secrets.token_urlsafe(24)
    payload = {"sub": username, "role": role, "pwv": pwv, "csrf": csrf,
               "iat": now, "exp": exp, "jti": secrets.token_urlsafe(8)}
    seg = (_b64u(json.dumps(header, separators=(",", ":")).encode()) + "."
           + _b64u(json.dumps(payload, separators=(",", ":")).encode()))
    return f"{seg}.{_sign(secret, seg.encode())}", csrf, exp


def verify_token(token: str) -> dict | None:
    """Claims for a valid, unexpired token whose account still exists, is still
    enabled, and has not changed its password since. None otherwise."""
    if not token or token.count(".") != 2:
        return None
    seg, _, sig = token.rpartition(".")
    data = _read()
    if not data:
        return None
    expected = _sign(data["secret"], seg.encode())
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(_b64u_dec(seg.split(".", 1)[1]))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    if int(payload.get("exp", 0)) <= time.time():
        return None
    rec = data["users"].get(payload.get("sub"))
    if not rec or not rec.get("enabled", True):
        return None
    if int(rec.get("pwv", 1)) != int(payload.get("pwv", -1)):
        return None
    # role is read from the store, never trusted from the token: a demotion
    # must take effect immediately, not when the token happens to expire.
    payload["role"] = rec.get("role", "user")
    payload["limits"] = effective_limits(rec)
    return payload


# --------------------------------------------------------------------------- #
# Accounts
# --------------------------------------------------------------------------- #
def effective_limits(rec: dict) -> dict:
    base = dict(ADMIN_LIMITS if rec.get("role") == "admin" else DEFAULT_LIMITS)
    base.update({k: v for k, v in (rec.get("limits") or {}).items() if k in base})
    if rec.get("role") == "admin":
        base.update(see_all=True, delete=True, daily_scans=0, concurrent=0)
    return base


def _public(name: str, rec: dict) -> dict:
    """An account as the admin page sees it · never the salt or the hash."""
    usage = rec.get("usage") or {}
    return {
        "username": name,
        "role": rec.get("role", "user"),
        "enabled": bool(rec.get("enabled", True)),
        "limits": effective_limits(rec),
        "created_at": rec.get("created_at"),
        "created_by": rec.get("created_by"),
        "last_login": rec.get("last_login"),
        "scans_today": int(usage.get("scans", 0)) if usage.get("day") == _today() else 0,
        "locked": bool(rec.get("locked_until", 0) > time.time()),
        "total_scans": int(rec.get("total_scans", 0)),
        "credits": max(0, int(rec.get("credits", 0))),
    }


def list_users() -> list[dict]:
    data = _read()
    if not data:
        return []
    return sorted((_public(n, r) for n, r in data["users"].items()),
                  key=lambda u: (u["role"] != "admin", u["username"]))


def get_user(username: str) -> dict | None:
    data = _read()
    if not data:
        return None
    rec = data["users"].get(username)
    return _public(username, rec) if rec else None


def _validate_name(username: str) -> str:
    username = (username or "").strip().lower()
    if not USERNAME_RE.match(username):
        raise AuthError("username must be 3-32 characters: letters, digits, "
                        "dot, dash or underscore, starting with a letter or digit")
    return username


def bootstrap(username: str, password: str) -> dict:
    """Create the very first admin. Refuses if an admin already exists, so this
    can never be used to mint a second one from outside."""
    with _LOCK:
        data = _read()
        if data and any(u.get("role") == "admin" for u in data["users"].values()):
            raise AuthError("an administrator already exists")
        data = data or _blank()
        data.setdefault("secret", secrets.token_urlsafe(48))
        name = _validate_name(username)
        rec = {"role": "admin", "enabled": True, "pwv": 0,
               "limits": dict(ADMIN_LIMITS), "usage": {"day": _today(), "scans": 0},
               "created_at": _now_iso(), "created_by": "install", "failures": 0,
               "locked_until": 0, "total_scans": 0}
        _set_password_fields(rec, password)
        data["users"][name] = rec
        _write(data)
        return _public(name, rec)


def create_user(username: str, password: str, *, role: str = "user",
                limits: dict | None = None, by: str = "admin") -> dict:
    with _LOCK:
        data = _read()
        if not data:
            raise AuthError("no account store · run ./install.sh first")
        name = _validate_name(username)
        if name in data["users"]:
            raise AuthError(f"'{name}' already exists")
        if role not in ROLES:
            raise AuthError("role must be admin or user")
        rec = {"role": role, "enabled": True, "pwv": 0,
               "limits": _clean_limits(limits, role),
               "usage": {"day": _today(), "scans": 0},
               "created_at": _now_iso(), "created_by": by, "failures": 0,
               "locked_until": 0, "total_scans": 0}
        _set_password_fields(rec, password)
        data["users"][name] = rec
        _write(data)
        return _public(name, rec)


def _clean_limits(limits: dict | None, role: str) -> dict:
    base = dict(ADMIN_LIMITS if role == "admin" else DEFAULT_LIMITS)
    for key, val in (limits or {}).items():
        if key not in base:
            continue
        if key in ("daily_scans", "concurrent"):
            try:
                base[key] = max(0, min(10000, int(val)))
            except (TypeError, ValueError):
                pass
        else:
            base[key] = bool(val)
    return base


def update_user(username: str, *, role: str | None = None,
                enabled: bool | None = None, limits: dict | None = None,
                unlock: bool = False) -> dict:
    with _LOCK:
        data = _read()
        if not data:
            raise AuthError("no account store")
        rec = data["users"].get(username)
        if not rec:
            raise AuthError("unknown account")
        if role is not None:
            if role not in ROLES:
                raise AuthError("role must be admin or user")
            if rec.get("role") == "admin" and role != "admin" \
                    and _admin_count(data) <= 1:
                raise AuthError("this is the only administrator · promote "
                                "someone else before changing this one")
            rec["role"] = role
        if enabled is not None:
            if not enabled and rec.get("role") == "admin" and _admin_count(data) <= 1:
                raise AuthError("cannot disable the only administrator")
            rec["enabled"] = bool(enabled)
            if not enabled:
                rec["pwv"] = int(rec.get("pwv", 0)) + 1   # cut live sessions
        if limits is not None:
            rec["limits"] = _clean_limits({**(rec.get("limits") or {}), **limits},
                                          rec.get("role", "user"))
        if unlock:
            rec["failures"] = 0
            rec["locked_until"] = 0
        _write(data)
        return _public(username, rec)


def _admin_count(data: dict) -> int:
    return sum(1 for u in data["users"].values()
               if u.get("role") == "admin" and u.get("enabled", True))


def set_password(username: str, new_password: str, *,
                 current_password: str | None = None) -> dict:
    """Change a password. `current_password` is required when a user changes
    their own · an admin resetting someone else's does not need it."""
    with _LOCK:
        data = _read()
        if not data:
            raise AuthError("no account store")
        rec = data["users"].get(username)
        if not rec:
            raise AuthError("unknown account")
        if current_password is not None and not _password_ok(rec, current_password):
            raise AuthError("current password is not correct")
        _set_password_fields(rec, new_password)
        rec["failures"] = 0
        rec["locked_until"] = 0
        _write(data)
        return _public(username, rec)


def delete_user(username: str) -> None:
    with _LOCK:
        data = _read()
        if not data:
            raise AuthError("no account store")
        rec = data["users"].get(username)
        if not rec:
            raise AuthError("unknown account")
        if rec.get("role") == "admin" and _admin_count(data) <= 1:
            raise AuthError("cannot delete the only administrator")
        del data["users"][username]
        _write(data)


# --------------------------------------------------------------------------- #
# Sign-in
# --------------------------------------------------------------------------- #
def verify(username: str, password: str) -> dict:
    """Check credentials. Returns the public account on success; raises AuthError
    with a message safe to show otherwise.

    The failure path deliberately spends the same PBKDF2 work whether or not the
    account exists, so response time does not reveal which usernames are real.
    """
    username = (username or "").strip().lower()
    with _LOCK:
        data = _read()
        if not data:
            raise AuthError("authentication is not configured on this dashboard")
        rec = data["users"].get(username)
        if rec is None:
            # burn equivalent work against a throwaway salt
            _hash_password(password or "", b"decoy-salt-16byte", config.AUTH_HASH_ROUNDS)
            raise AuthError("incorrect username or password")
        now = time.time()
        if rec.get("locked_until", 0) > now:
            wait = int(rec["locked_until"] - now)
            raise AuthError(f"too many failed attempts · try again in "
                            f"{max(1, wait // 60)} minute(s)")
        if not rec.get("enabled", True):
            raise AuthError("this account is disabled")
        if not _password_ok(rec, password):
            rec["failures"] = int(rec.get("failures", 0)) + 1
            if rec["failures"] >= config.AUTH_MAX_FAILURES:
                rec["locked_until"] = now + config.AUTH_LOCKOUT_SEC
                rec["failures"] = 0
            _write(data)
            raise AuthError("incorrect username or password")
        rec["failures"] = 0
        rec["locked_until"] = 0
        rec["last_login"] = _now_iso()
        _write(data)
        return _public(username, rec)


# --------------------------------------------------------------------------- #
# Scan allowance
# --------------------------------------------------------------------------- #
def quota(username: str) -> dict:
    """Where this account stands against its allowance right now."""
    data = _read()
    rec = (data or {}).get("users", {}).get(username) if data else None
    if not rec:
        return {"daily_scans": 0, "used": 0, "remaining": None, "concurrent": 0}
    limits = effective_limits(rec)
    usage = rec.get("usage") or {}
    used = int(usage.get("scans", 0)) if usage.get("day") == _today() else 0
    cap = int(limits.get("daily_scans", 0))
    # Bonus scan credits an admin has granted · usable beyond the daily cap.
    credits = max(0, int(rec.get("credits", 0)))
    return {"daily_scans": cap, "used": used, "credits": credits,
            "remaining": None if cap == 0 else max(0, cap - used) + credits,
            "concurrent": int(limits.get("concurrent", 0))}


def check_scan_allowed(username: str, *, running: int = 0,
                       options: dict | None = None) -> None:
    """Raise AuthError if this account may not start the scan it is asking for.
    `running` is how many of its scans are already in flight."""
    data = _read()
    rec = (data or {}).get("users", {}).get(username) if data else None
    if not rec:
        raise AuthError("unknown account")
    limits = effective_limits(rec)
    q = quota(username)
    if q["daily_scans"] and q["remaining"] == 0:
        raise AuthError(f"daily scan limit reached ({q['daily_scans']} per day) · "
                        "ask an administrator to raise it")
    if limits.get("concurrent") and running >= int(limits["concurrent"]):
        raise AuthError(f"you already have {running} scan(s) running · your "
                        f"limit is {limits['concurrent']} at a time")
    for opt, label in (("portscan", "port scan"), ("tor", "Tor routing"),
                       ("wayback", "web archive mining"), ("deep", "deep DNS"),
                       ("xss", "XSS testing"), ("sqli", "SQL injection testing"),
                       ("nuclei", "Nuclei scanning")):
        if (options or {}).get(opt) and not limits.get(opt, True):
            raise AuthError(f"{label} is not enabled for your account")


def record_scan(username: str) -> None:
    """Count one started scan against today's allowance. Best-effort."""
    with _LOCK:
        data = _read()
        if not data:
            return
        rec = data["users"].get(username)
        if not rec:
            return
        usage = rec.get("usage") or {}
        if usage.get("day") != _today():
            usage = {"day": _today(), "scans": 0}
        usage["scans"] = int(usage.get("scans", 0)) + 1
        rec["usage"] = usage
        rec["total_scans"] = int(rec.get("total_scans", 0)) + 1
        # A scan past the daily cap spends one bonus credit, if any remain.
        cap = int(effective_limits(rec).get("daily_scans", 0))
        if cap and usage["scans"] > cap and int(rec.get("credits", 0)) > 0:
            rec["credits"] = int(rec["credits"]) - 1
        try:
            _write(data)
        except Exception:
            pass


def grant_credits(username: str, amount: int) -> dict:
    """Give (or, with a negative amount, remove) bonus scan credits · scans an
    account may run beyond its daily cap. Returns the account's updated quota."""
    try:
        amount = int(amount)
    except (TypeError, ValueError):
        raise AuthError("credits must be a whole number")
    with _LOCK:
        data = _read()
        rec = (data or {}).get("users", {}).get(username) if data else None
        if not rec:
            raise AuthError("unknown account")
        rec["credits"] = max(0, int(rec.get("credits", 0)) + amount)
        try:
            _write(data)
        except Exception:
            pass
    return quota(username)


def may_see(claims: dict | None, owner: str | None) -> bool:
    """Can this session see a scan owned by `owner`? Admins and accounts with
    `see_all` see everything; everyone else sees only their own runs. A scan from
    before accounts existed has no owner and is treated as the estate's, so it
    stays visible to whoever can see everything."""
    if not claims:
        return True                       # auth not configured
    limits = claims.get("limits") or {}
    if claims.get("role") == "admin" or limits.get("see_all"):
        return True
    return bool(owner) and owner == claims.get("sub")
