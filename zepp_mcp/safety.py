"""Fail-closed limits for the local reading trial.

No new Zepp endpoints and no change to the existing login identity. The
trial process exposes five tools, one explicit calendar day, and only DNS
names under zepp.com.
"""

from __future__ import annotations

import datetime as dt
import os
import stat
from pathlib import Path
from zoneinfo import ZoneInfo

# One successful login plus one 401 refresh. A failure stops the process
# before it can walk Zepp's shared 10-attempt lockout.
_MAX_LOGIN_ATTEMPTS = 2
_login_attempts = 0
_login_blocked = False

TRIAL_TOOLS = frozenset({
    "zepp_auth_status",
    "zepp_profile",
    "zepp_sleep",
    "zepp_list_workouts",
    "zepp_workout_detail",
})

_GPS_FIELDS = frozenset({
    "longitude_latitude", "altitude", "accuracy", "DEMAltitude",
})

# Trial days are America/Bogota calendar dates. Colombia has no DST.
TRIAL_TIMEZONE = "America/Bogota"
_EPOCH_MIN = 946684800    # 2000-01-01 UTC
_EPOCH_MAX = 4102444800   # 2100-01-01 UTC


def trial_timezone() -> dt.tzinfo:
    return ZoneInfo(TRIAL_TIMEZONE)


def track_epoch(value: object) -> int | None:
    """Start epoch from a history track id. None means do not emit the row."""
    if isinstance(value, bool) or value is None:
        return None
    try:
        seconds = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    if seconds < _EPOCH_MIN or seconds >= _EPOCH_MAX:
        return None
    return seconds


def on_trial_day(epoch: int, day: str) -> bool:
    """True when `epoch` falls on `day` from local midnight inclusive."""
    try:
        local = dt.datetime.fromtimestamp(epoch, trial_timezone())
    except (OverflowError, OSError, ValueError):
        return False
    return local.date().isoformat() == day


def service_error_note(http_status: int, error_kind: str | None) -> str:
    """Fixed text for a failed call. No upstream body, id, or exception text."""
    if error_kind == "network":
        return "The request could not reach the service."
    if http_status == 401 or error_kind == "unauthorized":
        return "The service refused the credentials."
    if http_status == 400 or error_kind == "bad_request":
        return "The service rejected the request."
    if http_status == 403 or error_kind == "forbidden":
        return "The service refused access."
    if http_status == 404 or error_kind == "not_found":
        return "The service has no such route."
    if http_status == 429 or error_kind == "rate_limited":
        return "The service is rate limiting this client."
    if http_status >= 500 or error_kind == "server_error":
        return "The service failed to answer."
    return "The service returned an error."


def sleep_instants(row: dict) -> tuple[int | None, int | None]:
    """Onset and wake epochs from a band row, in seconds. Unknown stays None."""
    from .decode import decode_band_summary

    summary = decode_band_summary(row.get("summary") or "")
    sleep = summary.get("slp") if isinstance(summary, dict) else None
    if not isinstance(sleep, dict):
        return None, None
    return track_epoch(sleep.get("st")), track_epoch(sleep.get("ed"))


def select_trial_day(
    items: list[dict], day: str,
) -> tuple[list[dict], int, int]:
    """Keep workouts whose start is on `day`. Drop the rest.

    Returns (kept, omitted_outside_day, omitted_invalid_timestamp). Invalid
    starts are not treated as in-range.
    """
    kept: list[dict] = []
    outside = 0
    invalid = 0
    for item in items:
        epoch = track_epoch(item.get("track_id"))
        if epoch is None:
            invalid += 1
            continue
        if on_trial_day(epoch, day):
            kept.append(item)
        else:
            outside += 1
    return kept, outside, invalid


class LoginStopped(RuntimeError):
    """Further password logins must not reach the network."""


def trial_enabled() -> bool:
    """Unset ZEPP_MODE is the trial. full/off/unrestricted is the old server."""
    mode = os.environ.get("ZEPP_MODE", "trial").strip().lower()
    return mode not in {"full", "off", "unrestricted"}


def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def host_allowed(host: str) -> bool:
    """True only for a plain DNS name under zepp.com.

    Rejects IPs, ports, userinfo, paths, whitespace, non-ASCII and punycode.
    TLS verify still has to accept the certificate; this stops a cached or
    login-supplied host from receiving the app token.
    """
    if not isinstance(host, str):
        return False
    name = normalize_host(host)
    if not name or len(name) > 253 or ".." in name:
        return False
    if any(ord(char) > 127 or not (char.isalnum() or char in ".-") for char in name):
        return False
    if not name.endswith(".zepp.com"):
        return False
    labels = name.split(".")
    if len(labels) < 3:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-") or label.startswith("xn--"):
            return False
    return True


def claim_login_attempt() -> None:
    global _login_attempts, _login_blocked
    if _login_blocked or _login_attempts >= _MAX_LOGIN_ATTEMPTS:
        _login_blocked = True
        raise LoginStopped(
            "Login stopped for this process. Restart only after checking "
            "the credentials; automatic retries are not performed."
        )
    _login_attempts += 1


def block_further_logins() -> None:
    global _login_blocked
    _login_blocked = True


def reset_login_guard() -> None:
    """Test hook. Production code does not call this."""
    global _login_attempts, _login_blocked
    _login_attempts = 0
    _login_blocked = False


def redact(text: str, *secrets: str) -> str:
    out = text
    for secret in secrets:
        if secret:
            out = out.replace(secret, "[redacted]")
    return out


def write_private_text(path: Path, text: str) -> None:
    """Write `text` as a private file. Fail closed: no symlink, no loose mode.

    The parent directory is mode 0700 and the file is mode 0600, replaced
    atomically. A chmod or mode check failure deletes the file and raises.
    """
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink():
        raise OSError("refusing to write through a symlinked directory")
    os.chmod(parent, 0o700)
    if stat.S_IMODE(parent.stat().st_mode) & 0o077:
        raise OSError("token directory is not private")
    if path.is_symlink():
        path.unlink()

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    tmp = parent / f".{path.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
    fd = os.open(tmp, flags, 0o600)
    try:
        os.write(fd, text.encode())
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        tmp.unlink(missing_ok=True)
        raise
    os.close(fd)
    try:
        os.replace(tmp, path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    if path.is_symlink():
        path.unlink(missing_ok=True)
        raise OSError("refusing to leave a symlink in place of the token")
    os.chmod(path, 0o600)
    if stat.S_IMODE(path.lstat().st_mode) & 0o077:
        path.unlink(missing_ok=True)
        raise OSError("token file is not private")


def drop_location_fields(result: dict) -> dict:
    """Remove GPS tracks from a workout-detail result. Splits stay."""
    result.pop("gps", None)
    result.pop("streams", None)
    fields = result.get("available_fields")
    if isinstance(fields, list):
        result["available_fields"] = [name for name in fields if name not in _GPS_FIELDS]
    return result
