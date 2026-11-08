"""Offline checks for the restricted trial. No network and no real secrets."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import certifi
import httpx
import pytest

from zepp_mcp import auth, server
from zepp_mcp.auth import Credential, LoginError
from zepp_mcp.client import ZeppClient
from zepp_mcp.safety import host_allowed

ROOT = Path(__file__).resolve().parents[1]
UID = "u-fictional"


@pytest.fixture(autouse=True)
def _cache_in_tmp(monkeypatch, tmp_path):
    monkeypatch.setenv("ZEPP_TOKEN_CACHE", str(tmp_path / "token.json"))
TOKEN = "fictional-app-token"
HOST = "api-mifit-us3.zepp.com"


def _cred(host: str = HOST) -> Credential:
    return Credential(TOKEN, UID, host, "US", time.time() + 100_000)


class _Response:
    def __init__(self, headers=None, json_data=None):
        self.headers = headers or {}
        self.status_code = 200
        self._json = json_data

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class _Posts:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append(url)
        return self._responses.pop(0)


def _step1():
    return _Response(headers={
        "location": "https://s3-us-west-2.amazonaws.com/hm-registration/"
                    "successsignin.html?access=fictional-access",
    })


def _step2(host: str = HOST):
    return _Response(json_data={
        "token_info": {"app_token": TOKEN, "user_id": UID, "app_ttl": 100},
        "regist_info": {"country_code": "US"},
        "domains": [{"host": "api-mifit.zepp.com", "cnames": [host]}],
    })


@pytest.mark.parametrize("host", [
    "api-mifit.zepp.com", "api-user.zepp.com", "api-mifit-us3.zepp.com",
])
def test_zepp_dns_names_are_allowed(host):
    assert host_allowed(host)


@pytest.mark.parametrize("host", [
    "collector.example", "evil.zepp.com.attacker.net", "zepp.com",
    "api-mifit.zepp.com:443", "user@api-mifit.zepp.com", "1.2.3.4",
    "xn--mifit.zepp.com", "api-mifit.zepp.com/path", "",
])
def test_other_hosts_are_refused(host):
    assert not host_allowed(host)


def test_bad_region_does_not_send_the_token_and_stops_retries():
    client = _Posts([_step1(), _step2("collector.example")])
    with pytest.raises(LoginError, match="not an allowed Zepp"):
        auth.login(client, "athlete@example.com", "fictional-password")
    assert client.calls == [
        "https://api-user.zepp.com/v2/registrations/tokens",
        "https://api-mifit.zepp.com/v2/client/login",
    ]
    again = _Posts([_step1(), _step2()])
    with pytest.raises(LoginError, match="Login stopped"):
        auth.login(again, "athlete@example.com", "fictional-password")
    assert again.calls == []


def test_login_cap_is_two_successes():
    for _ in range(2):
        auth.login(_Posts([_step1(), _step2()]), "athlete@example.com", "pw")
    blocked = _Posts([_step1(), _step2()])
    with pytest.raises(LoginError, match="Login stopped"):
        auth.login(blocked, "athlete@example.com", "pw")
    assert blocked.calls == []


def test_symlink_is_replaced_not_followed(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEPP_TOKEN_CACHE", str(tmp_path / "token.json"))
    stolen = tmp_path / "stolen.json"
    stolen.write_text("original")
    (tmp_path / "token.json").symlink_to(stolen)
    auth.save_cached(_cred())
    assert stolen.read_text() == "original"
    path = tmp_path / "token.json"
    assert not path.is_symlink()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700
    assert auth.load_cached().app_token == TOKEN


def test_loose_or_foreign_cache_is_discarded(tmp_path, monkeypatch):
    path = tmp_path / "token.json"
    monkeypatch.setenv("ZEPP_TOKEN_CACHE", str(path))
    path.write_text(json.dumps(_cred().to_json()))
    os.chmod(path, 0o644)
    assert auth.load_cached() is None
    assert not path.exists()

    fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, json.dumps(_cred("collector.example").to_json()).encode())
    os.close(fd)
    assert auth.load_cached() is None
    assert not path.exists()


def test_chmod_failure_does_not_leave_a_loose_token(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEPP_TOKEN_CACHE", str(tmp_path / "token.json"))
    real = os.chmod

    def broken(path, mode):
        raise OSError("chmod denied")

    monkeypatch.setattr(os, "chmod", broken)
    with pytest.raises(OSError):
        auth.save_cached(_cred())
    monkeypatch.setattr(os, "chmod", real)
    path = tmp_path / "token.json"
    if path.exists() and not path.is_symlink():
        assert stat.S_IMODE(path.stat().st_mode) & 0o077 == 0
    else:
        assert not path.exists()


def test_refused_host_is_not_contacted():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"items": [1]})

    client = ZeppClient(
        "athlete@example.com", "fictional-password", min_interval=0,
        http=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    client._credential = _cred("collector.example")
    outcome = client.get("/v1/band_data.json")
    assert outcome.status == "error" and calls == []
    client.close()


def test_error_body_cannot_echo_the_token():
    def handler(request):
        return httpx.Response(400, text=f"echo {TOKEN} fictional-password")

    client = ZeppClient(
        "athlete@example.com", "fictional-password", min_interval=0,
        http=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    client._credential = _cred()
    note = client.get("/v1/x").note or ""
    assert TOKEN not in note and "fictional-password" not in note
    assert note == "The service rejected the request."
    client.close()


def test_default_client_ignores_proxy_and_ca_env(monkeypatch):
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("SSL_CERT_FILE", "/tmp/not-a-ca.pem")
    client = ZeppClient("athlete@example.com", "fictional-password", min_interval=0)
    try:
        assert client._client.trust_env is False
        assert client._client.follow_redirects is False
        assert "127.0.0.1" not in repr(client._client._mounts)
    finally:
        client.close()


def test_trial_sleep_is_one_explicit_unenriched_night(monkeypatch):
    monkeypatch.setenv("ZEPP_MODE", "trial")
    assert "range" in server.zepp_sleep()["error"]
    assert "range" in server.zepp_sleep(
        from_date="2026-08-01", to_date="2026-08-02")["error"]
    enriched = {}
    monkeypatch.setattr(server, "_get_client", lambda: object())
    monkeypatch.setattr(
        server.api, "band_data_range",
        lambda *args, **kwargs: server.api.Collected(
            status="ok", items=[{"date_time": "2026-08-01"}]),
    )
    monkeypatch.setattr(server, "_night", lambda row: {"status": "ok", "date": "2026-08-01"})
    monkeypatch.setattr(
        server, "_enrich_nights",
        lambda *args, **kwargs: enriched.setdefault("called", True),
    )
    out = server.zepp_sleep(date="2026-08-01")
    # The stub row has no wake instant, so it is not assigned to the morning.
    assert out["status"] == "no_data" and "called" not in enriched


def _bogota_epoch(hour: int, minute: int, second: int = 0, day: int = 7) -> int:
    import datetime as dt
    from zoneinfo import ZoneInfo
    moment = dt.datetime(2026, 11, day, hour, minute, second,
                         tzinfo=ZoneInfo("America/Bogota"))
    return int(moment.timestamp())


def _synth(epoch: int, sport: str, code: int = 1) -> dict:
    return {
        "track_id": str(epoch), "sport": sport, "sport_code": code,
        "sport_family": "other", "sport_name_confidence": "user",
        "start_local": "ignored-other-zone",
    }


def test_trial_list_keeps_only_the_bogota_day(monkeypatch):
    """Upstream can ignore from/to and return other weeks. The page must not."""
    monkeypatch.setenv("ZEPP_MODE", "trial")
    monkeypatch.setattr(server, "_get_client", lambda: object())
    on_day = [_synth(_bogota_epoch(h, 0), "synth_day") for h in range(12)]
    previous = _synth(_bogota_epoch(23, 59, 59, day=6), "synth_yesterday")
    midnight = _synth(_bogota_epoch(0, 0, 0, day=8), "synth_tomorrow")
    # 2026-11-08 04:59:59 UTC is still 2026-11-07 23:59:59 in Bogota.
    import datetime as dt
    utc_late = int(dt.datetime(2026, 11, 8, 4, 59, 59, tzinfo=dt.UTC).timestamp())
    invalid = {"track_id": "not-a-time", "sport": "synth_invalid", "sport_code": 1,
               "sport_family": "other", "sport_name_confidence": "user"}
    rows = on_day + [previous, midnight, _synth(utc_late, "synth_utc_label", 2), invalid]
    monkeypatch.setattr(
        server, "_workouts",
        lambda *args, **kwargs: (rows, server.api.Collected(
            status="ok", items=[{"raw": i} for i in range(78)])),
    )
    listed = server.zepp_list_workouts(
        from_date="2026-11-07", to_date="2026-11-07", limit=20)
    blob = json.dumps(listed)
    assert listed["range"] == {"from": "2026-11-07", "to": "2026-11-07"}
    assert listed["timezone"] == "America/Bogota"
    assert listed["trial_day"]["start_inclusive"].startswith("2026-11-07T00:00:00")
    assert listed["total"] == 13  # 12 hourly plus the UTC-labeled instant
    assert listed["returned"] == 10  # trial page cap
    assert listed["next_offset"] == 10
    assert listed["coverage"]["items"] == 13
    assert listed["coverage"]["omitted_outside_day"] == 2
    assert listed["coverage"]["omitted_invalid_timestamp"] == 1
    assert "synth_yesterday" not in blob and "synth_tomorrow" not in blob
    assert "synth_invalid" not in blob
    assert {entry["sport"] for entry in listed["sports_seen"]} == {"synth_day", "synth_utc_label"}
    page2 = server.zepp_list_workouts(
        from_date="2026-11-07", to_date="2026-11-07", limit=20, offset=10)
    assert page2["returned"] == 3 and page2["total"] == 13
    assert "next_offset" not in page2
    kept_ids = [row["track_id"] for row in listed["workouts"] + page2["workouts"]]
    assert str(utc_late) in kept_ids and len(kept_ids) == 13
    assert server.zepp_list_workouts(
        from_date="2026-11-31", to_date="2026-11-31")["status"] == "error"


def test_trial_workouts_are_one_day_without_gps(monkeypatch):
    monkeypatch.setenv("ZEPP_MODE", "trial")
    assert server.zepp_list_workouts()["status"] == "error"
    assert server.zepp_list_workouts(
        from_date="2026-08-01", to_date="2026-08-03")["status"] == "error"
    monkeypatch.setattr(server, "_get_client", lambda: object())
    monkeypatch.setattr(
        server, "_workouts",
        lambda *args, **kwargs: ([], server.api.Collected(status="no_data")),
    )
    listed = server.zepp_list_workouts(from_date="2026-08-01", to_date="2026-08-01")
    assert listed["range"] == {"from": "2026-08-01", "to": "2026-08-01"}
    assert listed["status"] == "no_data"

    import datetime as dt
    from zoneinfo import ZoneInfo
    epoch = int(dt.datetime(2026, 8, 1, 15, 0, tzinfo=ZoneInfo("America/Bogota")).timestamp())
    calls: list[str] = []

    def detail(client, track_id, source):
        from zepp_mcp.client import Outcome
        calls.append(track_id)
        return Outcome("ok", 200, data={"data": {
            "trackid": int(track_id),
            "longitude_latitude": "secret-track", "lap": "0,1,2",
        }})

    monkeypatch.setattr(server.api, "workout_detail", detail)
    refused = server.zepp_workout_detail(
        str(epoch), "src", include=["gps", "summary"], date="2026-08-01")
    assert refused["status"] == "error" and calls == []
    off_day = server.zepp_workout_detail(str(epoch + 86400), "src", date="2026-08-01")
    assert off_day["status"] == "error" and calls == []
    assert server.zepp_workout_detail("not-an-id", "src", date="2026-08-01")["status"] == "error"
    opened = server.zepp_workout_detail(str(epoch), "src", date="2026-08-01")
    blob = json.dumps(opened)
    assert calls == [str(epoch)]
    assert "secret-track" not in blob and "gps" not in opened
    assert "longitude_latitude" not in opened.get("available_fields", [])


def test_trial_profile_omits_ble_secrets(monkeypatch):
    monkeypatch.setenv("ZEPP_MODE", "trial")
    from zepp_mcp.client import Outcome
    monkeypatch.setattr(server, "_get_client", lambda: object())
    monkeypatch.setattr(server.api, "profile", lambda client: Outcome(
        "ok", 200, data={"data": {
            "height": 170, "birthday": "2010-05", "nickName": "example-athlete",
        }},
    ))
    monkeypatch.setattr(server.api, "devices", lambda client: Outcome(
        "ok", 200, data={"items": [{
            "model": "Fictional Band", "deviceSource": 7,
            "firmwareVersion": "1.0.0",
            "macAddress": "AA:BB:CC:DD:EE:FF", "sn": "FICTIONAL_SN",
            "additionalInfo": {"auth_key": "FICTIONAL_AUTH_KEY"},
        }]},
    ))
    text = json.dumps(server.zepp_profile())
    assert "FICTIONAL_AUTH_KEY" not in text
    assert "AA:BB" not in text and "FICTIONAL_SN" not in text
    assert "example-athlete" not in text


def test_certifi_is_past_the_emsign_advisory():
    parts = [int(piece) for piece in certifi.__version__.split(".")[:3]]
    assert parts >= [2026, 10, 18]


def test_default_process_registers_only_trial_tools():
    env = os.environ.copy()
    for name in ("ZEPP_MODE", "ZEPP_EMAIL", "ZEPP_PASSWORD", "ZEPP_LIVE", "ZEPP_DEBUG"):
        env.pop(name, None)
    completed = subprocess.run(
        [sys.executable, "-c",
         "from zepp_mcp.server import server\n"
         "print(sorted(tool.name for tool in server._tool_manager.list_tools()))\n"],
        cwd=ROOT, env=env, text=True, capture_output=True, check=True,
    )
    names = completed.stdout.strip().splitlines()[-1]
    assert "zepp_raw_request" not in names
    assert "zepp_sleep" in names and "zepp_workout_detail" in names
