"""Wake-morning sleep selection and error sanitization. Trial only, no network."""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from zepp_mcp import server
from zepp_mcp.auth import Credential
from zepp_mcp.client import ZeppClient

UTC = dt.timezone.utc
DAY = "2026-11-07"
MARKERS = (
    "hrv-marker", "spo2-marker", "gps-marker", "raw-marker",
    "faketoken-XYZ", "fakepass-XYZ", "uid-synth-99",
)
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _trial(monkeypatch, tmp_path):
    monkeypatch.setenv("ZEPP_MODE", "trial")
    monkeypatch.setenv("ZEPP_TOKEN_CACHE", str(tmp_path / "token.json"))
    monkeypatch.delenv("ZEPP_EMAIL", raising=False)
    monkeypatch.delenv("ZEPP_PASSWORD", raising=False)
    monkeypatch.delenv("ZEPP_DEBUG", raising=False)


def _ep(text: str) -> int:
    return int(dt.datetime.fromisoformat(text).timestamp())


def _night_row(start: str, end: str, *, score: int = 70) -> dict:
    st, ed = _ep(start), _ep(end)
    minutes = max((ed - st) // 60, 1)
    slp = {
        "st": st, "ed": ed, "lt": minutes, "dp": 0, "dt": 0, "wk": 0,
        "ss": score, "rhr": 48, "wc": 0,
        "stage": [{"start": 0, "stop": minutes - 1, "mode": 4}],
    }
    blob = base64.b64encode(json.dumps({"tz": -18000, "slp": slp}).encode()).decode()
    return {"date_time": "ignored", "summary": blob}


def _absent_row() -> dict:
    slp = {"st": 0, "ed": 0, "lt": 0, "dp": 0, "dt": 0, "wk": 0,
           "ss": 0, "rhr": 0, "wc": 0, "stage": []}
    blob = base64.b64encode(json.dumps({"tz": -18000, "slp": slp}).encode()).decode()
    return {"date_time": DAY, "summary": blob}


def _bind(monkeypatch, rows):
    calls = {"n": 0, "args": []}

    def band(client, start, end):
        calls["n"] += 1
        calls["args"].append((start, end))
        return server.api.Collected(status="ok", items=list(rows))

    monkeypatch.setattr(server, "_get_client", lambda: object())
    monkeypatch.setattr(server.api, "band_data_range", band)
    monkeypatch.setattr(
        server.api, "events_v2",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("enrich")),
    )
    return calls


def test_sleep_follows_wake_morning_not_row_order(monkeypatch):
    ends_on_day = _night_row("2026-11-07T03:30:00+00:00", "2026-11-07T11:10:00+00:00")
    ends_next = _night_row("2026-11-08T04:50:00+00:00", "2026-11-08T12:00:00+00:00")
    calls = _bind(monkeypatch, [ends_next, ends_on_day])
    out = server.zepp_sleep(date=DAY)
    assert calls["n"] == 1 and calls["args"] == [(DAY, DAY)]
    assert out["end_local"] == "2026-11-07T06:10-05:00"
    assert out["start_local"] == "2026-11-06T22:30-05:00"
    assert out.get("total_asleep_minutes")
    flipped = _bind(monkeypatch, [ends_on_day, ends_next])
    again = server.zepp_sleep(date=DAY)
    assert flipped["n"] == 1
    assert again["end_local"] == out["end_local"]


def test_two_wakes_same_morning_prefer_latest_then_earliest_onset(monkeypatch):
    early = _night_row("2026-11-07T02:00:00+00:00", "2026-11-07T11:00:00+00:00", score=11)
    late = _night_row("2026-11-07T04:00:00+00:00", "2026-11-07T13:00:00+00:00", score=22)
    _bind(monkeypatch, [early, late])
    assert server.zepp_sleep(date=DAY)["sleep_score"] == 22
    _bind(monkeypatch, [late, early])
    assert server.zepp_sleep(date=DAY)["sleep_score"] == 22
    same_end_early_start = _night_row(
        "2026-11-07T01:00:00+00:00", "2026-11-07T12:00:00+00:00", score=31)
    same_end_late_start = _night_row(
        "2026-11-07T03:00:00+00:00", "2026-11-07T12:00:00+00:00", score=32)
    _bind(monkeypatch, [same_end_late_start, same_end_early_start])
    assert server.zepp_sleep(date=DAY)["sleep_score"] == 31


def test_wake_boundaries_and_missing_are_not_zero(monkeypatch):
    before = _night_row("2026-11-06T20:00:00+00:00", "2026-11-07T04:59:59+00:00")
    at = _night_row("2026-11-07T01:00:00+00:00", "2026-11-07T05:00:00+00:00")
    after = _night_row("2026-11-07T20:00:00+00:00", "2026-11-08T05:00:00+00:00")
    _bind(monkeypatch, [before, after, _absent_row()])
    missed = server.zepp_sleep(date=DAY)
    assert missed["status"] == "no_data"
    assert missed.get("total_asleep_minutes") is None
    assert missed.get("sleep_score") is None
    _bind(monkeypatch, [before, at, after])
    chosen = server.zepp_sleep(date=DAY)
    assert chosen["end_local"] == "2026-11-07T00:00-05:00"


def test_week_and_enrich_do_not_add_calls(monkeypatch):
    calls = {"band": 0, "events": 0}

    def band(*_a, **_k):
        calls["band"] += 1
        return server.api.Collected(status="ok", items=[])

    def events(*_a, **_k):
        calls["events"] += 1
        return server.api.Collected(status="ok", items=[])

    monkeypatch.setattr(server, "_get_client", lambda: object())
    monkeypatch.setattr(server.api, "band_data_range", band)
    monkeypatch.setattr(server.api, "events_v2", events)
    week = server.zepp_sleep(from_date="2026-11-01", to_date="2026-11-08")
    assert week["status"] == "error" and calls == {"band": 0, "events": 0}
    server.zepp_sleep(date=DAY, enrich=True)
    assert calls == {"band": 1, "events": 0}


def _http(status, text):
    return lambda request: httpx.Response(status, text=text)


def test_error_bodies_and_exceptions_stay_out_of_the_result(tmp_path, monkeypatch):
    monkeypatch.setenv("ZEPP_TOKEN_CACHE", str(tmp_path / "token.json"))
    bodies = {
        400: "hrv-marker " + ("x" * 250) + " spo2-marker",
        401: json.dumps({"nested": {"gps": "gps-marker"}, "token": "faketoken-XYZ"}),
        403: "uid-synth-99",
        429: "raw-marker",
        500: "fakepass-XYZ",
    }
    for status, text in bodies.items():
        def handler(request, text=text, status=status):
            return httpx.Response(status, text=text)

        http = httpx.Client(transport=httpx.MockTransport(handler))
        client = ZeppClient("synth@example.com", "fakepass-XYZ", min_interval=0,
                            http=http, cache=False)
        client._credential = Credential(
            "faketoken-XYZ", "uid-synth-99", "api-mifit-us3.zepp.com", "US",
            dt.datetime.now(UTC).timestamp() + 10000,
        )
        note = client.get("/v1/data/band_data.json").as_dict().get("note") or ""
        blob = json.dumps(client.get("/v1/data/band_data.json").as_dict())
        for marker in MARKERS:
            assert marker not in note and marker not in blob
        client.close()

    def not_json(request):
        return httpx.Response(200, text="hrv-marker " + ("n" * 240) + " spo2-marker")

    http = httpx.Client(transport=httpx.MockTransport(not_json))
    client = ZeppClient("synth@example.com", "fakepass-XYZ", min_interval=0,
                        http=http, cache=False)
    client._credential = Credential(
        "faketoken-XYZ", "uid-synth-99", "api-mifit-us3.zepp.com", "US",
        dt.datetime.now(UTC).timestamp() + 10000,
    )
    payload = client.get("/v1/data/band_data.json").as_dict()
    assert payload["note"] == "The service response was not JSON."
    assert "hrv-marker" not in json.dumps(payload)
    client.close()

    def boom(request):
        raise httpx.ConnectError("hrv-marker faketoken-XYZ")

    http = httpx.Client(transport=httpx.MockTransport(boom))
    client = ZeppClient("synth@example.com", "fakepass-XYZ", min_interval=0,
                        http=http, cache=False)
    client._credential = Credential(
        "faketoken-XYZ", "uid-synth-99", "api-mifit-us3.zepp.com", "US",
        dt.datetime.now(UTC).timestamp() + 10000,
    )
    blob = json.dumps(client.get("/v1/x").as_dict())
    assert "hrv-marker" not in blob and "faketoken-XYZ" not in blob
    plain = client.get("/v1/x")
    assert plain.note and "ConnectError" not in plain.note
    client.close()
    written = list(tmp_path.rglob("*"))
    assert written == [] or all(p.is_dir() or MARKERS[0] not in p.read_text() for p in written if p.is_file())


def test_profile_allowlist_and_logs_omit_markers(monkeypatch, tmp_path):
    monkeypatch.setenv("ZEPP_TOKEN_CACHE", str(tmp_path / "token.json"))
    bufs = []
    for name in ("", "httpx", "zepp_mcp"):
        buf = __import__("io").StringIO()
        log = logging.getLogger(name)
        handler = logging.StreamHandler(buf)
        handler.setLevel(logging.INFO)
        log.addHandler(handler)
        log.setLevel(logging.INFO)
        bufs.append((log, handler, buf))

    def handler(request):
        return httpx.Response(200, json={"items": [{
            "model": "Synth", "deviceSource": 1, "firmwareVersion": "0",
            "macAddress": "AA:BB:CC:DD:EE:FF", "sn": "SN-MARKER",
            "hrv": "hrv-marker",
            "additionalInfo": {"auth_key": "KEY-MARKER"},
        }]})

    http = httpx.Client(transport=httpx.MockTransport(handler))
    client = ZeppClient("synth@example.com", "fakepass-XYZ", min_interval=0,
                        http=http, cache=False)
    client._credential = Credential(
        "faketoken-XYZ", "uid-synth-99", "api-mifit-us3.zepp.com", "US",
        dt.datetime.now(UTC).timestamp() + 10000,
    )
    monkeypatch.setattr(server, "_get_client", lambda: client)
    monkeypatch.setattr(server.api, "profile", lambda c: server.api.Outcome(
        "ok", 200, data={"data": {"height": 170, "birthday": "2010-05"}}))
    out = server.zepp_profile()
    blob = json.dumps(out)
    assert "KEY-MARKER" not in blob and "AA:BB" not in blob and "hrv-marker" not in blob
    logs = "".join(buf.getvalue() for _, _, buf in bufs)
    assert "KEY-MARKER" not in logs and "faketoken-XYZ" not in logs
    for log, handler, _buf in bufs:
        log.removeHandler(handler)
    client.close()


def test_mcp_call_drops_poisoned_upstream_note(monkeypatch):
    poisoned = server.api.Outcome(
        "error", 500, error_kind="server_error",
        note="hrv-marker " + ("x" * 220) + " spo2-marker uid-synth-99",
        data={"nested": {"gps": "gps-marker", "token": "faketoken-XYZ"}},
    )
    monkeypatch.setattr(server, "_get_client", lambda: object())
    monkeypatch.setattr(
        server.api, "band_data_range",
        lambda *args, **kwargs: server.api.Collected(status="error", error=poisoned),
    )
    result = asyncio.run(server.server.call_tool("zepp_sleep", {"date": DAY}))
    blob = result.model_dump_json()
    for marker in MARKERS:
        assert marker not in blob
    assert "The service failed to answer." in blob


def test_trial_mcp_stdio_errors_carry_no_markers():
    env = os.environ.copy()
    env.pop("ZEPP_MODE", None)
    env.pop("ZEPP_EMAIL", None)
    env.pop("ZEPP_PASSWORD", None)
    env["ZEPP_TOKEN_CACHE"] = "off"
    env["ZEPP_DEBUG"] = "1"
    proc = subprocess.run(
        [sys.executable, "-m", "zepp_mcp.server"],
        input="\n".join([
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "corr", "version": "0"}}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "zepp_sleep",
                "arguments": {"from_date": "2026-11-01", "to_date": "2026-11-08"}}}),
            json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
                "name": "zepp_list_workouts",
                "arguments": {"from_date": "2026-11-01", "to_date": "2026-11-07"}}}),
            json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
                "name": "zepp_workout_detail",
                "arguments": {"track_id": "1794114000", "source": "s", "date": DAY,
                              "include": ["gps"]}}}),
        ]) + "\n",
        text=True, capture_output=True, cwd=ROOT, env=env, timeout=20,
    )
    assert proc.returncode == 0
    names = None
    calls = {}
    for line in proc.stdout.splitlines():
        msg = json.loads(line)
        if msg.get("id") == 2:
            names = sorted(t["name"] for t in msg["result"]["tools"])
        if msg.get("id") in (3, 4, 5):
            calls[msg["id"]] = msg
    assert names == [
        "zepp_auth_status", "zepp_list_workouts", "zepp_profile",
        "zepp_sleep", "zepp_workout_detail",
    ]
    blob = proc.stdout + proc.stderr
    for marker in MARKERS:
        assert marker not in blob
    for msg in calls.values():
        assert "gps-marker" not in json.dumps(msg)
        text = json.dumps(msg["result"])
        assert "error" in text or msg["result"].get("isError") is True
