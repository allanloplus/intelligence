"""Shared constants and helpers."""
import datetime as dt
import json
import pathlib
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
PUBLIC = ROOT / "public"
UA = "Mozilla/5.0 (compatible; threat-intel-collector/1.0)"

# Column order and header text of the 2026-11 sheet (IS-P-052). Line breaks are part of the header.
COLUMNS = [
    ("date", "資料日期"),
    ("source", "資料來源"),
    ("title", "資料標題"),
    ("url", "訊息網址連結"),
    ("origin", "威脅情資來源"),
    ("category", "威脅情報類別"),
    ("severity", "對組織的現況威脅程度"),
    ("countermeasure", "因應對策"),
    ("progress", "執行進度說明"),
    ("kev", "弱點已知被利用(CISA KEV)"),
    ("automatable", "弱點能否被 自動化利用"),
    ("impact", "弱點遭利用後之\n 技術影響程度"),
    ("duePublic", "弱點處置期限\n (曝露於公眾網路)"),
    ("dueInternal", "弱點處置期限\n (未曝露於公眾網路)"),
]
VULN_KEYS = ["kev", "automatable", "impact", "duePublic", "dueInternal"]
# Columns that only exist on tabs before 2026-11; exported only when a month has data in them.
LEGACY_COLUMNS = [("riskScope", "風險之層面/影響資通系統"), ("affected", "受影響之作業系統或應用程式版本")]


def settings():
    return json.loads((ROOT / "config" / "settings.json").read_text(encoding="utf-8"))


def today(cfg=None):
    off = (cfg or settings()).get("timezone_offset_hours", 8)
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=off)).date()


def http_get(url, timeout=40, retries=3):
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:  # network errors are retried, then surfaced to the caller
            last = e
            time.sleep(2 * (i + 1))
    raise last


def http_text(url, **kw):
    return http_get(url, **kw).decode("utf-8", errors="replace")
