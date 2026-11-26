"""One-off, READ-ONLY import of the existing yearly Google Sheets into data/.

Only the public xlsx export endpoint is called; nothing is ever written to the sheets.
Usage: python -m intel import-history 2024=<sheetId> 2025=<sheetId> ...   (or a local .xlsx path)
"""
import datetime as dt
import io
import pathlib
import re

from openpyxl import load_workbook

from . import store
from .common import http_get

FIELDS = [  # same header matching as the war-room dashboard (headers vary between years)
    ("date", r"資料日期"), ("source", r"^資料來源"), ("title", r"資料標題"), ("url", r"網址|每則資料下方"),
    ("origin", r"威脅情資來源"), ("category", r"威脅情報類別"), ("severity", r"威脅程度"),
    ("riskScope", r"風險之層面|影響資通系統"), ("affected", r"受影響"), ("countermeasure", r"因應對策"),
    ("progress", r"執行進度"), ("kev", r"KEV|已知被利用"), ("automatable", r"自動化"), ("impact", r"技術影響"),
    ("dueInternal", r"處置期限.*未曝露"), ("duePublic", r"處置期限"),
]
TAB = re.compile(r"^(\d{4})年(\d{1,2})月$")


def layout(headers):
    used, out = set(), []
    for raw in headers:
        lab = re.sub(r"\s+", "", str(raw or ""))
        key = next((k for k, pat in FIELDS if lab and k not in used and re.search(pat, lab, re.I)), None)
        if key:
            used.add(key)
        out.append(key)
    for i, k in enumerate(["date", "source", "title", "url"]):  # e.g. 2026年1月 has no 資料日期 label
        if k not in used and i < len(out) and out[i] is None:
            out[i] = k
    return out


def to_date(v, year, month):
    if isinstance(v, dt.datetime):
        return v.date()
    if isinstance(v, dt.date):
        return v
    m = re.search(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", str(v or ""))
    if m:
        try:
            return dt.date(int(m[1]), int(m[2]), int(m[3]))
        except ValueError:
            pass
    return None


def import_workbook(year, blob):
    wb = load_workbook(io.BytesIO(blob), read_only=True, data_only=True)
    report = []
    for ws in wb.worksheets:
        m = TAB.match(ws.title.strip())
        if not m or int(m[1]) != year:
            continue  # other tabs (說明, 外部議題蒐集, next year's draft tab ...) are not monthly intel
        month = int(m[2])
        rows = ws.iter_rows(values_only=True)
        lay = layout(next(rows, []))
        recs, seen = [], set()
        for row in rows:
            r = {k: ("" if v is None else v) for k, v in zip(lay, row) if k}
            title, url = str(r.get("title", "")).strip(), str(r.get("url", "")).strip()
            if not title:
                continue
            d = to_date(r.get("date"), year, month) or dt.date(year, month, 1)
            rid = store.rec_id(url, title)
            if rid in seen:
                rid = store.rec_id(url + "|" + title)
            seen.add(rid)
            rec = {"id": rid, "date": d.isoformat(), "source": str(r.get("source", "")).strip(), "title": title, "url": url}
            for k, _ in FIELDS[4:]:
                rec[k] = re.sub(r"[ \t]*\n[ \t]*", "\n", str(r.get(k, "")).strip())
            rec["auto"] = False
            recs.append(rec)
        if recs:
            store.save_month(year, month, recs)
        report.append((ws.title, len(recs)))
    return report


def run(args):
    for a in args:
        year, ref = a.split("=", 1)
        if pathlib.Path(ref).exists():
            blob = pathlib.Path(ref).read_bytes()
        else:
            blob = http_get(f"https://docs.google.com/spreadsheets/d/{ref}/export?format=xlsx", timeout=120)
        for tab, n in import_workbook(int(year), blob):
            print(f"  {tab}: {n}")
