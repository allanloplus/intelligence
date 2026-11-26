"""Month files: data/YYYY/YYYY-MM.json — the single source of truth (plain JSON, reviewed via git)."""
import hashlib
import json
import re

from .common import DATA


def rec_id(url, title=""):
    return hashlib.sha1((url or title).strip().encode("utf-8")).hexdigest()[:12]


def month_path(year, month):
    return DATA / str(year) / f"{year}-{month:02d}.json"


def load_month(year, month):
    p = month_path(year, month)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else []


def save_month(year, month, recs):
    recs = sorted(recs, key=lambda r: (r["date"], r["source"], r["title"]))
    p = month_path(year, month)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(recs, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def months():
    """All stored (year, month) pairs, oldest first."""
    out = []
    for p in sorted(DATA.glob("*/*.json")):
        m = re.fullmatch(r"(\d{4})-(\d{2})", p.stem)
        if m:
            out.append((int(m[1]), int(m[2])))
    return out


def known_ids():
    return {r["id"] for y, m in months() for r in load_month(y, m)}
