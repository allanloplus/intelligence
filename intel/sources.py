"""Fetch candidate items from each source. Every fetcher returns [{date, source, title, url, summary}]."""
import datetime as dt
import email.utils
import html
import json
import re
import xml.etree.ElementTree as ET

from .common import http_text

TAG = re.compile(r"<[^>]+>")


def clean(s):
    return re.sub(r"\s+", " ", html.unescape(TAG.sub("", s or ""))).strip()


def parse_date(s, tz_hours):
    """Return a local date from RFC-822, ISO or yyyy/m/d text."""
    s = (s or "").strip()
    try:
        d = email.utils.parsedate_to_datetime(s)
        if d.tzinfo:
            d = d.astimezone(dt.timezone(dt.timedelta(hours=tz_hours)))
        return d.date()
    except (TypeError, ValueError):
        pass
    m = re.search(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", s)
    return dt.date(int(m[1]), int(m[2]), int(m[3])) if m else None


def fetch_rss(src, tz):
    root = ET.fromstring(http_text(src["url"]).lstrip().encode("utf-8"))
    must = re.compile(src["title_must_match"]) if src.get("title_must_match") else None
    out = []
    for it in root.iter("item"):
        title = clean(it.findtext("title"))
        link = (it.findtext("link") or "").strip()
        date = parse_date(it.findtext("pubDate"), tz)
        if not (title and link and date) or (must and not must.search(title)):
            continue
        out.append({"date": date, "source": src["name"], "title": title, "url": link,
                    "summary": clean(it.findtext("description"))})
    cap = src.get("max_per_day")
    if cap:  # busy news feed: keep only the N most security-relevant items of each day
        words = src.get("prefer_keywords", [])
        by_day = {}
        for x in out:
            by_day.setdefault(x["date"], []).append(x)
        out = []
        for day in by_day.values():
            day.sort(key=lambda x: -sum(w.lower() in (x["title"] + x["summary"]).lower() for w in words))
            out += day[:cap]
    return out


def fetch_twcert_list(src, tz):
    base = "https://www.twcert.org.tw"
    node = src["node"]
    page = http_text(f"{base}/tw/lp-{node}-1.html")
    out = []
    pat = re.compile(r'<a href="(/tw/cp-%d-[^"]+)"[^>]*>(.*?)<time>([^<]+)</time>' % node, re.S)
    for href, body, when in pat.findall(page):
        title = clean(re.sub(r'<span class="num">.*?</span>', "", body, flags=re.S))
        date = parse_date(when, tz)
        if title and date:
            out.append({"date": date, "source": src["name"], "title": title, "url": base + href, "summary": ""})
    return out


def fetch_nics_alerts(src, tz):
    page = http_text(src["url"])
    m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', page, re.S)
    if not m:
        raise ValueError("NICS page layout changed: __NEXT_DATA__ not found")
    out = []

    def walk(o):
        if isinstance(o, dict):
            if o.get("label") and o.get("date") and str(o.get("link", "")).startswith("/core_business"):
                date = parse_date(o["date"], tz)
                if date:
                    out.append({"date": date, "source": src["name"], "title": clean(o["label"]),
                                "url": "https://www.nics.nat.gov.tw" + o["link"], "summary": ""})
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(json.loads(m[1])["props"]["pageProps"].get("data", {}))
    return out


FETCHERS = {"rss": fetch_rss, "twcert_list": fetch_twcert_list, "nics_alerts": fetch_nics_alerts}


def fetch_all(cfg):
    """Return (items, errors). One failing source never blocks the others."""
    items, errors = [], []
    tz = cfg.get("timezone_offset_hours", 8)
    for src in cfg["sources"]:
        label = f'{src["name"]}/{src.get("note") or src["type"]}'
        try:
            got = FETCHERS[src["type"]](src, tz)
            for g in got:
                if src.get("category"):
                    g["category"] = src["category"]
            if not got:
                errors.append(f"{label}: 0 items (layout may have changed)")
            items += got
        except Exception as e:
            errors.append(f"{label}: {type(e).__name__}: {e}")
    return items, errors
