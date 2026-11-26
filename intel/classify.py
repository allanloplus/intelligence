"""Rule-based classification (category / severity / countermeasure).

The rules are a transparent first pass derived from the 2026-11 sheet. Records keep
"auto": true until a person reviews them; edit data/YYYY/YYYY-MM.json to override.
"""
import re

from . import enrich

CAT_VULN, CAT_THREAT = "外部：漏洞情報", "外部：威脅情報"
CAT_INCIDENT, CAT_GUIDE = "外部：安全事件情報", "外部：安全建議和指南"

RE_KEV_WEEKLY = re.compile(r"Known Exploited Vulnerabilities|KEV\)?\s*週報", re.I)
RE_VULN = re.compile(r"CVE-\d{4}-\d+|漏洞|弱點|修補|安全性更新|例行更新|安全更新|資安公告|安全公告|修補公告|零時差|Vulnerabilit|資安日報", re.I)
RE_GUIDE = re.compile(r"指引|指南|懶人包|守則|最佳實務|手冊")
RE_INCIDENT = re.compile(r"遭駭|外洩|洩漏|入侵|遭竊|當機|中斷|癱瘓|遭.{0,6}攻擊|受害|恐嚇|事故|資安事件")
RE_ACTIVE_THREAT = re.compile(r"殭屍網路|惡意軟體|惡意程式|駭客|APT|後門|木馬|間諜|釣魚|供應鏈|勒索|Botnet", re.I)
RE_CRITICAL = re.compile(r"重大|嚴重|零時差|已遭利用|遭利用|Critical|RCE|遠端執行", re.I)
RE_LOCAL = re.compile(r"臺灣|台灣|國內|我國")


def category(title):
    if RE_KEV_WEEKLY.search(title) or RE_VULN.search(title):
        return CAT_VULN
    if RE_GUIDE.search(title):
        return CAT_GUIDE
    if RE_INCIDENT.search(title):
        return CAT_INCIDENT
    return CAT_THREAT


def classify(item, cfg, enricher):
    """Return the classification + vulnerability columns for one fetched item."""
    title = item["title"]
    cat = item.get("category") or category(title)  # a source may pin its category (vulnerability alert lists)
    words = cfg.get("asset_watchlist", {}).get("keywords", [])
    relevant = any(w.lower() in title.lower() for w in words)
    rec = {"category": cat, "cves": []}

    if cat != CAT_VULN:
        rec.update(enrich.fixed(enrich.NA))
        if cat == CAT_THREAT:
            sev = "中" if RE_ACTIVE_THREAT.search(title) else "低"
        elif cat == CAT_INCIDENT:
            sev = "中" if (relevant or RE_LOCAL.search(title)) else "低"
        else:
            sev = "低"
    elif RE_KEV_WEEKLY.search(title):
        # Weekly KEV digest: every listed CVE is exploited, so the strictest deadline applies.
        rec.update({"kev": "是", "automatable": "是", "impact": "完全控制", "duePublic": "3天", "dueInternal": "3天"})
        sev = "現行不影響"
    else:
        cves = enrich.find_cves(title + " " + item.get("summary", "")) or enrich.page_cves(item["url"])
        rec["cves"] = cves[:60]
        if cves:
            rec.update(enricher.assess(cves))
        else:
            rec.update(enrich.fixed(enrich.NO_CVE))
        hot = rec["kev"] == "是" or RE_CRITICAL.search(title)
        if relevant:
            sev = "高" if hot else "中"
        else:
            sev = "低" if rec["kev"] == "是" else "現行不影響"

    rec["severity"] = sev
    if sev == "現行不影響":
        rec["countermeasure"] = "僅列入知識庫"
    elif sev == "低" or cat in (CAT_INCIDENT, CAT_GUIDE):
        rec["countermeasure"] = "列入風險評鑑"
    elif cat == CAT_VULN:
        rec["countermeasure"] = "技術預防和檢測控制"
    else:
        rec["countermeasure"] = "執行資安測試和技術的輸入"
    return rec
