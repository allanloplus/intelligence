"""Rule-based classification (category / severity / countermeasure) plus the J–N assessment.

Severity is a first-pass value: it depends on config/settings.json "asset_watchlist", which must
reflect the organisation's real assets. Each record keeps a "basis" sentence explaining the result.
"""
import re

from . import enrich

CAT_VULN, CAT_THREAT = "外部：漏洞情報", "外部：威脅情報"
CAT_INCIDENT, CAT_GUIDE, CAT_LAW = "外部：安全事件情報", "外部：安全建議和指南", "外部：法規和合規性情報"

RE_LAW = re.compile(r"個資法|資安法|資通安全管理法|GDPR|NIS2|法規|法案|修法|草案|裁罰|罰款|合規|ISO ?27001|ISO ?27701|監管")
RE_GUIDE = re.compile(r"指引|指南|防護建議|最佳實務|白皮書|手冊|檢核表|守則|Guideline|Playbook", re.I)
RE_INCIDENT = re.compile(r"外洩|外流|遭竊|遭駭|被駭|遭入侵|遭勒索|服務中斷|當機|癱瘓|重訊|[遭被].{0,8}(攻擊|入侵|加密|竄改|劫持)")
RE_VULN = re.compile(r"CVE-\d{4}-\d+|漏洞|弱點|零時差|CVSS|KEV|Known Exploited|修補|安全性更新|例行更新|安全更新|"
                     r"資安公告|安全公告|終止支援", re.I)
RE_ATTACK = re.compile(r"釣魚|詐騙|勒索|惡意軟體|惡意程式|社交工程|假冒|冒名|木馬|後門|殭屍網路|駭客|間諜|供應鏈攻擊|帳密|APT", re.I)
RE_PHISH = re.compile(r"釣魚|詐騙|社交工程|假冒|冒名|密碼|帳密")
RE_MALWARE = re.compile(r"惡意軟體|惡意程式|後門|勒索軟體|木馬|殭屍網路|入侵指標|IoC")
RE_CRITICAL = re.compile(r"重大|Critical|滿分|高風險|緊急|RCE|遠端程式碼執行|遠端執行|權限提升|身分驗證繞過", re.I)
RE_LOCAL = re.compile(r"臺灣|台灣|我國|國內|上市櫃|重訊")
RE_NOT_AFFECTED = re.compile(r"(臺灣|台灣|國內)[^。]{0,12}不受影響")
RE_CVSS = re.compile(r"CVSS[^0-9。]{0,24}?(\d{1,2}(?:\.\d)?)", re.I)


def category(title):
    """Title rules in priority order; an incident wording only wins when no vulnerability word precedes it."""
    if RE_LAW.search(title):
        return CAT_LAW, "標題含法規／合規字詞"
    if RE_GUIDE.search(title):
        return CAT_GUIDE, "標題含指引／建議字詞"
    if RE_VULN.search(title):   # an exploited flaw is still vulnerability intel, even when an incident is named
        return CAT_VULN, "標題含漏洞／修補字詞"
    if RE_INCIDENT.search(title):
        return CAT_INCIDENT, "標題描述已發生的資安事件"
    return CAT_THREAT, "無其他類別特徵，歸為威脅情報"


def classify(item, cfg, enricher, text=""):
    """Return category, severity, countermeasure, the five vulnerability columns and the basis note."""
    title = item["title"]
    if item.get("category"):
        cat, why = item["category"], "來源為漏洞警訊公告"
    else:
        cat, why = category(title)
    basis = [f"類別：{why}"]
    # Alert pages are about one product family, so their body may be searched; news bodies are too noisy.
    hay = title + ("\n" + text if item.get("category") else "")
    hits = [w for w in cfg.get("asset_watchlist", {}).get("keywords", []) if w.lower() in hay.lower()]
    relevant = bool(hits)
    basis.append("資產：命中 " + "、".join(hits[:4]) if hits else "資產：未命中資產清單")
    rec = {"category": cat, "cves": [], "cve_detail": []}

    title_cves = enrich.find_cves(title)
    scope = text
    if "資安日報" in title:
        scope = enrich.digest_story(title, text)
        others = [c for c in enrich.find_cves(text) if c not in enrich.find_cves(scope)]
        basis.append("資安日報：以標題頭條新聞評估" + (f"，同日另提及 {len(others)} 個 CVE" if others else ""))
        if others:
            rec["cves_other"] = others
    body_cves = [c for c in enrich.find_cves(scope) if c not in title_cves]
    if cat == CAT_VULN or title_cves or ("資安日報" in title and body_cves):
        cves = title_cves + body_cves
        rec["cves"] = cves
        if cves:
            cols, rec["cve_detail"], skipped = enricher.assess(cves)
            rec.update(cols)
            if skipped:
                basis.append(f"CVE 共 {len(cves)} 個，僅評估前 {enrich.MAX_CVES} 個")
        else:
            rec.update(enrich.fixed(enrich.NO_CVE))
    else:
        rec.update(enrich.fixed(enrich.NA))

    exploited = rec["kev"] == "是"
    scores = [d["cvss"] for d in rec["cve_detail"] if "cvss" in d] + [float(s) for s in RE_CVSS.findall(text) if float(s) <= 10]
    top = max(scores) if scores else None
    severe = (top is not None and top >= 7) or bool(RE_CRITICAL.search(title))
    local, attack = bool(RE_LOCAL.search(title)), bool(RE_ATTACK.search(title))

    if cat == CAT_VULN:
        if exploited:
            basis.append("已知被利用")
        if top is not None:
            basis.append(f"CVSS 最高 {top:g}")
        if relevant:
            sev = "高" if exploited else ("中" if severe else "低")
        else:
            sev = "低" if exploited and top is not None and top >= 9 else "現行不影響"
        if RE_NOT_AFFECTED.search(text):
            sev = "現行不影響"
            basis.append("原文說明國內不受影響")
    elif cat == CAT_THREAT:
        sev = "中" if attack and (relevant or local) else ("低" if attack else "現行不影響")
        basis.append("含攻擊活動字詞" if attack else "無攻擊活動字詞")
    elif cat == CAT_INCIDENT:
        sev = "中" if local and relevant else ("低" if local or relevant else "現行不影響")
    elif cat == CAT_LAW:
        sev = "中" if local and re.search(r"個資|個人資料", title) else ("低" if local else "現行不影響")
    else:
        sev = "低" if relevant or local else "現行不影響"
    if local:
        basis.append("涉及國內")

    if sev == "現行不影響":
        counter = "僅列入知識庫"
    elif sev == "低":
        counter = "列入風險評鑑"
    elif cat == CAT_VULN:
        counter = "技術預防和檢測控制"
    elif cat == CAT_THREAT and RE_PHISH.search(title):
        counter = "執行資安測試和技術的輸入"
    elif cat == CAT_THREAT and RE_MALWARE.search(title):
        counter = "技術預防和檢測控制"
    else:
        counter = "列入風險評鑑"
    rec.update(severity=sev, countermeasure=counter, basis="；".join(basis) + f" → {sev}")
    return rec
