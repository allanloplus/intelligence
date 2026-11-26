"""CVE enrichment: CISA KEV, CISA SSVC (Vulnrichment) and the disposal-deadline table.

Deadlines follow 《各機關基於風險導向之弱點處置期限評估指引》(115-11-06) 表一, keyed by
KEV (Y/N) + automatable (Y/N) + technical impact (T total / P partial).
"""
import json
import re

from .common import http_text

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_API = "https://cveawg.mitre.org/api/cve/"
MAX_CVES = 25  # CVE records looked up per item; KEV membership is checked for all
LATER = "待下次系統更新"
DUE_TABLE = {
    "public":   {"YYT": "3天", "YYP": "3天", "YNT": "3天", "YNP": "14天", "NYT": "3天", "NYP": "14天", "NNT": "14天", "NNP": "60天"},
    "internal": {"YYT": "3天", "YYP": "14天", "YNT": "14天", "YNP": "14天", "NYT": "60天", "NYP": "60天", "NNT": LATER, "NNP": LATER},
}
DUE_RANK = {"3天": 0, "14天": 1, "60天": 2, LATER: 3}
NA, NO_CVE, UNKNOWN = "不適用", "無 CVE 編號", "待確認"
GUESS = "（推定）"


def find_cves(text):
    seen = []
    for c in CVE_RE.findall(text or ""):
        c = c.upper()
        if c not in seen:
            seen.append(c)
    return seen


def page_cves(url):
    """CVE ids mentioned in the article body. Body extraction is per site so that
    sidebars / related-news links do not leak unrelated CVEs into the assessment."""
    try:
        page = http_text(url, retries=2)
    except Exception:
        return []
    if "nics.nat.gov.tw" in url:  # Next.js page: the article lives in the embedded JSON
        m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', page, re.S)
        return find_cves(m[1] if m else "")
    page = re.sub(r"<(script|style)\b.*?</\1>", " ", page, flags=re.S | re.I)
    meta = " ".join(re.findall(r'<meta (?:name|property)="(?:og:)?description" content="([^"]*)"', page))
    if "twcert.org.tw" in url:
        m = re.search(r'<section class="cp">.*?</section>', page, re.S)
    elif "ithome.com.tw" in url:
        m = re.search(r'field-name-body.*?(?=view-hot-news|<footer|$)', page, re.S)
    else:
        m = re.search(r"<article\b.*?</article>", page, re.S | re.I)
    return find_cves(meta + " " + (m[0] if m else ""))


class Enricher:
    def __init__(self):
        self._kev = None
        self._cache = {}

    def kev_set(self):
        if self._kev is None:
            data = json.loads(http_text(KEV_URL, timeout=90))
            self._kev = {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
        return self._kev

    def assess_cve(self, cve):
        """Return {kev: bool, auto: (bool, guessed)|None, total: (bool, guessed)|None}."""
        if cve in self._cache:
            return self._cache[cve]
        res = {"kev": cve in self.kev_set(), "auto": None, "total": None}
        try:
            rec = json.loads(http_text(CVE_API + cve, retries=2))
        except Exception:
            rec = {}
        cont = rec.get("containers", {})
        vectors = []
        for block in [cont.get("cna", {})] + list(cont.get("adp", [])):
            for m in block.get("metrics", []):
                other = m.get("other", {})
                if other.get("type") == "kev":
                    res["kev"] = True
                if other.get("type") == "ssvc":
                    opts = {k: str(v).lower() for o in other.get("content", {}).get("options", []) for k, v in o.items()}
                    if opts.get("Exploitation") == "active":
                        res["kev"] = res["kev"] or cve in self.kev_set()
                    if opts.get("Automatable") in ("yes", "no"):
                        res["auto"] = (opts["Automatable"] == "yes", False)
                    if opts.get("Technical Impact") in ("total", "partial"):
                        res["total"] = (opts["Technical Impact"] == "total", False)
                for k, v in m.items():
                    if k.startswith("cvssV") and isinstance(v, dict) and v.get("vectorString"):
                        vectors.append(v["vectorString"])
        if vectors and (res["auto"] is None or res["total"] is None):
            # No SSVC decision yet: infer from the CVSS vector and label the value as 推定.
            parts = dict(p.split(":", 1) for p in vectors[0].split("/") if ":" in p)
            auto = parts.get("AV") == "N" and parts.get("AC") == "L" and parts.get("PR") == "N" and parts.get("UI") == "N"
            conf, integ = parts.get("C") or parts.get("VC"), parts.get("I") or parts.get("VI")
            if res["auto"] is None:
                res["auto"] = (auto, True)
            if res["total"] is None:
                res["total"] = (conf == "H" and integ == "H", True)
        self._cache[cve] = res
        return res

    def assess(self, cves):
        """Aggregate several CVEs into the five sheet columns (worst case wins)."""
        in_kev = [c for c in cves if c in self.kev_set()]
        picked = (in_kev + [c for c in cves if c not in in_kev])[:MAX_CVES]  # exploited ones first
        rows = [self.assess_cve(c) for c in picked]
        kev = bool(in_kev) or any(r["kev"] for r in rows)

        def fold(key, yes, no):
            vals = [r[key] for r in rows if r[key] is not None]
            if not vals:
                return UNKNOWN
            if any(v and not g for v, g in vals):
                return yes
            if any(v for v, g in vals):
                return yes + GUESS
            return no if any(not g for v, g in vals) else no + GUESS

        out = {"kev": "是" if kev else "否", "automatable": fold("auto", "是", "否"),
               "impact": fold("total", "完全控制", "部分控制")}
        dues = {"public": [], "internal": []}
        for r in rows:
            if r["auto"] is None or r["total"] is None:
                continue
            key = ("Y" if r["kev"] else "N") + ("Y" if r["auto"][0] else "N") + ("T" if r["total"][0] else "P")
            for side in dues:
                dues[side].append(DUE_TABLE[side][key])
        for side, col in (("public", "duePublic"), ("internal", "dueInternal")):
            out[col] = min(dues[side], key=DUE_RANK.get) if dues[side] else UNKNOWN
        return out


def fixed(value):
    return {k: value for k in ("kev", "automatable", "impact", "duePublic", "dueInternal")}
