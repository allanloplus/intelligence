"""Vulnerability assessment for the five J–N columns.

Follows 《各機關基於風險導向之弱點處置期限評估指引》(115-11-06):
  J 已知被利用      CISA KEV catalog as of today (falls back to the domestic alert if the catalog is unreachable)
  K 能否被自動化利用  domestic alert (NICS / TWCERT) > CISA SSVC > inferred from CVSS, labelled （推定）
  L 技術影響程度     same order as K
  M/N 處置期限       deadline designated by NICS > deadline published in the alert (only while its KEV
                    status still matches today's catalog) > 表一 looked up from J/K/L
Every CVE keeps its own result and data source in the record (cve_detail) so a row can be audited.
"""
import html
import json
import re

from .common import http_text

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
KEV_URLS = ["https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"]
CVE_API = "https://cveawg.mitre.org/api/cve/"
MAX_CVES = 20
LATER = "待下次系統更新"
# 表一: key = KEV + automatable + impact (T total / P partial); type numbers 1-8 public, 9-16 internal.
ORDER = ["YYT", "YYP", "YNT", "YNP", "NYT", "NYP", "NNT", "NNP"]
DUE_TABLE = {
    "public":   dict(zip(ORDER, ["3天", "3天", "3天", "14天", "3天", "14天", "14天", "60天"])),
    "internal": dict(zip(ORDER, ["3天", "14天", "14天", "14天", "60天", "60天", LATER, LATER])),
}
NA, NO_CVE, UNKNOWN, FAILED = "不適用", "無 CVE 編號", "待確認", "查詢失敗"
GUESS = "（推定）"
SRC_DOMESTIC, SRC_SSVC, SRC_CVSS = "國內警訊", "CISA SSVC", "CVSS 推定"
VULN_COLS = ("kev", "automatable", "impact", "duePublic", "dueInternal")


def due_rank(v):
    m = re.fullmatch(r"(\d+)天", v or "")
    return int(m[1]) if m else (10 ** 6 if v == LATER else 10 ** 9)


def find_cves(text):
    seen = []
    for c in CVE_RE.findall(text or ""):
        c = c.upper()
        if c not in seen:
            seen.append(c)
    return seen


def to_text(fragment):
    fragment = re.sub(r"<(script|style)\b.*?</\1>", " ", fragment, flags=re.S | re.I)
    fragment = re.sub(r"<br\s*/?>|</p>|</li>|</div>|</h\d>|</tr>", "\n", fragment, flags=re.I)
    text = html.unescape(re.sub(r"<[^>]+>", "", fragment)).replace("\xa0", " ")
    return re.sub(r"[ \t]+", " ", re.sub(r"\n\s*\n+", "\n", text)).strip()


def page_text(url):
    """Plain text of the article body. Extraction is per site so sidebars and related-news
    links cannot leak unrelated CVEs into the assessment. Returns "" when the page is unreachable."""
    try:
        page = http_text(url, retries=2)
    except Exception:
        return ""
    if "nics.nat.gov.tw" in url:  # Next.js page: the article HTML lives inside the embedded JSON
        m = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', page, re.S)
        if not m:
            return ""
        chunks = []

        def walk(o):
            if isinstance(o, dict):
                if isinstance(o.get("code"), str):
                    chunks.append(o["code"])
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)

        try:
            walk(json.loads(m[1])["props"]["pageProps"].get("data", {}))
        except (ValueError, KeyError):
            return ""
        return to_text("\n".join(chunks))
    meta = " ".join(re.findall(r'<meta (?:name|property)="(?:og:)?description" content="([^"]*)"', page))
    if "twcert.org.tw" in url:
        m = re.search(r'<section class="cp">.*?</section>', page, re.S)
    elif "ithome.com.tw" in url:
        m = re.search(r'field-name-body[^>]*>(.*?)(?=view-hot-news|<footer|$)', page, re.S)
    else:
        m = re.search(r"<article\b.*?</article>", page, re.S | re.I)
    body = to_text(m[0]) if m else ""
    for stop in ("延伸閱讀", "相關文章", "近期資安日報", "熱門新聞"):
        body = body.split(stop)[0]
    return (html.unescape(meta) + "\n" + body).strip()


def digest_story(title, text):
    """iThome 資安日報 bundles ~15 stories. Return the text of the story the row title is about,
    so the row's J–N columns describe its own headline rather than unrelated news of the day."""
    head = re.sub(r"^【資安日報】[^，,]*[，,]", "", title)
    body = text.split("資安新聞總覽", 1)[-1]
    grams = {head[i:i + 2] for i in range(len(head) - 1)}
    best, score = "", 0
    for story in body.split("詳全文"):
        story = story.strip()
        first = story.split("\n", 1)[0]
        hit = sum(g in first for g in grams) * 3 + sum(g in story for g in grams)
        if hit > score:
            best, score = story, hit
    return best if score >= 6 else ""


# ---- indicators published in domestic alerts (NICS since 2026-11-16, TWCERT KEV weekly) -------------
_YN = {"是": True, "否": False}
_IND = re.compile(r"已知被利用\s*[\[［【(（]\s*(是|否)\s*[\]］】)）].{0,12}?自動化利用\s*[\[［【(（]\s*(是|否)\s*[\]］】)）]"
                  r".{0,16}?影響\s*[\[［【(（]\s*(完全控制|部分控制)\s*[\]］】)）]", re.S)
_DUE_VAL = r"(\d+\s*天|待下次系統更新)"
_DUE_BOTH = re.compile(r"(?<!未)曝露於公眾網路\s*=\s*[>＞]\s*" + _DUE_VAL + r".{0,12}?未曝露於公眾網路\s*=\s*[>＞]\s*" + _DUE_VAL, re.S)
_DUE_ONE = re.compile(r"弱點處置期限\s*[:：]\s*(\d+\s*天)")


def parse_domestic(text):
    """Return {CVE: {kev, auto, total, duePublic, dueInternal, designated}} from an alert body."""
    if not text or ("弱點處置期限" not in text and "評估指標結果" not in text):
        return {}
    out = {}
    heads = list(re.finditer(r"[【\[]\s*(CVE-\d{4}-\d{4,7})\s*[】\]]", text, re.I))
    blocks = [(h[1].upper(), text[h.end():h.end() + 800].split("【")[0]) for h in heads]
    if not blocks and len(find_cves(text)) == 1:
        blocks = [(find_cves(text)[0], text)]
    for cve, block in blocks:
        d = {}
        m = _IND.search(block)
        if m:
            d.update(kev=_YN[m[1]], auto=_YN[m[2]], total=m[3] == "完全控制")
        m = _DUE_BOTH.search(block)
        if m:  # a garbled deadline line simply fails to match; the indicators alone are then used
            d.update(duePublic=m[1].replace(" ", ""), dueInternal=m[2].replace(" ", ""))
        elif "曝露於公眾網路" not in block:
            m = _DUE_ONE.search(block)
            if m:
                d["designated"] = m[1].replace(" ", "")
        if d and (cve not in out or ("auto" in d and "auto" not in out[cve])):
            out[cve] = d
    return out


# ---- CVSS fallback -----------------------------------------------------------------------------------
def infer_from_cvss(vector):
    """Return (automatable, total) booleans or (None, None) when the vector lacks the metrics."""
    p = dict(x.split(":", 1) for x in vector.split("/") if ":" in x)
    if vector.startswith("CVSS:4"):
        need = ("AV", "AC", "AT", "PR", "UI", "VC", "VI")
        auto = p.get("AV") == "N" and p.get("AC") == "L" and p.get("AT") == "N" and p.get("PR") == "N" and p.get("UI") == "N"
        total = p.get("VC") == "H" or p.get("VI") == "H"
    elif vector.startswith("CVSS:3"):
        need = ("AV", "AC", "PR", "UI", "C", "I")
        auto = p.get("AV") == "N" and p.get("AC") == "L" and p.get("PR") == "N" and p.get("UI") == "N"
        total = p.get("C") == "H" or p.get("I") == "H"
    else:  # CVSS 2.0
        need = ("AV", "AC", "Au", "C", "I")
        auto = p.get("AV") == "N" and p.get("AC") == "L" and p.get("Au") == "N"
        total = p.get("C") == "C" or p.get("I") == "C"
    return (auto, total) if all(k in p for k in need) else (None, None)


def parse_cve_record(rec):
    """Pull SSVC decisions, the best CVSS vector and base score out of a CVE Program record."""
    out = {"found": bool(rec.get("cveMetadata")), "ssvc_auto": None, "ssvc_total": None, "vector": None, "score": None}
    cont = rec.get("containers", {})
    vectors = {}
    for block in [cont.get("cna", {})] + list(cont.get("adp", [])):
        for m in block.get("metrics", []):
            other = m.get("other", {})
            if other.get("type") == "ssvc":
                opts = {k: str(v).lower() for o in other.get("content", {}).get("options", []) for k, v in o.items()}
                if opts.get("Automatable") in ("yes", "no"):
                    out["ssvc_auto"] = opts["Automatable"] == "yes"
                if opts.get("Technical Impact") in ("total", "partial"):
                    out["ssvc_total"] = opts["Technical Impact"] == "total"
            for k, v in m.items():
                if k.startswith("cvssV") and isinstance(v, dict) and v.get("vectorString"):
                    vectors.setdefault(k, v)
    for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
        if k in vectors:
            out["vector"] = vectors[k]["vectorString"]
            break
    scores = [v.get("baseScore") for v in vectors.values() if isinstance(v.get("baseScore"), (int, float))]
    out["score"] = max(scores) if scores else None
    return out


class Enricher:
    def __init__(self, domestic=None):
        self._kev = None          # set of CVE ids, or False when the catalog could not be downloaded
        self._records = {}
        self.domestic = dict(domestic or {})   # CVE -> indicators published by NICS / TWCERT

    def register(self, text):
        """Record indicators found in an alert body; later items citing the same CVE reuse them."""
        found = parse_domestic(text)
        for cve, d in found.items():
            if cve not in self.domestic or ("auto" in d and "auto" not in self.domestic[cve]):
                self.domestic[cve] = d
        return found

    def kev_set(self):
        if self._kev is None:
            self._kev = False
            for url in KEV_URLS:
                try:
                    data = json.loads(http_text(url, timeout=90, retries=2))
                    self._kev = {v["cveID"].upper() for v in data["vulnerabilities"]}
                    break
                except Exception:
                    continue
        return self._kev

    def cve_record(self, cve):
        if cve not in self._records:
            try:
                self._records[cve] = parse_cve_record(json.loads(http_text(CVE_API + cve, retries=2)))
            except Exception as e:
                # HTTP 404 means the id is not published yet; anything else is a lookup failure.
                self._records[cve] = {"found": False, "failed": getattr(e, "code", None) != 404,
                                      "ssvc_auto": None, "ssvc_total": None, "vector": None, "score": None}
        return self._records[cve]

    def assess_cve(self, cve):
        dom = self.domestic.get(cve, {})
        rec = self.cve_record(cve)
        kevs = self.kev_set()
        d = {"cve": cve, "score": rec.get("score")}
        notes = []
        # J
        if kevs is not False:
            d["kev"] = cve in kevs or dom.get("kev") is True
            if "kev" in dom and dom["kev"] != (cve in kevs):
                notes.append("警訊標示已知被利用，CISA 清單未列" if dom["kev"] else "警訊發布後已列入 CISA KEV，期限依表一重新評估")
        else:
            d["kev"] = dom.get("kev")
        # K / L
        inferred = infer_from_cvss(rec["vector"]) if rec.get("vector") else (None, None)
        for key, dkey, skey, idx in (("auto", "auto", "ssvc_auto", 0), ("total", "total", "ssvc_total", 1)):
            if dkey in dom:
                d[key], d[key + "_src"] = dom[dkey], SRC_DOMESTIC
            elif rec.get(skey) is not None:
                d[key], d[key + "_src"] = rec[skey], SRC_SSVC
            elif inferred[idx] is not None:
                d[key], d[key + "_src"] = inferred[idx], SRC_CVSS
            else:
                d[key], d[key + "_src"] = None, None
        d["failed"] = bool(rec.get("failed")) and (d["auto"] is None or d["total"] is None)
        # M / N
        kev_consistent = kevs is False or dom.get("kev") == (cve in kevs)
        if dom.get("designated"):
            d["duePublic"] = d["dueInternal"] = dom["designated"]
            d["due_src"] = "資安院指定期限"
        elif dom.get("duePublic") and kev_consistent:
            d["duePublic"], d["dueInternal"], d["due_src"] = dom["duePublic"], dom["dueInternal"], "警訊公布期限"
        elif None not in (d["kev"], d["auto"], d["total"]):
            key = ("Y" if d["kev"] else "N") + ("Y" if d["auto"] else "N") + ("T" if d["total"] else "P")
            d["duePublic"], d["dueInternal"] = DUE_TABLE["public"][key], DUE_TABLE["internal"][key]
            n = ORDER.index(key) + 1
            d["due_src"] = f"表一類型 {n}／{n + 8}"
        else:
            d["duePublic"] = d["dueInternal"] = None
            d["due_src"] = None
        if notes:
            d["note"] = "；".join(notes)
        return d

    def assess(self, cves):
        """Assess up to MAX_CVES ids and fold them into the five columns (worst case wins)."""
        kevs = self.kev_set() or set()
        # Exploited CVEs and those with domestic indicators are looked up first so the cap never hides them.
        ranked = sorted(cves, key=lambda c: (c not in kevs, c not in self.domestic))[:MAX_CVES]
        details = [self.assess_cve(c) for c in ranked]

        def fold(key, yes, no):
            vals = [(d[key], d[key + "_src"] == SRC_CVSS) for d in details if d[key] is not None]
            if not vals:
                return FAILED if details and all(d["failed"] for d in details) else UNKNOWN
            if any(v and not g for v, g in vals):
                return yes
            if any(v for v, g in vals):
                return yes + GUESS
            return no if any(not g for v, g in vals) else no + GUESS

        known = [d["kev"] for d in details if d["kev"] is not None]
        cols = {"kev": "是" if any(known) else ("否" if known else FAILED),
                "automatable": fold("auto", "是", "否"),
                "impact": fold("total", "完全控制", "部分控制")}
        for col in ("duePublic", "dueInternal"):
            dues = [d[col] for d in details if d[col]]
            cols[col] = min(dues, key=due_rank) if dues else (FAILED if cols["automatable"] == FAILED else UNKNOWN)
        return cols, [format_detail(d) for d in details], len(cves) - len(ranked)


def format_detail(d):
    """Human-readable per-CVE result stored in the record and shown on the site / in Excel comments."""
    def val(key, yes, no):
        if d[key] is None:
            return UNKNOWN
        return (yes if d[key] else no) + (GUESS if d[key + "_src"] == SRC_CVSS else "")
    out = {"cve": d["cve"], "kev": "是" if d["kev"] else ("否" if d["kev"] is not None else FAILED),
           "automatable": val("auto", "是", "否"), "impact": val("total", "完全控制", "部分控制"),
           "duePublic": d["duePublic"] or UNKNOWN, "dueInternal": d["dueInternal"] or UNKNOWN,
           "source": "、".join(dict.fromkeys(s for s in (d["auto_src"], d["total_src"]) if s)) or "無資料",
           "dueSource": d["due_src"] or ""}
    if d.get("score") is not None:
        out["cvss"] = d["score"]
    if d.get("note"):
        out["note"] = d["note"]
    return out


def fixed(value):
    return {k: value for k in VULN_COLS}
