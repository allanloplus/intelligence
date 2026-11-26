"""Build the static site payload: per-month JSON, monthly/annual xlsx, and the index."""
import datetime as dt
import json
import shutil

from openpyxl import Workbook
from openpyxl.comments import Comment
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from . import store
from .common import COLUMNS, LEGACY_COLUMNS, PUBLIC, ROOT, settings, today

WIDTHS = {"date": 12, "source": 11, "title": 60, "url": 42, "origin": 12, "category": 20, "severity": 14,
          "countermeasure": 24, "progress": 12, "kev": 14, "automatable": 14, "impact": 16,
          "duePublic": 16, "dueInternal": 18, "riskScope": 22, "affected": 26}
HEAD_FILL = PatternFill("solid", fgColor="1F4E78")
VULN_FILL = PatternFill("solid", fgColor="7F3F00")
SEV_FILL = {"高": "F8CBAD", "中": "FFE699", "低": "C6E0B4", "現行不影響": "E7E6E6"}
THIN = Side(style="thin", color="BFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
NOTE = ("註：「弱點處置期限」的天數係參考《各機關基於風險導向之弱點處置期限評估指引》（115 年 11 月 6 日訂定）表一，"
        "依是否曝露於公眾網路、弱點已知被利用、能否被自動化利用、技術影響程度評估；期限自知悉日起算，以日曆天計。"
        "評估指標優先採用資安院、TWCERT/CC 警訊公布之結果，其次為 CISA SSVC；兩者皆無時依 CVSS 向量推定並標示「（推定）」。"
        "「已知被利用」以 CISA KEV 清單現況為準，近 60 日情資每日重新評估。")


def note(text):
    cm = Comment(text[:3000], "情資自動蒐集系統")
    cm.width, cm.height = 520, min(60 + 18 * text.count("\n"), 520)
    return cm


def cve_note(r):
    """Per-CVE result and data source, attached to the J cell so the row can be audited."""
    lines = [f"逐一 CVE 判定（評估日 {r.get('assessed', '')}）："]
    for d in r["cve_detail"]:
        lines.append(f"{d['cve']}｜被利用 {d['kev']}｜自動化 {d['automatable']}｜影響 {d['impact']}｜"
                     f"{d['duePublic']}／{d['dueInternal']}｜{d['source']}｜{d['dueSource']}"
                     + (f"｜{d['note']}" if d.get("note") else ""))
    extra = len(r.get("cves", [])) - len(r["cve_detail"])
    if extra > 0:
        lines.append(f"另有 {extra} 個 CVE 未逐一評估（已優先評估列入 KEV 與警訊公布指標者）。")
    lines.append("各欄取所有 CVE 中最嚴格者；類型 1、2、3、9 依指引應先檢視日誌確認是否已遭利用。")
    return "\n".join(lines)


def month_columns(recs):
    return COLUMNS + [c for c in LEGACY_COLUMNS if any(r.get(c[0]) for r in recs)]


def write_sheet(ws, recs):
    cols = month_columns(recs)
    for ci, (key, label) in enumerate(cols, 1):
        c = ws.cell(row=1, column=ci, value=label)
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = VULN_FILL if ci > 9 and ci <= 14 else HEAD_FILL
        c.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        c.border = BORDER
        ws.column_dimensions[get_column_letter(ci)].width = WIDTHS.get(key, 16)
    ws.row_dimensions[1].height = 48
    for ri, r in enumerate(recs, 2):
        for ci, (key, _) in enumerate(cols, 1):
            v = r.get(key, "")
            c = ws.cell(row=ri, column=ci)
            if key == "date" and v:
                c.value = dt.date.fromisoformat(v)
                c.number_format = "yyyy/m/d"
            else:
                c.value = v
            c.alignment = Alignment(vertical="top", wrap_text=key in ("title", "url", "riskScope", "affected"),
                                    horizontal=None if key in ("title", "url", "riskScope", "affected") else "center")
            c.border = BORDER
            if key == "url" and str(v).startswith("http"):
                c.hyperlink = v
                c.font = Font(color="0563C1", underline="single")
            if key == "severity" and v in SEV_FILL:
                c.fill = PatternFill("solid", fgColor=SEV_FILL[v])
                if r.get("basis"):
                    c.comment = note("判定依據（系統初判）：\n" + r["basis"].replace("；", "\n"))
            if key == "kev" and r.get("cve_detail"):
                c.comment = note(cve_note(r))
    ws.freeze_panes = "D2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(cols))}{max(len(recs) + 1, 2)}"


def write_notes(wb, cfg, generated):
    ws = wb.create_sheet("說明")
    lines = [cfg["document_name"], f"產生時間：{generated}（自動蒐集系統產出）", "",
             "資料來源：" + "、".join(dict.fromkeys(s["name"] for s in cfg["sources"])),
             "威脅程度與因應對策為系統依規則初判，請各組織依自身資產與環境覆核後調整。", "", NOTE]
    for i, t in enumerate(lines, 1):
        c = ws.cell(row=i, column=1, value=t)
        c.alignment = Alignment(wrap_text=True, vertical="top")
    ws["A1"].font = Font(bold=True, size=14)
    ws.column_dimensions["A"].width = 110


def build():
    cfg = settings()
    now = today(cfg)
    generated = dt.datetime.now(dt.timezone(dt.timedelta(hours=cfg.get("timezone_offset_hours", 8)))).strftime("%Y-%m-%d %H:%M")
    first_year = now.year - cfg.get("retention_years", 3)
    if PUBLIC.exists():
        shutil.rmtree(PUBLIC)
    (PUBLIC / "data").mkdir(parents=True)
    (PUBLIC / "downloads").mkdir()
    shutil.copy(ROOT / "site" / "index.html", PUBLIC / "index.html")
    (PUBLIC / ".nojekyll").write_text("")

    years = {}
    for y, m in store.months():
        if y < first_year:
            continue  # older months stay in git history/data but leave the public site
        recs = store.load_month(y, m)
        if not recs:
            continue
        years.setdefault(y, []).append((m, recs))

    index = {"generated": generated, "document": cfg["document_name"], "note": NOTE, "years": {}}
    for y, mlist in sorted(years.items()):
        annual = Workbook()
        annual.remove(annual.active)
        entries = []
        for m, recs in sorted(mlist):
            tab = f"{y}年{m}月"
            write_sheet(annual.create_sheet(tab), recs)
            single = Workbook()
            single.active.title = tab
            write_sheet(single.active, recs)
            write_notes(single, cfg, generated)
            xlsx = f"downloads/intel-{y}-{m:02d}.xlsx"
            single.save(PUBLIC / xlsx)
            data = f"data/{y}-{m:02d}.json"
            (PUBLIC / data).write_text(json.dumps(recs, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
            entries.append({"month": m, "count": len(recs), "data": data, "xlsx": xlsx,
                            "xlsxName": f'{cfg["document_name"]}_{tab}.xlsx'})
        write_notes(annual, cfg, generated)
        axlsx = f"downloads/IS-P-052_{y}.xlsx"
        annual.save(PUBLIC / axlsx)
        index["years"][str(y)] = {"xlsx": axlsx, "xlsxName": f'{cfg["document_name"]}_{y}.xlsx', "months": entries}
    (PUBLIC / "data" / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    return index
