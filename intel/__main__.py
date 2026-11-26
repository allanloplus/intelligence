"""CLI: python -m intel [run|collect|refresh|build|reassess YYYY-MM [--apply]|import-history ...]"""
import datetime as dt
import json
import sys

from . import classify, enrich, export, import_history, sources, store
from .common import DATA, settings, today

STATE = DATA / "_state" / "domestic.json"   # indicators published by NICS / TWCERT, keyed by CVE


def load_enricher():
    known = json.loads(STATE.read_text(encoding="utf-8")) if STATE.exists() else {}
    return enrich.Enricher(known)


def save_state(enricher):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(enricher.domestic, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def collect(enricher, lookback_days=7):
    cfg = settings()
    now = today(cfg)
    since = now - dt.timedelta(days=lookback_days)
    items, errors = sources.fetch_all(cfg)
    known = store.known_ids()
    todo = []
    for it in items:
        rid = store.rec_id(it["url"])
        if since <= it["date"] <= now and rid not in known:   # existing records are never re-created
            known.add(rid)
            todo.append((rid, it, enrich.page_text(it["url"])))
    for _, _, text in todo:   # register every alert first so indicators are shared across the batch
        enricher.register(text)
    fresh = {}
    for rid, it, text in todo:
        rec = {"id": rid, "date": it["date"].isoformat(), "source": it["source"], "title": it["title"],
               "url": it["url"], "origin": cfg["defaults"]["origin"], "progress": cfg["defaults"]["progress"]}
        rec.update(classify.classify(it, cfg, enricher, text))
        rec.update(auto=True, assessed=now.isoformat())
        fresh.setdefault((it["date"].year, it["date"].month), []).append(rec)
    # A busy news source keeps only its best item per day (highest severity, then feed relevance order).
    rank = {"高": 0, "中": 1, "低": 2, "現行不影響": 3}
    for src in cfg["sources"]:
        cap = src.get("max_per_day")
        if not cap:
            continue
        for key, recs in fresh.items():
            taken = {r["date"] for r in store.load_month(*key) if r["source"] == src["name"]}
            mine = sorted((r for r in recs if r["source"] == src["name"]), key=lambda r: rank[r["severity"]])
            drop, per_day = set(), {}
            for r in mine:
                per_day[r["date"]] = per_day.get(r["date"], 0) + 1
                if r["date"] in taken or per_day[r["date"]] > cap:
                    drop.add(r["id"])
            fresh[key] = [r for r in recs if r["id"] not in drop]
    for (y, m), recs in fresh.items():
        if recs:
            store.save_month(y, m, store.load_month(y, m) + recs)
    added = sum(len(v) for v in fresh.values())
    print(f"fetched {len(items)} items, added {added} new records")
    for e in errors:
        print("WARNING source problem:", e)
    return errors


def reassess_record(rec, enricher, now):
    """Recompute J–N for one record from its stored CVE list. Returns the list of changed columns."""
    if not rec.get("cves"):
        return []
    cols, detail, _ = enricher.assess(rec["cves"])
    changed = [k for k in enrich.VULN_COLS if rec.get(k) != cols[k]]
    # A failed lookup must never overwrite a value obtained earlier.
    if any(cols[k] == enrich.FAILED for k in enrich.VULN_COLS):
        return []
    rec.update(cols)
    rec["cve_detail"] = detail
    rec["assessed"] = now.isoformat()
    if changed:
        before = rec.get("basis", "")
        rec["basis"] = (before + "；" if before else "") + f"{now.isoformat()} 弱點欄位依最新資料更新"
    return changed


def refresh(enricher, days=60):
    """Dynamic adjustment (指引第五點): re-evaluate J–N of recent records, e.g. when a CVE
    enters CISA KEV or CISA publishes its SSVC decision after the alert was collected."""
    now = today()
    since = (now - dt.timedelta(days=days)).isoformat()
    total = 0
    for y, m in store.months():
        if f"{y}-{m:02d}-31" < since:
            continue
        recs = store.load_month(y, m)
        hit = 0
        for r in recs:
            if r["date"] >= since:   # J–N are factual lookups, so reviewed records are refreshed too
                changed = reassess_record(r, enricher, now)
                if changed:
                    hit += 1
                    print(f"  updated {r['date']} {r['title'][:40]}: {','.join(changed)}")
        if hit:
            store.save_month(y, m, recs)
        total += hit
    print(f"refresh: {total} records updated")


def reassess_month(ym, apply, enricher):
    """Re-derive J–N for every record of a month from its article page (used for imported months)."""
    y, m = map(int, ym.split("-"))
    cfg, now = settings(), today()
    recs = store.load_month(y, m)
    texts = {r["id"]: enrich.page_text(r["url"]) for r in recs}
    for t in texts.values():
        enricher.register(t)
    diffs = 0
    for r in recs:
        it = {"title": r["title"], "url": r["url"]}
        if r["source"] == "NICS" or "/cp-169-" in r["url"]:
            it["category"] = classify.CAT_VULN
        new = classify.classify(it, cfg, enricher, texts[r["id"]])
        changed = [k for k in enrich.VULN_COLS if r.get(k) != new[k]]
        if changed:
            diffs += 1
            print(f"{r['date']} {r['source']} {r['title'][:38]}")
            print("    舊:", [r.get(k) for k in enrich.VULN_COLS], "\n    新:", [new[k] for k in enrich.VULN_COLS])
        if apply and not any(new[k] == enrich.FAILED for k in enrich.VULN_COLS):
            r.update({k: new[k] for k in enrich.VULN_COLS})
            r.update(cves=new["cves"], cve_detail=new["cve_detail"], assessed=now.isoformat())
    print(f"{ym}: {diffs}/{len(recs)} records differ" + ("（已套用）" if apply else "（僅比對，未寫入）"))
    if apply:
        store.save_month(y, m, recs)


def main(argv):
    cmd = argv[0] if argv else "run"
    errors = []
    if cmd == "import-history":
        import_history.run(argv[1:])
    if cmd in ("collect", "run", "refresh", "reassess"):
        enricher = load_enricher()
        if cmd in ("collect", "run"):
            errors = collect(enricher, int(argv[1]) if len(argv) > 1 else 7)
        if cmd in ("refresh", "run"):
            refresh(enricher)
        if cmd == "reassess":
            reassess_month(argv[1], "--apply" in argv, enricher)
        if enricher.kev_set() is False:
            errors.append("CISA KEV 清單下載失敗")
            print("WARNING source problem: CISA KEV 清單下載失敗")
        save_state(enricher)
    if cmd in ("build", "run", "import-history") or "--apply" in argv:
        idx = export.build()
        print("site built:", {y: sum(m["count"] for m in v["months"]) for y, v in idx["years"].items()})
    # Data is saved and the site rebuilt first; a failing source then fails the job so someone is notified.
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
