"""CLI: python -m intel [collect|build|run|import-history ...]"""
import datetime as dt
import sys

from . import classify, enrich, export, import_history, sources, store
from .common import settings, today


def collect(lookback_days=7):
    cfg = settings()
    now = today(cfg)
    since = now - dt.timedelta(days=lookback_days)
    items, errors = sources.fetch_all(cfg)
    known = store.known_ids()
    enricher = enrich.Enricher()
    fresh = {}
    for it in items:
        if not (since <= it["date"] <= now):
            continue
        rid = store.rec_id(it["url"])
        if rid in known:
            continue  # existing records are never touched, so manual edits survive
        known.add(rid)
        rec = {"id": rid, "date": it["date"].isoformat(), "source": it["source"], "title": it["title"],
               "url": it["url"], "origin": cfg["defaults"]["origin"], "progress": cfg["defaults"]["progress"]}
        rec.update(classify.classify(it, cfg, enricher))
        rec["auto"] = True
        fresh.setdefault((it["date"].year, it["date"].month), []).append(rec)
    for (y, m), recs in fresh.items():
        store.save_month(y, m, store.load_month(y, m) + recs)
    added = sum(len(v) for v in fresh.values())
    print(f"fetched {len(items)} items, added {added} new records")
    for e in errors:
        print("WARNING source problem:", e)
    return added, errors


def main(argv):
    cmd = argv[0] if argv else "run"
    if cmd == "import-history":
        import_history.run(argv[1:])
    errors = []
    if cmd in ("collect", "run"):
        _, errors = collect(int(argv[1]) if len(argv) > 1 else 7)
    if cmd in ("build", "run", "import-history"):
        idx = export.build()
        print("site built:", {y: sum(m["count"] for m in v["months"]) for y, v in idx["years"].items()})
    # Data is saved and the site rebuilt first; a failing source then fails the job so someone is notified.
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
