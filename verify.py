"""Compare regenerated outputs in code/out with the released ones in revision_outputs/ and artifacts/."""
import gzip, hashlib, json, pathlib, sys
root = pathlib.Path(__file__).resolve().parent; out = root / "code" / "out"; rel = root / "revision_outputs"
def h(b): return hashlib.sha256(b).hexdigest()
pairs = [(out / "run_main_check/replay_rows_prespecified.csv", root / "artifacts/run_main/replay_rows_prespecified.csv", False)]
for f in ["main_analysis.json", "main_fix.json", "stats.json", "residual.json", "multimodel.json", "pooled_models.json", "adjudication_summary.json", "utility_raw_counts.csv"]:
    pairs.append((out / f, rel / f, False))
pairs.append((out / "adj_sample.csv", rel / "label_adjudication_sample.csv", False))
pairs.append((out / "main.csv", rel / "row_level/gpt-4o-2024-05-13.csv.gz", True))
ok = True
for a, b, gz in pairs:
    if not a.exists(): print("MISSING", a.name); ok = False; continue
    ba = a.read_bytes(); bb = gzip.decompress(b.read_bytes()) if gz else b.read_bytes()
    same = h(ba) == h(bb); ok &= same
    print(("identical " if same else "DIFFERENT ") + a.name)
sys.exit(0 if ok else 1)
