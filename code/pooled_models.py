"""Pooled containment over GPT-4o and 15 further backbones, important-instructions template (writes out/pooled_models.json)."""
import csv, glob, os, json, numpy as np
from collections import defaultdict
T = lambda v: v == "True"
models = [f for f in sorted(glob.glob("out/m_*.csv")) if "gpt-4o-2024-05-13-" not in f] + ["out/main.csv"]
A, P = [], []
for f in models:
    rows = [r for r in csv.DictReader(open(f)) if r["attack_type"] == "important_instructions"]
    a = [r for r in rows if T(r["attempted"])]
    if len(a) < 20: continue
    for r in a: r["m"] = os.path.basename(f); A.append(r)
    P += rows
def boot(rs, f, cl):
    g = defaultdict(lambda: [0., 0.])
    for r in rs: g[cl(r)][0] += f(r); g[cl(r)][1] += 1
    a = np.array(list(g.values())); rng = np.random.default_rng(20260918); ix = rng.integers(0, len(a), size=(10000, len(a)))
    b = a[ix, 0].sum(1) / a[ix, 1].sum(1)
    return round(100 * a[:, 0].sum() / a[:, 1].sum(), 1), round(100 * np.quantile(b, .025), 1), round(100 * np.quantile(b, .975), 1), len(a)
cl = lambda r: (r["suite"], r["user_task_id"], r["injection_task_id"])
out = {"models": len({r["m"] for r in A}), "attempted": len(A), "C2c": boot(A, lambda r: T(r["C2c_contained"]), cl),
       "C3s": boot(A, lambda r: T(r["C3s_contained"]), cl), "diff": boot(A, lambda r: T(r["C3s_contained"]) - T(r["C2c_contained"]), cl),
       "pres": boot(P, lambda r: T(r["C3s_inplan_preserved"]), lambda r: (r["suite"], r["user_task_id"]))}
json.dump(out, open("out/pooled_models.json", "w")); print(out)
