import csv, json, sys
from collections import defaultdict, Counter
import numpy as np

DOS = {"dos", "captcha_dos", "felony_dos", "swearwords_dos", "offensive_email_dos"}
R = 10000; SEED = 20260918
rows = list(csv.DictReader(open(sys.argv[1])))
att_rows = [r for r in rows if r["attack_type"] not in DOS and r["attack_type"] != "none"]
none_rows = [r for r in rows if r["attack_type"] == "none"]
A = [r for r in att_rows if r["attempted"] == "True"]
T = lambda v: v == "True"
case = lambda r: (r["suite"], r["user_task_id"], r["injection_task_id"])
utask = lambda r: (r["suite"], r["user_task_id"])

def boot(rs, num, den, cl, reps=R):
    """Ratio estimator sum(num)/sum(den) with whole-cluster resampling."""
    g = defaultdict(lambda: [0.0, 0.0])
    for r in rs:
        k = cl(r); g[k][0] += num(r); g[k][1] += den(r)
    a = np.array(list(g.values()))
    rng = np.random.default_rng(SEED)
    ix = rng.integers(0, len(a), size=(reps, len(a)))
    b = a[ix, 0].sum(1) / a[ix, 1].sum(1)
    est = a[:, 0].sum() / a[:, 1].sum()
    return [round(100 * est, 1), round(100 * np.quantile(b, .025), 1), round(100 * np.quantile(b, .975), 1), len(a)]

out = {"n_attack_runs": len(att_rows), "n_attempted": len(A), "n_no_attack": len(none_rows)}
ARMS = ["C2c", "C3s", "C3f", "C2tf", "C3tf", "C3p"]
out["containment"] = {a: [sum(T(r[f"{a}_contained"]) for r in A)] + boot(A, lambda r: T(r[f"{a}_contained"]), lambda r: 1, case) for a in ARMS}
out["paired"] = {
    "C3s-C2c": boot(A, lambda r: T(r["C3s_contained"]) - T(r["C2c_contained"]), lambda r: 1, case),
    "C3tf-C2tf": boot(A, lambda r: T(r["C3tf_contained"]) - T(r["C2tf_contained"]), lambda r: 1, case),
    "C3p-C2c": boot(A, lambda r: T(r["C3p_contained"]) - T(r["C2c_contained"]), lambda r: 1, case)}
out["inplan_preservation"] = {a: boot(att_rows, lambda r: T(r[f"{a}_inplan_preserved"]), lambda r: 1, utask) for a in ARMS}
# R1.3 (i) share of all non-attacker calls admitted, attacked runs
out["i_benign_calls_admitted"] = {a: boot(att_rows, lambda r: int(r[f"{a}_benign_admitted"]), lambda r: int(r["n_benign"]), utask) for a in ARMS}
# (ii) utility-successful attacked runs with any benign call blocked
U = [r for r in att_rows if T(r["utility"])]
out["ii_util_success_runs"] = len(U)
out["ii_any_benign_blocked_in_util_success"] = {a: boot(U, lambda r: int(r[f"{a}_benign_admitted"]) < int(r["n_benign"]), lambda r: 1, utask) for a in ARMS}
# (iii) no-attack runs
NU = [r for r in none_rows if T(r["utility"])]
out["iii_no_attack"] = {"runs": len(none_rows), "util_success": len(NU),
    "calls_admitted": {a: boot(none_rows, lambda r: int(r[f"{a}_benign_admitted"]), lambda r: int(r["n_benign"]), utask) for a in ARMS},
    "util_success_runs_any_blocked": {a: boot(NU, lambda r: int(r[f"{a}_benign_admitted"]) < int(r["n_benign"]), lambda r: 1, utask) for a in ARMS}}
# strata
st = {}
for s in ["user_given", "retrieved", "no_destination"]:
    rs = [r for r in att_rows if r["stratum"] == s]; ar = [r for r in rs if T(r["attempted"])]
    st[s] = {"user_tasks": len({utask(r) for r in rs}), "security_cases": len({case(r) for r in rs}), "attempted": len(ar),
             "containment": {a: boot(ar, lambda r: T(r[f"{a}_contained"]), lambda r: 1, case) for a in ["C2c", "C3s", "C3p", "C3tf"]},
             "inplan_preservation": {a: boot(rs, lambda r: T(r[f"{a}_inplan_preserved"]), lambda r: 1, utask) for a in ["C3s", "C3p", "C3tf"]}}
out["strata"] = st
out["fallback_attempted"] = sum(T(r["fallback"]) for r in A)
json.dump(out, open(sys.argv[2], "w"), indent=1)
print(json.dumps(out, indent=1))
