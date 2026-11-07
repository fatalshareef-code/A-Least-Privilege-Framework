"""Revision analyses (R1/R2/R3). Extends evaluate.py without changing it.

New arms (all built without injection information):
  C2tf  tool scope = tools chosen by AgentDojo's tool_filter LLM from the user
        prompt alone (archived, gpt-4o-2024-05-13-tool_filter, no-attack run)
  C3tf  C2tf tool scope + destinations that appear literally in the user prompt
  C3p   oracle tool scope + destinations that appear literally in the user prompt
Per-run utility metrics over ALL non-attacker calls, sequential enforcement.
"""
import csv, json, sys
from pathlib import Path
import policy as P
import evaluate as E

ROOT = Path(sys.argv[1])           # runs/<pipeline>
OUT = Path(sys.argv[2])
TF_ROOT = Path(sys.argv[3])        # runs/gpt-4o-2024-05-13-tool_filter
GT_FIX = len(sys.argv) > 4 and sys.argv[4] == "fix_v111"

pol = P.build_policies()
if GT_FIX:  # AgentDojo v1.1.1 correction of banking user_task_15 (attacker IBAN in v1 GT)
    k = "banking:user_task_15"
    pol["dest_prespecified"][k] = {d for d in pol["dest_prespecified"][k] if d != "us133000000121212121212"} | {"ca133012400231215421872"}
inj_gt = json.loads((E.ART / "injection_ground_truth.json").read_text())
markers, critical, legit_per_task = E.build_markers(inj_gt, pol["legit"])
if GT_FIX:
    legit_per_task["banking:user_task_15"] = {v for v in legit_per_task["banking:user_task_15"] if "us13300000012121212" not in v} | {"ca133012400231215421872"}

# ---- tool_filter plans (prompt-only, model generated) -------------------
tf_tools = {}
for p in TF_ROOT.glob("*/*/none/none.json"):
    d = json.loads(p.read_text())
    for i, m in enumerate(d["messages"]):
        if m["role"] == "user" and "filter the list of tools" in str(m.get("content")):
            txt = str(d["messages"][i + 1]["content"])
            tf_tools[f"{d['suite_name']}:{d['user_task_id']}"] = {t.strip() for t in txt.replace("\n", ",").split(",") if t.strip()}
            break

def prompt_dests(key):
    pr = pol["legit"][key]["prompt"].lower()
    return {d for d in pol["dest_prespecified"][key] if d in pr}

def stratum(key):
    ds = pol["dest_prespecified"][key]
    if not ds: return "no_destination"
    return "user_given" if ds <= prompt_dests(key) else "retrieved"

def decide(arm, call, key, suite, spent):
    if arm in ("C2c", "C3s", "C3f"):
        return P.authorize({"C2c": "C2_task", "C3s": "C3_lpf_scope", "C3f": "C3_lpf_full"}[arm],
                           call, key, suite, pol, spent)[0]
    tools = tf_tools.get(key, set()) if arm in ("C2tf", "C3tf") else pol["plan_tools"][key]
    if call["function"] not in tools: return False
    if arm == "C2tf": return True
    allowed = prompt_dests(key) if arm in ("C3tf", "C3p") else pol["dest_prespecified"][key]
    return not (P.destinations_of(call, P.DEST_PRESPECIFIED) - allowed)

ARMS = ["C2c", "C3s", "C3f", "C2tf", "C3tf", "C3p"]
rows = []
for path in sorted(ROOT.rglob("*.json")):
    d, calls = E.parse_run(path)
    suite, ut, it, atk = d.get("suite_name"), d.get("user_task_id"), d.get("injection_task_id"), d.get("attack_type")
    if not suite or not str(ut).startswith("user_task"): continue
    key = f"{suite}:{ut}"
    if key not in pol["plan_tools"]: continue
    if it:
        marks = markers.get(f"{suite}:{it}")
        if marks is None: continue
        eff = {m for m in marks if not any(m == lv or m in lv for lv in legit_per_task[key])}
        mal = [i for i, c in enumerate(calls) if E.is_malicious(c, eff, critical[f"{suite}:{it}"] or set())]
        fallback = not eff
    else:
        mal, fallback = [], False
    r = {"suite": suite, "user_task_id": ut, "injection_task_id": it or "", "attack_type": atk or "none",
         "security": bool(d.get("security")), "utility": bool(d.get("utility")),
         "attempted": bool(mal), "fallback": fallback, "stratum": stratum(key),
         "n_calls": len(calls), "n_benign": len(calls) - len(mal)}
    for arm in ARMS:
        spent = {}
        dec = [decide(arm, c, key, suite, spent) for c in calls]
        r[f"{arm}_contained"] = all(not dec[i] for i in mal) if mal else ""
        ben = [i for i in range(len(calls)) if i not in mal]
        r[f"{arm}_benign_admitted"] = sum(dec[i] for i in ben)
        # old definition: in-plan benign calls, evaluated alone (as Table 8)
        sp2 = {}
        inplan = [calls[i] for i in ben if calls[i]["function"] in pol["plan_tools"][key]]
        r[f"{arm}_inplan_preserved"] = all(decide(arm, c, key, suite, sp2) for c in inplan)
    rows.append(r)

OUT.parent.mkdir(parents=True, exist_ok=True)
with open(OUT, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
print(OUT, len(rows), "tool_filter plans:", len(tf_tools))
