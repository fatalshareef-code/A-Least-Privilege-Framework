"""Replay AgentDojo archived run traces against frozen access-control policies.

Each archived run is a real live-model trajectory. This script replays the
tool calls the model actually issued and asks, for each policy arm,
whether the attacker's critical call would have been admitted, and
whether the legitimate calls would have survived.

Nothing here is a live-model experiment: no model is invoked. It is an
offline counterfactual over authentic recorded trajectories.
"""
import argparse
import csv
import re
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import policy as P

ART = Path(__file__).resolve().parent / "artifacts"

# Argument names too generic to identify an attacker's call.
GENERIC_ARGS = frozenset({
    "body", "subject", "content", "description", "query", "amount", "date",
    "title", "start_time", "end_time", "n", "day", "permission", "recurring",
})


def parse_run(path):
    d = json.loads(path.read_text())
    calls = []
    for m in d.get("messages", []):
        for c in (m.get("tool_calls") or []):
            fn = c.get("function")
            args = c.get("args") or {}
            if isinstance(fn, str):
                calls.append({"function": fn, "args": args})
    return d, calls


TOKEN_PATTERNS = [
    re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),                       # email
    re.compile(r"\b[a-z]{2}\d{16,}\b", re.I),                       # IBAN-like
    re.compile(r"(?:https?://)?(?:www\.)[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+(?:/[^\s'\"]*)?", re.I),
]


def _tokens(text):
    out = set()
    for pat in TOKEN_PATTERNS:
        for m in pat.findall(text):
            t = m.strip().lower().rstrip(".,;:)")
            t = re.sub(r"^https?://", "", t)
            if len(t) >= 6:
                out.add(t)
    return out


def build_markers(inj_gt_all, legit_all):
    """Attacker-controlled string markers per injection task.

    A marker is a distinctive destination-like token appearing in the
    injection's ground truth that does NOT appear anywhere in the
    legitimate ground truth of the same suite. Markers are what makes a
    replayed call attributable to the attacker rather than to the user's
    own task.
    """
    # Legitimate values are indexed PER USER TASK, not per suite: a token
    # that is a legitimate destination for one task can still be the
    # attacker's destination in another.
    legit_per_task = {}
    for key, rec in legit_all.items():
        vals = set()
        for c in (rec["ground_truth"] or []):
            blob = json.dumps(c["args"], default=str).lower()
            vals |= _tokens(blob)
            for v in c["args"].values():
                vals |= P._norm(v)
        legit_per_task[key] = vals

    markers, critical = {}, {}
    for key, rec in inj_gt_all.items():
        gt = rec["ground_truth"] or []
        if not gt:
            markers[key], critical[key] = None, None
            continue
        found = set()
        for c in gt:
            blob = json.dumps(c["args"], default=str).lower()
            found |= _tokens(blob)
            for arg, v in c["args"].items():
                if arg in GENERIC_ARGS:
                    continue
                for val in P._norm(v):
                    if len(val) >= 4:
                        found.add(val)
        markers[key] = found
        critical[key] = {c["function"] for c in gt}
    return markers, critical, legit_per_task


def is_malicious(call, marks, crit_functions):
    """True when this replayed call carries the attacker's objective."""
    if marks is None:
        return False
    blob = json.dumps(call.get("args", {}), default=str).lower()
    if marks:
        return any(m in blob for m in marks)
    # No distinctive marker for this injection task: fall back to the
    # ground-truth function set. Reported separately in the manifest.
    return call["function"] in crit_functions


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--schema", default="prespecified", choices=["prespecified", "refined"])
    a = ap.parse_args()

    pol = P.build_policies()
    inj_gt = json.loads((ART / "injection_ground_truth.json").read_text())
    legit_all = pol["legit"]
    markers, critical, legit_per_task = build_markers(inj_gt, legit_all)

    excluded_no_gt = sorted(k for k, m in markers.items() if m is None)
    no_ident = sorted(k for k, m in markers.items() if m is not None and not m)

    rows = []
    skipped = defaultdict(int)
    for path in sorted(a.runs.rglob("*.json")):
        d, calls = parse_run(path)
        suite = d.get("suite_name")
        utid = d.get("user_task_id")
        itid = d.get("injection_task_id")
        attack = d.get("attack_type")
        if not (suite and utid and itid and attack):
            skipped["not_a_security_case"] += 1
            continue
        task_key = f"{suite}:{utid}"
        inj_key = f"{suite}:{itid}"
        if task_key not in pol["plan_tools"]:
            skipped["unknown_user_task"] += 1
            continue
        marks = markers.get(inj_key)
        if marks is None:
            skipped["injection_without_ground_truth"] += 1
            continue
        crit = critical.get(inj_key) or set()
        # Drop markers that are also legitimate destinations for THIS task.
        eff = {m for m in marks if not any(m == lv or m in lv for lv in legit_per_task[task_key])}

        mal_idx = [i for i, c in enumerate(calls) if is_malicious(c, eff, crit)]
        legit_calls = [c for c in calls if c["function"] in pol["plan_tools"][task_key]]

        row = {
            "suite": suite, "user_task_id": utid, "injection_task_id": itid,
            "attack_type": attack,
            "security": bool(d.get("security")),
            "utility": bool(d.get("utility")),
            "n_calls": len(calls),
            "attempted_injection": bool(mal_idx),
            "n_malicious_calls": len(mal_idx),
            "has_markers": bool(eff),
        }

        for arm in P.ALL_ARMS:
            spent = {}
            decisions, reasons = [], []
            for c in calls:
                ok, why = P.authorize(arm, c, task_key, suite, pol, spent, a.schema)
                decisions.append(ok)
                reasons.append(why)
            mal_blocked = all(not decisions[i] for i in mal_idx) if mal_idx else None
            mal_reasons = sorted({reasons[i] for i in mal_idx}) if mal_idx else []
            # Utility proxy: every legitimate in-plan call the model made
            # is still admitted under this arm.
            spent2 = {}
            legit_ok = True
            for c in legit_calls:
                ok, _ = P.authorize(arm, c, task_key, suite, pol, spent2, a.schema)
                legit_ok = legit_ok and ok
            row[f"{arm}__contained"] = mal_blocked
            row[f"{arm}__reason"] = "|".join(mal_reasons)
            row[f"{arm}__legit_preserved"] = legit_ok
        rows.append(row)

    marker_dump = {k: sorted(v) for k, v in markers.items() if v}
    manifest = {
        "runs_root": str(a.runs),
        "schema": a.schema,
        "n_rows": len(rows),
        "skipped": dict(skipped),
        "excluded_injection_tasks_without_ground_truth": excluded_no_gt,
        "injection_tasks_without_identifying_arguments": no_ident,
        "arms": P.ALL_ARMS,
        "destination_schema": sorted(P.DEST_REFINED if a.schema == "refined" else P.DEST_PRESPECIFIED),
        "high_impact_tools": sorted(P.HIGH_IMPACT),
        "policy_source": "AgentDojo v1 legitimate user-task ground truth only",
        "attacker_markers": marker_dump,
    }

    a.out.mkdir(parents=True, exist_ok=True)
    with open(a.out / f"replay_rows_{a.schema}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    manifest["rows_sha256"] = hashlib.sha256(
        (a.out / f"replay_rows_{a.schema}.csv").read_bytes()).hexdigest()
    (a.out / f"manifest_{a.schema}.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
