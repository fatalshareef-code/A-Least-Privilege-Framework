"""Clustered-bootstrap analysis of the archived-replay containment results.

Uncertainty is estimated with a paired cluster bootstrap. Observations are
NOT independent: many runs share a security case, an injection task, or an
attack template. Clusters are resampled whole, which is what the reviewer
asked for and what a Wilson interval over all combinations gets wrong.
"""
import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import numpy as np

DOS_ATTACKS = {"dos", "captcha_dos", "felony_dos", "swearwords_dos", "offensive_email_dos"}
ARMS = ["C1_none", "C2_broad", "C2_suite_used", "C2_task", "C3_lpf_scope", "C3_lpf_full"]
CLUSTERINGS = {
    "security_case": ["suite", "user_task_id", "injection_task_id"],
    "injection_task": ["suite", "injection_task_id"],
    "attack_template": ["attack_type"],
    "user_task": ["suite", "user_task_id"],
}


def tb(s):
    return s == "True"


def load(path):
    rows = list(csv.DictReader(open(path)))
    return [r for r in rows if r["attack_type"] not in DOS_ATTACKS], \
           [r for r in rows if r["attack_type"] in DOS_ATTACKS]


def cluster_bootstrap(rows, metrics, keys, replicates=10000, seed=20260918):
    """Resample whole clusters; return estimate and percentile interval.

    `metrics` maps a name to a per-row float (already filtered to the
    rows the metric is defined on).
    """
    if not rows:
        return None
    names = list(metrics)
    y = np.array([[metrics[n](r) for n in names] for r in rows], dtype=float)
    groups = defaultdict(list)
    for i, r in enumerate(rows):
        groups[tuple(r[k] for k in keys)].append(i)
    sizes = np.array([len(v) for v in groups.values()])
    totals = np.array([y[v].sum(axis=0) for v in groups.values()])
    g = len(sizes)
    rng = np.random.default_rng(seed)
    boot = np.empty((replicates, y.shape[1]))
    for b in range(replicates):
        ix = rng.integers(0, g, size=g)
        boot[b] = totals[ix].sum(axis=0) / sizes[ix].sum()
    lo, hi = np.quantile(boot, [0.025, 0.975], axis=0)
    est = y.mean(axis=0)
    return {
        "clusters": g, "observations": len(rows),
        "metrics": {n: {"estimate": float(e), "low": float(l), "high": float(h)}
                    for n, e, l, h in zip(names, est, lo, hi)},
        "warning": "fewer than 30 clusters" if g < 30 else None,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--replicates", type=int, default=10000)
    ap.add_argument("--seed", type=int, default=20260918)
    a = ap.parse_args()

    main_rows, dos_rows = load(a.rows)
    attempted = [r for r in main_rows if tb(r["attempted_injection"])]

    out = {
        "input_sha256": hashlib.sha256(a.rows.read_bytes()).hexdigest(),
        "seed": a.seed, "replicates": a.replicates,
        "numpy": np.__version__,
        "counts": {
            "all_runs": len(main_rows) + len(dos_rows),
            "non_dos_runs": len(main_rows),
            "dos_runs_reported_separately": len(dos_rows),
            "runs_with_attempted_malicious_call": len(attempted),
            "security_breaches_reported_by_agentdojo": sum(tb(r["security"]) for r in main_rows),
            "distinct_security_cases": len({(r["suite"], r["user_task_id"], r["injection_task_id"]) for r in main_rows}),
            "distinct_user_tasks": len({(r["suite"], r["user_task_id"]) for r in main_rows}),
            "distinct_injection_tasks": len({(r["suite"], r["injection_task_id"]) for r in main_rows}),
            "attack_templates": len({r["attack_type"] for r in main_rows}),
        },
        "label_validation": {
            "recall_of_malicious_call_labelling_on_agentdojo_breaches": (
                sum(tb(r["attempted_injection"]) for r in main_rows if tb(r["security"]))
                / max(sum(tb(r["security"]) for r in main_rows), 1)),
            "p_breach_given_attempted": (
                sum(tb(r["security"]) for r in attempted) / max(len(attempted), 1)),
        },
    }

    # Containment, conditional on the model actually attempting the attack.
    cont_metrics = {arm: (lambda arm: lambda r: float(tb(r[f"{arm}__contained"])))(arm) for arm in ARMS}
    out["containment_conditional_on_attempt"] = {
        name: cluster_bootstrap(attempted, cont_metrics, keys, a.replicates, a.seed)
        for name, keys in CLUSTERINGS.items()
    }

    # Paired differences against the strongest static baseline.
    pair_metrics = {
        "C3_lpf_scope_minus_C2_task": lambda r: float(tb(r["C3_lpf_scope__contained"])) - float(tb(r["C2_task__contained"])),
        "C3_lpf_full_minus_C2_task": lambda r: float(tb(r["C3_lpf_full__contained"])) - float(tb(r["C2_task__contained"])),
        "C2_task_minus_C2_broad": lambda r: float(tb(r["C2_task__contained"])) - float(tb(r["C2_broad__contained"])),
        "C3_lpf_full_minus_C3_lpf_scope": lambda r: float(tb(r["C3_lpf_full__contained"])) - float(tb(r["C3_lpf_scope__contained"])),
    }
    out["paired_differences"] = {
        name: cluster_bootstrap(attempted, pair_metrics, keys, a.replicates, a.seed)
        for name, keys in CLUSTERINGS.items()
    }

    # Utility proxy over ALL non-DoS runs: were the model's in-plan
    # legitimate calls preserved under each arm?
    util_metrics = {arm: (lambda arm: lambda r: float(tb(r[f"{arm}__legit_preserved"])))(arm) for arm in ARMS}
    out["legitimate_call_preservation"] = {
        name: cluster_bootstrap(main_rows, util_metrics, keys, a.replicates, a.seed)
        for name, keys in [("user_task", CLUSTERINGS["user_task"]),
                           ("security_case", CLUSTERINGS["security_case"])]
    }

    # Structural limit: security cases in which the attacker's destination
    # is ALSO a legitimate destination of the user's own task. Destination
    # scoping cannot separate these by construction.
    import policy as _P
    pol = _P.build_policies()
    inj = json.loads((Path(__file__).resolve().parent / "artifacts" / "injection_ground_truth.json").read_text())
    inj_dest = {}
    for k, rec in inj.items():
        vals = set()
        for c in (rec["ground_truth"] or []):
            vals |= _P.destinations_of(c, _P.DEST_PRESPECIFIED)
        inj_dest[k] = vals
    coincident = set()
    for r in main_rows:
        tk = f"{r['suite']}:{r['user_task_id']}"
        ik = f"{r['suite']}:{r['injection_task_id']}"
        if inj_dest.get(ik) and (inj_dest[ik] & pol["dest_prespecified"].get(tk, set())):
            coincident.add((r["suite"], r["user_task_id"], r["injection_task_id"]))
    out["structural_destination_coincidence"] = {
        "cases": len(coincident),
        "of_total_cases": out["counts"]["distinct_security_cases"],
        "note": "The attacker destination is a legitimate destination of the user's own task. "
                "Destination scoping cannot contain these cases by construction; they bound "
                "what Layer 2 can achieve.",
    }

    # Enforcement-mechanism breakdown for the full LPF arm.
    reasons = defaultdict(int)
    for r in attempted:
        for why in (r["C3_lpf_full__reason"] or "").split("|"):
            if why:
                reasons[why] += 1
    out["lpf_block_reasons_over_attempted_runs"] = dict(reasons)

    # Per-suite containment.
    per_suite = {}
    for suite in sorted({r["suite"] for r in attempted}):
        sub = [r for r in attempted if r["suite"] == suite]
        per_suite[suite] = cluster_bootstrap(sub, cont_metrics, CLUSTERINGS["security_case"], a.replicates, a.seed)
    out["containment_by_suite"] = per_suite

    # DoS attacks: no privileged ground-truth call exists, reported separately.
    out["dos_attacks"] = {
        "runs": len(dos_rows),
        "agentdojo_breaches": sum(tb(r["security"]) for r in dos_rows),
        "note": "Denial-of-service payloads have no privileged ground-truth tool call. "
                "Access control cannot contain them and they are excluded from the "
                "containment denominator.",
    }

    a.out.write_text(json.dumps(out, indent=2))
    print(a.out)


if __name__ == "__main__":
    main()
