"""Frozen policy definitions for the LPF archived-replay evaluation.

CONSTRUCTION RULE: every policy object in this module is derived from
AgentDojo legitimate user-task ground truth and from static tool
semantics only. No injection task, attack payload, attack template or
run outcome is consulted. Injection ground truth is loaded separately in
evaluate.py and used only to LABEL malicious calls after policies are
fixed.
"""
import json
from pathlib import Path

ART = Path(__file__).resolve().parent / "artifacts"

# ---------------------------------------------------------------------------
# Destination schema.
#
# PRE-SPECIFIED mirrors the schema reported in the manuscript
# (recipient / email / channel style arguments). REFINED adds the URL and
# endpoint arguments and is reported ONLY as a post-hoc sensitivity
# analysis, never as a headline result.
# ---------------------------------------------------------------------------
DEST_PRESPECIFIED = frozenset({
    "recipient", "recipients", "email", "user_email", "channel",
})
DEST_REFINED = DEST_PRESPECIFIED | frozenset({
    "url", "link", "endpoint", "user", "participants", "file_id", "hotel",
})

# ---------------------------------------------------------------------------
# High-impact tools: external, destructive or privilege-changing effects.
# Derived from AgentDojo tool semantics, independent of any attack.
# ---------------------------------------------------------------------------
HIGH_IMPACT = frozenset({
    "send_email", "delete_email", "delete_file", "share_file",
    "create_calendar_event", "cancel_calendar_event",
    "add_calendar_event_participants", "reschedule_calendar_event",
    "append_to_file", "create_file",
    "reserve_hotel", "reserve_restaurant", "reserve_car_rental",
    "send_money", "schedule_transaction", "update_scheduled_transaction",
    "update_password", "update_user_info",
    "send_direct_message", "send_channel_message", "post_webpage",
    "invite_user_to_slack", "remove_user_from_slack", "add_user_to_channel",
})

# Pure scoping arms, evaluated like-for-like without any approval gate.
SCOPING_ARMS = ["C1_none", "C2_broad", "C2_suite_used", "C2_task", "C3_lpf_scope"]
# Full LPF adds the declared-budget approval gate on high-impact actions.
ALL_ARMS = SCOPING_ARMS + ["C3_lpf_full"]


def _norm(value):
    """Normalise an argument value into a set of comparable scalar strings."""
    if value is None:
        return set()
    if isinstance(value, (list, tuple, set)):
        out = set()
        for item in value:
            out |= _norm(item)
        return out
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return {str(value).strip().lower()}
    if isinstance(value, str):
        v = value.strip().lower()
        return {v} if v else set()
    return {str(value).strip().lower()}


def destinations_of(call, schema):
    out = set()
    for arg, value in call.get("args", {}).items():
        if arg in schema:
            out |= _norm(value)
    return out


def build_policies():
    """Return the frozen policy bundle.

    C2_broad      role tools = every tool in the suite. The baseline
                  configuration reported in the current manuscript.
    C2_suite_used role tools = union of ground-truth tool sets over the
                  connected components of the "two user tasks share at
                  least one required tool" graph. In AgentDojo v1 this
                  collapses to a single role in three of four suites, so
                  it is in practice the suite role with never-required
                  tools removed. Reported to show that pruning unused
                  tools from a broad role buys very little.
    C2_task       role tools = the exact ground-truth tool set of the
                  user task. This is the most restrictive static
                  tool-level policy that still admits every legitimate
                  call, and therefore upper-bounds containment over all
                  utility-preserving static tool-scoped RBAC designs.
    C3_lpf_scope  C2_task tool scope PLUS destination-argument scoping.
    C3_lpf_full   C3_lpf_scope PLUS the declared-budget approval gate.
    """
    legit = json.loads((ART / "legitimate_ground_truth.json").read_text())
    suite_tools = json.loads((ART / "suite_tools.json").read_text())

    plan_tools, plan_budget, dest_pre, dest_ref = {}, {}, {}, {}
    for key, rec in legit.items():
        calls = rec["ground_truth"] or []
        plan_tools[key] = {c["function"] for c in calls}
        budget = {}
        for c in calls:
            budget[c["function"]] = budget.get(c["function"], 0) + 1
        plan_budget[key] = budget
        dest_pre[key] = set().union(*[destinations_of(c, DEST_PRESPECIFIED) for c in calls]) if calls else set()
        dest_ref[key] = set().union(*[destinations_of(c, DEST_REFINED) for c in calls]) if calls else set()

    # Connected components over shared required tools, per suite.
    role_tools = {}
    for suite in suite_tools:
        keys = [k for k in legit if legit[k]["suite"] == suite]
        parent = {k: k for k in keys}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for i, a in enumerate(keys):
            for b in keys[i + 1:]:
                if plan_tools[a] & plan_tools[b]:
                    ra, rb = find(a), find(b)
                    if ra != rb:
                        parent[rb] = ra
        comps = {}
        for k in keys:
            comps.setdefault(find(k), set()).update(plan_tools[k])
        for k in keys:
            role_tools[k] = comps[find(k)]

    return {
        "suite_tools": {s: set(t) for s, t in suite_tools.items()},
        "plan_tools": plan_tools,
        "plan_budget": plan_budget,
        "role_tools": role_tools,
        "dest_prespecified": dest_pre,
        "dest_refined": dest_ref,
        "legit": legit,
    }


def authorize(arm, call, task_key, suite, pol, spent=None, schema="prespecified"):
    """Return (allowed, reason).

    `spent` is a mutable dict tracking how much of each declared
    high-impact budget this run has already consumed. It is required for
    C3_lpf_full and ignored otherwise.
    """
    fn = call["function"]

    if arm == "C1_none":
        return True, "no_control"

    if arm == "C2_broad":
        return (fn in pol["suite_tools"][suite]), ("admitted" if fn in pol["suite_tools"][suite] else "tool_scope")

    if arm == "C2_suite_used":
        return (fn in pol["role_tools"][task_key]), ("admitted" if fn in pol["role_tools"][task_key] else "tool_scope")

    if arm == "C2_task":
        return (fn in pol["plan_tools"][task_key]), ("admitted" if fn in pol["plan_tools"][task_key] else "tool_scope")

    if arm in ("C3_lpf_scope", "C3_lpf_full"):
        if fn not in pol["plan_tools"][task_key]:
            return False, "tool_scope"
        key = "dest_refined" if schema == "refined" else "dest_prespecified"
        args = DEST_REFINED if schema == "refined" else DEST_PRESPECIFIED
        if destinations_of(call, args) - pol[key][task_key]:
            return False, "argument_scope"
        if arm == "C3_lpf_full" and fn in HIGH_IMPACT:
            allowance = pol["plan_budget"][task_key].get(fn, 0)
            used = spent.get(fn, 0) if spent is not None else 0
            if used >= allowance:
                return False, "approval_gate"
            if spent is not None:
                spent[fn] = used + 1
        return True, "admitted"

    raise ValueError(arm)
