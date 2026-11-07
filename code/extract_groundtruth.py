"""Extract AgentDojo v1 ground-truth requirements.

Policy inputs are derived from LEGITIMATE user-task ground truth only.
Injection ground truth is extracted separately and is used ONLY at
evaluation time to label malicious calls. It never enters policy
construction.
"""
import json
from pathlib import Path

from agentdojo.task_suite.load_suites import get_suites

OUT = Path(__file__).resolve().parent / "artifacts"
OUT.mkdir(exist_ok=True)


def call_to_dict(c):
    return {"function": c.function, "args": {k: v for k, v in c.args.items()}}


def main():
    suites = get_suites("v1")
    legit, inject, suite_tools = {}, {}, {}

    for sname, suite in suites.items():
        env = suite.load_and_inject_default_environment({})
        suite_tools[sname] = sorted(t.name for t in suite.tools)

        for utid, ut in suite.user_tasks.items():
            try:
                gt = [call_to_dict(c) for c in ut.ground_truth(env)]
            except Exception as exc:  # environment-dependent ground truth
                gt = None
                print(f"  ! {sname}/{utid} ground truth failed: {exc}")
            legit[f"{sname}:{utid}"] = {
                "suite": sname,
                "user_task_id": utid,
                "prompt": ut.PROMPT,
                "ground_truth": gt,
            }

        for itid, it in suite.injection_tasks.items():
            try:
                gt = [call_to_dict(c) for c in it.ground_truth(env)]
            except Exception as exc:
                gt = None
                print(f"  ! {sname}/{itid} ground truth failed: {exc}")
            inject[f"{sname}:{itid}"] = {
                "suite": sname,
                "injection_task_id": itid,
                "goal": it.GOAL,
                "ground_truth": gt,
            }

    (OUT / "legitimate_ground_truth.json").write_text(json.dumps(legit, indent=1))
    (OUT / "injection_ground_truth.json").write_text(json.dumps(inject, indent=1))
    (OUT / "suite_tools.json").write_text(json.dumps(suite_tools, indent=1))

    print("user tasks:", len(legit), "with GT:", sum(v["ground_truth"] is not None for v in legit.values()))
    print("injection tasks:", len(inject), "with GT:", sum(v["ground_truth"] is not None for v in inject.values()))
    print("tools per suite:", {k: len(v) for k, v in suite_tools.items()})


if __name__ == "__main__":
    main()
