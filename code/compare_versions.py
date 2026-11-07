"""Compare AgentDojo v1 ground truth with later task-suite versions (writes out/version_diff.json)."""
import json
from agentdojo.task_suite.load_suites import get_suites
def gt(ver):
    out = {}
    for s, suite in get_suites(ver).items():
        env = suite.load_and_inject_default_environment({})
        for tid, t in list(suite.user_tasks.items()) + list(suite.injection_tasks.items()):
            try: out[f"{s}:{tid}"] = [{"function": c.function, "args": dict(c.args)} for c in t.ground_truth(env)]
            except Exception as e: out[f"{s}:{tid}"] = str(e)
    return out
v1 = gt("v1"); res = {}
for ver in ["v1.1", "v1.1.1", "v1.1.2", "v1.2", "v1.2.1"]:
    o = gt(ver)
    res[ver] = {k: {"v1": v1[k], ver: o[k]} for k in v1 if k in o and json.dumps(v1[k], default=str, sort_keys=True) != json.dumps(o[k], default=str, sort_keys=True)}
json.dump(res, open("out/version_diff.json", "w"), indent=1, default=str)
print({k: sorted(v) for k, v in res.items()})
