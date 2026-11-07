import csv,json,sys
from collections import Counter
import policy as P, evaluate as E
from pathlib import Path
RUNS=Path(sys.argv[1]); PKG=Path(sys.argv[2])
DOS={"dos","captcha_dos","felony_dos","swearwords_dos","offensive_email_dos"}
pol=P.build_policies(); inj=json.loads((E.ART/"injection_ground_truth.json").read_text())
markers,critical,lpt=E.build_markers(inj,pol["legit"])
ref={ (r['suite'],r['user_task_id'],r['injection_task_id'],r['attack_type']):r for r in csv.DictReader(open(PKG/"artifacts/run_main/replay_rows_refined.csv"))}
inj_dest={k:set().union(*[P.destinations_of(c,P.DEST_PRESPECIFIED) for c in (v['ground_truth'] or [])]) if v['ground_truth'] else set() for k,v in inj.items()}
def coincident(s,u,i): return bool(inj_dest.get(f"{s}:{i}",set()) & pol['dest_prespecified'][f"{s}:{u}"])
out={}
for arm,parm in [("C3s","C3_lpf_scope"),("C3f","C3_lpf_full")]:
    cats=Counter(); sub=Counter(); att=Counter(); ex=[]
    for p in sorted(RUNS.rglob("*.json")):
        d,calls=E.parse_run(p); s,u,i,a=d.get("suite_name"),d.get("user_task_id"),d.get("injection_task_id"),d.get("attack_type")
        if not(s and u and i and a) or a in DOS: continue
        k=f"{s}:{u}"; m=markers.get(f"{s}:{i}")
        if m is None: continue
        eff={x for x in m if not any(x==lv or x in lv for lv in lpt[k])}
        mal=[c for c in calls if E.is_malicious(c,eff,critical[f"{s}:{i}"] or set())]
        if not mal: continue
        sp={}; dec=[]
        seq=[P.authorize(parm,c,k,s,pol,sp)[0] for c in calls]
        malidx=[j for j,c in enumerate(calls) if E.is_malicious(c,eff,critical[f"{s}:{i}"] or set())]
        # attribution (sequential, first blocking reason of each malicious call; run-level most restrictive)
        if all(not seq[j] for j in malidx):
            reasons=set()
            sp={}
            for j,c in enumerate(calls):
                ok,why=P.authorize(parm,c,k,s,pol,sp)
                if j in malidx: reasons.add(why)
            att["tool_scope" if reasons=={"tool_scope"} else ("approval_gate" if "approval_gate" in reasons else ("argument_scope" if reasons<= {"tool_scope","argument_scope"} else str(reasons)))]+=1
            continue
        att["residual"]+=1
        adm=[calls[j] for j in malidx if seq[j]]
        if coincident(s,u,i): cats["coincidence"]+=1; continue
        if ref[(s,u,i,a)][f"{parm}__contained"]=="True": cats["schema_absent"]+=1; continue
        cats["unexplained"]+=1
        c=adm[0]; dest=P.destinations_of(c,P.DEST_PRESPECIFIED)
        if not eff: t="fallback_label"
        elif not dest: t="no_destination_argument:"+c['function']
        elif dest<=pol['dest_prespecified'][k]: t="destination_in_plan"
        else: t="other"
        sub[t]+=1; ex.append((s,u,i,a,c['function'],json.dumps(c['args'])[:150]))
    out[arm]={"attribution":dict(att),"residual":dict(cats),"unexplained_sub":dict(sub)}
    if arm=="C3s": json.dump(ex,open("out/unexplained_examples.json","w"),indent=0)
json.dump(out,open("out/residual.json","w"),indent=1); print(json.dumps(out,indent=1))
