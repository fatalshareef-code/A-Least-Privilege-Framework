import csv,glob,json,os
import numpy as np
from collections import defaultdict
T=lambda v:v=="True"
def boot(rs,f,cl,reps=10000):
    g=defaultdict(lambda:[0.,0.])
    for r in rs: k=cl(r); g[k][0]+=f(r); g[k][1]+=1
    a=np.array(list(g.values())); rng=np.random.default_rng(20260918)
    ix=rng.integers(0,len(a),size=(reps,len(a))); b=a[ix,0].sum(1)/a[ix,1].sum(1)
    return round(100*a[:,0].sum()/a[:,1].sum(),1),round(100*np.quantile(b,.025),1),round(100*np.quantile(b,.975),1)
case=lambda r:(r['suite'],r['user_task_id'],r['injection_task_id'])
res={}
files=["out/main.csv"]+sorted(glob.glob("out/m_*.csv"))
for f in files:
    name="gpt-4o-2024-05-13" if f=="out/main.csv" else os.path.basename(f)[2:-4]
    rows=list(csv.DictReader(open(f)))
    att=[r for r in rows if r['attack_type']=='important_instructions']
    none=[r for r in rows if r['attack_type']=='none']
    A=[r for r in att if T(r['attempted'])]
    if len(A)<20: res[name]={"runs":len(att),"attempted":len(A)}; continue
    res[name]={"runs":len(att),"attempted":len(A),"attempt_rate":round(100*len(A)/len(att),1),
      "utility_attack":round(100*sum(T(r['utility']) for r in att)/len(att),1),
      "utility_none":round(100*sum(T(r['utility']) for r in none)/len(none),1),
      "C2c":boot(A,lambda r:T(r['C2c_contained']),case),"C3s":boot(A,lambda r:T(r['C3s_contained']),case),
      "diff":boot(A,lambda r:T(r['C3s_contained'])-T(r['C2c_contained']),case),
      "pres_C3s":round(100*sum(T(r['C3s_inplan_preserved']) for r in att)/len(att),1),
      "residual":round(100*sum(not T(r['C3s_contained']) for r in A)/len(att),1)}
json.dump(res,open("out/multimodel.json","w"),indent=1)
for k,v in res.items(): print(k,v)
