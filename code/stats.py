import csv, itertools, json, numpy as np
from scipy import stats
DOS={"dos","captcha_dos","felony_dos","swearwords_dos","offensive_email_dos"}
rows=[r for r in csv.DictReader(open("out/main.csv")) if r['attack_type'] not in DOS|{'none'} and r['attempted']=='True']
T=lambda v: v=="True"
dims={"case":lambda r:(r['suite'],r['user_task_id'],r['injection_task_id']),"inj":lambda r:(r['suite'],r['injection_task_id']),"tmpl":lambda r:r['attack_type'],"user":lambda r:(r['suite'],r['user_task_id'])}
def cgm(y, ds):
    n=len(y); e=y-y.mean(); V=0
    for k in range(1,len(ds)+1):
        for comb in itertools.combinations(ds,k):
            ids=[tuple(dims[d](r) for d in comb) for r in rows]
            s={}
            for i,e_ in zip(ids,e): s[i]=s.get(i,0)+e_
            V+=(-1)**(k+1)*sum(v*v for v in s.values())
    V=max(V,0)/n**2; G=min(len({dims[d](r) for r in rows}) for d in ds)
    se=np.sqrt(V); t=stats.t.ppf(.975,G-1)
    return [round(100*y.mean(),1),round(100*(y.mean()-t*se),1),round(100*(y.mean()+t*se),1),round(100*se,2),G]
def wild(y, d="tmpl", B=9999, seed=20260918):
    # wild cluster bootstrap-t (restricted not needed for CI; unrestricted, Webb 6-point weights)
    ids=[dims[d](r) for r in rows]; G=sorted(set(ids)); gi=np.array([G.index(i) for i in ids])
    n=len(y); mu=y.mean(); e=y-mu
    def se_of(res):
        s=np.bincount(gi,weights=res,minlength=len(G)); return np.sqrt((s**2).sum())/n
    se0=se_of(e); rng=np.random.default_rng(seed)
    W=np.array([-np.sqrt(1.5),-1,-np.sqrt(.5),np.sqrt(.5),1,np.sqrt(1.5)])
    ts=[]
    for b in range(B):
        w=rng.choice(W,len(G))[gi]; yb=mu+e*w; eb=yb-yb.mean()
        ts.append((yb.mean()-mu)/se_of(eb))
    lo,hi=np.quantile(ts,[.025,.975])
    return [round(100*mu,1),round(100*(mu-hi*se0),1),round(100*(mu-lo*se0),1),len(G)]
out={}
for name,f in {"C2c":lambda r:T(r['C2c_contained']),"C3s":lambda r:T(r['C3s_contained']),"C3f":lambda r:T(r['C3f_contained']),
               "C3s-C2c":lambda r:T(r['C3s_contained'])-T(r['C2c_contained'])}.items():
    y=np.array([f(r) for r in rows],float)
    out[name]={"threeway_case_inj_tmpl":cgm(y,["case","inj","tmpl"]),"fourway_plus_user":cgm(y,["case","inj","tmpl","user"]),"wild_tmpl":wild(y),"wild_inj":wild(y,"inj")}
json.dump(out,open("out/stats.json","w"),indent=1)
for k,v in out.items(): print(k,v)
