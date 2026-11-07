"""Draw the stratified adjudication sample (40 runs per group, seed 20261106) from
out/adjudication_all.csv and attach the recorded verdicts from verdicts.csv."""
import csv, random, json
r = list(csv.DictReader(open("out/adjudication_all.csv")))
random.seed(20261106)
groups = {"marker": [x for x in r if x["label"] == "marker" and x["coincident"] == "False"],
          "fallback": [x for x in r if x["label"] == "fallback" and x["coincident"] == "False"],
          "coincident": [x for x in r if x["coincident"] == "True"]}
samp = []
for g, v in groups.items():
    for x in random.sample(v, 40): x = dict(x); x["stratum"] = g; samp.append(x)
for n, x in enumerate(samp): x["id"] = n
ver = {int(v["id"]): v for v in csv.DictReader(open("verdicts.csv"))}
for x in samp: x["adjudication"] = ver[x["id"]]["adjudication"]; x["note"] = ver[x["id"]]["note"]
with open("out/adj_sample.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(samp[0])); w.writeheader(); w.writerows(samp)
N = {g: len(v) for g, v in groups.items()}
res = {}
for g in N:
    sub = [x for x in samp if x["stratum"] == g]; conf = [x for x in sub if x["adjudication"] == "attack"]
    res[g] = {"population": N[g], "n": len(sub), "confirmed": len(conf),
              "C2c": sum(x["C2c"] == "True" for x in conf), "C3s": sum(x["C3s"] == "True" for x in conf),
              "false_labels_admitted_by_C3": sum(x["C3s"] == "False" for x in sub if x["adjudication"] != "attack")}
tot = sum(N.values())
prec = sum(N[g] * res[g]["confirmed"] / res[g]["n"] for g in N) / tot
wc = lambda a: round(100 * sum(N[g] / res[g]["n"] * res[g][a] for g in N) / sum(N[g] / res[g]["n"] * res[g]["confirmed"] for g in N), 1)
out = {"strata": res, "weighted_precision": round(100 * prec, 1), "weighted_C2c": wc("C2c"), "weighted_C3s": wc("C3s")}
json.dump(out, open("out/adjudication_summary.json", "w"), indent=1); print(out)
