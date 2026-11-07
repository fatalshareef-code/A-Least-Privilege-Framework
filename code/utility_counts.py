"""Raw numerators and denominators behind the Table 9 utility proxies (writes out/utility_raw_counts.csv)."""
import csv
DOS = {"dos", "captcha_dos", "felony_dos", "swearwords_dos", "offensive_email_dos"}
r = list(csv.DictReader(open("out/main.csv")))
att = [x for x in r if x["attack_type"] not in DOS | {"none"}]; cl = [x for x in r if x["attack_type"] == "none"]
U = [x for x in att if x["utility"] == "True"]; NU = [x for x in cl if x["utility"] == "True"]
w = csv.writer(open("out/utility_raw_counts.csv", "w", newline=""))
w.writerow(["config", "attacked_benign_admitted", "attacked_benign_total", "clean_benign_admitted", "clean_benign_total",
            "attacked_success_runs_with_refusal", "attacked_success_runs", "clean_success_runs_with_refusal", "clean_success_runs"])
for a in ["C2c", "C3s", "C3f", "C2tf", "C3p", "C3tf"]:
    w.writerow([a, sum(int(x[f"{a}_benign_admitted"]) for x in att), sum(int(x["n_benign"]) for x in att),
                sum(int(x[f"{a}_benign_admitted"]) for x in cl), sum(int(x["n_benign"]) for x in cl),
                sum(int(x[f"{a}_benign_admitted"]) < int(x["n_benign"]) for x in U), len(U),
                sum(int(x[f"{a}_benign_admitted"]) < int(x["n_benign"]) for x in NU), len(NU)])
