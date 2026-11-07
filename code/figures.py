"""Manuscript figures for the archived-replay evaluation.

House style: serif type, accent 1B4F72, no boxes, separate figures,
95% cluster-bootstrap intervals on every measured bar.
"""
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ART = Path(__file__).resolve().parent / "artifacts"
OUT = Path(__file__).resolve().parent / "figures"
OUT.mkdir(exist_ok=True)

ACCENT = "#1B4F72"
MUTED = "#B7950B"
GREY = "#7F8C8D"
LIGHT = "#AEB6BF"

plt.rcParams.update({
    "font.family": "serif",
    "font.serif": ["Liberation Serif", "Times New Roman", "DejaVu Serif"],
    "font.size": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.edgecolor": "#333333",
    "axes.labelcolor": "#222222",
    "text.color": "#222222",
    "xtick.color": "#333333",
    "ytick.color": "#333333",
    "figure.dpi": 200,
})

LABELS = {
    "C1_none": "C1\nno controls",
    "C2_broad": "C2a\nbroad suite role",
    "C2_suite_used": "C2b\nsuite role, unused\ntools pruned",
    "C2_task": "C2c\ntask-partitioned role\n(best static RBAC)",
    "C3_lpf_scope": "C3\nLPF task scope\n+ destination scope",
    "C3_lpf_full": "C3+\nLPF + approval gate",
}


def err(metrics, key):
    m = metrics[key]
    e = m["estimate"] * 100
    return e, [[e - m["low"] * 100], [m["high"] * 100 - e]]


def fig_containment(a):
    m = a["containment_conditional_on_attempt"]["security_case"]
    arms = ["C1_none", "C2_broad", "C2_suite_used", "C2_task", "C3_lpf_scope", "C3_lpf_full"]
    colors = [LIGHT, LIGHT, GREY, MUTED, ACCENT, ACCENT]
    fig, ax = plt.subplots(figsize=(8.2, 4.4))
    for i, arm in enumerate(arms):
        e, yerr = err(m["metrics"], arm)
        ax.bar(i, e, color=colors[i], width=0.66,
               edgecolor="none", alpha=1.0 if arm.startswith("C3") else 0.92)
        ax.errorbar(i, e, yerr=yerr, fmt="none", ecolor="#222222",
                    elinewidth=1.1, capsize=4)
        ax.text(i, e + (yerr[1][0] if yerr[1][0] else 0) + 2.4, f"{e:.1f}%",
                ha="center", fontsize=9.5, fontweight="bold")
    ax.set_xticks(range(len(arms)))
    ax.set_xticklabels([LABELS[x] for x in arms], fontsize=8.4)
    ax.set_ylabel("Attack containment (%)")
    ax.set_ylim(0, 100)
    ax.yaxis.grid(True, color="#E5E8E8", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title("Containment of attempted malicious tool calls, GPT-4o archived trajectories",
                 fontsize=10.5, pad=12)
    n = m["observations"]
    c = m["clusters"]
    fig.text(0.5, -0.015,
             f"n = {n} runs in which the model attempted the attacker's action; "
             f"{c} security-case clusters; 95% cluster-bootstrap intervals",
             ha="center", fontsize=8.4, color="#555555")
    fig.tight_layout()
    fig.savefig(OUT / "fig_containment_by_configuration.png", bbox_inches="tight")
    plt.close(fig)


def fig_tradeoff(a, a_ref):
    arms = ["C2_broad", "C2_task", "C3_lpf_scope", "C3_lpf_full"]
    cont = a["containment_conditional_on_attempt"]["security_case"]["metrics"]
    util = a["legitimate_call_preservation"]["user_task"]["metrics"]
    cont_r = a_ref["containment_conditional_on_attempt"]["security_case"]["metrics"]
    util_r = a_ref["legitimate_call_preservation"]["user_task"]["metrics"]

    fig, ax = plt.subplots(figsize=(7.0, 5.0))
    spec = {
        "C2_broad": ("C2a broad role", (0, -20), "center"),
        "C2_task": ("C2c task-partitioned role", (-10, 6), "right"),
        "C3_lpf_scope": ("C3 LPF, scoping only", (7, -4), "left"),
        "C3_lpf_full": ("C3+ LPF with approval gate", (-9, -14), "right"),
    }
    for arm in arms:
        x = util[arm]["estimate"] * 100
        y = cont[arm]["estimate"] * 100
        label, off, ha = spec[arm]
        ax.scatter(x, y, s=66, color=ACCENT if arm.startswith("C3") else MUTED, zorder=3)
        ax.annotate(label, (x, y), textcoords="offset points",
                    xytext=off, ha=ha, fontsize=8.8)
    xr = util_r["C3_lpf_scope"]["estimate"] * 100
    yr = cont_r["C3_lpf_scope"]["estimate"] * 100
    ax.scatter(xr, yr, s=66, facecolor="none", edgecolor=ACCENT, linewidth=1.6, zorder=3)
    ax.annotate("LPF, post-hoc refined schema\n(sensitivity only)", (xr, yr),
                textcoords="offset points", xytext=(4, 12), ha="left",
                fontsize=8.8, color="#555555")
    ax.annotate("", xy=(xr, yr), xytext=(util["C3_lpf_scope"]["estimate"] * 100,
                                         cont["C3_lpf_scope"]["estimate"] * 100),
                arrowprops=dict(arrowstyle="->", color="#AAAAAA", linewidth=1.0,
                                linestyle=(0, (3, 2))), zorder=1)
    ax.set_xlabel("Legitimate call sets preserved (%)")
    ax.set_ylabel("Attack containment (%)")
    ax.set_xlim(66, 108)
    ax.set_ylim(-8, 104)
    ax.grid(True, color="#E5E8E8", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title("Containment is bought with utility", fontsize=10.5, pad=10)
    fig.tight_layout()
    fig.savefig(OUT / "fig_containment_utility_tradeoff.png", bbox_inches="tight")
    plt.close(fig)


def fig_stacking(rows):
    fig, ax = plt.subplots(figsize=(7.8, 4.4))
    names = [r[0] for r in rows]
    base = [r[1] * 100 for r in rows]
    after = [r[2] * 100 for r in rows]
    x = range(len(rows))
    ax.bar([i - 0.19 for i in x], base, width=0.38, color=MUTED, label="No deployment-layer control")
    ax.bar([i + 0.19 for i in x], after, width=0.38, color=ACCENT, label="With LPF enforcement")
    for i, (b, af) in enumerate(zip(base, after)):
        ax.text(i - 0.19, b + 0.9, f"{b:.1f}%", ha="center", fontsize=8.6)
        ax.text(i + 0.19, af + 0.9, f"{af:.1f}%", ha="center", fontsize=8.6)
    ax.set_xticks(list(x))
    ax.set_xticklabels(names, fontsize=8.4)
    ax.set_ylabel("Runs reaching an unauthorised action (%)")
    ax.legend(frameon=False, fontsize=9)
    ax.yaxis.grid(True, color="#E5E8E8", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_title("Deployment-layer containment composes with model-level defences",
                 fontsize=10.5, pad=12)
    fig.text(0.5, -0.02,
             "Measured on the same archived runs; no independence assumption is made.",
             ha="center", fontsize=8.4, color="#555555")
    fig.tight_layout()
    fig.savefig(OUT / "fig_composition_with_model_defences.png", bbox_inches="tight")
    plt.close(fig)


def main():
    a = json.loads((ART / "run_main" / "analysis.json").read_text())
    a_ref = json.loads((ART / "run_main" / "analysis_refined.json").read_text())
    fig_containment(a)
    fig_tradeoff(a, a_ref)

    rows = []
    pipelines = [("none (undefended)", "run_main"),
                 ("repeat user prompt", "run_repeat_user_prompt"),
                 ("spotlighting", "run_spotlighting_with_delimiting"),
                 ("tool filter", "run_tool_filter"),
                 ("PI detector", "run_transformers_pi_detector")]
    for label, d in pipelines:
        x = json.loads((ART / d / "analysis.json").read_text())
        rate = x["counts"]["runs_with_attempted_malicious_call"] / x["counts"]["non_dos_runs"]
        lpf = x["containment_conditional_on_attempt"]["security_case"]["metrics"]["C3_lpf_scope"]["estimate"]
        rows.append((label, rate, rate * (1 - lpf)))
    fig_stacking(rows)
    print("\n".join(str(p) for p in sorted(OUT.iterdir())))


if __name__ == "__main__":
    main()
