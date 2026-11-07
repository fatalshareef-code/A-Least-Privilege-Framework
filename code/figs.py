import json, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
plt.rcParams.update({"font.family": "Liberation Serif", "font.size": 11, "axes.spines.top": False, "axes.spines.right": False})
NAVY, GOLD, GREY, RED, GREEN = "#1B4F72", "#B8960C", "#8C9696", "#B03A2E", "#1E7B45"
OUT = "figs/"
import os; os.makedirs(OUT, exist_ok=True)
d = json.load(open("out/main_analysis.json"))
c = d["containment"]; p = d["inplan_preservation"]

# ---- Figure 4: containment by configuration
labels = ["C1\nno controls", "C2a\nbroad suite role", "C2b\npruned suite role", "C2c\noracle static reference\n(task tool allowlist)",
          "C3\nLPF, scoping only", "C3\nLPF with approval\nallowance"]
vals = [(0, 0, 0), (0, 0, 0), (6.4, 4.3, 8.7), tuple(c["C2c"][1:4]), tuple(c["C3s"][1:4]), tuple(c["C3f"][1:4])]
cols = [GREY, GREY, GREY, GOLD, NAVY, NAVY]
fig, ax = plt.subplots(figsize=(10, 5))
for i, (v, lo, hi) in enumerate(vals):
    ax.bar(i, v, 0.62, color=cols[i])
    if hi > lo: ax.errorbar(i, v, yerr=[[v - lo], [hi - v]], color="black", capsize=6, lw=1.3)
    ax.text(i, max(hi, v) + 2.5, f"{v:.1f}%", ha="center", fontweight="bold")
ax.set_xticks(range(6)); ax.set_xticklabels(labels, fontsize=10); ax.set_ylim(0, 100)
ax.set_ylabel("Attack containment (%)"); ax.yaxis.grid(True, color="#e6e6e6"); ax.set_axisbelow(True)
fig.tight_layout(); fig.savefig(OUT + "fig4.png", dpi=300); plt.close(fig)

# ---- Figure 5: containment vs preservation, oracle and non-oracle plans
pts = [("C2a broad suite role", 0.0, 100.0, GOLD, "o", (-10, 10), "right"),
       ("C2c oracle tool allowlist", c["C2c"][1], 100.0, GOLD, "o", (-10, 0), "right"),
       ("C3 scoping only and\nC3 with approval allowance", c["C3s"][1], p["C3s"][0], NAVY, "o", (-12, -16), "right"),
       ("", c["C3f"][1], p["C3f"][0], NAVY, "o", (0, 0), "left"),
       ("C3p", c["C3p"][1], p["C3p"][0], NAVY, "s", (8, 8), "left"),
       ("C2tf", c["C2tf"][1], p["C2tf"][0], GOLD, "s", (10, 0), "left"),
       ("C3tf", c["C3tf"][1], p["C3tf"][0], NAVY, "s", (10, 0), "left"),
       ("C3, refined schema (post hoc)", 90.2, 78.9, NAVY, "D", (-12, 12), "right")]
fig, ax = plt.subplots(figsize=(8, 5.4))
for name, y, x, col, m, off, ha in pts:
    face = "white" if m == "s" else col
    ax.scatter(x, y, s=70, marker=m, facecolor=face, edgecolor=col, linewidth=1.8, zorder=3)
    if name: ax.annotate(name, (x, y), xytext=off, textcoords="offset points", ha=ha, va="center", fontsize=9.5)
ax.set_xlim(45, 100.8); ax.set_ylim(-5, 100)
ax.set_xlabel("Runs with all benign in-plan calls admitted (%)"); ax.set_ylabel("Attack containment (%)")
ax.grid(True, color="#e6e6e6"); ax.set_axisbelow(True)
ax.scatter([], [], marker="o", color="#555555", label="main configurations (C2a; C2c and C3 with oracle plan)")
ax.scatter([], [], marker="s", facecolor="white", edgecolor="#555555", linewidth=1.5, label="reduced oracle information (C2tf, C3p, C3tf)")
ax.scatter([], [], marker="D", color="#555555", label="oracle plan, post-hoc refined schema")
ax.scatter([], [], marker="s", color=GOLD, label="tool scope only")
ax.scatter([], [], marker="s", color=NAVY, label="tool and destination scope")
ax.legend(loc="lower left", fontsize=8.5, frameon=False)
fig.tight_layout(); fig.savefig(OUT + "fig5.png", dpi=300); plt.close(fig)

# ---- Figure 6: composition (American spelling)
m = json.load(open("out/multimodel.json"))
rows = [("none (undefended)", "gpt-4o-2024-05-13"), ("repeat user prompt", "gpt-4o-2024-05-13-repeat_user_prompt"),
        ("spotlighting", "gpt-4o-2024-05-13-spotlighting_with_delimiting"), ("tool filter", "gpt-4o-2024-05-13-tool_filter"),
        ("PI detector", "gpt-4o-2024-05-13-transformers_pi_detector")]
fig, ax = plt.subplots(figsize=(10, 5))
for i, (lab, k) in enumerate(rows):
    a, r = m[k]["attempt_rate"], m[k]["residual"]
    ax.bar(i - 0.19, a, 0.38, color=GOLD, label="No deployment-layer control" if i == 0 else None)
    ax.bar(i + 0.19, r, 0.38, color=NAVY, label="With LPF enforcement" if i == 0 else None)
    ax.text(i - 0.19, a + 0.8, f"{a:.1f}%", ha="center"); ax.text(i + 0.19, r + 0.8, f"{r:.1f}%", ha="center")
ax.set_xticks(range(5)); ax.set_xticklabels([r[0] for r in rows]); ax.set_ylabel("Runs reaching an unauthorized action (%)")
ax.yaxis.grid(True, color="#e6e6e6"); ax.set_axisbelow(True); ax.legend(frameon=False)
fig.tight_layout(); fig.savefig(OUT + "fig6.png", dpi=300); plt.close(fig)

# ---- Diagram helpers
def box(ax, x, y, w, h, title, body="", col=NAVY, fill="#EAF1F6", fs=10.5):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fill, ec=col, lw=1.6))
    ax.text(x + w / 2, y + h - 0.16, title, ha="center", va="top", fontsize=fs, fontweight="bold", color=col)
    if body: ax.text(x + w / 2, y + h - 0.62, body, ha="center", va="top", fontsize=9, linespacing=1.35)
def arrow(ax, x1, y1, x2, y2, col="black", ls="-"):
    ax.annotate("", (x2, y2), (x1, y1), arrowprops=dict(arrowstyle="-|>", color=col, lw=1.5, ls=ls))

# Figure 1: one execution order
fig, ax = plt.subplots(figsize=(12, 3.5)); ax.set_xlim(0, 12); ax.set_ylim(0, 3.5); ax.axis("off")
ax.text(2.25, 3.4, "Task start (once per task)", ha="center", fontsize=10, style="italic")
ax.text(7.6, 3.4, "Every tool call", ha="center", fontsize=10, style="italic")
box(ax, 0.1, 1.3, 2.0, 1.9, "L1 Identity &\nDiscovery", "Attested or X.509\nagent identity\nRegistry, ownership,\nrisk tier")
box(ax, 2.4, 1.3, 2.0, 1.9, "L2 Token\nIssuance", "Proof of Intent checked\nby policy engine\nTask-scoped JIT token:\ntools + destinations")
box(ax, 5.0, 1.3, 2.0, 1.9, "L3 Runtime\nScreening", "Inputs and planned\naction screened against\ndeclared plan")
box(ax, 7.3, 1.3, 2.0, 1.9, "L2 Per-call\nValidation", "Tool and destination\nwithin token scope?\nHigh-impact: approval")
box(ax, 9.9, 2.35, 1.9, 0.85, "Execute", "", GREEN, "#E9F5EE")
box(ax, 9.9, 1.3, 1.9, 0.85, "Deny or escalate", "", RED, "#F8E9E7")
for x1, x2 in [(2.1, 2.4), (4.4, 5.0), (7.0, 7.3)]: arrow(ax, x1, 2.25, x2, 2.25)
arrow(ax, 9.3, 2.5, 9.9, 2.75); arrow(ax, 9.3, 2.0, 9.9, 1.75, RED)
box(ax, 0.1, 0.25, 11.7, 0.6, "L4 Signed audit log: identity, token, policy decisions, approvals, tool calls and outputs (no hidden reasoning)", "", "#5B2C6F", "#F3EDF6", fs=10)
for x in [1.1, 3.4, 6.0, 8.3]: arrow(ax, x, 1.3, x, 0.85, "#5B2C6F", "--")
fig.tight_layout(); fig.savefig(OUT + "fig1.png", dpi=300); plt.close(fig)

# Figure 2: token lifecycle with approval only on the high-impact branch
fig, ax = plt.subplots(figsize=(12, 3.0)); ax.set_xlim(0, 12); ax.set_ylim(0, 3.0); ax.axis("off")
steps = [("1 Task\nrequest", ""), ("2 Proof of\nIntent", "tools, destinations,\nhigh-impact actions"), ("3 Policy\nevaluation", "deny by default"),
         ("4 JIT token\nissued", "task-scoped,\ntime-bound"), ("5 Per-call\nvalidation", "tool + destination"), ("6 Revocation", "on completion\nor expiry")]
for i, (t, b) in enumerate(steps):
    box(ax, 0.1 + i * 2.0, 1.45, 1.7, 1.45, t, b)
    if i: arrow(ax, 0.1 + i * 2.0 - 0.3, 2.15, 0.1 + i * 2.0, 2.15)
box(ax, 4.6, 0.1, 3.2, 0.9, "Human approval", "high-impact actions only", RED, "#F8E9E7")
arrow(ax, 5.0, 1.45, 5.4, 1.0, RED); arrow(ax, 7.0, 1.0, 7.4, 1.45, RED)
fig.tight_layout(); fig.savefig(OUT + "fig2.png", dpi=300); plt.close(fig)

# Figure 3: L3 pipeline, author-written signatures, output to L2 per-call validation
fig, ax = plt.subplots(figsize=(12, 2.8)); ax.set_xlim(0, 12); ax.set_ylim(0, 2.8); ax.axis("off")
items = [("External input", "tool output, document,\nweb page, message", GREEN, "#E9F5EE"),
         ("Stage 1", "author-written structural\ninjection signatures", NAVY, "#EAF1F6"),
         ("Stage 2", "instruction-like content\nvs. declared task", NAVY, "#EAF1F6"),
         ("Stage 3", "planned action: external\ndestination, bulk disclosure", NAVY, "#EAF1F6"),
         ("L2 per-call\nvalidation", "", GREEN, "#E9F5EE")]
for i, (t, b, col, f) in enumerate(items):
    box(ax, 0.1 + i * 2.4, 1.2, 2.0, 1.45, t, b, col, f)
    if i: arrow(ax, 0.1 + i * 2.4 - 0.4, 1.95, 0.1 + i * 2.4, 1.95)
    if 1 <= i <= 3:
        arrow(ax, 1.1 + i * 2.4, 1.2, 1.1 + i * 2.4, 0.65, RED)
        ax.text(1.1 + i * 2.4, 0.45, "block or escalate", ha="center", fontsize=9.5, color=RED)
fig.tight_layout(); fig.savefig(OUT + "fig3.png", dpi=300); plt.close(fig)
print("ok")
