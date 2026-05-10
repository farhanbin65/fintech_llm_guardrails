"""
Modern academic charts — GSAM 2026 paper.
Clean, colourful, conference-ready.
"""

import json
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

os.makedirs("evaluation/charts", exist_ok=True)

# ── Palette ───────────────────────────────────────────────────────────────────
BLUE        = "#2563EB"
BLUE_LIGHT  = "#93C5FD"
TEAL        = "#0D9488"
TEAL_LIGHT  = "#99F6E4"
AMBER       = "#D97706"
AMBER_LIGHT = "#FDE68A"
SLATE       = "#334155"
SLATE_MID   = "#64748B"
SLATE_LIGHT = "#CBD5E1"
BG          = "#F8FAFC"
WHITE       = "#FFFFFF"
RED         = "#DC2626"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "axes.labelsize": 11,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.spines.left": False,
    "axes.spines.bottom": False,
    "axes.grid": True,
    "axes.grid.axis": "y",
    "grid.alpha": 0.25,
    "grid.linestyle": "-",
    "grid.color": SLATE_LIGHT,
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
    "savefig.pad_inches": 0.2,
    "axes.facecolor": BG,
    "figure.facecolor": WHITE,
    "xtick.bottom": False,
    "ytick.left": False,
})

# ── Chart 1: Block Rate ───────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 4.5))
systems = ["LLM Guard\n(DeBERTa-v3)", "Fintech LLM Guard\n(This Work)"]
rates   = [68.5, 100.0]
colours = [BLUE_LIGHT, BLUE]

for i, (val, col) in enumerate(zip(rates, colours)):
    ax.bar(i, val, width=0.5, color=col, zorder=3, linewidth=0)
    y_pos = val - 6 if val > 20 else val + 2
    color = WHITE if val > 20 else SLATE
    ax.text(i, y_pos, f"{val:.1f}%", ha="center", va="bottom",
            fontsize=16, fontweight="bold", color=color, zorder=5)

ax.annotate("", xy=(1, 103), xytext=(0, 103),
            arrowprops=dict(arrowstyle="<->", color=TEAL, lw=2))
ax.text(0.5, 106, "+31.5 pp", ha="center", fontsize=10,
        color=TEAL, fontweight="bold")
ax.set_xticks([0, 1])
ax.set_xticklabels(systems, fontsize=11)
ax.set_ylim(0, 118)
ax.set_ylabel("Block Rate (%)", color=SLATE_MID)
ax.set_title("Attack Block Rate — Baseline Comparison", pad=14, color=SLATE)
ax.text(0.5, -0.13,
        "54 expected-blocked cases · 107-case synthetic corpus · 8 attack vectors",
        transform=ax.transAxes, ha="center", fontsize=9, color=SLATE_MID, style="italic")
ax.axhline(100, color=TEAL, linewidth=1.2, linestyle="--", alpha=0.6, zorder=2)
ax.text(1.27, 100.5, "100%\ntarget", fontsize=8, color=TEAL, va="bottom")
for spine in ax.spines.values(): spine.set_visible(False)
ax.tick_params(colors=SLATE_MID)
plt.tight_layout()
plt.savefig("evaluation/charts/fig1_block_rate.png")
plt.close()
print("Saved fig1_block_rate.png")

# ── Chart 2: Latency ─────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 4.5))
systems  = ["LLM Guard\n(DeBERTa-v3)", "Fintech LLM Guard\n(This Work)"]
mean_lat = [229.9, 5.8]
med_lat  = [223.1, 5.3]
x = np.arange(2); width = 0.3

b1 = ax.bar(x - width/2, mean_lat, width, label="Mean latency",
            color=[AMBER, TEAL], zorder=3, linewidth=0)
b2 = ax.bar(x + width/2, med_lat, width, label="Median latency",
            color=[AMBER_LIGHT, TEAL_LIGHT], zorder=3,
            edgecolor=[AMBER, TEAL], linewidth=1.2)

for bar, val in zip(b1, mean_lat):
    ax.text(bar.get_x()+bar.get_width()/2, val+3, f"{val}",
            ha="center", va="bottom", fontsize=10, fontweight="bold", color=SLATE)
for bar, val in zip(b2, med_lat):
    ax.text(bar.get_x()+bar.get_width()/2, val+3, f"{val}",
            ha="center", va="bottom", fontsize=10, color=SLATE_MID)

ax.annotate("", xy=(1, 18), xytext=(0, 218),
            arrowprops=dict(arrowstyle="-|>", color=RED, lw=2, mutation_scale=14))
bbox_props = dict(boxstyle="round,pad=0.3", fc=RED, ec="none", alpha=0.9)
ax.text(0.54, 0.52, "~40×\nfaster", transform=ax.transAxes,
        fontsize=10, color=WHITE, fontweight="bold",
        ha="center", bbox=bbox_props, rotation=-58)

ax.set_xticks(x); ax.set_xticklabels(systems, fontsize=11)
ax.set_ylabel("Latency (ms)", color=SLATE_MID)
ax.set_title("Per-Request Latency Overhead", pad=14, color=SLATE)
ax.text(0.5, -0.13,
        "Measured across 167 cases (107 attack + 60 legitimate queries)",
        transform=ax.transAxes, ha="center", fontsize=9, color=SLATE_MID, style="italic")
legend = ax.legend(framealpha=0, fontsize=9, loc="upper right")
for text in legend.get_texts(): text.set_color(SLATE_MID)
for spine in ax.spines.values(): spine.set_visible(False)
ax.tick_params(colors=SLATE_MID)
plt.tight_layout()
plt.savefig("evaluation/charts/fig2_latency.png")
plt.close()
print("Saved fig2_latency.png")

# ── Chart 3: ROUGE ───────────────────────────────────────────────────────────
with open("evaluation/rouge_results.json") as f:
    rouge_data = json.load(f)
cases = rouge_data["cases"]
ids = [c["id"] for c in cases]
r1  = [c["rouge1_f"] for c in cases]
r2  = [c["rouge2_f"] for c in cases]
rl  = [c["rougeL_f"] for c in cases]
x = np.arange(len(ids)); width = 0.26

fig, ax = plt.subplots(figsize=(11, 5))
ax.bar(x - width, r1, width, label="ROUGE-1", color=BLUE,  zorder=3, linewidth=0)
ax.bar(x,          r2, width, label="ROUGE-2", color=TEAL,  zorder=3, linewidth=0)
ax.bar(x + width,  rl, width, label="ROUGE-L", color=AMBER, zorder=3, linewidth=0)

ax.set_xticks(x); ax.set_xticklabels(ids, fontsize=9.5)
ax.set_ylim(0.75, 1.10)
ax.set_ylabel("F-Measure", color=SLATE_MID)
ax.set_title("Semantic Preservation — ROUGE Scores per Test Case", pad=14, color=SLATE)
ax.text(0.5, -0.13,
        "R-010 = no-PII control (upper bound) · Lower scores reflect minor article-word re-mapping artefacts",
        transform=ax.transAxes, ha="center", fontsize=9, color=SLATE_MID, style="italic")

mean_r1 = rouge_data["summary"]["mean_rouge1"]
ax.axhline(mean_r1, color=BLUE, linewidth=1.5, linestyle="--", alpha=0.7, zorder=4)
ax.axhline(1.0, color=SLATE_MID, linewidth=0.8, linestyle=":", alpha=0.5, zorder=2)
bbox = dict(boxstyle="round,pad=0.25", fc=BLUE, ec="none", alpha=0.85)
ax.text(9.6, mean_r1+0.005, f"Mean R-1={mean_r1:.3f}",
        fontsize=8, color=WHITE, va="bottom", ha="right", bbox=bbox)
ax.axvspan(8.6, 9.6, color=TEAL, alpha=0.07, zorder=1)
ax.text(9.1, 0.77, "control", fontsize=7.5, color=TEAL, ha="center", style="italic")

legend = ax.legend(framealpha=0, fontsize=10, loc="lower left", ncol=3, columnspacing=1.5)
for text in legend.get_texts(): text.set_color(SLATE)
for spine in ax.spines.values(): spine.set_visible(False)
ax.tick_params(colors=SLATE_MID)
plt.tight_layout()
plt.savefig("evaluation/charts/fig3_rouge.png")
plt.close()
print("Saved fig3_rouge.png")

# ── Chart 4: Corpus breakdown ─────────────────────────────────────────────────
vector_labels = [
    "V1\nDirect\nInjection", "V2\nTransaction\nDesc.", "V3\nCSV\nImport",
    "V4\nAction\nHijack", "V5\nExfiltration", "V6\nObfuscated",
    "V7\nPII\nDirect", "V8\nFalse\nContext",
]
total_cases   = [18, 14, 13, 13, 13, 12, 12, 12]
blocked_cases = [16,  0,  0, 10, 10, 10,  0, 10]
benign_cases  = [c - b for c, b in zip(total_cases, blocked_cases)]
pii_cases     = [ 0,  2,  3,  0,  2,  1,  9,  0]
x = np.arange(len(vector_labels)); width = 0.6

fig, ax = plt.subplots(figsize=(11, 5))
ax.bar(x, blocked_cases, width, label="Attack (expected blocked)",
       color=BLUE, zorder=3, linewidth=0)
ax.bar(x, benign_cases, width, bottom=blocked_cases,
       label="Benign / structural (pass-through)",
       color=BLUE_LIGHT, zorder=3, linewidth=0)
ax.bar(x, pii_cases, width,
       bottom=[b+n for b,n in zip(blocked_cases, benign_cases)],
       label="Contains PII (redacted by L3)",
       color=AMBER, zorder=3, linewidth=0, alpha=0.9)

for i, total in enumerate(total_cases):
    ax.text(i, total+0.35, str(total), ha="center", va="bottom",
            fontsize=11, fontweight="bold", color=SLATE)
for i, val in enumerate(blocked_cases):
    if val > 0:
        ax.text(i, val/2, str(val), ha="center", va="center",
                fontsize=10, fontweight="bold", color=WHITE)

ax.set_xticks(x); ax.set_xticklabels(vector_labels, fontsize=9)
ax.set_ylabel("Number of Cases", color=SLATE_MID)
ax.set_title("Synthetic Attack Corpus — Case Distribution by Vector", pad=14, color=SLATE)
ax.text(0.5, -0.17,
        "107 total cases · 54 expected-blocked · 53 benign/structural/PII pass-through",
        transform=ax.transAxes, ha="center", fontsize=9, color=SLATE_MID, style="italic")
ax.set_ylim(0, 26)
legend = ax.legend(framealpha=0, fontsize=9, loc="upper right")
for text in legend.get_texts(): text.set_color(SLATE)
for spine in ax.spines.values(): spine.set_visible(False)
ax.tick_params(colors=SLATE_MID)
plt.tight_layout()
plt.savefig("evaluation/charts/fig4_corpus.png")
plt.close()
print("Saved fig4_corpus.png")

print("\nAll charts saved to evaluation/charts/")