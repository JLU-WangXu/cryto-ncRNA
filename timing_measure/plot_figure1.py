"""
Redraw Figure 1 (TODO-9 addendum: text-figure consistency after the
timing-convention correction).
Data sources:
  Panel A = results_all.json exp2 per-message all_times (30 trials)
            + exp1/exp3 key-establishment reference lines
  Panel B = results_all.json exp2 derived throughput (same source as
            SI Table S4)
  Panel C = SI Table S7 success rates (data unchanged)
  Panel D = SI Table S6 entropy (data unchanged)
Output: version2/figs/figure1_redraft.png (draft; does not overwrite
latex/fig/figure1.png).
"""
import os
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results_all.json")
OUT = "/lenovofs1/home/wangyq/npj_uncon_comput/version2/figs/figure1_redraft.png"

# Palette of the original figure (taken from figure1.png)
C_NCRNA = "#92B5D8"   # blue
C_AES = "#F5B871"     # orange
C_RSA = "#97C283"     # green
EDGE = dict(edgecolors="#666666", linewidths=0.4, s=28)

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.titlesize": 13,
    "axes.titleweight": "bold",
    "axes.labelsize": 11,
    "axes.labelweight": "bold",
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
})

data = json.load(open(RESULTS))
exp2 = data["results"]["exp2"]["measurements"]

LENGTHS = [50, 100, 500, 1000, 5000, 10000, 50000, 100000]
ALGOS = [("ncRNA", "ncRNA", C_NCRNA), ("AES", "AES", C_AES), ("RSA", "RSA", C_RSA)]

# SI Table S6 entropy (main_combined.tex tab:avg_entropy_si)
ENTROPY = {
    "ncRNA": [7.230238137, 7.520643336, 7.906697071, 7.954174669, 7.990878249, 7.995409292, 7.99908728, 7.999546736],
    "AES":   [6.029898017, 6.553651309, 7.603863355, 7.808256544, 7.962331187, 7.981768972, 7.996283968, 7.998177172],
    "RSA":   [7.166932575, 7.1746127, 7.739013967, 7.875851176, 7.972694673, 7.986424963, 7.997251254, 7.998614323],
}

# SI Table S7 success rates (tab:correctness_si)
CORR_LENGTHS = ["50", "100", "1000", "100000", "1000000"]
CORR = 100.0  # all 100%

fig = plt.figure(figsize=(17, 8.9))
gs = fig.add_gridspec(2, 2, left=0.045, right=0.985, top=0.93, bottom=0.11,
                      hspace=0.52, wspace=0.18)

# ============ A: per-message time distributions (with key-establishment reference lines) ============
gsA = gs[0, 0].subgridspec(1, 2, wspace=0.22)
for k, (op, title) in enumerate([("encryption", "Per-Message Encryption Time"),
                                 ("decryption", "Per-Message Decryption Time")]):
    ax = fig.add_subplot(gsA[0, k])
    for i, (key, label, color) in enumerate(ALGOS):
        xs, ys = [], []
        for j, L in enumerate(LENGTHS):
            times_ms = np.array(exp2[f"{key}_{L}"][op]["all_times"]) * 1e3
            jitter = (np.random.RandomState(20260909 + j).uniform(-0.18, 0.18, len(times_ms))
                      if k == 0 else np.random.RandomState(20260909 + 8 + j).uniform(-0.18, 0.18, len(times_ms)))
            xs.append(np.full(len(times_ms), j) + jitter)
            ys.append(times_ms)
        ax.scatter(np.concatenate(xs), np.concatenate(ys), color=color, label=label, **EDGE)
    # Key-establishment reference lines (one-off costs)
    from matplotlib.lines import Line2D
    ref_handles = []
    for v, txt, cc in [(41.9, "PBKDF2 $10^5$ (ncRNA): 41.9 ms", "#4477AA"),
                       (28.2, "scrypt $2^{14}$ (AES): 28.2 ms", "#EE7733"),
                       (314.9, "RSA keygen: 314.9 ms", "#228833")]:
        ax.axhline(v, ls="--", lw=1.1, color=cc, alpha=0.9)
        ref_handles.append(Line2D([0], [0], ls="--", lw=1.1, color=cc, label=txt))
    if k == 1:  # decryption subplot: merge the algorithm and reference-line legends, upper left
        hands, labs = ax.get_legend_handles_labels()
        ax.legend(handles=hands + ref_handles, loc="upper left", fontsize=8, framealpha=0.92)
    ax.set_yscale("log")
    ax.set_ylim(1e-3, 2e3)
    ax.set_xticks(range(len(LENGTHS)))
    ax.set_xticklabels([str(L) for L in LENGTHS], rotation=30)
    ax.set_xlabel("Data Length (Bytes)")
    ax.set_ylabel("Time (ms, log scale)")
    ax.set_title(title)
    ax.grid(axis="y", alpha=0.3)
    if k == 0:
        ax.legend(loc="upper left", framealpha=0.92)
fig.text(0.012, 0.97, "A", fontsize=20, fontweight="bold")
fig.text(0.012, 0.50, "B", fontsize=20, fontweight="bold")
fig.text(0.545, 0.97, "C", fontsize=20, fontweight="bold")
fig.text(0.545, 0.50, "D", fontsize=20, fontweight="bold")

# ============ B: throughput ============
gsB = gs[1, 0].subgridspec(1, 2, wspace=0.22)
for k, (col, title) in enumerate([("encryption", "Encryption Throughput"),
                                  ("decryption", "Decryption Throughput")]):
    ax = fig.add_subplot(gsB[0, k])
    for key, label, color in ALGOS:
        thr = [L / 1024 / (exp2[f"{key}_{L}"][col]["median"]) for L in LENGTHS]
        ax.plot(range(len(LENGTHS)), thr, marker="o", ms=4.5, lw=1.6, color=color, label=label)
    ax.set_xticks(range(len(LENGTHS)))
    ax.set_xticklabels([str(L) for L in LENGTHS], rotation=30)
    ax.set_xlabel("Data Length (Bytes)")
    ax.set_ylabel("Throughput (KiB/s)")
    ax.set_title(title)
    ax.grid(alpha=0.3)
    if k == 0:
        ax.legend(loc="upper left", framealpha=0.9)

# ============ C: success rates ============
axC = fig.add_subplot(gs[0, 1])
x = np.arange(len(CORR_LENGTHS))
axC.bar(x - 0.18, [CORR] * len(x), width=0.36, color=C_NCRNA, edgecolor="#666666", label="Encryption Success Rate (%)")
axC.bar(x + 0.18, [CORR] * len(x), width=0.36, color=C_AES, edgecolor="#666666", label="Decryption Success Rate (%)")
for xi in x:
    axC.text(xi - 0.18, 100.15, "100%", ha="center", fontsize=8)
    axC.text(xi + 0.18, 100.15, "100%", ha="center", fontsize=8)
axC.set_xticks(x)
axC.set_xticklabels(CORR_LENGTHS)
axC.set_ylim(97, 101)
axC.set_xlabel("Data Length (Bytes)")
axC.set_ylabel("Success Rate (%)")
axC.set_title("Encryption and Decryption Success Rates")
axC.legend(loc="lower right", framealpha=0.9)
axC.grid(axis="y", alpha=0.3)

# ============ D: entropy ============
axD = fig.add_subplot(gs[1, 1])
for key, label, color in ALGOS:
    axD.plot(LENGTHS, ENTROPY[key], marker="o", ms=4.5, lw=1.6, color=color, label=label)
axD.axvspan(40, 1500, color="#DDEEF6", alpha=0.5)
axD.axvspan(4500, 130000, color="#E8E8F8", alpha=0.5)
axD.text(280, 6.06, "Small Data Range", ha="center", fontsize=8.5, color="#555555")
axD.text(20000, 6.06, "Large Data Range", ha="center", fontsize=8.5, color="#555555")
axD.set_xscale("log")
axD.set_xticks(LENGTHS)
axD.set_xticklabels(["50", "100", "500", "1K", "5K", "10K", "50K", "100K"])
axD.minorticks_off()
axD.set_xlabel("Data Length (Bytes) - Log Scale")
axD.set_ylabel("Entropy (Small Range)")
axD.set_ylim(6.0, 8.05)
axD.set_title("Entropy Analysis")
axD.legend(loc="upper left", ncol=3, framealpha=0.9)
axD.grid(alpha=0.3)

fig.savefig(OUT, dpi=200, facecolor="white")
print(f"written: {OUT}")
