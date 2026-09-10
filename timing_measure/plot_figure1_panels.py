"""
Redraw panels A/B of Figure 1 (strictly replicating the original PPT panel
style, only replacing the data convention).
  Panel A (image2.png, 900x400): per-message encryption/decryption time
          scatter (log axis)
  Panel B (image3.png, 800x400): per-message throughput lines
Data source = results_all.json exp2 (all 30 trials + medians).
Panels C (success rates) / D (entropy) keep their data unchanged, following
the original PPT figure.
Outputs: the panel PNGs plus the rewritten figure1_revised.pptx (repo root,
handed to the user for export).
"""
import os
import json
import zipfile
import shutil
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results_all.json")
FIGS = "/lenovofs1/home/wangyq/npj_uncon_comput/version2/figs"
SRC_PPTX = os.path.join(FIGS, "figure1_source.pptx")
OUT_PPTX = "/lenovofs1/home/wangyq/npj_uncon_comput/figure1_revised.pptx"

C_NCRNA, C_AES, C_RSA = "#92B5D8", "#F5C173", "#A8CE8F"
ALGOS = [("ncRNA", C_NCRNA, "o"), ("AES", C_AES, "s"), ("RSA", C_RSA, "D")]
LENGTHS = [50, 100, 500, 1000, 5000, 10000, 50000, 100000]

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.titlesize": 12, "axes.titleweight": "bold",
    "axes.labelsize": 11, "axes.labelweight": "bold",
    "xtick.labelsize": 8, "ytick.labelsize": 9,
    "legend.fontsize": 9,
})

data = json.load(open(RESULTS))
exp2 = data["results"]["exp2"]["measurements"]

# ============ Panel A: per-message time distributions (900x400 @400dpi = 3600x1600) ============
fig, axes = plt.subplots(1, 2, figsize=(9, 4), dpi=400)
fig.subplots_adjust(left=0.075, right=0.985, top=0.88, bottom=0.14, wspace=0.30)
for k, (op, title) in enumerate([("encryption", "Encryption Time Distribution"),
                                 ("decryption", "Decryption Time Distribution")]):
    ax = axes[k]
    for key, color, marker in ALGOS:
        for j, L in enumerate(LENGTHS):
            t_s = np.array(exp2[f"{key}_{L}"][op]["all_times"])  # seconds
            rng = np.random.RandomState(20260909 + 100 * k + j)
            xs = np.full(len(t_s), j) + rng.uniform(-0.18, 0.18, len(t_s))
            ax.scatter(xs, t_s, s=22, color=color, edgecolors="#777777",
                       linewidths=0.3, label=key if (k == 1 and j == 0) else None)
    ax.set_yscale("log")
    ax.set_ylim(2e-6, 1.2)
    ax.set_xticks(range(len(LENGTHS)))
    ax.set_xticklabels([str(L) for L in LENGTHS])
    ax.set_xlim(-0.7, len(LENGTHS) - 0.3)
    ax.set_xlabel("Data Length")
    if k == 0:
        ax.set_ylabel("Time (s, log scale)")
    ax.set_title(title, pad=8)
if True:
    axes[1].legend(loc="upper left", title="Algorithm", framealpha=0.95)
fig.savefig(os.path.join(FIGS, "panel_A_new.png"), facecolor="white")
plt.close(fig)

# ============ Panel B: throughput (800x400 @400dpi = 3200x1600) ============
fig, axes = plt.subplots(1, 2, figsize=(8, 4), dpi=400)
fig.subplots_adjust(left=0.11, right=0.985, top=0.88, bottom=0.14, wspace=0.32)
for k, (col, title) in enumerate([("encryption", "Encryption Throughput"),
                                  ("decryption", "Decryption Throughput")]):
    ax = axes[k]
    for key, color, marker in ALGOS:
        thr = [L / 1024 / exp2[f"{key}_{L}"][col]["median"] for L in LENGTHS]
        ax.plot(range(len(LENGTHS)), thr, marker=marker, ms=5, lw=1.5,
                color=color, markeredgecolor="#777777", markeredgewidth=0.4,
                label=key if k == 0 else None)
    ax.set_xticks(range(len(LENGTHS)))
    ax.set_xticklabels([str(L) for L in LENGTHS])
    ax.set_xlabel("Data Length (Bytes)")
    ax.set_ylabel("Throughput (KiB/s)")
    ax.set_ylim(0, 500000)
    ax.set_yticks([0, 100000, 200000, 300000, 400000, 500000])
    ax.set_title(title, pad=8)
    if k == 0:
        ax.legend(loc="upper left", title="Algorithm", framealpha=0.95)
fig.savefig(os.path.join(FIGS, "panel_B_new.png"), facecolor="white")
plt.close(fig)

# ============ Panel D: entropy analysis (800x500 @400dpi = 3200x2000, broken axis with dual y-axes, replicating the original style) ============
# Data = SI Table S6 (tab:avg_entropy_si); the original plots up to 500K but the table has no
# value there, so the redraft uses only the 8 lengths present in the table (4+4 broken axis)
from matplotlib.lines import Line2D
from matplotlib.patches import Patch
ENTROPY = {
    "ncRNA": [7.144818, 7.520643336, 7.906697071, 7.954174669, 7.990878249, 7.995409292, 7.99908728, 7.999546736],
    "AES":   [6.029898017, 6.553651309, 7.603863355, 7.808256544, 7.962331187, 7.981768972, 7.996283968, 7.998177172],
    "RSA":   [7.166932575, 7.1746127, 7.739013967, 7.875851176, 7.972694673, 7.986424963, 7.997251254, 7.998614323],
}
fig = plt.figure(figsize=(8, 5), dpi=400)
gsD = fig.add_gridspec(1, 2, width_ratios=[4, 4], wspace=0.05,
                       left=0.085, right=0.875, top=0.86, bottom=0.24)
axL, axR = fig.add_subplot(gsD[0]), fig.add_subplot(gsD[1])
xL = np.arange(4)
for (key, color, marker), vals in zip(ALGOS, [ENTROPY["ncRNA"], ENTROPY["AES"], ENTROPY["RSA"]]):
    axL.plot(xL, vals[:4], marker=marker, ms=5, lw=1.5, color=color,
             markeredgecolor="#777777", markeredgewidth=0.4)
    axR.plot(xL, vals[4:], marker=marker, ms=5, lw=1.5, color=color,
             markeredgecolor="#777777", markeredgewidth=0.4)
axL.set_xticks(xL); axL.set_xticklabels(["50", "100", "500", "1K"])
axR.set_xticks(xL); axR.set_xticklabels(["5K", "10K", "50K", "100K"])
axL.set_xlim(-0.4, 3.4); axR.set_xlim(-0.4, 3.4)
axL.set_ylim(6.0, 8.0); axL.set_yticks(np.arange(6.0, 8.01, 0.25))
axR.set_ylim(7.96, 8.0); axR.set_yticks(np.arange(7.96, 8.001, 0.005))
axL.set_ylabel("Entropy (Small Range)")
axR.yaxis.tick_right()
axR.yaxis.set_label_position("right")
axR.set_ylabel("Entropy (Large Range)")
axL.axvspan(-0.4, 3.4, color="#DDEEF6", alpha=0.55, zorder=0)
axR.axvspan(-0.4, 3.4, color="#E8E8F8", alpha=0.55, zorder=0)
axL.spines["right"].set_visible(False)
axR.spines["left"].set_visible(False)
axL.tick_params(right=False); axR.tick_params(left=False)
axL.grid(axis="y", alpha=0.35); axR.grid(axis="y", alpha=0.35)
fig.suptitle("Entropy Analysis", y=0.95, fontsize=12, fontweight="bold")
fig.text(0.48, 0.135, "Data Length (Bytes) - Log Scale", ha="center",
         fontsize=11, fontweight="bold")
handles = [Line2D([0], [0], color=c, marker=m, ms=5, lw=1.5,
                  markeredgecolor="#777777", markeredgewidth=0.4, label=k)
           for k, c, m in ALGOS] + [
           Patch(facecolor="#DDEEF6", label="Small Data Range"),
           Patch(facecolor="#E8E8F8", label="Large Data Range")]
fig.legend(handles=handles, loc="lower center", ncol=5, title="Legend",
           fontsize=9, title_fontsize=10, framealpha=0.95,
           bbox_to_anchor=(0.5, 0.0))
fig.savefig(os.path.join(FIGS, "panel_D_new.png"), facecolor="white")
plt.close(fig)

# ============ Substitute into the PPTX (image2=A, image3=B, image1=D; C kept as-is) ============
buf = {}
zin = zipfile.ZipFile(SRC_PPTX)
for item in zin.infolist():
    buf[item.filename] = zin.read(item.filename)
zin.close()

buf["ppt/media/image2.png"] = open(os.path.join(FIGS, "panel_A_new.png"), "rb").read()
buf["ppt/media/image3.png"] = open(os.path.join(FIGS, "panel_B_new.png"), "rb").read()
buf["ppt/media/image1.png"] = open(os.path.join(FIGS, "panel_D_new.png"), "rb").read()

zout = zipfile.ZipFile(OUT_PPTX, "w", zipfile.ZIP_DEFLATED)
for name, blob in buf.items():
    zout.writestr(name, blob)
zout.close()

print("panels: A/B/D ->", os.path.join(FIGS, "panel_A_new.png"), "panel_B_new.png", "panel_D_new.png")
print("written:", OUT_PPTX)
