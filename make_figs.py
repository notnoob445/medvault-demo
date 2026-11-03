#!/usr/bin/env python3
"""Draws the paper's graphs from the CSV files in results/ (no numbers are typed in by hand)."""
import csv, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
HERE = os.path.dirname(os.path.abspath(__file__)); R = os.path.join(HERE, "results"); F = os.path.join(HERE, "figs")
os.makedirs(F, exist_ok=True)
plt.rcParams.update({"font.family": "Liberation Serif", "font.size": 10, "axes.spines.top": False, "axes.spines.right": False,
                     "savefig.dpi": 300, "savefig.bbox": "tight", "axes.grid": True, "grid.color": "#dddddd", "grid.linewidth": 0.6,
                     "axes.axisbelow": True, "legend.frameon": False})
METH = ["Existing-A", "Existing-B", "Proposed"]
LAB = {"Existing-A": "Existing-A (single-AZ plaintext)", "Existing-B": "Existing-B (storage encryption only)", "Proposed": "Proposed MedVault"}
COL = {"Existing-A": "#bdbdbd", "Existing-B": "#737373", "Proposed": "#1f1f1f"}
HAT = {"Existing-A": "", "Existing-B": "//", "Proposed": ""}
rd = lambda n: list(csv.DictReader(open(os.path.join(R, n))))

# Fig: enforcement comparison
enf = rd("enforcement_summary.csv")
metrics = ["Plaintext absent from raw storage image", "Plaintext absent from database-engine view",
           "Unauthorised plaintext access blocked", "SQLi blocked before compute", "Audit coverage of API-path events",
           "Tampered records detected on read"]
short = ["Plaintext absent\n(raw storage)", "Plaintext absent\n(DB-engine view)", "Unauthorised\naccess blocked",
         "SQLi blocked\nbefore compute", "Audit coverage\n(API events)", "Tamper detected\non read"]
val = {(r["method"], r["metric"]): float(r["rate_pct"]) for r in enf}
x = np.arange(len(metrics)); w = 0.26
fig, ax = plt.subplots(figsize=(7.0, 3.1))
for i, m in enumerate(METH):
    v = [val[(m, k)] for k in metrics]
    b = ax.bar(x + (i - 1) * w, v, w, label=LAB[m], color=COL[m], hatch=HAT[m], edgecolor="black", linewidth=0.5)
    for xi, vi in zip(x + (i - 1) * w, v):
        ax.text(xi, vi + 1.5, f"{vi:.0f}", ha="center", va="bottom", fontsize=7.5)
ax.set_xticks(x); ax.set_xticklabels(short, fontsize=8.5); ax.set_ylim(0, 112); ax.set_ylabel("Rate on SCW-64 (%)")
ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.17), ncol=3, fontsize=8.5)
fig.savefig(os.path.join(F, "fig_enforcement.png")); plt.close(fig)

# Fig: latency mean + p95
lat = rd("latency_summary.csv"); raw = rd("latency_raw.csv")
ops = ["write", "authorised read", "denied read"]
fig, ax = plt.subplots(figsize=(6.6, 2.9)); x = np.arange(len(ops))
for i, m in enumerate(METH):
    mean, p95 = [], []
    for op in ops:
        r = [q for q in lat if q["method"] == m and q["operation"] == op][0]
        mean.append(float(r["mean_us"]) if r["mean_us"] != "n/a" else np.nan)
        p95.append(float(r["p95_us"]) if r["p95_us"] != "n/a" else np.nan)
    mean, p95 = np.array(mean), np.array(p95)
    ax.bar(x + (i - 1) * w, mean, w, label=LAB[m], color=COL[m], hatch=HAT[m], edgecolor="black", linewidth=0.5)
    ax.errorbar(x + (i - 1) * w, mean, yerr=[np.zeros_like(mean), np.nan_to_num(p95 - mean)], fmt="none", ecolor="black", capsize=3, linewidth=0.8)
    for xi, mi, pi in zip(x + (i - 1) * w, mean, p95):
        if np.isnan(mi): ax.text(xi, 0.6, "n/a", ha="center", fontsize=7.5)
        else: ax.text(xi, pi + 0.7, f"{mi:.1f}", ha="center", fontsize=7.5)
ax.set_xticks(x); ax.set_xticklabels(["Write", "Authorised read", "Denied (intern) read"])
ax.set_ylabel("Latency per operation (µs)"); ax.legend(loc="upper right", fontsize=8)
fig.savefig(os.path.join(F, "fig_latency.png")); plt.close(fig)

# Fig: latency distribution (CDF) of proposed ops
fig, ax = plt.subplots(figsize=(6.0, 2.6))
for op, ls in zip(ops, ["-", "--", ":"]):
    xs = np.sort([float(r["latency_us"]) for r in raw if r["method"] == "Proposed" and r["operation"] == op])
    ax.plot(xs, np.arange(1, len(xs) + 1) / len(xs), ls, color="black", label=op.capitalize(), linewidth=1.2)
ax.set_xlim(0, 45); ax.set_xlabel("Latency (µs)"); ax.set_ylabel("Cumulative fraction"); ax.legend(loc="lower right")
ax.axhline(0.95, color="#888888", linewidth=0.7); ax.text(1, 0.965, "p95", fontsize=8, color="#555555")
fig.savefig(os.path.join(F, "fig_latency_cdf.png")); plt.close(fig)

# Fig: proposed write breakdown
br = rd("proposed_write_breakdown.csv")
fig, ax = plt.subplots(figsize=(6.4, 2.4))
names = [r["component"].split(" ", 1)[1] for r in br][::-1]; mean = [float(r["mean_us"]) for r in br][::-1]; p95 = [float(r["p95_us"]) for r in br][::-1]
y = np.arange(len(names))
ax.barh(y, mean, 0.55, color="#4d4d4d", edgecolor="black", linewidth=0.5, label="mean")
ax.errorbar(mean, y, xerr=[np.zeros(len(mean)), np.array(p95) - np.array(mean)], fmt="none", ecolor="black", capsize=3, linewidth=0.8, label="p95")
for yi, mi, pi in zip(y, mean, p95): ax.text(pi + 0.2, yi, f"{mi:.2f} µs (p95 {pi:.2f})", va="center", fontsize=8)
ax.set_yticks(y); ax.set_yticklabels(names, fontsize=8.5); ax.set_xlabel("Time per write (µs)"); ax.set_xlim(0, max(p95) * 1.75)
ax.grid(axis="y", visible=False)
fig.savefig(os.path.join(F, "fig_write_breakdown.png")); plt.close(fig)

# Fig: budget trajectory
bt = rd("budget_trace.csv"); bs = {r["method"]: r for r in rd("budget_summary.csv")}
d = [int(r["day"]) for r in bt]; mtd = [float(r["month_to_date_usd"]) for r in bt]; fc = [float(r["linear_forecast_usd"]) for r in bt]
fig, ax = plt.subplots(figsize=(6.6, 2.8))
ax.plot(d, mtd, "-", color="black", linewidth=1.5, label="Month-to-date spend")
ax.plot(d, fc, "--", color="#555555", linewidth=1.1, label="Linear month-end forecast")
ax.axhline(16, color="#888888", linewidth=0.9, linestyle="-."); ax.text(1, 16.4, "80 % of cap (USD 16)", fontsize=8)
ax.axhline(20, color="#888888", linewidth=0.9); ax.text(1, 20.4, "USD 20 cap", fontsize=8)
fa, aa, br_ = int(bs["Proposed"]["forecast_80pct_alert_day"]), int(bs["Proposed"]["actual_80pct_alert_day"]), int(bs["Proposed"]["day_cap_breached"])
ax.plot([fa], [fc[fa - 1]], "v", color="black", markersize=7); ax.annotate(f"forecast alert, day {fa}", (fa, fc[fa - 1]), xytext=(13.2, 11.2), fontsize=8, arrowprops=dict(arrowstyle="-", lw=0.6))
ax.plot([aa], [mtd[aa - 1]], "o", color="black", markersize=6); ax.annotate(f"actual alert, day {aa}", (aa, mtd[aa - 1]), xytext=(17.5, 17.6), fontsize=8, arrowprops=dict(arrowstyle="-", lw=0.6))
ax.plot([br_], [mtd[br_ - 1]], "x", color="black", markersize=7); ax.annotate(f"cap exceeded, day {br_}", (br_, mtd[br_ - 1]), xytext=(22.5, 23.0), fontsize=8, arrowprops=dict(arrowstyle="-", lw=0.6))
ax.set_xlim(0.5, 30.5); ax.set_ylim(0, 25); ax.set_xlabel("Day of month"); ax.set_ylabel("USD"); ax.legend(loc="lower right", fontsize=8)
fig.savefig(os.path.join(F, "fig_budget.png")); plt.close(fig)

# Fig: failover outcome
fo = {r["method"]: r for r in rd("failover.csv")}
fig, ax = plt.subplots(figsize=(6.4, 2.5)); x = np.arange(3); w = 0.26
series = [("committed_writes_lost", "Committed writes lost", "#1f1f1f", ""), ("writes_rejected_no_writer", "Writes rejected (no writer)", "#9e9e9e", ""),
          ("writes_retried_during_promotion", "Writes retried during promotion", "#ffffff", "..")]
for i, (k, lbl, c, h) in enumerate(series):
    v = [int(fo[m][k]) for m in METH]
    ax.bar(x + (i - 1) * w, v, w, color=c, hatch=h, edgecolor="black", linewidth=0.5, label=lbl)
    for xi, vi in zip(x + (i - 1) * w, v): ax.text(xi, vi + 0.4, str(vi), ha="center", fontsize=8)
ax.set_xticks(x); ax.set_xticklabels([LAB[m].replace(" (", "\n(") for m in METH], fontsize=8.5); ax.set_ylabel("Writes (of 64)"); ax.legend(fontsize=8, loc="upper right")
ax.set_ylim(0, 30)
fig.savefig(os.path.join(F, "fig_failover.png")); plt.close(fig)
print("figures written to", F)
