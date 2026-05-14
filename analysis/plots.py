"""
Visualisation module.

All charts follow Storytelling with Data principles:
  - Grayscale only (no colour used as decoration)
  - Direct labels instead of legends wherever possible
  - Maximum data-ink ratio (no chartjunk)
  - Clear, descriptive titles and axis labels
  - Saved at 300 DPI as PNG
"""

import logging
from pathlib import Path
from typing import Dict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# ── Global style ─────────────────────────────────────────────────────────────

_GRAY = "#222222"
_LIGHT_GRAY = "#AAAAAA"
_MID_GRAY = "#666666"
_VERY_LIGHT = "#EEEEEE"

plt.rcParams.update({
    "figure.facecolor": "white",
    "axes.facecolor": "white",
    "axes.edgecolor": _LIGHT_GRAY,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": False,
    "text.color": _GRAY,
    "axes.labelcolor": _GRAY,
    "xtick.color": _GRAY,
    "ytick.color": _GRAY,
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.titlesize": 12,
    "axes.titleweight": "bold",
    "axes.titlepad": 12,
    "figure.dpi": 100,
})

_DPI = 300


def _save(fig: plt.Figure, path: Path) -> None:
    fig.savefig(path, dpi=_DPI, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    logger.info("  Saved: %s", path)


def _remove_spines(ax: plt.Axes, keep=("left", "bottom")) -> None:
    for spine in ("top", "right", "left", "bottom"):
        ax.spines[spine].set_visible(spine in keep)


def _add_bar_labels(ax: plt.Axes, bars, fmt="{:.0f}", color=_GRAY, fontsize=9) -> None:
    for bar in bars:
        h = bar.get_height()
        if h > 0:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                h + ax.get_ylim()[1] * 0.01,
                fmt.format(h),
                ha="center", va="bottom", color=color, fontsize=fontsize,
            )


def _add_hbar_labels(ax: plt.Axes, bars, fmt="{:.0f}", fontsize=9) -> None:
    for bar in bars:
        w = bar.get_width()
        if w > 0:
            ax.text(
                w + ax.get_xlim()[1] * 0.005,
                bar.get_y() + bar.get_height() / 2,
                fmt.format(w),
                ha="left", va="center", color=_GRAY, fontsize=fontsize,
            )


# ── Individual chart functions ───────────────────────────────────────────────

def plot_star_distribution(repos_df: pd.DataFrame, out_dir: Path) -> None:
    if "stars" not in repos_df.columns or repos_df["stars"].dropna().empty:
        return
    fig, ax = plt.subplots(figsize=(8, 4))
    data = repos_df["stars"].dropna().astype(float)
    bins = np.logspace(np.log10(data.min()), np.log10(data.max()), 20)
    ax.hist(data, bins=bins, color=_MID_GRAY, edgecolor="white", linewidth=0.5)
    ax.set_xscale("log")
    ax.set_xlabel("Stars (log scale)")
    ax.set_ylabel("Number of repositories")
    ax.set_title("Distribution of Stars Among Analysed Repositories")
    _remove_spines(ax)
    fig.tight_layout()
    _save(fig, out_dir / "01_star_distribution.png")


def plot_security_feature_adoption(repos_df: pd.DataFrame, out_dir: Path) -> None:
    features = {
        "SECURITY.md": "has_security_md",
        "CODE_OF_CONDUCT.md": "has_code_of_conduct",
        "CONTRIBUTING.md": "has_contributing",
        "CODEOWNERS": "has_codeowners",
        "Private vuln. reporting": "private_vulnerability_reporting_enabled",
        "Security contact": "has_security_contact",
        "Dependabot": "dependabot_enabled",
        "CodeQL": "codeql_enabled",
        "Has advisory": "has_advisories",
    }
    available = {k: v for k, v in features.items() if v in repos_df.columns}
    if not available:
        return

    n = len(repos_df)
    labels, pcts = [], []
    for label, col in available.items():
        pct = repos_df[col].map({True: 1, False: 0, "True": 1, "False": 0}).mean() * 100
        labels.append(label)
        pcts.append(round(pct, 1))

    order = sorted(range(len(pcts)), key=lambda i: pcts[i])
    labels = [labels[i] for i in order]
    pcts = [pcts[i] for i in order]

    fig, ax = plt.subplots(figsize=(8, max(4, len(labels) * 0.5)))
    bars = ax.barh(labels, pcts, color=_MID_GRAY, edgecolor="white")
    ax.set_xlim(0, 115)
    ax.set_xlabel("Adoption rate (%)")
    ax.set_title(f"Security Feature Adoption (n={n})")
    _remove_spines(ax, keep=("bottom",))
    ax.tick_params(left=False)
    _add_hbar_labels(ax, bars, fmt="{:.1f}%")
    fig.tight_layout()
    _save(fig, out_dir / "02_security_feature_adoption.png")


def plot_dependabot_merge_time(repos_df: pd.DataFrame, out_dir: Path) -> None:
    if "dependabot_avg_merge_days" not in repos_df.columns:
        return
    data = repos_df["dependabot_avg_merge_days"].dropna()
    if data.empty:
        return
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.hist(data, bins=20, color=_MID_GRAY, edgecolor="white", linewidth=0.5)
    median = data.median()
    ax.axvline(median, color=_GRAY, linestyle="--", linewidth=1.2)
    ax.text(median + data.max() * 0.01, ax.get_ylim()[1] * 0.9,
            f"Median: {median:.1f}d", color=_GRAY, fontsize=9)
    ax.set_xlabel("Average days to merge a Dependabot PR")
    ax.set_ylabel("Number of repositories")
    ax.set_title("Distribution of Dependabot PR Merge Times")
    _remove_spines(ax)
    fig.tight_layout()
    _save(fig, out_dir / "03_dependabot_merge_time.png")


def plot_top_dependabot_libraries(depbot_df: pd.DataFrame, out_dir: Path) -> None:
    if depbot_df.empty or "library_name" not in depbot_df.columns:
        return
    counts = (
        depbot_df[depbot_df["library_name"] != "unknown"]
        .groupby("library_name").size()
        .sort_values(ascending=False)
        .head(20)
    )
    if counts.empty:
        return

    fig, ax = plt.subplots(figsize=(9, max(5, len(counts) * 0.4)))
    bars = ax.barh(counts.index[::-1], counts.values[::-1], color=_MID_GRAY, edgecolor="white")
    ax.set_xlabel("Number of Dependabot PRs")
    ax.set_title("Top 20 Libraries Updated by Dependabot")
    _remove_spines(ax, keep=("bottom",))
    ax.tick_params(left=False)
    _add_hbar_labels(ax, bars)
    fig.tight_layout()
    _save(fig, out_dir / "04_top_dependabot_libraries.png")


def plot_correlation_heatmap(repos_df: pd.DataFrame, out_dir: Path) -> None:
    num_cols = [
        "stars", "contributors_count",
        "dependabot_avg_merge_days", "dependabot_acceptance_rate",
        "dependabot_total_prs", "advisory_total", "codeql_total_alerts",
    ]
    bool_cols = [
        "has_security_md", "dependabot_enabled", "codeql_enabled",
        "private_vulnerability_reporting_enabled",
    ]

    all_cols = [c for c in num_cols if c in repos_df.columns]
    for c in bool_cols:
        if c in repos_df.columns:
            repos_df[f"_b_{c}"] = repos_df[c].map({True: 1, False: 0, "True": 1, "False": 0})
            all_cols.append(f"_b_{c}")

    sub = repos_df[all_cols].apply(pd.to_numeric, errors="coerce")
    valid = [c for c in all_cols if sub[c].nunique() > 1]
    if len(valid) < 2:
        return
    corr = sub[valid].corr(method="spearman")

    nice_names = {
        "stars": "Stars",
        "contributors_count": "Contributors",
        "dependabot_avg_merge_days": "Dep. merge days",
        "dependabot_acceptance_rate": "Dep. accept. rate",
        "dependabot_total_prs": "Dep. PRs total",
        "advisory_total": "Advisories total",
        "codeql_total_alerts": "CodeQL alerts",
        "_b_has_security_md": "Has SECURITY.md",
        "_b_dependabot_enabled": "Dependabot on",
        "_b_codeql_enabled": "CodeQL on",
        "_b_private_vulnerability_reporting_enabled": "Priv. vuln. rep.",
    }
    corr.columns = [nice_names.get(c, c) for c in corr.columns]
    corr.index = corr.columns

    n = len(corr)
    fig, ax = plt.subplots(figsize=(max(6, n * 0.8), max(5, n * 0.8)))
    im = ax.imshow(corr.values, cmap="gray_r", vmin=-1, vmax=1, aspect="auto")

    ax.set_xticks(range(n))
    ax.set_xticklabels(corr.columns, rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(n))
    ax.set_yticklabels(corr.index, fontsize=8)

    for i in range(n):
        for j in range(n):
            val = corr.values[i, j]
            if not np.isnan(val):
                color = "white" if abs(val) > 0.5 else _GRAY
                ax.text(j, i, f"{val:.2f}", ha="center", va="center", fontsize=7, color=color)

    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("Spearman ρ", fontsize=9)
    ax.set_title("Correlation Matrix (Spearman)")
    fig.tight_layout()
    _save(fig, out_dir / "05_correlation_heatmap.png")


def plot_advisory_severity(advisories_df: pd.DataFrame, out_dir: Path) -> None:
    if advisories_df.empty or "severity" not in advisories_df.columns:
        return
    order = ["critical", "high", "medium", "low", "unknown"]
    counts = advisories_df["severity"].value_counts()
    counts = counts.reindex([o for o in order if o in counts.index], fill_value=0)
    if counts.sum() == 0:
        return

    grays = ["#111111", "#444444", "#777777", "#AAAAAA", "#CCCCCC"]
    colors = [grays[i % len(grays)] for i in range(len(counts))]

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(counts.index, counts.values, color=colors, edgecolor="white")
    ax.set_ylabel("Number of advisories")
    ax.set_title("Security Advisory Severity Distribution")
    _remove_spines(ax)
    _add_bar_labels(ax, bars)
    fig.tight_layout()
    _save(fig, out_dir / "06_advisory_severity.png")


def plot_codeql_severity(codeql_df: pd.DataFrame, out_dir: Path) -> None:
    if codeql_df.empty or "severity" not in codeql_df.columns:
        return
    order = ["critical", "high", "medium", "low", "unknown"]
    counts = codeql_df["severity"].value_counts()
    counts = counts.reindex([o for o in order if o in counts.index], fill_value=0)
    if counts.sum() == 0:
        return

    grays = ["#111111", "#444444", "#777777", "#AAAAAA", "#CCCCCC"]
    colors = [grays[i % len(grays)] for i in range(len(counts))]

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(counts.index, counts.values, color=colors, edgecolor="white")
    ax.set_ylabel("Number of alerts")
    ax.set_title("CodeQL Alert Severity Distribution")
    _remove_spines(ax)
    _add_bar_labels(ax, bars)
    fig.tight_layout()
    _save(fig, out_dir / "07_codeql_severity.png")


def plot_stars_by_language(repos_df: pd.DataFrame, out_dir: Path) -> None:
    if "primary_language" not in repos_df.columns or "stars" not in repos_df.columns:
        return
    top_langs = repos_df["primary_language"].value_counts().head(8).index.tolist()
    sub = repos_df[repos_df["primary_language"].isin(top_langs)].copy()
    if sub.empty:
        return

    medians = sub.groupby("primary_language")["stars"].median().sort_values(ascending=False)
    order = medians.index.tolist()

    fig, ax = plt.subplots(figsize=(9, 5))
    parts = ax.boxplot(
        [sub[sub["primary_language"] == lang]["stars"].dropna().values for lang in order],
        labels=order,
        patch_artist=True,
        medianprops={"color": "black", "linewidth": 2},
        boxprops={"facecolor": _VERY_LIGHT, "edgecolor": _MID_GRAY},
        whiskerprops={"color": _MID_GRAY},
        capprops={"color": _MID_GRAY},
        flierprops={"marker": "o", "color": _LIGHT_GRAY, "markersize": 4},
    )
    ax.set_ylabel("Stars")
    ax.set_xlabel("Primary Language")
    ax.set_title("Star Distribution by Programming Language (top 8)")
    _remove_spines(ax)
    fig.tight_layout()
    _save(fig, out_dir / "08_stars_by_language.png")


def plot_dependabot_pr_status(repos_df: pd.DataFrame, out_dir: Path) -> None:
    cols = ["dependabot_merged_prs", "dependabot_closed_prs", "dependabot_open_prs"]
    cols = [c for c in cols if c in repos_df.columns]
    if not cols:
        return
    totals = repos_df[cols].sum()
    if totals.sum() == 0:
        return

    labels = [c.replace("dependabot_", "").replace("_prs", "").capitalize() for c in cols]
    grays = ["#333333", "#888888", "#CCCCCC"]

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(labels, totals.values, color=grays[:len(labels)], edgecolor="white")
    ax.set_ylabel("Total Dependabot PRs")
    ax.set_title("Dependabot PR Outcomes (All Repositories)")
    _remove_spines(ax)
    _add_bar_labels(ax, bars)
    fig.tight_layout()
    _save(fig, out_dir / "09_dependabot_pr_status.png")


def plot_security_score_distribution(repos_df: pd.DataFrame, out_dir: Path) -> None:
    bool_cols = [
        "has_security_md", "has_code_of_conduct", "has_contributing",
        "has_codeowners", "private_vulnerability_reporting_enabled",
        "has_security_contact", "dependabot_enabled", "codeql_enabled",
    ]
    avail = [c for c in bool_cols if c in repos_df.columns]
    if not avail:
        return

    score_df = repos_df[avail].copy()
    for c in avail:
        score_df[c] = score_df[c].map({True: 1, False: 0, "True": 1, "False": 0}).fillna(0)
    scores = score_df.sum(axis=1)

    fig, ax = plt.subplots(figsize=(8, 4))
    bins = range(0, len(avail) + 2)
    ax.hist(scores, bins=[b - 0.5 for b in bins], color=_MID_GRAY, edgecolor="white", linewidth=0.5)
    ax.set_xlabel("Security feature score (# features present)")
    ax.set_ylabel("Number of repositories")
    ax.set_title(f"Security Feature Score Distribution (max = {len(avail)})")
    ax.xaxis.set_major_locator(mticker.MultipleLocator(1))
    _remove_spines(ax)
    fig.tight_layout()
    _save(fig, out_dir / "10_security_score_distribution.png")


# ── Entry point ───────────────────────────────────────────────────────────────

def run(
    repos_df: pd.DataFrame,
    depbot_df: pd.DataFrame,
    codeql_df: pd.DataFrame,
    advisories_df: pd.DataFrame,
    analysis: Dict,
    out_dir: Path,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Generating plots → %s", out_dir)

    plot_star_distribution(repos_df, out_dir)
    plot_security_feature_adoption(repos_df, out_dir)
    plot_dependabot_merge_time(repos_df, out_dir)
    plot_top_dependabot_libraries(depbot_df, out_dir)
    plot_correlation_heatmap(repos_df.copy(), out_dir)
    plot_advisory_severity(advisories_df, out_dir)
    plot_codeql_severity(codeql_df, out_dir)
    plot_stars_by_language(repos_df, out_dir)
    plot_dependabot_pr_status(repos_df, out_dir)
    plot_security_score_distribution(repos_df, out_dir)

    logger.info("All plots saved.")
