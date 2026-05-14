"""
Statistical analysis module.

Produces:
  - Descriptive statistics for all numeric and boolean/categorical columns
  - Pearson and Spearman correlation matrices
  - Rankings (top libraries, top advisory repos, best/worst response times)
  - Group comparisons (by language, year, security-feature presence)

All results are returned as a nested dict and also saved to output/analysis.json.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd
from scipy import stats as scipy_stats

logger = logging.getLogger(__name__)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _safe_round(v, n=4):
    try:
        return round(float(v), n) if v is not None and not np.isnan(float(v)) else None
    except (TypeError, ValueError):
        return None


def _describe_numeric(series: pd.Series) -> Dict:
    s = series.dropna()
    if s.empty:
        return {}
    return {
        "count": int(s.count()),
        "mean": _safe_round(s.mean()),
        "median": _safe_round(s.median()),
        "std": _safe_round(s.std()),
        "min": _safe_round(s.min()),
        "p25": _safe_round(s.quantile(0.25)),
        "p75": _safe_round(s.quantile(0.75)),
        "max": _safe_round(s.max()),
    }


def _describe_categorical(series: pd.Series) -> Dict:
    counts = series.value_counts(dropna=False)
    total = len(series)
    return {
        str(k): {
            "count": int(v),
            "pct": _safe_round(v / total * 100, 2) if total else 0,
        }
        for k, v in counts.items()
    }


def _correlation(df: pd.DataFrame, cols: List[str]) -> Dict:
    sub = df[cols].apply(pd.to_numeric, errors="coerce").dropna(how="all")
    valid = [c for c in cols if sub[c].nunique() > 1]
    if len(valid) < 2:
        return {}
    sub = sub[valid].dropna()
    if len(sub) < 3:
        return {}

    pearson = sub.corr(method="pearson").round(4)
    spearman = sub.corr(method="spearman").round(4)

    return {
        "pearson": pearson.to_dict(),
        "spearman": spearman.to_dict(),
        "columns_used": valid,
        "n_observations": len(sub),
    }


# ── Main analysis entry point ────────────────────────────────────────────────

def run(
    repos_df: pd.DataFrame,
    depbot_df: pd.DataFrame,
    codeql_df: pd.DataFrame,
    advisories_df: pd.DataFrame,
    output_dir: Path,
) -> Dict:
    logger.info("Running statistical analysis …")
    result: Dict = {}

    # ── 1. Descriptive stats ────────────────────────────────────────────────

    numeric_cols = [
        "stars", "contributors_count",
        "dependabot_total_prs", "dependabot_merged_prs", "dependabot_closed_prs",
        "dependabot_open_prs", "dependabot_avg_merge_days", "dependabot_acceptance_rate",
        "codeql_total_alerts", "codeql_low_alerts", "codeql_medium_alerts",
        "codeql_high_alerts", "codeql_critical_alerts",
        "advisory_total", "advisory_low", "advisory_medium",
        "advisory_high", "advisory_critical",
    ]
    bool_cols = [
        "has_security_md", "has_code_of_conduct", "has_contributing", "has_codeowners",
        "private_vulnerability_reporting_enabled", "has_security_contact",
        "dependabot_enabled", "codeql_enabled", "has_advisories",
    ]

    desc: Dict = {}
    for col in numeric_cols:
        if col in repos_df.columns:
            desc[col] = _describe_numeric(repos_df[col])
    for col in bool_cols:
        if col in repos_df.columns:
            desc[col] = _describe_categorical(repos_df[col])

    result["descriptive"] = desc
    logger.info("  Descriptive stats: %d numeric, %d categorical", len(numeric_cols), len(bool_cols))

    # ── 2. Correlations ─────────────────────────────────────────────────────

    corr_cols = [
        "stars", "contributors_count",
        "dependabot_avg_merge_days", "dependabot_acceptance_rate",
        "dependabot_total_prs",
        "codeql_total_alerts",
        "advisory_total",
    ]
    # Convert booleans to 0/1 for correlation
    for col in bool_cols:
        if col in repos_df.columns:
            repos_df[f"_num_{col}"] = repos_df[col].map({True: 1, False: 0, "True": 1, "False": 0})
            corr_cols.append(f"_num_{col}")

    corr_cols = [c for c in corr_cols if c in repos_df.columns]
    result["correlations"] = _correlation(repos_df, corr_cols)

    # ── 3. Rankings ─────────────────────────────────────────────────────────

    rankings: Dict = {}

    # 3a. Top 20 libraries updated by Dependabot
    if not depbot_df.empty and "library_name" in depbot_df.columns:
        lib_counts = (
            depbot_df[depbot_df["library_name"] != "unknown"]
            .groupby("library_name")
            .size()
            .sort_values(ascending=False)
            .head(20)
        )
        rankings["top_20_dependabot_libraries"] = lib_counts.to_dict()
    else:
        rankings["top_20_dependabot_libraries"] = {}

    # 3b. Top 20 repos with most advisories
    if "advisory_total" in repos_df.columns:
        top_adv = (
            repos_df[["full_name", "advisory_total"]]
            .sort_values("advisory_total", ascending=False)
            .head(20)
        )
        rankings["top_20_repos_by_advisories"] = top_adv.set_index("full_name")["advisory_total"].to_dict()
    else:
        rankings["top_20_repos_by_advisories"] = {}

    # 3c. Dependabot response time — best and worst
    if "dependabot_avg_merge_days" in repos_df.columns:
        rt = repos_df[["full_name", "dependabot_avg_merge_days"]].dropna()
        rankings["dependabot_fastest_response"] = (
            rt.sort_values("dependabot_avg_merge_days").head(10)
            .set_index("full_name")["dependabot_avg_merge_days"].to_dict()
        )
        rankings["dependabot_slowest_response"] = (
            rt.sort_values("dependabot_avg_merge_days", ascending=False).head(10)
            .set_index("full_name")["dependabot_avg_merge_days"].to_dict()
        )

    # 3d. Security feature score (number of security features present)
    feat_cols = [c for c in bool_cols if c in repos_df.columns]
    if feat_cols:
        feat_df = repos_df[["full_name"] + feat_cols].copy()
        for c in feat_cols:
            feat_df[c] = feat_df[c].map({True: 1, False: 0, "True": 1, "False": 0}).fillna(0)
        feat_df["_sec_score"] = feat_df[feat_cols].sum(axis=1)
        rankings["most_secure_repos"] = (
            feat_df.sort_values("_sec_score", ascending=False)
            .head(10)[["full_name", "_sec_score"]]
            .set_index("full_name")["_sec_score"].to_dict()
        )
        rankings["least_secure_repos"] = (
            feat_df.sort_values("_sec_score")
            .head(10)[["full_name", "_sec_score"]]
            .set_index("full_name")["_sec_score"].to_dict()
        )

    result["rankings"] = rankings

    # ── 4. Comparisons ──────────────────────────────────────────────────────

    comparisons: Dict = {}

    def _group_stats(group_col: str, metric_cols: List[str]) -> Dict:
        out = {}
        for gval, gdf in repos_df.groupby(group_col, dropna=True):
            out[str(gval)] = {
                "n": len(gdf),
                **{col: _describe_numeric(gdf[col]) for col in metric_cols if col in gdf.columns},
            }
        return out

    metric_subset = [
        "dependabot_avg_merge_days", "dependabot_acceptance_rate",
        "advisory_total", "codeql_total_alerts", "stars",
    ]

    # By primary language (top 8 most common)
    if "primary_language" in repos_df.columns:
        top_langs = repos_df["primary_language"].value_counts().head(8).index.tolist()
        lang_df = repos_df[repos_df["primary_language"].isin(top_langs)]
        comparisons["by_language"] = {}
        for lang, gdf in lang_df.groupby("primary_language"):
            comparisons["by_language"][lang] = {
                "n": len(gdf),
                **{col: _describe_numeric(gdf[col]) for col in metric_subset if col in gdf.columns},
            }

    # By year of creation
    if "year_created" in repos_df.columns:
        comparisons["by_year"] = _group_stats("year_created", metric_subset)

    # Has SECURITY.md vs not
    if "has_security_md" in repos_df.columns:
        comparisons["has_security_md"] = _group_stats("has_security_md", metric_subset)

    # Has Dependabot vs not
    if "dependabot_enabled" in repos_df.columns:
        comparisons["has_dependabot"] = _group_stats("dependabot_enabled", metric_subset)

    # Has CodeQL vs not
    if "codeql_enabled" in repos_df.columns:
        comparisons["has_codeql"] = _group_stats("codeql_enabled", metric_subset)

    result["comparisons"] = comparisons

    # ── 5. Advisory severity distribution across all repos ──────────────────

    if not advisories_df.empty and "severity" in advisories_df.columns:
        result["advisory_severity_distribution"] = _describe_categorical(advisories_df["severity"])

    # ── 6. CodeQL severity distribution ─────────────────────────────────────

    if not codeql_df.empty and "severity" in codeql_df.columns:
        result["codeql_severity_distribution"] = _describe_categorical(codeql_df["severity"])

    # ── Save ─────────────────────────────────────────────────────────────────

    out_path = output_dir / "analysis.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("Analysis saved to %s", out_path)
    return result
