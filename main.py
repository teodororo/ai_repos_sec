"""
GitHub Security Analysis — main entry point.

Usage:
    python main.py              # resume from last run (skips already-saved repos)
    python main.py --fresh      # delete CSVs and start over (cache kept)
    python main.py --no-cache   # ignore cached API responses (implies fresh HTTP calls)
    python main.py --log DEBUG  # verbose logging
    python main.py --workers 8  # override MAX_WORKERS

Resume behaviour
----------------
Each repo's data is written to the four CSV files immediately after collection.
On restart, repos already present in repositories.csv are skipped automatically.
Use --fresh to force a full re-run (e.g. after changing MAX_REPOS or search criteria).
"""

import argparse
import logging
import shutil
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import pandas as pd
from tqdm import tqdm

from config import (
    CACHE_DIR,
    MAX_REPOS,
    MAX_WORKERS,
    OUTPUT_DIR,
    SEARCH_TOPICS,
    GITHUB_TOKEN,
)
from utils.logging_setup import setup_logging
from utils.github_client import GitHubClient

import collectors.repos as repo_collector
import collectors.security_docs as security_docs_collector
import collectors.dependabot as dependabot_collector
import collectors.codeql as codeql_collector
import collectors.advisories as advisory_collector

import analysis.stats as stats_module
import analysis.plots as plots_module

logger = logging.getLogger(__name__)


# ── CSV column schemas ────────────────────────────────────────────────────────

_REPOS_COLUMNS = [
    "full_name", "stars", "year_created", "primary_language", "topics",
    "contributors_count",
    # security docs
    "has_security_md", "has_code_of_conduct", "has_contributing", "has_codeowners",
    "private_vulnerability_reporting_enabled", "has_security_contact",
    # dependabot
    "dependabot_enabled", "dependabot_frequency",
    "dependabot_total_prs", "dependabot_merged_prs", "dependabot_closed_prs",
    "dependabot_open_prs", "dependabot_avg_merge_days", "dependabot_acceptance_rate",
    # codeql
    "codeql_enabled", "codeql_detection_strategy", "codeql_languages",
    "codeql_total_alerts", "codeql_low_alerts", "codeql_medium_alerts",
    "codeql_high_alerts", "codeql_critical_alerts",
    # advisories
    "has_advisories",
    "advisory_total", "advisory_low", "advisory_medium", "advisory_high", "advisory_critical",
]

_DEPBOT_COLUMNS = [
    "repo_full_name", "pr_number", "pr_title",
    "created_at", "merged_at", "closed_at",
    "status", "library_name", "days_to_resolution",
]

_CODEQL_COLUMNS = [
    "repo_full_name", "alert_number", "title", "severity", "cwes", "state",
]

_ADVISORY_COLUMNS = [
    "repo_full_name", "advisory_id", "ghsa_id", "cve_id",
    "title", "severity", "cwes", "ecosystem",
]


# ── Incremental CSV writer ────────────────────────────────────────────────────

class IncrementalCSV:
    """Thread-safe CSV writer that appends rows immediately after each repo."""

    def __init__(self, path: Path, columns: List[str]) -> None:
        self.path = path
        self.columns = columns
        self._lock = threading.Lock()
        if not path.exists():
            pd.DataFrame(columns=columns).to_csv(path, index=False, encoding="utf-8")

    def append(self, rows: List[Dict]) -> None:
        if not rows:
            return
        df = pd.DataFrame(rows)
        for col in self.columns:
            if col not in df.columns:
                df[col] = None
        df = df[self.columns]
        with self._lock:
            df.to_csv(self.path, mode="a", header=False, index=False, encoding="utf-8")

    def existing_keys(self, key_column: str) -> Set[str]:
        """Return set of values already stored in key_column (for skip logic)."""
        if not self.path.exists():
            return set()
        try:
            df = pd.read_csv(self.path, usecols=[key_column], dtype=str)
            return set(df[key_column].dropna().tolist())
        except Exception as exc:
            logger.warning("Could not read existing keys from %s: %s", self.path, exc)
            return set()

    def row_count(self) -> int:
        if not self.path.exists():
            return 0
        try:
            return sum(1 for _ in open(self.path, encoding="utf-8")) - 1  # minus header
        except Exception:
            return 0


# ── Per-repo collection ───────────────────────────────────────────────────────

def collect_repo(
    client: GitHubClient,
    raw_repo: Dict,
) -> Tuple[Optional[Dict], List[Dict], List[Dict], List[Dict]]:
    """Collect all data for one repository.

    Each sub-collector is wrapped individually: a failure in one (e.g. CodeQL)
    does not discard data already gathered by the others.

    Returns (repo_row | None, depbot_prs, codeql_alerts, advisories).
    """
    full_name = raw_repo.get("full_name", "")
    owner, _, repo = full_name.partition("/")
    if not owner or not repo:
        logger.warning("Skipping malformed repo name: %s", full_name)
        return None, [], [], []

    logger.info("Collecting: %s", full_name)

    # 1. Basic info — if this fails, skip the whole repo
    try:
        contributors = client.get_contributors_count(owner, repo)
        basic = repo_collector.parse_basic_info(raw_repo, contributors)
    except Exception as exc:
        logger.error("[%s] basic info failed: %s", full_name, exc)
        return None, [], [], []

    # 2. Security docs
    try:
        sec_docs = security_docs_collector.collect(client, owner, repo)
    except Exception as exc:
        logger.warning("[%s] security docs failed: %s", full_name, exc)
        sec_docs = {}

    # 3. Dependabot
    try:
        dep_stats, dep_prs = dependabot_collector.collect(client, owner, repo)
    except Exception as exc:
        logger.warning("[%s] dependabot failed: %s", full_name, exc)
        dep_stats, dep_prs = {}, []

    # 4. CodeQL
    try:
        cql_stats, cql_alerts = codeql_collector.collect(client, owner, repo)
    except Exception as exc:
        logger.warning("[%s] codeql failed: %s", full_name, exc)
        cql_stats, cql_alerts = {}, []

    # 5. Advisories
    try:
        adv_stats, adv_rows = advisory_collector.collect(client, owner, repo)
    except Exception as exc:
        logger.warning("[%s] advisories failed: %s", full_name, exc)
        adv_stats, adv_rows = {}, []

    repo_row = {**basic, **sec_docs, **dep_stats, **cql_stats, **adv_stats}
    return repo_row, dep_prs, cql_alerts, adv_rows


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="GitHub Security Analysis for SBSEG")
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Delete output CSVs and restart from scratch (cache is kept)",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Delete the API cache and ignore any cached responses",
    )
    parser.add_argument("--log", default="INFO", help="Log level (DEBUG|INFO|WARNING)")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS)
    args = parser.parse_args()

    setup_logging(args.log)
    start_time = time.perf_counter()

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # ── Handle --fresh and --no-cache ─────────────────────────────────────────
    if args.no_cache and CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR)
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        logger.info("API cache cleared (--no-cache).")

    csv_paths = [
        OUTPUT_DIR / "repositories.csv",
        OUTPUT_DIR / "dependabot_prs.csv",
        OUTPUT_DIR / "codeql_alerts.csv",
        OUTPUT_DIR / "advisories.csv",
    ]
    if args.fresh:
        for p in csv_paths:
            p.unlink(missing_ok=True)
        logger.info("Output CSVs deleted (--fresh). Starting from scratch.")

    # ── Initialise incremental writers ───────────────────────────────────────
    repos_csv    = IncrementalCSV(OUTPUT_DIR / "repositories.csv",  _REPOS_COLUMNS)
    depbot_csv   = IncrementalCSV(OUTPUT_DIR / "dependabot_prs.csv", _DEPBOT_COLUMNS)
    codeql_csv   = IncrementalCSV(OUTPUT_DIR / "codeql_alerts.csv",  _CODEQL_COLUMNS)
    advisory_csv = IncrementalCSV(OUTPUT_DIR / "advisories.csv",     _ADVISORY_COLUMNS)

    already_done: Set[str] = repos_csv.existing_keys("full_name")
    if already_done:
        logger.info(
            "Resuming: %d repo(s) already in repositories.csv — will be skipped.",
            len(already_done),
        )

    # ── GitHub client ─────────────────────────────────────────────────────────
    client = GitHubClient()

    rl = client.get_rate_limit()
    if rl:
        core = (rl.get("resources") or {}).get("core", {})
        remaining = core.get("remaining", "?")
        limit = core.get("limit", "?")
        logger.info("GitHub API rate limit: %s / %s remaining", remaining, limit)
        if not GITHUB_TOKEN:
            logger.warning(
                "Running unauthenticated — %s requests remaining. "
                "Set GITHUB_TOKEN in .env for 5 000 requests/hour.",
                remaining,
            )

    # ── 1. Search repositories ────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("Searching for AI repositories …")
    logger.info(
        "Criteria: stars >= 1000, created 2024-01-01..2026-04-30, %d topics",
        len(SEARCH_TOPICS),
    )
    logger.info(
        "MAX_REPOS = %s  |  already done = %d",
        MAX_REPOS, len(already_done),
    )

    raw_repos, unique_total = repo_collector.search_repositories(client)

    # Filter out already-processed repos
    pending = [r for r in raw_repos if r.get("full_name") not in already_done]

    logger.info("=" * 60)
    logger.info("Unique repos found: %d", unique_total)
    logger.info("Already processed:  %d", len(already_done))
    logger.info("To collect now:     %d", len(pending))
    logger.info("=" * 60)

    if not pending:
        logger.info("Nothing new to collect. Use --fresh to re-run everything.")
        _print_summary(client, repos_csv, depbot_csv, codeql_csv, advisory_csv,
                       unique_total, start_time)
        return

    # ── 2. Collect data per repository (parallel, incremental saves) ──────────
    n_workers = min(args.workers, len(pending))
    logger.info("Collecting data with %d worker(s) …", n_workers)

    ok_count = 0
    err_count = 0
    errors: List[str] = []

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = {
            pool.submit(collect_repo, client, raw): raw.get("full_name", "?")
            for raw in pending
        }

        with tqdm(total=len(futures), desc="Repositories", unit="repo", ncols=80) as pbar:
            for future in as_completed(futures):
                name = futures[future]
                try:
                    row, dep_prs, cql_alerts, adv_rows = future.result()
                    if row:
                        # Write immediately — safe even if process is killed after this line
                        repos_csv.append([row])
                        depbot_csv.append(dep_prs)
                        codeql_csv.append(cql_alerts)
                        advisory_csv.append(adv_rows)
                        ok_count += 1
                    else:
                        err_count += 1
                        errors.append(name)
                except Exception as exc:
                    logger.error("Unhandled error for %s: %s", name, exc, exc_info=True)
                    err_count += 1
                    errors.append(name)
                finally:
                    pbar.update(1)
                    pbar.set_postfix({"ok": ok_count, "err": err_count})

    logger.info("Collection complete. OK: %d, Errors: %d", ok_count, err_count)
    if errors:
        logger.warning("Failed repos: %s", ", ".join(errors))

    # ── 3. Statistical analysis & plots ──────────────────────────────────────
    # Re-read full CSVs (includes previously saved + just collected)
    def _read(path: Path, cols: List[str]) -> pd.DataFrame:
        try:
            return pd.read_csv(path, dtype=str) if path.exists() else pd.DataFrame(columns=cols)
        except Exception:
            return pd.DataFrame(columns=cols)

    repos_df    = _read(OUTPUT_DIR / "repositories.csv",  _REPOS_COLUMNS)
    depbot_df   = _read(OUTPUT_DIR / "dependabot_prs.csv", _DEPBOT_COLUMNS)
    codeql_df   = _read(OUTPUT_DIR / "codeql_alerts.csv",  _CODEQL_COLUMNS)
    advisory_df = _read(OUTPUT_DIR / "advisories.csv",     _ADVISORY_COLUMNS)

    # Coerce numeric columns
    num_cols = [
        "stars", "contributors_count",
        "dependabot_total_prs", "dependabot_merged_prs", "dependabot_closed_prs",
        "dependabot_open_prs", "dependabot_avg_merge_days", "dependabot_acceptance_rate",
        "codeql_total_alerts", "codeql_low_alerts", "codeql_medium_alerts",
        "codeql_high_alerts", "codeql_critical_alerts",
        "advisory_total", "advisory_low", "advisory_medium", "advisory_high", "advisory_critical",
        "year_created",
    ]
    for col in num_cols:
        if col in repos_df.columns:
            repos_df[col] = pd.to_numeric(repos_df[col], errors="coerce")

    analysis = stats_module.run(
        repos_df.copy(), depbot_df.copy(), codeql_df.copy(), advisory_df.copy(),
        OUTPUT_DIR,
    )

    plots_module.run(
        repos_df.copy(), depbot_df.copy(), codeql_df.copy(), advisory_df.copy(),
        analysis,
        OUTPUT_DIR / "plots",
    )

    _print_summary(client, repos_csv, depbot_csv, codeql_csv, advisory_csv,
                   unique_total, start_time)


def _print_summary(
    client: GitHubClient,
    repos_csv: IncrementalCSV,
    depbot_csv: IncrementalCSV,
    codeql_csv: IncrementalCSV,
    advisory_csv: IncrementalCSV,
    unique_total: int,
    start_time: float,
) -> None:
    elapsed = time.perf_counter() - start_time
    h, rem = divmod(int(elapsed), 3600)
    m, s = divmod(rem, 60)

    # Re-read repos for quick stats
    repos_path = OUTPUT_DIR / "repositories.csv"
    try:
        repos_df = pd.read_csv(repos_path, dtype=str)
    except Exception:
        repos_df = pd.DataFrame()

    print("\n" + "=" * 60)
    print("  COLLECTION SUMMARY")
    print("=" * 60)
    print(f"  Unique repos found (search):          {unique_total:>6,}")
    print(f"  Repos in repositories.csv:            {repos_csv.row_count():>6,}")
    print(f"  Dependabot PRs in depbot_prs.csv:     {depbot_csv.row_count():>6,}")
    print(f"  CodeQL alerts in codeql_alerts.csv:   {codeql_csv.row_count():>6,}")
    print(f"  Advisories in advisories.csv:         {advisory_csv.row_count():>6,}")
    print()

    if not repos_df.empty:
        bool_features = [
            ("has_security_md",                       "Has SECURITY.md"),
            ("dependabot_enabled",                    "Dependabot enabled"),
            ("codeql_enabled",                        "CodeQL enabled"),
            ("private_vulnerability_reporting_enabled", "Private vuln. reporting"),
        ]
        for col, label in bool_features:
            if col in repos_df.columns:
                pct = (
                    repos_df[col]
                    .map({"True": 1, "False": 0, "1": 1, "0": 0})
                    .mean() * 100
                )
                print(f"  {label:<40} {pct:5.1f}%")

        if "codeql_detection_strategy" in repos_df.columns:
            print()
            print("  CodeQL detection strategies used:")
            strats = repos_df.loc[
                repos_df["codeql_enabled"].isin(["True", "1"]), "codeql_detection_strategy"
            ].value_counts()
            for strat, count in strats.items():
                print(f"    {strat:<30} {count:>4} repo(s)")

    print()
    print("  API requests:")
    print(f"    Core (REST)     {client.stats.core:>8,}")
    print(f"    Search          {client.stats.search:>8,}")
    print(f"    Cache hits      {client.stats.cache_hits:>8,}")
    print(f"    Git clones      {client.stats.git_clones:>8,}")
    print(f"    Total API calls {client.stats.total_api():>8,}")
    print()
    print(f"  Total elapsed time: {h:02d}:{m:02d}:{s:02d}")
    print()
    print(f"  Output files → {OUTPUT_DIR.resolve()}/")
    print("    repositories.csv  |  dependabot_prs.csv")
    print("    codeql_alerts.csv |  advisories.csv")
    print("    analysis.json     |  plots/ (10 charts)")
    print("=" * 60 + "\n")

    logger.info("Done. Elapsed: %02d:%02d:%02d", h, m, s)


if __name__ == "__main__":
    main()
