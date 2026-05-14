"""
CodeQL data collection.

Detection strategies (tried in order, first match wins):
  1. workflow_name     — .github/workflows/ file whose name contains "codeql"
  2. workflow_content  — any workflow file whose content references github/codeql-action
  3. api_analyses      — GET /repos/{owner}/{repo}/code-scanning/analyses returns results

Alert collection:
  - Primary: GET /repos/{owner}/{repo}/code-scanning/alerts (no special scope needed
    for public repos; requires security_events scope for private repos)
  - Fallback (ENABLE_CODEQL_FORK_RUN=True): fork the repo, push a CodeQL workflow,
    wait for the run, collect alerts. The fork is NEVER deleted so subsequent runs
    skip the clone/push and go straight to fetching alerts.
"""

import logging
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from config import (
    CODEQL_BATCH_SIZE,
    CODEQL_CLONE_DIR,
    CODEQL_WORKFLOW_POLL_INTERVAL,
    CODEQL_WORKFLOW_TIMEOUT,
    DATE_FORMAT,
    ENABLE_CODEQL_FORK_RUN,
    GIT_CLONE_DELAY_SECONDS,
    GITHUB_TOKEN,
)
from utils.github_client import GitHubClient

logger = logging.getLogger(__name__)

_CODEQL_ACTION_RE = re.compile(r"github/codeql-action", re.IGNORECASE)
_SEVERITY_MAP = {"none": "low", "note": "low", "warning": "medium", "error": "high"}

# Limits concurrent git clones to CODEQL_BATCH_SIZE regardless of how many
# threads the outer ThreadPoolExecutor is running.
_clone_semaphore = threading.Semaphore(CODEQL_BATCH_SIZE)


# ── Detection ────────────────────────────────────────────────────────────────

def _detect_from_workflows(
    client: GitHubClient, owner: str, repo: str
) -> Tuple[bool, List[str], str]:
    """Scan .github/workflows for CodeQL usage.

    Returns (found, [languages], strategy_string).
    strategy_string is one of: "workflow_name", "workflow_content", "".
    """
    workflows = client.get(f"/repos/{owner}/{repo}/contents/.github/workflows")
    if not isinstance(workflows, list):
        return False, [], ""

    for wf in workflows:
        name = (wf.get("name") or "").lower()
        path = wf.get("path", "")
        content = client.get_file_content(owner, repo, path)

        if "codeql" in name:
            langs = _extract_languages(content or "")
            return True, langs, "workflow_name"

        if content and _CODEQL_ACTION_RE.search(content):
            langs = _extract_languages(content)
            return True, langs, "workflow_content"

    return False, [], ""


def _extract_languages(content: str) -> List[str]:
    langs = re.findall(r"language['\"]?\s*:\s*['\"]?([a-zA-Z+\-]+)['\"]?", content)
    return list({l.lower() for l in langs if l.lower() not in ("language", "languages")})


# ── Alert collection ─────────────────────────────────────────────────────────

def _get_alerts_from_api(
    client: GitHubClient, owner: str, repo: str
) -> Optional[List[Dict]]:
    """Fetch code-scanning alerts via the REST API.
    Returns None if access is denied (403/404), or a list (possibly empty).
    """
    probe = client.get(
        f"/repos/{owner}/{repo}/code-scanning/alerts",
        params={"per_page": 1},
        use_cache=False,
    )
    if probe is None:
        return None
    return client.get_paginated(f"/repos/{owner}/{repo}/code-scanning/alerts")


def _parse_alert(alert: Dict, owner: str, repo: str) -> Dict:
    rule = alert.get("rule") or {}
    severity_raw = (
        rule.get("security_severity_level") or rule.get("severity") or ""
    ).lower()
    severity = (
        severity_raw
        if severity_raw in ("critical", "high", "medium", "low")
        else _SEVERITY_MAP.get(severity_raw, severity_raw or "unknown")
    )
    tags = rule.get("tags") or []
    cwes = [t for t in tags if t.lower().startswith("cwe")]
    return {
        "repo_full_name": f"{owner}/{repo}",
        "alert_number": alert.get("number"),
        "title": (rule.get("description") or rule.get("name") or "")[:255],
        "severity": severity,
        "cwes": ";".join(cwes),
        "state": alert.get("state", ""),
    }


# ── Fork-and-run ─────────────────────────────────────────────────────────────

_CODEQL_WORKFLOW_TEMPLATE = """\
name: "CodeQL Analysis (SBSEG Research)"
on:
  push:
    branches: ["**"]
  workflow_dispatch:
jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write
    strategy:
      fail-fast: false
      matrix:
        language: ["python", "javascript", "typescript", "java", "go", "cpp", "csharp", "ruby"]
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
      - name: Autobuild
        uses: github/codeql-action/autobuild@v3
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3
"""


def _fork_and_run(
    client: GitHubClient, owner: str, repo: str
) -> Tuple[Optional[List[Dict]], str]:
    """Fork repo, run CodeQL, collect alerts.

    The fork is NEVER deleted. On subsequent calls the existing fork is reused
    directly and alerts are fetched without cloning again.

    Returns (alert_list_or_None, strategy_string).
    strategy_string: "fork_existing" | "fork_new" | "fork_failed"
    """
    import subprocess

    if not GITHUB_TOKEN:
        logger.warning(
            "ENABLE_CODEQL_FORK_RUN requires GITHUB_TOKEN — skipping %s/%s", owner, repo
        )
        return None, "fork_failed"

    me_data = client.get("/user", use_cache=False)
    if not me_data:
        logger.warning("Could not determine authenticated user — skipping fork-and-run")
        return None, "fork_failed"
    me = me_data.get("login", "")
    if not me:
        return None, "fork_failed"

    fork_full = f"{me}/{repo}"

    # ── Check if fork already exists ─────────────────────────────────────────
    existing = client.get(f"/repos/{fork_full}", use_cache=False)
    if existing:
        logger.info(
            "[%s/%s] Fork already exists at %s — fetching existing alerts",
            owner, repo, fork_full,
        )
        raw = client.get_paginated(f"/repos/{fork_full}/code-scanning/alerts")
        alerts = [_parse_alert(a, owner, repo) for a in (raw or [])]
        logger.info(
            "[%s/%s] Found %d alert(s) in existing fork", owner, repo, len(alerts)
        )
        return alerts, "fork_existing"

    # ── Create new fork ───────────────────────────────────────────────────────
    logger.info("[%s/%s] Creating fork for CodeQL run …", owner, repo)
    fork_data = client.post(
        f"/repos/{owner}/{repo}/forks", {"default_branch_only": True}
    )
    if not fork_data:
        logger.warning("Failed to fork %s/%s", owner, repo)
        return None, "fork_failed"

    time.sleep(15)  # GitHub needs a moment to provision the fork

    # ── Clone, add workflow, push ─────────────────────────────────────────────
    clone_dir = CODEQL_CLONE_DIR / repo
    clone_dir.parent.mkdir(parents=True, exist_ok=True)
    clone_url = f"https://{GITHUB_TOKEN}@github.com/{fork_full}.git"

    with _clone_semaphore:
        try:
            subprocess.run(
                ["git", "clone", "--depth=1", clone_url, str(clone_dir)],
                check=True, capture_output=True, text=True,
            )
            client.stats.git_clones += 1
        except subprocess.CalledProcessError as exc:
            logger.error("git clone failed for %s: %s", fork_full, exc.stderr[:500])
            return None, "fork_failed"
        finally:
            time.sleep(GIT_CLONE_DELAY_SECONDS)

    try:
        wf_dir = clone_dir / ".github" / "workflows"
        wf_dir.mkdir(parents=True, exist_ok=True)
        (wf_dir / "codeql-sbseg.yml").write_text(_CODEQL_WORKFLOW_TEMPLATE)

        subprocess.run(["git", "-C", str(clone_dir), "config", "user.email", "sbseg@research.local"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(clone_dir), "config", "user.name", "SBSEG Research"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(clone_dir), "add", ".github/workflows/codeql-sbseg.yml"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(clone_dir), "commit", "-m", "ci: add CodeQL analysis for SBSEG research"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(clone_dir), "push"], check=True, capture_output=True)
        logger.info("[%s] Workflow pushed — fork kept for future runs", fork_full)
    except subprocess.CalledProcessError as exc:
        logger.error(
            "Git operations failed for %s: %s",
            fork_full,
            exc.stderr[:500] if exc.stderr else str(exc),
        )
        return None, "fork_failed"
    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)  # local clone removed; fork kept on GitHub

    # ── Poll for workflow completion ──────────────────────────────────────────
    logger.info(
        "[%s] Waiting for CodeQL workflow … (max %ds)", fork_full, CODEQL_WORKFLOW_TIMEOUT
    )
    deadline = time.time() + CODEQL_WORKFLOW_TIMEOUT

    while time.time() < deadline:
        time.sleep(CODEQL_WORKFLOW_POLL_INTERVAL)
        runs_data = client.get(f"/repos/{fork_full}/actions/runs", use_cache=False)
        if not runs_data:
            continue
        for run in runs_data.get("workflow_runs", []):
            run_name = (run.get("name") or run.get("path") or "").lower()
            if "codeql" not in run_name and "sbseg" not in run_name:
                continue
            if run.get("status") == "completed":
                conclusion = run.get("conclusion", "")
                logger.info(
                    "[%s] CodeQL run finished: %s", fork_full, conclusion
                )
                break
        else:
            logger.debug("[%s] CodeQL still running …", fork_full)
            continue
        break
    else:
        logger.warning("[%s] CodeQL timed out — collecting whatever alerts exist", fork_full)

    raw = client.get_paginated(f"/repos/{fork_full}/code-scanning/alerts")
    alerts = [_parse_alert(a, owner, repo) for a in (raw or [])]
    logger.info("[%s/%s] CodeQL fork-and-run complete: %d alerts", owner, repo, len(alerts))
    return alerts, "fork_new"


# ── Public entry point ────────────────────────────────────────────────────────

def collect(
    client: GitHubClient, owner: str, repo: str
) -> Tuple[Dict, List[Dict]]:
    """Return (repo_level_stats_dict, list_of_alert_dicts)."""
    logger.debug("[%s/%s] Collecting CodeQL data …", owner, repo)

    _empty = {
        "codeql_enabled": False,
        "codeql_detection_strategy": "",
        "codeql_languages": "",
        "codeql_total_alerts": 0,
        "codeql_low_alerts": 0,
        "codeql_medium_alerts": 0,
        "codeql_high_alerts": 0,
        "codeql_critical_alerts": 0,
    }

    # Step 1: detect usage
    found_wf, langs_wf, strategy = _detect_from_workflows(client, owner, repo)

    # Secondary check via analyses API
    analyses = client.get(
        f"/repos/{owner}/{repo}/code-scanning/analyses",
        params={"per_page": 1},
    )
    found_api = isinstance(analyses, list) and len(analyses) > 0
    if found_api and not found_wf:
        strategy = "api_analyses"

    enabled = found_wf or found_api

    if not enabled:
        return _empty, []

    logger.info(
        "[%s/%s] CodeQL detected via strategy: %s", owner, repo, strategy
    )

    # Step 2: collect alerts
    raw_alerts = _get_alerts_from_api(client, owner, repo)

    if raw_alerts is None and ENABLE_CODEQL_FORK_RUN:
        logger.info(
            "[%s/%s] API alerts inaccessible — starting fork-and-run", owner, repo
        )
        raw_alerts, fork_strategy = _fork_and_run(client, owner, repo)
        if fork_strategy != "fork_failed":
            strategy = fork_strategy
    elif raw_alerts is None:
        raw_alerts = []
        logger.debug("[%s/%s] CodeQL alerts not accessible via API", owner, repo)

    alert_rows = [_parse_alert(a, owner, repo) for a in (raw_alerts or [])]

    sev = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for a in alert_rows:
        k = a["severity"]
        if k in sev:
            sev[k] += 1

    # Enrich languages from analyses if workflow parsing yielded nothing
    detected_langs = langs_wf
    if not detected_langs and found_api:
        all_analyses = client.get_paginated(
            f"/repos/{owner}/{repo}/code-scanning/analyses"
        )
        lang_set = {a.get("tool", {}).get("name", "") for a in all_analyses}
        detected_langs = [l.lower() for l in lang_set if l]

    repo_stats = {
        "codeql_enabled": True,
        "codeql_detection_strategy": strategy,
        "codeql_languages": ";".join(sorted(set(detected_langs))),
        "codeql_total_alerts": len(alert_rows),
        "codeql_low_alerts": sev["low"],
        "codeql_medium_alerts": sev["medium"],
        "codeql_high_alerts": sev["high"],
        "codeql_critical_alerts": sev["critical"],
    }

    logger.debug(
        "[%s/%s] CodeQL: strategy=%s, alerts=%d", owner, repo, strategy, len(alert_rows)
    )
    return repo_stats, alert_rows
