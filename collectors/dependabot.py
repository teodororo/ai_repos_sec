"""
Dependabot data collection:
  - enabled / frequency from .github/dependabot.yml
  - all PRs created by the dependabot bot (historical, all states)
  - aggregated stats
"""

import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import yaml

from config import DATE_FORMAT
from utils.github_client import GitHubClient

logger = logging.getLogger(__name__)

_DEPENDABOT_LOGINS = {"dependabot[bot]", "dependabot-preview[bot]"}

_LIBRARY_RE = re.compile(
    r"(?:bump|update)\s+(\S+)\s+(?:requirement\s+)?from\s",
    re.IGNORECASE,
)
_LIBRARY_TO_RE = re.compile(
    r"(?:bump|update)\s+(\S+)\s+to\s+",
    re.IGNORECASE,
)


def _parse_library(title: str) -> str:
    for pat in (_LIBRARY_RE, _LIBRARY_TO_RE):
        m = pat.search(title)
        if m:
            return m.group(1).lower()
    return "unknown"


def _fmt_date(dt_str: Optional[str]) -> Optional[str]:
    if not dt_str:
        return None
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        return dt.strftime(DATE_FORMAT)
    except ValueError:
        return dt_str[:10]


def _days_between(start: Optional[str], end: Optional[str]) -> Optional[float]:
    if not start or not end:
        return None
    try:
        t0 = datetime.fromisoformat(start.replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(end.replace("Z", "+00:00"))
        return max(0.0, round((t1 - t0).total_seconds() / 86400, 2))
    except ValueError:
        return None


def _get_config(client: GitHubClient, owner: str, repo: str) -> Tuple[bool, Optional[str]]:
    """Return (enabled, frequency_string | None)."""
    content = client.get_file_content(owner, repo, ".github/dependabot.yml")
    if content is None:
        content = client.get_file_content(owner, repo, ".github/dependabot.yaml")
    if content is None:
        return False, None

    try:
        cfg = yaml.safe_load(content)
        updates = cfg.get("updates", [])
        frequencies = list({u.get("schedule", {}).get("interval") for u in updates if isinstance(u, dict)})
        frequencies = [f for f in frequencies if f]
        freq_str = ";".join(sorted(frequencies)) if frequencies else None
        return True, freq_str
    except Exception as exc:
        logger.debug("Failed to parse dependabot.yml for %s/%s: %s", owner, repo, exc)
        return True, None  # file exists but couldn't parse


def collect(
    client: GitHubClient, owner: str, repo: str
) -> Tuple[Dict, List[Dict]]:
    """Return (repo_level_stats_dict, list_of_pr_dicts)."""
    logger.debug("[%s/%s] Collecting Dependabot data …", owner, repo)

    enabled, frequency = _get_config(client, owner, repo)

    # Fetch all PRs (open + closed) and filter to Dependabot ones
    prs_raw = client.get_paginated(
        f"/repos/{owner}/{repo}/pulls",
        params={"state": "all"},
    )

    pr_rows: List[Dict] = []
    for pr in prs_raw:
        login = (pr.get("user") or {}).get("login", "")
        if login not in _DEPENDABOT_LOGINS:
            continue

        number = pr.get("number")
        title = pr.get("title", "")
        created_at = pr.get("created_at")
        merged_at = pr.get("merged_at")
        closed_at = pr.get("closed_at")

        if merged_at:
            status = "merged"
            resolution_date = merged_at
        elif closed_at:
            status = "closed"
            resolution_date = closed_at
        else:
            status = "open"
            resolution_date = None

        days = _days_between(created_at, resolution_date)
        library = _parse_library(title)

        # Mark dependabot as enabled if we find at least one PR even without the config file
        if not enabled:
            enabled = True

        pr_rows.append({
            "repo_full_name": f"{owner}/{repo}",
            "pr_number": number,
            "pr_title": title,
            "created_at": _fmt_date(created_at),
            "merged_at": _fmt_date(merged_at),
            "closed_at": _fmt_date(closed_at),
            "status": status,
            "library_name": library,
            "days_to_resolution": days,
        })

    # Aggregated stats
    total = len(pr_rows)
    merged = sum(1 for p in pr_rows if p["status"] == "merged")
    closed = sum(1 for p in pr_rows if p["status"] == "closed")
    open_ = sum(1 for p in pr_rows if p["status"] == "open")

    merge_days = [p["days_to_resolution"] for p in pr_rows if p["status"] == "merged" and p["days_to_resolution"] is not None]
    avg_merge_days = round(sum(merge_days) / len(merge_days), 2) if merge_days else None

    denominator = merged + closed
    acceptance_rate = round(merged / denominator * 100, 2) if denominator > 0 else None

    repo_stats = {
        "dependabot_enabled": enabled,
        "dependabot_frequency": frequency or "",
        "dependabot_total_prs": total,
        "dependabot_merged_prs": merged,
        "dependabot_closed_prs": closed,
        "dependabot_open_prs": open_,
        "dependabot_avg_merge_days": avg_merge_days,
        "dependabot_acceptance_rate": acceptance_rate,
    }

    logger.debug(
        "[%s/%s] Dependabot: enabled=%s, total_prs=%d, merged=%d",
        owner, repo, enabled, total, merged,
    )
    return repo_stats, pr_rows
