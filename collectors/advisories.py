"""
GitHub Security Advisories collection.

Endpoint: GET /repos/{owner}/{repo}/security-advisories
Returns advisories *published by the repository maintainers* about
vulnerabilities found in that project (GHSA records).
Accessible for public repos without special token scopes.
"""

import logging
from typing import Dict, List, Tuple

from utils.github_client import GitHubClient

logger = logging.getLogger(__name__)

_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _normalise_severity(raw: str) -> str:
    s = (raw or "").lower()
    return s if s in _VALID_SEVERITIES else "unknown"


def _parse_advisory(adv: Dict, owner: str, repo: str) -> Dict:
    cwes = [
        c.get("cwe_id", "") for c in (adv.get("cwes") or []) if c.get("cwe_id")
    ]

    vulnerabilities = adv.get("vulnerabilities") or []
    ecosystem = ";".join(
        sorted({(v.get("package") or {}).get("ecosystem", "") for v in vulnerabilities} - {""})
    )

    return {
        "repo_full_name": f"{owner}/{repo}",
        "advisory_id": adv.get("id") or adv.get("ghsa_id", ""),
        "ghsa_id": adv.get("ghsa_id", ""),
        "cve_id": adv.get("cve_id") or "",
        "title": (adv.get("summary") or adv.get("description") or "")[:255],
        "severity": _normalise_severity(adv.get("severity", "")),
        "cwes": ";".join(cwes),
        "ecosystem": ecosystem,
    }


def collect(
    client: GitHubClient, owner: str, repo: str
) -> Tuple[Dict, List[Dict]]:
    """Return (repo_level_stats_dict, list_of_advisory_dicts)."""
    logger.debug("[%s/%s] Collecting security advisories …", owner, repo)

    raw = client.get_paginated(f"/repos/{owner}/{repo}/security-advisories")

    # Filter to only published advisories
    published = [a for a in raw if a.get("state") in ("published", None)]

    adv_rows = [_parse_advisory(a, owner, repo) for a in published]

    sev: Dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for a in adv_rows:
        k = a["severity"]
        if k in sev:
            sev[k] += 1

    total = len(adv_rows)

    repo_stats = {
        "has_advisories": total > 0,
        "advisory_total": total,
        "advisory_low": sev["low"],
        "advisory_medium": sev["medium"],
        "advisory_high": sev["high"],
        "advisory_critical": sev["critical"],
    }

    logger.debug("[%s/%s] Advisories: total=%d", owner, repo, total)
    return repo_stats, adv_rows
