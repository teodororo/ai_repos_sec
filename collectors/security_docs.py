"""
Security documentation presence checks:
  SECURITY.md, CODE_OF_CONDUCT.md, CONTRIBUTING.md, CODEOWNERS,
  private vulnerability reporting, security contact.
"""

import logging
import re
from typing import Dict

from utils.github_client import GitHubClient

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

_CODEOWNERS_PATHS = [
    "CODEOWNERS",
    ".github/CODEOWNERS",
    "docs/CODEOWNERS",
]

_SECURITY_MD_PATHS = [
    "SECURITY.md",
    ".github/SECURITY.md",
    "docs/SECURITY.md",
    "security.md",
]

_COC_PATHS = [
    "CODE_OF_CONDUCT.md",
    ".github/CODE_OF_CONDUCT.md",
    "docs/CODE_OF_CONDUCT.md",
]

_CONTRIBUTING_PATHS = [
    "CONTRIBUTING.md",
    ".github/CONTRIBUTING.md",
    "docs/CONTRIBUTING.md",
]


def _any_exists(client: GitHubClient, owner: str, repo: str, paths: list) -> bool:
    return any(client.file_exists(owner, repo, p) for p in paths)


def _find_first(client: GitHubClient, owner: str, repo: str, paths: list):
    for p in paths:
        content = client.get_file_content(owner, repo, p)
        if content is not None:
            return content
    return None


def collect(client: GitHubClient, owner: str, repo: str) -> Dict:
    logger.debug("[%s/%s] Collecting security docs …", owner, repo)

    has_security_md = _any_exists(client, owner, repo, _SECURITY_MD_PATHS)
    has_coc = _any_exists(client, owner, repo, _COC_PATHS)
    has_contributing = _any_exists(client, owner, repo, _CONTRIBUTING_PATHS)
    has_codeowners = _any_exists(client, owner, repo, _CODEOWNERS_PATHS)

    # Private vulnerability reporting
    pvr_data = client.get(f"/repos/{owner}/{repo}/private-vulnerability-reporting", use_cache=True)
    private_vuln_reporting = bool(pvr_data and pvr_data.get("enabled"))

    # Security contact: look for an email address in SECURITY.md
    security_contact = False
    if has_security_md:
        content = _find_first(client, owner, repo, _SECURITY_MD_PATHS)
        if content and _EMAIL_RE.search(content):
            security_contact = True
        elif content and re.search(r"contact|email|report", content, re.IGNORECASE):
            security_contact = True

    return {
        "has_security_md": has_security_md,
        "has_code_of_conduct": has_coc,
        "has_contributing": has_contributing,
        "has_codeowners": has_codeowners,
        "private_vulnerability_reporting_enabled": private_vuln_reporting,
        "has_security_contact": security_contact,
    }
