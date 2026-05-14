"""
Repository search and basic info collection.

Search strategy:
  One API call per topic (no OR groups — GitHub's search API does not
  reliably support `OR` with the `topic:` qualifier and returns 0 results).
  Results are deduplicated by repo ID and sorted by stars descending.

  `unique_total` is the count of distinct repos that matched at least one
  topic query. The GitHub total_count per topic is also logged for reference.
"""

import logging
from typing import Dict, List, Tuple

from config import (
    CREATED_AFTER,
    CREATED_BEFORE,
    MAX_REPOS,
    MIN_STARS,
    SEARCH_TOPICS,
)
from utils.github_client import GitHubClient

logger = logging.getLogger(__name__)


def search_repositories(client: GitHubClient) -> Tuple[List[Dict], int]:
    """Return (repos_sorted_by_stars, unique_total).

    repos_sorted_by_stars is trimmed to MAX_REPOS (or all if MAX_REPOS is None).
    unique_total reflects distinct repos found across all topic queries.
    """
    seen_ids: set = set()
    all_repos: List[Dict] = []

    for topic in SEARCH_TOPICS:
        q = (
            f"topic:{topic} "
            f"stars:>={MIN_STARS} "
            f"created:{CREATED_AFTER}..{CREATED_BEFORE}"
        )
        logger.info("Searching topic: %s", topic)

        # First page — grab total_count for this topic
        first_page = client.get(
            "/search/repositories",
            params={"q": q, "sort": "stars", "order": "desc", "per_page": 100, "page": 1},
        )
        if not first_page:
            logger.warning("  No response for topic: %s", topic)
            continue

        topic_total = first_page.get("total_count", 0)
        items = first_page.get("items", [])
        logger.info("  topic:%-30s → %d total, %d on page 1", topic, topic_total, len(items))

        # Fetch remaining pages (GitHub caps results at 1 000 per query)
        page = 2
        while items and len(items) % 100 == 0 and page <= 10:
            data = client.get(
                "/search/repositories",
                params={"q": q, "sort": "stars", "order": "desc", "per_page": 100, "page": page},
            )
            if not data or not data.get("items"):
                break
            items.extend(data["items"])
            page += 1

        before = len(seen_ids)
        for repo in items:
            rid = repo["id"]
            if rid not in seen_ids:
                seen_ids.add(rid)
                all_repos.append(repo)
        logger.info("  +%d new unique repos (total: %d)", len(seen_ids) - before, len(seen_ids))

    unique_total = len(all_repos)
    logger.info(
        "Search complete. Unique repos across all topics: %d", unique_total
    )

    # Sort by stars descending
    all_repos.sort(key=lambda r: r.get("stargazers_count", 0), reverse=True)

    if MAX_REPOS is not None:
        all_repos = all_repos[:MAX_REPOS]
        logger.info("Trimmed to top %d repos by stars.", MAX_REPOS)

    return all_repos, unique_total


def parse_basic_info(raw: Dict, contributors_count: int) -> Dict:
    """Extract basic fields from a search-result repo object."""
    from config import DATE_FORMAT
    from datetime import datetime

    created_raw = raw.get("created_at", "")
    try:
        created_dt = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
        year_created = created_dt.year
    except ValueError:
        year_created = None

    topics = raw.get("topics", [])

    return {
        "full_name": raw.get("full_name", ""),
        "stars": raw.get("stargazers_count", 0),
        "year_created": year_created,
        "primary_language": raw.get("language") or "",
        "topics": ";".join(topics),
        "contributors_count": contributors_count,
    }
