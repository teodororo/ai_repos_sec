"""
GitHub Security Analysis — Configuration
All tunable parameters live here.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# ─── GitHub Authentication ──────────────────────────────────────────────────
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
# Leave blank to run unauthenticated (60 req/hour — very slow for large scans).
# Authenticated (5 000 req/hour): create a token at https://github.com/settings/tokens
# Required scopes: public_repo, security_events
GITHUB_API_BASE = "https://api.github.com"

# ─── Repository Search Criteria ────────────────────────────────────────────
SEARCH_TOPICS = [
    "artificial-intelligence", "ai", "machine-learning", "ml", "deep-learning",
    "neural-networks", "llm", "llms", "large-language-models", "transformer",
    "transformers", "gpt", "generative-ai", "chatbot", "nlp",
    "computer-vision", "cv", "pytorch", "tensorflow", "rag",
    "retrieval-augmented-generation", "embeddings", "fine-tuning", "prompt-engineering",
    "langchain", "vector-database", "huggingface", "openai",
]
MIN_STARS = 1000
CREATED_AFTER = "2024-01-01"
CREATED_BEFORE = "2026-04-30"

# ─── Repository Limit ──────────────────────────────────────────────────────
# Phase 1: top 30 repos by stars.
# Full scan: set MAX_REPOS = None  (collects everything the search API returns,
#            up to ~1 000 results per topic group — see collectors/repos.py).
MAX_REPOS = 10

# ─── Parallelisation ───────────────────────────────────────────────────────
MAX_WORKERS = 12           # concurrent threads for per-repo API calls
RATE_LIMIT_BUFFER = 200        # core API (5 000/hour): pause below this threshold
SEARCH_RATE_LIMIT_BUFFER = 3   # search API (30/min): pause below this threshold

# ─── Cache ─────────────────────────────────────────────────────────────────
CACHE_DIR = Path("cache")
CACHE_EXPIRY_HOURS = 24

# ─── Output ────────────────────────────────────────────────────────────────
OUTPUT_DIR = Path("output")
DATE_FORMAT = "%Y-%m-%d"   # used for all date columns in CSVs (except year → int)

# ─── CodeQL fork-and-run (advanced, disabled by default) ───────────────────
# When True: repos that have a CodeQL workflow but inaccessible alert results
# will be forked, cloned, CodeQL triggered, results pulled, then the fork deleted.
# Requires write permission (token with repo scope) and patience (~30 min/repo).
ENABLE_CODEQL_FORK_RUN = True
CODEQL_CLONE_DIR = Path("temp_repos")
CODEQL_BATCH_SIZE = 3        # repos processed in parallel during fork-and-run
GIT_CLONE_DELAY_SECONDS = 2  # delay between git clone calls
CODEQL_WORKFLOW_POLL_INTERVAL = 60   # seconds between status checks
CODEQL_WORKFLOW_TIMEOUT = 900       # give up after 30 minutes
