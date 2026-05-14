"""Logging configuration: console (INFO) + rotating file (DEBUG)."""

import logging
import sys
from pathlib import Path


def setup_logging(log_level: str = "INFO") -> logging.Logger:
    Path("logs").mkdir(exist_ok=True)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    console.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    root.addHandler(console)

    file_h = logging.FileHandler("logs/githubsec.log", encoding="utf-8")
    file_h.setFormatter(fmt)
    file_h.setLevel(logging.DEBUG)
    root.addHandler(file_h)

    for noisy in ("urllib3", "requests", "git", "matplotlib"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return root
