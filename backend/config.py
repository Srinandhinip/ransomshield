"""
Central path configuration.

Every module that needs to read/write the sandbox, honeypots, or logs
imports from here instead of using relative paths like Path("sandbox").
Relative paths silently break the moment the app is launched from a
different working directory (a very common cause of "it works on my
machine" bugs) - resolving everything from this file's own location
makes the project runnable from anywhere.
"""

from pathlib import Path

# backend/config.py -> backend/ -> ransomshield/  (project root)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

SANDBOX_DIR = PROJECT_ROOT / "sandbox"
HONEYPOT_DIR = SANDBOX_DIR / "honeypots"
DOCUMENTS_DIR = SANDBOX_DIR / "documents"
IMAGES_DIR = SANDBOX_DIR / "images"

LOGS_DIR = PROJECT_ROOT / "logs"
BACKUPS_DIR = PROJECT_ROOT / "backups"

FRONTEND_DIR = PROJECT_ROOT / "frontend"


def ensure_directories():
    for directory in (
        SANDBOX_DIR,
        HONEYPOT_DIR,
        DOCUMENTS_DIR,
        IMAGES_DIR,
        LOGS_DIR,
        BACKUPS_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)
