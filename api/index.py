import sys
import os
from pathlib import Path

# Make the project root importable
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

# Set VERCEL env for /tmp data fallback
os.environ.setdefault("VERCEL", "1")

from server import app

# Vercel Python runtime needs 'app' at module level — this is it.
