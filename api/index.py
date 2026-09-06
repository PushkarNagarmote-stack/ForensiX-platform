import sys
from pathlib import Path

# Add parent directory to sys.path so server and engine modules are discoverable
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from server import app

# Export app for Vercel Serverless
__all__ = ["app"]
