"""Clean application code following security best practices."""

import os

# Secrets are cleanly loaded from the environment
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///default.db")
API_KEY = os.environ.get("THIRD_PARTY_API_KEY", "")

# Debug mode defaults to False
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"


def run_server():
    print(f"Server starting (debug={DEBUG})")
