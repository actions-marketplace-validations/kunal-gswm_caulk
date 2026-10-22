"""Caulk Demonstration: Secure Patterns.

This file demonstrates secure remediation patterns corresponding to the
vulnerabilities in vulnerable_example.py. Caulk's deterministic rules actively
exempt these patterns to prevent false positives.
"""

import os
import subprocess

# SEC002 Remediation: Secrets are read from the environment at runtime
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")

# CFG001 Remediation: Debug mode defaults to False in production
DEBUG = os.environ.get("DEBUG", "False").lower() == "true"


def get_user_profile_safe(request, db_cursor):
    """Secure endpoint: parameterized SQL query with query arguments separated."""
    user_id = request.args.get("id")
    # Parameterized queries are explicitly exempted from SAST001
    db_cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))


def ping_host_safe(request):
    """Secure endpoint: command arguments passed as a sequence without shell=True."""
    host = request.args.get("host")
    # Safe argument lists without shell=True are exempted from SAST002
    subprocess.run(["ping", "-c", "1", host])
