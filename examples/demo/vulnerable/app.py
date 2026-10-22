"""Caulk Demonstration: Vulnerable Patterns.

This file contains synthetic, intentionally vulnerable code patterns designed to
demonstrate Caulk's deterministic detection capabilities.

ALL CREDENTIALS IN THIS FILE ARE SYNTHETIC DOCUMENTATION EXAMPLES.
"""

import subprocess

# SEC002: Synthetic AWS Access Key ID (standard AWS documentation example)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# CFG001: Application debug mode explicitly enabled in code
DEBUG = True


def get_user_profile(request, db_cursor):
    """Vulnerable endpoint: untrusted input directly formatted into SQL sink."""
    user_id = request.args.get("id")
    # SAST001 (HIGH): Dynamic input in SQL execution sink
    db_cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")


def ping_host(request):
    """Vulnerable endpoint: untrusted input passed to shell execution sink."""
    host = request.args.get("host")
    # SAST002 (HIGH): Shell execution with untrusted input and shell=True
    subprocess.run(f"ping -c 1 {host}", shell=True)
