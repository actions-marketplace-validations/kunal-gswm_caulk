"""Synthetic vulnerable test file for Caulk rule verification."""

# SEC002: Synthetic AWS Access Key from official AWS documentation examples
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# SEC003: Synthetic GitHub PAT pattern
GITHUB_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

# SEC005: Synthetic Slack Webhook pattern
SLACK_WEBHOOK = "https://hooks.slack.com/services/T01234567/B01234567/sample_token_fixture_94819481"

# SEC006: Hardcoded DB credentials with realistic host and non-placeholder password
DATABASE_URL = "postgres://prod_admin:N3v3rGu3ssMeP@ss!@db.internal.production.net:5432/customers"

# SEC007: Realistic secret assignment
api_key = "caulk_test_secret_token_9481948104810481"

# CFG001: Hardcoded debug mode
DEBUG = True
