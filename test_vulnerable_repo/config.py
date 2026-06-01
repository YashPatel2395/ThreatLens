"""
config.py — Intentionally contains hardcoded secrets.

Vulnerabilities present (for scanner testing only):
  - Stripe live secret key (gitleaks rule: stripe-access-token)
  - AWS access key ID + secret (gitleaks rule: aws-access-token)
  - Generic high-entropy API key

DO NOT use these credentials. They are fabricated test fixtures.
"""

# ---------------------------------------------------------------------------
# Vulnerability: Hardcoded Stripe live secret key
# Gitleaks rule: stripe-access-token
# Pattern: sk_live_<24 alphanumeric chars>
# ---------------------------------------------------------------------------
STRIPE_SECRET_KEY = "sk_live_" + "4eC39HqLyjWDarjtT7en2HF4"

# ---------------------------------------------------------------------------
# Vulnerability: Hardcoded AWS access key pair
# Gitleaks rule: aws-access-token
# Pattern: AKIA[0-9A-Z]{16}
# ---------------------------------------------------------------------------
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ---------------------------------------------------------------------------
# Application configuration
# ---------------------------------------------------------------------------
DATABASE_URL = "sqlite:///users.db"
DEBUG = True
ALLOWED_HOSTS = ["*"]
