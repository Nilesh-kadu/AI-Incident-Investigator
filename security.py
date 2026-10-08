# security.py

import re
from dataclasses import dataclass


@dataclass
class SanitizationResult:
    logs: str
    redaction_count: int
    categories: list[str]


# ---------------------------------------------------------
# Secret / Sensitive Data Patterns
# ---------------------------------------------------------

PATTERNS = [
    (
        "Bearer token",
        re.compile(
            r"(?i)(authorization\s*[:=]\s*bearer\s+)[A-Za-z0-9._~+/=-]+"
        ),
        r"\1[REDACTED_BEARER_TOKEN]",
    ),

    (
        "Bearer token",
        re.compile(
            r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+"
        ),
        r"\1[REDACTED_BEARER_TOKEN]",
    ),

    (
        "JWT token",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"
        ),
        "[REDACTED_JWT]",
    ),

    (
        "API key",
        re.compile(
            r"(?i)(\b(?:api[_-]?key|apikey)\s*[:=]\s*)[^\s,;]+"
        ),
        r"\1[REDACTED_API_KEY]",
    ),

    (
        "Access token",
        re.compile(
            r"(?i)(\b(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*)[^\s,;]+"
        ),
        r"\1[REDACTED_ACCESS_TOKEN]",
    ),

    (
        "Secret key",
        re.compile(
            r"(?i)(\b(?:secret[_-]?key|client[_-]?secret)\s*[:=]\s*)[^\s,;]+"
        ),
        r"\1[REDACTED_SECRET]",
    ),

    (
        "Password",
        re.compile(
            r"(?i)(\b(?:password|passwd|pwd)\s*[:=]\s*)[^\s,;]+"
        ),
        r"\1[REDACTED_PASSWORD]",
    ),

    (
        "AWS access key",
        re.compile(
            r"\bAKIA[0-9A-Z]{16}\b"
        ),
        "[REDACTED_AWS_ACCESS_KEY]",
    ),

    (
        "Google API key",
        re.compile(
            r"\bAIza[0-9A-Za-z_-]{35}\b"
        ),
        "[REDACTED_GOOGLE_API_KEY]",
    ),

    (
        "GitHub token",
        re.compile(
            r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b"
        ),
        "[REDACTED_GITHUB_TOKEN]",
    ),

    (
        "Private key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
]


# ---------------------------------------------------------
# Sanitization
# ---------------------------------------------------------

def sanitize_logs(logs: str) -> SanitizationResult:
    """
    Remove common secrets and credentials from logs
    before sending them to the LLM.
    """

    if not isinstance(logs, str):
        raise ValueError("Logs must be provided as text.")

    sanitized = logs
    detected_categories = []

    for category, pattern, replacement in PATTERNS:

        sanitized, replacements = pattern.subn(
            replacement,
            sanitized
        )

        if replacements > 0:
            detected_categories.extend(
                [category] * replacements
            )

    return SanitizationResult(
        logs=sanitized,
        redaction_count=len(detected_categories),
        categories=sorted(set(detected_categories)),
    )


def get_security_message(result: SanitizationResult) -> str:
    """
    Create a safe user-facing security message.
    Never expose the original secret values.
    """

    if result.redaction_count == 0:
        return ""

    categories = ", ".join(result.categories)

    return (
        f"🔐 {result.redaction_count} sensitive value(s) "
        f"redacted before AI analysis "
        f"({categories})."
    )