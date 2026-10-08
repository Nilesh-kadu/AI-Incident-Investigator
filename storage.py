# storage.py

import json
import os
import hashlib
from datetime import datetime
from security import sanitize_logs


HISTORY_FILE = "incident_history.json"


# =========================================================
# LOG HASH
# =========================================================

def generate_log_hash(logs):
    """
    Generate a stable SHA-256 fingerprint from the original logs.

    The original logs are used only to generate the fingerprint.
    They are NOT stored by this function.
    """

    normalized_logs = "\n".join(
        line.strip()
        for line in str(logs).strip().splitlines()
        if line.strip()
    )

    return hashlib.sha256(
        normalized_logs.encode("utf-8")
    ).hexdigest()


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if not isinstance(data, list):
            return []

        changed = False

        # ------------------------------------
        # SECURITY MIGRATION
        # ------------------------------------
        # Sanitize older history records that
        # may have been stored before security
        # sanitization was implemented.
        for item in data:
            old_logs = item.get("logs", "")

            if old_logs:
                sanitized = sanitize_logs(old_logs)

                if sanitized.logs != old_logs:
                    item["logs"] = sanitized.logs
                    changed = True

                    report = item.get("report")

                    if isinstance(report, dict):
                        report["_security"] = {
                            "redaction_count": sanitized.redaction_count,
                            "categories": sanitized.categories,
                        }

        # Save cleaned history immediately
        if changed:
            with open(
                HISTORY_FILE,
                "w",
                encoding="utf-8",
            ) as file:
                json.dump(
                    data,
                    file,
                    indent=2,
                    ensure_ascii=False,
                )

        return data

    except (json.JSONDecodeError, OSError):
        return []


# =========================================================
# SAVE HISTORY
# =========================================================

def save_history(history):

    try:

        with open(
            HISTORY_FILE,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                history,
                file,
                indent=2,
                ensure_ascii=False,
            )

    except OSError as exc:

        raise RuntimeError(
            f"Unable to save investigation history: {exc}"
        )


# =========================================================
# FIND BY HASH
# =========================================================

def find_by_log_hash(log_hash):

    history = load_history()

    for item in history:

        # New secure records
        if item.get("log_hash") == log_hash:
            return item

        # Backward compatibility for old records
        old_logs = item.get("logs", "")

        if old_logs:

            old_hash = generate_log_hash(
                old_logs
            )

            if old_hash == log_hash:
                return item

    return None


# =========================================================
# ADD INVESTIGATION
# =========================================================

def add_investigation(
    logs,
    report,
    log_hash=None,
):
    """
    Save an investigation.

    IMPORTANT:
    `logs` should contain the SANITIZED / REDACTED logs.

    `log_hash` can be generated from the original logs so
    duplicate detection remains accurate.

    Raw logs are never intentionally persisted here.
    """

    if log_hash is None:
        log_hash = generate_log_hash(logs)

    existing = find_by_log_hash(
        log_hash
    )

    if existing:
        return existing

    history = load_history()

    now = datetime.now()

    investigation = {
        "id": now.strftime(
            "%Y%m%d%H%M%S%f"
        ),

        "created_at": now.isoformat(
            timespec="seconds"
        ),

        "title": report.get(
            "incident_title",
            "Untitled Investigation",
        ),

        "severity": report.get(
            "severity",
            "UNKNOWN",
        ),

        "confidence": report.get(
            "confidence",
            0,
        ),

        "log_hash": log_hash,

        # IMPORTANT:
        # This must be the sanitized version.
        "logs": logs,

        "report": report,

        "saved": False,
    }

    history.insert(
        0,
        investigation,
    )

    save_history(
        history
    )

    return investigation


# =========================================================
# UPDATE INVESTIGATION
# =========================================================

def update_investigation(
    investigation_id,
    updates,
):

    history = load_history()

    for item in history:

        if item.get("id") == investigation_id:

            item.update(
                updates
            )

            break

    save_history(
        history
    )


# =========================================================
# TOGGLE SAVED
# =========================================================

def toggle_saved(
    investigation_id,
):

    history = load_history()

    updated_item = None

    for item in history:

        if item.get("id") == investigation_id:

            item["saved"] = not item.get(
                "saved",
                False,
            )

            updated_item = item

            break

    save_history(
        history
    )

    return updated_item


# =========================================================
# DELETE INVESTIGATION
# =========================================================

def delete_investigation(
    investigation_id,
):

    history = load_history()

    history = [
        item
        for item in history
        if item.get("id") != investigation_id
    ]

    save_history(
        history
    )


# =========================================================
# GET INVESTIGATION
# =========================================================

def get_investigation(
    investigation_id,
):

    history = load_history()

    for item in history:

        if item.get("id") == investigation_id:
            return item

    return None


# =========================================================
# CLEAR HISTORY
# =========================================================

def clear_history():

    save_history([])