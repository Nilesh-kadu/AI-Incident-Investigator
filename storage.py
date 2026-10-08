# storage.py

import hashlib
from datetime import datetime

import streamlit as st


# ============================================================
# SESSION-BASED STORAGE
# ============================================================

def _get_history():
    """
    Return investigation history for the current
    Streamlit browser session only.
    """

    if "investigation_history" not in st.session_state:
        st.session_state.investigation_history = []

    return st.session_state.investigation_history


# ============================================================
# LOG HASH
# ============================================================

def generate_log_hash(logs):
    """
    Generate a normalized SHA-256 fingerprint
    for duplicate detection.
    """

    normalized_logs = "\n".join(
        line.strip()
        for line in str(logs).strip().splitlines()
        if line.strip()
    )

    return hashlib.sha256(
        normalized_logs.encode("utf-8")
    ).hexdigest()


# ============================================================
# LOAD HISTORY
# ============================================================

def load_history():
    """
    Return only the current user's session history.

    Nothing is loaded from disk or shared between users.
    """

    return _get_history()


# ============================================================
# SAVE HISTORY
# ============================================================

def save_history(history):
    """
    Store history only in the current Streamlit session.
    """

    st.session_state.investigation_history = history


# ============================================================
# FIND BY LOG HASH
# ============================================================

def find_by_log_hash(log_hash):
    """
    Find an existing investigation belonging to
    the current session.
    """

    history = load_history()

    for item in history:

        if item.get("log_hash") == log_hash:
            return item

        old_logs = item.get("logs", "")

        if old_logs:
            old_hash = generate_log_hash(old_logs)

            if old_hash == log_hash:
                return item

    return None


# ============================================================
# ADD INVESTIGATION
# ============================================================

def add_investigation(
    logs,
    report,
    log_hash=None,
):
    """
    Add investigation to the current user's session.
    """

    if log_hash is None:
        log_hash = generate_log_hash(logs)

    existing = find_by_log_hash(log_hash)

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

        # logs passed here are already sanitized
        "logs": logs,

        "report": report,

        "saved": False,
    }

    history.insert(
        0,
        investigation,
    )

    save_history(history)

    return investigation


# ============================================================
# UPDATE INVESTIGATION
# ============================================================

def update_investigation(
    investigation_id,
    updates,
):
    """
    Update an investigation belonging to
    the current session.
    """

    history = load_history()

    for item in history:

        if item.get("id") == investigation_id:

            item.update(updates)

            break

    save_history(history)


# ============================================================
# TOGGLE SAVED
# ============================================================

def toggle_saved(investigation_id):
    """
    Save / unsave an investigation for the
    current session.
    """

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

    save_history(history)

    return updated_item


# ============================================================
# DELETE INVESTIGATION
# ============================================================

def delete_investigation(
    investigation_id,
):
    """
    Delete an investigation from the
    current user's session.
    """

    history = load_history()

    history = [
        item
        for item in history
        if item.get("id") != investigation_id
    ]

    save_history(history)


# ============================================================
# GET INVESTIGATION
# ============================================================

def get_investigation(
    investigation_id,
):
    """
    Get an investigation from the
    current session.
    """

    history = load_history()

    for item in history:

        if item.get("id") == investigation_id:

            return item

    return None


# ============================================================
# CLEAR HISTORY
# ============================================================

def clear_history():
    """
    Clear only the current user's history.
    """

    st.session_state.investigation_history = []