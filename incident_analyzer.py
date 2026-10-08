# incident_analyzer.py

import json
import re

from llm import ask_gemini
from prompts import build_incident_prompt
from security import sanitize_logs


REQUIRED_FIELDS = [
    "incident_title",
    "severity",
    "summary",
    "root_cause",
    "evidence",
    "timeline",
    "affected_components",
    "impact",
    "immediate_actions",
    "prevention",
    "confidence",
    "uncertainties",
]


LIST_FIELDS = [
    "evidence",
    "timeline",
    "affected_components",
    "impact",
    "immediate_actions",
    "prevention",
    "uncertainties",
]


ALLOWED_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
    "UNKNOWN",
}


# ---------------------------------------------------------
# JSON CLEANING
# ---------------------------------------------------------

def clean_json_response(response: str) -> str:

    if not isinstance(response, str):
        raise ValueError("Gemini response must be text.")

    response = response.strip()

    response = re.sub(
        r"^```json\s*",
        "",
        response,
        flags=re.IGNORECASE,
    )

    response = re.sub(
        r"^```\s*",
        "",
        response,
    )

    response = re.sub(
        r"\s*```$",
        "",
        response,
    )

    return response.strip()


# ---------------------------------------------------------
# JSON EXTRACTION
# ---------------------------------------------------------

def extract_json(response: str) -> dict:

    cleaned = clean_json_response(response)

    try:

        parsed = json.loads(cleaned)

        if not isinstance(parsed, dict):
            raise ValueError(
                "AI response must contain a JSON object."
            )

        return parsed

    except json.JSONDecodeError:
        pass

    start = cleaned.find("{")
    end = cleaned.rfind("}")

    if start == -1 or end == -1 or end <= start:
        raise ValueError(
            "Gemini did not return a valid JSON object."
        )

    json_text = cleaned[start:end + 1]

    try:

        parsed = json.loads(json_text)

    except json.JSONDecodeError as exc:

        raise ValueError(
            "Gemini returned malformed JSON."
        ) from exc

    if not isinstance(parsed, dict):

        raise ValueError(
            "Gemini response is not a JSON object."
        )

    return parsed


# ---------------------------------------------------------
# NORMALIZATION
# ---------------------------------------------------------

def normalize_text(
    value,
    fallback="Not determined from the available logs.",
):

    if value is None:
        return fallback

    value = str(value).strip()

    if not value:
        return fallback

    return value


def normalize_list(value):

    if value is None:
        return []

    if isinstance(value, list):

        cleaned_items = []

        for item in value:

            if item is None:
                continue

            if isinstance(item, dict):

                cleaned_items.append(item)

            else:

                text = str(item).strip()

                if text:
                    cleaned_items.append(text)

        return cleaned_items

    text = str(value).strip()

    if not text:
        return []

    return [text]


def normalize_timeline(value):

    if not isinstance(value, list):
        return []

    timeline = []

    for item in value:

        if isinstance(item, dict):

            time_value = str(
                item.get("time", "Unknown time")
            ).strip()

            event_value = str(
                item.get("event", "")
            ).strip()

            if event_value:

                timeline.append(
                    {
                        "time": time_value or "Unknown time",
                        "event": event_value,
                    }
                )

        elif item is not None:

            event_value = str(item).strip()

            if event_value:

                timeline.append(
                    {
                        "time": "Unknown time",
                        "event": event_value,
                    }
                )

    return timeline


def normalize_confidence(value):

    try:

        confidence = int(float(value))

    except (ValueError, TypeError):

        confidence = 0

    return max(0, min(100, confidence))


# ---------------------------------------------------------
# REPORT VALIDATION
# ---------------------------------------------------------

def validate_report(report: dict) -> dict:

    if not isinstance(report, dict):

        raise ValueError(
            "AI response is not a JSON object."
        )

    missing_fields = [
        field
        for field in REQUIRED_FIELDS
        if field not in report
    ]

    if missing_fields:

        raise ValueError(
            "AI response is missing fields: "
            + ", ".join(missing_fields)
        )

    report["incident_title"] = normalize_text(
        report.get("incident_title"),
        "Untitled Incident",
    )

    report["summary"] = normalize_text(
        report.get("summary")
    )

    report["root_cause"] = normalize_text(
        report.get("root_cause")
    )

    severity = str(
        report.get("severity", "UNKNOWN")
    ).upper().strip()

    if severity not in ALLOWED_SEVERITIES:
        severity = "UNKNOWN"

    report["severity"] = severity

    for field in [
        "evidence",
        "affected_components",
        "impact",
        "immediate_actions",
        "prevention",
        "uncertainties",
    ]:

        report[field] = normalize_list(
            report.get(field)
        )

    report["timeline"] = normalize_timeline(
        report.get("timeline")
    )

    report["confidence"] = normalize_confidence(
        report.get("confidence")
    )

    return report


# ---------------------------------------------------------
# MAIN INVESTIGATION
# ---------------------------------------------------------

def investigate_incident(logs: str) -> dict:
    
    

    if not isinstance(logs, str):
        raise ValueError(
            "Logs must be provided as text."
        )

    logs = logs.strip()

    if not logs:
        raise ValueError(
            "No logs were provided."
        )

    # SECURITY LAYER
    security_result = sanitize_logs(logs)
    safe_logs = security_result.logs

    # ------------------------------------
    # LARGE LOG PROTECTION
    # ------------------------------------
    MAX_LOG_CHARS = 50000

    if len(safe_logs) > MAX_LOG_CHARS:
        first_part = 30000
        last_part = 20000

        safe_logs = (
            safe_logs[:first_part]
            + "\n\n"
            + "[... MIDDLE OF LOGS TRUNCATED FOR AI ANALYSIS ...]"
            + "\n\n"
            + safe_logs[-last_part:]
        )

    prompt = build_incident_prompt(safe_logs)

    # -----------------------------------------------------
    # CALL GEMINI
    # -----------------------------------------------------

    try:
        raw_response = ask_gemini(prompt)

    except Exception as exc:
      error_message = str(exc).lower()

      if "503" in error_message or "unavailable" in error_message:
        message = (
            "Gemini is temporarily unavailable. "
            "Please wait a moment and try again."
        )

      elif "429" in error_message or "quota" in error_message:
        message = (
            "Gemini API rate limit or quota reached. "
            "Please wait and try again."
        )

      elif "401" in error_message or "403" in error_message:
        message = (
            "Gemini API authentication failed. "
            "Please check your API configuration."
        )

      elif "timeout" in error_message:
        message = (
            "The AI request timed out. "
            "Please try again with a smaller log."
        )

      else:
        message = (
            "AI investigation failed. "
            "Please try again."
        )

      raise RuntimeError(message) from exc
    if not raw_response:

        raise ValueError(
            "Gemini returned an empty response."
        )

    # -----------------------------------------------------
    # PARSE RESPONSE
    # -----------------------------------------------------

    report = extract_json(
        raw_response
    )

    # -----------------------------------------------------
    # VALIDATE REPORT
    # -----------------------------------------------------

    report = validate_report(
        report
    )

    # -----------------------------------------------------
    # SECURITY METADATA
    # -----------------------------------------------------

    report["_security"] = {
        "redaction_count": security_result.redaction_count,
        "categories": security_result.categories,
    }

    return report