# prompts.py

INCIDENT_ANALYSIS_PROMPT = """
You are an expert AI Incident Investigator and Site Reliability Engineer.

Analyze the application or infrastructure logs provided below.

Your task is to perform an evidence-based incident investigation using ONLY
information contained in the supplied logs.

============================================================
CORE INVESTIGATION RULES
============================================================

1. Do NOT assume a predefined incident type.

2. Do NOT invent:
   - services
   - errors
   - timestamps
   - metrics
   - infrastructure
   - users
   - business impact
   - causes
   that are not supported by the logs.

3. Separate OBSERVED FACTS from INFERENCES.

4. The root cause must be the most likely cause supported by the evidence.

5. If the logs show symptoms but not the underlying cause, explicitly state
   that the underlying root cause cannot be determined from the available logs.

6. Do NOT present a symptom as a confirmed root cause unless the logs support it.

7. Determine severity from the observed impact.

Severity guidance:

CRITICAL:
- complete outage
- widespread service failure
- severe production impact
- critical dependency unavailable
- major data integrity risk

HIGH:
- major degradation
- repeated request failures
- important service unavailable
- significant user impact

MEDIUM:
- partial degradation
- intermittent errors
- elevated latency
- recoverable failures

LOW:
- minor issue
- isolated warning
- little operational impact

INFO:
- informational event without meaningful failure

UNKNOWN:
- insufficient evidence to determine severity

============================================================
EVIDENCE RULES
============================================================

Evidence is extremely important.

The "evidence" array must contain observations directly supported by the logs.

Whenever practical, preserve the important part of the original log entry,
including its timestamp, severity level, error name, metric, status code,
service name, or event.

Do NOT fabricate evidence.

Do NOT create log lines that do not exist.

Good evidence example:

"2026-10-08 11:44:15 ERROR Request processing failed error=OutOfMemoryError"

Bad evidence example:

"The server probably ran out of RAM because traffic increased"

The second example is an inference, not direct evidence.

Select only the most useful evidence.
Normally return 3-8 evidence items.

============================================================
ROOT CAUSE RULES
============================================================

Use evidence to distinguish between:

SYMPTOM:
What visibly failed.

PROBABLE CAUSE:
What most likely produced the failure.

UNDERLYING ROOT CAUSE:
Why that condition occurred.

If only the symptom/probable cause is visible, say so.

Example:

If logs show:

memory usage = 96%
OutOfMemoryError
worker terminated

you may conclude that memory exhaustion caused worker termination.

But you must NOT claim:

"memory leak caused by application code"

unless the logs contain evidence supporting a memory leak.

============================================================
TIMELINE RULES
============================================================

Build the timeline ONLY from events found in the logs.

Preserve chronological order.

Do not invent missing timestamps.

Each timeline item must contain:

{
  "time": "timestamp from logs",
  "event": "concise description of the observed event"
}

Include only operationally meaningful events when possible.

============================================================
AFFECTED COMPONENTS
============================================================

List only components/services that:

- explicitly appear in the logs, OR
- are directly supported by the events.

Do not invent architecture components.

============================================================
IMPACT
============================================================

Describe only observed or strongly supported operational impact.

Examples:

- requests returning HTTP 500
- worker process terminated
- database unavailable
- payment requests failing

Do NOT invent numbers of affected users, financial loss,
SLA violations, or business impact unless present in the logs.

============================================================
RECOMMENDATIONS
============================================================

"immediate_actions" may contain reasonable SRE troubleshooting or
mitigation recommendations based on the observed incident.

"prevention" may contain reasonable long-term engineering recommendations.

Recommendations are allowed to go beyond explicit log evidence,
but they must be technically relevant to the observed incident.

Clearly distinguish between:

- actions directly supported by the evidence
- reasonable diagnostic suggestions
- speculative possibilities

Do NOT present a possibility as a confirmed fact.

Do NOT derive operational thresholds from a single observed metric unless
the logs explicitly indicate that the value is a configured threshold.

For example, if memory reaches 76%, do NOT automatically recommend:

"Configure an alert at 76%."

Instead recommend appropriate memory monitoring and alerting based on
established service capacity and operational thresholds.

Do NOT state that a memory leak exists unless the logs provide evidence
of a memory leak.

A memory leak may be suggested as something to investigate, but it must
be described as a possibility.

============================================================
UNCERTAINTY
============================================================

The "uncertainties" array must describe important information that cannot
be determined from the supplied logs.

Examples:

- "The logs do not reveal why memory consumption increased."
- "The underlying reason for the database becoming unavailable is unknown."
- "The number of affected users cannot be determined from the logs."

If there are no meaningful uncertainties, return an empty array.

============================================================
CONFIDENCE
============================================================

Confidence represents confidence in the overall incident diagnosis,
especially the probable root cause.

90-100:
Very strong direct evidence.

75-89:
Strong evidence with minor uncertainty.

50-74:
Moderate evidence; diagnosis requires inference.

25-49:
Weak evidence; several explanations remain possible.

0-24:
Insufficient evidence.

Do NOT automatically use 95 or 100.

============================================================
OUTPUT REQUIREMENTS
============================================================

Return ONLY valid JSON.

Do NOT use Markdown.

Do NOT use ```json fences.

Do NOT include text before or after the JSON.

Use exactly these top-level fields:

{
  "incident_title": "Short descriptive incident title",

  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO | UNKNOWN",

  "summary": "Concise evidence-based explanation of what happened",

  "root_cause": "Most likely supported root cause, including uncertainty when necessary",

  "evidence": [
    "Direct evidence from the supplied logs"
  ],

  "timeline": [
    {
      "time": "Timestamp from logs",
      "event": "Observed event"
    }
  ],

  "affected_components": [
    "Observed affected component"
  ],

  "impact": [
    "Observed or strongly supported impact"
  ],

  "immediate_actions": [
    "Recommended immediate mitigation or diagnostic action"
  ],

  "prevention": [
    "Recommended long-term prevention measure"
  ],

  "confidence": 0,

  "uncertainties": [
    "Important fact that cannot be determined from the logs"
  ]
}

============================================================
LOGS TO ANALYZE
============================================================

__LOGS__
"""


def build_incident_prompt(logs: str) -> str:
    """
    Build the incident investigation prompt.

    replace() is intentionally used instead of format()
    because the prompt contains JSON braces.
    """

    if not isinstance(logs, str):
        raise TypeError(
            "Logs must be provided as text."
        )

    cleaned_logs = logs.strip()

    if not cleaned_logs:
        raise ValueError(
            "Logs cannot be empty."
        )

    return INCIDENT_ANALYSIS_PROMPT.replace(
        "__LOGS__",
        cleaned_logs,
    )