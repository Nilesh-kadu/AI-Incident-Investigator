import streamlit as st

import time

import json

import html


from incident_analyzer import investigate_incident

from security import sanitize_logs


from storage import (
    add_investigation,
    load_history,
    get_investigation,
    update_investigation,
    toggle_saved,
    delete_investigation,
    generate_log_hash,
    find_by_log_hash,
)


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AI Incident Investigator",
    page_icon="🚨",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# SESSION STATE
# ============================================================

if "report" not in st.session_state:
    st.session_state.report = None

if "logs" not in st.session_state:
    st.session_state.logs = ""

if "logs_input" not in st.session_state:
    st.session_state.logs_input = ""

if "analysis_time" not in st.session_state:
    st.session_state.analysis_time = None

if "current_investigation_id" not in st.session_state:
    st.session_state.current_investigation_id = None

if "page" not in st.session_state:
    st.session_state.page = "investigate"

# Default button state
analyze_clicked = False


# ============================================================
# HELPERS
# ============================================================

def render_html(content):
    st.html(content)


def safe_text(value):
    return html.escape(str(value))


def severity_class(severity):

    severity = str(
        severity
    ).upper()

    if severity == "CRITICAL":
        return "critical"

    if severity == "HIGH":
        return "high"

    if severity == "MEDIUM":
        return "medium"

    if severity == "LOW":
        return "low"

    return "unknown"


def build_text_report(report):

    lines = []

    lines.append(
        "AI INCIDENT INVESTIGATION REPORT"
    )

    lines.append("=" * 60)
    lines.append("")

    lines.append(
        f"Incident: {report.get('incident_title', 'Unknown')}"
    )

    lines.append(
        f"Severity: {report.get('severity', 'UNKNOWN')}"
    )

    lines.append(
        f"Confidence: {report.get('confidence', 0)}%"
    )

    lines.append("")

    sections = [
        (
            "SUMMARY",
            report.get(
                "summary",
                "Not available",
            ),
        ),
        (
            "ROOT CAUSE",
            report.get(
                "root_cause",
                "Not determined",
            ),
        ),
    ]

    for title, content in sections:

        lines.append(title)
        lines.append("-" * 60)
        lines.append(str(content))
        lines.append("")

    lines.append("EVIDENCE")
    lines.append("-" * 60)

    for item in report.get(
        "evidence",
        [],
    ):
        lines.append(f"- {item}")

    lines.append("")

    lines.append("AFFECTED COMPONENTS")
    lines.append("-" * 60)

    for item in report.get(
        "affected_components",
        [],
    ):
        lines.append(f"- {item}")

    lines.append("")

    lines.append("TIMELINE")
    lines.append("-" * 60)

    for event in report.get(
        "timeline",
        [],
    ):

        if isinstance(event, dict):

            lines.append(
                f"{event.get('time', '')} - "
                f"{event.get('event', '')}"
            )

        else:

            lines.append(
                f"- {event}"
            )

    lines.append("")

    for title, key in [
        (
            "IMPACT",
            "impact",
        ),
        (
            "IMMEDIATE ACTIONS",
            "immediate_actions",
        ),
        (
            "PREVENTION",
            "prevention",
        ),
    ]:

        lines.append(title)
        lines.append("-" * 60)

        for item in report.get(
            key,
            [],
        ):
            lines.append(
                f"- {item}"
            )

        lines.append("")

    return "\n".join(lines)


# ============================================================
# CSS
# ============================================================

st.html("""
<style>

html, body, [class*="css"] {
    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

.stApp {
    background:
        radial-gradient(
            circle at 80% 0%,
            rgba(80,70,180,.08),
            transparent 28%
        ),
        #070B14;
    color:#F4F7FB;
}


/* ================= SIDEBAR ================= */

section[data-testid="stSidebar"] {
    background:#090E19;
    border-right:1px solid #1B2638;
}

section[data-testid="stSidebar"] .stButton button {
    background:transparent;
    border:1px solid transparent;
    color:#AAB7C9;
    text-align:left;
    border-radius:8px;
}

section[data-testid="stSidebar"] .stButton button:hover {
    background:#111A2A;
    border-color:#24334A;
    color:#FFFFFF;
}


/* ================= HEADER ================= */

[data-testid="stHeader"] {
    background:#070B14 !important;
}

[data-testid="stToolbar"] {
    background:transparent !important;
}

[data-testid="stDecoration"] {
    display:none !important;
}


/* ================= HERO ================= */

.hero {
    padding:18px 0 28px;
}

.hero-title {
    font-size:42px;
    font-weight:750;
    letter-spacing:-1.5px;
}

.hero-gradient {
    background:
        linear-gradient(
            90deg,
            #8B7CFF,
            #5EA7FF
        );

    -webkit-background-clip:text;
    -webkit-text-fill-color:transparent;
}

.hero-by {
    font-size:17px;
    font-weight:500;
    color:#7F8DA3;
    margin-left:12px;
}

.hero-description {
    margin-top:10px;
    color:#B8C4D6;
    font-size:15px;
    line-height:1.6;
    max-width:780px;
}


/* ================= PANELS ================= */

.panel {
    background:#0B1220;
    border:1px solid #1C293C;
    border-radius:12px;
    padding:18px;
}

.panel-title {
    font-size:14px;
    font-weight:650;
    color:#F2F5F9;
}

.panel-subtitle {
    font-size:12px;
     color:#A5B2C5;
    margin-top:5px;
}


/* ================= METRICS ================= */

.metric-card {
    background:#0D1626;
    border:1px solid #203047;
    border-radius:10px;
    padding:16px;
    min-height:100px;
}

.metric-label {
    color:#8796AA;
    font-size:11px;
    text-transform:uppercase;
    letter-spacing:.08em;
}

.metric-value {
    margin-top:8px;
    font-size:25px;
    font-weight:750;
}

.metric-value.critical {
    color:#FF6B78;
}

.metric-value.high {
    color:#FF8A65;
}

.metric-value.medium {
    color:#FFC857;
}

.metric-value.low {
    color:#58D68D;
}

.metric-value.unknown {
    color:#AEBBD0;
}


/* ================= RESULT SECTIONS ================= */

.section-card {
    background:#0B1220;
    border:1px solid #1C293C;
    border-radius:12px;
    padding:18px;
    margin-top:12px;
}

.section-heading {
    color:#F3F6FA;
    font-size:14px;
    font-weight:700;
    margin-bottom:10px;
}

.section-content {
    color:#B9C4D4;
    font-size:14px;
    line-height:1.65;
}

.root-cause {
    color:#E3E9F2;
    font-size:15px;
    line-height:1.65;
}


/* ================= LIST ================= */

.ai-list {
    margin:0;
    padding-left:20px;
    color:#B9C4D4;
}

.ai-list li {
    margin-bottom:8px;
    line-height:1.55;
}


/* ================= TIMELINE ================= */

.timeline-item {
    display:grid;
    grid-template-columns:120px 1fr;
    gap:16px;
    padding:12px 0;
    border-bottom:1px solid #182438;
}

.timeline-item:last-child {
    border-bottom:none;
}

.timeline-time {
    color:#8B7CFF;
    font-family:monospace;
    font-size:12px;
}

.timeline-event {
    color:#C0CAD8;
    font-size:13px;
}




/* ================= FILE UPLOADER ================= */

[data-testid="stFileUploader"] {
    background: #0B1220 !important;
    border: 1px solid #1C293C !important;
    border-radius: 10px !important;
    padding: 10px !important;
}

[data-testid="stFileUploaderDropzone"] {
    background: #0B1220 !important;
    border: 1px dashed #2A3A53 !important;
    border-radius: 8px !important;
}

[data-testid="stFileUploaderDropzone"] > div {
    background: #0B1220 !important;
}

/* Upload button */

[data-testid="stFileUploaderDropzone"] button {
    background: #111A2A !important;
    color: #E8EDF5 !important;
    border: 1px solid #33445E !important;
    border-radius: 7px !important;
}

[data-testid="stFileUploaderDropzone"] button:hover {
    background: #172238 !important;
    color: #FFFFFF !important;
    border-color: #5965E8 !important;
}

/* Uploader description */

[data-testid="stFileUploaderDropzone"] small {
    color: #AAB7C9 !important;
    opacity: 1 !important;
}

/* Uploader text */

[data-testid="stFileUploaderDropzone"] span {
    color: #C2CDDC !important;
    opacity: 1 !important;
}

/* General uploader text */

[data-testid="stFileUploader"] label {
    color: #C2CDDC !important;
}

[data-testid="stFileUploader"] p {
    color: #AAB7C9 !important;
}

[data-testid="stFileUploader"] svg {
    color: #AAB7C9 !important;
}


/* ================= BUTTON ================= */

.stButton > button {
    background:#5965E8;
    color:white;
    border:1px solid #6874F0;
    border-radius:9px;
    font-weight:650;
    min-height:42px;
}

.stButton > button:hover {
    background:#6874F0;
}


/* ================= DOWNLOAD ================= */

.stDownloadButton > button {
    background:#111A2A;
    color:#DCE4EF;
    border:1px solid #2A3A53;
    border-radius:9px;
}


/* ================= HISTORY ================= */

.history-card {
    background:#0B1220;
    border:1px solid #1C293C;
    border-radius:11px;
    padding:16px;
    margin-bottom:10px;
}

/* ================= TEXT INPUT FIX ================= */

[data-testid="stTextArea"] textarea {
    background: #080E19 !important;
    color: #E8EDF5 !important;
    caret-color: #FFFFFF !important;
    border: 1px solid #2A3A53 !important;
    border-radius: 9px !important;
    font-family:
        "JetBrains Mono",
        Consolas,
        monospace !important;
    font-size: 12px !important;
    line-height: 1.6 !important;
}

[data-testid="stTextArea"] textarea:focus {
    background: #080E19 !important;
    color: #F4F7FB !important;
    border-color: #5965E8 !important;
    box-shadow:
        0 0 0 1px #5965E8 !important;
}

[data-testid="stTextArea"] textarea::placeholder {
    color: #718096 !important;
    opacity: 1 !important;
}

.history-title {
    color:#E9EEF6;
    font-size:14px;
    font-weight:650;
}

.history-meta {
    color:#73839A;
    font-size:11px;
    margin-top:6px;
}

.history-severity {
    font-size:11px;
    font-weight:700;
    letter-spacing:.08em;
}


/* ================= EMPTY ================= */

.empty-state {
    min-height:420px;
    display:flex;
    flex-direction:column;
    align-items:center;
    justify-content:center;
    border:1px dashed #26364D;
    border-radius:14px;
    background:rgba(11,18,32,.55);
    text-align:center;
    padding:40px;
}

.empty-icon {
    font-size:36px;
    margin-bottom:14px;
}

.empty-title {
    font-size:18px;
    font-weight:650;
    color:#E8EDF5;
}

.empty-description {
    margin-top:8px;
    max-width:420px;
    color:#A5B2C5;
    font-size:13px;
    line-height:1.6;
}


/* ================= FOOTER ================= */

.footer {
    text-align:center;
    color:#526176;
    font-size:11px;
    padding:25px 0 8px;
}

/* =========================================================
   FINAL UI POLISH — AI INCIDENT INVESTIGATOR
   ========================================================= */

/* ---------- GLOBAL ---------- */

.stApp {
    background:
        radial-gradient(
            circle at 80% 10%,
            rgba(83, 92, 255, 0.055),
            transparent 28%
        ),
        #070b14;
}

.main .block-container {
    max-width: 1500px;
    padding-top: 2rem;
    padding-bottom: 3rem;
}

/* ---------- TYPOGRAPHY ---------- */

body,
.stApp,
p,
label,
span,
div {
    font-family:
        Inter,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

h1,
h2,
h3 {
    letter-spacing: -0.025em;
}

/* ---------- SIDEBAR ---------- */

section[data-testid="stSidebar"] {
    background:
        linear-gradient(
            180deg,
            #080e18 0%,
            #070c15 100%
        ) !important;

    border-right: 1px solid #172235;
}

section[data-testid="stSidebar"] > div {
    padding-top: 1.5rem;
}

section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] span {
    color: #BBC8DA;
}

/* ---------- TOP STREAMLIT BAR ---------- */

header[data-testid="stHeader"] {
    background: #070b14 !important;
}

/* ---------- TABS ---------- */

button[data-baseweb="tab"] {
    color: #66748a !important;
    font-weight: 600 !important;
    font-size: 13px !important;
    padding-left: 0.2rem !important;
    padding-right: 1.2rem !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: #f3f6ff !important;
}

div[data-baseweb="tab-highlight"] {
    background: #5968ff !important;
    height: 2px !important;
}

/* ---------- FILE UPLOADER ---------- */

[data-testid="stFileUploader"] {
    background: #09111e !important;
    border: 1px solid #20304a !important;
    border-radius: 10px !important;
    padding: 8px !important;
}

[data-testid="stFileUploader"] section {
    background: #09111e !important;
    border: 1px dashed #263957 !important;
    border-radius: 8px !important;
}

[data-testid="stFileUploader"] button {
    background: #101d31 !important;
    color: #e8efff !important;
    border: 1px solid #314767 !important;
    border-radius: 7px !important;
    font-weight: 600 !important;
}

[data-testid="stFileUploader"] button:hover {
    background: #172a45 !important;
    border-color: #5968ff !important;
    color: #ffffff !important;
}

[data-testid="stFileUploader"] small,
[data-testid="stFileUploader"] span {
    color: #a9b8cf !important;
}

[data-testid="stFileUploader"] label {
    color: #dbe5f5 !important;
}

/* ---------- PASTE LOG TEXTAREA ---------- */

.stTextArea textarea {
    background: #070d18 !important;
    color: #e6edf8 !important;
    border: 1px solid #2a3d5a !important;
    border-radius: 9px !important;
    font-family:
        "JetBrains Mono",
        "Cascadia Code",
        Consolas,
        monospace !important;
    font-size: 12px !important;
    line-height: 1.65 !important;
    padding: 15px !important;
    caret-color: #7180ff !important;
}

.stTextArea textarea::placeholder {
    color: #64748b !important;
    opacity: 1 !important;
}

.stTextArea textarea:focus {
    border-color: #5968ff !important;
    box-shadow:
        0 0 0 1px rgba(89, 104, 255, 0.25),
        0 0 20px rgba(89, 104, 255, 0.08) !important;
}

/* ---------- ANALYZE BUTTON ---------- */

button[kind="primary"] {
    background:
        linear-gradient(
            135deg,
            #5367ef 0%,
            #6674ff 100%
        ) !important;

    border: 1px solid #7180ff !important;
    color: #ffffff !important;
    border-radius: 8px !important;
    min-height: 44px !important;
    font-weight: 700 !important;
    letter-spacing: 0.01em !important;

    box-shadow:
        0 8px 24px rgba(67, 83, 220, 0.20) !important;

    transition:
        transform 0.15s ease,
        box-shadow 0.15s ease !important;
}

button[kind="primary"]:hover {
    background:
        linear-gradient(
            135deg,
            #6174ff 0%,
            #7480ff 100%
        ) !important;

    transform: translateY(-1px);

    box-shadow:
        0 12px 30px rgba(67, 83, 220, 0.30) !important;
}

/* ---------- NORMAL BUTTONS ---------- */

.stButton > button {
    border-radius: 8px !important;
    font-weight: 600 !important;
}

/* ---------- CUSTOM CARDS ---------- */

div[class*="card"] {
    transition:
        border-color 0.18s ease,
        transform 0.18s ease,
        box-shadow 0.18s ease;
}


/* ---------- EMPTY STATE ---------- */

.empty-state {
    background:
        radial-gradient(
            circle at 50% 40%,
            rgba(83, 103, 239, 0.045),
            transparent 45%
        ) !important;

    border: 1px dashed #263957 !important;
}

/* ---------- ALERTS ---------- */

div[data-testid="stAlert"] {
    background: #0b1627 !important;
    border: 1px solid #203655 !important;
    border-radius: 8px !important;
    color: #bcd0ea !important;
}

/* ---------- DOWNLOAD BUTTON ---------- */

.stDownloadButton > button {
    background: #0d1929 !important;
    color: #d8e4f5 !important;
    border: 1px solid #253a57 !important;
    border-radius: 8px !important;
}

.stDownloadButton > button:hover {
    background: #13243b !important;
    border-color: #5367ef !important;
    color: #ffffff !important;
}

/* ---------- SCROLLBAR ---------- */

::-webkit-scrollbar {
    width: 7px;
    height: 7px;
}

::-webkit-scrollbar-track {
    background: #070b14;
}

::-webkit-scrollbar-thumb {
    background: #1e2d45;
    border-radius: 10px;
}

::-webkit-scrollbar-thumb:hover {
    background: #304565;
}

/* ---------- REDUCE STREAMLIT DEFAULT GAPS ---------- */

div[data-testid="stVerticalBlock"] {
    gap: 0.65rem;
}

/* ---------- MOBILE / SMALL WINDOWS ---------- */

@media (max-width: 1000px) {

    .main .block-container {
        padding-left: 1.2rem;
        padding-right: 1.2rem;
    }

}

/* ---------- TAB CONTRAST ---------- */

button[data-baseweb="tab"] {
    color: #9aa9bf !important;
    opacity: 1 !important;
}

button[data-baseweb="tab"]:hover {
    color: #e8eef9 !important;
}

button[data-baseweb="tab"][aria-selected="true"] {
    color: #ffffff !important;
    font-weight: 700 !important;
}

</style>
""")


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    render_html("""
    <div style="
        font-size:20px;
        font-weight:750;
        color:#F4F7FB;
        margin-bottom:3px;
    ">
        ◈ Incident AI
    </div>

    <div style="
        font-size:11px;
        color:#91A4BE;
        letter-spacing:.08em;
        text-transform:uppercase;
        margin-bottom:24px;
    ">
        AI Operations Center
    </div>
    """)

    if st.button(
        "⌕   Investigate",
        use_container_width=True,
    ):

        st.session_state.page = "investigate"

        st.session_state.report = None

        st.session_state.logs = ""

        st.session_state.logs_input = ""

        st.session_state.current_investigation_id = None

        st.rerun()


    if st.button(
        "◷   History",
        use_container_width=True,
    ):

        st.session_state.page = "history"

        st.rerun()


    if st.button(
        "▣   Saved Reports",
        use_container_width=True,
    ):

        st.session_state.page = "saved"

        st.rerun()


    render_html("""
    <div style="
        margin-top:35px;
        padding:13px;
        border:1px solid #1C293C;
        border-radius:9px;
        background:#0B1220;
    ">

        <div style="
            font-size:11px;
            color:#91A4BE;
            text-transform:uppercase;
            letter-spacing:.08em;
        ">
            AI Capabilities
        </div>

        <div style="
            margin-top:10px;
            color:#AAB7C9;
            font-size:12px;
            line-height:1.8;
        ">
            Incident Detection<br>
            Root Cause Analysis<br>
            Evidence Extraction<br>
            Timeline Reconstruction<br>
            Impact Analysis<br>
            Remediation Planning
        </div>

    </div>
    """)


# ============================================================
# PAGE — HISTORY
# ============================================================

if st.session_state.page == "history":

    render_html("""
    <div class="hero">

        <div class="hero-title">
            Investigation <span class="hero-gradient">History</span>
        </div>

        <div class="hero-description">
            Review previous AI incident investigations.
        </div>

    </div>
    """)

    history = load_history()

    if not history:

        render_html("""
<div class="empty-state"
     style="
        min-height: 470px;
        height: 100%;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        text-align: center;
        padding: 40px;
        border: 1px dashed #263957;
        border-radius: 12px;
        background:
            radial-gradient(
                circle at 50% 40%,
                rgba(83,103,239,0.06),
                transparent 48%
            ),
            #080f1b;
     ">

<div style="
    width:46px;
    height:46px;
    border:2px solid #dbe5f5;
    transform:rotate(45deg);
    display:flex;
    align-items:center;
    justify-content:center;
    margin-bottom:30px;
    box-shadow:0 0 24px rgba(89,104,255,0.08);
">
    <div style="
        width:11px;
        height:11px;
        background:#5968ff;
        transform:rotate(45deg);
    "></div>
</div>

<div style="
    font-size:18px;
    font-weight:700;
    color:#f3f6ff;
    margin-bottom:10px;
">
    Waiting for an incident
</div>

<div style="
    max-width:430px;
    font-size:13px;
    line-height:1.7;
    color:#8fa1ba;
">
    Provide application or infrastructure logs on the left
    and start an AI investigation.
    <br>
    Your investigation results will appear here.
</div>

</div>
""")

    else:

        for item in history:

            severity = item.get(
                "severity",
                "UNKNOWN",
            )

            sev_class = severity_class(
                severity
            )

            col1, col2, col3 = st.columns(
                [5, 1.3, 1.2],
                gap="small",
            )

            with col1:

                render_html(
                    f"""
                    <div class="history-card">

                        <div class="history-title">
                            {safe_text(item.get(
                                "title",
                                "Untitled"
                            ))}
                        </div>

                        <div class="history-meta">
                            {safe_text(item.get(
                                "created_at",
                                ""
                            ))}
                            &nbsp; • &nbsp;
                            Confidence:
                            {item.get("confidence", 0)}%
                        </div>

                    </div>
                    """
                )

            with col2:

                render_html(
                    f"""
                    <div style="
                        margin-top:16px;
                        color:{'#FF6B78' if sev_class == 'critical'
                        else '#FF8A65' if sev_class == 'high'
                        else '#FFC857' if sev_class == 'medium'
                        else '#AEBBD0'};
                        font-size:11px;
                        font-weight:700;
                    ">
                        {safe_text(severity)}
                    </div>
                    """
                )

            with col3:

                if st.button(
                    "Open",
                    key=f"open_{item['id']}",
                    use_container_width=True,
                ):

                    loaded_logs = item.get(
                        "logs",
                        "",
                    )

                    st.session_state.logs = loaded_logs

                    # IMPORTANT:
                    # Keep the Paste Logs text area synchronized
                    # with the investigation being opened.
                    st.session_state.logs_input = loaded_logs

                    st.session_state.report = item.get(
                        "report"
                    )

                    st.session_state.current_investigation_id = (
                        item["id"]
                    )

                    st.session_state.page = "investigate"

                    st.rerun()


# ============================================================
# PAGE — SAVED REPORTS
# ============================================================

elif st.session_state.page == "saved":

    render_html("""
    <div class="hero">

        <div class="hero-title">
            Saved <span class="hero-gradient">Reports</span>
        </div>

        <div class="hero-description">
            Your saved incident investigations.
        </div>

    </div>
    """)

    history = load_history()

    saved_reports = [
        item
        for item in history
        if item.get("saved", False)
    ]

    if not saved_reports:

        render_html("""
        <div class="empty-state">

            <div class="empty-icon">▣</div>

            <div class="empty-title">
                No saved reports
            </div>

            <div class="empty-description">
                Save an investigation report to keep it
                available here for future reference.
            </div>

        </div>
        """)

    else:

        for item in saved_reports:

            col1, col2, col3 = st.columns(
                [5, 1.2, 1.2],
                gap="small",
            )

            with col1:

                render_html(
                    f"""
                    <div class="history-card">

                        <div class="history-title">
                            {safe_text(item.get(
                                "title",
                                "Untitled"
                            ))}
                        </div>

                        <div class="history-meta">
                            {safe_text(item.get(
                                "created_at",
                                ""
                            ))}
                            &nbsp; • &nbsp;
                            {safe_text(item.get(
                                "severity",
                                "UNKNOWN"
                            ))}
                        </div>

                    </div>
                    """
                )

            with col2:

                if st.button(
                    "Open",
                    key=f"saved_open_{item['id']}",
                    use_container_width=True,
                ):

                    st.session_state.logs = item.get(
                        "logs",
                        "",
                    )

                    st.session_state.report = item.get(
                        "report"
                    )

                    st.session_state.current_investigation_id = (
                        item["id"]
                    )

                    st.session_state.page = "investigate"

                    st.rerun()

            with col3:

                if st.button(
                    "Remove",
                    key=f"saved_remove_{item['id']}",
                    use_container_width=True,
                ):

                    toggle_saved(
                        item["id"]
                    )

                    st.rerun()


# ============================================================
# PAGE — INVESTIGATION
# ============================================================

else:

    # --------------------------------------------------------
    # TOP STATUS
    # --------------------------------------------------------

    render_html("""
    <div style="
        display:flex;
        justify-content:space-between;
        align-items:center;
        padding:7px 0 2px;
        border-bottom:1px solid #162236;
    ">

        <div style="
            color:#91A4BE;
            font-size:11px;
            letter-spacing:.08em;
            text-transform:uppercase;
            font-weight:500;
        ">
            AI Operations / Incident Investigation
        </div>

        <div style="
            color:#67D391;
            font-size:11px;
        ">
            ● AI ENGINE READY
        </div>

    </div>
    """)


    # --------------------------------------------------------
    # HERO
    # --------------------------------------------------------

    render_html("""
    <div class="hero">

        <div class="hero-title">
            AI Incident
            <span class="hero-gradient">
                Investigator
            </span>

            <span class="hero-by">
                by&nbsp;&nbsp;Nilesh
            </span>
        </div>

        <div class="hero-description">
            Analyze application and infrastructure logs
            with AI to identify incidents, root causes,
            evidence, impact, timelines and remediation.
        </div>

    </div>
    """)


    # --------------------------------------------------------
    # INPUT AREA
    # --------------------------------------------------------

    left_col, right_col = st.columns(
        [0.90, 1.25],
        gap="large",
    )


    with left_col:

        render_html("""
        <div class="panel">

            <div class="panel-title">
                Provide Application Logs
            </div>

            <div class="panel-subtitle">
                Upload a log file or paste logs manually.
            </div>

        </div>
        """)


        upload_tab, paste_tab = st.tabs(
            [
                "☁ Upload File",
                "▣ Paste Logs",
            ]
        )


        with upload_tab:

            uploaded_file = st.file_uploader(
                "Upload application log",
                type=[
                    "log",
                    "txt",
                ],
                label_visibility="collapsed",
            )

            if uploaded_file:

                uploaded_bytes = (
                    uploaded_file.read()
                )

                try:

                    uploaded_text = (
                        uploaded_bytes.decode(
                            "utf-8"
                        )
                    )

                except UnicodeDecodeError:

                    uploaded_text = (
                        uploaded_bytes.decode(
                            "utf-8",
                            errors="replace",
                        )
                    )

                st.session_state.logs = uploaded_text
                st.session_state.logs_input = uploaded_text

                st.success(
                    f"Loaded: {uploaded_file.name}"
                )


        with paste_tab:

            st.text_area(
                "Application logs",
                height=290,
                placeholder=(
                    "Paste application or infrastructure logs here..."
                ),
                label_visibility="collapsed",
                key="logs_input",
            )

        def clear_logs():
            st.session_state.logs = ""
            st.session_state.logs_input = ""


        if st.button(
            "✕  Clear Logs",
            key="clear_logs",
            use_container_width=True,
            on_click=clear_logs,
        ):
            pass


        st.html(
            '<div style="height:14px;"></div>'
        )


        analyze_clicked = st.button(
            "✦  Analyze Incident",
            use_container_width=True,
        )


    # ========================================================
    # ANALYZE
    # ========================================================

    if analyze_clicked:

        logs = (
            st.session_state.get(
                "logs_input",
                st.session_state.logs,
            ).strip()
        )

        st.session_state.logs = logs

        if not logs:

            st.warning(
                "Please provide logs first."
            )

        else:

            # ------------------------------------------------
            # CREATE A FINGERPRINT FROM THE ORIGINAL LOGS
            # ------------------------------------------------

            log_hash = generate_log_hash(logs)

            # ------------------------------------------------
            # CHECK WHETHER THESE LOGS WERE ALREADY ANALYZED
            # ------------------------------------------------

            existing_investigation = find_by_log_hash(
                log_hash
            )

            if existing_investigation:

                # --------------------------------------------
                # SAME LOGS FOUND
                # --------------------------------------------

                st.session_state.report = (
                    existing_investigation["report"]
                )

                st.session_state.current_investigation_id = (
                    existing_investigation["id"]
                )

                st.session_state.analysis_time = 0

                st.info(
                    "This log set was already investigated. "
                    "Showing the existing investigation."
                )

            else:

                # --------------------------------------------
                # NEW LOGS
                # --------------------------------------------

                with st.spinner(
                    "AI is investigating the incident..."
                ):

                    start_time = time.perf_counter()

                    try:

                        report = investigate_incident(
                            logs
                        )

                        elapsed = (
                            time.perf_counter()
                            - start_time
                        )

                        st.session_state.report = report

                        st.session_state.analysis_time = (
                            elapsed
                        )

                        # ------------------------------------
                        # SAVE SANITIZED LOGS ONLY
                        # ------------------------------------

                        sanitization_result = sanitize_logs(
                            logs
                        )

                        investigation = add_investigation(
                            sanitization_result.logs,
                            report,
                            log_hash=log_hash,
                        )

                        st.session_state.current_investigation_id = (
                            investigation["id"]
                        )

                    except Exception as exc:

                        st.session_state.report = None

                        st.error(
                            f"Incident analysis failed: {exc}"
                        )


    # ========================================================
    # RESULT
    # ========================================================

    report = st.session_state.report


    if report:

        render_html("""
        <div style="
            margin-top:35px;
            border-top:1px solid #1C293C;
            padding-top:24px;
        ">
        </div>
        """)


        # ----------------------------------------------------
        # RESULT HEADER
        # ----------------------------------------------------

        elapsed = (
            st.session_state.analysis_time
        )

        elapsed_text = (
            f"Analyzed in {elapsed:.1f}s"
            if elapsed
            else ""
        )


        header_left, header_right = st.columns(
            [4, 1],
        )


        with header_left:

            render_html("""
            <div style="
                font-size:21px;
                font-weight:750;
                color:#F4F7FB;
            ">
                Incident Analysis
            </div>
            """)


        with header_right:

            render_html(
                f"""
                <div style="
                    text-align:right;
                    color:#75849A;
                    font-size:12px;
                    padding-top:7px;
                ">
                    {safe_text(elapsed_text)}
                </div>
                """
            )


        # ----------------------------------------------------
        # METRICS
        # ----------------------------------------------------

        severity = str(
            report.get(
                "severity",
                "UNKNOWN",
            )
        ).upper()

        confidence = int(
            report.get(
                "confidence",
                0,
            )
        )


        metric1, metric2 = st.columns(
            2,
            gap="small",
        )


        with metric1:

            render_html(
                f"""
                <div class="metric-card">

                    <div class="metric-label">
                        Severity
                    </div>

                    <div class="
                        metric-value
                        {severity_class(severity)}
                    ">
                        {safe_text(severity)}
                    </div>

                </div>
                """
            )


        with metric2:

            render_html(
                f"""
                <div class="metric-card">

                    <div class="metric-label">
                        AI Confidence
                    </div>

                    <div class="metric-value">
                        {confidence}%
                    </div>

                </div>
                """
            )


        # ----------------------------------------------------
        # INCIDENT TITLE
        # ----------------------------------------------------

        render_html(
            f"""
            <div class="section-card">

                <div class="section-heading">
                    Incident
                </div>

                <div class="root-cause">
                    {safe_text(
                        report.get(
                            "incident_title",
                            "Incident Investigation",
                        )
                    )}
                </div>

            </div>
            """
        )


        # ----------------------------------------------------
        # SUMMARY
        # ----------------------------------------------------

        render_html(
            f"""
            <div class="section-card">

                <div class="section-heading">
                    Summary
                </div>

                <div class="section-content">
                    {safe_text(
                        report.get(
                            "summary",
                            "Not available.",
                        )
                    )}
                </div>

            </div>
            """
        )


        # ----------------------------------------------------
        # ROOT CAUSE
        # ----------------------------------------------------

        render_html(
            f"""
            <div class="section-card">

                <div class="section-heading">
                    Root Cause
                </div>

                <div class="root-cause">
                    {safe_text(
                        report.get(
                            "root_cause",
                            "Could not be determined.",
                        )
                    )}
                </div>

            </div>
            """
        )


        # ----------------------------------------------------
        # EVIDENCE + COMPONENTS
        # ----------------------------------------------------

        evidence_col, component_col = st.columns(
            2,
            gap="small",
        )


        with evidence_col:

            evidence = report.get(
                "evidence",
                [],
            )

            evidence_html = ""

            for item in evidence:

                evidence_html += (
                    f"<li>{safe_text(item)}</li>"
                )

            render_html(
                f"""
                <div class="section-card">

                    <div class="section-heading">
                        Evidence
                    </div>

                    <ul class="ai-list">
                        {evidence_html}
                    </ul>

                </div>
                """
            )


        with component_col:

            components = report.get(
                "affected_components",
                [],
            )

            components_html = ""

            for item in components:

                components_html += (
                    f"<li>{safe_text(item)}</li>"
                )

            render_html(
                f"""
                <div class="section-card">

                    <div class="section-heading">
                        Affected Components
                    </div>

                    <ul class="ai-list">
                        {components_html}
                    </ul>

                </div>
                """
            )


        # ----------------------------------------------------
        # TIMELINE
        # ----------------------------------------------------

        timeline = report.get(
            "timeline",
            [],
        )

        timeline_html = ""

        for event in timeline:

            if isinstance(event, dict):

                event_time = event.get(
                    "time",
                    "",
                )

                event_text = event.get(
                    "event",
                    "",
                )

            else:

                event_time = ""

                event_text = str(event)

            timeline_html += f"""
            <div class="timeline-item">

                <div class="timeline-time">
                    {safe_text(event_time)}
                </div>

                <div class="timeline-event">
                    {safe_text(event_text)}
                </div>

            </div>
            """


        render_html(
            f"""
            <div class="section-card">

                <div class="section-heading">
                    Timeline
                </div>

                {timeline_html}

            </div>
            """
        )


        # ----------------------------------------------------
        # IMPACT + ACTIONS
        # ----------------------------------------------------

        impact_col, action_col = st.columns(
            2,
            gap="small",
        )


        with impact_col:

            impact = report.get(
                "impact",
                [],
            )

            impact_html = ""

            for item in impact:

                impact_html += (
                    f"<li>{safe_text(item)}</li>"
                )

            render_html(
                f"""
                <div class="section-card">

                    <div class="section-heading">
                        Impact
                    </div>

                    <ul class="ai-list">
                        {impact_html}
                    </ul>

                </div>
                """
            )


        with action_col:

            actions = report.get(
                "immediate_actions",
                [],
            )

            actions_html = ""

            for item in actions:

                actions_html += (
                    f"<li>{safe_text(item)}</li>"
                )

            render_html(
                f"""
                <div class="section-card">

                    <div class="section-heading">
                        Immediate Actions
                    </div>

                    <ul class="ai-list">
                        {actions_html}
                    </ul>

                </div>
                """
            )


        # ----------------------------------------------------
        # PREVENTION
        # ----------------------------------------------------

        prevention = report.get(
            "prevention",
            [],
        )

        prevention_html = ""

        for item in prevention:

            prevention_html += (
                f"<li>{safe_text(item)}</li>"
            )


        render_html(
            f"""
            <div class="section-card">

                <div class="section-heading">
                    Prevention
                </div>

                <ul class="ai-list">
                    {prevention_html}
                </ul>

            </div>
            """
        )


        # ----------------------------------------------------
        # SAVE / EXPORT
        # ----------------------------------------------------

        st.html(
            '<div style="height:18px;"></div>'
        )


        save_col, txt_col, json_col = st.columns(
            [1.2, 1, 1],
            gap="small",
        )


        current_id = (
            st.session_state.current_investigation_id
        )


        with save_col:

            current_item = (
                get_investigation(
                    current_id
                )
                if current_id
                else None
            )

            is_saved = (
                current_item.get(
                    "saved",
                    False,
                )
                if current_item
                else False
            )


            save_label = (
                "★  Saved"
                if is_saved
                else "☆  Save Report"
            )


            if st.button(
                save_label,
                use_container_width=True,
            ):

                if current_id:

                    toggle_saved(
                        current_id
                    )

                    st.rerun()


        text_report = build_text_report(
            report
        )


        with txt_col:

            st.download_button(
                "↓  TXT Report",
                data=text_report,
                file_name=(
                    "incident_investigation_report.txt"
                ),
                mime="text/plain",
                use_container_width=True,
            )


        with json_col:

            json_report = json.dumps(
                report,
                indent=2,
                ensure_ascii=False,
            )

            st.download_button(
                "↓  JSON Report",
                data=json_report,
                file_name=(
                    "incident_investigation_report.json"
                ),
                mime="application/json",
                use_container_width=True,
            )


    # ========================================================
    # EMPTY RESULT
    # ========================================================

    else:

        with right_col:

            render_html("""
            <div class="empty-state">

                <div class="empty-icon">
                    ◈
                </div>

                <div class="empty-title">
                    Waiting for an incident
                </div>

                <div class="empty-description">
                    Provide application or infrastructure
                    logs and start an AI investigation.
                    Your investigation will appear here.
                </div>

            </div>
            """)


# ============================================================
# FOOTER
# ============================================================

render_html("""
<div class="footer">
    AI Incident Investigator · Powered by Generative AI ·
    Built by Nilesh
</div>
""")