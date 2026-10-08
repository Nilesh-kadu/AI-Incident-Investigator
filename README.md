# 🚨 AI Incident Investigator

> **GenAI-powered incident analysis assistant for application and infrastructure logs**

AI Incident Investigator is a Python + Streamlit application that uses Generative AI to analyze application/infrastructure logs and produce a structured incident investigation report.

It is designed as an **AI/SRE operations assistant** that helps engineers quickly understand incidents, identify evidence, reconstruct timelines, assess impact, and generate remediation recommendations.

---

## ✨ Key Features

- 🤖 **AI-powered incident investigation**
- 🔴 **Incident severity classification**
- 🎯 **Confidence scoring**
- 🧠 **Root-cause analysis**
- 🔎 **Evidence extraction directly from logs**
- 🕒 **Timeline reconstruction**
- 🧩 **Affected-component identification**
- 💥 **Impact analysis**
- 🛠️ **Immediate remediation actions**
- 🛡️ **Prevention recommendations**
- ❓ **Uncertainty detection**
- 🔐 **Sensitive-data redaction before AI analysis**
- 📦 **Large-log protection and truncation**
- ♻️ **Duplicate investigation detection**
- 🗂️ **Investigation history**
- ⭐ **Saved reports**
- 📄 **TXT report export**
- 📋 **JSON report export**
- 📁 **Upload `.log` / `.txt` files**
- ✍️ **Paste logs directly**
- 🧹 **Clear logs**
- 🌙 **Dark SRE/AI operations interface**

---

## 🏗️ Architecture

```text
                  ┌─────────────────────────┐
                  │      Streamlit UI       │
                  │  Upload / Paste Logs    │
                  └────────────┬────────────┘
                               │
                               ▼
                  ┌─────────────────────────┐
                  │   Security Layer        │
                  │                         │
                  │ • Credential Redaction  │
                  │ • Secret Sanitization   │
                  │ • Sensitive Data Filter │
                  └────────────┬────────────┘
                               │
                               ▼
                  ┌─────────────────────────┐
                  │    Log Protection       │
                  │                         │
                  │ • Large Log Detection   │
                  │ • Safe Truncation       │
                  │ • Duplicate Detection  │
                  └────────────┬────────────┘
                               │
                               ▼
                  ┌─────────────────────────┐
                  │   Investigation Prompt  │
                  │   + Incident Rules      │
                  └────────────┬────────────┘
                               │
                               ▼
                  ┌─────────────────────────┐
                  │      Gemini LLM         │
                  │   Generative AI Model   │
                  └────────────┬────────────┘
                               │
                               ▼
                  ┌─────────────────────────┐
                  │ JSON Extraction &       │
                  │ Report Validation      │
                  └────────────┬────────────┘
                               │
                               ▼
        ┌──────────────────────┴──────────────────────┐
        │                                             │
        ▼                                             ▼
┌──────────────────┐                         ┌──────────────────┐
│ Investigation    │                         │ Report Export    │
│ History / Saved  │                         │ TXT / JSON       │
│ Reports          │                         │                  │
└──────────────────┘                         └──────────────────┘
```

---

## 🧠 AI Investigation Workflow

The application follows this workflow:

```text
Application / Infrastructure Logs
                ↓
        Input Validation
                ↓
      Security Sanitization
                ↓
      Large Log Protection
                ↓
       Incident Prompting
                ↓
          Gemini LLM
                ↓
        JSON Extraction
                ↓
        Report Validation
                ↓
     Structured Investigation
                ↓
   History / Saved / Export
```

---

## 📊 Generated Investigation Report

The AI produces structured information including:

### Incident
- Incident title
- Severity
- Confidence

### Analysis
- Summary
- Root cause
- Evidence
- Affected components
- Timeline
- Impact

### Response
- Immediate actions
- Prevention recommendations
- Uncertainties

The prompting layer is designed to keep the investigation **evidence-driven** and reduce unsupported claims.

---

## 🔐 Security

Before logs are sent to the AI model, the application sanitizes common sensitive values.

Examples include:

- Bearer tokens
- JWT tokens
- API keys
- Access tokens
- Secret keys
- Passwords
- AWS access keys
- Google API keys
- GitHub tokens
- Private keys

Sensitive values are replaced with safe placeholders such as:

```text
[REDACTED_PASSWORD]
[REDACTED_API_KEY]
[REDACTED_BEARER_TOKEN]
[REDACTED_JWT]
```

The application also records the number and categories of redactions without exposing the original secret values.

> **Important:** Log sanitization is a defensive layer, not a guarantee that every possible secret format will be detected. Production deployments should use additional enterprise secret-scanning and data-loss-prevention controls.

---

## 📦 Large Log Protection

Very large logs are protected from being sent entirely to the model.

The application applies a maximum analysis size and, when required, keeps the beginning and end of the log while replacing the middle with a truncation marker.

This helps control:

- Prompt size
- Processing cost
- Model latency
- Failure risk

---

## ♻️ Duplicate Detection

The application generates a normalized SHA-256 hash of the supplied logs.

If the same normalized log content has already been investigated, the existing investigation can be reused instead of unnecessarily sending the same incident to the AI model again.

---

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python | Application/backend logic |
| Streamlit | Web interface |
| Google Gemini | Generative AI investigation |
| Google GenAI SDK | Gemini API integration |
| python-dotenv | Environment configuration |
| JSON | Structured reports/history |
| hashlib | Duplicate detection |
| Regular Expressions | Security sanitization |

---

## 📁 Project Structure

```text
AI-Incident-Investigator/
│
├── app.py
├── incident_analyzer.py
├── llm.py
├── prompts.py
├── security.py
├── storage.py
├── requirements.txt
├── .env
├── .gitignore
└── incident_history.json
```

### File responsibilities

**`app.py`**
- Streamlit interface
- Navigation
- Log input
- Investigation results
- History
- Saved reports
- Export

**`incident_analyzer.py`**
- Investigation workflow
- Security sanitization
- Large-log protection
- Gemini request handling
- JSON extraction/validation

**`llm.py`**
- Gemini API client
- LLM request execution

**`prompts.py`**
- Incident-investigation instructions
- Evidence-based analysis rules
- Structured output schema

**`security.py`**
- Secret detection
- Credential redaction
- Security reporting

**`storage.py`**
- Investigation history
- Duplicate detection
- Saved reports
- Local JSON persistence

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd AI-Incident-Investigator
```

### 2. Create a virtual environment

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure the API key

Create a `.env` file:

```env
GEMINI_API_KEY=your_gemini_api_key_here
```

**Never commit `.env` or expose your API key publicly.**

### 5. Run the application

```bash
streamlit run app.py
```

The application will open in your browser.

---

## 🧪 Example Incident

Example input:

```text
2026-10-08 10:00:01 INFO Application started
2026-10-08 10:01:12 INFO Processing request
2026-10-08 10:01:15 WARN Response time increased to 850ms
2026-10-08 10:01:18 ERROR Request failed with status 504
2026-10-08 10:01:19 ERROR Gateway timeout
2026-10-08 10:01:20 CRITICAL Service unavailable
```

The system analyzes the evidence and produces a structured incident report containing severity, confidence, root-cause assessment, evidence, timeline, impact, immediate actions, prevention and uncertainties.

---

## 🎯 Why This Project?

Traditional incident investigation often requires engineers to manually:

1. Read large volumes of logs
2. Identify important events
3. Determine the incident severity
4. Reconstruct the timeline
5. Identify affected services
6. Investigate possible root causes
7. Decide immediate remediation steps
8. Document the incident

This project demonstrates how Generative AI can assist with that workflow while keeping the analysis grounded in the supplied logs.

---

## 💼 Skills Demonstrated

This project demonstrates practical experience with:

- Generative AI
- LLM integration
- Prompt engineering
- Structured LLM output
- Python application development
- Streamlit
- API integration
- Error handling
- Security-aware AI workflows
- Secret redaction
- Input validation
- Large-input handling
- Hash-based duplicate detection
- JSON persistence
- Report generation
- AI-assisted root-cause analysis

---

## 🚀 Future Enhancements

Potential production-level improvements:

- Real-time log streaming
- Cloud log integrations
- Elasticsearch / OpenSearch integration
- PostgreSQL investigation storage
- Authentication and role-based access
- Slack / Teams incident notifications
- PagerDuty integration
- Observability platform integrations
- RAG over historical incidents
- Incident similarity search
- Multi-agent investigation workflow
- Automated Jira incident creation
- Production monitoring and audit logging

---

## 👨‍💻 Author

**Nilesh**

Python & Generative AI Developer  
AI/ML • LLMs • RAG • FastAPI • Deep Learning • Java • Spring Boot

---

## ⭐ Project Highlights

> **AI-powered incident investigation from raw application logs — with security-aware log sanitization, evidence-driven analysis, structured reporting, investigation history, and export capabilities.**
