# 🛡️ AI Log Anomaly Detection System

> **Detect suspicious server activity using Machine Learning.**

An AI-powered cybersecurity dashboard that automatically detects anomalous activity in **Apache/Nginx access logs** using the **Isolation Forest** algorithm. The application provides an intuitive **Streamlit dashboard** for log visualization, anomaly detection, and security monitoring.

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?logo=streamlit)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-F7931E?logo=scikitlearn)
![Plotly](https://img.shields.io/badge/Plotly-Visualization-3F4F75?logo=plotly)

---

# ✨ Features

### 📄 Log Parsing
- Parses **Apache/Nginx Combined Access Logs**
- Converts raw logs into structured records
- Automatically skips malformed log entries

### 🧠 Intelligent Feature Engineering
Extracts behavioral features such as:
- Request frequency
- Response size
- HTTP status patterns
- Error rate
- User-Agent characteristics
- Off-hours activity
- Suspicious HTTP methods
- Per-IP behavioral statistics

### 🤖 AI-Powered Anomaly Detection
Uses **Isolation Forest**, an unsupervised Machine Learning algorithm, to identify unusual requests without requiring labeled training data.

The anomaly sensitivity can be adjusted using a configurable **Contamination Threshold**.

### 📊 Interactive Dashboard
Visualize security events using:
- 📈 Request Timeline
- 🚨 Anomaly Score Distribution
- 🌐 Top Suspicious IP Addresses
- 📉 HTTP Status Code Analytics
- 📋 Sortable Anomaly Table
- 📥 Export anomalies as CSV

### 🧪 Synthetic Log Generator
Generate realistic server traffic with injected attacks including:
- SQL Injection
- Path Traversal
- Web Scanners
- Large Data Exfiltration Responses
- Brute Force Patterns

---

# 🛠 Tech Stack

| Category | Technologies |
|----------|--------------|
| Programming | Python |
| Dashboard | Streamlit |
| Machine Learning | Scikit-Learn (Isolation Forest) |
| Data Processing | Pandas, NumPy |
| Visualization | Plotly |

---

# 🧠 System Workflow

```text
Apache / Nginx Logs
        │
        ▼
   Log Parsing
        │
        ▼
Feature Engineering
        │
        ▼
 Isolation Forest
        │
        ▼
 Anomaly Detection
        │
        ▼
Streamlit Dashboard
```

---

# ⚡ Quick Start

Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/AI-Log-Anomaly-Detection-System.git
cd AI-Log-Anomaly-Detection-System
```

Create a virtual environment

```bash
python -m venv .venv
```

Activate it

**macOS/Linux**

```bash
source .venv/bin/activate
```

**Windows**

```bash
.venv\Scripts\activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

Generate sample logs

```bash
python scripts/generate_sample_logs.py --out data/sample_access.log --n 5000
```

Run the application

```bash
streamlit run app.py
```

---

# 📂 Project Structure

```text
AI-Log-Anomaly-Detection-System/
│
├── app.py
├── requirements.txt
├── README.md
├── src/
│   ├── log_parser.py
│   ├── features.py
│   └── detector.py
├── scripts/
│   └── generate_sample_logs.py
└── data/
```

---

# 🔍 How It Works

1. **Parse Logs** – Convert Apache/Nginx access logs into structured records.

2. **Feature Engineering** – Extract request-level and IP-level behavioral features.

3. **Detect Anomalies** – Apply the Isolation Forest algorithm to identify suspicious requests.

4. **Visualize Results** – Display insights through an interactive Streamlit dashboard for easier analysis.

---

# 📥 Using Your Own Logs

The application supports any **Apache/Nginx Combined Access Log**.

Example:

```text
12.34.56.78 - - [06/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0 ..."
```

Upload your `.log` or `.txt` file using the sidebar. Invalid or malformed log entries are skipped automatically.

---

# 💻 Programmatic Usage

```python
from src import parse_log_file, build_features, AnomalyDetector

logs = parse_log_file("data/sample_access.log")
features = build_features(logs)

results = AnomalyDetector(contamination=0.03).fit_predict(features)

flagged = logs[results["anomaly"].values]
print(flagged[["ip", "path", "status"]])
```

---

# 🚀 Future Improvements

- 🌍 GeoIP Mapping
- 📧 Email Alerts
- ⚡ Real-time Log Streaming
- 🐳 Docker Support
- ☸️ Kubernetes Deployment
- 🔥 SIEM Integration

---

# ⭐ Support

If you found this project useful, consider giving it a **Star ⭐** on GitHub.
