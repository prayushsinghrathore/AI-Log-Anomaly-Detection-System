# 🛡️ AI Log Anomaly Detection System

An AI-powered cybersecurity dashboard that automatically detects suspicious activity in Apache/Nginx access logs using the Isolation Forest algorithm and presents interactive visualizations through Streamlit.

---

A machine-learning application that detects anomalous activity in server access
logs using an **Isolation Forest**, with an interactive **Streamlit** dashboard
for log visualization, anomaly detection, and security monitoring.

## Features

- **Log parsing** — parses Apache/Nginx *combined* access-log format into
  structured records.
- **Feature engineering** — derives behavioural signals per request and per
  source IP: error rates, response sizes, request frequency, URL/User-Agent
  characteristics, off-hours activity, and unusual HTTP methods.
- **Unsupervised detection** — Isolation Forest flags outliers with no labelled
  training data required; an adjustable *contamination* threshold controls
  sensitivity.
- **Interactive dashboard** — KPIs, request timeline (normal vs. anomalous),
  anomaly-score distribution, status-code breakdown, top offending IPs, and a
  sortable/exportable table of flagged requests.
- **Synthetic data generator** — produces realistic traffic with injected
  attacks (scanners, SQLi probes, path traversal, data-exfil-style large
  responses) so the app works out of the box.

## Quick start

```bash
cd ai-log-anomaly-detection

# 1. (recommended) create a virtual environment
python3 -m venv .venv && source .venv/bin/activate

# 2. install dependencies
pip install -r requirements.txt

# 3. generate a sample log with injected anomalies
python scripts/generate_sample_logs.py --out data/sample_access.log --n 5000

# 4. launch the dashboard
streamlit run app.py
```

Then open the URL Streamlit prints (default http://localhost:8501), click
**Use bundled sample log**, or upload your own `.log` / `.txt` access log.

## Project layout

```
ai-log-anomaly-detection/
├── app.py                       # Streamlit dashboard
├── requirements.txt
├── README.md
├── src/
│   ├── log_parser.py            # combined-format log → DataFrame
│   ├── features.py              # numeric feature engineering
│   └── detector.py              # Isolation Forest wrapper
├── scripts/
│   └── generate_sample_logs.py  # synthetic log generator
└── data/                        # generated sample logs (gitignored)
```

## How it works

1. **Parse** raw log lines into structured fields (IP, timestamp, method, path,
   status, bytes, user agent).
2. **Engineer features** — each request becomes a numeric vector combining its
   own attributes with aggregates about its source IP.
3. **Detect** — features are standardized and scored by an Isolation Forest.
   Requests that isolate quickly in the tree ensemble receive high anomaly
   scores and are flagged.
4. **Visualize** — the dashboard surfaces flagged requests and traffic patterns
   for a security analyst to triage.

## Using your own logs

Any Apache/Nginx *combined* format log works, e.g.:

```
12.34.56.78 - - [06/Jul/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1043 "-" "Mozilla/5.0 ..."
```

Upload it via the sidebar; unparseable lines are skipped automatically.

## Programmatic use

```python
from src import parse_log_file, build_features, AnomalyDetector

logs = parse_log_file("data/sample_access.log")
features = build_features(logs)
results = AnomalyDetector(contamination=0.03).fit_predict(features)

flagged = logs[results["anomaly"].values]
print(flagged[["ip", "path", "status"]])
```
