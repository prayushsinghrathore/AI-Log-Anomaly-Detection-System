from __future__ import annotations

import io
import os

import pandas as pd
import plotly.express as px
import streamlit as st

from src import AnomalyDetector, build_features, parse_log_lines

SAMPLE_LOG = os.path.join(os.path.dirname(__file__), "data", "sample_access.log")

st.set_page_config(
    page_title="AI Log Anomaly Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---- Theme -----------------------------------------------------------------
ACCENT = "#7c5cff"       # violet accent
ANOMALY = "#ff5470"      # anomaly red/pink
NORMAL = "#38bdf8"       # normal cyan
BG = "#0e1117"
CARD_BG = "#171a23"

CUSTOM_CSS = f"""
<style>
    /* App background */
    .stApp {{
        background: radial-gradient(1200px 600px at 20% -10%, #1b1f2e 0%, {BG} 55%);
    }}

    /* Hero header banner */
    .hero {{
        border-radius: 18px;
        padding: 26px 32px;
        margin-bottom: 8px;
        background: linear-gradient(120deg, rgba(124,92,255,0.22), rgba(56,189,248,0.10));
        border: 1px solid rgba(124,92,255,0.35);
        box-shadow: 0 8px 30px rgba(0,0,0,0.35);
    }}
    .hero h1 {{
        margin: 0; font-size: 2.0rem; font-weight: 800;
        letter-spacing: -0.5px; color: #f5f6fa;
    }}
    .hero p {{
        margin: 6px 0 0; color: #aab0c0; font-size: 0.98rem;
    }}

    /* KPI metric cards */
    div[data-testid="stMetric"] {{
        background: {CARD_BG};
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 14px;
        padding: 16px 18px;
        box-shadow: 0 4px 18px rgba(0,0,0,0.25);
        transition: transform .15s ease, border-color .15s ease;
    }}
    div[data-testid="stMetric"]:hover {{
        transform: translateY(-2px);
        border-color: {ACCENT};
    }}
    div[data-testid="stMetricLabel"] p {{
        color: #8b93a7; font-weight: 600; text-transform: uppercase;
        font-size: 0.72rem; letter-spacing: 0.6px;
    }}
    div[data-testid="stMetricValue"] {{ color: #f5f6fa; font-weight: 800; }}

    /* Section subheaders */
    h3 {{ color: #e7e9f0 !important; font-weight: 700 !important; }}

    /* Sidebar */
    section[data-testid="stSidebar"] {{
        background: {CARD_BG};
        border-right: 1px solid rgba(255,255,255,0.06);
    }}

    /* Buttons */
    .stButton>button, .stDownloadButton>button {{
        border-radius: 10px; font-weight: 600;
        border: 1px solid {ACCENT};
        background: linear-gradient(120deg, {ACCENT}, #5b8bff);
        color: white;
    }}
    .stButton>button:hover, .stDownloadButton>button:hover {{
        filter: brightness(1.08); border-color: {ACCENT};
    }}

    /* Divider spacing */
    hr {{ margin: 0.6rem 0 1.2rem; border-color: rgba(255,255,255,0.08); }}
</style>
"""


def _style_fig(fig, height: int = 300):
    """Apply the dark app theme to a Plotly figure."""
    fig.update_layout(
        template="plotly_dark",
        margin=dict(t=10, b=0, l=0, r=0),
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        legend_title="",
        font=dict(color="#c7cbd6"),
    )
    fig.update_xaxes(gridcolor="rgba(255,255,255,0.06)", zeroline=False)
    fig.update_yaxes(gridcolor="rgba(255,255,255,0.06)", zeroline=False)
    return fig


@st.cache_data(show_spinner=False)
def _load_and_detect(raw_text: str, contamination: float) -> tuple[pd.DataFrame, dict]:
    """Parse logs, build features, run detection. Cached on inputs."""
    logs = parse_log_lines(raw_text.splitlines())
    if logs.empty:
        return logs, {}

    features = build_features(logs)
    detector = AnomalyDetector(contamination=contamination)
    results = detector.fit_predict(features)

    combined = pd.concat([logs.reset_index(drop=True), results.reset_index(drop=True)], axis=1)
    stats = {
        "total": len(combined),
        "anomalies": int(combined["anomaly"].sum()),
        "unique_ips": combined["ip"].nunique(),
        "error_rate": float((combined["status"] >= 400).mean()),
    }
    return combined, stats


def _get_raw_text() -> str | None:
    st.sidebar.markdown("### 🛡️ Controls")
    st.sidebar.markdown("#### 📁 Log source")
    uploaded = st.sidebar.file_uploader(
        "Upload an access log (combined format)", type=["log", "txt"]
    )
    if uploaded is not None:
        return io.TextIOWrapper(uploaded, encoding="utf-8", errors="replace").read()

    if os.path.exists(SAMPLE_LOG):
        if st.sidebar.button("Use bundled sample log", use_container_width=True):
            st.session_state["use_sample"] = True
        if st.session_state.get("use_sample"):
            with open(SAMPLE_LOG, "r", encoding="utf-8") as fh:
                return fh.read()
    else:
        st.sidebar.info(
            "No sample found. Generate one:\n\n"
            "`python scripts/generate_sample_logs.py`"
        )
    return None


def main() -> None:
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)
    st.markdown(
        """
        <div class="hero">
            <h1>🛡️ AI Log Anomaly Detection</h1>
            <p>Isolation Forest–based detection of anomalous activity in server access logs.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    contamination = st.sidebar.slider(
        "Expected anomaly rate (contamination)",
        min_value=0.005, max_value=0.15, value=0.03, step=0.005,
        help="Higher values flag more requests as anomalous.",
    )

    raw_text = _get_raw_text()
    if not raw_text:
        st.info("⬅️ Upload a log file or click **Use bundled sample log** to begin.")
        return

    data, stats = _load_and_detect(raw_text, contamination)
    if data.empty:
        st.error("No valid log lines could be parsed. Check the log format.")
        return

    # ---- KPI row ---------------------------------------------------------
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total requests", f"{stats['total']:,}")
    c2.metric("Anomalies flagged", f"{stats['anomalies']:,}")
    c3.metric("Unique IPs", f"{stats['unique_ips']:,}")
    c4.metric("HTTP error rate", f"{stats['error_rate']:.1%}")

    st.divider()

    # ---- Charts ----------------------------------------------------------
    left, right = st.columns(2)

    with left:
        st.subheader("Requests over time")
        ts = data.dropna(subset=["datetime"]).copy()
        if not ts.empty:
            ts["bucket"] = ts["datetime"].dt.floor("15min")
            timeline = (
                ts.groupby(["bucket", "anomaly"]).size().reset_index(name="count")
            )
            timeline["type"] = timeline["anomaly"].map({True: "Anomaly", False: "Normal"})
            fig = px.area(
                timeline, x="bucket", y="count", color="type",
                color_discrete_map={"Anomaly": ANOMALY, "Normal": NORMAL},
            )
            st.plotly_chart(_style_fig(fig), use_container_width=True)

    with right:
        st.subheader("Anomaly score distribution")
        fig = px.histogram(
            data, x="anomaly_score", nbins=40,
            color=data["anomaly"].map({True: "Anomaly", False: "Normal"}),
            color_discrete_map={"Anomaly": ANOMALY, "Normal": NORMAL},
        )
        st.plotly_chart(_style_fig(fig), use_container_width=True)

    left2, right2 = st.columns(2)
    with left2:
        st.subheader("Status codes")
        sc = data["status"].value_counts().sort_index().reset_index()
        sc.columns = ["status", "count"]
        fig = px.bar(sc, x="status", y="count")
        fig.update_traces(marker_color=ACCENT)
        st.plotly_chart(_style_fig(fig), use_container_width=True)

    with right2:
        st.subheader("Top source IPs by anomalies")
        top = (
            data[data["anomaly"]]
            .groupby("ip").size().sort_values(ascending=False).head(10)
            .reset_index(name="anomalies")
        )
        if top.empty:
            st.write("No anomalies detected at this threshold.")
        else:
            fig = px.bar(top, x="anomalies", y="ip", orientation="h")
            fig.update_traces(marker_color=ANOMALY)
            fig.update_layout(yaxis=dict(categoryorder="total ascending"))
            st.plotly_chart(_style_fig(fig), use_container_width=True)

    st.divider()

    # ---- Anomaly table ---------------------------------------------------
    st.subheader("🚨 Flagged anomalies")
    anomalies = (
        data[data["anomaly"]]
        .sort_values("anomaly_score", ascending=False)
        [["datetime", "ip", "method", "path", "status", "bytes",
          "user_agent", "anomaly_score"]]
    )
    st.dataframe(
        anomalies,
        use_container_width=True,
        column_config={
            "anomaly_score": st.column_config.ProgressColumn(
                "Severity", min_value=0.0, max_value=1.0, format="%.2f"
            ),
        },
    )
    st.download_button(
        "⬇️ Download anomalies as CSV",
        anomalies.to_csv(index=False).encode("utf-8"),
        file_name="anomalies.csv",
        mime="text/csv",
    )


if __name__ == "__main__":
    main()
