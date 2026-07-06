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
)


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
    st.sidebar.header("📁 Log source")
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
    st.title("🛡️ AI Log Anomaly Detection")
    st.caption(
        "Isolation Forest-based detection of anomalous activity in server access logs."
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
                color_discrete_map={"Anomaly": "#e4572e", "Normal": "#4c78a8"},
            )
            fig.update_layout(margin=dict(t=10, b=0, l=0, r=0), legend_title="")
            st.plotly_chart(fig, use_container_width=True)

    with right:
        st.subheader("Anomaly score distribution")
        fig = px.histogram(
            data, x="anomaly_score", nbins=40,
            color=data["anomaly"].map({True: "Anomaly", False: "Normal"}),
            color_discrete_map={"Anomaly": "#e4572e", "Normal": "#4c78a8"},
        )
        fig.update_layout(margin=dict(t=10, b=0, l=0, r=0), legend_title="")
        st.plotly_chart(fig, use_container_width=True)

    left2, right2 = st.columns(2)
    with left2:
        st.subheader("Status codes")
        sc = data["status"].value_counts().sort_index().reset_index()
        sc.columns = ["status", "count"]
        fig = px.bar(sc, x="status", y="count")
        fig.update_layout(margin=dict(t=10, b=0, l=0, r=0))
        st.plotly_chart(fig, use_container_width=True)

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
            fig.update_layout(margin=dict(t=10, b=0, l=0, r=0),
                              yaxis=dict(categoryorder="total ascending"))
            st.plotly_chart(fig, use_container_width=True)

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
