import json
import csv
import io
from pathlib import Path

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

# ---------------- PAGE CONFIG ----------------

st.set_page_config(
    page_title="Sentinel | Cloud Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

REPORT_PATH = Path("reports/security_report.json")

# ---------------- STYLING ----------------

st.markdown("""
<style>
    .stApp {
        background-color: #0b1020;
        color: #e5e7eb;
    }

    section[data-testid="stSidebar"] {
        background-color: #111827;
        border-right: 1px solid #263247;
    }

    div[data-testid="stMetric"] {
        background: linear-gradient(145deg, #151f33, #111827);
        border: 1px solid #263247;
        padding: 20px;
        border-radius: 14px;
    }

    div[data-testid="stMetricLabel"] {
        color: #9ca3af;
    }

    div[data-testid="stMetricValue"] {
        color: #f9fafb;
    }

    .subtitle {
        color: #9ca3af;
        font-size: 14px;
    }

    .section-title {
        font-size: 21px;
        font-weight: 600;
        margin-top: 15px;
    }

    div[data-testid="stExpander"] {
        border: 1px solid #263247;
        border-radius: 10px;
        background-color: #111827;
    }
</style>
""", unsafe_allow_html=True)


# ---------------- LOAD REPORT ----------------

def load_report():
    if not REPORT_PATH.exists():
        return None

    try:
        with REPORT_PATH.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return None


report = load_report()


# ---------------- SIDEBAR ----------------

with st.sidebar:
    st.markdown("# 🛡️ SENTINEL")
    st.divider()

    st.markdown("### Scan Controls")

    if st.button("🔄 Run Security Scan", use_container_width=True):
        import subprocess
        import sys

        with st.spinner("Scanning your AWS environment..."):
            result = subprocess.run(
                [sys.executable, "scanner.py"],
                capture_output=True,
                text=True,
                timeout=180
            )

        if result.returncode == 0:
            st.success("Security scan completed!")
            st.rerun()
        else:
            st.error("Security scan failed.")
            st.code(result.stderr or result.stdout)
    st.caption("CLOUD SECURITY PLATFORM")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        ["Overview", "Security Findings", "Reports"],
        label_visibility="visible"
    )

    st.divider()
    st.caption("AWS SECURITY ASSESSMENT")
    st.caption("Scanner: Python + Boto3")
    st.caption("Dashboard: Streamlit")


# ---------------- HEADER ----------------

st.title("Cloud Security Center")
st.markdown(
    '<p class="subtitle">Monitor security posture, identify risks, '
    'and review remediation recommendations.</p>',
    unsafe_allow_html=True
)

if report is None:
    st.warning("No valid security report found.")
    st.code("python scanner.py", language="powershell")
    st.stop()


scan = report.get("scan", {})
summary = report.get("summary", {})
findings = report.get("findings", [])
scan_errors = report.get("errors", [])

if scan_errors:
    st.warning("Some security checks failed. Results may be incomplete.")

    for error in scan_errors:
        st.error(
            f"{error.get('check', 'Unknown check')}: "
            f"{error.get('error', 'Unknown error')}"
        )

score = report.get("security_score", 0)
rating = report.get("security_rating", "UNKNOWN")
total = len(findings)

severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

severity_colors = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#3b82f6"
}


# ---------------- OVERVIEW ----------------

if page == "Overview":

    st.markdown("### Security Posture")

    c1, c2, c3, c4, c5 = st.columns(5)

    c1.metric("Security Score", f"{score}/100")
    c2.metric("Security Rating", rating)
    c3.metric("Total Findings", total)
    c4.metric("High Risk", summary.get("HIGH", 0))
    c5.metric(
        "Scan Status",
        report.get("scan_status", "UNKNOWN")
    )

    st.write("")

    left, right = st.columns([1, 1.5])

    with left:
        st.markdown("### Overall Security Score")

        if score >= 75:
            score_color = "#22c55e"
        elif score >= 50:
            score_color = "#eab308"
        else:
            score_color = "#ef4444"

        gauge = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=score,
                number={
                    "suffix": "/100",
                    "font": {"size": 34, "color": "#f9fafb"}
                },
                gauge={
                    "axis": {
                        "range": [0, 100],
                        "tickcolor": "#9ca3af"
                    },
                    "bar": {"color": score_color},
                    "bgcolor": "#111827",
                    "borderwidth": 0,
                    "steps": [
                        {"range": [0, 50], "color": "#263247"},
                        {"range": [50, 75], "color": "#263247"},
                        {"range": [75, 100], "color": "#263247"}
                    ]
                }
            )
        )

        gauge.update_layout(
            height=270,
            margin=dict(l=25, r=25, t=20, b=10),
            paper_bgcolor="rgba(0,0,0,0)",
            font={"color": "#f9fafb"}
        )

        st.plotly_chart(gauge, use_container_width=True)

        st.caption(
            report.get(
                "score_method",
                "Score calculated using project-defined severity penalties."
            )
        )

        st.caption(
            "This is a project-defined assessment score, "
            "not an official AWS security rating."
        )

    with right:
        st.markdown("### Findings by Severity")

        chart_data = {
            "Severity": severity_order,
            "Count": [
                summary.get(level, 0)
                for level in severity_order
            ]
        }

        fig = px.bar(
            chart_data,
            x="Severity",
            y="Count",
            color="Severity",
            text="Count",
            color_discrete_map=severity_colors,
            category_orders={"Severity": severity_order}
        )

        fig.update_layout(
            template="plotly_dark",
            height=300,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            showlegend=False,
            margin=dict(l=10, r=10, t=20, b=10)
        )

        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    st.markdown("### Latest Security Findings")

    if findings:
        for finding in findings[:4]:
            severity = finding.get("severity", "UNKNOWN")
            color = severity_colors.get(severity, "#9ca3af")

            st.markdown(
                f"**<span style='color:{color}'>"
                f"{severity}</span>** — "
                f"{finding.get('check', 'Unnamed finding')}",
                unsafe_allow_html=True
            )

            st.caption(
                f"Resource: {finding.get('resource', 'Unknown')}"
            )
    else:
        st.success("No findings were reported in the latest scan.")

    st.divider()

    st.markdown("### Scan Information")

    st.write("**AWS Account:**", scan.get("account_id", "Unknown"))
    st.write("**Last Scan:**", scan.get("timestamp", "Unknown"))


# ---------------- SECURITY FINDINGS ----------------

elif page == "Security Findings":

    st.subheader("Security Findings")
    st.caption("Review detected risks and recommended remediation.")

    selected_severity = st.multiselect(
        "Filter by severity",
        severity_order,
        default=severity_order
    )

    search_text = st.text_input(
        "Search findings",
        placeholder="Search by check name or resource..."
    )

    filtered = [
        finding for finding in findings
        if finding.get("severity") in selected_severity
        and search_text.lower() in (
            finding.get("check", "") + " "
            + finding.get("resource", "")
        ).lower()
    ]

    st.caption(f"Showing {len(filtered)} of {total} findings")

    if not filtered:
        st.info("No findings match your filters.")

    for index, finding in enumerate(filtered, start=1):
        severity = finding.get("severity", "UNKNOWN")
        color = severity_colors.get(severity, "#9ca3af")

        with st.expander(
            f"{index}. {finding.get('check', 'Unnamed finding')} "
            f"— {severity}"
        ):
            st.markdown(
                f"**Severity:** "
                f"<span style='color:{color}'>{severity}</span>",
                unsafe_allow_html=True
            )

            st.write(
                "**Resource:**",
                finding.get("resource", "Unknown")
            )

            st.write(
                "**Risk:**",
                finding.get("risk", "No risk description available.")
            )

            st.info(
                "Recommended action: "
                + finding.get(
                    "recommendation",
                    "No recommendation available."
                )
            )


# ---------------- REPORTS ----------------

elif page == "Reports":

    st.subheader("Security Assessment Reports")

    st.write("**AWS Account:**", scan.get("account_id", "Unknown"))
    st.write("**Scan Timestamp:**", scan.get("timestamp", "Unknown"))
    st.write("**Total Findings:**", total)
    st.write("**Security Score:**", f"{score}/100")
    st.write("**Security Rating:**", rating)

    st.divider()
    st.markdown("### Export Findings to JSON")
    report_bytes = json.dumps(
        report,
        indent=4
    ).encode("utf-8")

    st.download_button(
        "Download JSON Report",
        data=report_bytes,
        file_name="aws_security_report.json",
        mime="application/json"
    )

    st.divider()

    st.markdown("### Export Findings to CSV")

    csv_buffer = io.StringIO()

    fieldnames = [
        "check",
        "severity",
        "resource",
        "risk",
        "recommendation"
    ]

    writer = csv.DictWriter(
        csv_buffer,
        fieldnames=fieldnames,
        extrasaction="ignore"
    )

    writer.writeheader()
    writer.writerows(findings)

    st.download_button(
        label="📊 Download CSV Report",
        data=csv_buffer.getvalue(),
        file_name="aws_security_findings.csv",
        mime="text/csv"
    )

    st.caption(
        "This report contains the results of the most recent "
        "scan saved by scanner.py"
    )