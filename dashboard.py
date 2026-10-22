import json
import csv
import io
import html
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
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

    html, body, [class*="css"], .stApp { font-family: 'Inter', sans-serif; }

    .stApp {
        background: radial-gradient(1200px 600px at 10% -10%, #16213e 0%, #0b1020 55%);
        color: #e5e7eb;
    }

    #MainMenu, footer { visibility: hidden; }
    header[data-testid="stHeader"] { background: transparent; }
    .block-container { padding-top: 2rem; max-width: 1400px; }

    section[data-testid="stSidebar"] {
        background-color: #0f172a;
        border-right: 1px solid #1f2a40;
    }

    /* Header */
    .page-title { font-size: 30px; font-weight: 700; color: #f9fafb; margin: 0; }
    .subtitle { color: #9ca3af; font-size: 14px; margin-top: 4px; }

    /* KPI cards */
    .kpi-card {
        background: linear-gradient(145deg, #151f33, #111827);
        border: 1px solid #263247;
        border-top: 3px solid #3b82f6;
        border-radius: 14px;
        padding: 18px 20px;
        height: 118px;
    }
    .kpi-label {
        color: #9ca3af; font-size: 11px; font-weight: 600;
        letter-spacing: .08em; text-transform: uppercase;
    }
    .kpi-value { color: #f9fafb; font-size: 30px; font-weight: 700; margin-top: 6px; }
    .kpi-sub { color: #6b7280; font-size: 12px; margin-top: 2px; }

    /* Severity badge */
    .badge {
        display: inline-block; padding: 2px 10px; border-radius: 999px;
        font-size: 11px; font-weight: 600; letter-spacing: .05em;
        border: 1px solid transparent;
    }

    /* Finding cards */
    .finding-card {
        background: #111827;
        border: 1px solid #263247;
        border-left: 4px solid #3b82f6;
        border-radius: 10px;
        padding: 14px 18px;
        margin-bottom: 10px;
    }
    .finding-title { color: #f9fafb; font-weight: 600; font-size: 15px; margin: 6px 0 2px; }
    .finding-resource { color: #9ca3af; font-size: 12.5px; font-family: monospace; }

    .section-title { font-size: 18px; font-weight: 600; color: #f9fafb; margin: 8px 0 4px; }

    div[data-testid="stExpander"] {
        border: 1px solid #263247;
        border-radius: 10px;
        background-color: #111827;
    }

    div[data-testid="stDownloadButton"] button,
    div[data-testid="stButton"] button {
        border-radius: 10px;
        border: 1px solid #263247;
        font-weight: 600;
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

st.markdown(
    '<p class="page-title">🛡️ Cloud Security Center</p>'
    '<p class="subtitle">Monitor security posture, identify risks, '
    'and review remediation recommendations.</p>',
    unsafe_allow_html=True
)
st.write("")

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

def badge(severity):
    color = severity_colors.get(severity, "#9ca3af")
    return (
        f"<span class='badge' style='color:{color};"
        f"background:{color}22;border-color:{color}55'>{severity}</span>"
    )


def kpi_card(label, value, sub="", accent="#3b82f6"):
    return (
        f"<div class='kpi-card' style='border-top-color:{accent}'>"
        f"<div class='kpi-label'>{label}</div>"
        f"<div class='kpi-value'>{value}</div>"
        f"<div class='kpi-sub'>{sub}</div>"
        f"</div>"
    )

# ---------------- OVERVIEW ----------------

if page == "Overview":

    st.markdown('<p class="section-title">Security Posture</p>', unsafe_allow_html=True)

    if score >= 75:
        score_color = "#22c55e"
    elif score >= 50:
        score_color = "#eab308"
    else:
        score_color = "#ef4444"

    critical_high = summary.get("CRITICAL", 0) + summary.get("HIGH", 0)
    scan_ok = not scan_errors

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.markdown(kpi_card("Security Score", f"{score}/100", "Project-defined score", score_color), unsafe_allow_html=True)
    c2.markdown(kpi_card("Rating", rating, "Overall posture", score_color), unsafe_allow_html=True)
    c3.markdown(kpi_card("Total Findings", total, "Across all checks", "#3b82f6"), unsafe_allow_html=True)
    c4.markdown(kpi_card("Critical + High", critical_high, "Needs priority action", "#ef4444" if critical_high else "#22c55e"), unsafe_allow_html=True)
    c5.markdown(kpi_card("Scan Status", report.get("scan_status", "UNKNOWN"), "All checks passed" if scan_ok else "Some checks failed", "#22c55e" if scan_ok else "#eab308"), unsafe_allow_html=True)

    st.write("")

    left, right = st.columns([1, 1.5])

    with left:
        st.markdown("### Overall Security Score")

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
                        {"range": [0, 50],   "color": "#3b1d24"},
                        {"range": [50, 75],  "color": "#3a3320"},
                        {"range": [75, 100], "color": "#1b3a2b"}
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

        fig = go.Figure(
            go.Pie(
                labels=severity_order,
                values=[summary.get(level, 0) for level in severity_order],
                hole=0.65,
                sort=False,
                textinfo="value",
                marker=dict(
                    colors=[severity_colors[l] for l in severity_order],
                    line=dict(color="#0b1020", width=3)
                )
            )
        )

        fig.update_layout(
            height=300,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font={"color": "#e5e7eb"},
            legend=dict(orientation="h", y=-0.1),
            margin=dict(l=10, r=10, t=20, b=10),
            annotations=[dict(
                text=f"<b>{total}</b><br>findings",
                x=0.5, y=0.5, showarrow=False,
                font=dict(size=18, color="#f9fafb")
            )]
        )

        st.plotly_chart(fig, use_container_width=True)

    st.divider()

    st.markdown("### Latest Security Findings")

    if findings:
        top_findings = sorted(
        findings,
        key=lambda f: severity_order.index(f.get("severity"))
        if f.get("severity") in severity_order else 99
    )[:5]

    for finding in top_findings:
        severity = finding.get("severity", "UNKNOWN")
        color = severity_colors.get(severity, "#9ca3af")

        st.markdown(
            f"<div class='finding-card' style='border-left-color:{color}'>"
            f"{badge(severity)}"
            f"<div class='finding-title'>{html.escape(finding.get('check', 'Unnamed finding'))}</div>"
            f"<div class='finding-resource'>{html.escape(str(finding.get('resource', 'Unknown')))}</div>"
            f"</div>",
            unsafe_allow_html=True
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

    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

    for finding in filtered:
        severity = finding.get("severity", "UNKNOWN")

        with st.expander(
            f"{icons.get(severity, '⚪')}  {finding.get('check', 'Unnamed finding')}  ·  {severity}"
        ):
            st.markdown(badge(severity), unsafe_allow_html=True)

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