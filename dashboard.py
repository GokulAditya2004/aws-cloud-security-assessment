import csv
import html
import io
import json
import subprocess
import sys
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

# ---------------- PAGE CONFIG ----------------

st.set_page_config(
    page_title="Sentinel | Cloud Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

REPORT_PATH = Path("reports/security_report.json")

# ---------------- DESIGN TOKENS ----------------

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

SEVERITY_COLORS = {
    "CRITICAL": "#f43f5e",
    "HIGH": "#fb923c",
    "MEDIUM": "#facc15",
    "LOW": "#60a5fa",
}

SEVERITY_ICONS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}

ACCENT = "#2dd4bf"
GOOD = "#34d399"
WARN = "#facc15"
BAD = "#f43f5e"
MUTED = "#8b9ab3"
TEXT = "#e6edf7"
FONT = "IBM Plex Sans, sans-serif"

# ---------------- STYLING ----------------

st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

    :root {
        --bg: #0a0f1a;
        --surface: #101827;
        --raised: #162033;
        --line: #223049;
        --text: #e6edf7;
        --muted: #8b9ab3;
        --accent: #2dd4bf;
    }

    html, body, [class*="css"], .stApp, button, input, textarea {
        font-family: 'IBM Plex Sans', sans-serif;
    }

    .stApp {
        background:
            radial-gradient(900px 500px at 100% -10%, rgba(45, 212, 191, 0.07), transparent 60%),
            radial-gradient(900px 500px at 0% -10%, rgba(96, 165, 250, 0.07), transparent 60%),
            var(--bg);
        color: var(--text);
    }

    #MainMenu, footer { visibility: hidden; }
    header[data-testid="stHeader"] { background: transparent; }
    .block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1400px; }

    h1, h2, h3, h4 { color: var(--text); letter-spacing: -0.01em; }

    /* ---------- Sidebar ---------- */
    section[data-testid="stSidebar"] {
        background: var(--surface);
        border-right: 1px solid var(--line);
    }
    .brand { display: flex; align-items: center; gap: 12px; padding: 6px 0 4px; }
    .brand-mark {
        width: 38px; height: 38px; border-radius: 10px;
        display: flex; align-items: center; justify-content: center;
        font-size: 20px;
        background: linear-gradient(135deg, rgba(45,212,191,.25), rgba(96,165,250,.25));
        border: 1px solid rgba(45,212,191,.45);
    }
    .brand-name { font-size: 19px; font-weight: 700; color: var(--text); line-height: 1.1; }
    .brand-tag { font-size: 12px; color: var(--muted); }
    .side-label { font-size: 12px; font-weight: 600; color: var(--muted); margin: 6px 0 6px; }
    .side-meta { font-size: 12px; color: var(--muted); line-height: 1.7; }
    .side-meta b { color: var(--text); font-weight: 500; }

    /* Navigation radio styled as menu */
    section[data-testid="stSidebar"] div[role="radiogroup"] { gap: 4px; }
    section[data-testid="stSidebar"] div[role="radiogroup"] label {
        padding: 9px 12px;
        border-radius: 10px;
        border: 1px solid transparent;
        width: 100%;
        cursor: pointer;
        transition: background .15s ease, border-color .15s ease;
    }
    section[data-testid="stSidebar"] div[role="radiogroup"] label > div:first-child { display: none; }
    section[data-testid="stSidebar"] div[role="radiogroup"] label:hover { background: var(--raised); }
    section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) {
        background: rgba(45, 212, 191, 0.10);
        border-color: rgba(45, 212, 191, 0.40);
    }
    section[data-testid="stSidebar"] div[role="radiogroup"] label:has(input:checked) p {
        color: var(--accent); font-weight: 600;
    }

    /* ---------- Page header ---------- */
    .hero { display: flex; justify-content: space-between; align-items: flex-end; gap: 24px; flex-wrap: wrap; }
    .page-title { font-size: 30px; font-weight: 700; color: var(--text); margin: 0; letter-spacing: -0.02em; }
    .subtitle { color: var(--muted); font-size: 14px; margin: 4px 0 0; max-width: 560px; }
    .chips { display: flex; gap: 8px; flex-wrap: wrap; }
    .chip {
        display: inline-flex; align-items: center; gap: 8px;
        padding: 6px 12px; border-radius: 999px;
        background: var(--surface); border: 1px solid var(--line);
        font-size: 12.5px; color: var(--muted);
    }
    .chip b { color: var(--text); font-weight: 500; font-family: 'IBM Plex Mono', monospace; font-size: 12px; }
    .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }

    /* ---------- KPI cards ---------- */
    .kpi {
        background: var(--surface);
        border: 1px solid var(--line);
        border-radius: 14px;
        padding: 18px 20px 16px;
        height: 132px;
        position: relative;
        overflow: hidden;
    }
    .kpi::before {
        content: ""; position: absolute; left: 0; top: 0; bottom: 0; width: 4px;
        background: var(--kpi-accent, var(--accent));
    }
    .kpi-label { color: var(--muted); font-size: 13px; font-weight: 500; }
    .kpi-value { color: var(--text); font-size: 34px; font-weight: 700; margin-top: 6px; letter-spacing: -0.02em; line-height: 1.1; }
    .kpi-value small { font-size: 16px; color: var(--muted); font-weight: 500; margin-left: 2px; }
    .kpi-sub { color: var(--muted); font-size: 12.5px; margin-top: 8px; }

    /* ---------- Panels ---------- */
    .panel-title { font-size: 16px; font-weight: 600; color: var(--text); margin: 0 0 2px; }
    .panel-sub { font-size: 12.5px; color: var(--muted); margin: 0 0 8px; }
    .section-title { font-size: 18px; font-weight: 600; color: var(--text); margin: 18px 0 10px; }

    div[data-testid="stVerticalBlockBorderWrapper"] { border-radius: 14px; }

    /* ---------- Severity legend rows ---------- */
    .sev-row { display: flex; align-items: center; gap: 12px; margin: 10px 0; font-size: 13.5px; }
    .sev-name { width: 74px; color: var(--text); font-weight: 500; }
    .sev-track { flex: 1; height: 8px; border-radius: 99px; background: var(--raised); overflow: hidden; }
    .sev-fill { height: 100%; border-radius: 99px; }
    .sev-count { width: 28px; text-align: right; color: var(--text); font-weight: 600; font-variant-numeric: tabular-nums; }

    /* ---------- Badge ---------- */
    .badge {
        display: inline-block; padding: 2px 10px; border-radius: 999px;
        font-size: 11.5px; font-weight: 600; letter-spacing: .03em;
        border: 1px solid transparent;
    }

    /* ---------- Finding cards ---------- */
    .finding-card {
        background: var(--surface);
        border: 1px solid var(--line);
        border-left: 4px solid var(--accent);
        border-radius: 12px;
        padding: 14px 18px;
        margin-bottom: 10px;
    }
    .finding-top { display: flex; align-items: center; gap: 10px; }
    .finding-title { color: var(--text); font-weight: 600; font-size: 15px; margin: 8px 0 4px; }
    .finding-risk { color: var(--muted); font-size: 13px; margin: 0 0 8px; line-height: 1.5; }
    .code {
        font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: #b6c4dc;
        background: var(--raised); border: 1px solid var(--line);
        padding: 3px 8px; border-radius: 6px; word-break: break-all; display: inline-block;
    }

    /* ---------- Finding detail (in expanders) ---------- */
    .detail-label { color: var(--muted); font-size: 12.5px; font-weight: 600; margin: 14px 0 4px; }
    .detail-text { color: var(--text); font-size: 14px; line-height: 1.6; }
    .callout {
        margin-top: 14px; padding: 12px 14px; border-radius: 10px;
        background: rgba(45, 212, 191, 0.08);
        border: 1px solid rgba(45, 212, 191, 0.35);
        color: var(--text); font-size: 14px; line-height: 1.6;
    }
    .callout b { color: var(--accent); }

    div[data-testid="stExpander"] {
        border: 1px solid var(--line);
        border-radius: 12px;
        background: var(--surface);
    }

    /* ---------- Buttons & inputs ---------- */
    div[data-testid="stButton"] button,
    div[data-testid="stDownloadButton"] button {
        border-radius: 10px;
        border: 1px solid var(--line);
        font-weight: 600;
        transition: border-color .15s ease, color .15s ease;
    }
    div[data-testid="stButton"] button:hover,
    div[data-testid="stDownloadButton"] button:hover {
        border-color: var(--accent);
        color: var(--accent);
    }
    button:focus-visible, input:focus-visible, label:focus-visible {
        outline: 2px solid var(--accent) !important;
        outline-offset: 2px;
    }

    hr { border-color: var(--line) !important; }
</style>
""",
    unsafe_allow_html=True,
)


# ---------------- HELPERS ----------------

def esc(value):
    return html.escape(str(value))


def severity_rank(severity):
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else 99


def badge(severity):
    color = SEVERITY_COLORS.get(severity, MUTED)
    return (
        f"<span class='badge' style='color:{color};"
        f"background:{color}1f;border-color:{color}66'>{esc(severity)}</span>"
    )


def kpi_card(label, value, sub="", accent=ACCENT, unit=""):
    unit_html = f"<small>{esc(unit)}</small>" if unit else ""
    return (
        f"<div class='kpi' style='--kpi-accent:{accent}'>"
        f"<div class='kpi-label'>{esc(label)}</div>"
        f"<div class='kpi-value'>{esc(value)}{unit_html}</div>"
        f"<div class='kpi-sub'>{esc(sub)}</div>"
        f"</div>"
    )


def chip(label, value, color=None):
    dot = f"<span class='dot' style='background:{color}'></span>" if color else ""
    return f"<span class='chip'>{dot}{esc(label)} <b>{esc(value)}</b></span>"


def finding_card(finding, show_risk=False):
    severity = finding.get("severity", "UNKNOWN")
    color = SEVERITY_COLORS.get(severity, MUTED)
    risk_html = ""
    if show_risk and finding.get("risk"):
        risk_html = f"<p class='finding-risk'>{esc(finding['risk'])}</p>"
    return (
        f"<div class='finding-card' style='border-left-color:{color}'>"
        f"<div class='finding-top'>{badge(severity)}</div>"
        f"<div class='finding-title'>{esc(finding.get('check', 'Unnamed finding'))}</div>"
        f"{risk_html}"
        f"<span class='code'>{esc(finding.get('resource', 'Unknown'))}</span>"
        f"</div>"
    )


def style_figure(fig, height):
    fig.update_layout(
        height=height,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family=FONT, color=TEXT),
        margin=dict(l=10, r=10, t=10, b=10),
    )
    return fig


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
    st.markdown(
        "<div class='brand'>"
        "<div class='brand-mark'>🛡️</div>"
        "<div><div class='brand-name'>Sentinel</div>"
        "<div class='brand-tag'>Cloud security platform</div></div>"
        "</div>",
        unsafe_allow_html=True,
    )
    st.divider()

    st.markdown("<div class='side-label'>Scan</div>", unsafe_allow_html=True)

    if st.button("🔄 Run security scan", use_container_width=True):
        try:
            with st.spinner("Scanning your AWS environment..."):
                result = subprocess.run(
                    [sys.executable, "scanner.py"],
                    capture_output=True,
                    text=True,
                    timeout=180,
                )

            if result.returncode == 0:
                st.success("Scan completed.")
                st.rerun()
            else:
                st.error("Scan failed.")
                st.code(result.stderr or result.stdout)
        except subprocess.TimeoutExpired:
            st.error("Scan timed out after 180 seconds.")

    if report is not None:
        last_scan = report.get("scan", {}).get("timestamp", "Unknown")
        st.markdown(
            f"<div class='side-meta'>Last scan<br><b>{esc(last_scan)}</b></div>",
            unsafe_allow_html=True,
        )

    st.divider()

    st.markdown("<div class='side-label'>Navigate</div>", unsafe_allow_html=True)
    page = st.radio(
        "Navigation",
        ["Overview", "Security Findings", "Reports"],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown(
        "<div class='side-meta'>AWS security assessment<br>"
        "Scanner: <b>Python + Boto3</b><br>"
        "Dashboard: <b>Streamlit</b></div>",
        unsafe_allow_html=True,
    )


# ---------------- EMPTY STATE ----------------

if report is None:
    st.markdown(
        "<p class='page-title'>Cloud Security Center</p>"
        "<p class='subtitle'>Monitor security posture, identify risks, "
        "and review remediation recommendations.</p>",
        unsafe_allow_html=True,
    )
    st.write("")
    st.warning("No valid security report found. Run a scan to create one.")
    st.code("python scanner.py", language="powershell")
    st.stop()


# ---------------- REPORT DATA ----------------

scan = report.get("scan", {})
summary = report.get("summary", {})
findings = report.get("findings", [])
scan_errors = report.get("errors", [])

score = report.get("security_score", 0)
rating = report.get("security_rating", "UNKNOWN")
scan_status = report.get("scan_status", "UNKNOWN")
total = len(findings)
scan_ok = not scan_errors

critical_high = summary.get("CRITICAL", 0) + summary.get("HIGH", 0)

if score >= 75:
    score_color = GOOD
elif score >= 50:
    score_color = WARN
else:
    score_color = BAD

# ---------------- HEADER ----------------

chips_html = (
    chip("Account", scan.get("account_id", "Unknown"))
    + chip("Last scan", scan.get("timestamp", "Unknown"))
    + chip("Status", scan_status, GOOD if scan_ok else WARN)
)

st.markdown(
    "<div class='hero'><div>"
    "<p class='page-title'>Cloud Security Center</p>"
    "<p class='subtitle'>Monitor security posture, identify risks, "
    "and review remediation recommendations.</p>"
    f"</div><div class='chips'>{chips_html}</div></div>",
    unsafe_allow_html=True,
)
st.write("")

if scan_errors:
    with st.expander(
        f"⚠️ {len(scan_errors)} security check(s) failed. Results may be incomplete.",
        expanded=False,
    ):
        for error in scan_errors:
            st.error(
                f"{error.get('check', 'Unknown check')}: "
                f"{error.get('error', 'Unknown error')}"
            )


# ---------------- OVERVIEW ----------------

if page == "Overview":

    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(
        kpi_card("Security score", score, f"Rated {rating}", score_color, unit="/100"),
        unsafe_allow_html=True,
    )
    c2.markdown(
        kpi_card("Total findings", total, "Across all checks", ACCENT),
        unsafe_allow_html=True,
    )
    c3.markdown(
        kpi_card(
            "Critical and high",
            critical_high,
            "Fix these first" if critical_high else "Nothing urgent",
            BAD if critical_high else GOOD,
        ),
        unsafe_allow_html=True,
    )
    c4.markdown(
        kpi_card(
            "Scan status",
            scan_status,
            "All checks completed" if scan_ok else f"{len(scan_errors)} check(s) failed",
            GOOD if scan_ok else WARN,
        ),
        unsafe_allow_html=True,
    )

    st.write("")

    left, right = st.columns([1, 1.4])

    with left:
        with st.container(border=True):
            st.markdown(
                "<p class='panel-title'>Security score</p>"
                "<p class='panel-sub'>Higher is better</p>",
                unsafe_allow_html=True,
            )

            gauge = go.Figure(
                go.Indicator(
                    mode="gauge+number",
                    value=score,
                    number={"font": {"size": 44, "color": TEXT, "family": FONT}},
                    gauge={
                        "axis": {
                            "range": [0, 100],
                            "tickcolor": MUTED,
                            "tickfont": {"color": MUTED, "size": 11},
                        },
                        "bar": {"color": score_color, "thickness": 0.28},
                        "bgcolor": "rgba(0,0,0,0)",
                        "borderwidth": 0,
                        "steps": [
                            {"range": [0, 50], "color": "rgba(244,63,94,0.16)"},
                            {"range": [50, 75], "color": "rgba(250,204,21,0.14)"},
                            {"range": [75, 100], "color": "rgba(52,211,153,0.16)"},
                        ],
                    },
                )
            )
            style_figure(gauge, 250)
            gauge.update_layout(margin=dict(l=25, r=25, t=20, b=0))
            st.plotly_chart(gauge, use_container_width=True)

            st.caption(
                report.get(
                    "score_method",
                    "Score calculated using project-defined severity penalties.",
                )
            )
            st.caption(
                "This is a project-defined assessment score, "
                "not an official AWS security rating."
            )

    with right:
        with st.container(border=True):
            st.markdown(
                "<p class='panel-title'>Findings by severity</p>"
                "<p class='panel-sub'>How risk is distributed across this scan</p>",
                unsafe_allow_html=True,
            )

            donut_col, legend_col = st.columns([1, 1])

            with donut_col:
                counts = [summary.get(level, 0) for level in SEVERITY_ORDER]
                donut = go.Figure(
                    go.Pie(
                        labels=SEVERITY_ORDER,
                        values=counts if sum(counts) else [1, 0, 0, 0],
                        hole=0.7,
                        sort=False,
                        textinfo="none",
                        hovertemplate="%{label}: %{value}<extra></extra>",
                        marker=dict(
                            colors=[SEVERITY_COLORS[l] for l in SEVERITY_ORDER]
                            if sum(counts)
                            else [SEVERITY_COLORS["LOW"], "#0a0f1a", "#0a0f1a", "#0a0f1a"],
                            line=dict(color="#101827", width=3),
                        ),
                    )
                )
                style_figure(donut, 270)
                donut.update_layout(
                    showlegend=False,
                    annotations=[
                        dict(
                            text=f"<b>{total}</b><br><span style='font-size:12px;color:{MUTED}'>findings</span>",
                            x=0.5,
                            y=0.5,
                            showarrow=False,
                            font=dict(size=30, color=TEXT, family=FONT),
                        )
                    ],
                )
                st.plotly_chart(donut, use_container_width=True)

            with legend_col:
                top = max([summary.get(l, 0) for l in SEVERITY_ORDER] + [1])
                rows = ""
                for level in SEVERITY_ORDER:
                    count = summary.get(level, 0)
                    width = (count / top) * 100
                    color = SEVERITY_COLORS[level]
                    rows += (
                        f"<div class='sev-row'>"
                        f"<span class='sev-name'>{level.title()}</span>"
                        f"<span class='sev-track'><span class='sev-fill' "
                        f"style='display:block;width:{width:.0f}%;background:{color}'></span></span>"
                        f"<span class='sev-count'>{count}</span>"
                        f"</div>"
                    )
                st.markdown("<div style='height:42px'></div>" + rows, unsafe_allow_html=True)

    st.markdown("<p class='section-title'>Fix these first</p>", unsafe_allow_html=True)

    if findings:
        top_findings = sorted(
            findings, key=lambda f: severity_rank(f.get("severity"))
        )[:5]

        for finding in top_findings:
            st.markdown(finding_card(finding, show_risk=True), unsafe_allow_html=True)

        if total > len(top_findings):
            st.caption(
                f"Showing the {len(top_findings)} highest-severity findings. "
                "Open Security Findings to see all "
                f"{total}."
            )
    else:
        st.success("No findings were reported in the latest scan.")


# ---------------- SECURITY FINDINGS ----------------

elif page == "Security Findings":

    st.markdown("<p class='section-title' style='margin-top:0'>Security findings</p>", unsafe_allow_html=True)
    st.caption("Review detected risks and recommended remediation.")

    f1, f2, f3 = st.columns([1.4, 1.4, 1])

    with f1:
        selected_severity = st.multiselect(
            "Filter by severity",
            SEVERITY_ORDER,
            default=SEVERITY_ORDER,
        )

    with f2:
        search_text = st.text_input(
            "Search findings",
            placeholder="Search by check name or resource...",
        )

    with f3:
        sort_by = st.selectbox(
            "Sort by",
            ["Severity (highest first)", "Check name"],
        )

    filtered = [
        finding
        for finding in findings
        if finding.get("severity") in selected_severity
        and search_text.lower()
        in (
            str(finding.get("check", "")) + " " + str(finding.get("resource", ""))
        ).lower()
    ]

    if sort_by == "Check name":
        filtered.sort(key=lambda f: str(f.get("check", "")).lower())
    else:
        filtered.sort(key=lambda f: severity_rank(f.get("severity")))

    st.caption(f"Showing {len(filtered)} of {total} findings")

    if not filtered:
        st.info("No findings match your filters. Clear the search or add more severities.")

    for finding in filtered:
        severity = finding.get("severity", "UNKNOWN")

        with st.expander(
            f"{SEVERITY_ICONS.get(severity, '⚪')}  "
            f"{finding.get('check', 'Unnamed finding')}  ·  {severity}"
        ):
            st.markdown(
                badge(severity)
                + "<div class='detail-label'>Resource</div>"
                f"<span class='code'>{esc(finding.get('resource', 'Unknown'))}</span>"
                "<div class='detail-label'>Risk</div>"
                f"<div class='detail-text'>{esc(finding.get('risk', 'No risk description available.'))}</div>"
                "<div class='callout'><b>Recommended action</b><br>"
                f"{esc(finding.get('recommendation', 'No recommendation available.'))}</div>",
                unsafe_allow_html=True,
            )


# ---------------- REPORTS ----------------

elif page == "Reports":

    st.markdown("<p class='section-title' style='margin-top:0'>Security assessment reports</p>", unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(kpi_card("Security score", score, f"Rated {rating}", score_color, unit="/100"), unsafe_allow_html=True)
    c2.markdown(kpi_card("Total findings", total, "In this report", ACCENT), unsafe_allow_html=True)
    c3.markdown(kpi_card("Critical and high", critical_high, "Priority items", BAD if critical_high else GOOD), unsafe_allow_html=True)
    c4.markdown(kpi_card("Medium and low", summary.get("MEDIUM", 0) + summary.get("LOW", 0), "Lower priority", "#60a5fa"), unsafe_allow_html=True)

    st.write("")

    with st.container(border=True):
        st.markdown(
            "<p class='panel-title'>Scan details</p>"
            "<p class='panel-sub'>Where this report came from</p>",
            unsafe_allow_html=True,
        )
        st.write("**AWS account:**", scan.get("account_id", "Unknown"))
        st.write("**Scan timestamp:**", scan.get("timestamp", "Unknown"))
        st.write("**Security rating:**", rating)

    st.write("")

    col_json, col_csv = st.columns(2)

    with col_json:
        with st.container(border=True):
            st.markdown(
                "<p class='panel-title'>JSON export</p>"
                "<p class='panel-sub'>Full report, including scan details and errors</p>",
                unsafe_allow_html=True,
            )
            report_bytes = json.dumps(report, indent=4).encode("utf-8")
            st.download_button(
                "Download JSON report",
                data=report_bytes,
                file_name="aws_security_report.json",
                mime="application/json",
                use_container_width=True,
            )

    with col_csv:
        with st.container(border=True):
            st.markdown(
                "<p class='panel-title'>CSV export</p>"
                "<p class='panel-sub'>Findings only, ready for a spreadsheet</p>",
                unsafe_allow_html=True,
            )

            csv_buffer = io.StringIO()
            writer = csv.DictWriter(
                csv_buffer,
                fieldnames=["check", "severity", "resource", "risk", "recommendation"],
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerows(findings)

            st.download_button(
                "Download CSV report",
                data=csv_buffer.getvalue(),
                file_name="aws_security_findings.csv",
                mime="text/csv",
                use_container_width=True,
            )

    st.markdown("<p class='section-title'>All findings</p>", unsafe_allow_html=True)

    if findings:
        table_rows = [
            {
                "Severity": f.get("severity", "UNKNOWN"),
                "Check": f.get("check", ""),
                "Resource": f.get("resource", ""),
                "Recommendation": f.get("recommendation", ""),
            }
            for f in sorted(findings, key=lambda f: severity_rank(f.get("severity")))
        ]
        st.dataframe(table_rows, use_container_width=True, hide_index=True)
    else:
        st.success("No findings were reported in the latest scan.")

    st.caption(
        "This report contains the results of the most recent "
        "scan saved by scanner.py"
    )