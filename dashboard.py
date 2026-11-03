
import re
import streamlit as st
import pandas as pd
from pathlib import Path

# ==========================================
# PROJECT CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"

st.set_page_config(
    page_title="SOC Email Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================
# DASHBOARD HEADER
# ==========================================

st.title("🛡️ SOC Phishing Email Investigation")
st.caption(
    "Email Threat Detection | Incident Monitoring | IOC Analysis"
)

st.divider()


# ==========================================
# REPORT EXTRACTION FUNCTION
# ==========================================

def extract_field(content, field, default="N/A"):

    pattern = (
        rf"(?m)^{re.escape(field)}:[ \t]*(.*)$"
    )

    match = re.search(
        pattern,
        content
    )

    if match:
        value = match.group(1).strip()
        return value if value else default

    return default


# ==========================================
# LOAD INVESTIGATION REPORTS
# ==========================================

def load_reports():

    reports = []

    if not OUTPUT_DIR.exists():
        return reports

    report_files = sorted(
        OUTPUT_DIR.glob("phishing_report_*.txt"),
        reverse=True
    )

    for file in report_files:

        content = file.read_text(
            encoding="utf-8"
        )

        score_text = extract_field(
            content,
            "Risk Score",
            "0/100"
        )

        risk_text = extract_field(
            content,
            "Risk Level",
            "UNKNOWN"
        )

        # Extract numerical risk score

        score_match = re.search(
            r"\d+",
            score_text
        )

        score = (
            int(score_match.group())
            if score_match else 0
        )

        # Extract email details

        sender = extract_field(
            content,
            "Sender"
        )

        recipient = extract_field(
            content,
            "Recipient"
        )

        subject = extract_field(
            content,
            "Subject"
        )

        date = extract_field(
            content,
            "Date"
        )

        sender_domain = extract_field(
            content,
            "Sender Domain"
        )

        reply_domain = extract_field(
            content,
            "Reply-To Domain"
        )

        # Extract IOC sections

        url_section = re.search(
            r"(?ms)^URL Domains\s*\n-+\s*\n(.*?)(?=^IP Addresses)",
            content
        )

        ip_section = re.search(
            r"(?ms)^IP Addresses\s*\n-+\s*\n(.*?)(?=^SECURITY FINDINGS)",
            content
        )

        urls = []

        if url_section:

            urls = re.findall(
                r"(?m)^-\s*(.+)$",
                url_section.group(1)
            )

        ips = []

        if ip_section:

            ips = re.findall(
                r"(?m)^-\s*(.+)$",
                ip_section.group(1)
            )

        reports.append({

            "filename": file.name,
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "date": date,
            "score": score,
            "risk": risk_text.upper(),
            "sender_domain": sender_domain,
            "reply_domain": reply_domain,
            "urls": urls,
            "ips": ips,
            "content": content

        })

    return reports


# ==========================================
# LOAD DATA
# ==========================================

reports = load_reports()


# ==========================================
# SECURITY OVERVIEW
# ==========================================

st.subheader("📊 Security Overview")

total = len(reports)

critical = sum(
    r["risk"] == "CRITICAL" for r in reports
)

high = sum(
    r["risk"] == "HIGH" for r in reports
)

medium = sum(
    r["risk"] == "MEDIUM" for r in reports
)

low = sum(
    r["risk"] == "LOW" for r in reports
)

c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("Total Investigations", total)
c2.metric("Critical", critical)
c3.metric("High", high)
c4.metric("Medium", medium)
c5.metric("Low", low)

st.divider()


# ==========================================
# THREAT DISTRIBUTION
# ==========================================

st.subheader("📈 Threat Distribution")

chart_data = pd.DataFrame({

    "Severity": [
        "Critical",
        "High",
        "Medium",
        "Low"
    ],

    "Investigations": [
        critical,
        high,
        medium,
        low
    ]

})

st.bar_chart(
    chart_data,
    x="Severity",
    y="Investigations"
)

st.divider()


# ==========================================
# INVESTIGATION HISTORY
# ==========================================

st.subheader("🔍 Email Investigation History")

severity_filter = st.selectbox(

    "Filter by threat severity",

    [
        "ALL",
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW"
    ]

)

filtered_reports = reports

if severity_filter != "ALL":

    filtered_reports = [

        r for r in reports
        if r["risk"] == severity_filter

    ]


# ==========================================
# INVESTIGATION TABLE
# ==========================================

if filtered_reports:

    table_data = []

    for r in filtered_reports:

        table_data.append({

            "Email Sender": r["sender"],
            "Subject": r["subject"],
            "Risk Score": f'{r["score"]}/100',
            "Threat Level": r["risk"],
            "Report": r["filename"]

        })

    st.dataframe(
        table_data,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No investigations found for this severity."
    )


# ==========================================
# INVESTIGATION DETAILS
# ==========================================

st.divider()

st.subheader("📧 Investigation Details")

if filtered_reports:

    selected_report = st.selectbox(

        "Select an email investigation",

        filtered_reports,

        format_func=lambda r: r["filename"],

        key="selected_investigation"

    )

    if selected_report:

        col1, col2 = st.columns(2)

        with col1:

            st.write(
                "**Sender:**",
                selected_report["sender"]
            )

            st.write(
                "**Recipient:**",
                selected_report["recipient"]
            )

            st.write(
                "**Subject:**",
                selected_report["subject"]
            )

            st.write(
                "**Date:**",
                selected_report["date"]
            )

        with col2:

            st.metric(
                "Risk Score",
                f'{selected_report["score"]}/100'
            )

            st.write(
                "**Threat Level:**",
                selected_report["risk"]
            )

        # ==================================
        # IOC VISUALIZATION
        # ==================================

        st.subheader("🎯 Indicators of Compromise")

        i1, i2, i3 = st.columns(3)

        i1.metric(
            "Sender Domain",
            selected_report["sender_domain"]
        )

        i2.metric(
            "URL Domains",
            len(selected_report["urls"])
        )

        i3.metric(
            "IP Addresses",
            len(selected_report["ips"])
        )

        st.write("**Sender Domain**")

        st.code(
            selected_report["sender_domain"]
        )

        st.write("**Reply-To Domain**")

        st.code(
            selected_report["reply_domain"]
        )

        st.write("**URL Domains**")

        if selected_report["urls"]:

            for domain in selected_report["urls"]:
                st.code(domain)

        else:

            st.write("No URL domains found.")

        st.write("**IP Addresses**")

        if selected_report["ips"]:

            for ip in selected_report["ips"]:
                st.code(ip)

        else:

            st.write("No IP addresses found.")

        # ==================================
        # FULL INVESTIGATION REPORT
        # ==================================

        with st.expander(
            "View Complete SOC Investigation Report"
        ):

            st.text(
                selected_report["content"]
            )

        # ==================================
        # DOWNLOAD REPORT
        # ==================================

        st.download_button(

            label="⬇️ Download Investigation Report",

            data=selected_report["content"],

            file_name=selected_report["filename"],

            mime="text/plain"

        )

else:

    st.warning(
        "No investigation reports available."
    )


# ==========================================
# DASHBOARD FOOTER
# ==========================================

st.divider()

st.caption(
    "SOC Phishing Email Investigation Tool | "
    "Developed using Python and Streamlit"
)
