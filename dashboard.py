
import re
import ipaddress
import streamlit as st
import pandas as pd
from pathlib import Path

# =====================================================
# PROJECT CONFIGURATION
# =====================================================

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"

st.set_page_config(
    page_title="SOC Email Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# =====================================================
# DASHBOARD HEADER
# =====================================================

st.title("🛡️ SOC Phishing Email Investigation")
st.caption(
    "Email Threat Detection | Incident Monitoring | IOC Analysis"
)

st.divider()


# =====================================================
# FIELD EXTRACTION
# =====================================================

def extract_field(content, field, default="N/A"):

    pattern = rf"(?mi)^\s*{re.escape(field)}\s*:\s*(.*?)\s*$"

    match = re.search(pattern, content)

    if match:
        value = match.group(1).strip()
        return value if value else default

    return default


# =====================================================
# SECTION EXTRACTION
# =====================================================

SECTION_HEADINGS = [
    "EMAIL DETAILS",
    "EXTRACTED URLS",
    "INDICATORS OF COMPROMISE",
    "URL DOMAINS",
    "IP ADDRESSES",
    "EMAIL AUTHENTICATION",
    "SECURITY FINDINGS",
    "THREAT ASSESSMENT",
    "ANALYST RECOMMENDATION",
    "FINAL THREAT ASSESSMENT"
]


def extract_section(content, heading):

    lines = content.splitlines()
    collecting = False
    results = []

    for line in lines:

        stripped = line.strip()

        if re.fullmatch(
            rf"{re.escape(heading)}\s*:?|{re.escape(heading)}",
            stripped,
            re.IGNORECASE
        ):
            collecting = True
            continue

        if not collecting:
            continue

        # Stop at the next known section heading
        if any(
            re.fullmatch(
                rf"{re.escape(section)}\s*:?",
                stripped,
                re.IGNORECASE
            )
            for section in SECTION_HEADINGS
            if section.lower() != heading.lower()
        ):
            break

        # Ignore empty lines and separator lines
        if not stripped or re.fullmatch(r"[-=_]{3,}", stripped):
            continue

        value = stripped.lstrip("-*• ").strip()

        if value.lower() in [
            "none",
            "n/a",
            "not available",
            "no url domains found",
            "no ip addresses found"
        ]:
            continue

        results.append(value)

    return results


# =====================================================
# VALIDATE AND EXTRACT IP ADDRESSES
# =====================================================

def extract_valid_ips(content):

    raw_ips = extract_section(
        content,
        "IP ADDRESSES"
    )

    valid_ips = []

    for item in raw_ips:

        # Extract possible IPv4 or IPv6 addresses
        candidates = re.findall(
            r"(?<![\w:.])(?:\d{1,3}\.){3}\d{1,3}(?![\w:.])|"
            r"(?<![\w:])[0-9a-fA-F:]{2,}(?![\w:])",
            item
        )

        for candidate in candidates:

            try:
                validated_ip = str(
                    ipaddress.ip_address(candidate)
                )

                if validated_ip not in valid_ips:
                    valid_ips.append(validated_ip)

            except ValueError:
                continue

    return valid_ips


# =====================================================
# RISK SCORE EXTRACTION
# =====================================================

def extract_score(content):

    score_text = extract_field(
        content,
        "Risk Score",
        "0/100"
    )

    match = re.search(
        r"(\d{1,3})\s*/\s*100",
        score_text
    )

    if match:
        return min(100, int(match.group(1)))

    match = re.search(r"\b(\d{1,3})\b", score_text)

    if match:
        return min(100, int(match.group(1)))

    return 0


# =====================================================
# THREAT LEVEL EXTRACTION
# =====================================================

def extract_risk(content, score):

    risk = extract_field(
        content,
        "Risk Level",
        "UNKNOWN"
    ).upper()

    if risk not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:

        if score >= 75:
            return "CRITICAL"

        elif score >= 50:
            return "HIGH"

        elif score >= 25:
            return "MEDIUM"

        else:
            return "LOW"

    return risk


# =====================================================
# LOAD INVESTIGATION REPORTS
# =====================================================

def load_reports():

    reports = []

    if not OUTPUT_DIR.exists():
        return reports

    report_files = sorted(
        OUTPUT_DIR.glob("phishing_report_*.txt"),
        reverse=True
    )

    for file in report_files:

        try:
            content = file.read_text(
                encoding="utf-8",
                errors="replace"
            )

        except OSError:
            continue

        # Email details
        sender = extract_field(content, "Sender")
        recipient = extract_field(content, "Recipient")
        reply_to = extract_field(content, "Reply-To")
        subject = extract_field(content, "Subject")
        date = extract_field(content, "Date")

        # Threat assessment
        score = extract_score(content)
        risk = extract_risk(content, score)

        # Indicators of compromise
        sender_domain = extract_field(
            content,
            "Sender Domain"
        )

        reply_domain = extract_field(
            content,
            "Reply-To Domain"
        )

        # Extract URL domains
        urls = extract_section(
            content,
            "URL DOMAINS"
        )

        # Extract IP addresses with validation
        ips = extract_valid_ips(content)

        # Extract security findings
        findings = extract_section(
            content,
            "SECURITY FINDINGS"
        )

        # Extract analyst recommendation
        recommendations = extract_section(
            content,
            "ANALYST RECOMMENDATION"
        )

        reports.append({

            "filename": file.name,
            "sender": sender,
            "recipient": recipient,
            "reply_to": reply_to,
            "subject": subject,
            "date": date,
            "score": score,
            "risk": risk,
            "sender_domain": sender_domain,
            "reply_domain": reply_domain,
            "urls": urls,
            "ips": ips,
            "findings": findings,
            "recommendations": recommendations,
            "content": content

        })

    return reports


# =====================================================
# LOAD DATA
# =====================================================

reports = load_reports()


# =====================================================
# SECURITY OVERVIEW
# =====================================================

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


# =====================================================
# THREAT DISTRIBUTION
# =====================================================

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


# =====================================================
# INVESTIGATION HISTORY
# =====================================================

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


# =====================================================
# INVESTIGATION TABLE
# =====================================================

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
        pd.DataFrame(table_data),
        use_container_width=True,
        hide_index=True
    )

else:

    st.info(
        "No investigations found for this severity."
    )


# =====================================================
# INVESTIGATION DETAILS
# =====================================================

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

        # ---------------------------------------------
        # EMAIL INFORMATION
        # ---------------------------------------------

        col1, col2 = st.columns(2)

        with col1:

            st.write("**Sender:**", selected_report["sender"])

            st.write(
                "**Recipient:**",
                selected_report["recipient"]
            )

            st.write(
                "**Reply-To:**",
                selected_report["reply_to"]
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

        st.divider()

        # ---------------------------------------------
        # INDICATORS OF COMPROMISE
        # ---------------------------------------------

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

            st.info("No URL domains found.")

        st.write("**IP Addresses**")

        if selected_report["ips"]:

            for ip in selected_report["ips"]:
                st.code(ip)

        else:

            st.info("No valid IP addresses found.")

        st.divider()

        # ---------------------------------------------
        # SECURITY FINDINGS
        # ---------------------------------------------

        st.subheader("🚨 Security Findings")

        if selected_report["findings"]:

            for finding in selected_report["findings"]:
                st.warning(finding)

        else:

            st.success(
                "No security findings recorded in this report."
            )

        st.divider()

        # ---------------------------------------------
        # ANALYST RECOMMENDATION
        # ---------------------------------------------

        st.subheader("🛡️ Analyst Recommendation")

        if selected_report["recommendations"]:

            for recommendation in selected_report["recommendations"]:
                st.info(recommendation)

        else:

            st.write(
                "No analyst recommendation recorded."
            )

        st.divider()

        # ---------------------------------------------
        # COMPLETE SOC INVESTIGATION REPORT
        # ---------------------------------------------

        with st.expander(
            "📄 View Complete SOC Investigation Report"
        ):

            st.text(
                selected_report["content"]
            )

        # ---------------------------------------------
        # DOWNLOAD REPORT
        # ---------------------------------------------

        st.download_button(

            label="⬇️ Download Investigation Report",

            data=selected_report["content"],

            file_name=selected_report["filename"],

            mime="text/plain",

            key="download_selected_report"

        )

else:

    st.warning(
        "No investigation reports available."
    )


# =====================================================
# DASHBOARD FOOTER
# =====================================================

st.divider()

st.caption(
    "SOC Phishing Email Investigation Tool | "
    "Developed using Python and Streamlit"
)
