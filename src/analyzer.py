
import re
import sys
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse


# ==========================================
# PROJECT CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent

DEFAULT_EMAIL = BASE_DIR / "samples" / "suspicious_email.eml"

OUTPUT_DIR = BASE_DIR / "output"


# ==========================================
# EMAIL ANALYSIS FUNCTION
# ==========================================

def analyze_email(file_path):

    # Read and parse email
    with open(file_path, "rb") as file:
        msg = BytesParser(
            policy=policy.default
        ).parse(file)

    # Extract email headers
    sender = msg.get("From", "")
    recipient = msg.get("To", "")
    reply_to = msg.get("Reply-To", "")
    subject = msg.get("Subject", "")
    date = msg.get("Date", "")

    # Extract email addresses
    sender_email = parseaddr(sender)[1].lower()
    reply_email = parseaddr(reply_to)[1].lower()

    # Extract sender domain
    sender_domain = (
        sender_email.split("@")[-1]
        if "@" in sender_email else ""
    )

    reply_domain = (
        reply_email.split("@")[-1]
        if "@" in reply_email else ""
    )

    # ======================================
    # EXTRACT EMAIL BODY
    # ======================================

    body = msg.get_body(preferencelist=("plain",))

    if body:
        email_body = body.get_content()
    else:
        email_body = ""

    # ======================================
    # EXTRACT URLS
    # ======================================

    urls = re.findall(
        r'https?://[^\s<>"\']+',
        email_body
    )

    # ======================================
    # EXTRACT URL DOMAINS
    # ======================================

    url_domains = []

    for url in urls:

        domain = urlparse(url).hostname

        if domain:
            url_domains.append(domain.lower())

    # ======================================
    # EXTRACT IP ADDRESSES
    # ======================================

    received_headers = msg.get_all("Received", [])

    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

    ip_addresses = []

    for header in received_headers:

        ips = re.findall(
            ip_pattern,
            str(header)
        )

        ip_addresses.extend(ips)

    ip_addresses = sorted(set(ip_addresses))

    # ======================================
    # EMAIL AUTHENTICATION RESULTS
    # ======================================

    auth_results = " ".join(
        str(item)
        for item in msg.get_all(
            "Authentication-Results", []
        )
    ).lower()

    # ======================================
    # PHISHING DETECTION ENGINE
    # ======================================

    risk_score = 0

    findings = []

    print("\n========== PHISHING DETECTION ENGINE ==========")

    # RULE 1: Sender and Reply-To mismatch

    if sender_domain and reply_domain:

        if sender_domain != reply_domain:

            risk_score += 25

            findings.append(
                "Sender and Reply-To domain mismatch detected"
            )

    # RULE 2: Suspicious keywords

    suspicious_keywords = [
        "urgent",
        "immediately",
        "suspended",
        "verify your account",
        "password",
        "click here"
    ]

    combined_text = (
        subject + " " + email_body
    ).lower()

    detected_keywords = [
        word
        for word in suspicious_keywords
        if word in combined_text
    ]

    if detected_keywords:

        risk_score += 15

        findings.append(
            "Suspicious keywords: "
            + ", ".join(detected_keywords)
        )

    # RULE 3: SPF authentication

    if re.search(r'\bspf=fail\b', auth_results):

        risk_score += 20

        findings.append(
            "SPF authentication failure"
        )

    # RULE 4: DKIM authentication

    if re.search(r'\bdkim=(none|fail)\b', auth_results):

        risk_score += 10

        findings.append(
            "DKIM missing or failed"
        )

    # RULE 5: DMARC authentication

    if re.search(r'\bdmarc=fail\b', auth_results):

        risk_score += 20

        findings.append(
            "DMARC authentication failure"
        )

    # RULE 6: URL domain comparison

    if sender_domain and any(
        domain != sender_domain
        for domain in url_domains
    ):

        risk_score += 10

        findings.append(
            "URL domain differs from sender domain"
        )

    # ======================================
    # RISK CLASSIFICATION
    # ======================================

    risk_score = min(risk_score, 100)

    if risk_score >= 75:

        risk_level = "CRITICAL"

    elif risk_score >= 50:

        risk_level = "HIGH"

    elif risk_score >= 25:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # ======================================
    # DISPLAY EMAIL DETAILS
    # ======================================

    print("\n[+] EMAIL DETAILS")

    print("Sender:", sender)
    print("Recipient:", recipient)
    print("Reply-To:", reply_to)
    print("Subject:", subject)
    print("Date:", date)

    # ======================================
    # DISPLAY EXTRACTED URLS
    # ======================================

    print("\n[+] EXTRACTED URLS")

    if urls:

        for url in urls:
            print("-", url)

    else:

        print("No URLs found")

    # ======================================
    # DISPLAY IOCs
    # ======================================

    print("\n[+] INDICATORS OF COMPROMISE (IOCs)")

    print("Sender Domain:", sender_domain or "Not available")

    print("Reply-To Domain:", reply_domain or "Not available")

    print("\nURL Domains:")

    if url_domains:

        for domain in url_domains:
            print("-", domain)

    else:

        print("No URL domains found")

    print("\nIP Addresses:")

    if ip_addresses:

        for ip in ip_addresses:
            print("-", ip)

    else:

        print("No IP addresses found")

    # ======================================
    # DISPLAY SECURITY FINDINGS
    # ======================================

    print("\n[+] SECURITY FINDINGS")

    if findings:

        for finding in findings:

            print("[!] ", finding)

    else:

        print("No suspicious indicators detected")

    # ======================================
    # DISPLAY THREAT ASSESSMENT
    # ======================================

    print("\n[+] FINAL THREAT ASSESSMENT")

    print("Risk Score:", str(risk_score) + "/100")

    print("Risk Level:", risk_level)

    # ======================================
    # GENERATE SOC INVESTIGATION REPORT
    # ======================================

    OUTPUT_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    report_file = OUTPUT_DIR / (
        f"phishing_report_{timestamp}.txt"
    )

    report_content = f"""
========== SOC INCIDENT REPORT ==========

Investigation Date:
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

EMAIL DETAILS
-------------

Sender: {sender}
Recipient: {recipient}
Reply-To: {reply_to}
Subject: {subject}
Date: {date}

EXTRACTED URLS
--------------

{chr(10).join(urls) if urls else "No URLs found"}

INDICATORS OF COMPROMISE
------------------------

Sender Domain: {sender_domain or "Not available"}
Reply-To Domain: {reply_domain or "Not available"}

URL Domains:
{chr(10).join(url_domains) if url_domains else "None"}

IP Addresses:
{chr(10).join(ip_addresses) if ip_addresses else "None"}

SECURITY FINDINGS
-----------------

{chr(10).join(findings) if findings else "No suspicious indicators detected"}

THREAT ASSESSMENT
-----------------

Risk Score: {risk_score}/100
Risk Level: {risk_level}

ANALYST RECOMMENDATION
----------------------

{"Escalate for further investigation. Do not interact with suspicious links." if risk_score >= 50 else "Review findings and continue normal email security checks."}

==========================================
"""

    report_file.write_text(
        report_content,
        encoding="utf-8"
    )

    print("\n[+] SOC REPORT GENERATED")

    print("Report Location:", report_file)

    print("\n========== INVESTIGATION COMPLETE ==========")


# ==========================================
# MAIN PROGRAM
# ==========================================

if __name__ == "__main__":

    if len(sys.argv) > 1:

        email_file = BASE_DIR / sys.argv[1]

    else:

        email_file = DEFAULT_EMAIL

    try:

        email_file = email_file.resolve()

        email_file.relative_to(BASE_DIR.resolve())

        if not email_file.is_file():
            print("Error: Email file not found!")
            sys.exit(1)

        analyze_email(email_file)

    except ValueError:

        print("Error: Email file must be inside the project folder.")

        sys.exit(1)

    except Exception as error:

        print("Error during email analysis:", error)

        sys.exit(1)
