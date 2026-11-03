import re
import sys
import ipaddress
from datetime import datetime
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


# ==========================================
# PROJECT CONFIGURATION
# ==========================================

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_EMAIL = BASE_DIR / "samples" / "suspicious_email.eml"
OUTPUT_DIR = BASE_DIR / "output"


# ==========================================
# HTML EMAIL BODY PARSER
# ==========================================

class EmailHTMLParser(HTMLParser):

    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.links = []

    def handle_data(self, data):
        text = data.strip()
        if text:
            self.text_parts.append(text)

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for key, value in attrs:
                if key.lower() == "href" and value:
                    self.links.append(value)


# ==========================================
# EXTRACT EMAIL BODY
# ==========================================

def extract_email_body(msg):

    text_parts = []
    html_links = []

    for part in msg.walk():

        if part.get_content_maintype() == "multipart":
            continue

        if part.get_content_disposition() == "attachment":
            continue

        content_type = part.get_content_type()

        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            content = part.get_content()
        except Exception:
            continue

        if not isinstance(content, str):
            continue

        if content_type == "text/plain":

            text_parts.append(content)

        elif content_type == "text/html":

            parser = EmailHTMLParser()
            parser.feed(content)

            text_parts.extend(parser.text_parts)
            html_links.extend(parser.links)

    email_body = "\n".join(text_parts)

    return email_body, html_links


# ==========================================
# EXTRACT URLS
# ==========================================

def extract_urls(email_body, html_links):

    url_pattern = r'https?://[^\s<>"\']+'

    body_urls = re.findall(url_pattern, email_body)

    all_urls = body_urls + [
        link for link in html_links
        if link.lower().startswith(("http://", "https://"))
    ]

    cleaned_urls = []

    for url in all_urls:

        url = url.rstrip(".,;:!?)]}")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


# ==========================================
# EXTRACT URL DOMAINS
# ==========================================

def extract_url_domains(urls):

    domains = []

    for url in urls:

        try:
            domain = urlparse(url).hostname

            if domain:

                domain = domain.lower().rstrip(".")

                if domain not in domains:
                    domains.append(domain)

        except Exception:
            continue

    return domains


# ==========================================
# EXTRACT IP ADDRESSES
# ==========================================

def extract_ip_addresses(msg, urls):

    ip_addresses = []

    received_headers = msg.get_all("Received", [])

    ip_pattern = r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])'

    for header in received_headers:

        matches = re.findall(
            ip_pattern,
            str(header)
        )

        for ip in matches:

            try:
                ipaddress.ip_address(ip)
                ip_addresses.append(ip)

            except ValueError:
                continue

    # Also check URLs for IP-based hosts

    for url in urls:

        hostname = urlparse(url).hostname

        if hostname:

            try:
                ipaddress.ip_address(hostname)
                ip_addresses.append(hostname)

            except ValueError:
                pass

    return sorted(set(ip_addresses))


# ==========================================
# EMAIL AUTHENTICATION ANALYSIS
# ==========================================

def analyze_authentication(msg):

    headers = msg.get_all("Authentication-Results", [])

    auth_results = " ".join(
        str(header) for header in headers
    ).lower()

    results = {
        "spf": "Not provided",
        "dkim": "Not provided",
        "dmarc": "Not provided"
    }

    for mechanism in results:

        match = re.search(
            rf'\b{mechanism}\s*=\s*([a-z]+)',
            auth_results
        )

        if match:
            results[mechanism] = match.group(1).upper()

    return results


# ==========================================
# PHISHING DETECTION ENGINE
# ==========================================

def calculate_risk(
    sender_domain,
    reply_domain,
    subject,
    email_body,
    url_domains,
    auth_results
):

    risk_score = 0
    findings = []

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
        word for word in suspicious_keywords
        if word in combined_text
    ]

    if detected_keywords:

        risk_score += 15

        findings.append(
            "Suspicious keywords detected: "
            + ", ".join(detected_keywords)
        )

    # RULE 3: SPF authentication

    spf = auth_results["spf"]

    if spf in ("FAIL", "SOFTFAIL", "PERMERROR"):

        risk_score += 20

        findings.append(
            f"SPF authentication problem: {spf}"
        )

    # RULE 4: DKIM authentication

    dkim = auth_results["dkim"]

    if dkim in ("FAIL", "PERMERROR"):

        risk_score += 10

        findings.append(
            f"DKIM authentication problem: {dkim}"
        )

    # RULE 5: DMARC authentication

    dmarc = auth_results["dmarc"]

    if dmarc in ("FAIL", "PERMERROR"):

        risk_score += 20

        findings.append(
            f"DMARC authentication problem: {dmarc}"
        )

    # RULE 6: URL domain comparison

    if sender_domain:

        mismatched_domains = [
            domain for domain in url_domains
            if domain != sender_domain
        ]

        if mismatched_domains:

            risk_score += 10

            findings.append(
                "URL domain differs from sender domain"
            )

    # FINAL RISK SCORE

    risk_score = min(risk_score, 100)

    if risk_score >= 75:
        risk_level = "CRITICAL"

    elif risk_score >= 50:
        risk_level = "HIGH"

    elif risk_score >= 25:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    return risk_score, risk_level, findings


# ==========================================
# GENERATE SOC INVESTIGATION REPORT
# ==========================================

def generate_report(
    sender,
    recipient,
    reply_to,
    subject,
    date,
    sender_domain,
    reply_domain,
    urls,
    url_domains,
    ip_addresses,
    auth_results,
    findings,
    risk_score,
    risk_level
):

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    report_file = OUTPUT_DIR / (
        f"phishing_report_{timestamp}.txt"
    )

    def format_list(items):

        if items:
            return "\n".join(
                f"- {item}" for item in items
            )

        return "- None"

    if risk_score >= 50:

        recommendation = (
            "Escalate for further investigation. "
            "Do not interact with suspicious links."
        )

    elif risk_score >= 25:

        recommendation = (
            "Investigate the identified indicators "
            "before trusting this email."
        )

    else:

        recommendation = (
            "No major suspicious indicators detected. "
            "Continue normal email security checks."
        )

    report_content = f"""
========== SOC INCIDENT REPORT ==========

Investigation Date:
{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

EMAIL DETAILS
-------------

Sender: {sender or "N/A"}
Recipient: {recipient or "N/A"}
Reply-To: {reply_to or "N/A"}
Subject: {subject or "N/A"}
Date: {date or "N/A"}

EXTRACTED URLS
--------------

{format_list(urls)}

INDICATORS OF COMPROMISE
------------------------

Sender Domain: {sender_domain or "Not available"}
Reply-To Domain: {reply_domain or "Not available"}

URL Domains
-----------
{format_list(url_domains)}

IP Addresses
------------
{format_list(ip_addresses)}

EMAIL AUTHENTICATION
--------------------

SPF: {auth_results["spf"]}
DKIM: {auth_results["dkim"]}
DMARC: {auth_results["dmarc"]}

SECURITY FINDINGS
-----------------

{format_list(findings)}

THREAT ASSESSMENT
-----------------

Risk Score: {risk_score}/100
Risk Level: {risk_level}

ANALYST RECOMMENDATION
----------------------

{recommendation}

==========================================
"""

    report_file.write_text(
        report_content,
        encoding="utf-8"
    )

    return report_file


# ==========================================
# MAIN EMAIL ANALYSIS FUNCTION
# ==========================================

def analyze_email(file_path):

    with open(file_path, "rb") as file:

        msg = BytesParser(
            policy=policy.default
        ).parse(file)

    # EMAIL HEADERS

    sender = str(msg.get("From", ""))
    recipient = str(msg.get("To", ""))
    reply_to = str(msg.get("Reply-To", ""))
    subject = str(msg.get("Subject", ""))
    date = str(msg.get("Date", ""))

    # EMAIL ADDRESSES

    sender_email = parseaddr(sender)[1].lower()
    reply_email = parseaddr(reply_to)[1].lower()

    sender_domain = (
        sender_email.split("@")[-1]
        if "@" in sender_email else ""
    )

    reply_domain = (
        reply_email.split("@")[-1]
        if "@" in reply_email else ""
    )

    # EMAIL BODY

    email_body, html_links = extract_email_body(msg)

    # URL EXTRACTION

    urls = extract_urls(email_body, html_links)

    url_domains = extract_url_domains(urls)

    # IP EXTRACTION

    ip_addresses = extract_ip_addresses(msg, urls)

    # AUTHENTICATION

    auth_results = analyze_authentication(msg)

    # RISK CALCULATION

    risk_score, risk_level, findings = calculate_risk(
        sender_domain,
        reply_domain,
        subject,
        email_body,
        url_domains,
        auth_results
    )

    # ======================================
    # TERMINAL OUTPUT
    # ======================================

    print("\n========== PHISHING DETECTION ENGINE ==========")

    print("\n[+] EMAIL DETAILS")

    print("Sender:", sender or "N/A")
    print("Recipient:", recipient or "N/A")
    print("Reply-To:", reply_to or "N/A")
    print("Subject:", subject or "N/A")
    print("Date:", date or "N/A")

    print("\n[+] EXTRACTED URLS")

    print("\n".join(urls) if urls else "No URLs found")

    print("\n[+] INDICATORS OF COMPROMISE")

    print("Sender Domain:", sender_domain or "Not available")
    print("Reply-To Domain:", reply_domain or "Not available")

    print("\nURL Domains:")

    print("\n".join(url_domains) if url_domains else "None")

    print("\nIP Addresses:")

    print("\n".join(ip_addresses) if ip_addresses else "None")

    print("\n[+] EMAIL AUTHENTICATION")

    for mechanism, result in auth_results.items():

        print(f"{mechanism.upper()}: {result}")

    print("\n[+] SECURITY FINDINGS")

    if findings:

        for finding in findings:
            print("[!] ", finding)

    else:

        print("No suspicious indicators detected")

    print("\n[+] FINAL THREAT ASSESSMENT")

    print(f"Risk Score: {risk_score}/100")
    print(f"Risk Level: {risk_level}")

    # ======================================
    # REPORT GENERATION
    # ======================================

    report_file = generate_report(
        sender,
        recipient,
        reply_to,
        subject,
        date,
        sender_domain,
        reply_domain,
        urls,
        url_domains,
        ip_addresses,
        auth_results,
        findings,
        risk_score,
        risk_level
    )

    print("\n[+] SOC REPORT GENERATED")
    print("Report Location:", report_file)

    print("\n========== INVESTIGATION COMPLETE ==========")


# ==========================================
# PROGRAM ENTRY POINT
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

        print(
            "Error: Email file must be inside "
            "the project folder."
        )

        sys.exit(1)

    except Exception as error:

        print("Error during email analysis:", error)

        sys.exit(1)