\# 🛡️ Phishing Email Investigation \& Detection System



\## 📌 Project Overview



A Python-based Security Operations Center (SOC) project designed to investigate suspicious emails, extract Indicators of Compromise (IOCs), identify phishing indicators, calculate threat scores, and generate investigation reports.



The project includes an interactive Streamlit dashboard for monitoring email investigations and visualizing threat severity.



\## 🎯 Objectives



\- Analyze email headers and message content.

\- Extract sender, recipient, subject, and date.

\- Identify suspicious URLs and IP addresses.

\- Examine email authentication results (SPF, DKIM, DMARC).

\- Detect suspicious email characteristics.

\- Calculate phishing risk scores.

\- Classify emails based on threat severity.

\- Generate SOC investigation reports.



\## ⚙️ Technologies Used



\- Python

\- Streamlit

\- Pandas

\- Python Email Parsing Library

\- Regular Expressions (Regex)



\## 🔍 Key Features



1\. Email Header Analysis

2\. URL and IP Address Extraction

3\. Email Authentication Analysis

4\. Phishing Indicator Detection

5\. Automated Risk Scoring

6\. Threat Severity Classification

7\. IOC Extraction

8\. Automated Investigation Report Generation

9\. Interactive SOC Dashboard

10\. Investigation History and Filtering



\## 📊 Threat Classification



The system classifies investigated emails into four severity levels:



| Severity | Description |

|---|---|

| Critical | Very high phishing risk |

| High | High phishing risk |

| Medium | Moderate phishing risk |

| Low | Low detected risk |



\## 📁 Project Structure



```text

PhishingEmailInvestigation/

│

├── src/

│   └── analyzer.py

│

├── samples/

│   ├── legitimate\_email.eml

│   └── suspicious\_email.eml

│

├── output/

│   └── Investigation Reports

│

├── dashboard.py

├── requirements.txt

└── README.md

```



\## 🚀 Installation and Setup



\### 1. Clone the repository



```bash

git clone YOUR\_GITHUB\_REPOSITORY\_URL

```



\### 2. Navigate to the project



```bash

cd PhishingEmailInvestigation

```



\### 3. Install dependencies



```bash

pip install -r requirements.txt

```



\### 4. Analyze a legitimate email



```bash

python src/analyzer.py samples/legitimate\_email.eml

```



\### 5. Analyze a suspicious email



```bash

python src/analyzer.py samples/suspicious\_email.eml

```



\### 6. Launch the SOC dashboard



```bash

python -m streamlit run dashboard.py

```



Open the dashboard at:



http://localhost:8501



\## 🧪 Testing



The project was tested using sample legitimate and suspicious email files.



Test scenarios include:



\- Legitimate email analysis.

\- Suspicious sender and Reply-To analysis.

\- URL and IP extraction.

\- Email authentication checks.

\- Threat score calculation.

\- Investigation report generation.



\## 🛡️ Security Disclaimer



This project is developed for educational purposes and cybersecurity training.



Only use authorized email samples and isolated testing environments. Do not open suspicious links or attachments during investigations.



A LOW risk score does not guarantee that an email is safe. Detection results require analyst verification.



\## 👨‍💻 Author



Cybersecurity Enthusiast | Aspiring SOC Analyst



Skills: Python, Email Security, IOC Analysis, Phishing Detection, Security Investigation, Streamlit.

