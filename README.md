
# Green Security — Security Alert Analyzer

[English](README.md) | [فارسی](README.fa.md)

## Project Overview

Green Security is a Python-based application designed to process, analyze, and generate reports from cybersecurity alerts stored in a JSON file.

The application extracts important information from security alerts, categorizes them based on severity, calculates statistical information, searches and filters alerts, and generates a structured JSON report.

The project focuses on basic security alert analysis and data processing without using Artificial Intelligence or Machine Learning models.

## Features

- **JSON Data Processing:** Read and process security alerts from a JSON file.
- **Alert Extraction:** Extract important information such as rule ID, name, severity, risk score, timestamp, and IP addresses.
- **Severity Analysis:** Categorize alerts into Critical, High, Medium, and Low levels.
- **Statistical Analysis:** Calculate alert statistics, average risk scores, and identify the highest-risk alert.
- **High-Risk Detection:** Identify alerts with high risk scores.
- **Alert Search:** Search alerts by source IP, alert name, and severity.
- **Evidence Analysis:** Extract detection reasons, confidence levels, event outcomes, and matched patterns.
- **Data Validation:** Handle missing, empty, or invalid alert fields.
- **JSON Report Generation:** Generate a structured report containing processed alert information.
- **Duplicate Detection:** Identify alerts with repeated rule IDs.

## Project Structure

```text
green_security/
│
├── data/
│   ├── __init__.py
│   └── json_reader.py
│
├── output/
│   ├── __init__.py
│   ├── json_writer.py
│   └── report.json
│
├── services/
│   ├── __init__.py
│   ├── alert_analyzer.py
│   ├── alert_extractor.py
│   ├── alert_reporter.py
│   ├── alert_search.py
│   ├── alert_validation.py
│   ├── optional_features.py
│   └── report_generator.py
│
├── security_alerts.json
├── main.py
└── README.md
```

### Directory and File Description

| File / Directory | Description |
|---|---|
| `data/` | Contains modules responsible for reading input data. |
| `json_reader.py` | Reads security alerts from the JSON input file. |
| `services/` | Contains the main application logic and processing modules. |
| `alert_extractor.py` | Extracts important information from security alerts. |
| `alert_analyzer.py` | Analyzes alerts and calculates statistical information. |
| `alert_search.py` | Provides search and filtering functionality. |
| `alert_validation.py` | Validates alert data and handles incomplete fields. |
| `alert_reporter.py` | Prepares alert information for reporting. |
| `report_generator.py` | Generates the final analysis report. |
| `optional_features.py` | Contains additional alert-processing features. |
| `output/` | Stores generated reports. |
| `json_writer.py` | Writes processed data into JSON files. |
| `security_alerts.json` | Input dataset containing security alerts. |
| `report.json` | Generated JSON analysis report. |
| `main.py` | Main entry point of the application. |

## Requirements

- Python 3
- PyCharm or another Python-compatible IDE

No external Python libraries are required for the core functionality.

## Installation and Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
```

### 2. Navigate to the Project Directory

```bash
cd green_security
```

### 3. Create a Virtual Environment

```bash
python3 -m venv .venv
```

### 4. Activate the Virtual Environment

On Linux:

```bash
source .venv/bin/activate
```

## Usage

Run the application from the project root directory:

```bash
python3 main.py
```

The application reads security alerts from `security_alerts.json`, processes the data, performs the analysis, and generates the output report.

## Input Data

The application uses `security_alerts.json` as its input dataset.

Each security alert contains three main sections:

### Rule

- `id`: Unique rule identifier.
- `name`: Name or type of suspicious activity.
- `severity`: Alert severity level.
- `risk_score`: Risk score assigned to the alert.
- `logic`: Detection logic.

### Event

- `@timestamp`: Event timestamp.
- `source.ip`: Source IP address.
- `destination.ip`: Destination IP address.
- `http.request.method`: HTTP request method.
- `url.path`: Requested URL path.
- `http.response.status_code`: HTTP response status code.
- `event.outcome`: Recorded event outcome.

### Evidence

- `reason`: Reason for generating the alert.
- `confidence`: Detection confidence level.
- `matched_pattern`: Identified suspicious pattern.

Some fields may be missing or empty. The application handles incomplete data during processing.

## Analysis and Reporting

The application performs several analysis operations:

- Groups alerts by severity: Critical, High, Medium, and Low.
- Calculates the total number of alerts.
- Calculates the average valid Risk Score.
- Identifies the alert with the highest Risk Score.
- Extracts High and Critical severity alerts.
- Searches alerts using different criteria.
- Identifies duplicate alerts based on `rule.id`.
- Extracts available evidence for each alert.

The application reports recorded information and evidence without assuming that a detected attack was necessarily successful.

## Output

The generated report is stored in:

```text
output/report.json
```

The report contains:

- Total number of alerts.
- Alert counts grouped by severity.
- Average Risk Score.
- Highest-risk alert information.
- High and Critical alerts.
- Key information extracted from processed alerts.

The output is saved in valid JSON format.

## Error Handling

The application includes error-handling mechanisms for common situations, such as:

- Missing input files.
- Invalid JSON format.
- Missing or incomplete alert fields.
- Invalid data values.
- Search queries with no matching results.

## Technologies and Concepts

- **Programming Language:** Python
- **Data Format:** JSON
- **Development Environment:** PyCharm
- **Version Control:** Git and GitHub

### Python Concepts Practiced

- File Handling
- JSON Processing
- Functions and Modules
- Lists and Dictionaries
- Loops and Conditional Statements
- Data Extraction and Validation
- Searching and Filtering
- Exception Handling
- Data Analysis
- Structured Report Generation



## Web Security Threat Research

Alongside project development, 10 web security topics were studied using OWASP resources to better understand common attack techniques, how they occur, and the potential risks they pose.

1. **SQL Injection (SQLi)**
   - [OWASP - SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)

2. **Cross-Site Scripting (XSS)**
   - [OWASP - Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

3. **Path Traversal**
   - [OWASP - Path Traversal Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html)

4. **Local File Inclusion (LFI)**
   - [OWASP - File Inclusion](https://wstg.owasp.org/latest/11-Injection/10.1-File_Inclusion/)

5. **Server-Side Request Forgery (SSRF)**
   - [OWASP - SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)

6. **Web Login Brute Force**
   - [OWASP - Testing for Weak Lock Out Mechanism](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism/)

7. **Web Directory Brute Force**
   - [OWASP - Enumerate Infrastructure and Application Admin Interfaces](https://wstg.owasp.org/latest/06-Configuration_and_Deployment_Management/04-Enumerate_Infrastructure_and_Application_Admin_Interfaces/)

8. **OS Command Injection**
   - [OWASP - OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)

9. **Suspicious Executable File Upload**
   - [OWASP - File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

10. **HTTP Authentication Bypass**
    - [OWASP - Bypassing Authentication Schema](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/04-Bypassing_Authentication_Schema/)

The purpose of this research was to understand common attack techniques, how they work, and the potential security risks they introduce to web applications.


## Future Improvements

Potential improvements for future versions include:

- Supporting additional security event formats.
- Adding more advanced alert filtering.
- Improving report visualization.
- Implementing alert correlation.
- Adding more detailed statistical analysis.

## Project Goals

This project was developed as part of an internship to gain practical experience in Python programming and understand the basic process of cybersecurity alert analysis.

The main goal is to build a structured application capable of processing security alert data, extracting useful information, performing initial analysis, and generating readable reports.
