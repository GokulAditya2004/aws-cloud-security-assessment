# 🛡️ AWS Cloud Security Assessment Tool

A Python-based AWS security assessment tool that identifies
common cloud security misconfigurations and presents findings
through an interactive Streamlit dashboard.

## Overview

This project demonstrates practical cloud security skills by
assessing selected AWS security configurations, explaining
potential risks, and providing remediation recommendations.

<img width="1535" height="817" alt="image" src="https://github.com/user-attachments/assets/2b32d117-d2bc-4e6d-970d-c8761ea6a0ee" />

## Features

- IAM users without MFA
- Broad IAM permissions detection
- IAM access-key usage review
- S3 public-access protection and encryption checks
- Security Group exposure checks
- CloudTrail configuration checks
- EBS volume encryption checks
- Severity-based findings
- Risk explanations and remediation recommendations
- Project-defined security score
- JSON and CSV report downloads
- Interactive Streamlit dashboard
- Scan status and error reporting

<img width="1523" height="813" alt="image" src="https://github.com/user-attachments/assets/4ca0f63f-9357-4490-bcf8-7c24a5998c9a" />

## Technology Stack

- Python
- Boto3
- AWS CLI
- Amazon Web Services
- Streamlit
- Plotly
- JSON and CSV

## Architecture

1. The scanner connects to AWS using Boto3.
2. Individual modules inspect selected security configurations.
3. Findings are assigned severity levels.
4. Risk explanations and recommendations are generated.
5. Results are saved to a JSON report.
6. The Streamlit dashboard displays the report and charts.
7. Users can download JSON and CSV reports.

## Project Structure

    aws-security-scanner/
    ├── scanner.py
    ├── dashboard.py
    ├── checks/
    │   ├── iam.py
    │   ├── s3.py
    │   ├── security_groups.py
    │   ├── cloudtrail.py
    │   └── ec2.py
    └── reports/
        └── security_report.json

## Prerequisites

- Python 3
- AWS account
- AWS CLI
- Read-only AWS credentials with the permissions
  required by the implemented checks

## Installation

Install the dependencies:

    python -m pip install boto3 streamlit plotly

Configure AWS CLI credentials:

    aws configure

Verify the configured AWS identity:

    aws sts get-caller-identity

Never commit AWS access keys or secret credentials.

## Running the Scanner

From the project directory:

    python scanner.py

The scanner saves its report to:

    reports/security_report.json

## Launching the Dashboard

    python -m streamlit run dashboard.py

The dashboard displays the latest saved report.

Use the dashboard's scan button to run a new assessment.

## Security Score

The project calculates a score starting at 100 and subtracts
fixed penalties for findings based on severity.

This is an experimental, project-defined score. It is not an
official AWS security rating or compliance assessment.

## Limitations

- Checks cover selected AWS security configurations only.
- Findings do not constitute a complete security audit.
- Some configurations and policy types may not yet be detected.
- A missing last-used date does not prove that a key is unnecessary.
- Scan results depend on the AWS permissions available to the scanner.
- A successful scan does not guarantee that an AWS environment is secure.

## Future Improvements

- Expand IAM policy analysis
- Improve security-check coverage
- Add unit tests and automated testing
- Improve error handling and scan completeness reporting
- Add historical scan comparisons
- Improve dashboard reporting

## Disclaimer

Use this tool only in AWS accounts you own or are explicitly
authorized to assess. Review recommendations before changing
production resources.
