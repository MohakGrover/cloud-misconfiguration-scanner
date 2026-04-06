# Testing Guide: Multi-Cloud Security Scanner

This guide explains how to test and verify the functionality of the security scanner.

## Prerequisites

### 1. Python Environment
Ensure you have the dependencies installed:
```bash
pip install -r requirements.txt
```

### 2. AWS Credentials
The scanner relies on `boto3`, which uses the standard AWS credential chain. You must have active credentials.

**Option A: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=... # If using temporary credentials
export AWS_DEFAULT_REGION=us-east-1
```

**Option B: AWS CLI Profile**
```bash
aws configure
```

## Running a Scan

### Basic Smoke Test (Help Command)
Verify the CLI is responsive:
```bash
python scan.py --help
```
**Expected Output**: Help message listing `--provider` and `--out` options.

### Active Scan (AWS)
Run a scan against your configured AWS account:
```bash
python scan.py --provider aws
```

**What to expect:**
1.  **Scanning resources...** (Progress spinner)
2.  **Scan S3 buckets...**
3.  **Scan Security Groups...**
4.  **Scan IAM Users...**
5.  **Collected X resources.**
6.  **Loaded Y rules.**
7.  **Scan Findings Table**: A table showing any detected misconfigurations.
    - **Severity**: Critical issues in Red, High in Yellow.
    - **Resource ID**: The name/ID of the failing resource.
    - **Rule**: Which rule was violated.

### Saving Results to File
To analyze results later or pass them to another tool:
```bash
python scan.py --provider aws --out results.json
```
Check the `results.json` file for the raw data.

## Verifying Specific Rules

You can verify the rules engine by manually creating resources that violate the rules.

| Rule | Trigger Condition | How to Test |
| :--- | :--- | :--- |
| **S3 Bucket Publicly Accessible** | S3 Bucket without "Block All Public Access" enabled. | Create a bucket, leave "Block all public access" unchecked (or partially unchecked). Run scan. |
| **Security Group Opens SSH to World** | Inbound rule: Port 22, Source 0.0.0.0/0. | Create a Security Group, add Inbound Rule > SSH > Any IPv4. Run scan. |
| **IAM User MFA Not Enabled** | IAM User without an MFA device assigned. | Create a new IAM user (console access or programmatic), do not assign MFA. Run scan. |

> [!CAUTION]
> **Use Non-Production Accounts**: Always test in a sandbox or dev account to avoid security risks or accidental deletions (if testing `nuke.py`).

## Troubleshooting
- **"No module named..."**: Re-run `pip install -r requirements.txt`.
- **"Unable to locate credentials"**: Check `aws sts get-caller-identity` to verify your session.
- **Empty Findings**: Congratulations! Or, your rules might not be matching. Ensure you have resources in the region you are scanning (default `us-east-1`).
