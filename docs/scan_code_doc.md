# Documentation: `scan.py`

## Overview
`scan.py` is the main entry point for the Multi-Cloud Misconfiguration Security Scanner. It provides a Command Line Interface (CLI) for users to trigger scans against their cloud environments.

## CLI Usage

### Basic Command
```bash
python scan.py [OPTIONS]
```

### Options
- `--provider TEXT`: Specifies the cloud provider to scan.
    - **Default**: `aws`
    - **Supported Values**: `aws` (Future: `azure`, `gcp`)
- `--out TEXT`: Optional path to save findings as a JSON file.
    - **Example**: `--out findings.json`
- `--help`: Shows the help message and exits.

## Execution Flow
1.  **Scanner Selection**: Instantiates the appropriate scanner class (e.g., `AWSScanner`) based on the `--provider` argument.
2.  **Resource Collection**: Calls scanner methods (`scan_s3`, `scan_security_groups`, `scan_iam`) to fetch resource configurations from the cloud API.
3.  **Rule Loading**: Uses `RuleLoader` to load YAML detection rules from the `rules/` directory for the selected provider.
4.  **Evaluation**: Uses `RuleEvaluator` to compare collected resources against the loaded rules.
5.  **Reporting**:
    - Prints a summary table of findings to the console using `rich`.
    - Optionally writes the raw findings JSON to a file if `--out` is specified.

## Example
```bash
# Scan AWS and save results
python scan.py --provider aws --out report.json
```
