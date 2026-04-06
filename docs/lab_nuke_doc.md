# Documentation: `lab/nuke.py`

## Overview
`lab/nuke.py` is a safety enforcement script designed to clean up (delete) AWS resources created for the "ScannerLab" environment. It specifically targets resources tagged with `ScannerLab` in the `us-east-2` region to prevent accidental billing for lab resources.

## Key Users
- **Security Learners/Testers**: Users who have deployed the vulnerable lab environment and want to tear it down completely.
- **Automated Schedules**: Can be run via cron or a scheduler to enforce a cleanup policy (e.g., nuke resources older than 4 hours).

## Configuration
- **`TAG_KEY`**: "ScannerLab" - The tag key used to identify resources to delete.
- **`SAFE_REGION`**: "us-east-2" - The specific region where the cleanup operations are permitted. This acts as a safety guardrail.

## Functions & Logic

### `nuke_lab_resources()`
- **Purpose**: The main function that orchestrates the deletion process.
- **Safety Checks**:
    - Prints warnings about the region and tag being targeted.
    - **Interactive Confirmation**: Asks the user for confirmation (`yes/no`) before proceeding. Aborts if the answer is not "yes".
- **Resource Deletion**:
    1.  **EC2 Instances**:
        - Filters instances by the `ScannerLab` tag.
        - Terminates identified instances.
    2.  **S3 Buckets**:
        - Iterates through all buckets (client-side filtering necessitated by `list_buckets` limitations).
        - Checks for the `ScannerLab` tag.
        - If found:
            - Deletes all objects within the bucket (required before bucket deletion).
            - Deletes the bucket itself.

## Usage
Run the script from the command line:
```bash
python lab/nuke.py
```
**Prerequisites**:
- AWS Credentials configured (e.g., via `aws configure` or environment variables).
- `boto3` installed.
