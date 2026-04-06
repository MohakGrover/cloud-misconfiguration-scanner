# Documentation: `scanners/`

## Overview
The `scanners/` package contains the logic for connecting to cloud provider APIs and collecting resource configuration data.

## Classes

### `BaseScanner` (`scanners/base_scanner.py`)
- **Type**: Abstract Base Class (ABC).
- **Purpose**: Defines the standard interface that all provider scanners must implement.
- **Methods**:
    - `scan_s3()`: Must return a list of storage bucket configurations.
    - `scan_security_groups()`: Must return a list of network security group configurations.
    - `scan_iam()`: Must return a list of identity/IAM configurations.

### `AWSScanner` (`scanners/aws_scanner.py`)
- **Inherits**: `BaseScanner`.
- **Dependencies**: `boto3`.
- **Initialization**: Accepts a `region` argument (default: `us-east-1`).
- **Methods**:
    - `scan_s3()`:
        - Uses `boto3.client('s3')`.
        - keys: `id` (Name), `public_access_block` (dict or None), `policy` (str or None).
    - `scan_security_groups()`:
        - Uses `boto3.client('ec2')`.
        - keys: `id` (GroupId), `ip_permissions` (list of rules).
    - `scan_iam()`:
        - Uses `boto3.client('iam')`.
        - keys: `id` (UserId), `mfa_active` (bool).

## Data Schema
Collected resources are standardized dictionaries expected by the `RuleEvaluator`. They typically include:
- `id`: Unique identifier (Name or ID).
- `name`: Human-readable name.
- `provider`: `aws`, `azure`, or `gcp`.
- `service`: `s3`, `ec2`, `iam`, etc.
- *Service-specific fields* (e.g., `public_access_block`, `ip_permissions`).
