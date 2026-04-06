# Documentation: `extract_pdf.py`

## Overview
`extract_pdf.py` is a utility script designed to extract text content from a specific PDF file (`cloud-security-scanner-pdr.md.pdf`) and save it to a text file (`pdr_text.txt`). It handles dependency installation automatically if required packages are missing.

## Key Users
- **Developers/Contributors**: To extract the Product Design & Requirements (PDR) document text for analysis or processing.
- **Automated Processes**: Can be used as a preprocessing step to convert the PDF spec into a readable text format.

## Dependencies
- `sys`, `subprocess`, `importlib.util` (Standard Library)
- `pypdf`: Used for reading and extracting text from PDF files. The script attempts to install this package using `pip` if it is not found.

## Functions & Logic

### `install(package)`
- **Purpose**: Installs a Python package using pip.
- **Arguments**: `package` (str) - The name of the package to install.
- **Behavior**: Uses `subprocess.check_call` to run `pip install`. Catches exceptions if installation fails.

### Main Execution Flow
1. **Dependency Check**: Checks if `pypdf` is installed. If not, calls `install("pypdf")`.
2. **PDF Extraction**:
    - Opens `cloud-security-scanner-pdr.md.pdf`.
    - Iterates through each page of the PDF.
    - Extracts text using `page.extract_text()`.
    - Appends text to a variable, adding a "--- Page X ---" delimiter.
    - Handles exceptions for individual empty pages or extraction failures.
3. **Output**:
    - Writes the accumulated text to `pdr_text.txt` with UTF-8 encoding.
    - Prints success message or global error details.

## Usage
Run the script directly from the command line:
```bash
python extract_pdf.py
```
Ensure `cloud-security-scanner-pdr.md.pdf` is in the same directory.
