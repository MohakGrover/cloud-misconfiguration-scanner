# Cloud Misconfiguration Scanner (AntiGravity) 🚀

[![Security: Cloud](https://img.shields.io/badge/Security-Cloud-blue.svg)](https://github.com/mohak/cloud-misconfiguration-scanner)
[![Python: 3.9+](https://img.shields.io/badge/Python-3.9+-yellow.svg)](https://python.org)

**AntiGravity** is a powerful, automated cloud security scanner designed to identify misconfigurations across major cloud providers (initially supporting AWS). It analyzes your cloud infrastructure against security best practices, providing actionable findings and remediation steps.

---

## ✨ Features

- **Multi-Cloud Support**: Currently implemented for **AWS** (S3, IAM, EC2, RDS).
- **Rule-Based Engine**: Evaluate resources using a customizable YAML-based rule definitions.
- **Deep Scanning**:
  - **S3**: Identifies public buckets, unencrypted buckets, and missing logging.
  - **IAM**: Detects overprivileged users, root account usage, and MFA status.
  - **EC2**: Scans for exposed ports, insecure security groups, and missing tags.
  - **RDS**: Finds public instances and unencrypted databases.
- **Interactive CLI**: Fast, terminal-based scanning with rich-text reporting.
- **Web Dashboard**: Modern UI for visualizing scan results and security posture trends.
- **Remediation Guides**: Each finding includes clear steps to fix the issue.

---

## 🛠️ Tech Stack

- **Backend**: Python 3.x, Flask, Boto3 (AWS SDK), DuckDB (Local Data), Click, Rich.
- **Frontend**: React (with Vite/Next.js integration).
- **Configuration**: YAML for rules and policies.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.9 or higher
- Node.js (for the Dashboard)
- AWS CLI configured with appropriate permissions

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/cloud-misconfiguration-scanner.git
   cd cloud-misconfiguration-scanner
   ```

2. **Setup the Backend**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   pip install -e .
   ```

3. **Setup the Frontend**:
   ```bash
   cd antigravity/dashboard/frontend
   npm install
   ```

---

## 📖 Usage

### CLI Scanning

Run a full scan on your AWS account:
```bash
python scan.py --provider aws --out results.json
```

For interactive credential entry:
```bash
python scan.py --provider aws --interactive
```

### Launching the Dashboard

1. **Start the API**:
   ```bash
   python dashboard.py
   ```

2. **Start the Frontend**:
   ```bash
   cd antigravity/dashboard/frontend
   npm run dev
   ```
Access the dashboard at `http://localhost:5173`.

---

## 📂 Project Structure

```text
.
├── antigravity/        # Core logic, collectors, and analysis
├── dashboard/          # Flask API and React frontend
├── rules/              # YAML security rules (S3, IAM, etc.)
├── scanners/           # Provider-specific scanner logic
├── docs/               # Project documentation and PDFs
├── requirements.txt    # Project dependencies
└── scan.py             # CLI Entry point
```

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

*Elevate your cloud security posture with AntiGravity.*
