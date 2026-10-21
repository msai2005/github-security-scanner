# 🔐 GitHub Security Scanner

A Python-based security scanning tool that analyzes GitHub repositories to identify potential security vulnerabilities, hardcoded secrets, insecure coding practices, and vulnerable dependencies.

The project integrates multiple security scanning tools with a locally running AI model to provide explanations of detected security findings.

## 🚀 Features

- **GitHub Repository Scanning:** Retrieves supported source files from a public GitHub repository.
- **Static Application Security Testing:** Uses Semgrep to identify potential vulnerabilities and insecure coding practices.
- **Python Security Analysis:** Uses Bandit to detect common security issues in Python applications.
- **Secret Detection:** Uses Gitleaks to identify potential hardcoded secrets in downloaded source files.
- **Dependency Vulnerability Detection:** Uses OSV-Scanner to check supported dependency manifests for known vulnerabilities.
- **AI-Powered Analysis:** Uses Ollama with the Llama 3.2 model to explain security findings.
- **Custom Security Rules:** Supports custom Semgrep rules for detecting specific security issues.
- **Markdown Reports:** Generates a security report containing scan findings.
- **Scan History:** Maintains timestamped scan reports for historical reference.

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| GitHub REST API | Repository information retrieval |
| Semgrep | Static application security testing |
| Bandit | Python security analysis |
| Gitleaks | Secret detection |
| OSV-Scanner | Dependency vulnerability scanning |
| Ollama | Local AI model execution |
| Llama 3.2 | AI-powered security explanations |
| Git and GitHub | Version control and source code hosting |

## 📂 Project Structure

```text
github-security-scanner/
│
├── scanner.py
├── requirements.txt
├── .gitignore
├── README.md
├── scanner_custom_rules.yml
│
├── scan_history/
│   └── Timestamped security reports
│
└── scan_runs/
    └── Temporary repository scan files
