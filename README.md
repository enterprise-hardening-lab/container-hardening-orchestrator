🧩 Enterprise Container Hardening & Governance Orchestrator
🚀 Overview

This repository hosts the Container Hardening Orchestrator, a centralized, reusable CI/CD framework designed to enforce container image hardening, vulnerability scanning, code security checks, and compliance reporting across all application repositories within the enterprise.

It ensures that every container image:

✅ Uses CIS-hardened base OS images from internal AWS ECR

✅ Passes Trivy CVE and Semgrep SAST security checks

✅ Complies with Dockerfile and policy validations (Hadolint + Conftest)

✅ Generates automated reports and creates GitHub Issues for visibility

✅ Promotes images to production ECR only when compliant

🧱 Problem Statement

Before this orchestrator, app teams built containers independently using unverified base images.
This created risks such as:

Unpatched CVEs in base layers

Inconsistent scanning and compliance enforcement

Missing traceability and auditability

The orchestrator provides a standardized, automated governance pipeline that every app repository can integrate with — ensuring security consistency across the enterprise.

⚙️ Key Features
Category	Description
Hardened Base Enforcement	Uses only pre-approved CIS-hardened OS base images
Trivy Scanning	Detects and reports critical & high CVEs
Semgrep SAST	Scans app source code for insecure patterns
Policy Validation	Dockerfile linting (Hadolint) & OPA Rego checks (Conftest)
Report Generation	Produces detailed JSON and HTML summaries
GitHub Issue Automation	Auto-creates/updates security summary issues
ECR Promotion	Pushes image to hardened ECR only on compliance pass
OIDC Authentication	Secure, credential-free AWS access from GitHub Actions
🧩 Architecture
App Repo (e.g., dashboard-api)
│
├── Dockerfile
├── src/main.py
└── .github/workflows/app-governance.yml  ← Triggers pipeline
       │
       ▼
Container Hardening Orchestrator Repo
├── .github/workflows/orchestrator.yml
└── actions/
     ├── build/
     ├── scan-image/
     ├── scan-code/
     ├── hardening-check/
     ├── generate-report/
     └── notify-issue/
       │
       ▼
AWS ECR (Hardened Image Registry)

🔁 End-to-End Workflow
Step	Description	Output
🏗️ Build	Build image using hardened base from ECR	Local Docker image
🔍 Scan Image	Run Trivy vulnerability scan	trivy-scan.json
🧪 Scan Code	Run Semgrep SAST scan	semgrep-report.sarif
🧰 Hardening Check	Run Hadolint and Conftest	Policy result
🧾 Generate Report	Aggregate results into JSON/HTML	reports/final/*
📣 Notify Issue	Create/Update “Security Summary” issue in GitHub	Auto-generated issue
🚀 Promote Image	Push image to ECR only if compliant	hardened-<app> repo
🧰 Tools & Frameworks
Tool	Purpose
Trivy	Container vulnerability scanner
Semgrep	Static code analyzer (SAST)
Hadolint	Dockerfile best practices linter
Conftest	OPA-based policy enforcement
gh CLI	Creates & updates GitHub Issues
AWS ECR + IAM (OIDC)	Secure, private image registry
GitHub Actions	Pipeline orchestration engine
☁️ AWS Integration
Service	Purpose
ECR	Stores hardened and app images
IAM Role (OIDC)	GitHubOIDC-ECRPushRole for secure GitHub→AWS auth
Region	ap-south-1
ARN	arn:aws:iam::661539128717:role/GitHubOIDC-ECRPushRole

No long-lived credentials are used — the role is assumed securely using GitHub OIDC tokens.

📊 Reporting & Notifications

After every pipeline run:

Detailed reports generated in reports/final/

Summary issue auto-created in app repo

Example issue:

### 🔐 Security Summary — dashboard-api
Generated: 2025-11-08T15:58Z
- Container: CRITICAL=0, HIGH=1
- Code: HIGH=2, MEDIUM=0
Overall Risk: 🟠 (3 total)


HTML dashboards and JSON outputs are attached as workflow artifacts.

🔐 Security Model

Only hardened base images are permitted for builds

No plaintext AWS credentials are used — all via OIDC

Scans run on every code or Dockerfile change

Images are promoted to ECR only when all checks pass

🧮 Directory Structure
.
├── .github/workflows/orchestrator.yml       # Central orchestrator
├── actions/
│   ├── build/
│   ├── scan-image/
│   ├── scan-code/
│   ├── hardening-check/
│   ├── generate-report/
│   └── notify-issue/
├── policies/                                # Hadolint & OPA rules
├── reports/                                 # Generated reports
└── docs/                                    # Documentation & design diagrams

🔮 Future Enhancements
Feature	Description
Cosign Integration	Sign and verify container attestations
OpenSearch Dashboard	Aggregate all scan data for compliance insights
Auto-Issue Closure	Close GitHub issue when all findings are resolved
Runtime Drift Detection	Identify configuration deviations at runtime
Cross-Cloud Support	Extend support to GCR, ACR, and on-prem registries
🧠 Summary

The Enterprise Container Hardening Orchestrator provides:

A unified CI/CD model for secure container delivery

End-to-end automation for compliance enforcement

Strong auditability for every app release
