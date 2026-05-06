# Data Loss Prevention (DLP)

> Part of the [worlds-biggest-software-project](https://github.com/worlds-biggest-software-project) initiative.
>
> An AI-native, open-source data loss prevention platform that combines content inspection, policy enforcement, and incident management without the tuning overhead and vendor lock-in of legacy DLP suites.

Data Loss Prevention (DLP) tools detect and block sensitive data — PII, payment data, source code, trade secrets — from leaving an organisation through email, web, cloud SaaS, and endpoints. This project is for security teams in regulated industries who need enforcement-grade DLP without paying enterprise prices to Broadcom, Forcepoint, or Microsoft, and without the false-positive fatigue that has plagued the category for two decades.

---

## Why Data Loss Prevention?

- **Legacy suites are expensive and stagnating.** Broadcom Symantec DLP customers have faced sharp price increases and slowing innovation post-acquisition; large enterprises pay $200K–$2M+/year for on-prem deployments.
- **Microsoft Purview only covers the Microsoft estate.** Bundled into M365 E5 (~$57/user/month), Purview is near-free for M365 shops but offers limited functionality outside the Microsoft ecosystem and lighter endpoint coverage than dedicated tools.
- **False-positive rates remain a structural problem.** Forcepoint, Symantec, and other rule-based platforms require complex tuning and produce high false-positive rates that drive analyst alert fatigue.
- **The only credible open-source option is discovery-only.** OpenDLP (Apache 2.0) scans for sensitive data at rest but offers no enforcement, no active prevention, and limited active development — leaving a clear gap for an OSS enforcement engine.
- **GenAI has opened a new exfiltration surface.** Data flowing into ChatGPT, Claude, and other LLM APIs is poorly covered by traditional text-only DLP, creating an emerging gap that incumbents are only beginning to address.

---

## Key Features

### Content Detection and Classification

- Pattern-based detection for SSN, credit card numbers, API keys, email addresses, and other structured identifiers
- ML-based confidence scoring to reduce false positives over time
- Advanced content analysis for PDFs, images, and screenshots
- Configurable custom patterns without code

### Policy Enforcement Across Channels

- Block, warn, or audit modes for email and web traffic
- Cloud SaaS coverage for Slack, Microsoft 365, Google Workspace, and Salesforce
- Lightweight endpoint agent for Windows and macOS to protect data at source
- Consistent multi-channel enforcement from a single policy framework

### User Context and Behaviour Analytics

- Identity, role, and department incorporated into policy decisions
- User behaviour baselining to flag anomalous activity
- Insider-threat risk scoring driven by ML models
- Automated remediation: quarantine files, revoke share access, notify users

### Incident Management and Compliance

- Real-time alerting and full audit logging of all violations
- Centralised admin console for policy creation, testing, and deployment
- Pre-built compliance reporting for GDPR, HIPAA, and PCI DSS
- RESTful API for SIEM, ticketing, and SOAR integration

### Emerging Capabilities (Backlog)

- GenAI DLP: monitor and prevent data exfiltration through LLM APIs
- AI-powered policy generation from natural-language descriptions
- Dark-web monitoring for organisational data exposure
- Industry-specific templates for healthcare, finance, and government

---

## AI-Native Advantage

AI changes the economics of DLP in ways legacy suites cannot easily retrofit. ML-based content classifiers can learn an organisation's specific sensitive data patterns — internal project codes, financial models, source code — without manual policy authoring. Real-time context analysis combining content, user behaviour, destination, and time-of-day signals materially reduces the false-positive rates that drive analyst alert fatigue. LLM-powered policy generation lets teams describe what should not leave the organisation in plain language, while multimodal vision models close the long-standing gap around sensitive content in images, screenshots, and video frames.

---

## Tech Stack & Deployment

The project targets hybrid deployment: self-hosted for regulated and air-gapped environments, with a cloud-native option for SaaS-first organisations. Integration points span email gateways, web proxies, cloud storage (AWS S3, Azure Blob, GCS), SaaS APIs (Slack, M365, Google Workspace, Salesforce), identity providers (Okta, Entra ID, Active Directory), and SIEM/SOAR platforms (Splunk, Sentinel, ServiceNow, Jira). Compliance alignment covers NIST SP 800-53 (SI-12, MP-6), NIST SP 800-171, ISO/IEC 27001:2022 Annex A.8.12, GDPR Article 32, HIPAA Security Rule, PCI DSS v4.0, and CCPA/CPRA.

---

## Market Context

The DLP software market was valued at approximately USD 3.15–4.12 billion in 2024–2025 and is projected to reach USD 12.5–15.83 billion by 2032–2035 at a CAGR of ~14–15% (per market research summarised in `research.md`). The top five vendors — Microsoft, Broadcom, Forcepoint, Zscaler, and Palo Alto Networks — hold roughly 55% of revenue. Cloud-native SaaS DLP starts from ~$10–15/user/month while enterprise on-prem solutions reach $200K–$2M+/year. Primary buyers are CISOs and data security teams in finance, healthcare, and government, alongside compliance officers driven by GDPR, HIPAA, and PCI.

---

## Project Status

> This project is in the **research and specification phase**.  
> Contributions, feedback, and domain expertise are welcome.

---

## Contributing

We welcome contributions from developers, domain experts, and potential users.
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Important:** All contributions must be your own original work or clearly attributed
open-source material with a compatible licence. Copyright infringement and licence
violations will not be tolerated and will result in immediate removal of the offending
contribution. If you are unsure whether a piece of code, text, or other material is
safe to contribute, open an issue and ask before submitting.

---

## Licence

Licence to be determined. See [discussion](#) for context.
