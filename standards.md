# Standards & API Reference

> Project: Data Loss Prevention · Generated: 2026-05-03

## Industry Standards & Specifications

### ISO Standards

- **ISO/IEC 27001:2022** — Information security management systems; Annex A control **A.8.12 (Data Leakage Prevention)** explicitly requires organisations to apply DLP controls to information systems, networks, and output devices that handle sensitive information. This control was new in the 2022 revision; migration deadline was October 2025. URL: https://www.iso.org/standard/82875.html

- **ISO/IEC 27002:2022** — Implementation guidance for ISO 27001; Section 8.12 details how DLP tools should monitor and detect data transfers, identify classification labels, and trigger alerts or blocks for policy violations across email, web, endpoints, and cloud storage. URL: https://www.iso.org/standard/75652.html

- **ISO/IEC 27018:2019 — Code of Practice for PII in Public Clouds** — Provides controls for protection of Personally Identifiable Information (PII) in cloud environments; DLP is a key technical control referenced for preventing unintended PII disclosure. URL: https://www.iso.org/standard/76559.html

- **ISO/IEC 27701:2019 — Privacy Information Management** — Extension of ISO 27001/27002 for privacy; requires data flow mapping and controls to prevent unauthorised disclosure, directly motivating DLP implementation for PII. URL: https://www.iso.org/standard/71670.html

### W3C & IETF Standards

- **RFC 8259 — JSON** — Standard data format used by DLP REST APIs for policy definitions, classification results, incident reports, and event notifications. URL: https://datatracker.ietf.org/doc/html/rfc8259

- **RFC 6749 — OAuth 2.0** — Authorization framework used by cloud-native DLP APIs (Microsoft Purview, Nightfall, Netskope) to authenticate consuming applications and enforce scoped access to DLP management functions. URL: https://datatracker.ietf.org/doc/html/rfc6749

- **RFC 7519 — JSON Web Token (JWT)** — Used in DLP API authentication flows and inline DLP policy decision responses to convey identity claims and classification results between enforcement points. URL: https://datatracker.ietf.org/doc/html/rfc7519

- **RFC 5321 — SMTP** — Email is a primary DLP enforcement channel; SMTP gateway inspection is foundational to email DLP for preventing exfiltration via email attachments and body content. URL: https://datatracker.ietf.org/doc/html/rfc5321

### Data Model & API Specifications

- **OpenAPI 3.1** — Used to describe the REST management APIs of cloud-native DLP platforms (Microsoft Purview, Nightfall Developer Platform, Forcepoint App Data Security API); enables SDK generation and automation integration. URL: https://spec.openapis.org/oas/latest.html

- **Microsoft Purview DLP via Microsoft Graph API** — Microsoft's unified API endpoint (`graph.microsoft.com`) exposes DLP policy management, compliance rule evaluation, and sensitivity label operations; supports both delegated and application permissions. URL: https://learn.microsoft.com/en-us/purview/developer/microsoft-purview-sdk-documentation-overview

- **Microsoft Purview SDK (Public Preview, 2025)** — REST SDK enabling AI applications to call Purview's `ComputeProtectionScope` and `ProcessContent` APIs for real-time inline DLP policy evaluation against prompts and AI-generated responses. URL: https://techcommunity.microsoft.com/blog/microsoft-security-blog/microsoft-purview-sdk-public-preview/4414240

- **Nightfall Developer Platform API** — Cloud-native DLP REST API providing 100+ AI-based classifiers (PII, PCI, PHI, secrets, credentials) as a service; JSON-based requests submit content chunks and receive classification results with confidence scores and policy actions. URL: https://www.nightfall.ai/guide/data-protection-security-with-nightfall-developer-platform

- **Forcepoint DLP Protector Inspection API** — On-premises/hybrid DLP inspection API that permits sending data across email, web, and CASB channels and receiving policy decisions (allow, block, encrypt, quarantine); requires a dedicated licence. URL: https://help.forcepoint.com/dlp/10.3.0/inspect/protector-inspection-API-integration-guide.pdf

### Security & Authentication Standards

- **GDPR Article 25 — Data Protection by Design and by Default** — Requires technical measures (including DLP) to ensure only necessary personal data is processed and disclosed; DLP is the primary technical control for enforcing data minimisation at egress points. URL: https://gdpr-info.eu/art-25-gdpr/

- **GDPR Article 32 — Security of Processing** — Requires appropriate technical measures to prevent unauthorised disclosure; DLP is explicitly cited in supervisory authority guidance as a relevant measure. URL: https://gdpr-info.eu/art-32-gdpr/

- **HIPAA Security Rule — §164.312(e)(2)(ii)** — Requires encryption and decryption controls for ePHI transmission; DLP enforces this requirement by blocking unencrypted PHI transmissions and quarantining non-compliant transfers. URL: https://www.hhs.gov/hipaa/for-professionals/security/

- **PCI DSS v4.0 — Requirement 3 (Protect Account Data)** — Requires controls preventing primary account numbers (PANs) from being transmitted in clear text over open networks; DLP is the standard enforcement mechanism. URL: https://www.pcisecuritystandards.org/

- **NIST SP 800-171 Rev. 3 — Protecting CUI in Non-Federal Systems** — Requirement 3.13.16 mandates protecting the confidentiality of CUI at rest; DLP controls are referenced in the assessment guide as applicable technical measures for CMMC 2.0 compliance. URL: https://csrc.nist.gov/publications/detail/sp/800-171/3/final

- **CCPA/CPRA — California Consumer Privacy Act** — Requires technical safeguards for consumer personal information; DLP for consumer data egress monitoring is referenced in California AG enforcement guidance. URL: https://oag.ca.gov/privacy/ccpa

- **OWASP Top 10 — A02: Cryptographic Failures** — Data exposure through insecure transmission is a top web vulnerability; DLP complements cryptographic controls by detecting unencrypted sensitive data exfiltration at the application layer. URL: https://owasp.org/Top10/

- **NIST CSF 2.0 — PR.DS (Protect: Data Security)** — The Data Security subcategory explicitly references DLP as a protective control for data-in-transit and data-at-rest across the organisation. URL: https://www.nist.gov/cyberframework

### MCP Server Specifications

DLP has become a critical control layer for AI and MCP-based agentic workflows in 2025-2026:

- **Nightfall MCP Security** — First enterprise DLP platform purpose-built for MCP; monitors every MCP tool call, classifies content in real time before it reaches the LLM, and logs timestamp, user, agent, data accessed, classification, and action taken. Discovers and catalogues MCP servers across Claude Desktop, Cursor, and VS Code. URL: https://www.nightfall.ai/products/mcp-security

- **Nightfall DLP MCP Server** — Nightfall's own MCP server exposes DLP classification capabilities to AI agents, enabling AI applications to self-classify content before transmission. URL: https://viasocket.com/mcp/nightfall-dlp

- **MCP DLP Pattern** — Emerging architecture (2025-2026) where DLP operates at the AI data flow layer: monitoring tool calls, classifying content in real time, and acting before sensitive data reaches the model or external API — addresses the 18,000+ unmanaged MCP server attack surface. URL: https://www.strac.io/blog/mcp-dlp

---

## Similar Products — Developer Documentation & APIs

### Microsoft Purview Information Protection (DLP)

- **Description:** Unified cloud-native DLP solution integrated across Microsoft 365 (Exchange Online, SharePoint, OneDrive, Teams), endpoints (via Defender), and third-party cloud environments via connectors; uses sensitivity labels and trainable classifiers; Purview SDK now enables inline AI prompt scanning.
- **API Documentation:** https://learn.microsoft.com/en-us/purview/developer/ and https://learn.microsoft.com/en-us/rest/api/purview/
- **SDKs/Libraries:** Microsoft Graph SDK (Python, .NET, Go, Java, JavaScript); PowerShell compliance cmdlets (`New-DlpCompliancePolicy`, `New-DlpComplianceRule`)
- **Developer Guide:** https://learn.microsoft.com/en-us/purview/developer/use-the-api
- **Standards:** REST/JSON, Microsoft Graph API, OpenAPI, OAuth 2.0 (Azure AD application permissions)
- **Authentication:** Azure AD OAuth 2.0 (client credentials or delegated); managed identity for Azure-native workloads

### Nightfall Developer Platform

- **Description:** Cloud-native AI-powered DLP API platform; 100+ ML classifiers for PII, PCI, PHI, secrets, credentials, and custom data types; designed for integration into SaaS apps, CI/CD pipelines, and agentic MCP workflows; available on AWS Marketplace.
- **API Documentation:** https://www.nightfall.ai/guide/data-protection-security-with-nightfall-developer-platform
- **SDKs/Libraries:** Python SDK; Go SDK; REST API (JSON); Nightfall MCP Server
- **Developer Guide:** https://help.nightfall.ai/
- **Standards:** REST/JSON, OpenAPI 3.1, OAuth 2.0
- **Authentication:** API key (Authorization header)

### Forcepoint DLP

- **Description:** Enterprise DLP suite covering endpoint, network, cloud, and email channels; 1,700+ data classifiers covering 80+ countries and 90+ regulations; Protector Inspection API enables integration of DLP decisions into custom applications; App Data Security API for custom app protection.
- **API Documentation:** https://help.forcepoint.com/docs/Tech_Pubs/DLP/DLP.html
- **Inspection API Guide:** https://help.forcepoint.com/dlp/10.3.0/inspect/protector-inspection-API-integration-guide.pdf
- **SDKs/Libraries:** REST API (App Data Security); ICAP protocol for proxy integration; SIEM connectors
- **Developer Guide:** https://support.forcepoint.com/Documentation
- **Standards:** REST/JSON, ICAP, OpenAPI (partial), SAML 2.0 for SSO
- **Authentication:** API key + username; dedicated licence required for Inspection API

### Netskope DLP (SASE-integrated)

- **Description:** Cloud-native SASE platform with integrated DLP; covers inline proxy path (real-time) and API-based scanning (stored data in Google Drive, SharePoint, Box, Dropbox); uses Cloud XD engine for granular activity-level controls.
- **API Documentation:** https://docs.netskope.com/en/dlp/ (requires JavaScript)
- **SDKs/Libraries:** Netskope REST API; SIEM connectors (Splunk, Microsoft Sentinel, QRadar); SOAR integrations
- **Developer Guide:** https://docs.netskope.com/
- **Standards:** REST/JSON, ICAP, OpenAPI, SAML 2.0, OAuth 2.0
- **Authentication:** API token; OAuth 2.0 for SSO integration

### Zscaler DLP (Zscaler Internet Access)

- **Description:** Cloud-delivered DLP embedded in Zscaler Internet Access (ZIA); provides inline DLP for web and cloud traffic passing through Zscaler's global proxy; integrates with ZPA for full SASE DLP coverage.
- **API Documentation:** https://help.zscaler.com/zia/data-loss-prevention and https://automate.zscaler.com/
- **SDKs/Libraries:** zscaler-sdk-python v2.x; zscaler-sdk-go; Terraform provider (zscaler/terraform-provider-zia)
- **Developer Guide:** https://automate.zscaler.com/docs/docs/api-reference-and-guides/api-reference/zia
- **Standards:** REST/JSON, OpenAPI (Swagger), ICAP, OAuth 2.0
- **Authentication:** OAuth 2.0 client credentials (client_id, client_secret, cloud)

### Proofpoint Information Protection (Endpoint DLP)

- **Description:** People-centric endpoint DLP platform combining Insider Threat Management (ITM) with email DLP; strong forensics on user actions; integrates with Proofpoint's email security stack for unified data protection.
- **API Documentation:** https://developer.proofpoint.com/ (requires account)
- **SDKs/Libraries:** REST API; Proofpoint PSAT API; SIEM integration via syslog
- **Developer Guide:** Proofpoint developer portal (account required)
- **Standards:** REST/JSON, Syslog (RFC 5424), SAML 2.0, OAuth 2.0
- **Authentication:** API key; OAuth 2.0 for enterprise integrations

### Cloudflare Gateway (CASB + inline DLP)

- **Description:** Part of Cloudflare One SASE; provides inline DLP for web traffic (including AI provider APIs like OpenAI, Claude, Gemini) and API-based CASB scanning for cloud storage; configurable via Cloudflare Zero Trust dashboard and API.
- **API Documentation:** https://developers.cloudflare.com/api/resources/zero_trust/
- **SDKs/Libraries:** cloudflare-python SDK; cloudflare-go SDK; Terraform provider (cloudflare/cloudflare)
- **Developer Guide:** https://developers.cloudflare.com/cloudflare-one/
- **Standards:** REST/JSON, OpenAPI 3.1, OAuth 2.0
- **Authentication:** Bearer token (Cloudflare API Token with scoped permissions)

### Google Cloud DLP API (Sensitive Data Protection)

- **Description:** Google Cloud managed DLP service for discovering, classifying, and de-identifying sensitive data in text and images; 150+ built-in infoTypes (PII, PCI, PHI); supports de-identification (redaction, masking, tokenisation, pseudonymisation).
- **API Documentation:** https://cloud.google.com/sensitive-data-protection/docs/reference/rest
- **SDKs/Libraries:** Google Cloud client libraries (Python, Go, Java, .NET, Node.js, Ruby, PHP)
- **Developer Guide:** https://cloud.google.com/sensitive-data-protection/docs
- **Standards:** REST/JSON, gRPC/Protocol Buffers, OpenAPI, OAuth 2.0
- **Authentication:** Google Cloud service account (OAuth 2.0); Application Default Credentials (ADC)

---

## Notes

- **ISO 27001:2022 A.8.12 migration deadline (October 2025)**: The new DLP control in ISO 27001:2022 has now passed its compliance migration deadline; organisations seeking certification must demonstrate DLP controls covering information systems, networks, and output devices.

- **AI-native DLP as the 2026 frontier**: The explosion of MCP-based agentic workflows has created a new DLP enforcement requirement — real-time classification of data flowing through MCP tool calls before it reaches LLMs. Nightfall is the first purpose-built solution; all major DLP vendors are extending coverage to this layer.

- **CASB vs Cloud DLP distinction**: CASBs inspect network-level traffic only; cloud-native DLP (Nightfall, Microsoft Purview, Google Cloud DLP) integrates at the application layer via APIs, providing deeper content inspection and lower false-positive rates.

- **Open-source landscape**: There is no dominant open-source DLP platform comparable to MISP in the threat intelligence space. The closest open-source adjacent tools are regex/ML classifiers (spaCy NER, Presidio from Microsoft) and Google Cloud DLP's open-source client libraries. Presidio (MIT licence) provides PII detection and de-identification utilities that can serve as building blocks.

- **NIST guidance**: NIST's primary DLP reference remains a 2012 white paper; NIST SP 800-171 Rev. 3 and CSF 2.0 reference DLP as an implementation mechanism without mandating specific technical approaches.
