# Data Model Suggestion 3: Hybrid Relational + JSONB

> Project: Data Loss Prevention · Created: 2026-05-19

## Philosophy

This model uses a pragmatic hybrid approach: core structural fields (IDs, foreign keys, status, timestamps) are relational columns with proper types and constraints, while variable, domain-specific, or rapidly-evolving fields are stored in JSONB columns. This is the approach taken by most modern SaaS platforms that need to ship quickly while supporting multi-tenant variability.

DLP is a domain where variability is high. Different organisations define different sensitive data types. Different jurisdictions have different PII definitions. Different channels (email, Slack, endpoint, GenAI API) produce findings with different metadata. A fully normalised model would require dozens of tables to capture this variability, while a fully document-oriented model would lose referential integrity. The hybrid approach threads the needle: foreign keys enforce structural relationships, JSONB handles the variable parts, and PostgreSQL's GIN indexes make JSONB queries performant.

This is how Nightfall AI structures its API responses (fixed fields like confidence, detector, and location alongside variable detection_metadata), and how Microsoft Purview exposes sensitivity labels (fixed label properties with extensible custom properties as key-value pairs). The hybrid model is native to PostgreSQL and requires no additional infrastructure.

**Best for:** Teams building an MVP or early-stage product that need to iterate quickly on schema while maintaining relational integrity for core entities.

**Trade-offs:**
- Pro: Fast iteration; adding new detector metadata or channel-specific fields requires no schema migration
- Pro: Multi-jurisdiction/multi-channel variability handled without wide tables or excessive junction tables
- Pro: Lower table count (~18-20 tables) compared to fully normalised approach
- Pro: PostgreSQL JSONB is well-supported with GIN indexes, containment operators, and jsonb_path_query
- Pro: Single database technology; no need for separate document store
- Con: JSONB fields are not self-documenting; schema lives in application code, not the database
- Con: No foreign key constraints inside JSONB; referential integrity must be enforced in application
- Con: JSONB index performance degrades for deeply nested structures
- Con: Reporting on JSONB fields requires more complex queries (jsonb_path_query, ->>)
- Con: Risk of "JSONB creep" where too much data moves into JSONB and the relational benefits are lost

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| OCSF | Finding metadata JSONB includes OCSF event class fields; can serialize entire finding to OCSF JSON for SIEM export |
| ISO/IEC 27001:2022 A.8.12 | Policy and audit tables satisfy DLP control requirements; JSONB audit details capture full context |
| NIST SP 800-53 SI-12 | Audit log with JSONB details field captures information handling context without fixed schema |
| GDPR Article 32 | Jurisdiction-specific PII definitions stored in JSONB on sensitive_info_types; adaptable per EU member state |
| PCI DSS v4.0 | PAN detection rules stored relationally; channel-specific enforcement config in JSONB |
| Nightfall API pattern | Detection results use fixed fields (confidence, detector) + variable metadata JSONB, mirroring Nightfall's API response format |
| Microsoft Purview pattern | Sensitivity labels use fixed properties + extensible JSONB custom properties |

---

## Core Platform Tables

```sql
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) NOT NULL UNIQUE,
    subscription_tier VARCHAR(50) NOT NULL DEFAULT 'standard',
    settings        JSONB NOT NULL DEFAULT '{}',
    -- settings example: {
    --   "max_users": 100,
    --   "max_endpoints": 500,
    --   "data_retention_days": 365,
    --   "default_enforcement_mode": "audit",
    --   "jurisdiction": "EU",
    --   "allowed_channels": ["email", "web", "endpoint", "saas", "genai"]
    -- }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           VARCHAR(255) NOT NULL,
    display_name    VARCHAR(255) NOT NULL,
    department      VARCHAR(255),
    risk_score      NUMERIC(5,2) DEFAULT 0.00,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    identity_provider JSONB DEFAULT '{}',
    -- identity_provider example: {
    --   "provider": "okta",
    --   "external_id": "00u1234567",
    --   "groups": ["engineering", "backend-team"],
    --   "mfa_enrolled": true,
    --   "last_sync": "2026-05-19T10:00:00Z"
    -- }
    profile         JSONB DEFAULT '{}',
    -- profile example: {
    --   "job_title": "Senior Engineer",
    --   "location": "London, UK",
    --   "manager_email": "manager@company.com",
    --   "hire_date": "2024-01-15",
    --   "clearance_level": "confidential"
    -- }
    roles           VARCHAR(50)[] NOT NULL DEFAULT '{viewer}',  -- '{admin,analyst,policy_author,viewer}'
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX idx_users_tenant ON users (tenant_id);
CREATE INDEX idx_users_roles ON users USING GIN (roles);
CREATE INDEX idx_users_risk ON users (tenant_id, risk_score DESC);
CREATE INDEX idx_users_idp ON users USING GIN (identity_provider jsonb_path_ops);
```

---

## Content Detection

```sql
CREATE TABLE detectors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,  -- NULL = system-provided
    code            VARCHAR(100) NOT NULL,
    display_name    VARCHAR(255) NOT NULL,
    category        VARCHAR(50) NOT NULL,     -- 'pii','pci','phi','credentials','ip','custom'
    detector_type   VARCHAR(50) NOT NULL,     -- 'regex','keyword','ml_classifier','fingerprint','exact_data_match','multimodal'
    is_system       BOOLEAN NOT NULL DEFAULT false,
    compliance_tags VARCHAR(50)[] DEFAULT '{}',
    config          JSONB NOT NULL DEFAULT '{}',
    -- config varies by detector_type:
    --
    -- regex: {
    --   "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
    --   "flags": "i",
    --   "validation_checksum": "luhn",
    --   "proximity_keywords": ["ssn", "social security"],
    --   "proximity_window": 50
    -- }
    --
    -- ml_classifier: {
    --   "model_name": "pii-ner-v3",
    --   "model_version": "3.2.1",
    --   "artifact_uri": "s3://models/pii-ner-v3/3.2.1/",
    --   "entity_types": ["PERSON", "PHONE", "ADDRESS"],
    --   "confidence_threshold": 0.85
    -- }
    --
    -- fingerprint: {
    --   "source_type": "database",
    --   "fingerprint_hash": "sha256:abc123...",
    --   "column_count": 5,
    --   "row_count": 10000,
    --   "last_refreshed": "2026-05-15T00:00:00Z"
    -- }
    --
    -- multimodal: {
    --   "model_name": "vision-dlp-v2",
    --   "supported_formats": ["png", "jpg", "pdf", "screenshot"],
    --   "ocr_enabled": true,
    --   "confidence_threshold": 0.80
    -- }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_detectors_tenant ON detectors (tenant_id);
CREATE INDEX idx_detectors_category ON detectors (category);
CREATE INDEX idx_detectors_type ON detectors (detector_type);
CREATE INDEX idx_detectors_compliance ON detectors USING GIN (compliance_tags);
```

---

## Policy Management

```sql
CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    status          VARCHAR(20) NOT NULL DEFAULT 'draft',
    enforcement_mode VARCHAR(20) NOT NULL DEFAULT 'audit',
    priority        INTEGER NOT NULL DEFAULT 100,
    channels        VARCHAR(50)[] NOT NULL DEFAULT '{}',  -- '{email,web,endpoint,saas,genai}'
    scope           JSONB NOT NULL DEFAULT '{}',
    -- scope example: {
    --   "include": {
    --     "departments": ["finance", "hr"],
    --     "user_groups": ["contractors"],
    --     "locations": ["US", "EU"]
    --   },
    --   "exclude": {
    --     "users": ["ciso@company.com"],
    --     "departments": ["security"]
    --   }
    -- }
    schedule        JSONB DEFAULT '{}',
    -- schedule example: {
    --   "effective_from": "2026-06-01T00:00:00Z",
    --   "effective_until": null,
    --   "active_hours": {"start": "08:00", "end": "18:00", "timezone": "America/New_York"},
    --   "active_days": ["mon","tue","wed","thu","fri"]
    -- }
    actions         JSONB NOT NULL DEFAULT '[]',
    -- actions example: [
    --   {"type": "block", "config": {}},
    --   {"type": "notify", "config": {"channels": ["email","slack"], "recipients": ["analyst@company.com"]}},
    --   {"type": "quarantine", "config": {"path": "/dlp/quarantine/"}}
    -- ]
    compliance_controls VARCHAR(100)[] DEFAULT '{}',  -- '{gdpr:Art.32,pci_dss:Req.3}'
    created_by      UUID NOT NULL REFERENCES users(id),
    approved_by     UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policies_tenant_status ON policies (tenant_id, status);
CREATE INDEX idx_policies_channels ON policies USING GIN (channels);
CREATE INDEX idx_policies_compliance ON policies USING GIN (compliance_controls);

CREATE TABLE policy_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    logical_operator VARCHAR(10) NOT NULL DEFAULT 'ANY',
    min_findings    INTEGER NOT NULL DEFAULT 1,
    rule_order      INTEGER NOT NULL DEFAULT 0,
    detectors       JSONB NOT NULL DEFAULT '[]',
    -- detectors example: [
    --   {"detector_id": "uuid", "min_confidence": 0.90, "min_count": 1},
    --   {"detector_id": "uuid", "min_confidence": 0.85, "min_count": 3}
    -- ]
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policy_rules ON policy_rules (policy_id, rule_order);
```

---

## Endpoints and Channels

```sql
CREATE TABLE endpoints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname        VARCHAR(255) NOT NULL,
    assigned_user_id UUID REFERENCES users(id),
    agent_status    VARCHAR(20) NOT NULL DEFAULT 'unknown',
    last_heartbeat  TIMESTAMPTZ,
    system_info     JSONB NOT NULL DEFAULT '{}',
    -- system_info example: {
    --   "os_type": "macos",
    --   "os_version": "15.4",
    --   "agent_version": "2.3.1",
    --   "ip_address": "10.0.1.42",
    --   "mac_address": "AA:BB:CC:DD:EE:FF",
    --   "disk_encryption": true,
    --   "mdm_managed": true,
    --   "tags": ["engineering", "london-office"]
    -- }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_endpoints_tenant ON endpoints (tenant_id);
CREATE INDEX idx_endpoints_user ON endpoints (assigned_user_id);
CREATE INDEX idx_endpoints_status ON endpoints (tenant_id, agent_status);

CREATE TABLE integrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    integration_type VARCHAR(50) NOT NULL,    -- 'email_gateway','web_proxy','saas_app','siem','identity_provider','genai_monitor'
    provider        VARCHAR(50) NOT NULL,     -- 'smtp','zscaler','slack','microsoft_365','splunk','okta','openai'
    name            VARCHAR(255) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'inactive',
    config          JSONB NOT NULL DEFAULT '{}',
    -- config varies by integration_type:
    --
    -- email_gateway: {"host": "smtp.company.com", "port": 25, "tls": true, "auth_method": "oauth2"}
    -- saas_app: {"oauth_scopes": ["read","write"], "webhook_url": "https://...", "last_sync": "2026-05-19"}
    -- siem: {"siem_type": "splunk", "hec_url": "https://splunk:8088", "export_format": "ocsf_json"}
    -- genai_monitor: {"providers": ["openai","anthropic"], "inspect_prompts": true, "inspect_responses": true}
    credentials_enc BYTEA,                    -- encrypted credentials blob
    last_sync_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_integrations_tenant ON integrations (tenant_id, integration_type);
```

---

## Findings

```sql
CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    policy_id       UUID NOT NULL REFERENCES policies(id),
    rule_id         UUID NOT NULL REFERENCES policy_rules(id),
    user_id         UUID REFERENCES users(id),
    endpoint_id     UUID REFERENCES endpoints(id),

    -- Core relational fields (always present, always queried)
    channel         VARCHAR(50) NOT NULL,     -- 'email','web','endpoint','saas','genai'
    matched_type    VARCHAR(100) NOT NULL,    -- detector code: 'CREDIT_CARD','SSN_US', etc.
    category        VARCHAR(50) NOT NULL,     -- 'pii','pci','phi','credentials','ip'
    confidence      NUMERIC(3,2) NOT NULL,
    match_count     INTEGER NOT NULL DEFAULT 1,
    severity        VARCHAR(20) NOT NULL,     -- 'info','low','medium','high','critical'
    action_taken    VARCHAR(30) NOT NULL,     -- 'blocked','warned','logged','quarantined','encrypted'
    content_hash    BYTEA,                    -- SHA-256 for dedup
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Channel-specific and detection metadata in JSONB
    detection_details JSONB NOT NULL DEFAULT '{}',
    -- detection_details example (email finding): {
    --   "source_type": "email",
    --   "message_id": "abc123@company.com",
    --   "from": "user@company.com",
    --   "to": ["external@partner.com"],
    --   "subject": "Q3 Financial Report",
    --   "attachment_name": "report.xlsx",
    --   "match_locations": [
    --     {"byte_start": 1024, "byte_end": 1040, "snippet": "****-****-****-4242"}
    --   ],
    --   "ocsf": {"category_uid": 4, "class_uid": 4003, "severity_id": 4, "activity_id": 2}
    -- }
    --
    -- detection_details example (GenAI finding): {
    --   "source_type": "genai_api",
    --   "provider": "openai",
    --   "model": "gpt-4",
    --   "prompt_snippet": "Here is the customer database...",
    --   "direction": "outbound",
    --   "api_endpoint": "https://api.openai.com/v1/chat/completions",
    --   "match_locations": [
    --     {"byte_start": 100, "byte_end": 130, "snippet": "SSN: ***-**-1234"}
    --   ]
    -- }
    --
    -- detection_details example (endpoint finding): {
    --   "source_type": "endpoint",
    --   "file_path": "/Users/jdoe/Downloads/customer_list.csv",
    --   "application": "Chrome",
    --   "transfer_method": "file_upload",
    --   "destination_url": "https://external-service.com/upload",
    --   "file_size_bytes": 2048000
    -- }

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_tenant_time ON findings (tenant_id, detected_at DESC);
CREATE INDEX idx_findings_policy ON findings (policy_id, detected_at DESC);
CREATE INDEX idx_findings_user ON findings (user_id, detected_at DESC);
CREATE INDEX idx_findings_severity ON findings (tenant_id, severity, detected_at DESC);
CREATE INDEX idx_findings_category ON findings (tenant_id, category, detected_at DESC);
CREATE INDEX idx_findings_channel ON findings (tenant_id, channel, detected_at DESC);
CREATE INDEX idx_findings_hash ON findings (content_hash);
CREATE INDEX idx_findings_details ON findings USING GIN (detection_details jsonb_path_ops);
```

### Example JSONB Queries on Findings

```sql
-- Find all GenAI-related findings (any provider)
SELECT * FROM findings
WHERE tenant_id = 'tenant-uuid'
  AND channel = 'genai'
  AND detected_at >= now() - INTERVAL '7 days'
ORDER BY detected_at DESC;

-- Find findings where data was sent to a specific external domain
SELECT * FROM findings
WHERE tenant_id = 'tenant-uuid'
  AND detection_details @> '{"to": ["external@partner.com"]}'
ORDER BY detected_at DESC;

-- Find endpoint findings involving USB transfers
SELECT * FROM findings
WHERE tenant_id = 'tenant-uuid'
  AND channel = 'endpoint'
  AND detection_details->>'transfer_method' = 'usb_copy'
ORDER BY detected_at DESC;

-- Aggregate findings by GenAI provider
SELECT
    detection_details->>'provider' AS ai_provider,
    COUNT(*) AS finding_count,
    AVG(confidence) AS avg_confidence
FROM findings
WHERE tenant_id = 'tenant-uuid'
  AND channel = 'genai'
  AND detected_at >= now() - INTERVAL '30 days'
GROUP BY detection_details->>'provider';
```

---

## Incidents

```sql
CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL,
    status          VARCHAR(30) NOT NULL DEFAULT 'open',
    assigned_to     UUID REFERENCES users(id),
    finding_ids     UUID[] NOT NULL DEFAULT '{}',  -- array of finding UUIDs
    resolution      JSONB DEFAULT '{}',
    -- resolution example: {
    --   "notes": "False positive - test data in staging environment",
    --   "action_taken": "false_positive",
    --   "resolved_by": "user-uuid",
    --   "resolved_at": "2026-05-19T14:30:00Z",
    --   "policy_updated": true,
    --   "policy_change": "Added staging environment to exclusion list"
    -- }
    timeline        JSONB NOT NULL DEFAULT '[]',
    -- timeline example: [
    --   {"at": "2026-05-19T10:00:00Z", "event": "created", "actor": "system"},
    --   {"at": "2026-05-19T10:05:00Z", "event": "assigned", "actor": "user-uuid", "assigned_to": "analyst-uuid"},
    --   {"at": "2026-05-19T11:00:00Z", "event": "commented", "actor": "analyst-uuid", "comment": "Investigating..."},
    --   {"at": "2026-05-19T14:30:00Z", "event": "resolved", "actor": "analyst-uuid", "resolution": "false_positive"}
    -- ]
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_incidents_tenant_status ON incidents (tenant_id, status, severity);
CREATE INDEX idx_incidents_assignee ON incidents (assigned_to, status);
CREATE INDEX idx_incidents_findings ON incidents USING GIN (finding_ids);
```

---

## Audit and Compliance

```sql
CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    actor_id        UUID,
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(50) NOT NULL,
    resource_id     UUID,
    details         JSONB NOT NULL DEFAULT '{}',
    -- details example: {
    --   "actor_ip": "10.0.1.42",
    --   "actor_email": "admin@company.com",
    --   "changes": {"status": {"from": "draft", "to": "active"}},
    --   "user_agent": "Mozilla/5.0..."
    -- }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_tenant_time ON audit_log (tenant_id, created_at DESC);
CREATE INDEX idx_audit_actor ON audit_log (actor_id, created_at DESC);
CREATE INDEX idx_audit_resource ON audit_log (resource_type, resource_id);

CREATE TABLE compliance_reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    framework       VARCHAR(50) NOT NULL,     -- 'gdpr','hipaa','pci_dss_v4','iso_27001'
    report_period   TSTZRANGE NOT NULL,       -- [start, end) date range
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    generated_by    UUID NOT NULL REFERENCES users(id),
    summary         JSONB NOT NULL,
    -- summary example: {
    --   "total_findings": 1247,
    --   "findings_by_severity": {"critical": 3, "high": 45, "medium": 189, "low": 510, "info": 500},
    --   "findings_by_category": {"pii": 800, "pci": 200, "phi": 100, "credentials": 147},
    --   "active_policies": 12,
    --   "controls_covered": ["A.8.12", "SI-12"],
    --   "compliance_score": 94.5,
    --   "top_violations": [
    --     {"type": "SSN_US", "count": 340, "trend": "decreasing"},
    --     {"type": "CREDIT_CARD", "count": 200, "trend": "stable"}
    --   ]
    -- }
    report_file_uri TEXT                      -- S3/GCS path to full PDF report
);

CREATE INDEX idx_compliance_reports ON compliance_reports (tenant_id, framework, generated_at DESC);
```

---

## API Clients and Webhooks

```sql
CREATE TABLE api_clients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    client_id       VARCHAR(100) NOT NULL UNIQUE,
    client_secret_hash BYTEA NOT NULL,
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    rate_limit_rpm  INTEGER NOT NULL DEFAULT 600,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    metadata        JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);

CREATE TABLE webhooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    url             TEXT NOT NULL,
    secret_hash     BYTEA NOT NULL,
    event_types     VARCHAR(100)[] NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    config          JSONB DEFAULT '{}',
    -- config example: {"retry_count": 3, "timeout_ms": 5000, "headers": {"X-Custom": "value"}}
    last_triggered  TIMESTAMPTZ,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## Row-Level Security

```sql
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON findings
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
CREATE POLICY tenant_isolation ON policies
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
CREATE POLICY tenant_isolation ON incidents
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Core Platform | 2 | tenants, users |
| Content Detection | 1 | detectors (unified with JSONB config per type) |
| Policy Management | 2 | policies, policy_rules |
| Endpoints & Integrations | 2 | endpoints, integrations |
| Findings | 1 | findings (channel-specific details in JSONB) |
| Incidents | 1 | incidents (timeline and resolution in JSONB) |
| Audit & Compliance | 2 | audit_log, compliance_reports |
| API & Webhooks | 2 | api_clients, webhooks |
| **Total** | **13** | |

---

## Key Design Decisions

1. **Unified detectors table with JSONB config.** Instead of separate tables for regex detectors, ML classifiers, and fingerprints (as in the normalised model), all detector types share one table with a discriminator column (detector_type) and a JSONB config field. This reduces table count from 3 to 1 and makes adding new detector types trivial.

2. **Policy scope, schedule, and actions in JSONB.** These are complex, variable structures that differ per organisation. Storing them as JSONB avoids the need for policy_scope_targets, policy_actions, and policy_schedule tables. The trade-off is that the database cannot enforce constraints on these structures; validation happens in the application layer.

3. **Channel-specific finding metadata in JSONB.** An email finding has different metadata (message_id, from, to, subject) than an endpoint finding (file_path, application, transfer_method) or a GenAI finding (provider, model, prompt_snippet). The detection_details JSONB column handles this variability without requiring separate finding_email, finding_endpoint, and finding_genai tables.

4. **Incident timeline as JSONB array.** Rather than a separate incident_timeline table, the timeline is stored as a JSONB array within the incident. This works well for incidents with fewer than ~100 timeline events (typical for DLP incidents) and eliminates a JOIN for the most common query pattern (fetch incident with timeline).

5. **Findings linked to incidents via UUID array.** The finding_ids UUID[] column on incidents replaces a junction table. GIN indexing makes "find all incidents containing this finding" queries efficient. The trade-off is that foreign key constraints are not enforced; application code must maintain consistency.

6. **Roles as PostgreSQL array.** Instead of separate roles, permissions, user_roles, and role_permissions tables, user roles are stored as a VARCHAR[] array. This works well for a simple RBAC model with a fixed set of roles (admin, analyst, policy_author, viewer). If role definitions need to become dynamic or granular, this should be refactored to a normalised RBAC model.

7. **Compliance reports as materialised snapshots.** Rather than computing compliance status from live data every time, compliance_reports stores point-in-time snapshots with JSONB summary data. This provides historical compliance trending and eliminates the need to re-query findings for past periods.

8. **GIN indexes on all JSONB columns.** Every JSONB column that will be queried has a GIN index with jsonb_path_ops for efficient containment queries (@>). This is the key to making JSONB queries performant at scale.
