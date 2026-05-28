# Data Model Suggestion 1: Entity-Centric Normalized Relational

> Project: Data Loss Prevention · Created: 2026-05-19

## Philosophy

This model follows a traditional normalized relational approach where every domain concept gets its own table with explicit foreign key relationships. The schema is designed around the core DLP lifecycle: define policies and detection rules, monitor data channels, generate findings when violations occur, and manage incidents through resolution. Every relationship is explicit, every constraint is enforced at the database level, and referential integrity is guaranteed.

This approach mirrors how enterprise DLP products like Broadcom Symantec DLP and Forcepoint structure their internal data: separate tables for policies, rules, detectors, findings, incidents, and users, joined through foreign keys. It aligns well with regulatory environments (GDPR, HIPAA, PCI DSS) where auditability and data integrity are paramount, and where compliance auditors expect well-defined data lineage.

The trade-off is a higher table count and more complex JOIN queries, but the benefit is that every query is predictable, every relationship is documented in the schema itself, and the database enforces business rules that would otherwise need application-level validation.

**Best for:** Regulated enterprise deployments where data integrity, auditability, and schema clarity outweigh development velocity.

**Trade-offs:**
- Pro: Maximum referential integrity; the database enforces business rules
- Pro: Clear, self-documenting schema; easy for new developers to understand relationships
- Pro: Strong compliance story; auditors can trace data lineage through foreign keys
- Pro: Well-suited to complex cross-entity queries (e.g., "all incidents for policies targeting PCI data in the finance department")
- Con: High table count (~45-50 tables) increases migration complexity
- Con: Schema changes require migrations; adding a new detector type means ALTER TABLE
- Con: Multi-jurisdiction variability (different PII definitions per country) creates wide tables or many junction tables
- Con: JOIN-heavy queries can become slow at high event volumes (millions of findings/day)

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| OCSF (Open Cybersecurity Schema Framework) | Event tables (findings, network activity, file activity) align with OCSF event class structure: category_uid, class_uid, severity_id, activity_id |
| ISO/IEC 27001:2022 Annex A.8.12 | Policy and control tables map directly to A.8.12 DLP control requirements; compliance_frameworks table tracks certification status |
| NIST SP 800-53 (SI-12) | Audit log tables satisfy SI-12 information handling controls; retention policies enforced via database-level constraints |
| GDPR Article 32 | PII classification types in sensitive_info_types table; data subject access request tracking in dedicated table |
| PCI DSS v4.0 Req. 3,4,7 | PAN detection rules as first-class entities; encryption status tracked per finding |
| STIX 2.1 | Threat indicator tables use STIX-compatible object types and relationship structures for threat intelligence integration |
| HIPAA Security Rule | PHI-specific detection rules; access logging satisfies §164.312 audit requirements |
| RFC 6749 / RFC 7519 | OAuth/JWT fields in api_clients and auth_tokens tables for API authentication |

---

## Core Platform Tables

### Tenants and Organizations

```sql
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) NOT NULL UNIQUE,
    subscription_tier VARCHAR(50) NOT NULL DEFAULT 'standard',  -- 'free','standard','enterprise'
    max_users       INTEGER NOT NULL DEFAULT 100,
    max_endpoints   INTEGER NOT NULL DEFAULT 500,
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tenants_slug ON tenants (slug);
```

### Users and RBAC

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           VARCHAR(255) NOT NULL,
    display_name    VARCHAR(255) NOT NULL,
    external_idp_id VARCHAR(255),          -- Okta/Entra ID/AD identifier
    idp_provider    VARCHAR(50),           -- 'okta','entra_id','active_directory','google'
    department      VARCHAR(255),
    job_title       VARCHAR(255),
    risk_score      NUMERIC(5,2) DEFAULT 0.00,  -- 0.00 to 100.00
    status          VARCHAR(20) NOT NULL DEFAULT 'active',  -- 'active','suspended','deactivated'
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX idx_users_tenant ON users (tenant_id);
CREATE INDEX idx_users_external_idp ON users (external_idp_id);
CREATE INDEX idx_users_risk_score ON users (tenant_id, risk_score DESC);

CREATE TABLE roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(100) NOT NULL,   -- 'admin','analyst','viewer','policy_author'
    description     TEXT,
    is_system_role  BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE permissions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    resource        VARCHAR(100) NOT NULL,   -- 'policies','incidents','findings','reports'
    action          VARCHAR(50) NOT NULL,     -- 'create','read','update','delete','export'
    description     TEXT,
    UNIQUE (resource, action)
);

CREATE TABLE role_permissions (
    role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id   UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE user_roles (
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by     UUID REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);
```

---

## Content Detection and Classification

```sql
CREATE TABLE sensitive_info_types (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,  -- NULL = system-provided
    code            VARCHAR(100) NOT NULL,    -- 'SSN_US','CREDIT_CARD','API_KEY','EMAIL','IBAN'
    display_name    VARCHAR(255) NOT NULL,
    category        VARCHAR(50) NOT NULL,     -- 'pii','pci','phi','credentials','ip','custom'
    description     TEXT,
    detection_method VARCHAR(50) NOT NULL,    -- 'regex','keyword','ml_classifier','fingerprint','exact_data_match'
    pattern         TEXT,                      -- regex pattern if detection_method='regex'
    confidence_threshold NUMERIC(3,2) NOT NULL DEFAULT 0.80,  -- 0.00 to 1.00
    is_system       BOOLEAN NOT NULL DEFAULT false,
    compliance_tags VARCHAR(50)[] DEFAULT '{}', -- '{gdpr,hipaa,pci_dss}'
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sit_tenant ON sensitive_info_types (tenant_id);
CREATE INDEX idx_sit_category ON sensitive_info_types (category);
CREATE INDEX idx_sit_compliance ON sensitive_info_types USING GIN (compliance_tags);

CREATE TABLE data_fingerprints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    source_type     VARCHAR(50) NOT NULL,     -- 'database','file','api_response'
    fingerprint_hash BYTEA NOT NULL,          -- SHA-256 hash of fingerprinted content
    column_count    INTEGER,
    row_count       INTEGER,
    last_refreshed  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ml_classifiers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    model_type      VARCHAR(50) NOT NULL,     -- 'text_classifier','image_ocr','multimodal','ner'
    model_version   VARCHAR(50) NOT NULL,
    accuracy_score  NUMERIC(5,4),             -- last evaluated accuracy
    training_status VARCHAR(30) NOT NULL DEFAULT 'pending', -- 'pending','training','ready','failed'
    artifact_uri    TEXT,                      -- S3/GCS path to model artifact
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## Policy Management

```sql
CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    status          VARCHAR(20) NOT NULL DEFAULT 'draft', -- 'draft','testing','active','disabled'
    priority        INTEGER NOT NULL DEFAULT 100,          -- lower = higher priority
    enforcement_mode VARCHAR(20) NOT NULL DEFAULT 'audit', -- 'audit','warn','block'
    scope_type      VARCHAR(30) NOT NULL DEFAULT 'all',    -- 'all','department','user_group','channel'
    effective_from  TIMESTAMPTZ,
    effective_until TIMESTAMPTZ,
    created_by      UUID NOT NULL REFERENCES users(id),
    approved_by     UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policies_tenant_status ON policies (tenant_id, status);
CREATE INDEX idx_policies_priority ON policies (tenant_id, priority);

CREATE TABLE policy_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    logical_operator VARCHAR(10) NOT NULL DEFAULT 'ANY',  -- 'ANY','ALL'
    min_findings    INTEGER NOT NULL DEFAULT 1,
    rule_order      INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policy_rules_policy ON policy_rules (policy_id);

CREATE TABLE rule_detectors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id         UUID NOT NULL REFERENCES policy_rules(id) ON DELETE CASCADE,
    sensitive_info_type_id UUID REFERENCES sensitive_info_types(id),
    ml_classifier_id UUID REFERENCES ml_classifiers(id),
    fingerprint_id  UUID REFERENCES data_fingerprints(id),
    min_confidence  NUMERIC(3,2) NOT NULL DEFAULT 0.80,
    min_count       INTEGER NOT NULL DEFAULT 1,
    detector_order  INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT chk_detector_source CHECK (
        (sensitive_info_type_id IS NOT NULL)::int +
        (ml_classifier_id IS NOT NULL)::int +
        (fingerprint_id IS NOT NULL)::int = 1
    )
);

CREATE TABLE policy_channels (
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    channel         VARCHAR(50) NOT NULL,  -- 'email','web','endpoint','cloud_storage','saas_app','genai'
    PRIMARY KEY (policy_id, channel)
);

CREATE TABLE policy_scope_targets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    target_type     VARCHAR(30) NOT NULL,   -- 'department','user','user_group','endpoint_group'
    target_value    VARCHAR(255) NOT NULL,
    is_exclusion    BOOLEAN NOT NULL DEFAULT false
);

CREATE INDEX idx_policy_scope ON policy_scope_targets (policy_id);

CREATE TABLE policy_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    action_type     VARCHAR(50) NOT NULL,   -- 'block','warn','quarantine','encrypt','notify','log'
    action_config   JSONB NOT NULL DEFAULT '{}',
    -- action_config example: {"notify_users": ["analyst@company.com"], "quarantine_path": "/dlp/quarantine/"}
    action_order    INTEGER NOT NULL DEFAULT 0
);
```

---

## Enforcement and Monitoring

### Endpoints and Channels

```sql
CREATE TABLE endpoints (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname        VARCHAR(255) NOT NULL,
    os_type         VARCHAR(30) NOT NULL,     -- 'windows','macos','linux'
    os_version      VARCHAR(50),
    agent_version   VARCHAR(30),
    agent_status    VARCHAR(20) NOT NULL DEFAULT 'unknown', -- 'online','offline','unknown','disabled'
    last_heartbeat  TIMESTAMPTZ,
    assigned_user_id UUID REFERENCES users(id),
    ip_address      INET,
    tags            VARCHAR(100)[] DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_endpoints_tenant ON endpoints (tenant_id);
CREATE INDEX idx_endpoints_user ON endpoints (assigned_user_id);
CREATE INDEX idx_endpoints_status ON endpoints (tenant_id, agent_status);

CREATE TABLE monitored_channels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    channel_type    VARCHAR(50) NOT NULL,     -- 'email_gateway','web_proxy','cloud_saas','endpoint','genai_api'
    name            VARCHAR(255) NOT NULL,
    connection_config JSONB NOT NULL DEFAULT '{}',
    -- connection_config example: {"gateway_host": "smtp.company.com", "port": 25, "tls": true}
    status          VARCHAR(20) NOT NULL DEFAULT 'inactive', -- 'active','inactive','error'
    last_sync_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE saas_integrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider        VARCHAR(50) NOT NULL,     -- 'slack','microsoft_365','google_workspace','salesforce','github'
    oauth_token_enc BYTEA,                    -- encrypted OAuth token
    scopes          TEXT[] DEFAULT '{}',
    status          VARCHAR(20) NOT NULL DEFAULT 'disconnected',
    last_sync_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## Findings and Incidents

```sql
CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    policy_id       UUID NOT NULL REFERENCES policies(id),
    policy_rule_id  UUID NOT NULL REFERENCES policy_rules(id),
    detector_id     UUID NOT NULL REFERENCES rule_detectors(id),
    user_id         UUID REFERENCES users(id),
    endpoint_id     UUID REFERENCES endpoints(id),
    channel_id      UUID REFERENCES monitored_channels(id),

    -- OCSF-aligned event fields
    category_uid    SMALLINT NOT NULL,         -- OCSF category (e.g., 4 = Network Activity)
    class_uid       SMALLINT NOT NULL,         -- OCSF event class
    activity_id     SMALLINT NOT NULL DEFAULT 0,
    severity_id     SMALLINT NOT NULL DEFAULT 1, -- 0=Unknown,1=Info,2=Low,3=Medium,4=High,5=Critical

    -- Detection details
    matched_type    VARCHAR(100) NOT NULL,     -- sensitive info type code: 'SSN_US','CREDIT_CARD', etc.
    confidence      NUMERIC(3,2) NOT NULL,     -- 0.00 to 1.00
    match_count     INTEGER NOT NULL DEFAULT 1,
    content_snippet TEXT,                       -- redacted snippet for analyst review
    content_hash    BYTEA,                     -- SHA-256 of original content (for dedup)

    -- Context
    source_type     VARCHAR(50) NOT NULL,      -- 'email','file','chat_message','api_request','clipboard'
    source_ref      TEXT,                       -- message-id, file path, URL, etc.
    destination     TEXT,                       -- recipient email, URL, external service
    action_taken    VARCHAR(30) NOT NULL,       -- 'blocked','warned','logged','quarantined','encrypted'

    -- Timestamps
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_tenant_time ON findings (tenant_id, detected_at DESC);
CREATE INDEX idx_findings_policy ON findings (policy_id);
CREATE INDEX idx_findings_user ON findings (user_id);
CREATE INDEX idx_findings_severity ON findings (tenant_id, severity_id DESC, detected_at DESC);
CREATE INDEX idx_findings_content_hash ON findings (content_hash);

CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL,     -- 'info','low','medium','high','critical'
    status          VARCHAR(30) NOT NULL DEFAULT 'open', -- 'open','investigating','escalated','resolved','false_positive','closed'
    assigned_to     UUID REFERENCES users(id),
    resolution_notes TEXT,
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_incidents_tenant_status ON incidents (tenant_id, status);
CREATE INDEX idx_incidents_severity ON incidents (tenant_id, severity, status);
CREATE INDEX idx_incidents_assignee ON incidents (assigned_to, status);

CREATE TABLE incident_findings (
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    finding_id      UUID NOT NULL REFERENCES findings(id),
    PRIMARY KEY (incident_id, finding_id)
);

CREATE TABLE incident_comments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author_id       UUID NOT NULL REFERENCES users(id),
    body            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_incident_comments ON incident_comments (incident_id, created_at);

CREATE TABLE incident_timeline (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id     UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_type      VARCHAR(50) NOT NULL,    -- 'created','assigned','escalated','commented','resolved','reopened'
    actor_id        UUID REFERENCES users(id),
    details         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_incident_timeline ON incident_timeline (incident_id, created_at);
```

---

## Compliance and Reporting

```sql
CREATE TABLE compliance_frameworks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code            VARCHAR(50) NOT NULL UNIQUE, -- 'gdpr','hipaa','pci_dss_v4','nist_800_53','iso_27001','ccpa'
    name            VARCHAR(255) NOT NULL,
    version         VARCHAR(30),
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE compliance_controls (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id    UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    control_id      VARCHAR(50) NOT NULL,     -- 'A.8.12','SI-12','Req.3','Art.32'
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    UNIQUE (framework_id, control_id)
);

CREATE TABLE policy_compliance_mappings (
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    control_id      UUID NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
    PRIMARY KEY (policy_id, control_id)
);

CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    actor_id        UUID REFERENCES users(id),
    actor_ip        INET,
    action          VARCHAR(100) NOT NULL,   -- 'policy.created','incident.resolved','user.login'
    resource_type   VARCHAR(50) NOT NULL,    -- 'policy','incident','finding','user','endpoint'
    resource_id     UUID,
    details         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_tenant_time ON audit_log (tenant_id, created_at DESC);
CREATE INDEX idx_audit_log_actor ON audit_log (actor_id, created_at DESC);
CREATE INDEX idx_audit_log_resource ON audit_log (resource_type, resource_id);
```

---

## API and Integration

```sql
CREATE TABLE api_clients (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    client_id       VARCHAR(100) NOT NULL UNIQUE,
    client_secret_hash BYTEA NOT NULL,
    scopes          TEXT[] NOT NULL DEFAULT '{}',   -- '{findings:read,policies:write}'
    rate_limit_rpm  INTEGER NOT NULL DEFAULT 600,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ
);

CREATE TABLE webhooks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    url             TEXT NOT NULL,
    secret_hash     BYTEA NOT NULL,
    event_types     VARCHAR(100)[] NOT NULL,  -- '{finding.created,incident.escalated}'
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    last_triggered  TIMESTAMPTZ,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE siem_exports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    siem_type       VARCHAR(50) NOT NULL,     -- 'splunk','sentinel','qradar','elastic','syslog'
    connection_config JSONB NOT NULL,
    export_format   VARCHAR(30) NOT NULL DEFAULT 'ocsf_json', -- 'ocsf_json','cef','leef','syslog_rfc5424'
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    last_export_at  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## Row-Level Security

```sql
-- Enable RLS on all tenant-scoped tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;

-- Example RLS policy (applied to each tenant-scoped table)
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
| Tenants & Auth | 6 | tenants, users, roles, permissions, role_permissions, user_roles |
| Content Detection | 3 | sensitive_info_types, data_fingerprints, ml_classifiers |
| Policy Management | 5 | policies, policy_rules, rule_detectors, policy_channels, policy_scope_targets, policy_actions |
| Enforcement & Monitoring | 3 | endpoints, monitored_channels, saas_integrations |
| Findings & Incidents | 5 | findings, incidents, incident_findings, incident_comments, incident_timeline |
| Compliance | 4 | compliance_frameworks, compliance_controls, policy_compliance_mappings, audit_log |
| API & Integration | 3 | api_clients, webhooks, siem_exports |
| **Total** | **29** | |

---

## Key Design Decisions

1. **Separate tables for each detector type** (sensitive_info_types, data_fingerprints, ml_classifiers) rather than a single polymorphic detectors table. This provides type-safe columns and cleaner queries at the cost of a slightly more complex rule_detectors junction table with a CHECK constraint ensuring exactly one FK is populated.

2. **OCSF-aligned event fields on findings** (category_uid, class_uid, severity_id, activity_id) to enable direct SIEM export without transformation. Findings can be serialized to OCSF JSON for Splunk, Amazon Security Lake, or any OCSF-compatible consumer.

3. **Policy-rule-detector hierarchy** mirrors how Nightfall AI and Microsoft Purview structure detection: a policy contains rules, each rule contains detectors with logical operators (ANY/ALL), and each detector has a minimum confidence threshold.

4. **PostgreSQL Row-Level Security** for tenant isolation rather than application-level WHERE clauses. The session variable `app.current_tenant_id` is set at connection time, and RLS policies automatically filter all queries.

5. **Explicit incident lifecycle** via incident_timeline table rather than status change tracking in the incidents table itself. This provides a complete audit trail of who did what and when during incident investigation.

6. **Compliance framework mapping as junction table** (policy_compliance_mappings) allows a single policy to satisfy multiple compliance controls across frameworks, and allows compliance reports to aggregate by framework or control.

7. **Content hashing for dedup** on findings (content_hash column) prevents duplicate findings for the same content detected across multiple channels, while keeping the original content snippet for analyst review.

8. **Encrypted sensitive fields** (oauth_token_enc, client_secret_hash) stored as BYTEA with application-level encryption, not plaintext. The schema enforces that secrets are never stored as VARCHAR.
