# Data Model Suggestion 2: Event-Sourced / Audit-First (CQRS)

> Project: Data Loss Prevention · Created: 2026-05-19

## Philosophy

This model treats every state change in the DLP system as an immutable event appended to an event store. The event log is the single source of truth; all queryable state (policies, incidents, user risk scores, compliance dashboards) is derived by replaying or projecting events into materialised read models. This follows the Command Query Responsibility Segregation (CQRS) pattern where writes go to the event store and reads come from purpose-built projections.

DLP is fundamentally an audit-centric domain. Regulators ask "what was the policy configuration when this violation occurred three months ago?" and "show me every action taken on this incident." In a traditional relational model, answering these questions requires separate audit tables or temporal columns. In an event-sourced model, the answer is inherent: replay the event stream to any point in time. Major investment banks use event sourcing for trade compliance for exactly this reason. The OCSF framework itself is event-oriented, making event sourcing a natural fit for DLP telemetry.

The trade-off is architectural complexity: the team must understand event sourcing, maintain projections, and handle eventual consistency between the event store and read models. But for a DLP platform where every action must be auditable, tamper-evident, and replayable, event sourcing provides guarantees that are expensive to retrofit onto a traditional schema.

**Best for:** Deployments where complete audit trails, temporal queries, and regulatory compliance are the primary requirements, and where the team has event-sourcing experience.

**Trade-offs:**
- Pro: Complete, tamper-evident audit trail by construction; no separate audit tables needed
- Pro: Temporal queries are trivial: replay to any point in time
- Pro: Natural fit for OCSF event-oriented telemetry
- Pro: New read models can be built from existing events without data migration
- Pro: Enables AI/ML training on historical event streams for pattern detection
- Con: Higher architectural complexity; requires understanding of event sourcing and CQRS
- Con: Eventual consistency between event store and read projections
- Con: Event schema evolution (versioning) must be handled carefully
- Con: Read model rebuilds can be slow for large event volumes
- Con: Debugging requires understanding both the event log and projected state

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| OCSF | Events natively align with OCSF event classes; each DLP event carries category_uid, class_uid, severity_id as first-class fields |
| ISO/IEC 27001:2022 A.8.12 | The immutable event log directly satisfies audit trail requirements for DLP controls |
| NIST SP 800-53 SI-12 | Information handling events are immutable and cannot be altered retroactively |
| GDPR Article 32 | Event store provides tamper-evident record of all data protection measures taken |
| PCI DSS v4.0 | Immutable event log satisfies cardholder data access logging requirements |
| HIPAA §164.312 | Complete event history satisfies audit log requirements for PHI access and transmission |
| STIX 2.1 | Threat intelligence events stored in the same event stream for correlation |

---

## Event Store (Source of Truth)

```sql
-- The single append-only event store. ALL state changes flow through here.
CREATE TABLE events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    stream_id       UUID NOT NULL,            -- aggregate root ID (policy_id, incident_id, user_id, etc.)
    stream_type     VARCHAR(50) NOT NULL,      -- 'policy','incident','finding','user','endpoint','channel'
    event_type      VARCHAR(100) NOT NULL,     -- 'PolicyCreated','PolicyRuleAdded','FindingDetected','IncidentOpened'
    event_version   INTEGER NOT NULL,          -- schema version for this event type (for evolution)
    sequence_num    BIGINT NOT NULL,           -- per-stream sequence number (optimistic concurrency)
    payload         JSONB NOT NULL,            -- event-specific data
    metadata        JSONB NOT NULL DEFAULT '{}',
    -- metadata example: {"actor_id": "uuid", "actor_ip": "1.2.3.4", "correlation_id": "uuid", "causation_id": "uuid"}
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Optimistic concurrency: no two events in the same stream can share a sequence number
    UNIQUE (stream_id, sequence_num)
);

-- Partition by month for performance at scale
-- CREATE TABLE events_2026_05 PARTITION OF events FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE INDEX idx_events_tenant_time ON events (tenant_id, created_at DESC);
CREATE INDEX idx_events_stream ON events (stream_id, sequence_num);
CREATE INDEX idx_events_type ON events (event_type, created_at DESC);
CREATE INDEX idx_events_payload ON events USING GIN (payload jsonb_path_ops);
```

### Example Event Payloads

```sql
-- PolicyCreated event
-- payload: {
--   "name": "PCI Card Data Protection",
--   "description": "Block credit card numbers in email and web",
--   "enforcement_mode": "block",
--   "channels": ["email", "web"],
--   "created_by": "user-uuid"
-- }

-- PolicyRuleAdded event
-- payload: {
--   "rule_name": "Credit Card Detection",
--   "logical_operator": "ANY",
--   "detectors": [
--     {"type": "sensitive_info_type", "code": "CREDIT_CARD", "min_confidence": 0.90, "min_count": 1},
--     {"type": "sensitive_info_type", "code": "PAN_PARTIAL", "min_confidence": 0.85, "min_count": 3}
--   ]
-- }

-- FindingDetected event
-- payload: {
--   "policy_id": "uuid",
--   "rule_id": "uuid",
--   "user_id": "uuid",
--   "channel": "email",
--   "matched_type": "CREDIT_CARD",
--   "confidence": 0.95,
--   "match_count": 2,
--   "content_snippet": "[REDACTED]...4242",
--   "source_ref": "message-id:abc@example.com",
--   "destination": "external@partner.com",
--   "action_taken": "blocked",
--   "ocsf": {"category_uid": 4, "class_uid": 4003, "severity_id": 4, "activity_id": 2}
-- }

-- IncidentEscalated event
-- payload: {
--   "from_status": "investigating",
--   "to_status": "escalated",
--   "escalated_to": "user-uuid",
--   "reason": "Multiple PCI violations from same user within 24 hours"
-- }

-- UserRiskScoreUpdated event
-- payload: {
--   "previous_score": 15.50,
--   "new_score": 42.30,
--   "factors": ["3 findings in 24h", "external destination", "after-hours activity"]
-- }
```

---

## Materialised Read Models (Projections)

These tables are rebuilt from events. They can be dropped and rebuilt at any time.

### Policy Read Model

```sql
CREATE TABLE rm_policies (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    status          VARCHAR(20) NOT NULL,
    enforcement_mode VARCHAR(20) NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 100,
    channels        VARCHAR(50)[] DEFAULT '{}',
    rule_count      INTEGER NOT NULL DEFAULT 0,
    created_by      UUID NOT NULL,
    approved_by     UUID,
    effective_from  TIMESTAMPTZ,
    effective_until TIMESTAMPTZ,
    last_event_seq  BIGINT NOT NULL,          -- last processed event sequence
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_rm_policies_tenant ON rm_policies (tenant_id, status);

CREATE TABLE rm_policy_rules (
    id              UUID PRIMARY KEY,
    policy_id       UUID NOT NULL REFERENCES rm_policies(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    logical_operator VARCHAR(10) NOT NULL,
    detectors       JSONB NOT NULL,           -- denormalized detector config for fast evaluation
    min_findings    INTEGER NOT NULL DEFAULT 1,
    rule_order      INTEGER NOT NULL DEFAULT 0
);
```

### Findings Read Model

```sql
CREATE TABLE rm_findings (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    policy_id       UUID NOT NULL,
    policy_name     VARCHAR(255),             -- denormalized for dashboard queries
    user_id         UUID,
    user_email      VARCHAR(255),             -- denormalized
    user_department VARCHAR(255),             -- denormalized
    endpoint_id     UUID,
    channel         VARCHAR(50) NOT NULL,
    matched_type    VARCHAR(100) NOT NULL,
    category        VARCHAR(50) NOT NULL,     -- 'pii','pci','phi','credentials','ip'
    confidence      NUMERIC(3,2) NOT NULL,
    match_count     INTEGER NOT NULL DEFAULT 1,
    severity_id     SMALLINT NOT NULL,
    action_taken    VARCHAR(30) NOT NULL,
    source_ref      TEXT,
    destination     TEXT,
    incident_id     UUID,                     -- populated when finding is linked to incident
    detected_at     TIMESTAMPTZ NOT NULL
);

-- Heavily indexed for dashboard queries
CREATE INDEX idx_rm_findings_tenant_time ON rm_findings (tenant_id, detected_at DESC);
CREATE INDEX idx_rm_findings_user ON rm_findings (user_id, detected_at DESC);
CREATE INDEX idx_rm_findings_severity ON rm_findings (tenant_id, severity_id DESC);
CREATE INDEX idx_rm_findings_category ON rm_findings (tenant_id, category, detected_at DESC);
CREATE INDEX idx_rm_findings_channel ON rm_findings (tenant_id, channel, detected_at DESC);
```

### Incident Read Model

```sql
CREATE TABLE rm_incidents (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL,
    status          VARCHAR(30) NOT NULL,
    assigned_to     UUID,
    assigned_to_name VARCHAR(255),            -- denormalized
    finding_count   INTEGER NOT NULL DEFAULT 0,
    comment_count   INTEGER NOT NULL DEFAULT 0,
    resolution_notes TEXT,
    created_at      TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    resolved_at     TIMESTAMPTZ,
    time_to_resolve INTERVAL                  -- computed on resolution
);

CREATE INDEX idx_rm_incidents_tenant ON rm_incidents (tenant_id, status, severity);
CREATE INDEX idx_rm_incidents_assignee ON rm_incidents (assigned_to, status);
```

### User Risk Read Model

```sql
CREATE TABLE rm_user_risk (
    user_id         UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    email           VARCHAR(255) NOT NULL,
    display_name    VARCHAR(255) NOT NULL,
    department      VARCHAR(255),
    risk_score      NUMERIC(5,2) NOT NULL DEFAULT 0.00,
    finding_count_7d  INTEGER NOT NULL DEFAULT 0,
    finding_count_30d INTEGER NOT NULL DEFAULT 0,
    finding_count_90d INTEGER NOT NULL DEFAULT 0,
    last_finding_at TIMESTAMPTZ,
    top_violation_types VARCHAR(100)[] DEFAULT '{}',
    risk_factors    JSONB DEFAULT '[]',
    updated_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_rm_user_risk_tenant ON rm_user_risk (tenant_id, risk_score DESC);
```

### Compliance Dashboard Read Model

```sql
CREATE TABLE rm_compliance_status (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    framework_code  VARCHAR(50) NOT NULL,     -- 'gdpr','hipaa','pci_dss_v4'
    control_id      VARCHAR(50) NOT NULL,     -- 'A.8.12','SI-12','Req.3'
    policy_count    INTEGER NOT NULL DEFAULT 0,
    finding_count_30d INTEGER NOT NULL DEFAULT 0,
    violation_rate  NUMERIC(5,2),             -- violations per 1000 monitored actions
    status          VARCHAR(20) NOT NULL,     -- 'compliant','at_risk','non_compliant'
    last_computed   TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, framework_code, control_id)
);
```

### Analytics Aggregates

```sql
CREATE TABLE rm_daily_stats (
    tenant_id       UUID NOT NULL,
    stat_date       DATE NOT NULL,
    channel         VARCHAR(50) NOT NULL,
    category        VARCHAR(50) NOT NULL,     -- 'pii','pci','phi','credentials','ip'
    severity        VARCHAR(20) NOT NULL,
    action_taken    VARCHAR(30) NOT NULL,
    finding_count   BIGINT NOT NULL DEFAULT 0,
    incident_count  BIGINT NOT NULL DEFAULT 0,
    unique_users    BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, stat_date, channel, category, severity, action_taken)
);
```

---

## Event Processing Infrastructure

```sql
-- Tracks projection rebuild progress
CREATE TABLE projections (
    projection_name VARCHAR(100) PRIMARY KEY,  -- 'rm_policies','rm_findings','rm_incidents'
    last_event_id   UUID,
    last_event_time TIMESTAMPTZ,
    status          VARCHAR(20) NOT NULL DEFAULT 'running', -- 'running','paused','rebuilding','error'
    lag_seconds     INTEGER DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Dead letter queue for events that fail projection processing
CREATE TABLE projection_failures (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    projection_name VARCHAR(100) NOT NULL,
    event_id        UUID NOT NULL,
    error_message   TEXT NOT NULL,
    retry_count     INTEGER NOT NULL DEFAULT 0,
    max_retries     INTEGER NOT NULL DEFAULT 5,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Snapshots for fast aggregate rebuild (optional optimisation)
CREATE TABLE snapshots (
    stream_id       UUID NOT NULL,
    stream_type     VARCHAR(50) NOT NULL,
    sequence_num    BIGINT NOT NULL,
    state           JSONB NOT NULL,           -- serialised aggregate state at this point
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (stream_id, sequence_num)
);
```

---

## Tenant and Reference Data (Non-Event-Sourced)

Some data is inherently static/reference and does not benefit from event sourcing.

```sql
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) NOT NULL UNIQUE,
    subscription_tier VARCHAR(50) NOT NULL DEFAULT 'standard',
    settings        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sensitive_info_types (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id),
    code            VARCHAR(100) NOT NULL,
    display_name    VARCHAR(255) NOT NULL,
    category        VARCHAR(50) NOT NULL,
    detection_method VARCHAR(50) NOT NULL,
    pattern         TEXT,
    confidence_threshold NUMERIC(3,2) NOT NULL DEFAULT 0.80,
    compliance_tags VARCHAR(50)[] DEFAULT '{}',
    is_system       BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE compliance_frameworks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code            VARCHAR(50) NOT NULL UNIQUE,
    name            VARCHAR(255) NOT NULL,
    version         VARCHAR(30),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE compliance_controls (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id    UUID NOT NULL REFERENCES compliance_frameworks(id),
    control_id      VARCHAR(50) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    UNIQUE (framework_id, control_id)
);
```

---

## Example Temporal Query

One of the key advantages of event sourcing: answering "what was the state at time X?"

```sql
-- Rebuild policy state as of a specific date
-- (what was this policy's configuration when the violation occurred?)
SELECT
    e.stream_id AS policy_id,
    e.event_type,
    e.payload,
    e.created_at
FROM events e
WHERE e.stream_id = 'policy-uuid-here'
  AND e.stream_type = 'policy'
  AND e.created_at <= '2026-03-15T00:00:00Z'
ORDER BY e.sequence_num ASC;

-- The application replays these events to reconstruct the policy state at that point in time.
```

```sql
-- Find all users whose risk score exceeded 50 at any point in the last 90 days
SELECT DISTINCT
    e.payload->>'user_id' AS user_id,
    (e.payload->>'new_score')::numeric AS peak_score,
    e.created_at
FROM events e
WHERE e.event_type = 'UserRiskScoreUpdated'
  AND e.tenant_id = 'tenant-uuid'
  AND (e.payload->>'new_score')::numeric > 50
  AND e.created_at >= now() - INTERVAL '90 days'
ORDER BY peak_score DESC;
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Event Store | 1 | events (partitioned by month) |
| Event Infrastructure | 3 | projections, projection_failures, snapshots |
| Read Model: Policies | 2 | rm_policies, rm_policy_rules |
| Read Model: Findings | 1 | rm_findings (denormalized) |
| Read Model: Incidents | 1 | rm_incidents (denormalized) |
| Read Model: Analytics | 3 | rm_user_risk, rm_compliance_status, rm_daily_stats |
| Reference Data | 4 | tenants, sensitive_info_types, compliance_frameworks, compliance_controls |
| **Total** | **15** | Plus partitions on events table |

---

## Key Design Decisions

1. **Single events table as source of truth.** All state changes — policy edits, findings, incident updates, user risk changes — are stored as immutable events. This eliminates the need for separate audit_log, incident_timeline, and policy_history tables because the event store IS the audit log.

2. **Stream-based organisation.** Each aggregate (policy, incident, user) has a stream_id and stream_type. Events within a stream are ordered by sequence_num, enabling optimistic concurrency control (two concurrent writes to the same policy will conflict on the unique constraint).

3. **Denormalized read models.** Projection tables like rm_findings include denormalized fields (user_email, policy_name, user_department) to avoid JOINs in dashboard queries. These are rebuilt from events, so denormalization carries no data integrity risk.

4. **Event versioning.** The event_version column enables event schema evolution. When the FindingDetected payload format changes, new events carry version 2 while old events remain at version 1. Projection code handles both versions.

5. **Monthly partitioning on events table.** DLP generates high event volumes (potentially millions per day for large organisations). Partitioning by month enables efficient time-range queries and simple data retention (DROP PARTITION for old months).

6. **Reference data is not event-sourced.** Tenants, sensitive info types, and compliance frameworks are relatively static lookup data. Event-sourcing them would add complexity without meaningful audit benefit.

7. **Projection infrastructure.** The projections table tracks which events each read model has processed, enabling catch-up and rebuild. The projection_failures table acts as a dead letter queue for events that fail processing, preventing a single bad event from blocking the entire pipeline.

8. **Snapshots for performance.** For aggregates with long event histories (e.g., a policy with hundreds of rule changes), snapshots capture the state at a point in time so replay starts from the snapshot rather than the beginning of the stream.
