# Data Model Suggestion 4: Graph-Relational Hybrid

> Project: Data Loss Prevention · Created: 2026-05-19

## Philosophy

This model combines a relational core for operational CRUD (policies, detectors, endpoints) with a graph layer for relationship-heavy queries that are central to advanced DLP: data flow analysis, user-to-data-to-destination relationship mapping, insider threat detection, and conflict-of-interest analysis. The graph layer uses PostgreSQL's `ltree` extension for hierarchical data and a lightweight property graph pattern (graph_nodes / graph_edges tables) for flexible relationship modeling.

DLP is fundamentally about data flows: sensitive data moves from a source (database, file share, application) through a user (or automated process) to a destination (email recipient, cloud storage, GenAI API). Detecting risky flows requires understanding chains of relationships: "this user has access to PCI data AND has been sending emails to personal accounts AND their risk score increased 3x this week." In a normalised relational model, answering these questions requires multi-table JOINs with complex subqueries. In a graph model, they are natural traversal queries.

This approach is inspired by how Varonis models data access governance (mapping users to permissions to data stores to access patterns) and how insider threat platforms model behavioral chains. It also draws from the STIX 2.1 threat intelligence data model, which uses a graph of objects (indicators, threat actors, campaigns) connected by typed relationships.

**Best for:** Deployments where data flow analysis, insider threat detection, supply chain risk mapping, and complex relationship queries are primary use cases.

**Trade-offs:**
- Pro: Natural fit for "follow the data" queries: trace sensitive data from source to destination through users and channels
- Pro: Insider threat detection through graph traversal: find users with unusual access-to-exfiltration paths
- Pro: Supply chain / third-party risk: model vendor relationships and data sharing agreements as graph edges
- Pro: STIX 2.1 compatibility: threat intelligence maps naturally to the graph layer
- Pro: Flexible: new relationship types added as edge types without schema changes
- Con: Higher query complexity; graph traversals require recursive CTEs or application-level traversal
- Con: Graph layer adds a conceptual overhead for developers unfamiliar with property graphs
- Con: Performance tuning for graph queries at scale requires expertise (index strategies, traversal depth limits)
- Con: No native graph database; property graph on PostgreSQL is less performant than Neo4j for deep traversals
- Con: Two conceptual models (relational + graph) must be kept in sync

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| STIX 2.1 | Graph nodes and edges directly map to STIX Domain Objects and Relationships; threat indicators, campaigns, and threat actors are first-class graph entities |
| OCSF | Finding events use OCSF-aligned fields; data flow edges carry OCSF category metadata |
| ISO/IEC 27001:2022 A.8.12 | Data flow graph enables demonstrating DLP coverage across all information paths |
| NIST SP 800-53 AC-4 | Information flow enforcement controls map directly to graph edges representing allowed/denied data flows |
| GDPR Article 30 | Records of processing activities modeled as graph: data subjects -> processing activities -> recipients -> legal bases |
| ISO 3166 | Jurisdiction nodes use ISO 3166 country/region codes for multi-jurisdictional data flow mapping |
| PCI DSS v4.0 Req. 7 | Restrict access to cardholder data modeled as graph edges between users and PCI data stores |

---

## Relational Core: Operational Tables

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

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           VARCHAR(255) NOT NULL,
    display_name    VARCHAR(255) NOT NULL,
    department      VARCHAR(255),
    risk_score      NUMERIC(5,2) DEFAULT 0.00,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    idp_provider    VARCHAR(50),
    idp_external_id VARCHAR(255),
    roles           VARCHAR(50)[] NOT NULL DEFAULT '{viewer}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE INDEX idx_users_tenant ON users (tenant_id);
CREATE INDEX idx_users_risk ON users (tenant_id, risk_score DESC);
```

### Policies and Detectors

```sql
CREATE TABLE detectors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID REFERENCES tenants(id) ON DELETE CASCADE,
    code            VARCHAR(100) NOT NULL,
    display_name    VARCHAR(255) NOT NULL,
    category        VARCHAR(50) NOT NULL,
    detector_type   VARCHAR(50) NOT NULL,
    config          JSONB NOT NULL DEFAULT '{}',
    compliance_tags VARCHAR(50)[] DEFAULT '{}',
    is_system       BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    status          VARCHAR(20) NOT NULL DEFAULT 'draft',
    enforcement_mode VARCHAR(20) NOT NULL DEFAULT 'audit',
    priority        INTEGER NOT NULL DEFAULT 100,
    channels        VARCHAR(50)[] NOT NULL DEFAULT '{}',
    scope           JSONB NOT NULL DEFAULT '{}',
    actions         JSONB NOT NULL DEFAULT '[]',
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policy_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    logical_operator VARCHAR(10) NOT NULL DEFAULT 'ANY',
    detectors       JSONB NOT NULL DEFAULT '[]',
    min_findings    INTEGER NOT NULL DEFAULT 1,
    rule_order      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_policies_tenant ON policies (tenant_id, status);
CREATE INDEX idx_policy_rules ON policy_rules (policy_id);
```

---

## Graph Layer: Nodes and Edges

The graph layer uses a generic property graph pattern. Any entity in the system (user, data store, endpoint, external service, jurisdiction) can be a graph node, and any relationship between entities is a graph edge.

```sql
-- Enable ltree extension for hierarchical paths
CREATE EXTENSION IF NOT EXISTS ltree;

CREATE TABLE graph_nodes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    node_type       VARCHAR(50) NOT NULL,
    -- Node types:
    --   'user'            - internal user (linked to users table)
    --   'data_store'      - database, file share, cloud storage bucket
    --   'application'     - SaaS app, internal tool, GenAI service
    --   'endpoint'        - laptop, desktop, mobile device
    --   'external_entity' - email recipient, partner org, cloud service
    --   'jurisdiction'    - country/region (ISO 3166)
    --   'data_class'      - data classification category (PII, PCI, PHI)
    --   'threat_actor'    - STIX-aligned threat actor
    --   'indicator'       - STIX-aligned threat indicator
    --   'vendor'          - third-party vendor/supplier
    external_ref    UUID,                     -- FK to relational table (users.id, endpoints.id, etc.)
    label           VARCHAR(255) NOT NULL,    -- human-readable name
    hierarchy_path  LTREE,                    -- hierarchical path (e.g., 'org.finance.accounting')
    properties      JSONB NOT NULL DEFAULT '{}',
    -- properties example (data_store node): {
    --   "store_type": "s3_bucket",
    --   "uri": "s3://company-data/financial-reports/",
    --   "classification": "confidential",
    --   "data_classes": ["pci", "pii"],
    --   "encryption": "aes-256",
    --   "jurisdiction": "US"
    -- }
    --
    -- properties example (external_entity node): {
    --   "entity_type": "email_domain",
    --   "domain": "partner.com",
    --   "trust_level": "low",
    --   "country": "CN",
    --   "first_seen": "2026-03-15"
    -- }
    --
    -- properties example (jurisdiction node): {
    --   "iso_3166_1": "DE",
    --   "name": "Germany",
    --   "gdpr_applies": true,
    --   "data_residency_required": true,
    --   "dpa_authority": "BfDI"
    -- }
    risk_score      NUMERIC(5,2) DEFAULT 0.00,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_graph_nodes_tenant ON graph_nodes (tenant_id, node_type);
CREATE INDEX idx_graph_nodes_type ON graph_nodes (node_type);
CREATE INDEX idx_graph_nodes_ref ON graph_nodes (external_ref);
CREATE INDEX idx_graph_nodes_hierarchy ON graph_nodes USING GIST (hierarchy_path);
CREATE INDEX idx_graph_nodes_props ON graph_nodes USING GIN (properties jsonb_path_ops);
CREATE INDEX idx_graph_nodes_risk ON graph_nodes (tenant_id, risk_score DESC);

CREATE TABLE graph_edges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_node_id  UUID NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    target_node_id  UUID NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    edge_type       VARCHAR(50) NOT NULL,
    -- Edge types:
    --   'has_access'       - user -> data_store (access relationship)
    --   'sent_data_to'     - user -> external_entity (data transfer)
    --   'contains_data'    - data_store -> data_class (classification)
    --   'located_in'       - data_store/user -> jurisdiction
    --   'managed_by'       - endpoint -> user
    --   'integrates_with'  - application -> external_entity
    --   'shares_data_with' - vendor -> external_entity (supply chain)
    --   'indicates'        - indicator -> threat_actor (STIX)
    --   'targets'          - threat_actor -> data_class (STIX)
    --   'policy_covers'    - policy -> data_store/channel (coverage mapping)
    --   'reports_to'       - user -> user (org hierarchy)
    --   'data_flows_to'    - data_store -> application -> external_entity (flow chain)
    properties      JSONB NOT NULL DEFAULT '{}',
    -- properties example (sent_data_to): {
    --   "channel": "email",
    --   "finding_count": 12,
    --   "last_finding_at": "2026-05-18T14:30:00Z",
    --   "data_classes": ["pii", "pci"],
    --   "highest_severity": "high"
    -- }
    --
    -- properties example (has_access): {
    --   "permission_level": "read_write",
    --   "granted_at": "2026-01-15",
    --   "granted_by": "admin@company.com",
    --   "last_accessed": "2026-05-17",
    --   "access_frequency": "daily"
    -- }
    weight          NUMERIC(5,2) DEFAULT 1.00,  -- edge weight for risk scoring/traversal
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now(),
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_graph_edges_tenant ON graph_edges (tenant_id);
CREATE INDEX idx_graph_edges_source ON graph_edges (source_node_id, edge_type);
CREATE INDEX idx_graph_edges_target ON graph_edges (target_node_id, edge_type);
CREATE INDEX idx_graph_edges_type ON graph_edges (tenant_id, edge_type);
CREATE INDEX idx_graph_edges_props ON graph_edges USING GIN (properties jsonb_path_ops);
```

---

## Findings (Relational + Graph-Linked)

```sql
CREATE TABLE findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    policy_id       UUID NOT NULL REFERENCES policies(id),
    rule_id         UUID NOT NULL REFERENCES policy_rules(id),
    user_id         UUID REFERENCES users(id),

    -- Graph references: link finding to source and destination nodes
    source_node_id  UUID REFERENCES graph_nodes(id),    -- data store or application where data originated
    dest_node_id    UUID REFERENCES graph_nodes(id),    -- external entity or service where data was heading

    channel         VARCHAR(50) NOT NULL,
    matched_type    VARCHAR(100) NOT NULL,
    category        VARCHAR(50) NOT NULL,
    confidence      NUMERIC(3,2) NOT NULL,
    match_count     INTEGER NOT NULL DEFAULT 1,
    severity        VARCHAR(20) NOT NULL,
    action_taken    VARCHAR(30) NOT NULL,
    content_hash    BYTEA,
    detection_details JSONB NOT NULL DEFAULT '{}',
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_tenant_time ON findings (tenant_id, detected_at DESC);
CREATE INDEX idx_findings_source ON findings (source_node_id);
CREATE INDEX idx_findings_dest ON findings (dest_node_id);
CREATE INDEX idx_findings_user ON findings (user_id, detected_at DESC);
CREATE INDEX idx_findings_severity ON findings (tenant_id, severity, detected_at DESC);
```

---

## Incidents (Relational)

```sql
CREATE TABLE incidents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL,
    status          VARCHAR(30) NOT NULL DEFAULT 'open',
    assigned_to     UUID REFERENCES users(id),
    finding_ids     UUID[] NOT NULL DEFAULT '{}',
    resolution      JSONB DEFAULT '{}',
    timeline        JSONB NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_incidents_tenant ON incidents (tenant_id, status, severity);
```

---

## Audit Log

```sql
CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    actor_id        UUID,
    action          VARCHAR(100) NOT NULL,
    resource_type   VARCHAR(50) NOT NULL,
    resource_id     UUID,
    details         JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_tenant_time ON audit_log (tenant_id, created_at DESC);
```

---

## Example Graph Queries

### Trace Data Flow: Source to Destination

```sql
-- Find all paths from a user to external entities (2-hop max)
-- "Where is this user sending sensitive data?"
WITH RECURSIVE data_flows AS (
    -- Start from a specific user node
    SELECT
        e.id AS edge_id,
        e.source_node_id,
        e.target_node_id,
        e.edge_type,
        e.properties,
        1 AS depth,
        ARRAY[e.source_node_id, e.target_node_id] AS path
    FROM graph_edges e
    JOIN graph_nodes n ON n.id = e.source_node_id
    WHERE n.external_ref = 'user-uuid-here'
      AND n.node_type = 'user'
      AND e.edge_type IN ('sent_data_to', 'has_access', 'data_flows_to')
      AND e.tenant_id = 'tenant-uuid'

    UNION ALL

    -- Traverse one more hop
    SELECT
        e.id,
        e.source_node_id,
        e.target_node_id,
        e.edge_type,
        e.properties,
        df.depth + 1,
        df.path || e.target_node_id
    FROM graph_edges e
    JOIN data_flows df ON e.source_node_id = df.target_node_id
    WHERE df.depth < 2
      AND NOT (e.target_node_id = ANY(df.path))  -- prevent cycles
)
SELECT
    df.depth,
    df.edge_type,
    src.label AS source_label,
    src.node_type AS source_type,
    tgt.label AS target_label,
    tgt.node_type AS target_type,
    df.properties
FROM data_flows df
JOIN graph_nodes src ON src.id = df.source_node_id
JOIN graph_nodes tgt ON tgt.id = df.target_node_id
ORDER BY df.depth, df.edge_type;
```

### Insider Threat: High-Risk User Patterns

```sql
-- Find users who have access to PCI data AND have sent data to external entities
-- in the last 30 days AND have a risk score above 50
SELECT
    u.email,
    u.department,
    u.risk_score,
    pci_access.data_store_count,
    ext_sends.external_send_count
FROM users u
JOIN (
    -- Users with access to PCI data stores
    SELECT
        n_user.external_ref AS user_id,
        COUNT(DISTINCT n_store.id) AS data_store_count
    FROM graph_edges e
    JOIN graph_nodes n_user ON n_user.id = e.source_node_id AND n_user.node_type = 'user'
    JOIN graph_nodes n_store ON n_store.id = e.target_node_id AND n_store.node_type = 'data_store'
    WHERE e.edge_type = 'has_access'
      AND n_store.properties @> '{"data_classes": ["pci"]}'
      AND e.tenant_id = 'tenant-uuid'
    GROUP BY n_user.external_ref
) pci_access ON pci_access.user_id = u.id
JOIN (
    -- Users who sent data to external entities recently
    SELECT
        n_user.external_ref AS user_id,
        COUNT(DISTINCT e.id) AS external_send_count
    FROM graph_edges e
    JOIN graph_nodes n_user ON n_user.id = e.source_node_id AND n_user.node_type = 'user'
    JOIN graph_nodes n_ext ON n_ext.id = e.target_node_id AND n_ext.node_type = 'external_entity'
    WHERE e.edge_type = 'sent_data_to'
      AND e.last_seen >= now() - INTERVAL '30 days'
      AND e.tenant_id = 'tenant-uuid'
    GROUP BY n_user.external_ref
) ext_sends ON ext_sends.user_id = u.id
WHERE u.risk_score > 50
  AND u.tenant_id = 'tenant-uuid'
ORDER BY u.risk_score DESC;
```

### Organisational Hierarchy Using ltree

```sql
-- Find all users in the Finance department and its sub-departments
SELECT n.label, n.properties, n.hierarchy_path
FROM graph_nodes n
WHERE n.tenant_id = 'tenant-uuid'
  AND n.node_type = 'user'
  AND n.hierarchy_path <@ 'org.finance'  -- all descendants of org.finance
ORDER BY n.hierarchy_path;

-- Find the department hierarchy for a specific user
SELECT n.label, n.hierarchy_path, nlevel(n.hierarchy_path) AS depth
FROM graph_nodes n
WHERE n.tenant_id = 'tenant-uuid'
  AND n.hierarchy_path @> (
      SELECT hierarchy_path FROM graph_nodes WHERE external_ref = 'user-uuid'
  )
ORDER BY nlevel(n.hierarchy_path);
```

### DLP Coverage Gap Analysis

```sql
-- Find data stores that contain sensitive data but are NOT covered by any policy
SELECT
    n_store.label AS data_store,
    n_store.properties->>'store_type' AS store_type,
    n_store.properties->'data_classes' AS data_classes,
    n_store.properties->>'jurisdiction' AS jurisdiction
FROM graph_nodes n_store
WHERE n_store.tenant_id = 'tenant-uuid'
  AND n_store.node_type = 'data_store'
  AND n_store.properties->'data_classes' IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM graph_edges e
      WHERE e.target_node_id = n_store.id
        AND e.edge_type = 'policy_covers'
        AND e.status = 'active'
  )
ORDER BY n_store.risk_score DESC;
```

### Cross-Jurisdiction Data Flow Compliance

```sql
-- Find data flows that cross jurisdiction boundaries (potential GDPR transfer issues)
SELECT
    src_store.label AS source_store,
    src_jur.label AS source_jurisdiction,
    dst_entity.label AS destination,
    dst_jur.label AS dest_jurisdiction,
    flow_edge.properties
FROM graph_edges flow_edge
JOIN graph_nodes src_store ON src_store.id = flow_edge.source_node_id
JOIN graph_edges src_loc ON src_loc.source_node_id = src_store.id AND src_loc.edge_type = 'located_in'
JOIN graph_nodes src_jur ON src_jur.id = src_loc.target_node_id AND src_jur.node_type = 'jurisdiction'
JOIN graph_nodes dst_entity ON dst_entity.id = flow_edge.target_node_id
JOIN graph_edges dst_loc ON dst_loc.source_node_id = dst_entity.id AND dst_loc.edge_type = 'located_in'
JOIN graph_nodes dst_jur ON dst_jur.id = dst_loc.target_node_id AND dst_jur.node_type = 'jurisdiction'
WHERE flow_edge.edge_type = 'data_flows_to'
  AND flow_edge.tenant_id = 'tenant-uuid'
  AND src_jur.properties->>'iso_3166_1' != dst_jur.properties->>'iso_3166_1'
  AND src_jur.properties->>'gdpr_applies' = 'true'
ORDER BY flow_edge.last_seen DESC;
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Core Platform | 2 | tenants, users |
| Content Detection | 1 | detectors |
| Policy Management | 2 | policies, policy_rules |
| Graph Layer | 2 | graph_nodes, graph_edges (the flexible relationship layer) |
| Findings | 1 | findings (linked to graph nodes) |
| Incidents | 1 | incidents |
| Audit | 1 | audit_log |
| **Total** | **10** | Plus ltree extension |

---

## Key Design Decisions

1. **Property graph on PostgreSQL rather than a separate graph database (Neo4j).** This keeps the deployment simple (single database) while still enabling graph traversals via recursive CTEs. For organisations processing fewer than ~10M graph edges, PostgreSQL performance is sufficient. If graph traversals become the bottleneck, the graph_nodes/graph_edges tables can be mirrored to Neo4j as a read replica.

2. **Findings linked to graph nodes via source_node_id and dest_node_id.** This connects every finding to the data flow graph, enabling queries like "show me all findings involving data that flows from this S3 bucket to external recipients." The graph provides context that the relational finding alone cannot.

3. **ltree for organisational hierarchy.** PostgreSQL's ltree extension enables efficient hierarchical queries (find all users in a department and its sub-departments) without recursive CTEs. The hierarchy_path column on graph_nodes stores paths like 'org.finance.accounting', and the @> and <@ operators enable ancestor/descendant queries with GIST index support.

4. **Edge weight for risk scoring.** The weight column on graph_edges enables risk score propagation through the graph. A user's risk score can be computed as a function of their edge weights to sensitive data stores, external entities, and recent findings.

5. **STIX 2.1 alignment in the graph layer.** Threat actors, indicators, and campaigns are modeled as graph nodes with typed edges (indicates, targets, attributed_to). This means threat intelligence from STIX/TAXII feeds can be ingested directly into the graph and correlated with DLP findings.

6. **Temporal edges via first_seen/last_seen.** Graph edges track when a relationship was first and last observed. This enables temporal analysis ("this user started accessing PCI data 2 weeks ago, which is new") and stale edge cleanup.

7. **Coverage gap analysis as graph query.** By modeling policy coverage as edges (policy_covers -> data_store), the graph can identify which sensitive data stores lack policy coverage. This is a query that would require complex multi-table JOINs in a relational-only model but is a simple NOT EXISTS on edges in the graph.

8. **Cross-jurisdiction data flow as graph traversal.** GDPR data transfer compliance requires understanding where data originates and where it flows. The graph models jurisdictions as nodes and located_in edges connect data stores and external entities to their jurisdictions, making cross-border flow detection a straightforward multi-hop traversal.
