# Data Loss Prevention (DLP) — Phased Development Plan

> Project: 153-data-loss-prevention · Created: 2026-05-25
> Purpose: Provide sufficient detail for Claude Code (Opus) to implement each phase end-to-end.

---

## Technology Decisions

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Primary language | Python 3.12+ | DLP is ML/NLP-heavy (content classification, NER, OCR, multimodal analysis); Python has the richest ecosystem for these (spaCy, Presidio, Tesseract bindings, transformers). Most DLP API references (Nightfall, Google Cloud DLP) offer Python SDKs first. |
| API framework | FastAPI 0.115+ | OpenAPI 3.1 auto-generation is critical for a DLP platform that must integrate with SIEM/SOAR; async support for high-throughput inline inspection; Pydantic v2 for request/response validation matches the data model's type constraints. |
| Database | PostgreSQL 16+ | Row-Level Security for multi-tenant isolation, JSONB with GIN indexes for variable detection metadata, ltree extension for org hierarchy, array types for compliance tags. All four data model suggestions target PostgreSQL. |
| Data model approach | Hybrid Relational + JSONB (Suggestion 3) | Best balance of development velocity and structural integrity for MVP. Fixed relational columns for queryable fields (tenant, severity, channel, confidence), JSONB for variable detection metadata and channel-specific details. 13 tables vs. 29 for full normalisation. Event-sourced audit log added from Suggestion 2 for compliance. |
| Migrations | Alembic 1.13+ | Standard SQLAlchemy-ecosystem migration tool; version-controlled schema changes required for regulated environments (ISO 27001 A.8.12 audit trail). |
| ORM | SQLAlchemy 2.0+ (async) | Async engine with asyncpg driver for non-blocking DB access under high finding volumes; declarative models map cleanly to the hybrid JSONB schema. |
| Task queue | Celery 5.4+ with Redis broker | DLP inspection is inherently async: content arrives, gets queued for detection, findings are generated asynchronously. Celery handles webhook delivery, ML inference jobs, SIEM export batches, and compliance report generation. |
| Cache / broker | Redis 7+ | Broker for Celery, cache for hot policy lookups during inline inspection, rate limiting for API clients. |
| Content detection | Microsoft Presidio (MIT) + custom regex engine | Presidio provides 30+ PII entity recognisers out of the box (SSN, credit card, IBAN, etc.) with pluggable NLP backends (spaCy, transformers). Custom regex engine adds domain-specific patterns. Avoids Nightfall AI patent concerns on ML classifiers. |
| NLP backend | spaCy 3.8+ with en_core_web_trf | Transformer-based NER for high-accuracy PII detection; Presidio uses spaCy as its NLP engine. |
| OCR | Tesseract 5 via pytesseract | Image/PDF text extraction for visual DLP; open-source, no licensing concerns. |
| Frontend | React 19 + TypeScript 5.5 + Vite 6 | Dashboard-heavy application (policy management, incident investigation, compliance reports). React for component reuse; TypeScript for type safety on complex policy/finding data structures. |
| UI component library | shadcn/ui + Tailwind CSS 4 | Composable, accessible components; no vendor lock-in (components are copied into the project); security dashboards require high customisation. |
| Charting | Recharts 2.x | Lightweight, React-native charting for compliance dashboards, finding trend lines, severity distributions. |
| Authentication | OAuth 2.0 / OIDC via python-jose + authlib | DLP platforms must integrate with enterprise IdPs (Okta, Entra ID, AD). OAuth 2.0 / OIDC is the standard (RFC 6749, RFC 7519). API clients use client_credentials grant. |
| Containerisation | Docker + docker-compose | Self-hosted deployment is a key differentiator (air-gapped, regulated environments). Compose orchestrates API, workers, database, Redis, and frontend. |
| Testing | pytest 8+ (backend), Vitest 3+ (frontend) | pytest for unit/integration with async support (pytest-asyncio); Vitest for React component and hook testing. |
| Code quality | Ruff (lint + format), mypy (type check) | Ruff replaces flake8 + black + isort with a single fast tool; mypy enforces type annotations critical for a security product. |
| API documentation | Auto-generated OpenAPI 3.1 via FastAPI | Standards compliance (standards.md references OpenAPI 3.1 as the DLP API standard); enables SDK generation for SIEM/SOAR integrations. |
| SIEM export format | OCSF JSON + CEF + Syslog RFC 5424 | OCSF is the emerging standard for security telemetry (aligned with data model suggestions); CEF for legacy SIEM (ArcSight, QRadar); Syslog for universal compatibility. |
| Email inspection | aiosmtpd (SMTP proxy) | Lightweight async SMTP proxy for email gateway inspection; intercepts outbound email for DLP scanning before forwarding to the real MTA. |
| Package manager | uv | Fast, reliable Python package management; lockfile support for reproducible builds in regulated environments. |

---

### Project Structure

```
data-loss-prevention/
├── pyproject.toml
├── alembic.ini
├── Dockerfile
├── Dockerfile.worker
├── Dockerfile.frontend
├── docker-compose.yml
├── .env.example
├── alembic/
│   └── versions/
├── src/
│   ├── __init__.py
│   ├── main.py                          # FastAPI application factory
│   ├── config.py                        # Settings via pydantic-settings
│   ├── database.py                      # Async SQLAlchemy engine + session
│   ├── models/                          # SQLAlchemy ORM models
│   │   ├── __init__.py
│   │   ├── tenant.py
│   │   ├── user.py
│   │   ├── detector.py
│   │   ├── policy.py
│   │   ├── endpoint.py
│   │   ├── integration.py
│   │   ├── finding.py
│   │   ├── incident.py
│   │   ├── audit.py
│   │   └── api_client.py
│   ├── schemas/                         # Pydantic request/response schemas
│   │   ├── __init__.py
│   │   ├── tenant.py
│   │   ├── user.py
│   │   ├── detector.py
│   │   ├── policy.py
│   │   ├── finding.py
│   │   ├── incident.py
│   │   └── common.py
│   ├── api/                             # FastAPI route modules
│   │   ├── __init__.py
│   │   ├── router.py                    # Top-level router aggregation
│   │   ├── auth.py
│   │   ├── tenants.py
│   │   ├── users.py
│   │   ├── detectors.py
│   │   ├── policies.py
│   │   ├── findings.py
│   │   ├── incidents.py
│   │   ├── compliance.py
│   │   ├── integrations.py
│   │   └── webhooks.py
│   ├── detection/                       # Content detection engine
│   │   ├── __init__.py
│   │   ├── engine.py                    # Detection orchestrator
│   │   ├── pattern_detector.py          # Regex-based detection
│   │   ├── presidio_detector.py         # Presidio NLP detection
│   │   ├── fingerprint_detector.py      # Document fingerprinting
│   │   ├── ocr_detector.py             # Image/PDF text extraction
│   │   └── types.py                     # Detection result types
│   ├── enforcement/                     # Policy enforcement
│   │   ├── __init__.py
│   │   ├── evaluator.py                 # Policy rule evaluation
│   │   ├── actions.py                   # Block, warn, quarantine, encrypt
│   │   └── types.py
│   ├── channels/                        # Monitoring channel adapters
│   │   ├── __init__.py
│   │   ├── base.py                      # Abstract channel interface
│   │   ├── email_channel.py             # SMTP proxy
│   │   ├── web_proxy_channel.py         # HTTP/HTTPS proxy
│   │   ├── saas/                        # SaaS integration adapters
│   │   │   ├── __init__.py
│   │   │   ├── slack.py
│   │   │   ├── microsoft365.py
│   │   │   └── google_workspace.py
│   │   └── genai_channel.py             # GenAI API monitor
│   ├── incidents/                       # Incident management logic
│   │   ├── __init__.py
│   │   ├── manager.py
│   │   ├── correlation.py               # Finding-to-incident correlation
│   │   └── escalation.py
│   ├── compliance/                      # Compliance reporting
│   │   ├── __init__.py
│   │   ├── frameworks.py
│   │   ├── reporter.py
│   │   └── templates/
│   ├── export/                          # SIEM/SOAR export
│   │   ├── __init__.py
│   │   ├── ocsf.py
│   │   ├── cef.py
│   │   └── syslog.py
│   ├── auth/                            # Authentication & authorisation
│   │   ├── __init__.py
│   │   ├── oauth.py
│   │   ├── rbac.py
│   │   └── tenant_context.py
│   ├── tasks/                           # Celery async tasks
│   │   ├── __init__.py
│   │   ├── celery_app.py
│   │   ├── detection_tasks.py
│   │   ├── export_tasks.py
│   │   ├── webhook_tasks.py
│   │   └── report_tasks.py
│   └── utils/
│       ├── __init__.py
│       ├── crypto.py                    # Encryption helpers for secrets
│       ├── hashing.py                   # Content hashing for dedup
│       └── ocsf_mapping.py             # OCSF event field mapping
├── frontend/
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── api/                         # API client (generated from OpenAPI)
│   │   ├── components/
│   │   │   ├── ui/                      # shadcn/ui components
│   │   │   ├── layout/
│   │   │   ├── policies/
│   │   │   ├── findings/
│   │   │   ├── incidents/
│   │   │   ├── compliance/
│   │   │   └── dashboard/
│   │   ├── hooks/
│   │   ├── pages/
│   │   ├── stores/                      # Zustand state management
│   │   └── types/
│   └── tests/
├── tests/
│   ├── conftest.py                      # Shared fixtures (async DB, test tenant)
│   ├── fixtures/                        # Test data files
│   │   ├── sample_emails/
│   │   ├── sample_documents/
│   │   ├── sample_images/
│   │   └── policies/
│   ├── unit/
│   │   ├── test_pattern_detector.py
│   │   ├── test_presidio_detector.py
│   │   ├── test_policy_evaluator.py
│   │   ├── test_ocsf_mapping.py
│   │   └── test_crypto.py
│   ├── integration/
│   │   ├── test_api_policies.py
│   │   ├── test_api_findings.py
│   │   ├── test_api_incidents.py
│   │   ├── test_detection_pipeline.py
│   │   └── test_email_channel.py
│   └── e2e/
│       ├── test_full_detection_flow.py
│       └── test_incident_lifecycle.py
└── docs/
    ├── api-guide.md
    └── deployment-guide.md
```

---

## Phase 1: Foundation — Project Scaffold, Configuration, and Database

### Purpose

Establish the project skeleton with a working build system, configuration management, database connection with migrations, and the base multi-tenant data model. After this phase, the application starts, connects to PostgreSQL, and serves a health-check endpoint. All subsequent phases build on this foundation.

### Tasks

#### 1.1 — Project Scaffold and Build Configuration

**What**: Create the Python project with uv, FastAPI entry point, Docker configuration, and CI-ready tooling.

**Design**:

```python
# pyproject.toml (key sections)
[project]
name = "data-loss-prevention"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.32.0",
    "sqlalchemy[asyncio]>=2.0.36",
    "asyncpg>=0.30.0",
    "alembic>=1.13.0",
    "pydantic>=2.10.0",
    "pydantic-settings>=2.6.0",
    "redis>=5.2.0",
    "celery[redis]>=5.4.0",
    "python-jose[cryptography]>=3.3.0",
    "authlib>=1.4.0",
    "httpx>=0.28.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3.0",
    "pytest-asyncio>=0.24.0",
    "pytest-cov>=6.0.0",
    "ruff>=0.8.0",
    "mypy>=1.13.0",
    "httpx>=0.28.0",
]
```

```python
# src/config.py
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "DLP Platform"
    debug: bool = False
    log_level: str = "INFO"

    # Database
    database_url: str = "postgresql+asyncpg://dlp:dlp@localhost:5432/dlp"
    database_pool_size: int = 20
    database_max_overflow: int = 10

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Auth
    jwt_secret_key: str  # required, no default
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60

    # Tenant
    default_tenant_slug: str = "default"

    model_config = {"env_prefix": "DLP_", "env_file": ".env"}
```

```python
# src/main.py
from fastapi import FastAPI
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialise DB pool, Redis connection
    await init_database()
    yield
    # Shutdown: close connections
    await close_database()

def create_app() -> FastAPI:
    app = FastAPI(
        title="Data Loss Prevention API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(api_router, prefix="/api/v1")
    return app

app = create_app()

@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok", "version": "0.1.0"}
```

```dockerfile
# Dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN pip install uv && uv sync --frozen --no-dev
COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .
EXPOSE 8000
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```yaml
# docker-compose.yml
services:
  api:
    build: .
    ports: ["8000:8000"]
    env_file: .env
    depends_on: [postgres, redis]
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: dlp
      POSTGRES_USER: dlp
      POSTGRES_PASSWORD: dlp
    ports: ["5432:5432"]
    volumes: [pgdata:/var/lib/postgresql/data]
  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
volumes:
  pgdata:
```

**Testing**:
- `Unit: Settings loads from environment variables with DLP_ prefix`
- `Unit: Settings raises ValidationError when jwt_secret_key is missing`
- `Unit: Settings uses correct defaults for database_pool_size (20)`
- `Integration: docker-compose up builds and starts all services`
- `Integration: GET /health returns 200 with {"status": "ok"}`

---

#### 1.2 — Database Connection and Base Models

**What**: Set up async SQLAlchemy engine, session factory, and base model class with tenant isolation.

**Design**:

```python
# src/database.py
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
import uuid
from datetime import datetime

class Base(DeclarativeBase):
    pass

class TenantMixin:
    """Mixin for all tenant-scoped models."""
    tenant_id: uuid.UUID  # FK to tenants.id, set via context

engine: create_async_engine | None = None
async_session_factory: async_sessionmaker[AsyncSession] | None = None

async def init_database() -> None:
    global engine, async_session_factory
    from src.config import get_settings
    settings = get_settings()
    engine = create_async_engine(
        settings.database_url,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_max_overflow,
    )
    async_session_factory = async_sessionmaker(engine, expire_on_commit=False)

async def get_session() -> AsyncSession:
    async with async_session_factory() as session:
        yield session
```

```python
# src/auth/tenant_context.py
from contextvars import ContextVar
import uuid

current_tenant_id: ContextVar[uuid.UUID] = ContextVar("current_tenant_id")

async def set_tenant_context(session: AsyncSession, tenant_id: uuid.UUID) -> None:
    """Set PostgreSQL session variable for RLS enforcement."""
    current_tenant_id.set(tenant_id)
    await session.execute(
        text(f"SET app.current_tenant_id = '{tenant_id}'")
    )
```

**Testing**:
- `Unit: init_database creates engine with configured pool_size`
- `Unit: get_session yields an AsyncSession and closes it on exit`
- `Integration: set_tenant_context sets PostgreSQL session variable correctly`
- `Integration: database connection pool handles 20 concurrent sessions`

---

#### 1.3 — Core Schema Migration (Tenants, Users, Detectors)

**What**: Create the initial Alembic migration with the tenants, users, and detectors tables from the hybrid data model.

**Design**:

```python
# src/models/tenant.py
from sqlalchemy import Column, String, DateTime, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from src.database import Base
import uuid

class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), nullable=False, unique=True)
    subscription_tier = Column(String(50), nullable=False, default="standard")
    settings = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
```

```python
# src/models/user.py
from sqlalchemy import Column, String, Numeric, DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from src.database import Base
import uuid

class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("tenant_id", "email"),)

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email = Column(String(255), nullable=False)
    display_name = Column(String(255), nullable=False)
    department = Column(String(255))
    risk_score = Column(Numeric(5, 2), default=0.00)
    status = Column(String(20), nullable=False, default="active")
    identity_provider = Column(JSONB, server_default="{}")
    profile = Column(JSONB, server_default="{}")
    roles = Column(ARRAY(String(50)), nullable=False, server_default="{viewer}")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
```

```python
# src/models/detector.py
class Detector(Base):
    __tablename__ = "detectors"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    code = Column(String(100), nullable=False)
    display_name = Column(String(255), nullable=False)
    category = Column(String(50), nullable=False)  # pii, pci, phi, credentials, ip, custom
    detector_type = Column(String(50), nullable=False)  # regex, keyword, ml_classifier, fingerprint, exact_data_match, multimodal
    is_system = Column(Boolean, nullable=False, default=False)
    compliance_tags = Column(ARRAY(String(50)), server_default="{}")
    config = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
```

Row-Level Security applied in migration:
```sql
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON users
    USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

**Testing**:
- `Unit: Tenant model sets default subscription_tier to "standard"`
- `Unit: User model enforces unique constraint on (tenant_id, email)`
- `Integration: Alembic migration upgrades cleanly on empty database`
- `Integration: Alembic migration downgrades cleanly`
- `Integration: RLS prevents cross-tenant user queries`
- `Integration: RLS allows same-tenant user queries`

---

#### 1.4 — Tenant and User CRUD API

**What**: REST endpoints for tenant and user management with Pydantic schemas.

**Design**:

```python
# src/schemas/tenant.py
from pydantic import BaseModel, Field
from datetime import datetime
import uuid

class TenantCreate(BaseModel):
    name: str = Field(max_length=255)
    slug: str = Field(max_length=100, pattern=r"^[a-z0-9-]+$")
    subscription_tier: str = Field(default="standard")
    settings: dict = Field(default_factory=dict)

class TenantResponse(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    subscription_tier: str
    settings: dict
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}

class TenantUpdate(BaseModel):
    name: str | None = None
    subscription_tier: str | None = None
    settings: dict | None = None
```

```python
# src/schemas/user.py
class UserCreate(BaseModel):
    email: str = Field(max_length=255)
    display_name: str = Field(max_length=255)
    department: str | None = None
    roles: list[str] = Field(default=["viewer"])
    identity_provider: dict = Field(default_factory=dict)
    profile: dict = Field(default_factory=dict)

class UserResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    display_name: str
    department: str | None
    risk_score: float
    status: str
    roles: list[str]
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}
```

API endpoints:
```
POST   /api/v1/tenants                    → TenantResponse
GET    /api/v1/tenants/{tenant_id}         → TenantResponse
PATCH  /api/v1/tenants/{tenant_id}         → TenantResponse
GET    /api/v1/users                       → PaginatedResponse[UserResponse]
POST   /api/v1/users                       → UserResponse
GET    /api/v1/users/{user_id}             → UserResponse
PATCH  /api/v1/users/{user_id}             → UserResponse
DELETE /api/v1/users/{user_id}             → 204
```

```python
# src/schemas/common.py
class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    has_more: bool
```

**Testing**:
- `Integration: POST /tenants with valid data → 201 with TenantResponse`
- `Integration: POST /tenants with duplicate slug → 409 Conflict`
- `Integration: GET /users returns only users for the current tenant (RLS)`
- `Integration: POST /users with invalid email format → 422`
- `Integration: DELETE /users/{id} → 204, user no longer retrievable`
- `Integration: PATCH /users/{id} with partial update changes only specified fields`
- `Integration: GET /users with pagination returns correct page_size and has_more`

---

## Phase 2: Content Detection Engine

### Purpose

Build the core detection engine that inspects content and identifies sensitive data. This is the heart of the DLP platform: without accurate content detection, nothing else matters. After this phase, the system can scan text, documents, and images for PII, PCI data, PHI, credentials, and custom patterns.

### Tasks

#### 2.1 — Pattern-Based Detection (Regex Engine)

**What**: Build a configurable regex-based detector for structured sensitive data types (SSN, credit card numbers, API keys, IBANs, email addresses).

**Design**:

```python
# src/detection/types.py
from pydantic import BaseModel
from enum import Enum
import uuid

class DetectorCategory(str, Enum):
    PII = "pii"
    PCI = "pci"
    PHI = "phi"
    CREDENTIALS = "credentials"
    IP = "ip"
    CUSTOM = "custom"

class MatchLocation(BaseModel):
    byte_start: int
    byte_end: int
    snippet: str            # redacted snippet, e.g., "****-****-****-4242"

class DetectionResult(BaseModel):
    detector_id: uuid.UUID
    detector_code: str      # e.g., "CREDIT_CARD", "SSN_US"
    category: DetectorCategory
    confidence: float       # 0.0 to 1.0
    match_count: int
    locations: list[MatchLocation]
    metadata: dict = {}     # detector-specific extra info

class ContentPayload(BaseModel):
    content_id: str         # unique ID for dedup
    text: str | None = None
    binary: bytes | None = None
    mime_type: str = "text/plain"
    source_type: str        # email, file, chat_message, api_request
    source_ref: str | None = None
```

```python
# src/detection/pattern_detector.py
import re
from dataclasses import dataclass

@dataclass
class PatternRule:
    code: str
    category: DetectorCategory
    pattern: re.Pattern
    validation_fn: Callable[[str], bool] | None  # e.g., Luhn check for credit cards
    proximity_keywords: list[str] = field(default_factory=list)
    proximity_window: int = 50
    base_confidence: float = 0.85

BUILT_IN_PATTERNS: list[PatternRule] = [
    PatternRule(
        code="CREDIT_CARD",
        category=DetectorCategory.PCI,
        pattern=re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        validation_fn=luhn_check,
        proximity_keywords=["card", "visa", "mastercard", "amex", "credit"],
        base_confidence=0.90,
    ),
    PatternRule(
        code="SSN_US",
        category=DetectorCategory.PII,
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        validation_fn=ssn_area_check,
        proximity_keywords=["ssn", "social security", "social sec"],
        base_confidence=0.85,
    ),
    PatternRule(
        code="API_KEY_GENERIC",
        category=DetectorCategory.CREDENTIALS,
        pattern=re.compile(r"\b(?:sk|pk|api|key|token|secret)[-_]?[a-zA-Z0-9]{20,}\b", re.IGNORECASE),
        validation_fn=None,
        proximity_keywords=["api", "key", "token", "secret", "authorization"],
        base_confidence=0.75,
    ),
    # AWS access key, IBAN, US phone, email, etc.
]

class PatternDetector:
    def __init__(self, rules: list[PatternRule] | None = None):
        self.rules = rules or BUILT_IN_PATTERNS

    def detect(self, text: str) -> list[DetectionResult]:
        """Scan text against all pattern rules, return matches."""
        results: list[DetectionResult] = []
        for rule in self.rules:
            matches = list(rule.pattern.finditer(text))
            if not matches:
                continue
            valid_matches = [
                m for m in matches
                if rule.validation_fn is None or rule.validation_fn(m.group())
            ]
            if not valid_matches:
                continue
            confidence = self._compute_confidence(rule, text, valid_matches)
            locations = [
                MatchLocation(
                    byte_start=m.start(),
                    byte_end=m.end(),
                    snippet=self._redact(m.group()),
                )
                for m in valid_matches
            ]
            results.append(DetectionResult(
                detector_id=...,  # resolved from detector registry
                detector_code=rule.code,
                category=rule.category,
                confidence=confidence,
                match_count=len(valid_matches),
                locations=locations,
            ))
        return results

    def _compute_confidence(
        self, rule: PatternRule, text: str, matches: list[re.Match]
    ) -> float:
        """Boost confidence if proximity keywords are found near matches."""
        confidence = rule.base_confidence
        for match in matches:
            window = text[max(0, match.start() - rule.proximity_window):match.end() + rule.proximity_window].lower()
            if any(kw in window for kw in rule.proximity_keywords):
                confidence = min(1.0, confidence + 0.10)
                break
        return round(confidence, 2)

    def _redact(self, value: str) -> str:
        """Redact all but the last 4 characters."""
        if len(value) <= 4:
            return "****"
        return "*" * (len(value) - 4) + value[-4:]
```

Validation helpers:
```python
def luhn_check(number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    # standard Luhn implementation
    ...

def ssn_area_check(ssn: str) -> bool:
    """Validate SSN area number is not in known-invalid ranges."""
    area = int(ssn[:3])
    return area not in (0, 666) and area < 900
```

**Testing**:
- `Unit: detect("My SSN is 123-45-6789") → 1 result, code=SSN_US, confidence>=0.85`
- `Unit: detect("Card: 4111-1111-1111-1111") → 1 result, code=CREDIT_CARD, Luhn passes`
- `Unit: detect("Card: 1234-5678-9012-3456") → 0 results (Luhn fails)`
- `Unit: detect("sk_live_abc123def456ghi789jkl") → 1 result, code=API_KEY_GENERIC`
- `Unit: detect("No sensitive data here") → empty list`
- `Unit: proximity boost: "social security number: 123-45-6789" → confidence >= 0.95`
- `Unit: redact("4111111111111111") → "************1111"`
- `Unit: SSN area check rejects 000-12-3456 and 666-12-3456`
- `Fixture: scan tests/fixtures/sample_documents/pci_test.txt → expected finding count`

---

#### 2.2 — Presidio NLP Detection Integration

**What**: Integrate Microsoft Presidio for ML-based PII detection with spaCy NER backend.

**Design**:

```python
# src/detection/presidio_detector.py
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_analyzer.nlp_engine import SpacyNlpEngine

class PresidioDetector:
    def __init__(self, model_name: str = "en_core_web_trf", score_threshold: float = 0.5):
        self.engine = AnalyzerEngine(
            nlp_engine=SpacyNlpEngine(models=[{"lang_code": "en", "model_name": model_name}])
        )
        self.score_threshold = score_threshold
        self._category_map: dict[str, DetectorCategory] = {
            "PERSON": DetectorCategory.PII,
            "PHONE_NUMBER": DetectorCategory.PII,
            "EMAIL_ADDRESS": DetectorCategory.PII,
            "CREDIT_CARD": DetectorCategory.PCI,
            "US_SSN": DetectorCategory.PII,
            "IBAN_CODE": DetectorCategory.PII,
            "IP_ADDRESS": DetectorCategory.PII,
            "MEDICAL_LICENSE": DetectorCategory.PHI,
            "US_DRIVER_LICENSE": DetectorCategory.PII,
        }

    def detect(self, text: str, language: str = "en") -> list[DetectionResult]:
        presidio_results: list[RecognizerResult] = self.engine.analyze(
            text=text,
            language=language,
            score_threshold=self.score_threshold,
        )
        # Group by entity type and convert to DetectionResult
        grouped: dict[str, list[RecognizerResult]] = {}
        for r in presidio_results:
            grouped.setdefault(r.entity_type, []).append(r)

        results: list[DetectionResult] = []
        for entity_type, matches in grouped.items():
            category = self._category_map.get(entity_type, DetectorCategory.PII)
            avg_confidence = sum(m.score for m in matches) / len(matches)
            locations = [
                MatchLocation(
                    byte_start=m.start,
                    byte_end=m.end,
                    snippet=self._redact(text[m.start:m.end]),
                )
                for m in matches
            ]
            results.append(DetectionResult(
                detector_id=...,
                detector_code=entity_type,
                category=category,
                confidence=round(avg_confidence, 2),
                match_count=len(matches),
                locations=locations,
                metadata={"engine": "presidio", "model": self.engine.nlp_engine.nlp["en"].meta["name"]},
            ))
        return results
```

**Testing**:
- `Unit: detect("John Smith lives at 123 Main St") → PERSON entity detected`
- `Unit: detect("Call me at +1-555-123-4567") → PHONE_NUMBER entity detected`
- `Unit: detect("Patient MRN: 12345") → no false positive (below threshold)`
- `Unit: detect("") → empty list, no errors`
- `Unit: score_threshold=0.8 filters out low-confidence matches`
- `Integration: Presidio engine loads spaCy model successfully`
- `Fixture: scan tests/fixtures/sample_documents/pii_mixed.txt → expected entities`

---

#### 2.3 — Detection Orchestrator

**What**: Build the central detection engine that routes content through multiple detectors (pattern + Presidio), deduplicates results, and produces a unified detection report.

**Design**:

```python
# src/detection/engine.py
from dataclasses import dataclass

@dataclass
class DetectionReport:
    content_id: str
    content_hash: bytes          # SHA-256 for dedup
    detections: list[DetectionResult]
    total_match_count: int
    highest_severity: str        # info, low, medium, high, critical
    processing_time_ms: float
    detectors_used: list[str]

class DetectionEngine:
    def __init__(
        self,
        pattern_detector: PatternDetector,
        presidio_detector: PresidioDetector,
    ):
        self.pattern_detector = pattern_detector
        self.presidio_detector = presidio_detector

    async def inspect(self, payload: ContentPayload) -> DetectionReport:
        """Run all applicable detectors on the content payload."""
        text = payload.text or ""
        if payload.binary and payload.mime_type.startswith("text/"):
            text = payload.binary.decode("utf-8", errors="replace")

        # Run detectors
        pattern_results = self.pattern_detector.detect(text)
        presidio_results = self.presidio_detector.detect(text)

        # Merge and deduplicate (by overlapping byte ranges)
        merged = self._deduplicate(pattern_results + presidio_results)

        content_hash = hashlib.sha256(text.encode()).digest()
        severity = self._compute_severity(merged)

        return DetectionReport(
            content_id=payload.content_id,
            content_hash=content_hash,
            detections=merged,
            total_match_count=sum(d.match_count for d in merged),
            highest_severity=severity,
            processing_time_ms=...,
            detectors_used=["pattern", "presidio"],
        )

    def _deduplicate(self, results: list[DetectionResult]) -> list[DetectionResult]:
        """Remove duplicate detections with overlapping byte ranges; keep higher confidence."""
        # Sort by byte_start, then by confidence desc
        # For overlapping ranges with same category, keep the higher-confidence result
        ...

    def _compute_severity(self, results: list[DetectionResult]) -> str:
        """Map detection categories and counts to severity level."""
        if not results:
            return "info"
        categories = {r.category for r in results}
        total = sum(r.match_count for r in results)
        max_confidence = max(r.confidence for r in results)

        if DetectorCategory.PCI in categories and max_confidence >= 0.90:
            return "critical"
        if DetectorCategory.PHI in categories and max_confidence >= 0.85:
            return "high"
        if total >= 10 or max_confidence >= 0.95:
            return "high"
        if total >= 3 or max_confidence >= 0.80:
            return "medium"
        return "low"
```

**Testing**:
- `Unit: inspect with text containing SSN and credit card → 2 DetectionResults`
- `Unit: deduplication removes overlapping Presidio + pattern results for same credit card`
- `Unit: severity = "critical" when PCI data detected with confidence >= 0.90`
- `Unit: severity = "info" when no detections found`
- `Unit: content_hash is SHA-256 of input text`
- `Unit: binary text/plain payload is decoded and scanned`
- `Integration: full pipeline scan of multi-entity document produces correct report`
- `Fixture: scan tests/fixtures/sample_documents/mixed_sensitive.txt → expected severity and counts`

---

#### 2.4 — Detector CRUD API

**What**: REST endpoints to manage custom detectors (create regex patterns, view system detectors, update configurations).

**Design**:

```python
# src/schemas/detector.py
class DetectorCreate(BaseModel):
    code: str = Field(max_length=100, pattern=r"^[A-Z0-9_]+$")
    display_name: str = Field(max_length=255)
    category: DetectorCategory
    detector_type: Literal["regex", "keyword", "ml_classifier", "fingerprint", "exact_data_match", "multimodal"]
    compliance_tags: list[str] = []
    config: dict  # validated per detector_type

class DetectorResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    code: str
    display_name: str
    category: str
    detector_type: str
    is_system: bool
    compliance_tags: list[str]
    config: dict
    created_at: datetime
    model_config = {"from_attributes": True}
```

Endpoints:
```
GET    /api/v1/detectors                   → PaginatedResponse[DetectorResponse]
POST   /api/v1/detectors                   → DetectorResponse
GET    /api/v1/detectors/{detector_id}      → DetectorResponse
PATCH  /api/v1/detectors/{detector_id}      → DetectorResponse
DELETE /api/v1/detectors/{detector_id}      → 204
POST   /api/v1/detectors/{detector_id}/test → list[DetectionResult]  (test a detector against sample text)
```

**Testing**:
- `Integration: POST /detectors with regex config → 201, detector created`
- `Integration: POST /detectors with invalid code (lowercase) → 422`
- `Integration: DELETE system detector → 403 Forbidden`
- `Integration: POST /detectors/{id}/test with sample text → detection results returned`
- `Integration: GET /detectors returns system + tenant-specific detectors`

---

## Phase 3: Policy Management and Enforcement

### Purpose

Build the policy framework that connects detectors to enforcement actions. After this phase, administrators can define policies ("block emails containing credit card numbers to external recipients"), test them in audit mode, and activate enforcement. This is where the DLP system transitions from a scanner to an enforcer.

### Tasks

#### 3.1 — Policy and Rule Data Model

**What**: Create the policies and policy_rules tables with migration, ORM models, and Pydantic schemas.

**Design**:

```python
# src/models/policy.py
class Policy(Base):
    __tablename__ = "policies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    status = Column(String(20), nullable=False, default="draft")  # draft, testing, active, disabled
    enforcement_mode = Column(String(20), nullable=False, default="audit")  # audit, warn, block
    priority = Column(Integer, nullable=False, default=100)  # lower = higher priority
    channels = Column(ARRAY(String(50)), nullable=False, server_default="{}")
    scope = Column(JSONB, nullable=False, server_default="{}")
    actions = Column(JSONB, nullable=False, server_default="[]")
    compliance_controls = Column(ARRAY(String(100)), server_default="{}")
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id = Column(UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    logical_operator = Column(String(10), nullable=False, default="ANY")  # ANY, ALL
    min_findings = Column(Integer, nullable=False, default=1)
    rule_order = Column(Integer, nullable=False, default=0)
    detectors = Column(JSONB, nullable=False, server_default="[]")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
```

Policy status lifecycle: `draft → testing → active → disabled`

```python
# src/schemas/policy.py
class PolicyCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = None
    enforcement_mode: Literal["audit", "warn", "block"] = "audit"
    priority: int = Field(default=100, ge=1, le=1000)
    channels: list[Literal["email", "web", "endpoint", "saas", "genai"]]
    scope: PolicyScope = Field(default_factory=PolicyScope)
    actions: list[PolicyAction] = Field(default_factory=list)
    compliance_controls: list[str] = []
    rules: list[PolicyRuleCreate] = Field(min_length=1)

class PolicyScope(BaseModel):
    include: ScopeFilter = Field(default_factory=ScopeFilter)
    exclude: ScopeFilter = Field(default_factory=ScopeFilter)

class ScopeFilter(BaseModel):
    departments: list[str] = []
    user_groups: list[str] = []
    users: list[str] = []
    locations: list[str] = []

class PolicyAction(BaseModel):
    type: Literal["block", "warn", "quarantine", "encrypt", "notify", "log"]
    config: dict = Field(default_factory=dict)

class PolicyRuleCreate(BaseModel):
    name: str = Field(max_length=255)
    logical_operator: Literal["ANY", "ALL"] = "ANY"
    min_findings: int = Field(default=1, ge=1)
    detectors: list[RuleDetectorRef] = Field(min_length=1)

class RuleDetectorRef(BaseModel):
    detector_id: uuid.UUID
    min_confidence: float = Field(default=0.80, ge=0.0, le=1.0)
    min_count: int = Field(default=1, ge=1)
```

**Testing**:
- `Unit: PolicyCreate requires at least one rule (min_length=1)`
- `Unit: PolicyCreate rejects priority < 1 or > 1000`
- `Unit: PolicyRuleCreate requires at least one detector reference`
- `Integration: Alembic migration creates policies and policy_rules tables`
- `Integration: RLS on policies table isolates tenants`

---

#### 3.2 — Policy CRUD API

**What**: REST endpoints for policy lifecycle management (create, update, activate, test, clone).

**Design**:

Endpoints:
```
POST   /api/v1/policies                       → PolicyResponse
GET    /api/v1/policies                        → PaginatedResponse[PolicyResponse]
GET    /api/v1/policies/{policy_id}            → PolicyResponse
PATCH  /api/v1/policies/{policy_id}            → PolicyResponse
DELETE /api/v1/policies/{policy_id}            → 204
POST   /api/v1/policies/{policy_id}/activate   → PolicyResponse (status → active)
POST   /api/v1/policies/{policy_id}/deactivate → PolicyResponse (status → disabled)
POST   /api/v1/policies/{policy_id}/test       → PolicyTestResult (dry-run against sample content)
POST   /api/v1/policies/{policy_id}/clone      → PolicyResponse (deep copy with draft status)
```

```python
class PolicyTestRequest(BaseModel):
    content: str
    source_type: str = "test"
    user_context: dict = Field(default_factory=dict)

class PolicyTestResult(BaseModel):
    policy_id: uuid.UUID
    would_trigger: bool
    matched_rules: list[str]
    detections: list[DetectionResult]
    enforcement_action: str  # what would happen if policy were active
```

**Testing**:
- `Integration: POST /policies creates policy with rules and detectors`
- `Integration: POST /policies/{id}/activate transitions draft → active`
- `Integration: POST /policies/{id}/activate on already-active policy → 409`
- `Integration: POST /policies/{id}/test with CC data → would_trigger=true, enforcement_action=block`
- `Integration: POST /policies/{id}/test with clean data → would_trigger=false`
- `Integration: POST /policies/{id}/clone → new policy with draft status, same rules`
- `Integration: DELETE active policy → 409 (must deactivate first)`

---

#### 3.3 — Policy Evaluation Engine

**What**: Build the core enforcement evaluator that takes a DetectionReport and evaluates it against active policies to determine what action to take.

**Design**:

```python
# src/enforcement/evaluator.py
from dataclasses import dataclass

@dataclass
class EvaluationContext:
    tenant_id: uuid.UUID
    user_id: uuid.UUID | None
    user_email: str | None
    user_department: str | None
    channel: str                  # email, web, endpoint, saas, genai
    source_ref: str | None
    destination: str | None
    timestamp: datetime

@dataclass
class PolicyDecision:
    policy_id: uuid.UUID
    policy_name: str
    enforcement_mode: str         # audit, warn, block
    matched_rule_ids: list[uuid.UUID]
    actions: list[PolicyAction]   # resolved action list
    severity: str

@dataclass
class EnforcementResult:
    decisions: list[PolicyDecision]
    final_action: str             # the most restrictive action across all matching policies
    should_block: bool
    should_warn: bool
    should_log: bool

class PolicyEvaluator:
    def __init__(self, policy_cache: PolicyCache):
        self.policy_cache = policy_cache

    async def evaluate(
        self,
        report: DetectionReport,
        context: EvaluationContext,
    ) -> EnforcementResult:
        """Evaluate detection report against all active policies for this tenant."""
        active_policies = await self.policy_cache.get_active_policies(
            tenant_id=context.tenant_id,
            channel=context.channel,
        )

        decisions: list[PolicyDecision] = []
        for policy in sorted(active_policies, key=lambda p: p.priority):
            if not self._in_scope(policy, context):
                continue
            matched_rules = self._evaluate_rules(policy.rules, report.detections)
            if matched_rules:
                decisions.append(PolicyDecision(
                    policy_id=policy.id,
                    policy_name=policy.name,
                    enforcement_mode=policy.enforcement_mode,
                    matched_rule_ids=[r.id for r in matched_rules],
                    actions=policy.actions,
                    severity=report.highest_severity,
                ))

        final_action = self._resolve_final_action(decisions)
        return EnforcementResult(
            decisions=decisions,
            final_action=final_action,
            should_block=final_action == "block",
            should_warn=final_action == "warn",
            should_log=True,  # always log
        )

    def _in_scope(self, policy: CachedPolicy, context: EvaluationContext) -> bool:
        """Check if context matches the policy's scope (include/exclude filters)."""
        ...

    def _evaluate_rules(
        self, rules: list[CachedPolicyRule], detections: list[DetectionResult]
    ) -> list[CachedPolicyRule]:
        """Return rules that match the detection results."""
        matched = []
        for rule in rules:
            if rule.logical_operator == "ANY":
                if any(self._detector_matches(det_ref, detections) for det_ref in rule.detectors):
                    matched.append(rule)
            elif rule.logical_operator == "ALL":
                if all(self._detector_matches(det_ref, detections) for det_ref in rule.detectors):
                    matched.append(rule)
        return matched

    def _resolve_final_action(self, decisions: list[PolicyDecision]) -> str:
        """Most restrictive action wins: block > warn > audit."""
        if any(d.enforcement_mode == "block" for d in decisions):
            return "block"
        if any(d.enforcement_mode == "warn" for d in decisions):
            return "warn"
        return "audit"
```

```python
# src/enforcement/actions.py
class ActionExecutor:
    async def execute(self, result: EnforcementResult, context: EvaluationContext) -> None:
        """Execute the resolved enforcement actions."""
        for decision in result.decisions:
            for action in decision.actions:
                match action.type:
                    case "block":
                        await self._block(context)
                    case "warn":
                        await self._warn(context, action.config)
                    case "quarantine":
                        await self._quarantine(context, action.config)
                    case "notify":
                        await self._notify(action.config)
                    case "log":
                        pass  # always logged via finding creation
```

Policy cache (Redis-backed):
```python
class PolicyCache:
    """Redis-backed cache of active policies, refreshed on policy changes."""
    def __init__(self, redis: Redis, ttl: int = 300):
        self.redis = redis
        self.ttl = ttl

    async def get_active_policies(self, tenant_id: uuid.UUID, channel: str) -> list[CachedPolicy]:
        ...

    async def invalidate(self, tenant_id: uuid.UUID) -> None:
        ...
```

**Testing**:
- `Unit: evaluate with CC detection + active PCI block policy → should_block=True`
- `Unit: evaluate with CC detection + audit-only policy → should_block=False, should_log=True`
- `Unit: most restrictive action wins when multiple policies match`
- `Unit: policy scope excludes user in excluded department`
- `Unit: ALL logical operator requires all detectors to match`
- `Unit: ANY logical operator triggers on first detector match`
- `Unit: no active policies for channel → empty decisions, final_action=audit`
- `Integration (mocked Redis): policy cache returns active policies for tenant`
- `Integration (mocked Redis): policy cache invalidates on policy update`

---

## Phase 4: Findings, Incidents, and Audit

### Purpose

Build the findings persistence layer, incident management, and audit logging. After this phase, every detection produces a traceable finding record, findings can be grouped into incidents for investigation, and all actions are audit-logged for compliance.

### Tasks

#### 4.1 — Findings Data Model and Persistence

**What**: Create the findings table, ORM model, and persistence service that stores detection results as findings linked to policies and users.

**Design**:

```python
# src/models/finding.py
class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    policy_id = Column(UUID(as_uuid=True), ForeignKey("policies.id"), nullable=False)
    rule_id = Column(UUID(as_uuid=True), ForeignKey("policy_rules.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    endpoint_id = Column(UUID(as_uuid=True), ForeignKey("endpoints.id"), nullable=True)

    channel = Column(String(50), nullable=False)
    matched_type = Column(String(100), nullable=False)
    category = Column(String(50), nullable=False)
    confidence = Column(Numeric(3, 2), nullable=False)
    match_count = Column(Integer, nullable=False, default=1)
    severity = Column(String(20), nullable=False)
    action_taken = Column(String(30), nullable=False)
    content_hash = Column(LargeBinary, nullable=True)
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
    detection_details = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
```

```python
# src/schemas/finding.py
class FindingResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    policy_id: uuid.UUID
    user_id: uuid.UUID | None
    channel: str
    matched_type: str
    category: str
    confidence: float
    match_count: int
    severity: str
    action_taken: str
    detected_at: datetime
    detection_details: dict
    model_config = {"from_attributes": True}

class FindingFilters(BaseModel):
    channel: str | None = None
    category: str | None = None
    severity: str | None = None
    user_id: uuid.UUID | None = None
    policy_id: uuid.UUID | None = None
    date_from: datetime | None = None
    date_to: datetime | None = None
```

Endpoints:
```
GET    /api/v1/findings                       → PaginatedResponse[FindingResponse]
GET    /api/v1/findings/{finding_id}          → FindingResponse
GET    /api/v1/findings/stats                 → FindingStats (aggregates by severity, category, channel)
POST   /api/v1/findings/search                → PaginatedResponse[FindingResponse] (advanced JSONB search)
```

**Testing**:
- `Integration: finding created after policy evaluation, retrievable via GET`
- `Integration: GET /findings filters by severity correctly`
- `Integration: GET /findings filters by date range correctly`
- `Integration: GET /findings/stats returns correct aggregates`
- `Integration: findings from other tenants not visible (RLS)`
- `Integration: content_hash dedup prevents duplicate findings for same content`

---

#### 4.2 — Incident Management

**What**: Build incident CRUD, finding-to-incident linking, and incident lifecycle (open, investigating, escalated, resolved, closed).

**Design**:

```python
# src/models/incident.py
class Incident(Base):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)
    status = Column(String(30), nullable=False, default="open")
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    finding_ids = Column(ARRAY(UUID(as_uuid=True)), nullable=False, server_default="{}")
    resolution = Column(JSONB, server_default="{}")
    timeline = Column(JSONB, nullable=False, server_default="[]")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
```

Incident status lifecycle: `open → investigating → escalated → resolved → closed`
Special status: `false_positive` (terminal)

```python
# src/incidents/manager.py
class IncidentManager:
    VALID_TRANSITIONS = {
        "open": {"investigating", "resolved", "false_positive"},
        "investigating": {"escalated", "resolved", "false_positive"},
        "escalated": {"investigating", "resolved"},
        "resolved": {"closed", "open"},  # reopen
        "closed": set(),
        "false_positive": set(),
    }

    async def create_from_findings(
        self, tenant_id: uuid.UUID, finding_ids: list[uuid.UUID]
    ) -> Incident:
        """Create an incident grouping related findings."""
        ...

    async def transition(
        self, incident_id: uuid.UUID, new_status: str, actor_id: uuid.UUID, notes: str = ""
    ) -> Incident:
        """Transition incident to a new status, validating the transition."""
        current = await self._get_incident(incident_id)
        if new_status not in self.VALID_TRANSITIONS[current.status]:
            raise InvalidTransition(current.status, new_status)
        # Append to timeline JSONB
        ...

    async def add_comment(
        self, incident_id: uuid.UUID, actor_id: uuid.UUID, body: str
    ) -> Incident:
        """Add a comment to the incident timeline."""
        ...
```

Endpoints:
```
POST   /api/v1/incidents                             → IncidentResponse
GET    /api/v1/incidents                              → PaginatedResponse[IncidentResponse]
GET    /api/v1/incidents/{incident_id}                → IncidentResponse
PATCH  /api/v1/incidents/{incident_id}                → IncidentResponse
POST   /api/v1/incidents/{incident_id}/transition     → IncidentResponse
POST   /api/v1/incidents/{incident_id}/comment        → IncidentResponse
POST   /api/v1/incidents/{incident_id}/assign         → IncidentResponse
POST   /api/v1/incidents/{incident_id}/findings       → IncidentResponse (link additional findings)
```

**Testing**:
- `Integration: POST /incidents creates incident with linked findings`
- `Integration: POST /incidents/{id}/transition open→investigating → success`
- `Integration: POST /incidents/{id}/transition open→closed → 400 (invalid transition)`
- `Integration: POST /incidents/{id}/comment appends to timeline JSONB`
- `Integration: POST /incidents/{id}/assign updates assigned_to`
- `Integration: GET /incidents filters by status and severity`
- `Unit: VALID_TRANSITIONS prevents closed→open`
- `Unit: create_from_findings calculates severity from linked findings`

---

#### 4.3 — Audit Logging

**What**: Implement comprehensive audit logging for all state-changing operations, satisfying ISO 27001 A.8.12 and NIST SP 800-53 SI-12 requirements.

**Design**:

```python
# src/models/audit.py
class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), nullable=False)
    actor_id = Column(UUID(as_uuid=True), nullable=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(UUID(as_uuid=True), nullable=True)
    details = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
```

Audit log actions follow the convention `{resource}.{verb}`:
- `policy.created`, `policy.activated`, `policy.deactivated`
- `incident.created`, `incident.transitioned`, `incident.assigned`
- `finding.created`
- `user.created`, `user.updated`, `user.deleted`
- `detector.created`, `detector.updated`, `detector.deleted`

```python
# src/audit/logger.py
class AuditLogger:
    def __init__(self, session_factory: async_sessionmaker):
        self.session_factory = session_factory

    async def log(
        self,
        tenant_id: uuid.UUID,
        actor_id: uuid.UUID | None,
        action: str,
        resource_type: str,
        resource_id: uuid.UUID | None = None,
        details: dict | None = None,
        request: Request | None = None,
    ) -> None:
        details = details or {}
        if request:
            details["actor_ip"] = request.client.host
            details["user_agent"] = request.headers.get("user-agent", "")
        async with self.session_factory() as session:
            entry = AuditLog(
                tenant_id=tenant_id,
                actor_id=actor_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details,
            )
            session.add(entry)
            await session.commit()
```

FastAPI middleware for automatic audit logging:
```python
@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    response = await call_next(request)
    if request.method in ("POST", "PATCH", "PUT", "DELETE"):
        # Log the action via AuditLogger
        ...
    return response
```

Endpoints:
```
GET    /api/v1/audit-log                → PaginatedResponse[AuditLogResponse]
GET    /api/v1/audit-log/export         → StreamingResponse (CSV/JSON export)
```

**Testing**:
- `Integration: creating a policy generates audit_log entry with action="policy.created"`
- `Integration: audit log captures actor_ip from request`
- `Integration: audit log entries are immutable (no UPDATE/DELETE endpoint)`
- `Integration: GET /audit-log filters by action, resource_type, date range`
- `Integration: audit log respects tenant isolation (RLS)`
- `Unit: AuditLogger.log creates entry with correct fields`

---

## Phase 5: Email Channel — SMTP Proxy DLP

### Purpose

Implement the first monitoring channel: an SMTP proxy that intercepts outbound email, inspects it for sensitive content, and enforces policy (block, warn, or log). Email is the most common DLP enforcement channel and validates the full detection-to-enforcement pipeline.

### Tasks

#### 5.1 — SMTP Proxy Server

**What**: Build an async SMTP proxy using aiosmtpd that intercepts outbound email, passes it through the detection engine, and forwards or blocks based on policy decisions.

**Design**:

```python
# src/channels/email_channel.py
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, Session, SMTP

class DLPSMTPHandler:
    def __init__(
        self,
        detection_engine: DetectionEngine,
        policy_evaluator: PolicyEvaluator,
        action_executor: ActionExecutor,
        upstream_host: str,
        upstream_port: int,
    ):
        self.detection_engine = detection_engine
        self.policy_evaluator = policy_evaluator
        self.action_executor = action_executor
        self.upstream_host = upstream_host
        self.upstream_port = upstream_port

    async def handle_DATA(
        self, server: SMTP, session: Session, envelope: Envelope
    ) -> str:
        # 1. Parse email (headers, body, attachments)
        message = email.message_from_bytes(envelope.content)
        text_parts = self._extract_text(message)
        attachments = self._extract_attachments(message)

        # 2. Run detection on body + attachments
        payload = ContentPayload(
            content_id=message["Message-ID"] or str(uuid.uuid4()),
            text="\n".join(text_parts),
            source_type="email",
            source_ref=message["Message-ID"],
        )
        report = await self.detection_engine.inspect(payload)

        # 3. Evaluate against policies
        context = EvaluationContext(
            tenant_id=...,  # resolved from sender domain
            user_id=...,    # resolved from sender email
            user_email=envelope.mail_from,
            channel="email",
            destination=str(envelope.rcpt_tos),
        )
        result = await self.policy_evaluator.evaluate(report, context)

        # 4. Execute enforcement
        if result.should_block:
            await self._create_finding(report, context, result, "blocked")
            return "550 Message blocked by DLP policy"

        # 5. Forward to upstream MTA
        await self._forward(envelope)
        await self._create_finding(report, context, result, result.final_action)
        return "250 OK"

    def _extract_text(self, message: Message) -> list[str]:
        """Extract text from all text/* MIME parts."""
        ...

    def _extract_attachments(self, message: Message) -> list[tuple[str, bytes]]:
        """Extract attachment filenames and content."""
        ...
```

Configuration:
```python
class EmailChannelSettings(BaseModel):
    listen_host: str = "0.0.0.0"
    listen_port: int = 2525
    upstream_host: str = "localhost"
    upstream_port: int = 25
    tls_enabled: bool = False
    tls_cert_path: str | None = None
    tls_key_path: str | None = None
    max_message_size_mb: int = 25
```

**Testing**:
- `Integration (mocked upstream): email with SSN in body → 550 blocked (block policy active)`
- `Integration (mocked upstream): email with no sensitive data → 250 OK, forwarded`
- `Integration (mocked upstream): email with CC in attachment → finding created`
- `Unit: _extract_text handles multipart/alternative (text + html)`
- `Unit: _extract_text handles base64-encoded text parts`
- `Unit: _extract_attachments extracts .csv and .txt attachments`
- `Fixture: tests/fixtures/sample_emails/pci_in_body.eml → blocked`
- `Fixture: tests/fixtures/sample_emails/clean_email.eml → forwarded`

---

#### 5.2 — Email Integration API

**What**: REST endpoints to configure and monitor the email channel.

**Design**:

Endpoints:
```
POST   /api/v1/integrations/email            → IntegrationResponse (configure email gateway)
GET    /api/v1/integrations/email             → IntegrationResponse (current config + status)
PATCH  /api/v1/integrations/email             → IntegrationResponse
GET    /api/v1/integrations/email/stats       → EmailChannelStats (messages scanned, blocked, forwarded)
POST   /api/v1/integrations/email/test        → EmailTestResult (send test email through proxy)
```

**Testing**:
- `Integration: POST /integrations/email configures upstream MTA`
- `Integration: GET /integrations/email/stats returns correct counts`
- `Integration: POST /integrations/email/test sends test email and returns detection results`

---

## Phase 6: API Authentication and Authorisation

### Purpose

Implement production-grade authentication (OAuth 2.0 / JWT) and role-based access control. After this phase, all API endpoints are protected, API clients can authenticate via client credentials, and users authenticate via IdP integration (Okta, Entra ID). Required for PCI DSS Requirement 7 (restrict access) and HIPAA access control requirements.

### Tasks

#### 6.1 — JWT Token Issuance and Validation

**What**: Implement JWT-based authentication with access and refresh tokens per RFC 7519.

**Design**:

```python
# src/auth/oauth.py
from jose import jwt, JWTError
from datetime import datetime, timedelta

class TokenService:
    def __init__(self, secret_key: str, algorithm: str = "HS256"):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def create_access_token(
        self,
        user_id: uuid.UUID,
        tenant_id: uuid.UUID,
        roles: list[str],
        expires_minutes: int = 60,
    ) -> str:
        payload = {
            "sub": str(user_id),
            "tenant_id": str(tenant_id),
            "roles": roles,
            "exp": datetime.utcnow() + timedelta(minutes=expires_minutes),
            "iat": datetime.utcnow(),
            "type": "access",
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def create_refresh_token(self, user_id: uuid.UUID, tenant_id: uuid.UUID) -> str:
        payload = {
            "sub": str(user_id),
            "tenant_id": str(tenant_id),
            "exp": datetime.utcnow() + timedelta(days=30),
            "type": "refresh",
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode_token(self, token: str) -> dict:
        return jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
```

```python
# src/auth/rbac.py
from enum import Enum
from fastapi import Depends, HTTPException

class Permission(str, Enum):
    POLICIES_READ = "policies:read"
    POLICIES_WRITE = "policies:write"
    FINDINGS_READ = "findings:read"
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_WRITE = "incidents:write"
    AUDIT_READ = "audit:read"
    ADMIN = "admin"

ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "admin": {p for p in Permission},
    "policy_author": {Permission.POLICIES_READ, Permission.POLICIES_WRITE, Permission.FINDINGS_READ},
    "analyst": {Permission.FINDINGS_READ, Permission.INCIDENTS_READ, Permission.INCIDENTS_WRITE},
    "viewer": {Permission.FINDINGS_READ, Permission.INCIDENTS_READ},
}

def require_permission(permission: Permission):
    async def check(current_user: User = Depends(get_current_user)):
        user_permissions = set()
        for role in current_user.roles:
            user_permissions |= ROLE_PERMISSIONS.get(role, set())
        if permission not in user_permissions:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return check
```

Endpoints:
```
POST   /api/v1/auth/token            → TokenResponse (user login)
POST   /api/v1/auth/refresh           → TokenResponse (refresh access token)
POST   /api/v1/auth/api-keys          → ApiKeyResponse (create API client credentials)
DELETE /api/v1/auth/api-keys/{key_id} → 204
GET    /api/v1/auth/me                → UserResponse (current user from JWT)
```

**Testing**:
- `Unit: create_access_token encodes user_id, tenant_id, roles in JWT`
- `Unit: decode_token rejects expired tokens`
- `Unit: decode_token rejects tokens with wrong algorithm`
- `Unit: require_permission("policies:write") allows admin role`
- `Unit: require_permission("policies:write") rejects viewer role`
- `Integration: unauthenticated GET /policies → 401`
- `Integration: authenticated GET /policies with viewer role → 200`
- `Integration: authenticated POST /policies with viewer role → 403`
- `Integration: API key authentication works for machine clients`

---

#### 6.2 — API Client Management (Machine-to-Machine)

**What**: API client registration and client_credentials OAuth flow for SIEM/SOAR integrations.

**Design**:

```python
# src/models/api_client.py
class ApiClient(Base):
    __tablename__ = "api_clients"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    client_id = Column(String(100), nullable=False, unique=True)
    client_secret_hash = Column(LargeBinary, nullable=False)
    scopes = Column(ARRAY(Text), nullable=False, server_default="{}")
    rate_limit_rpm = Column(Integer, nullable=False, default=600)
    status = Column(String(20), nullable=False, default="active")
    metadata = Column(JSONB, server_default="{}")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True))
```

```
POST   /api/v1/auth/clients                  → ApiClientResponse (registers new client, returns secret once)
POST   /api/v1/auth/clients/token             → TokenResponse (client_credentials grant)
```

**Testing**:
- `Integration: POST /auth/clients creates API client, returns client_secret once`
- `Integration: POST /auth/clients/token with valid credentials → access token`
- `Integration: POST /auth/clients/token with invalid credentials → 401`
- `Integration: API client scopes restrict accessible endpoints`
- `Unit: client_secret is stored as bcrypt hash, not plaintext`

---

## Phase 7: Webhook and SIEM Export

### Purpose

Enable the DLP platform to push events to external systems. Webhooks notify SOAR/ticketing systems of new findings and incidents. SIEM export formats findings as OCSF JSON, CEF, or Syslog for ingestion by Splunk, Sentinel, QRadar, and Elastic.

### Tasks

#### 7.1 — Webhook Delivery System

**What**: Build a webhook registration and delivery system with retry logic, signature verification, and failure tracking.

**Design**:

```python
# src/models/webhook (in api_client.py)
class Webhook(Base):
    __tablename__ = "webhooks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    url = Column(Text, nullable=False)
    secret_hash = Column(LargeBinary, nullable=False)
    event_types = Column(ARRAY(String(100)), nullable=False)
    status = Column(String(20), nullable=False, default="active")
    config = Column(JSONB, server_default="{}")
    last_triggered = Column(DateTime(timezone=True))
    failure_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
```

Webhook payload format:
```python
class WebhookPayload(BaseModel):
    event_id: uuid.UUID
    event_type: str            # finding.created, incident.created, incident.escalated
    timestamp: datetime
    tenant_id: uuid.UUID
    data: dict                 # event-specific payload
```

```python
# src/tasks/webhook_tasks.py
@celery_app.task(bind=True, max_retries=5, default_retry_delay=60)
def deliver_webhook(self, webhook_id: str, payload: dict) -> None:
    """Deliver webhook with HMAC signature and exponential backoff retry."""
    webhook = get_webhook(webhook_id)
    signature = hmac.new(webhook.secret, json.dumps(payload).encode(), hashlib.sha256).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-DLP-Signature": f"sha256={signature}",
        "X-DLP-Event": payload["event_type"],
    }
    response = httpx.post(webhook.url, json=payload, headers=headers, timeout=10)
    if response.status_code >= 400:
        raise self.retry(exc=WebhookDeliveryError(response.status_code))
```

Endpoints:
```
POST   /api/v1/webhooks                     → WebhookResponse
GET    /api/v1/webhooks                     → list[WebhookResponse]
PATCH  /api/v1/webhooks/{webhook_id}         → WebhookResponse
DELETE /api/v1/webhooks/{webhook_id}         → 204
POST   /api/v1/webhooks/{webhook_id}/test    → WebhookTestResult
```

**Testing**:
- `Integration (mocked endpoint): webhook delivers finding.created payload with correct HMAC`
- `Integration (mocked endpoint): webhook retries on 500 response`
- `Integration (mocked endpoint): webhook disables after 5 consecutive failures`
- `Integration: POST /webhooks/{id}/test sends test payload and reports result`
- `Unit: HMAC signature matches expected value for known payload`

---

#### 7.2 — SIEM Export (OCSF, CEF, Syslog)

**What**: Export findings and incidents in standard security event formats for SIEM ingestion.

**Design**:

```python
# src/export/ocsf.py
class OCSFMapper:
    """Map DLP findings to OCSF Data Security Finding event class (class_uid=2001)."""

    CATEGORY_MAP = {
        "pii": {"category_uid": 2, "category_name": "Findings"},
        "pci": {"category_uid": 2, "category_name": "Findings"},
        "phi": {"category_uid": 2, "category_name": "Findings"},
        "credentials": {"category_uid": 2, "category_name": "Findings"},
    }

    SEVERITY_MAP = {
        "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
    }

    def to_ocsf(self, finding: Finding, tenant: Tenant, user: User | None) -> dict:
        return {
            "class_uid": 2001,
            "class_name": "Data Security Finding",
            "category_uid": 2,
            "severity_id": self.SEVERITY_MAP[finding.severity],
            "activity_id": 1,  # Create
            "time": finding.detected_at.isoformat(),
            "message": f"DLP: {finding.matched_type} detected in {finding.channel}",
            "finding_info": {
                "uid": str(finding.id),
                "title": f"{finding.matched_type} detected",
                "types": [finding.category],
                "data_sources": [finding.channel],
            },
            "actor": {
                "user": {"email_addr": user.email if user else None},
            },
            "metadata": {
                "product": {"name": "DLP Platform", "vendor_name": "Open Source"},
                "version": "1.0.0",
            },
        }
```

```python
# src/export/cef.py
class CEFFormatter:
    def to_cef(self, finding: Finding) -> str:
        severity = {"info": 1, "low": 3, "medium": 5, "high": 7, "critical": 10}
        return (
            f"CEF:0|DLP|DLP Platform|1.0|{finding.matched_type}|"
            f"Data Loss Prevention Finding|{severity[finding.severity]}|"
            f"src={finding.detection_details.get('source_ref', '')} "
            f"dst={finding.detection_details.get('destination', '')} "
            f"cat={finding.category} "
            f"cs1={finding.channel} cs1Label=Channel "
            f"cn1={finding.match_count} cn1Label=MatchCount"
        )
```

```python
# src/export/syslog.py (RFC 5424)
class SyslogFormatter:
    def to_syslog(self, finding: Finding) -> str:
        """Format as RFC 5424 syslog message."""
        ...
```

Endpoints:
```
POST   /api/v1/integrations/siem              → SIEMIntegrationResponse
GET    /api/v1/integrations/siem              → list[SIEMIntegrationResponse]
POST   /api/v1/integrations/siem/{id}/test     → SIEMTestResult
GET    /api/v1/export/findings                 → StreamingResponse (OCSF JSON / CEF / Syslog)
```

**Testing**:
- `Unit: OCSFMapper produces valid OCSF JSON with correct class_uid=2001`
- `Unit: CEFFormatter produces valid CEF string with correct severity mapping`
- `Unit: SyslogFormatter produces RFC 5424 compliant output`
- `Integration: GET /export/findings?format=ocsf returns OCSF JSON stream`
- `Fixture: finding fixture → expected OCSF output (golden file test)`

---

## Phase 8: Frontend Dashboard

### Purpose

Build the web-based admin dashboard for policy management, finding investigation, incident triage, and compliance reporting. After this phase, security teams have a visual interface for all DLP operations.

### Tasks

#### 8.1 — Frontend Scaffold and API Client

**What**: Set up React + TypeScript + Vite project with auto-generated API client from OpenAPI spec.

**Design**:

```
frontend/
├── package.json
├── tsconfig.json
├── vite.config.ts
├── src/
│   ├── main.tsx
│   ├── App.tsx
│   ├── api/
│   │   └── client.ts           # Generated from OpenAPI via openapi-typescript-codegen
│   ├── components/
│   │   └── ui/                  # shadcn/ui components
│   ├── hooks/
│   │   ├── useAuth.ts
│   │   ├── useFindings.ts
│   │   └── usePolicies.ts
│   ├── pages/
│   │   ├── LoginPage.tsx
│   │   ├── DashboardPage.tsx
│   │   ├── PoliciesPage.tsx
│   │   ├── FindingsPage.tsx
│   │   ├── IncidentsPage.tsx
│   │   └── CompliancePage.tsx
│   ├── stores/
│   │   └── authStore.ts         # Zustand for auth state
│   └── types/
│       └── index.ts
```

```typescript
// src/api/client.ts
import createClient from "openapi-fetch";
import type { paths } from "./generated/schema";

export const api = createClient<paths>({
  baseUrl: import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1",
});

// Auth interceptor
api.use({
  onRequest: ({ request }) => {
    const token = localStorage.getItem("access_token");
    if (token) {
      request.headers.set("Authorization", `Bearer ${token}`);
    }
    return request;
  },
});
```

```typescript
// src/stores/authStore.ts
import { create } from "zustand";

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  token: null,
  isAuthenticated: false,
  login: async (email, password) => { /* POST /auth/token */ },
  logout: () => set({ user: null, token: null, isAuthenticated: false }),
}));
```

**Testing**:
- `Unit (Vitest): authStore.login sets token and user on success`
- `Unit (Vitest): authStore.logout clears all auth state`
- `Unit (Vitest): API client attaches Bearer token to requests`
- `E2E: login flow renders dashboard after successful authentication`

---

#### 8.2 — Dashboard Overview Page

**What**: Build the main dashboard showing finding trends, severity distribution, active incidents, and channel breakdown.

**Design**:

```typescript
// src/pages/DashboardPage.tsx
interface DashboardStats {
  findingsToday: number;
  findingsThisWeek: number;
  activeIncidents: number;
  blockedActions: number;
  findingsBySeverity: Record<string, number>;
  findingsByChannel: Record<string, number>;
  findingsTrend: { date: string; count: number }[];
  topViolatedPolicies: { policy_name: string; count: number }[];
}

// Components:
// - StatCard: large number + label + trend indicator
// - SeverityPieChart: Recharts PieChart for severity distribution
// - ChannelBarChart: Recharts BarChart for channel breakdown
// - FindingsTrendLine: Recharts LineChart for 30-day trend
// - TopPoliciesTable: sortable table of most-triggered policies
// - ActiveIncidentsList: recent open/escalated incidents
```

**Testing**:
- `Unit (Vitest): DashboardPage renders StatCards with correct values from API response`
- `Unit (Vitest): SeverityPieChart renders correct segments`
- `Unit (Vitest): DashboardPage shows "No data" state when stats are empty`

---

#### 8.3 — Policy Management UI

**What**: Policy list, detail, create/edit forms, and policy testing interface.

**Design**:

Pages and components:
- `PoliciesPage` — table of all policies with status, enforcement mode, priority; filter by status
- `PolicyDetailPage` — view policy with rules and detectors; action buttons for activate/deactivate/clone
- `PolicyFormPage` — create/edit form with dynamic rule builder (add rules, select detectors, set thresholds)
- `PolicyTestPanel` — paste sample content, run against policy, see detection results

```typescript
// src/components/policies/PolicyRuleBuilder.tsx
interface PolicyRuleFormData {
  name: string;
  logical_operator: "ANY" | "ALL";
  min_findings: number;
  detectors: {
    detector_id: string;
    min_confidence: number;
    min_count: number;
  }[];
}
```

**Testing**:
- `Unit (Vitest): PolicyRuleBuilder adds/removes detector rows`
- `Unit (Vitest): PolicyFormPage validates at least one rule required`
- `Unit (Vitest): PolicyTestPanel displays detection results correctly`
- `E2E: create policy → appears in policy list with "draft" status`

---

#### 8.4 — Findings and Incidents UI

**What**: Finding list with filtering, finding detail view, incident list, and incident investigation workflow.

**Design**:

- `FindingsPage` — table with filters (severity, channel, category, date range, user); sortable columns
- `FindingDetailPage` — shows detection details, matched policy, user context, redacted content snippet
- `IncidentsPage` — Kanban-style board (Open | Investigating | Escalated | Resolved)
- `IncidentDetailPage` — timeline view, linked findings, comments, status transition buttons, assignment

```typescript
// src/components/incidents/IncidentTimeline.tsx
interface TimelineEntry {
  at: string;
  event: "created" | "assigned" | "commented" | "escalated" | "resolved";
  actor: string;
  details?: string;
}
```

**Testing**:
- `Unit (Vitest): FindingsPage renders table with correct columns`
- `Unit (Vitest): severity filter updates API query params`
- `Unit (Vitest): IncidentTimeline renders events in chronological order`
- `Unit (Vitest): status transition buttons only show valid transitions`
- `E2E: filter findings by severity=critical → table shows only critical findings`

---

## Phase 9: Endpoint Agent and Additional Channels

### Purpose

Extend DLP coverage beyond email to endpoints (file operations, clipboard, USB), web proxy, and SaaS applications (Slack, Microsoft 365, Google Workspace). After this phase, the platform monitors all major data exfiltration channels.

### Tasks

#### 9.1 — Endpoint Integration Model and API

**What**: Create the endpoints table and REST API for registering and managing monitored endpoints.

**Design**:

```python
# src/models/endpoint.py
class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    hostname = Column(String(255), nullable=False)
    assigned_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    agent_status = Column(String(20), nullable=False, default="unknown")
    last_heartbeat = Column(DateTime(timezone=True))
    system_info = Column(JSONB, nullable=False, server_default="{}")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
```

Endpoints:
```
GET    /api/v1/endpoints                          → PaginatedResponse[EndpointResponse]
POST   /api/v1/endpoints/register                 → EndpointResponse (agent self-registration)
POST   /api/v1/endpoints/{id}/heartbeat            → 200 (agent heartbeat)
POST   /api/v1/endpoints/{id}/findings             → 201 (agent submits findings)
GET    /api/v1/endpoints/{id}/policies             → list[PolicyResponse] (agent fetches applicable policies)
```

**Testing**:
- `Integration: POST /endpoints/register creates endpoint with system_info`
- `Integration: POST /endpoints/{id}/heartbeat updates last_heartbeat and agent_status`
- `Integration: POST /endpoints/{id}/findings creates finding linked to endpoint`
- `Integration: stale endpoints (no heartbeat >5 min) marked as "offline"`

---

#### 9.2 — SaaS Integration Framework

**What**: Build the integration framework for monitoring SaaS applications via OAuth-connected APIs.

**Design**:

```python
# src/channels/base.py
from abc import ABC, abstractmethod

class SaaSChannel(ABC):
    @abstractmethod
    async def connect(self, oauth_token: str) -> None:
        """Establish connection to SaaS provider."""
        ...

    @abstractmethod
    async def poll_events(self, since: datetime) -> list[ContentPayload]:
        """Poll for new content events since the given timestamp."""
        ...

    @abstractmethod
    async def enforce(self, content_id: str, action: str) -> bool:
        """Execute enforcement action on the content."""
        ...
```

```python
# src/channels/saas/slack.py
class SlackChannel(SaaSChannel):
    """Monitor Slack messages for sensitive content via Slack Events API."""
    async def connect(self, oauth_token: str) -> None:
        self.client = AsyncWebClient(token=oauth_token)

    async def poll_events(self, since: datetime) -> list[ContentPayload]:
        # Use conversations.history to fetch messages
        ...

    async def enforce(self, content_id: str, action: str) -> bool:
        if action == "block":
            await self.client.chat_delete(channel=..., ts=content_id)
            return True
        ...
```

```python
# src/models/integration.py
class Integration(Base):
    __tablename__ = "integrations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    integration_type = Column(String(50), nullable=False)
    provider = Column(String(50), nullable=False)
    name = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False, default="inactive")
    config = Column(JSONB, nullable=False, server_default="{}")
    credentials_enc = Column(LargeBinary)
    last_sync_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
```

Endpoints:
```
POST   /api/v1/integrations                     → IntegrationResponse
GET    /api/v1/integrations                     → list[IntegrationResponse]
PATCH  /api/v1/integrations/{id}                 → IntegrationResponse
DELETE /api/v1/integrations/{id}                 → 204
POST   /api/v1/integrations/{id}/connect          → IntegrationResponse (trigger OAuth flow)
POST   /api/v1/integrations/{id}/sync             → SyncResult (manual poll)
```

**Testing**:
- `Integration (mocked Slack API): SlackChannel.poll_events returns ContentPayloads`
- `Integration (mocked Slack API): SlackChannel.enforce("block") deletes message`
- `Integration: POST /integrations creates integration record with encrypted credentials`
- `Unit: SaaSChannel abstract class enforces interface contract`

---

## Phase 10: Compliance Reporting

### Purpose

Build the compliance reporting engine that maps DLP findings to regulatory frameworks (GDPR, HIPAA, PCI DSS, ISO 27001, NIST). After this phase, compliance officers can generate framework-specific reports showing control coverage, violation trends, and overall compliance posture.

### Tasks

#### 10.1 — Compliance Framework Data and Mapping

**What**: Seed compliance frameworks and controls, implement policy-to-control mapping.

**Design**:

```python
# Seed data for compliance_reports table
FRAMEWORKS = [
    {"code": "gdpr", "name": "General Data Protection Regulation", "version": "2016/679",
     "controls": [
        {"control_id": "Art.25", "title": "Data protection by design and by default"},
        {"control_id": "Art.32", "title": "Security of processing"},
        {"control_id": "Art.33", "title": "Notification of a personal data breach"},
     ]},
    {"code": "hipaa", "name": "HIPAA Security Rule", "version": "45 CFR §164",
     "controls": [
        {"control_id": "164.312(a)", "title": "Access control"},
        {"control_id": "164.312(e)", "title": "Transmission security"},
     ]},
    {"code": "pci_dss_v4", "name": "PCI DSS", "version": "4.0",
     "controls": [
        {"control_id": "Req.3", "title": "Protect stored account data"},
        {"control_id": "Req.4", "title": "Protect cardholder data with strong cryptography"},
        {"control_id": "Req.7", "title": "Restrict access to system components and cardholder data"},
     ]},
    {"code": "iso_27001", "name": "ISO/IEC 27001:2022", "version": "2022",
     "controls": [
        {"control_id": "A.8.12", "title": "Data leakage prevention"},
     ]},
    {"code": "nist_800_53", "name": "NIST SP 800-53", "version": "Rev. 5",
     "controls": [
        {"control_id": "SI-12", "title": "Information management and retention"},
        {"control_id": "MP-6", "title": "Media sanitization"},
     ]},
]
```

**Testing**:
- `Integration: seed migration populates all frameworks and controls`
- `Integration: policy compliance_controls array maps to framework controls`
- `Unit: framework lookup by code returns correct version`

---

#### 10.2 — Compliance Report Generation

**What**: Build the compliance report generator that aggregates findings by framework and produces point-in-time compliance snapshots.

**Design**:

```python
# src/compliance/reporter.py
class ComplianceReporter:
    async def generate_report(
        self,
        tenant_id: uuid.UUID,
        framework_code: str,
        period_start: datetime,
        period_end: datetime,
    ) -> ComplianceReport:
        """Generate a compliance report for a specific framework and time period."""
        # 1. Fetch all policies mapped to this framework's controls
        # 2. Aggregate findings for those policies in the period
        # 3. Calculate compliance score
        # 4. Store as compliance_reports snapshot
        ...

class ComplianceReport(BaseModel):
    id: uuid.UUID
    framework: str
    period_start: datetime
    period_end: datetime
    summary: ComplianceSummary
    controls: list[ControlStatus]

class ComplianceSummary(BaseModel):
    total_findings: int
    findings_by_severity: dict[str, int]
    active_policies: int
    controls_covered: int
    controls_total: int
    compliance_score: float  # 0-100

class ControlStatus(BaseModel):
    control_id: str
    title: str
    policy_count: int
    finding_count: int
    status: Literal["compliant", "at_risk", "non_compliant"]
```

Endpoints:
```
POST   /api/v1/compliance/reports                → ComplianceReport (generate new report)
GET    /api/v1/compliance/reports                → list[ComplianceReportSummary]
GET    /api/v1/compliance/reports/{report_id}     → ComplianceReport
GET    /api/v1/compliance/dashboard               → ComplianceDashboard (cross-framework summary)
```

**Testing**:
- `Integration: POST /compliance/reports generates GDPR report with correct control mapping`
- `Integration: compliance score reflects finding count vs. policy coverage`
- `Unit: compliance_score = 100 when 0 findings across all controls`
- `Unit: compliance_score degrades proportionally to finding severity and count`
- `Fixture: tenant with known policies and findings → expected compliance score`

---

## Phase 11: Advanced Detection — OCR, Images, and GenAI Monitoring

### Purpose

Extend detection capabilities to close gaps that differentiate this platform from legacy DLP: visual content detection (OCR for images and PDFs) and GenAI API monitoring (detect sensitive data flowing to ChatGPT, Claude, etc.). These are the AI-native advantages identified in the research.

### Tasks

#### 11.1 — OCR-Based Detection for Images and PDFs

**What**: Add Tesseract OCR integration to detect sensitive data in images, screenshots, and PDF documents.

**Design**:

```python
# src/detection/ocr_detector.py
import pytesseract
from PIL import Image
from io import BytesIO
import fitz  # PyMuPDF for PDF rendering

class OCRDetector:
    def __init__(self, pattern_detector: PatternDetector, presidio_detector: PresidioDetector):
        self.pattern_detector = pattern_detector
        self.presidio_detector = presidio_detector

    def detect_image(self, image_bytes: bytes) -> list[DetectionResult]:
        """Extract text from image via OCR, then run detection."""
        image = Image.open(BytesIO(image_bytes))
        text = pytesseract.image_to_string(image)
        if not text.strip():
            return []
        results = self.pattern_detector.detect(text) + self.presidio_detector.detect(text)
        for r in results:
            r.metadata["source"] = "ocr"
            r.metadata["ocr_confidence"] = self._get_ocr_confidence(image)
        return results

    def detect_pdf(self, pdf_bytes: bytes) -> list[DetectionResult]:
        """Extract text from PDF pages (text layer + OCR fallback), then run detection."""
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        all_results: list[DetectionResult] = []
        for page_num, page in enumerate(doc):
            text = page.get_text()
            if not text.strip():
                # Fallback to OCR on rendered page image
                pix = page.get_pixmap()
                text = pytesseract.image_to_string(Image.frombytes("RGB", [pix.width, pix.height], pix.samples))
            if text.strip():
                results = self.pattern_detector.detect(text) + self.presidio_detector.detect(text)
                for r in results:
                    r.metadata["source"] = "ocr_pdf"
                    r.metadata["page_number"] = page_num + 1
                all_results.extend(results)
        return all_results
```

**Testing**:
- `Unit: detect_image with screenshot containing SSN text → SSN_US detected`
- `Unit: detect_image with blank image → empty results`
- `Unit: detect_pdf with text-layer PDF containing credit cards → CREDIT_CARD detected`
- `Unit: detect_pdf with scanned (image-only) PDF → OCR fallback extracts text`
- `Fixture: tests/fixtures/sample_images/credit_card_screenshot.png → expected detection`
- `Fixture: tests/fixtures/sample_documents/scanned_medical_form.pdf → PHI detected`

---

#### 11.2 — GenAI API Monitoring Channel

**What**: Build a proxy/monitor for GenAI API calls (OpenAI, Anthropic, Google) that detects sensitive data in prompts before they reach the LLM.

**Design**:

```python
# src/channels/genai_channel.py
class GenAIMonitor:
    """HTTP proxy that intercepts requests to GenAI API endpoints."""

    MONITORED_ENDPOINTS = [
        {"provider": "openai", "pattern": r"https?://api\.openai\.com/v1/.*"},
        {"provider": "anthropic", "pattern": r"https?://api\.anthropic\.com/v1/.*"},
        {"provider": "google", "pattern": r"https?://generativelanguage\.googleapis\.com/.*"},
    ]

    async def inspect_request(
        self,
        url: str,
        body: dict,
        headers: dict,
        tenant_id: uuid.UUID,
        user_id: uuid.UUID | None,
    ) -> GenAIInspectionResult:
        """Inspect a GenAI API request for sensitive data."""
        provider = self._identify_provider(url)
        prompt_text = self._extract_prompt(body, provider)

        payload = ContentPayload(
            content_id=str(uuid.uuid4()),
            text=prompt_text,
            source_type="genai_api",
            source_ref=url,
        )
        report = await self.detection_engine.inspect(payload)
        result = await self.policy_evaluator.evaluate(report, EvaluationContext(
            tenant_id=tenant_id,
            user_id=user_id,
            channel="genai",
            destination=url,
        ))

        return GenAIInspectionResult(
            allowed=not result.should_block,
            provider=provider,
            detections=report.detections,
            action=result.final_action,
        )

    def _extract_prompt(self, body: dict, provider: str) -> str:
        """Extract user prompt text from provider-specific request format."""
        if provider == "openai":
            messages = body.get("messages", [])
            return "\n".join(m.get("content", "") for m in messages if m.get("role") == "user")
        elif provider == "anthropic":
            messages = body.get("messages", [])
            return "\n".join(m.get("content", "") for m in messages if m.get("role") == "user")
        return json.dumps(body)
```

```python
@dataclass
class GenAIInspectionResult:
    allowed: bool
    provider: str
    detections: list[DetectionResult]
    action: str  # block, warn, audit
```

Endpoints:
```
POST   /api/v1/genai/inspect                → GenAIInspectionResult (inline inspection API)
GET    /api/v1/genai/stats                   → GenAIStats (prompts scanned, blocked, by provider)
```

**Testing**:
- `Integration: POST /genai/inspect with SSN in prompt text → allowed=false (block policy active)`
- `Integration: POST /genai/inspect with clean prompt → allowed=true`
- `Unit: _extract_prompt handles OpenAI chat completions format`
- `Unit: _extract_prompt handles Anthropic messages format`
- `Unit: _identify_provider returns "openai" for api.openai.com URL`
- `Fixture: sample GenAI request with PII in prompt → detection results`

---

## Phase 12: ML-Based Confidence Scoring and User Behaviour Analytics

### Purpose

Add the differentiating AI capabilities: ML-based confidence scoring that learns from analyst feedback to reduce false positives, and user behaviour analytics that baseline normal activity and flag anomalies. These address the two biggest pain points in legacy DLP: false-positive fatigue and insider threat detection.

### Tasks

#### 12.1 — Analyst Feedback Loop for Confidence Tuning

**What**: Track analyst decisions (true positive, false positive) on findings and use the feedback to adjust detection confidence thresholds over time.

**Design**:

```python
# Extends findings schema
class FindingFeedback(BaseModel):
    finding_id: uuid.UUID
    verdict: Literal["true_positive", "false_positive", "needs_review"]
    analyst_id: uuid.UUID
    notes: str | None = None

class ConfidenceTuner:
    """Adjust detector confidence thresholds based on analyst feedback."""

    async def record_feedback(self, feedback: FindingFeedback) -> None:
        """Store feedback and update running statistics."""
        ...

    async def compute_adjusted_threshold(
        self, detector_code: str, tenant_id: uuid.UUID
    ) -> float:
        """Calculate optimal threshold from feedback history.

        Uses a rolling window of the last 1000 feedbacks per detector.
        Target: >=95% precision (true positives / all positives).
        """
        feedbacks = await self._get_recent_feedbacks(detector_code, tenant_id, limit=1000)
        if len(feedbacks) < 50:
            return None  # insufficient data
        # Binary search for threshold that achieves target precision
        ...
```

Endpoints:
```
POST   /api/v1/findings/{finding_id}/feedback   → FeedbackResponse
GET    /api/v1/detectors/{id}/accuracy           → DetectorAccuracyStats
```

**Testing**:
- `Unit: compute_adjusted_threshold raises threshold when false positive rate > 5%`
- `Unit: compute_adjusted_threshold lowers threshold when false positive rate < 1%`
- `Unit: returns None when feedback count < 50`
- `Integration: POST /findings/{id}/feedback stores feedback and updates stats`

---

#### 12.2 — User Risk Scoring and Behaviour Analytics

**What**: Compute risk scores for users based on their finding history, activity patterns, and behaviour anomalies.

**Design**:

```python
# src/incidents/risk_scorer.py
class UserRiskScorer:
    """Compute user risk scores from finding patterns and behavior signals."""

    RISK_WEIGHTS = {
        "finding_count_7d": 2.0,
        "finding_count_30d": 1.0,
        "critical_findings": 10.0,
        "high_findings": 5.0,
        "external_destinations": 3.0,
        "after_hours_activity": 2.0,
        "new_destination_spike": 4.0,
    }

    async def compute_risk_score(self, user_id: uuid.UUID, tenant_id: uuid.UUID) -> UserRiskProfile:
        """Calculate composite risk score (0-100) for a user."""
        factors = await self._gather_risk_factors(user_id, tenant_id)
        raw_score = sum(
            factors.get(k, 0) * w
            for k, w in self.RISK_WEIGHTS.items()
        )
        normalized_score = min(100.0, raw_score)
        return UserRiskProfile(
            user_id=user_id,
            risk_score=round(normalized_score, 2),
            factors=factors,
            computed_at=datetime.utcnow(),
        )

@dataclass
class UserRiskProfile:
    user_id: uuid.UUID
    risk_score: float
    factors: dict[str, float]
    computed_at: datetime
```

Celery task for periodic risk recalculation:
```python
@celery_app.task
def recalculate_user_risk_scores(tenant_id: str) -> None:
    """Recalculate risk scores for all active users in the tenant. Runs hourly."""
    ...
```

Endpoints:
```
GET    /api/v1/users/{user_id}/risk              → UserRiskProfile
GET    /api/v1/users/risk-leaderboard            → list[UserRiskSummary] (top-N risky users)
```

**Testing**:
- `Unit: user with 5 critical findings in 7 days → risk_score > 80`
- `Unit: user with 0 findings → risk_score = 0`
- `Unit: after_hours_activity factor increases score`
- `Integration: GET /users/{id}/risk returns computed risk profile`
- `Integration: risk-leaderboard returns users sorted by risk_score desc`
- `Integration: Celery task recalculates scores for all tenant users`

---

## Phase Summary & Dependencies

```
Phase 1: Foundation                    ─── required by everything
    │
Phase 2: Content Detection Engine      ─── requires Phase 1
    │
Phase 3: Policy Management             ─── requires Phase 2
    │
Phase 4: Findings, Incidents, Audit    ─── requires Phase 3
    │
    ├── Phase 5: Email Channel         ─── requires Phase 4; can parallel with Phase 6
    ├── Phase 6: Auth & RBAC           ─── requires Phase 4; can parallel with Phase 5
    │       │
    │       └── Phase 7: Webhook/SIEM  ─── requires Phase 6
    │
    ├── Phase 8: Frontend Dashboard    ─── requires Phase 6 (auth); can parallel with Phase 7
    │
    ├── Phase 9: Endpoints & SaaS      ─── requires Phase 4; can parallel with Phases 5-8
    │
    └── Phase 10: Compliance Reports   ─── requires Phase 4; can parallel with Phases 5-9
         │
Phase 11: OCR & GenAI Monitoring       ─── requires Phase 2 (detection) + Phase 4 (findings)
    │
Phase 12: ML Scoring & UBA             ─── requires Phase 4 (findings) + Phase 10 (partial)
```

**Parallelism opportunities:**
- Phases 5, 6, 9, 10 can all begin after Phase 4 completes
- Phase 8 can begin after Phase 6 completes, in parallel with Phase 7
- Phase 11 can begin after Phase 4 completes, in parallel with most other phases
- Phase 12 can begin after Phase 4 completes, but benefits from Phase 10's compliance data

---

## Definition of Done (per phase)

1. All tasks in the phase are implemented and code-reviewed.
2. All unit tests pass (`pytest tests/unit/` green).
3. All integration tests pass (`pytest tests/integration/` green).
4. Ruff lint and format checks pass (`ruff check . && ruff format --check .`).
5. mypy type checking passes (`mypy src/`).
6. Docker build succeeds (`docker build -t dlp-api .`).
7. Alembic migrations apply cleanly on a fresh database (`alembic upgrade head`).
8. Alembic migrations downgrade cleanly (`alembic downgrade -1`).
9. OpenAPI spec is auto-generated and reflects all new endpoints.
10. New configuration options are documented in `.env.example`.
11. RLS tenant isolation verified for all new tenant-scoped tables.
12. Audit log entries are generated for all state-changing operations.
13. Feature works end-to-end via API (verified with httpx or curl).
14. Frontend components render correctly (for frontend phases, verified with Vitest).
