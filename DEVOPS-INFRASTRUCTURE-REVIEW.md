# DevOps/Infrastructure Review: HeroSSID Platform
## Operational Readiness Assessment

**Project**: HeroSSID - Multi-Tenant Self-Sovereign Identity Platform
**Review Date**: 2025-10-15
**Reviewer Role**: Senior DevOps Engineer (15+ years enterprise infrastructure experience)
**Review Scope**: Production readiness from operational perspective
**Current Status**: Pre-implementation (architectural planning phase)

---

## Executive Summary

**Overall Operational Complexity Score: 8.5/10** (Very High Complexity)

HeroSSID presents significant operational challenges for a multi-tenant SaaS platform due to:
- **Emerging orchestration technology** (.NET Aspire 9.5.1 - production usage unclear)
- **External blockchain dependency** (Hyperledger Indy ledger - distributed consensus latency)
- **Complex multi-tenant data isolation** (PostgreSQL RLS + session variables + connection pooling)
- **Prerelease SDK dependency** (Open Wallet Foundation v2.0.0-xam-rc.202)
- **Cryptographic key management at scale** (1000+ tenants = 1000+ KEKs in Azure Key Vault)

**CRITICAL FINDING**: Multiple production deployment paths are undefined or incompatible with stated technology choices. The project is NOT production-ready without significant infrastructure design work.

---

## 1. Deployment Architecture Analysis

### 1.1 .NET Aspire Production Readiness

**RISK LEVEL**: 🔴 **CRITICAL**

#### Issues Identified:

1. **Aspire Production Deployment Gap**:
   - .NET Aspire 9.5.1 is designed primarily for **local development orchestration**
   - AppHost (`HeroSSID.AppHost`) is NOT intended to run in production Kubernetes clusters
   - Aspire provides service discovery and observability wiring for **development**, not production orchestration

2. **Missing Deployment Manifest Generation**:
   - Aspire has experimental `azd` (Azure Developer CLI) integration for Azure Container Apps
   - **No native Kubernetes manifest generation** - must use `Aspire.Hosting.Kubernetes` (community package, not official)
   - Documentation references T007 (Docker Compose for local dev) and T003 (Aspire AppHost) but provides NO production deployment strategy

3. **What Will Break in Production**:
   - **Service discovery**: Aspire's development-time service discovery (`builder.AddPostgres("herossid-postgres")`) does NOT translate to Kubernetes Service DNS
   - **Configuration**: Aspire's connection string injection works locally but breaks in Kubernetes without ConfigMaps/Secrets
   - **Observability wiring**: Aspire auto-configures OpenTelemetry collectors for local dashboards - production requires external OTLP endpoints (Application Insights, Jaeger, etc.)

#### Recommendations:

**IMMEDIATE (Phase 1 Prototype)**:
- Document that Aspire AppHost is for **local development ONLY**
- Use Aspire's `azd` tooling to generate Azure Container Apps deployment for initial cloud testing
- Accept vendor lock-in to Azure for prototype (Container Apps, App Service, or AKS with Azure tooling)

**PRODUCTION (Before MVP Launch)**:
- Choose ONE deployment target:
  - **Option A (Azure-native)**: Use `azd` + Azure Container Apps (simplest, Aspire-native)
  - **Option B (Kubernetes)**: Abandon Aspire orchestration for production; use Aspire ONLY for local dev + use Helm/Kustomize for Kubernetes manifests
  - **Option C (Hybrid)**: Use `Aspire.Hosting.Kubernetes` community package (experimental, risky)

- Create Helm charts for:
  - `HeroSSID.Api` (StatefulSet or Deployment with anti-affinity rules)
  - PostgreSQL 17 (StatefulSet with persistent volumes OR managed service like Azure Database for PostgreSQL)
  - Configuration management (ConfigMaps for non-sensitive, Sealed Secrets/External Secrets Operator for sensitive data)

**DO NOT** assume Aspire AppHost will "just work" in Kubernetes - this is a critical architectural gap.

---

### 1.2 Container Orchestration Strategy

**RISK LEVEL**: 🟠 **HIGH**

#### Missing Components:

1. **Helm Charts**: No charts defined for:
   - API deployment (replicas, resource limits, health checks, rolling update strategy)
   - PostgreSQL StatefulSet (or external managed service configuration)
   - Ingress controller configuration (NGINX, Traefik, Azure Application Gateway)
   - Certificate management (cert-manager for Let's Encrypt or manual TLS secret management)

2. **Service Mesh Considerations**: NOT mentioned but SHOULD consider for multi-tenant SaaS:
   - **Istio or Linkerd** for mTLS between services (defense-in-depth for tenant isolation)
   - Distributed tracing (Aspire uses OpenTelemetry, but service mesh adds network-level tracing)
   - Traffic splitting for canary deployments
   - **Trade-off**: Adds operational complexity but provides production-grade observability and security

3. **Storage for Wallet Files**:
   - Architecture specifies "SQLite per tenant wallet" (research.md mentions Open Wallet Foundation uses SQLite)
   - **WHERE ARE THESE FILES IN KUBERNETES?**
     - Cannot use ephemeral pod storage (data loss on pod restart)
     - Options:
       - **Persistent Volumes** (PV/PVC per pod - complex at scale, not horizontally scalable)
       - **Object storage** (Azure Blob, S3 - requires wallet SDK to support object storage backends)
       - **Shared filesystem** (Azure Files, NFS - potential performance bottleneck, single point of failure)
   - **BLOCKER**: Horizontal scaling is IMPOSSIBLE if wallet files require pod-local persistent volumes

#### What Will Break:

- **Auto-scaling**: If API pods have persistent volumes for wallet files, you CANNOT horizontally scale (1 pod = 1 volume = no scale-out)
- **Pod eviction/restart**: Wallet data loss unless persistent volumes configured correctly
- **Cross-region failover**: Persistent volumes are region-specific (no multi-region replication)

#### Recommendations:

**CRITICAL - Phase 1**:
- Clarify wallet storage architecture:
  - Does Open Wallet Foundation SDK support **object storage backends** (Azure Blob, S3)?
  - If SQLite-only: Document that horizontal scaling requires session affinity (sticky sessions) and persistent volumes
  - Research alternative: PostgreSQL-backed wallet storage (if OWF SDK supports it)

**Production**:
- If SQLite wallets required:
  - Use StatefulSet (NOT Deployment) with pod-indexed persistent volumes
  - Implement **session affinity** at load balancer (tenant ID-based routing to same pod)
  - Scale by adding StatefulSet replicas with tenant-to-pod assignment strategy
  - Accept that this is NOT true horizontal scaling (cannot load balance arbitrary requests)

- If PostgreSQL wallets possible:
  - Store wallet data in PostgreSQL (same RLS-protected database)
  - Enable true stateless horizontal scaling
  - Simplify deployment (no persistent volume management)

**Create Helm Charts** (T007A extension):
```yaml
# Example: charts/herossid-api/values.yaml
replicaCount: 3
image:
  repository: acr.azurecr.io/herossid/api
  tag: latest
persistence:
  enabled: true  # For SQLite wallets
  storageClass: managed-premium-retain
  size: 10Gi
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 1000m
    memory: 1Gi
autoscaling:
  enabled: false  # Cannot auto-scale with persistent volumes
```

---

## 2. Database Operations

### 2.1 PostgreSQL RLS + Connection Pooling

**RISK LEVEL**: 🟠 **HIGH**

#### Critical Issue: Session Variables Do NOT Survive Connection Pooling

From research.md:
```sql
-- Set tenant context after opening connection
await using var conn = dataSource.OpenConnection();
await conn.ExecuteAsync("SET LOCAL app.current_tenant = @tenantId", new { tenantId });
```

**PROBLEM**:
- `SET LOCAL` applies to **current transaction only**
- Connection pools REUSE connections across requests
- If connection is returned to pool, `app.current_tenant` is **reset to NULL or previous value**
- **CONSEQUENCE**: Cross-tenant data leakage (User A's request gets User B's connection with User B's tenant context)

#### What Will Break:

**Scenario**:
1. Request from Tenant A opens pooled connection #5
2. Middleware executes `SET LOCAL app.current_tenant = 'tenant-a-uuid'`
3. Request completes, connection #5 returned to pool
4. Request from Tenant B gets connection #5 from pool
5. If middleware doesn't re-set tenant context, **Tenant B sees Tenant A's data**

#### Solutions:

**Option A (Current Architecture - RISKY)**:
- Execute `SET LOCAL app.current_tenant` at **start of EVERY transaction**
- Verify middleware runs BEFORE any database queries
- Add integration test: "Concurrent requests from different tenants must have isolated results"
- **Risk**: One missed middleware execution = data leakage

**Option B (Connection String Per Tenant - RECOMMENDED)**:
- Create separate connection pool per tenant
- Use Npgsql's `NpgsqlDataSourceBuilder` with per-tenant search_path or role
- Set tenant context at connection establishment, not per-transaction
```csharp
// Connection pool per tenant (cache these)
var dataSourceBuilder = new NpgsqlDataSourceBuilder(baseConnectionString);
dataSourceBuilder.ConnectionStringBuilder.SearchPath = $"tenant_{tenantId}";
var dataSource = dataSourceBuilder.Build(); // Pooled per tenant
```
- **Trade-off**: More connection pools (100 tenants = 100 pools), but isolation guaranteed

**Option C (Schema Per Tenant - Reject per research.md, but safer)**:
- Use PostgreSQL schemas instead of RLS
- `tenant_a` schema, `tenant_b` schema, etc.
- Set `search_path` at connection level
- **Trade-off**: 100+ schemas, migration complexity, but foolproof isolation

#### Recommendations:

**CRITICAL - Before T021 Implementation**:
1. Test connection pooling with `SET LOCAL`:
   - Create integration test simulating concurrent tenant requests
   - Verify tenant context isolation under connection pool reuse
2. If isolation fails, switch to **Option B (per-tenant connection pools)**
3. Add **RLS policy failure logging** (PostgreSQL logs policy violations - monitor these)

**Production - Database Security**:
- Apply `FORCE ROW LEVEL SECURITY` to all tenant-scoped tables (research.md mentions this)
- Database user MUST NOT have `BYPASSRLS` privilege (already specified)
- Add circuit breaker: If RLS policy violation detected, kill application connections and alert

---

### 2.2 Zero-Downtime Migrations

**RISK LEVEL**: 🟠 **HIGH**

#### Issues:

- T032A mentions "migrations zero-downtime compatible" but NOT designed
- Multi-tenant SaaS requires **online schema changes** (cannot take 100 tenants offline for migration)
- PostgreSQL DDL operations acquire locks (e.g., `ALTER TABLE ADD COLUMN` locks table for duration)

#### What Will Break:

**Scenario**: Deploy new version with migration adding column to `verifiable_credentials` table (millions of rows)
- Migration runs `ALTER TABLE verifiable_credentials ADD COLUMN new_field TEXT`
- Table locked for **seconds to minutes** depending on row count
- All credential issuance/verification requests FAIL during lock
- SLA violation (99.5% uptime target)

#### Recommendations:

**Phase 1 (Before T032)**:
- Document migration strategy:
  - Use **expand-contract pattern**: Add columns as nullable first, backfill data, add NOT NULL constraint later
  - Use PostgreSQL `NOT VALID` constraints for instant constraint additions
  - Avoid `ALTER TYPE` on enum columns (requires table rewrite)

**Production**:
- Use migration tool with zero-downtime support:
  - **pg-online-schema-change** (GitHub: shayonj/pg-osc)
  - **pgroll** (Xata's zero-downtime migration tool)
  - OR Blue-Green database deployments (expensive, complex)

- Example expand-contract:
```sql
-- Migration 1: Add column (nullable, instant)
ALTER TABLE dids ADD COLUMN new_field TEXT NULL;

-- Migration 2: Backfill data (batched updates, no lock)
-- (Run in background job, not in migration)
UPDATE dids SET new_field = '<default>' WHERE new_field IS NULL;

-- Migration 3: Add constraint (with NOT VALID, instant)
ALTER TABLE dids ADD CONSTRAINT check_new_field CHECK (new_field IS NOT NULL) NOT VALID;

-- Migration 4: Validate constraint (slow, but no write lock)
ALTER TABLE dids VALIDATE CONSTRAINT check_new_field;
```

---

### 2.3 Backup Strategy for Multi-Tenant Data

**RISK LEVEL**: 🟠 **HIGH**

#### Missing Strategy:

- No backup/restore design mentioned
- Multi-tenant SaaS cannot use simple `pg_dump` (all-or-nothing)
- Requirements:
  - **Per-tenant restore** (Tenant A requests data recovery without affecting Tenant B)
  - **Point-in-time recovery** (PITR) for compliance (restore to state 2 hours ago)
  - **Audit log immutability** (audit_log_entries table must survive backup/restore)

#### What Will Break:

- Tenant requests "restore my credentials from yesterday" → Cannot restore single tenant from full DB dump
- Database corruption → Full DB restore affects all 100 tenants (not just affected tenant)
- Ransomware encrypts database → No PITR strategy means total data loss

#### Recommendations:

**Production - Backup Strategy**:

1. **PostgreSQL PITR (Point-in-Time Recovery)**:
   - Enable Write-Ahead Log (WAL) archiving to object storage (Azure Blob, S3)
   - Use `pg_basebackup` + WAL archives for recovery
   - Azure Database for PostgreSQL includes built-in PITR (simplest option)

2. **Per-Tenant Logical Backups**:
   - Scheduled job: `pg_dump --table=dids --table=verifiable_credentials -W "tenant_id='<uuid>'"` per tenant
   - Store per-tenant backups separately (restore without affecting others)
   - Retention policy: 30 days (configurable per tenant contract)

3. **Immutable Audit Logs**:
   - Replicate `audit_log_entries` table to **separate append-only storage** (Azure Table Storage, S3 Glacier)
   - Use PostgreSQL logical replication or change data capture (CDC) with Debezium
   - Ensure audit logs survive database restore (separate storage = independent recovery)

**Cost Estimate** (100 tenants, 1TB data):
- Azure Database for PostgreSQL with PITR: ~$500-1000/month (includes backups)
- WAL archive storage: ~$20/month (Azure Blob cool tier)
- Per-tenant backup storage: ~$50/month (compressed logical dumps)
- **Total: ~$600-1100/month** for production-grade backup

---

### 2.4 Read Replicas and RLS

**RISK LEVEL**: 🟡 **MEDIUM**

#### Question: Does `SET LOCAL app.current_tenant` Replicate?

- PostgreSQL read replicas use **physical replication** (block-level)
- Session variables (`app.current_tenant`) are NOT replicated (they're session-local)
- **PROBLEM**: Read queries against replica require re-setting tenant context

#### Solution:

- Middleware must execute `SET LOCAL app.current_tenant` on **both primary and replica connections**
- If using read-write splitting (e.g., primary for writes, replicas for reads), ensure tenant context set on ALL connections
- Test failover: If primary fails and replica promoted, tenant context middleware must work identically

---

## 3. External Dependencies

### 3.1 Hyperledger Indy Ledger Availability

**RISK LEVEL**: 🔴 **CRITICAL**

#### Issues:

1. **Ledger Downtime = Platform Outage**:
   - DID creation (T053-T058): Requires ledger write → BLOCKS if ledger down
   - Schema publishing (T077): Requires ledger write → BLOCKS
   - Credential issuance (T092-T096): Reads ledger for schema/cred def → BLOCKS
   - Credential verification (T107-T113): Reads ledger for issuer public key + revocation registry → BLOCKS

2. **Ledger Consensus Delays**:
   - Research.md: "Ledger write latency: typically 2-5 seconds"
   - **QUESTION**: What's the P99 latency? What about network partitions? Byzantine fault scenarios?
   - Performance targets: DID creation <10s (includes 2-5s ledger write) = **only 5-8s buffer**

3. **Von Network for Testing**:
   - T007A mentions "Von Network for testing"
   - Von Network is **development-only** Indy ledger (single node, no consensus, no persistence)
   - **NOT production-grade** - must use Sovrin MainNet or private consortium (4+ validator nodes)

#### What Will Break:

**Scenario 1: Ledger Network Partition**
- Sovrin MainNet experiences consensus failure (validator nodes disagree)
- All DID creation requests fail → Users cannot create identities
- All credential issuances fail (cannot read cred def from ledger)
- **Platform is DOWN** despite API servers being healthy

**Scenario 2: Ledger Consensus Timeout**
- Byzantine fault: 33% of validators fail (Indy uses RBFT consensus)
- Write transactions timeout after 30+ seconds
- DID creation exceeds 10s target → Violates SC-002
- Users experience "identity creation failed" errors

#### Recommendations:

**CRITICAL - Phase 1**:
1. **Document ledger dependency**:
   - DID operations: Ledger is CRITICAL PATH (writes required)
   - Credential issuance/verification: Ledger is CRITICAL PATH (reads required)
   - Platform availability ≤ Ledger availability (if ledger 99%, platform <99%)

2. **Choose ledger network**:
   - **Sovrin MainNet** (public, production-grade, ~99.5% uptime, transaction fees apply)
   - **Private consortium** (control availability, higher ops burden, 4+ validator nodes required)
   - **Sovrin BuilderNet/StagingNet** (testing only, NOT production)

3. **Implement caching strategy**:
   - Cache DID Documents (T059 resolution) with TTL (1 hour)
   - Cache schemas (T079 retrieval) with TTL (24 hours - schemas immutable)
   - Cache credential definitions with TTL (24 hours)
   - **Trade-off**: Stale data risk vs. availability during ledger outages

4. **Add retry logic with exponential backoff** (T112 mentions this):
   - Retry ledger reads: 3 attempts with 1s, 2s, 4s delays
   - Retry ledger writes: 2 attempts with 5s, 10s delays (writes are expensive)
   - After retries exhausted: Return "service unavailable" with actionable error

5. **Circuit breaker pattern**:
   - If ledger fails 10 consecutive requests, open circuit for 60 seconds
   - Serve reads from cache (if available)
   - Return "ledger temporarily unavailable" for writes
   - Auto-close circuit on successful health check

**Production - Ledger Operations**:

- **Monitoring**:
  - Track ledger latency P50/P95/P99 (add Prometheus metrics)
  - Alert if P95 latency >10s (approaching timeout)
  - Alert if ledger error rate >5% (consensus issues)

- **Multi-Ledger Strategy** (Future):
  - Support writing DIDs to MULTIPLE ledgers (Sovrin + private consortium)
  - Read from fastest available ledger (active-active)
  - **Trade-off**: Complexity, but increases availability to 99.9%+

- **Fallback for Reads** (Advanced):
  - Implement **Indy VDR** (Verifiable Data Registry) with local ledger cache
  - Periodically sync ledger state to local PostgreSQL (read replica of ledger)
  - Serve reads from local cache if ledger unavailable
  - **Risk**: Eventual consistency (local cache lags ledger by seconds/minutes)

**SLA Impact**:
- Target: 99.5% uptime (SC-006)
- Ledger dependency: If ledger 99.5%, platform ≤99.5%
- If ledger 99%, platform <99% (VIOLATES SLA)
- **Mitigation**: Caching + circuit breaker can boost platform availability to 99.7%+ even if ledger 99%

---

### 3.2 Azure Key Vault Dependency

**RISK LEVEL**: 🟠 **HIGH**

#### Issues:

1. **KEK Storage at Scale**:
   - Research.md: Private keys encrypted with KEKs in Azure Key Vault
   - Data-model.md: `encryption_key_id` per DID (references Key Vault key ID)
   - **QUESTION**: 1000 tenants with 100 DIDs each = 100,000 KEKs?
   - Azure Key Vault pricing: $0.03/10,000 operations + $0.15/key/month (Premium tier for HSM)
   - **Cost**: 100,000 keys = **$15,000/month** for key storage alone

2. **Key Vault as Single Point of Failure**:
   - DID creation (T055): Encrypt private key using Key Vault KEK → BLOCKS if Key Vault down
   - Credential issuance (T096): Decrypt issuer private key to sign credential → BLOCKS
   - **Availability**: Azure Key Vault SLA 99.9% (regional), 99.99% (geo-redundant Premium)

3. **Regional Failover**:
   - Key Vault keys are region-specific
   - If using non-geo-redundant Key Vault, regional outage = CANNOT decrypt keys = platform DOWN
   - Geo-redundant Premium Key Vault auto-replicates, but costs 3-5x more

#### What Will Break:

**Scenario**: Azure Key Vault regional outage
- Cannot encrypt new DID private keys → DID creation fails
- Cannot decrypt existing private keys → Credential issuance fails
- **Platform partially DOWN** (reads work, writes fail)

#### Recommendations:

**CRITICAL - Phase 1 Architecture Revision**:

1. **Reduce KEK Count** (MUST FIX):
   - DO NOT use per-DID KEKs (unscalable, expensive)
   - Use **per-tenant KEK** (1 tenant = 1 KEK in Key Vault)
   - Encrypt DID private keys using tenant KEK + AES-256-GCM with local key derivation (HKDF)
   - **New cost**: 1000 tenants = 1000 KEKs = **$150/month** (100x cheaper)

2. **Key Hierarchy**:
```
Azure Key Vault KEK (per tenant)
  → Tenant Master Key (TenantMasterKey = Decrypt(KEK))
    → DID-specific keys derived via HKDF(TenantMasterKey, did_id)
      → Private keys encrypted: AES-GCM(DID-key, private_key_data)
```

3. **Caching Strategy**:
   - Cache decrypted tenant master keys in memory (encrypted at rest in API pod)
   - TTL: 1 hour (refresh from Key Vault periodically)
   - Evict on tenant key rotation
   - **Benefit**: Reduces Key Vault API calls by 95%+, speeds up credential operations

4. **Failover**:
   - Use Azure Key Vault **Premium tier with geo-replication** (99.99% SLA)
   - Alternative: Replicate KEKs to secondary Key Vault in different region (manual sync)
   - If Key Vault unavailable: Use cached master keys (allows operations for ~1 hour)

**Production - Key Management**:

- **Key Rotation**:
  - Rotate tenant KEKs every 90 days (compliance requirement)
  - Process: Decrypt all DID keys with old KEK, re-encrypt with new KEK, update `encryption_key_id`
  - **Downtime**: If not designed for online rotation, tenant credential operations BLOCK during rotation

- **Key Backup**:
  - Azure Key Vault has built-in backup (HSM-backed keys exportable only in encrypted form)
  - Store encrypted KEK backups in separate Azure region (disaster recovery)
  - **Test restore procedure** (Key Vault restore is complex - must verify before disaster)

**Cost Estimate** (1000 tenants, optimized architecture):
- 1000 KEKs in Premium Key Vault: ~$150/month
- Key operations (10,000 decrypt ops/month per tenant): ~$300/month
- **Total: ~$450/month** (vs. $15,000+ for per-DID KEKs)

---

## 4. Secrets Management

### 4.1 JWT Signing Keys

**RISK LEVEL**: 🟡 **MEDIUM**

#### Current Design (from research.md):

```csharp
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:SecretKey"]));
```

**PROBLEM**:
- Where is `Jwt:SecretKey` stored in production?
- Research.md says "Azure Key Vault or .NET Aspire secrets" (vague)

#### What Will Break:

- If secret in `appsettings.json`: Checked into source control → **SECRET LEAK**
- If secret in environment variable: Visible in Kubernetes pod spec → **SECRET LEAK**
- If secret in Azure Key Vault but not rotated: Compromise = revoke ALL JWT tokens (user logouts)

#### Recommendations:

**Production - JWT Secret Management**:

1. **Storage**:
   - Store JWT signing key in Azure Key Vault (separate from KEKs)
   - OR use asymmetric keys (RS256): Public key in config, private key in Key Vault
   - Benefit of RS256: Can rotate private key without invalidating cached JWTs (public key remains same)

2. **Rotation**:
   - JWT signing keys MUST rotate every 90 days
   - Use **key versioning**: Generate new key, keep old key for validation (grace period: 24 hours)
   - Process:
     - Generate new signing key in Key Vault
     - Update API to sign new tokens with new key
     - Accept tokens signed with old key for 24 hours (smooth transition)
     - Revoke old key after grace period

3. **Kubernetes Secret Management**:
   - DO NOT use plain Kubernetes Secrets (base64-encoded, not encrypted)
   - Use **External Secrets Operator** (syncs from Azure Key Vault to K8s Secrets)
   - OR use **Sealed Secrets** (encrypted secrets checked into Git)
   - OR use **Azure Key Vault CSI Driver** (mount Key Vault secrets as volumes)

**Recommended Flow**:
```
Azure Key Vault (JWT signing key v2)
  ↓ (External Secrets Operator syncs every 5min)
Kubernetes Secret (jwt-signing-key)
  ↓ (Volume mount)
API Pod reads secret from /mnt/secrets/jwt-signing-key
```

---

### 4.2 Database Credentials

**RISK LEVEL**: 🟡 **MEDIUM**

#### Issue:

- Research.md: `"Username=herossid_app;Password=<secure>"`
- NO mention of credential rotation strategy
- If database password compromised: ALL tenant data at risk

#### Recommendations:

**Production**:

1. **Managed Identity (Azure)**:
   - Use Azure Managed Identity for API to authenticate to Azure Database for PostgreSQL
   - NO passwords in config (Azure AD authentication)
   - Auto-rotated credentials (Azure handles rotation)

2. **Credential Rotation** (if not using Managed Identity):
   - Rotate database passwords every 90 days
   - Use **blue-green credential rotation**:
     - Create new DB user with new password
     - Update API config to use new credentials
     - Deploy API with new credentials
     - Drop old DB user after grace period

3. **Least Privilege**:
   - API user should NOT have DDL privileges (no `CREATE TABLE`, `DROP TABLE`)
   - Migrations run with separate privileged user (only in CI/CD, not runtime)
   - API user: `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO herossid_app`

---

### 4.3 Hyperledger Indy Wallet Passwords

**RISK LEVEL**: 🟠 **HIGH**

#### Issue:

- Open Wallet Foundation SDK requires per-wallet passwords to encrypt local wallet storage
- **QUESTION**: Where are wallet passwords stored?
  - If in database: Encrypted with what key? (KEK in Key Vault?)
  - If in Key Vault: 100,000 wallets = 100,000 secrets (unscalable)
  - If hardcoded: **SECURITY DISASTER**

#### Recommendations:

**Architecture Decision** (MUST RESOLVE IN PHASE 1):

1. **Derive wallet passwords from tenant KEK**:
   - Wallet password = HKDF(Tenant_KEK, wallet_id, "wallet-password")
   - No need to store wallet passwords (derived on-demand)
   - Wallet passwords change if tenant KEK rotates (requires wallet re-encryption)

2. **Store encrypted wallet passwords in database**:
   - `wallet_passwords` table with `wallet_id`, `encrypted_password`, `encryption_key_id`
   - Decrypt using tenant KEK from Key Vault
   - **Trade-off**: Extra database table, but simpler wallet operations

**Test in Phase 1**: Verify Open Wallet Foundation SDK wallet encryption works with derived passwords

---

## 5. Monitoring & Observability

### 5.1 Distributed Tracing Backend

**RISK LEVEL**: 🟡 **MEDIUM**

#### Issue:

- T016B: ".NET Aspire distributed tracing"
- **QUESTION**: What's the backend?
  - Aspire uses OpenTelemetry, but exports to WHERE?
  - Local dev: Aspire Dashboard (not production)
  - Production: ??? (Jaeger? Zipkin? Application Insights? Honeycomb?)

#### Recommendations:

**Production**:

1. **Azure-Native** (If using Azure):
   - Export to **Azure Monitor Application Insights** (built-in Aspire support)
   - Cost: ~$2.30/GB ingested (first 5GB/month free)
   - 100k traces/day ≈ 500MB/day ≈ $35/month

2. **Self-Hosted** (If Kubernetes-native):
   - Deploy **Jaeger** or **Tempo** (Grafana) in cluster
   - Export OTLP from API to Jaeger collector
   - Store traces in object storage (S3/Blob) for cost efficiency
   - **Trade-off**: Must manage Jaeger/Tempo infrastructure

3. **SaaS** (Simplest):
   - **Honeycomb** or **Lightstep** (premium observability platforms)
   - Cost: ~$150-500/month for 100k traces/day
   - **Benefit**: Zero ops burden, powerful analytics

**Must Configure in T016B**: Export OTLP to chosen backend, NOT just Aspire Dashboard

---

### 5.2 Metrics Collection Backend

**RISK LEVEL**: 🟡 **MEDIUM**

#### Issue:

- T024: "Configure metrics collection in HeroSSID.Observability/Metrics/MetricsCollector.cs"
- FR-038: "Track metrics including credential issuance rates, verification latency, and ledger operation success/failure"
- **QUESTION**: Metrics stored WHERE? Prometheus? Azure Monitor? Datadog?

#### Recommendations:

**Production - Metrics Stack**:

1. **Prometheus + Grafana** (Standard Kubernetes):
   - Deploy Prometheus operator in cluster
   - API exposes `/metrics` endpoint (ASP.NET Core built-in)
   - Prometheus scrapes metrics every 15s
   - Grafana dashboards for visualization
   - **Cost**: Free (self-hosted), ~$100/month infra (if managed Grafana Cloud)

2. **Azure Monitor** (Azure-native):
   - Export metrics to Azure Monitor custom metrics
   - Integrate with Application Insights for unified observability
   - **Cost**: ~$0.25 per million API calls (can get expensive at scale)

3. **Key Metrics to Track** (from FR-038):
   - `herossid_did_creation_duration_seconds` (histogram)
   - `herossid_credential_issuance_total` (counter by tenant_id)
   - `herossid_credential_verification_duration_seconds` (histogram)
   - `herossid_ledger_operation_total` (counter by operation, outcome=success/failure)
   - `herossid_ledger_latency_seconds` (histogram)
   - `herossid_database_connection_pool_active` (gauge)
   - `herossid_tenant_count_total` (gauge)

**Alerting** (CRITICAL):
- Alert: Ledger error rate >5% for 5 minutes → Page on-call engineer
- Alert: P95 DID creation latency >10s → Investigate ledger performance
- Alert: Database connection pool exhausted → Scale API replicas or DB
- Alert: Credential issuance rate drops to 0 for 10 minutes → Platform outage

---

### 5.3 Log Aggregation for Multi-Tenant

**RISK LEVEL**: 🟠 **HIGH**

#### Issue:

- FR-035: Structured logs with tenant_id, correlation_id, operation_type
- **PROBLEM**: How to query logs for specific tenant in production?
  - If using Azure Monitor Logs: Can query by `tenant_id` (JSON field)
  - If using ELK: Can filter by `tenant_id` in Kibana
  - If using plain Docker logs: **IMPOSSIBLE** to isolate tenant logs

#### Recommendations:

**Production - Log Aggregation**:

1. **Azure Monitor Logs** (Azure-native):
   - Aspire auto-configures Application Insights logging
   - Logs stored in Log Analytics Workspace
   - Query: `traces | where customDimensions.tenant_id == "tenant-uuid"`
   - **Cost**: ~$2.76/GB ingested (100GB/month ≈ $276)

2. **ELK Stack** (Self-hosted):
   - FluentBit/Fluentd collects logs from Kubernetes pods
   - Elasticsearch stores logs with tenant_id indexed
   - Kibana for querying/visualization
   - **Cost**: ~$200-500/month infra (managed Elasticsearch) or free (self-hosted)

3. **CRITICAL - PII Scrubbing**:
   - FR-039: NO private keys, credentials, or PII in logs
   - Implement **log scrubbing middleware**:
     - Redact fields: `password`, `private_key`, `ssn`, `credential_values`
     - Use regex to detect and mask sensitive patterns
     - Test: Query logs for "private_key" → MUST return 0 results

4. **Tenant Log Isolation** (Compliance):
   - Some tenants may require isolated log storage (HIPAA, GDPR)
   - Solution: Route tenant logs to separate Log Analytics Workspace or Elasticsearch index
   - **Implementation**: Add tenant-aware log routing in T017 (StructuredLogger.cs)

---

## 6. Scalability & Performance

### 6.1 Horizontal Scaling Constraints

**RISK LEVEL**: 🔴 **CRITICAL**

#### Issue: Wallet Storage Prevents Stateless Scaling

**From Section 1.2**: If Open Wallet Foundation uses SQLite wallet files (per tenant), API pods are **stateful** (cannot horizontally scale without session affinity)

**What Will Break**:
- Kubernetes Horizontal Pod Autoscaler (HPA) adds new API pod
- Load balancer routes tenant request to new pod
- New pod does not have tenant's wallet file (SQLite stored in old pod)
- Credential issuance **FAILS** (cannot access wallet)

#### Solutions:

**Option A: Session Affinity (Sticky Sessions)**:
- Load balancer routes all requests from `tenant_id=X` to same pod
- Pod has persistent volume with tenant wallets
- **Limitation**: Cannot scale beyond number of pods × tenants per pod
- Example: 10 pods, 10 tenants per pod = max 100 tenants (cannot scale further without adding pods)

**Option B: Shared Filesystem for Wallets**:
- Mount Azure Files (NFS) or AWS EFS as shared volume across all pods
- All pods access same wallet files
- **Risk**: File locking issues, performance bottleneck (NFS is slow for random I/O)

**Option C: PostgreSQL Wallet Storage** (RECOMMENDED):
- Research if Open Wallet Foundation SDK supports PostgreSQL wallet backend
- Store wallet data in same PostgreSQL database (separate `wallets` table)
- **Benefit**: Stateless API pods, true horizontal scaling
- **Risk**: If SDK doesn't support, requires custom wallet storage plugin

#### Recommendations:

**CRITICAL - Phase 1 Research**:
1. Test Open Wallet Foundation SDK wallet storage options:
   - Does it support PostgreSQL storage plugin?
   - Can wallet files be on network filesystem without corruption?
2. If PostgreSQL supported → Use PostgreSQL wallets (simplest)
3. If not → Design session affinity strategy + persistent volumes

**Production**:
- If using session affinity:
  - Configure load balancer: Hash-based routing on `tenant_id` header
  - StatefulSet with pod-indexed persistent volumes (pod-0 gets PV-0, etc.)
  - Scale by adding StatefulSet replicas (manual scaling, not HPA)
- If using shared filesystem:
  - Use Azure Files Premium tier (better performance than Standard)
  - Monitor file lock contention (metrics on failed wallet opens)

---

### 6.2 Auto-Scaling Triggers

**RISK LEVEL**: 🟡 **MEDIUM**

#### Issue:

- No auto-scaling design mentioned
- Default HPA uses CPU/memory metrics (not ideal for API workloads)

#### Recommendations:

**Production - Auto-Scaling**:

1. **If Stateless (PostgreSQL wallets)**:
   - Enable Kubernetes HPA on API Deployment
   - Scale on custom metrics:
     - `herossid_api_requests_per_second > 1000` → Scale up
     - `herossid_credential_issuance_queue_depth > 100` → Scale up
   - Min replicas: 3 (high availability)
   - Max replicas: 20 (cost control)

2. **If Stateful (Wallet files + session affinity)**:
   - Cannot use HPA (StatefulSet scaling requires tenant reassignment)
   - Scale manually based on tenant count:
     - 0-50 tenants: 3 pods
     - 51-100 tenants: 5 pods
     - 101-200 tenants: 10 pods
   - Monitor: If pod handles >20 tenants, add replica

3. **Database Auto-Scaling**:
   - Azure Database for PostgreSQL: Enable auto-scaling storage (grows automatically)
   - Scale compute tier based on CPU: >80% sustained → Upgrade to next tier
   - Read replicas: If read query latency >500ms, add read replica

**Load Balancer Configuration**:
- If stateless: Round-robin or least-connections
- If stateful: Consistent hashing on `tenant_id`
- Health checks: `/health` endpoint (200 = healthy, 503 = unhealthy)
- Readiness probe: Check database + ledger connectivity before routing traffic

---

### 6.3 Performance Targets Validation

**RISK LEVEL**: 🟡 **MEDIUM**

#### Targets (from plan.md):

- DID creation: <10 seconds
- Credential issuance: <3 seconds
- Credential verification: <2 seconds
- Throughput: 10,000 credential operations/hour

#### Reality Check:

**DID Creation (<10s)**:
- Key generation: 10-50ms (Ed25519)
- Database insert: 5-20ms
- Ledger write: **2-5 seconds** (consensus latency)
- Key encryption (Key Vault): 100-300ms
- **Total**: ~2.5-6s (P50), ~8-15s (P99)
- **Verdict**: Target ACHIEVABLE at P50, RISKY at P99 (ledger variance)

**Credential Issuance (<3s)**:
- Retrieve schema from ledger: 100-500ms (with caching: 5-10ms)
- Decrypt issuer private key: 50-100ms (Key Vault)
- Sign credential (Ed25519): 5-10ms
- Database insert: 5-20ms
- **Total**: ~200-700ms (P50), ~1-2s (P99)
- **Verdict**: Target ACHIEVABLE (comfortable margin)

**Credential Verification (<2s)**:
- Retrieve issuer public key from ledger: 100-500ms (cached: 5-10ms)
- Verify signature: 5-10ms
- Check revocation (if applicable): 100-500ms (ledger query)
- **Total**: ~300-1000ms (P50), ~1.5-3s (P99)
- **Verdict**: Target ACHIEVABLE at P50, RISKY at P99 (if checking revocation)

**Throughput (10k ops/hour)**:
- 10,000 ops/hour = 2.78 ops/second average
- With 3 API pods, each handling 1 op/second → EASILY achievable
- **Bottleneck**: Database (credentials table inserts)
- PostgreSQL on moderate hardware: 5,000-10,000 inserts/second → NOT a bottleneck
- **Verdict**: Target EASILY ACHIEVABLE (10k/hour is LOW for modern systems)

#### Recommendations:

**Production - Performance Testing**:
- T149: Validate performance targets BEFORE launch
- Use **k6** or **Locust** for load testing:
  - Simulate 100 concurrent users across 10 tenants
  - Run for 1 hour to detect memory leaks, connection pool exhaustion
  - Verify P50/P95/P99 latencies meet targets
- Test ledger failure scenarios (what happens when ledger slow?)

---

## 7. Disaster Recovery

### 7.1 RPO/RTO Requirements

**RISK LEVEL**: 🟠 **HIGH**

#### Issue:

- NO RPO (Recovery Point Objective) or RTO (Recovery Time Objective) defined
- Typical SaaS expectations:
  - RPO: <1 hour (max 1 hour data loss acceptable)
  - RTO: <4 hours (restore service within 4 hours of disaster)

#### What Will Break:

**Scenario**: Azure region failure (rare but happens ~1-2 times per year per region)
- Primary database in failed region
- No multi-region replica → **Total platform outage**
- Recovery time: 4-48 hours (restore from backup, re-create infrastructure)
- Data loss: Up to 24 hours (if backups only run daily)

#### Recommendations:

**Production - Disaster Recovery**:

1. **Define RPO/RTO**:
   - Suggested: RPO = 1 hour, RTO = 4 hours (industry standard for SaaS)
   - Document in SLA (Service Level Agreement) with tenants

2. **Multi-Region Architecture** (Premium):
   - Primary region: East US (API + Database + Key Vault)
   - Secondary region: West US (standby API + Read replica database + replicated Key Vault)
   - Use **Azure Traffic Manager** or **Azure Front Door** for geo-routing
   - If primary fails, Traffic Manager routes to secondary
   - **Cost**: 2x infrastructure (but achieves 99.99% availability)

3. **Database Replication**:
   - Azure Database for PostgreSQL: Enable geo-replication to secondary region
   - Replication lag: <10 seconds (async replication)
   - Failover: Manual (5-10 minutes) or Auto (30-60 seconds)

4. **Ledger Failover** (HARD):
   - Hyperledger Indy ledger is distributed (multiple validators)
   - If using Sovrin: Validators in different regions → Natural HA
   - If using private consortium: Deploy validators in 3+ regions (PBFT requires >2/3 healthy)

5. **Backup Testing**:
   - MUST test restore procedure quarterly
   - Restore to test environment, verify data integrity, measure restore time
   - **Disaster recovery is useless if untested**

**Estimated Cost** (Multi-region):
- 2x API pods in secondary region: +100% compute (~$200/month)
- Geo-replicated database: +50% database cost (~$300/month)
- Traffic Manager: ~$5/month
- **Total DR overhead**: ~$505/month for 99.99% availability

---

### 7.2 Wallet Backup/Restore

**RISK LEVEL**: 🟠 **HIGH**

#### Issue:

- T011C mentions "wallet backup/restore" but NOT designed
- If wallets lost (database corruption, accidental delete), **tenants lose access to private keys** = CANNOT sign credentials = **BUSINESS DISASTER**

#### Recommendations:

**Production - Wallet Protection**:

1. **Immutability**:
   - Private keys (in `dids` table) should NEVER be deleted (only marked `status=deactivated`)
   - Implement soft delete: Add `deleted_at` column, exclude in queries
   - Prevent accidental key deletion with database constraints

2. **Backup**:
   - Encrypted wallet data (private keys) included in PostgreSQL backups (already covered in Section 2.3)
   - Test restore: Verify decrypted private keys still work after restore (sign test message)

3. **Key Escrow** (Optional, Controversial):
   - Some regulations require key escrow (ability to recover keys if user loses access)
   - Solution: Export encrypted private keys to tenant's own Key Vault (tenant controls)
   - **Trade-off**: Reduces decentralization, but meets compliance

---

### 7.3 Cross-Region Ledger Failover

**RISK LEVEL**: 🟡 **MEDIUM**

#### Issue:

- Hyperledger Indy ledger: Is it regional or global?
- Sovrin MainNet: Global (validators worldwide) → No regional failure
- Private consortium: Depends on validator deployment

#### Recommendations:

**If Private Consortium**:
- Deploy validator nodes in 3+ regions (Azure East US, West US, Europe)
- Indy RBFT consensus: Requires >2/3 validators healthy
- 4 validators: Can tolerate 1 failure
- 7 validators: Can tolerate 2 failures (recommended for production)

**If Sovrin MainNet**:
- No action needed (Sovrin Foundation manages validators)
- Monitor Sovrin status page for outages

---

## 8. CI/CD Pipeline

### 8.1 Pipeline Design

**RISK LEVEL**: 🟠 **HIGH**

#### Issue:

- T141: "GitHub Actions or Azure Pipelines" (no design)
- NO pipeline specification for:
  - Build process
  - Test execution (unit, integration, contract)
  - Container image creation
  - Security scanning
  - Deployment to environments

#### Recommendations:

**Production - CI/CD Pipeline**:

**Build Stage**:
```yaml
# .github/workflows/build.yml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '9.0.x'
      - run: dotnet restore
      - run: dotnet build --no-restore
      - run: dotnet test --no-build --verbosity normal
      - run: dotnet publish -c Release -o ./publish
```

**Test Stage** (Constitution mandates TDD):
```yaml
  test:
    needs: build
    steps:
      - run: dotnet test tests/Unit/**/*.csproj --collect:"XPlat Code Coverage"
      - run: dotnet test tests/Integration/**/*.csproj
      - run: dotnet test tests/Contract/**/*.csproj
      - uses: codecov/codecov-action@v3  # Upload coverage
      - name: Enforce 80% coverage
        run: |
          coverage=$(cat coverage.xml | grep line-rate | ...)
          if [ $coverage -lt 80 ]; then exit 1; fi
```

**Security Scan Stage**:
```yaml
  security:
    needs: test
    steps:
      - name: NuGet vulnerability scan
        run: dotnet list package --vulnerable --include-transitive
      - name: Container image scan (Trivy)
        run: |
          docker build -t herossid-api:${{ github.sha }} .
          trivy image --severity HIGH,CRITICAL herossid-api:${{ github.sha }}
      - name: SAST (Static analysis)
        run: dotnet security-scan ./HeroSSID.sln  # Use Roslyn analyzers
```

**Publish Stage**:
```yaml
  publish:
    needs: security
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Build Docker image
        run: docker build -t acr.azurecr.io/herossid-api:${{ github.sha }} .
      - name: Login to ACR
        run: az acr login --name acr
      - name: Push image
        run: docker push acr.azurecr.io/herossid-api:${{ github.sha }}
```

**Deploy Stage** (Dev → Staging → Prod):
```yaml
  deploy-dev:
    needs: publish
    environment: dev
    steps:
      - name: Deploy to AKS dev
        run: |
          helm upgrade --install herossid ./charts/herossid \
            --set image.tag=${{ github.sha }} \
            --namespace dev

  deploy-staging:
    needs: deploy-dev
    environment: staging  # Manual approval gate
    steps:
      - name: Deploy to AKS staging
        run: helm upgrade --install herossid ./charts/herossid --namespace staging

  deploy-prod:
    needs: deploy-staging
    environment: prod  # Manual approval + security review
    steps:
      - name: Deploy to AKS prod
        run: helm upgrade --install herossid ./charts/herossid --namespace prod
```

**Gates**:
- Dev: Auto-deploy on merge to `main`
- Staging: Auto-deploy after dev succeeds
- Prod: Manual approval + security review (require 2 approvers)

---

### 8.2 Container Registry

**RISK LEVEL**: 🟡 **MEDIUM**

#### Issue:

- NO container registry specified (ACR? Docker Hub? ECR?)

#### Recommendations:

**Production**:
- **Azure Container Registry (ACR)** (if using Azure):
  - Premium tier for geo-replication (multi-region DR)
  - Vulnerability scanning integrated
  - Managed identity authentication (no passwords)
  - **Cost**: ~$150/month (Premium tier)

- **Docker Hub** (NOT recommended for production):
  - Rate limits (200 pulls/6 hours for free tier)
  - No private registry on free tier → Security risk

- **GitHub Container Registry** (ghcr.io):
  - Free for public repos
  - Good for open-source projects
  - Less enterprise features than ACR

---

### 8.3 Deployment Strategy

**RISK LEVEL**: 🟡 **MEDIUM**

#### Issue:

- NO deployment strategy defined (blue-green? canary? rolling?)

#### Recommendations:

**Production - Deployment Strategies**:

1. **Rolling Deployment** (Default Kubernetes):
   - Gradually replace old pods with new pods
   - `maxUnavailable: 1`, `maxSurge: 1` (always N-1 pods available)
   - **Benefit**: Simple, zero-downtime
   - **Risk**: If new version has bug, 50% of traffic affected before rollback

2. **Blue-Green Deployment** (Safest):
   - Deploy new version alongside old version
   - Test new version (smoke tests)
   - Switch traffic from blue (old) to green (new)
   - Keep blue running for 1 hour (fast rollback)
   - **Benefit**: Instant rollback, zero risk
   - **Cost**: 2x pods during deployment

3. **Canary Deployment** (Recommended):
   - Deploy new version to 10% of pods
   - Route 10% of traffic to canary
   - Monitor error rate, latency for 30 minutes
   - If healthy: Gradually increase to 50%, then 100%
   - If unhealthy: Rollback immediately
   - **Tools**: Flagger (Flux CD) or Argo Rollouts

**Rollback Procedure**:
```bash
# Immediate rollback (blue-green or canary)
helm rollback herossid -n prod

# Rolling deployment rollback (manual)
kubectl set image deployment/herossid-api herossid-api=acr.azurecr.io/herossid-api:v1.2.3 -n prod
```

---

### 8.4 Environment Promotion

**RISK LEVEL**: 🟡 **MEDIUM**

#### Recommendations:

**Environments**:
1. **Dev**: Auto-deploy on merge to `main`, uses Von Network (test ledger)
2. **Staging**: Manual promotion, uses Sovrin BuilderNet (test ledger), mirrors prod config
3. **Prod**: Manual approval + change control, uses Sovrin MainNet or private consortium

**Configuration Drift Prevention**:
- Use **Kustomize** overlays or Helm value files:
  - `values-dev.yaml`: 1 replica, small DB, no geo-redundancy
  - `values-staging.yaml`: 3 replicas, medium DB, mirrors prod
  - `values-prod.yaml`: 5 replicas, large DB, geo-redundancy enabled

---

## 9. Security Operations

### 9.1 Container Security Scanning

**RISK LEVEL**: 🟡 **MEDIUM**

#### Recommendations:

**CI/CD Integration**:
- **Trivy** (open-source vulnerability scanner):
  - Scan Docker images in pipeline
  - Fail build if CRITICAL vulnerabilities found
  - Example: `trivy image --severity CRITICAL --exit-code 1 herossid-api:latest`

- **Snyk** or **Aqua Security** (enterprise):
  - Deeper analysis, compliance checks
  - ~$100-500/month

**Runtime Scanning**:
- Azure Defender for Containers (if using AKS)
- Scans running containers for vulnerabilities + runtime threats

---

### 9.2 Network Policies

**RISK LEVEL**: 🟡 **MEDIUM**

#### Issue:

- NO network policies defined (Kubernetes allows all pod-to-pod traffic by default)

#### Recommendations:

**Production - Network Policies**:

```yaml
# Deny all traffic by default
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress

---
# Allow API to database
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-to-database
spec:
  podSelector:
    matchLabels:
      app: herossid-api
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: postgresql
    ports:
    - protocol: TCP
      port: 5432

---
# Allow API to external (ledger, Key Vault)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-to-external
spec:
  podSelector:
    matchLabels:
      app: herossid-api
  egress:
  - to:
    - namespaceSelector: {}  # Allow egress to internet
    ports:
    - protocol: TCP
      port: 443  # HTTPS only
```

---

### 9.3 HTTPS/TLS Certificate Management

**RISK LEVEL**: 🟡 **MEDIUM**

#### Recommendations:

**Production**:
- **cert-manager** (Kubernetes):
  - Auto-provision Let's Encrypt certificates
  - Auto-renew before expiry
  - ```yaml
    apiVersion: cert-manager.io/v1
    kind: Certificate
    metadata:
      name: herossid-tls
    spec:
      secretName: herossid-tls-secret
      issuerRef:
        name: letsencrypt-prod
      dnsNames:
      - api.herossid.com
    ```

- **Azure Application Gateway** (if using Azure):
  - Managed TLS termination
  - Auto-renew certificates
  - Web Application Firewall (WAF) included

---

### 9.4 DDoS Protection

**RISK LEVEL**: 🟡 **MEDIUM**

#### Issue:

- T139 mentions rate limiting per tenant (application-level)
- NO infrastructure-level DDoS protection

#### Recommendations:

**Production**:
- **Azure DDoS Protection Standard** (if using Azure):
  - Protects against volumetric attacks (UDP floods, SYN floods)
  - ~$2,944/month (expensive but protects entire VNet)

- **Cloudflare** (Alternative):
  - Place in front of API
  - DDoS protection + CDN + WAF
  - ~$200-2,000/month (Pro to Enterprise tier)

- **Rate Limiting** (Already in T139):
  - Application-level: 100 requests/minute per tenant (from research.md)
  - Add: Global rate limit: 10,000 requests/minute total (prevent resource exhaustion)

---

### 9.5 Penetration Testing

**RISK LEVEL**: 🟡 **MEDIUM**

#### Recommendations:

**Before Production Launch**:
- Hire external penetration testing firm
- Test for:
  - Cross-tenant data leakage (CRITICAL)
  - SQL injection (PostgreSQL parameterized queries should prevent, but verify)
  - JWT token manipulation
  - Private key extraction attempts
  - Ledger write replay attacks

**Cost**: $5,000-15,000 for comprehensive pentest (one-time)

---

## 10. Cost Optimization

### 10.1 Azure Key Vault Costs

**ADDRESSED IN SECTION 3.2**:
- Optimized architecture: 1000 tenants = $450/month (vs. $15,000+ without optimization)

---

### 10.2 PostgreSQL Instance Sizing

**RISK LEVEL**: 🟡 **MEDIUM**

#### Recommendations:

**Phase 1 (Prototype)**:
- Azure Database for PostgreSQL: General Purpose, 2 vCores, 50GB storage
- **Cost**: ~$150/month

**Production (100 tenants, 1M credentials)**:
- General Purpose, 8 vCores, 500GB storage, geo-redundancy enabled
- **Cost**: ~$800/month
- Read replicas (if needed): +$400/month per replica

**Optimization**:
- Use Azure Reserved Instances: 30-60% discount for 1-year commitment
- Right-size after launch (monitor CPU/memory utilization)

---

### 10.3 Hyperledger Indy Ledger Costs

**RISK LEVEL**: 🟡 **MEDIUM**

#### Costs:

**Sovrin MainNet**:
- Write transactions: ~$0.10-0.50 per transaction (varies by steward)
- Read transactions: Free
- Example: 1,000 DID creations/month = $100-500/month

**Private Consortium**:
- No per-transaction fees
- **BUT** infrastructure costs:
  - 4 validator nodes: ~$400-800/month (depending on VM size)
  - Ledger storage: ~$50/month
  - Network egress: ~$20/month
  - **Total**: ~$500-900/month

**Trade-off**:
- Sovrin MainNet: Lower barrier to entry, pay-per-use, no ops burden
- Private Consortium: Predictable costs, full control, higher ops burden

---

### 10.4 Storage Costs

**RISK LEVEL**: 🟡 **MEDIUM**

#### Estimates:

**Wallet SQLite Files** (if using persistent volumes):
- 1000 tenants, 10MB per wallet = 10GB total
- Azure Managed Disks (Premium SSD): ~$2/GB/month = $20/month

**Audit Logs**:
- 1M audit log entries/month, 500 bytes each = 500MB/month
- PostgreSQL storage: Included in database cost
- Long-term archive (Azure Blob cool tier): ~$0.01/GB/month = $0.50/month

**Database Backups**:
- Azure Database includes 1x data size in backups (free)
- Additional backups: $0.10/GB/month
- 500GB database with 7 days backups: ~$350/month (included)

---

### 10.5 Total Cost of Ownership (TCO) Estimate

**Production (100 tenants, 1M credentials, 10k ops/hour)**:

| Component | Monthly Cost |
|-----------|-------------|
| API pods (5 replicas, 2 vCPU each) | $300 |
| PostgreSQL (8 vCores, 500GB, geo-redundant) | $800 |
| Azure Key Vault (1000 KEKs, 10k ops) | $450 |
| Container Registry (Premium) | $150 |
| Azure Monitor + Application Insights | $200 |
| Kubernetes cluster (AKS, 3 nodes) | $400 |
| Ledger costs (Sovrin MainNet) | $250 |
| DDoS Protection (Standard) | $2,944 |
| Load balancer + networking | $100 |
| Disaster recovery (multi-region) | $500 |
| **TOTAL (without DDoS)** | **$3,150/month** |
| **TOTAL (with DDoS)** | **$6,094/month** |

**Cost per Tenant**: ~$31-61/month (100 tenants)

**Optimization Opportunities**:
- Skip DDoS Protection Standard (use Cloudflare instead): Saves $2,744/month
- Use Azure Reserved Instances: Save ~$500/month
- Self-host monitoring (Prometheus): Save ~$150/month
- **Optimized Total**: ~$2,200/month (~$22/tenant)

---

## 11. Operational Risks Summary

### CRITICAL Risks (Must Fix Before Production)

| Risk ID | Category | Issue | Impact | Mitigation |
|---------|----------|-------|--------|------------|
| **R-001** | Deployment | .NET Aspire not production-ready for Kubernetes | Cannot deploy to production | Use Aspire for dev only; create Helm charts for Kubernetes |
| **R-002** | Scalability | SQLite wallet files prevent horizontal scaling | Cannot scale beyond StatefulSet pods | Research PostgreSQL wallet storage or implement session affinity |
| **R-003** | Data Isolation | PostgreSQL RLS + connection pooling may leak tenant data | Cross-tenant data breach | Test RLS with pooling; implement per-tenant connection pools if needed |
| **R-004** | Availability | Hyperledger Indy ledger is single point of failure | Platform outage if ledger down | Implement caching + circuit breaker + retry logic |
| **R-005** | Cost | Per-DID KEKs in Key Vault = $15k/month | Unsustainable costs | Use per-tenant KEKs with key derivation ($450/month) |

---

### HIGH Risks (Should Fix Before MVP)

| Risk ID | Category | Issue | Impact | Mitigation |
|---------|----------|-------|--------|------------|
| **R-006** | Database | Zero-downtime migrations not designed | Downtime during schema changes | Use expand-contract pattern + pg-online-schema-change |
| **R-007** | DR | No backup strategy for per-tenant restore | Cannot restore single tenant | Implement per-tenant logical backups |
| **R-008** | Secrets | JWT signing key rotation strategy undefined | Compromised key = all tokens revoked | Use key versioning with grace period |
| **R-009** | Observability | Tracing/metrics backends not specified | Cannot troubleshoot production issues | Choose Azure Monitor or Prometheus+Grafana |
| **R-010** | CI/CD | No pipeline design | Manual deployments, high error rate | Create GitHub Actions workflow with security scans |

---

### MEDIUM Risks (Can Address Post-Launch)

| Risk ID | Category | Issue | Impact | Mitigation Priority |
|---------|----------|-------|--------|---------------------|
| R-011 | DR | No RPO/RTO defined | Unclear recovery expectations | Define before launch |
| R-012 | Network | No Kubernetes network policies | Pod-to-pod traffic unrestricted | Implement before prod |
| R-013 | Security | Container scanning not automated | Vulnerable images deployed | Add Trivy to CI/CD |
| R-014 | Performance | Auto-scaling strategy undefined | Under/over-provisioning | Define HPA rules |
| R-015 | Compliance | Penetration testing not planned | Unknown security gaps | Schedule before launch |

---

## 12. Production Readiness Gaps

### Infrastructure Components Missing:

1. **Kubernetes Manifests/Helm Charts**:
   - API Deployment/StatefulSet
   - PostgreSQL StatefulSet (or external DB config)
   - Ingress controller + TLS certificates
   - ConfigMaps for configuration
   - Secrets management (External Secrets Operator)

2. **CI/CD Pipeline**:
   - Build + test + security scan workflow
   - Container image publishing
   - Multi-environment deployment (dev/staging/prod)
   - Rollback procedures

3. **Monitoring Stack**:
   - Tracing backend (Application Insights or Jaeger)
   - Metrics backend (Prometheus or Azure Monitor)
   - Log aggregation (ELK or Azure Monitor Logs)
   - Alerting rules (PagerDuty, Opsgenie)

4. **Disaster Recovery**:
   - Multi-region deployment design
   - Database geo-replication
   - Backup/restore procedures (tested)
   - Failover runbooks

5. **Security Hardening**:
   - Network policies (deny-by-default)
   - Container security scanning
   - Secrets encryption at rest
   - Penetration testing report

6. **Operational Runbooks**:
   - Incident response procedures
   - Escalation matrix (who to page?)
   - Common troubleshooting scenarios
   - Ledger outage response

---

## 13. What Will Break in Production (That Won't in Dev)

### Critical Differences:

1. **Aspire AppHost Doesn't Run in Production**:
   - Dev: Aspire auto-wires service discovery, observability
   - Prod: Must manually configure Kubernetes Services, OTLP exporters

2. **Connection Pooling + RLS**:
   - Dev: Single-user testing, no connection pool reuse issues
   - Prod: Concurrent multi-tenant requests, potential tenant context leakage

3. **Wallet File Storage**:
   - Dev: Local filesystem, single pod
   - Prod: Multiple pods, ephemeral storage → Data loss

4. **Ledger Latency**:
   - Dev: Von Network (instant consensus, <100ms)
   - Prod: Sovrin MainNet (distributed consensus, 2-5s, occasional 30s timeouts)

5. **Key Vault Latency**:
   - Dev: Mock Key Vault or same-region Key Vault (<10ms)
   - Prod: Cross-region Key Vault calls (50-200ms), rate limits

6. **Database Load**:
   - Dev: 1-10 tenants, low query volume
   - Prod: 100+ tenants, connection pool exhaustion, lock contention

7. **Secret Management**:
   - Dev: Hardcoded secrets in `appsettings.Development.json`
   - Prod: Secrets in Key Vault, must sync to Kubernetes Secrets

8. **TLS Certificate Expiry**:
   - Dev: Self-signed certs, never expire
   - Prod: Let's Encrypt certs expire every 90 days (must auto-renew)

9. **Log Volume**:
   - Dev: 100 log entries/day
   - Prod: 1M+ log entries/day → Log aggregation required

10. **Cost Constraints**:
    - Dev: Single VM, minimal resources
    - Prod: Multi-region, geo-redundancy → 10x cost

---

## 14. Recommendations for Phase 1 Prototyping

### MUST DO (Before Writing Code):

1. **Resolve Deployment Strategy**:
   - [ ] Decide: Azure Container Apps (Aspire-native) OR Kubernetes (Helm charts required)
   - [ ] If Kubernetes: Create basic Helm chart for API + PostgreSQL
   - [ ] Test Aspire `azd` deployment to Azure Container Apps

2. **Resolve Wallet Storage**:
   - [ ] Test Open Wallet Foundation SDK wallet storage options
   - [ ] If PostgreSQL supported: Use PostgreSQL wallets (simplest)
   - [ ] If SQLite-only: Design StatefulSet + persistent volumes + session affinity

3. **Test PostgreSQL RLS + Connection Pooling**:
   - [ ] Create integration test: Concurrent requests from 2 tenants
   - [ ] Verify `SET LOCAL app.current_tenant` isolation under pooling
   - [ ] If isolation fails: Switch to per-tenant connection pools

4. **Optimize Key Vault Architecture**:
   - [ ] Change from per-DID KEKs to per-tenant KEKs
   - [ ] Implement key derivation (HKDF) for DID-specific keys
   - [ ] Test key caching strategy

5. **Define Observability Backends**:
   - [ ] Choose: Azure Monitor OR Prometheus+Grafana
   - [ ] Configure OTLP export in Aspire
   - [ ] Create basic dashboards (API latency, ledger latency, error rate)

6. **Document Production Deployment Path**:
   - [ ] Create `docs/deployment.md` with step-by-step production deployment
   - [ ] Clarify: Aspire is for dev only, production uses [X] strategy
   - [ ] List all missing infrastructure components (from Section 12)

---

### SHOULD DO (Phase 1):

7. **Create Minimal CI/CD Pipeline**:
   - [ ] GitHub Actions: Build + test + publish Docker image
   - [ ] Add NuGet vulnerability scan (T141)
   - [ ] Add Trivy container scan

8. **Test Ledger Failure Scenarios**:
   - [ ] Simulate ledger timeout (network delay)
   - [ ] Verify retry logic works
   - [ ] Test circuit breaker (if implemented)

9. **Create Helm Chart Skeleton**:
   - [ ] Basic Deployment for API
   - [ ] ConfigMap for non-sensitive config
   - [ ] Secret placeholder for sensitive config

10. **Define DR Strategy**:
    - [ ] Document RPO/RTO targets
    - [ ] Choose: Single-region OR multi-region
    - [ ] Plan database backup strategy

---

### CAN DEFER (Post-Prototype):

11. Network policies (can add later)
12. Multi-region deployment (unless required for prototype)
13. DDoS protection (not critical for prototype)
14. Penetration testing (do before public launch)
15. Advanced monitoring (start with basic metrics)

---

## 15. Complexity Scoring Breakdown

**Operational Complexity Score: 8.5/10**

| Factor | Score (1-10) | Weight | Weighted Score | Justification |
|--------|--------------|--------|----------------|---------------|
| Deployment Technology | 9 | 20% | 1.8 | .NET Aspire experimental for prod, Kubernetes requires custom manifests |
| External Dependencies | 9 | 15% | 1.35 | Hyperledger Indy ledger critical path, unpredictable latency |
| Multi-Tenancy | 8 | 15% | 1.2 | PostgreSQL RLS + pooling complex, high isolation risk |
| Secret Management | 7 | 10% | 0.7 | Key Vault + per-tenant KEKs + wallet passwords |
| Stateful Components | 9 | 15% | 1.35 | SQLite wallets may require StatefulSet, limits scaling |
| Observability Setup | 6 | 10% | 0.6 | Aspire helps, but backend choice undefined |
| Disaster Recovery | 8 | 10% | 0.8 | Multi-region + geo-replication + ledger HA |
| CI/CD Maturity | 7 | 5% | 0.35 | Not designed yet, but standard patterns apply |
| Security Hardening | 6 | 5% | 0.3 | Standard practices, but crypto key management complex |
| Cost Optimization | 4 | 5% | 0.2 | Moderate costs (~$2-6k/month), predictable |
| **TOTAL** | | **100%** | **8.5/10** | **Very High Complexity** |

**Interpretation**:
- **8.5/10 = Very High Complexity**: Requires senior DevOps engineer with Kubernetes, blockchain, and multi-tenant SaaS experience
- **NOT suitable** for junior DevOps or single-person operations
- **Recommended team**: 1 senior DevOps (full-time) + 1 SRE (part-time) for 100-tenant production deployment

**Comparison**:
- Simple CRUD API on App Service: **2-3/10**
- Standard multi-tenant SaaS (no blockchain): **5-6/10**
- HeroSSID (multi-tenant + blockchain + crypto): **8.5/10**
- Decentralized exchange with smart contracts: **9.5/10**

---

## 16. Final Recommendations

### For Phase 1 Prototype (Next 2-4 Weeks):

**PRIORITY 1 (BLOCKERS)**:
1. Resolve deployment path: Azure Container Apps OR Kubernetes
2. Test wallet storage options (PostgreSQL vs. SQLite)
3. Verify PostgreSQL RLS isolation with connection pooling
4. Optimize Key Vault to per-tenant KEKs (not per-DID)

**PRIORITY 2 (FOUNDATION)**:
5. Choose observability backends (Azure Monitor recommended for Aspire)
6. Create minimal CI/CD pipeline (build + test + publish)
7. Document ledger dependency + caching strategy
8. Create basic Helm chart (if Kubernetes path chosen)

**PRIORITY 3 (RISK REDUCTION)**:
9. Test ledger failure scenarios (timeout, circuit breaker)
10. Define RPO/RTO for disaster recovery
11. Create deployment documentation (`docs/deployment.md`)
12. Estimate production costs (validate budget)

---

### For MVP Launch (Before 100 Tenants):

**INFRASTRUCTURE**:
- [ ] Production-ready Helm charts with resource limits, health checks
- [ ] Multi-environment deployment (dev/staging/prod)
- [ ] Database backup/restore tested (PITR + per-tenant logical backups)
- [ ] Secrets management (External Secrets Operator or Key Vault CSI driver)

**OBSERVABILITY**:
- [ ] Distributed tracing to Application Insights or Jaeger
- [ ] Prometheus metrics + Grafana dashboards (OR Azure Monitor)
- [ ] Log aggregation (ELK or Azure Monitor Logs)
- [ ] Alerting (PagerDuty or Azure Monitor alerts)

**SECURITY**:
- [ ] Network policies (deny-by-default)
- [ ] Container vulnerability scanning in CI/CD
- [ ] Penetration testing completed
- [ ] Secrets rotation procedures documented

**OPERATIONS**:
- [ ] Incident response runbook
- [ ] Ledger outage response procedure
- [ ] Backup/restore tested quarterly
- [ ] DR failover tested (if multi-region)

**COST CONTROL**:
- [ ] Azure Reserved Instances purchased (if committed)
- [ ] Resource right-sizing after 30 days monitoring
- [ ] Cost alerts configured ($5k/month threshold)

---

### For Scale (1000+ Tenants):

- [ ] Horizontal pod auto-scaling (if stateless wallets achieved)
- [ ] Read replicas for database (geo-distributed reads)
- [ ] Multi-region deployment (99.99% availability)
- [ ] Advanced caching (Redis for ledger reads)
- [ ] Dedicated DevOps engineer + on-call rotation

---

## Conclusion

HeroSSID is an **architecturally ambitious project** with significant operational challenges. The combination of:
- Emerging orchestration technology (.NET Aspire)
- External blockchain dependency (Hyperledger Indy)
- Complex multi-tenant isolation (PostgreSQL RLS)
- Cryptographic key management at scale (Azure Key Vault)

...creates an **Operational Complexity Score of 8.5/10** (Very High).

**Key Takeaways**:
1. **.NET Aspire is NOT production-ready** for Kubernetes without custom manifests - this is a CRITICAL gap
2. **Wallet storage architecture is undefined** - blocks horizontal scaling decision
3. **PostgreSQL RLS + connection pooling** requires careful testing to prevent tenant data leakage
4. **Hyperledger Indy ledger availability** directly determines platform availability - must implement caching + circuit breakers
5. **Azure Key Vault costs** will be $15,000/month WITHOUT optimization (MUST use per-tenant KEKs, not per-DID)

**Immediate Actions**:
- [ ] Read this review with development team
- [ ] Prioritize 10 MUST DO items from Section 14
- [ ] Schedule architecture review meeting to resolve critical decisions
- [ ] Update `plan.md` and `tasks.md` with infrastructure tasks
- [ ] Allocate DevOps resource (cannot be an afterthought)

**Final Verdict**: The project is **NOT production-ready** in its current planning state. With focused effort on the identified gaps, MVP launch is achievable in 3-6 months with proper DevOps investment.

---

**Report End**
**Review Completed**: 2025-10-15
**Next Review Recommended**: After Phase 1 prototype deployment (test all critical assumptions)
