# HeroSSID - Self-Sovereign Identity Platform

**Status**: 🔄 **PIVOTING TO MODERN STANDARDS** - Phase 2 Complete, Migrating to W3C/OpenWallet
**Architecture**: CLI-first, W3C Standards-compliant, Modern SSI Stack

A production-ready CLI tool for decentralized identity management built on **W3C DID Core** and **Verifiable Credentials standards**, using modern `did:web` and `did:key` methods.

---

## 🚨 **IMPORTANT: Technology Pivot Announcement (2025-10-17)**

HeroSSID is pivoting from Hyperledger Indy to **modern W3C/OpenWallet Foundation standards**:

### Why the Pivot?
- ❌ **Hyperledger Indy SDK is deprecated**
- ❌ **Hyperledger Aries moved to OpenWallet Foundation**
- ✅ **W3C standards are industry-standard and future-proof**
- ✅ **`did:web` and `did:key` are simpler, more practical**
- ✅ **Our architecture is already 80% compatible**

### What's Changing?
- **Primary DID Method**: `did:web` (web-based DIDs using your domain)
- **Secondary DID Method**: `did:key` (self-contained, offline-capable DIDs)
- **Credential Format**: W3C Verifiable Credentials (JWT-VC)
- **Protocols**: DIDComm v2, OpenID4VC (via OpenWallet Foundation's ACA-Py)

### What's NOT Changing?
- ✅ .NET 9.0 stack
- ✅ PostgreSQL database
- ✅ CLI-first approach
- ✅ Your existing DID data (backward compatible)
- ✅ All Phase 2 work remains valid

**📚 See [docs/PIVOT-PLAN.md](docs/PIVOT-PLAN.md) for full details.**

---

## Quick Start

### Prerequisites

- [.NET 9.0 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- [Docker Desktop](https://www.docker.com/products/docker-desktop)
- Git

### Setup (5 minutes)

```bash
# Clone repository
git clone <repo-url>
cd HeroSSID

# Restore NuGet packages
dotnet restore

# Build solution
dotnet build

# Start infrastructure with .NET Aspire (recommended)
cd src/Services/HeroSSID.AppHost
dotnet run

# This automatically starts:
# - PostgreSQL with PgAdmin
# - Hyperledger Indy pool (Von Network)
# - Aspire Dashboard at http://localhost:15888
```

**Alternative**: Use manual docker-compose (see [RUNNING-WITH-ASPIRE.md](RUNNING-WITH-ASPIRE.md) for details):
```bash
docker-compose up -d
```

After infrastructure is running:

```bash
# Apply database migrations
cd src/Libraries/HeroSSID.Data
dotnet ef database update --startup-project ../../Services/HeroSSID.AppHost

# Run tests
dotnet test

# Run CLI (when ready)
dotnet run --project src/Cli/HeroSSID.Cli
```

**See [RUNNING-WITH-ASPIRE.md](RUNNING-WITH-ASPIRE.md) for detailed setup and troubleshooting.**

---

## Project Structure

```
HeroSSID/
├── src/
│   ├── HeroSSID.Cli/                    # CLI interface
│   ├── Services/
│   │   └── HeroSSID.AppHost/            # .NET Aspire orchestration
│   ├── Libraries/
│   │   ├── HeroSSID.Core/               # Domain models, interfaces
│   │   ├── HeroSSID.Data/               # EF Core, entities
│   │   ├── HeroSSID.DidOperations/      # DID creation
│   │   ├── HeroSSID.SchemaManagement/   # Schemas + Credential Definitions
│   │   ├── HeroSSID.CredentialIssuance/ # Credential issuance
│   │   └── HeroSSID.CredentialVerification/ # Credential verification
│   └── Shared/
│       ├── HeroSSID.Contracts/          # DTOs
│       └── HeroSSID.LedgerClient/       # Indy SDK wrapper
├── tests/
│   ├── Unit/                            # Service unit tests
│   ├── Integration/                     # End-to-end tests
│   └── Contract/                        # Indy ledger tests
├── specs/001-core-herossid-identity/    # 📚 Implementation plan & docs
├── docker-compose.yml                   # Local infrastructure
└── HeroSSID.sln
```

---

## Documentation

### Implementation Guides
- **[specs/001-core-herossid-identity/README.md](specs/001-core-herossid-identity/README.md)** - MVP overview & quick start
- **[specs/001-core-herossid-identity/tasks.md](specs/001-core-herossid-identity/tasks.md)** - 77-task implementation checklist
- **[specs/001-core-herossid-identity/DEPENDENCIES-REVISED.md](specs/001-core-herossid-identity/DEPENDENCIES-REVISED.md)** - Dependency strategy (11 packages with Aspire)

### Architecture & Decisions
- **[specs/001-core-herossid-identity/mvp-architecture-decisions.md](specs/001-core-herossid-identity/mvp-architecture-decisions.md)** - 10 ADRs explaining design choices
- **[specs/001-core-herossid-identity/data-model.md](specs/001-core-herossid-identity/data-model.md)** - Entity relationship model
- **[specs/001-core-herossid-identity/plan.md](specs/001-core-herossid-identity/plan.md)** - Technical implementation plan

### Future Planning
- **[specs/001-core-herossid-identity/MVP-TO-FULL-PLATFORM-RECONCILIATION.md](specs/001-core-herossid-identity/MVP-TO-FULL-PLATFORM-RECONCILIATION.md)** - Migration path to v2.0+

---

## Technology Stack

### Core Dependencies (11 NuGet packages)
- **.NET 9.0** - Runtime and SDK
- **.NET Aspire 9.5.1** - Cloud-native orchestration with dashboard
- **PostgreSQL 17** - Database with EF Core
- **Open Wallet Foundation SDK** - Hyperledger Indy/Aries integration
- **xUnit.v3** - Testing framework
- **Serilog** - File-based logging
- **Spectre.Console** - Beautiful CLI interface
- **System.CommandLine** - CLI command parsing
- **Microsoft.Extensions.Caching.Memory** - In-memory caching for schema lookups

### Infrastructure
- **.NET Aspire AppHost** - Service discovery and configuration management
- **Docker Compose** - PostgreSQL + Indy test pool
- **Von Network** - Local Hyperledger Indy test ledger

See [DEPENDENCIES-REVISED.md](specs/001-core-herossid-identity/DEPENDENCIES-REVISED.md) for full rationale.

---

## CLI Commands (Target - Day 20)

```bash
# Create a DID
herossid did create --name "Acme University Issuer"

# Publish a credential schema
herossid schema publish \
  --name "UniversityDegree" \
  --version "1.0" \
  --attributes "name,degree,university,graduationYear"

# Create credential definition
herossid credential-definition create \
  --schema <schema-id> \
  --issuer <issuer-did>

# Issue a credential
herossid credential issue \
  --issuer <issuer-did> \
  --holder <holder-did> \
  --cred-def <cred-def-id> \
  --attributes '{"name":"Alice Smith","degree":"BSc CS","university":"Acme University","graduationYear":"2024"}'

# Verify a credential
herossid credential verify --file credential.json
```

---

## Development Workflow

### Daily Workflow (TDD)
1. **Morning**: Read next task from [tasks.md](specs/001-core-herossid-identity/tasks.md)
2. **Write Tests First**: Create unit/integration tests (verify they fail ⚠️)
3. **Implement**: Make tests pass ✅
4. **Integrate**: Add CLI command if needed
5. **Commit**: One task per commit

### Running Tests
```bash
# Run all tests
dotnet test

# Run specific test project
dotnet test tests/Unit/HeroSSID.DidOperations.Tests/

# Run tests with coverage
dotnet test /p:CollectCoverage=true
```

### Database Migrations
```bash
# Add new migration
dotnet ef migrations add MigrationName --project src/Libraries/HeroSSID.Data

# Apply migrations
dotnet ef database update --project src/Libraries/HeroSSID.Data

# Rollback migration
dotnet ef database update PreviousMigrationName --project src/Libraries/HeroSSID.Data
```

### Viewing Logs
```bash
# View application logs
tail -f logs/herossid-*.log

# View Docker logs
docker-compose logs -f postgres
docker-compose logs -f indy-pool
```

---

## Configuration

### appsettings.json
```json
{
  "Indy": {
    "PoolName": "herossid-local-pool",
    "GenesisPath": "./genesis/pool_transactions_genesis"
  },
  "Logging": {
    "File": {
      "Path": "./logs/herossid-.log"
    }
  },
  "Tenant": {
    "DefaultTenantId": "11111111-1111-1111-1111-111111111111"
  },
  "Encryption": {
    "Type": "Local",
    "KeyStoragePath": "./keys"
  }
}
```

**Note**:
- Connection strings are managed by .NET Aspire AppHost (no hardcoded strings needed)
- For production, use environment variables or .NET secrets for sensitive values
- Local encryption uses .NET Data Protection API (can swap to Azure Key Vault in v2.0)

---

## MVP Scope (v1.0)

### ✅ Included
- DID creation on Hyperledger Indy
- Credential schema publishing
- Credential definition management
- Credential issuance (W3C VC format)
- Credential verification
- CLI interface
- Single-tenant deployment
- Local encryption (.NET Data Protection)
- Full TDD test coverage

### ⏸️ Deferred to v2.0+
- Multi-tenancy (Month 2)
- REST API (Month 2)
- User authentication (Month 2)
- Azure Key Vault encryption (optional - Month 2)
- Credential revocation (Month 3)
- DID resolution/deactivation (Month 3)
- Distributed tracing & metrics (Month 3)

See [mvp-architecture-decisions.md](specs/001-core-herossid-identity/mvp-architecture-decisions.md) for rationale.

---

## Timeline

| Week | Focus | Deliverable |
|------|-------|-------------|
| **Week 1** | Foundation (Days 1-7) | Can run CLI, connect to ledger/DB |
| **Week 2** | DID Operations (Days 8-10) | `herossid did create` works |
| **Week 3** | Schemas + Cred Defs (Days 11-15) | Can publish schemas |
| **Week 4** | Issuance + Verification (Days 16-20) | Complete credential lifecycle ✅ |

**Total**: 77 tasks in 20 days

---

## Contributing

### Development Setup
1. Read [specs/001-core-herossid-identity/README.md](specs/001-core-herossid-identity/README.md)
2. Review [tasks.md](specs/001-core-herossid-identity/tasks.md) for current progress
3. Follow TDD workflow (tests before implementation)
4. Commit format: `[T###] Brief description` (e.g., `[T042] Implement DID creation service`)

### Code Quality Standards
- ✅ Follow .NET coding conventions (enforced via `.editorconfig`)
- ✅ All tests must pass before commit
- ✅ Test coverage >80% for service layer
- ✅ No compiler warnings
- ✅ Constitution compliance (see [.specify/memory/constitution.md](.specify/memory/constitution.md))

---

## License

TBD - Add license information

---

## Support & Resources

### Documentation
- **Implementation Guide**: [specs/001-core-herossid-identity/](specs/001-core-herossid-identity/)
- **W3C DID Core**: https://www.w3.org/TR/did-core/
- **W3C Verifiable Credentials**: https://www.w3.org/TR/vc-data-model/
- **Hyperledger Indy**: https://www.hyperledger.org/use/hyperledger-indy

### External Resources
- **Open Wallet Foundation**: https://openwallet.foundation/
- **Von Network (Indy Test Pool)**: https://github.com/bcgov/von-network

---

**Built with** ❤️ **using .NET 9.0, Hyperledger Indy, and Test-Driven Development**

*Last Updated: 2025-10-15 | Status: MVP Implementation Phase*
