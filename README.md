# HeroSSID - Australia's Self-Sovereign Identity Platform

**Status**: ✅ **W3C STANDARDS + OPENID4VC** - Building Australia's SSI Infrastructure
**Architecture**: Production-ready, W3C-compliant, OpenID4VC wallet-compatible

A production-ready self-sovereign identity platform built on **W3C DID Core 1.0** and **W3C Verifiable Credentials 2.0**, with **OpenID4VC** wallet integration for global interoperability.

---

## 🎯 **Vision: Australia's Digital Sovereignty**

HeroSSID is building Australia's decentralized identity infrastructure to serve millions of businesses and individuals, positioning Australia as APAC's digital identity leader.

### Why HeroSSID?
- ✅ **W3C Standards-Compliant** - DID Core 1.0 + VC 2.0 official specifications
- ✅ **OpenID4VC Protocol** - Compatible with 30+ jurisdictions (UK, Switzerland, Japan, EU eIDAS 2.0)
- ✅ **Australian Sovereignty** - Data residency, legal jurisdiction, local support
- ✅ **.NET 9 Native** - Enterprise-grade, no deprecated dependencies
- ✅ **Production-Ready** - Ed25519 cryptography, PostgreSQL 17, OAuth 2.0

### Technology Stack
- **DID Methods**: `did:web` (primary), `did:key` (secondary)
- **Credential Format**: W3C Verifiable Credentials (JWT-VC, JSON-LD)
- **Wallet Protocols**: OpenID4VCI (issuance) + OpenID4VP (presentation)
- **Cryptography**: .NET 9 native Ed25519 (Ed25519Signature2020)
- **No Blockchain Required** - Web-based DIDs, optional DLT integration

**📚 See [docs/VISION.md](docs/VISION.md) for the full strategic vision.**

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
# - PostgreSQL 17 with PgAdmin
# - Aspire Dashboard at http://localhost:15888
```

**Alternative**: Use manual docker-compose:
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

# Run developer platform API
dotnet run --project src/Services/HeroSSID.Api
```

**See [GETTING-STARTED.md](GETTING-STARTED.md) for detailed setup and troubleshooting.**

---

## Project Structure

```
HeroSSID/
├── src/
│   ├── Services/
│   │   ├── HeroSSID.Api/                # REST API + OpenID4VC endpoints
│   │   └── HeroSSID.AppHost/            # .NET Aspire orchestration
│   ├── Libraries/
│   │   ├── HeroSSID.Core/               # Domain models, interfaces
│   │   ├── HeroSSID.Data/               # EF Core, PostgreSQL entities
│   │   ├── HeroSSID.DidOperations/      # W3C DID creation (did:web, did:key)
│   │   ├── HeroSSID.CredentialIssuance/ # W3C VC issuance + OpenID4VCI
│   │   ├── HeroSSID.CredentialVerification/ # W3C VC verification + OpenID4VP
│   │   └── HeroSSID.OAuth/              # OAuth 2.0 authorization server
│   └── Shared/
│       └── HeroSSID.Contracts/          # DTOs, API models
├── tests/
│   ├── Unit/                            # Service unit tests
│   ├── Integration/                     # End-to-end API tests
│   └── Interoperability/                # OpenID4VC wallet tests
├── specs/001-core-herossid-identity/    # 📚 Implementation plan (Q3 2025)
├── docs/                                # Vision, roadmap, pitch deck
├── docker-compose.yml                   # PostgreSQL infrastructure
└── HeroSSID.sln
```

---

## Documentation

### Vision & Strategy
- **[docs/VISION.md](docs/VISION.md)** - Australia's SSI Infrastructure vision (why this matters)
- **[docs/STRATEGIC-ROADMAP.md](docs/STRATEGIC-ROADMAP.md)** - Path to 1 million credentials by 2026
- **[docs/PITCH-DECK-OUTLINE.md](docs/PITCH-DECK-OUTLINE.md)** - Investor/government presentation guide

### Implementation Guides (Q3 2025)
- **[specs/001-core-herossid-identity/spec.md](specs/001-core-herossid-identity/spec.md)** - Feature specification (W3C + OpenID4VC)
- **[specs/001-core-herossid-identity/plan.md](specs/001-core-herossid-identity/plan.md)** - 12-week technical implementation plan
- **[specs/001-core-herossid-identity/tasks.md](specs/001-core-herossid-identity/tasks.md)** - Week 1-4 task breakdown

### Architecture & Decisions
- **[specs/001-core-herossid-identity/architecture/ADR-001-pivot-to-w3c-did-methods.md](specs/001-core-herossid-identity/architecture/ADR-001-pivot-to-w3c-did-methods.md)** - W3C standards adoption decision
- **[specs/001-core-herossid-identity/architecture/modern-ssi-stack-2025.md](specs/001-core-herossid-identity/architecture/modern-ssi-stack-2025.md)** - Modern SSI landscape analysis

---

## Technology Stack

### Core Dependencies
- **.NET 9.0** - Runtime with native Ed25519 cryptography
- **.NET Aspire 9.5.1** - Cloud-native orchestration
- **PostgreSQL 17** - Primary database with EF Core 9
- **SimpleBase** - Multibase/multicodec encoding (did:key format)
- **xUnit.v3** - Testing framework
- **ASP.NET Core 9** - REST API and OpenID4VC endpoints
- **OAuth 2.0** - Authorization server for credential issuance

### W3C Standards Implementation
- **W3C DID Core 1.0** - DID document creation and resolution
- **W3C Verifiable Credentials 2.0** - Credential data model
- **Ed25519Signature2020** - Cryptographic proof suite
- **JSON-LD and JWT-VC** - Credential serialization formats

### OpenID4VC Protocols
- **OpenID4VCI** - Wallet-based credential issuance
- **OpenID4VP** - Wallet-based presentation protocol
- **Presentation Exchange** - Flexible verification requests (DIF)

### Infrastructure
- **.NET Aspire AppHost** - Service orchestration
- **Docker Compose** - PostgreSQL infrastructure
- **No blockchain required** - Web-based DIDs (did:web)

---

## API Examples (Week 9-12 Target)

### W3C DID Operations

```bash
# Create a did:web DID
POST /api/dids
{
  "method": "web",
  "domain": "herossid.au",
  "verificationMethod": {
    "type": "Ed25519VerificationKey2020",
    "publicKeyMultibase": "z6Mk..."
  }
}

# Resolve a DID
GET /api/dids/{did}
# Returns W3C DID Document with @context

# Create a did:key DID (offline)
POST /api/dids
{
  "method": "key",
  "keyType": "Ed25519"
}
# Returns did:key:z6Mk... with embedded public key
```

### W3C Verifiable Credentials

```bash
# Issue a credential
POST /api/credentials/issue
{
  "issuer": "did:web:herossid.au",
  "credentialSubject": {
    "id": "did:key:z6Mk...",
    "degree": "Bachelor of Computer Science",
    "university": "University of Technology Sydney"
  },
  "type": ["VerifiableCredential", "UniversityDegreeCredential"]
}

# Verify a credential
POST /api/credentials/verify
{
  "verifiableCredential": { ... }
}
```

### OpenID4VC Wallet Integration

```bash
# Create credential offer for wallet
POST /openid4vci/offer
{
  "credentials": ["UniversityDegree"],
  "subjectDid": "did:key:z6Mk..."
}
# Returns: openid-credential-offer://?credential_offer_uri=...

# Wallet exchanges code for credential
POST /oauth2/token
{
  "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
  "pre-authorized_code": "eyJhbGc..."
}

POST /openid4vci/credential
Authorization: Bearer {access_token}
{
  "format": "jwt_vc_json",
  "credential_definition": {
    "type": ["VerifiableCredential", "UniversityDegreeCredential"]
  }
}
```

---

## Development Workflow

### Weekly Cadence (Q3 2025)
1. **Week 1-4**: W3C Core (DID methods, Ed25519, multibase/multicodec)
2. **Week 5-8**: Credential Issuance/Verification (W3C VC 2.0)
3. **Week 9-10**: Developer Platform (REST API + OpenID4VC protocols)
4. **Week 11-12**: SDKs and Documentation

### Daily Workflow (TDD)
1. **Morning**: Read next task from [tasks.md](specs/001-core-herossid-identity/tasks.md)
2. **Write Tests First**: Create unit/integration tests (verify they fail ⚠️)
3. **Implement**: Make tests pass ✅
4. **Commit**: One task per commit with clear message

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
# View Aspire Dashboard
# Navigate to http://localhost:15888 for live logs, traces, and metrics

# View Docker logs
docker-compose logs -f postgres
```

---

## Configuration

### appsettings.json
```json
{
  "DID": {
    "DefaultMethod": "web",
    "WebDomain": "herossid.au"
  },
  "Cryptography": {
    "DefaultAlgorithm": "Ed25519",
    "SignatureSuite": "Ed25519Signature2020"
  },
  "OpenID4VC": {
    "IssuerUrl": "https://herossid.au",
    "AuthorizationServer": "https://herossid.au/oauth2",
    "TokenLifetimeSeconds": 3600
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  }
}
```

**Note**:
- Connection strings managed by .NET Aspire AppHost
- Production: Use Azure Key Vault or AWS Secrets Manager
- Ed25519 keys use .NET 9 native cryptography (no external dependencies)

---

## Q3 2025 Scope (12-Week Implementation)

### ✅ Week 1-4: W3C Core Foundation
- W3C DID Core 1.0 compliance (did:web, did:key)
- .NET 9 native Ed25519 cryptography
- Proper multibase/multicodec encoding
- DID method abstraction layer
- W3C @context in all DID Documents

### ✅ Week 5-8: Credential Lifecycle
- W3C VC 2.0 data model implementation
- Credential issuance API (JWT-VC and JSON-LD)
- Credential verification with Ed25519Signature2020
- Selective disclosure primitives
- Revocation registry (placeholder)

### ✅ Week 9-12: Developer Platform + OpenID4VC
- REST API with OpenAPI specification
- OpenID4VCI protocol (wallet issuance)
- OpenID4VP protocol (wallet presentations)
- OAuth 2.0 authorization server
- .NET SDK (NuGet) + JavaScript SDK (npm)
- Developer sandbox and documentation

### ⏸️ Deferred to Q4 2025+
- Multi-tenancy (Q4 2025 - pilot deployments)
- Consumer wallet apps (Q3 2026)
- DIDComm v2 messaging (Q2 2026)
- Credential marketplace (Q3 2026)

See [plan.md](specs/001-core-herossid-identity/plan.md) for complete timeline.

---

## 12-Week Timeline (Q3 2025)

| Weeks | Focus | Key Deliverable |
|-------|-------|-----------------|
| **1-4** | W3C Core Foundation | did:web, did:key, Ed25519, multibase/multicodec |
| **5-8** | Credential Lifecycle | W3C VC 2.0 issuance + verification |
| **9-10** | REST API + OpenID4VC | OpenID4VCI, OpenID4VP, OAuth 2.0 server |
| **11-12** | SDKs + Documentation | .NET SDK (NuGet), JS SDK (npm), developer docs |

**Target**: Production-ready W3C + OpenID4VC platform by September 2025

---

## Contributing

### Development Setup
1. Read [specs/001-core-herossid-identity/spec.md](specs/001-core-herossid-identity/spec.md) - Feature specification
2. Review [tasks.md](specs/001-core-herossid-identity/tasks.md) for Week 1-4 tasks
3. Follow TDD workflow (tests before implementation)
4. Check [VISION.md](docs/VISION.md) to understand the strategic context

### Code Quality Standards
- ✅ Follow .NET coding conventions (enforced via `.editorconfig`)
- ✅ All tests must pass before commit (xUnit.v3)
- ✅ Test coverage >80% for service layer
- ✅ No compiler warnings
- ✅ W3C standards compliance (DID Core 1.0, VC 2.0)
- ✅ Constitution compliance (see [.specify/memory/constitution.md](.specify/memory/constitution.md))

---

## License

TBD - Add license information

---

## Support & Resources

### W3C Standards
- **W3C DID Core 1.0**: https://www.w3.org/TR/did-core/
- **W3C Verifiable Credentials 2.0**: https://www.w3.org/TR/vc-data-model-2.0/
- **Ed25519Signature2020**: https://w3c-ccg.github.io/lds-ed25519-2020/

### OpenID4VC Protocols
- **OpenID4VCI Specification**: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- **OpenID4VP Specification**: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- **Presentation Exchange (DIF)**: https://identity.foundation/presentation-exchange/

### Community
- **Open Wallet Foundation**: https://openwallet.foundation/
- **W3C Credentials Community Group**: https://www.w3.org/community/credentials/
- **Decentralized Identity Foundation**: https://identity.foundation/

---

**Built with** ❤️ **using .NET 9.0, W3C Standards, and OpenID4VC Protocols**

*Last Updated: 2025-10-17 | Status: W3C + OpenID4VC Implementation Phase*
