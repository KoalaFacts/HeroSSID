# Modern SSI Stack 2025 - HeroSSID Technology Strategy

## Executive Summary

**Critical Update (2025)**: Hyperledger Indy has been deprecated, and Hyperledger Aries has transitioned to the OpenWallet Foundation. This document outlines HeroSSID's updated technology strategy for building a production-ready Self-Sovereign Identity platform using modern, actively maintained technologies.

**Key Changes**:
- ❌ **Deprecated**: Hyperledger Indy SDK
- ❌ **Archived**: Hyperledger Aries (moved to OpenWallet Foundation)
- ✅ **Recommended**: OpenWallet Foundation projects (ACA-Py, Credo-TS)
- ✅ **Recommended**: DID methods: `did:web`, `did:key`, `did:peer`
- ✅ **Recommended**: Ledger-optional architecture

---

## Current State of SSI Technology (2025)

### Market Overview

- **SSI Market**: $1.9B (2025) → $38B (2030) - **66.8% CAGR**
- **DID Market**: $2.1B (2024) → $11.5B (2034)
- **Driver**: European Digital Identity Wallet (EUDI) under eIDAS 2.0

### Technology Shifts

#### 1. **Ledger-Optional Architecture**
- Moving away from mandatory blockchain/ledger dependency
- Web-based DID resolution (`did:web`) gaining traction
- Organizations can self-host DID Documents on their websites

#### 2. **Multi-Protocol Support**
- DIDComm v1 and v2 for secure messaging
- OpenID4VC (OpenID for Verifiable Credentials) for enterprise integration
- W3C Verifiable Credentials Data Model as universal standard

#### 3. **OpenWallet Foundation Ecosystem**
- **ACA-Py** (Aries Cloud Agent - Python): Production-ready SSI agent
- **Credo-TS** (formerly Aries Framework JavaScript): TypeScript/JavaScript framework
- **Bifold Wallet**: Mobile wallet reference implementation

---

## Recommended Technology Stack for HeroSSID

### 1. DID Methods (Priority Order)

#### **Primary: `did:web`** ✅ **RECOMMENDED**

**Why**:
- No blockchain required
- Uses existing web infrastructure
- Low operational cost
- Easy enterprise adoption
- W3C standard

**Format**: `did:web:example.com:users:alice`

**Resolution**:
```
DID: did:web:example.com:users:alice
→ HTTPS GET: https://example.com/users/alice/did.json
→ Returns: DID Document
```

**DID Document Location**:
```
/.well-known/did.json           (root identity)
/users/alice/did.json           (user-specific)
/departments/hr/did.json        (organizational)
```

**Advantages**:
- ✅ Familiar DNS/HTTPS infrastructure
- ✅ Built-in trust via TLS certificates
- ✅ No transaction fees
- ✅ Immediate resolution (no blockchain sync)
- ✅ Full organizational control

**Disadvantages**:
- ⚠️ Centralization risk (domain ownership)
- ⚠️ Requires web server availability
- ⚠️ Less censorship-resistant than blockchain

**HeroSSID Implementation**:
```csharp
// Phase 3: did:web Support
public class DidWebService : IDidService
{
    public async Task<string> CreateDidAsync(string domain, string path)
    {
        // Generate keypair
        var (publicKey, privateKey) = await _keyGen.GenerateEd25519KeyPairAsync();

        // Create DID
        string did = $"did:web:{domain}:{path}";

        // Create DID Document
        var didDocument = new DidDocument
        {
            Id = did,
            VerificationMethod = new[] {
                new VerificationMethod {
                    Id = $"{did}#key-1",
                    Type = "JsonWebKey2020",
                    Controller = did,
                    PublicKeyJwk = ConvertToJwk(publicKey)
                }
            }
        };

        // Store for serving via HTTPS
        await _repository.SaveDidDocumentAsync(did, didDocument);

        return did;
    }
}
```

#### **Secondary: `did:key`** ✅ **RECOMMENDED**

**Why**:
- Self-contained, no external infrastructure
- Perfect for ephemeral/temporary DIDs
- Cryptographically verifiable
- Offline-capable

**Format**: `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`

**Resolution**: DID Document derived directly from the public key (no network call)

**Use Cases**:
- Temporary session DIDs
- Device-to-device communication
- Peer-to-peer connections
- Testing and development

**HeroSSID Implementation**:
```csharp
// Phase 3: did:key Support
public class DidKeyService : IDidService
{
    public async Task<string> CreateDidAsync()
    {
        var (publicKey, privateKey) = await _keyGen.GenerateEd25519KeyPairAsync();

        // Multicodec prefix for Ed25519 public key: 0xed01
        byte[] multicodecKey = new byte[] { 0xed, 0x01 }
            .Concat(publicKey)
            .ToArray();

        // Base58-btc encode with 'z' prefix
        string did = $"did:key:z{Base58.Encode(multicodecKey)}";

        return did;
    }

    public DidDocument ResolveDidKey(string did)
    {
        // Extract public key from DID
        string encoded = did.Replace("did:key:z", "");
        byte[] decoded = Base58.Decode(encoded);

        // Skip multicodec prefix (2 bytes)
        byte[] publicKey = decoded.Skip(2).ToArray();

        // Generate DID Document on-the-fly
        return new DidDocument
        {
            Id = did,
            VerificationMethod = new[] {
                new VerificationMethod {
                    Id = $"{did}#{did}",
                    Type = "Ed25519VerificationKey2020",
                    Controller = did,
                    PublicKeyBase58 = Base58.Encode(publicKey)
                }
            }
        };
    }
}
```

#### **Tertiary: `did:peer`** 🔄 **FUTURE**

**Why**:
- Private pairwise DIDs
- No global registry
- Perfect for relationship privacy

**Format**: `did:peer:2.Ez6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc`

**Use Cases**:
- Unique DID per relationship
- Prevents correlation across services
- Ephemeral connections

#### **Legacy: `did:indy`** ⚠️ **DEPRECATED - PHASE OUT**

**Status**: Hyperledger Indy SDK deprecated, but `did:indy` method still supported on existing networks

**Migration Path**:
1. Continue `did:indy` support for backward compatibility (Phase 2-3)
2. Add `did:web` and `did:key` in parallel (Phase 3)
3. Recommend `did:web` for new users (Phase 4+)
4. Gradual migration tools for existing `did:indy` users (Phase 5)

---

### 2. SSI Agent Framework

#### **Option A: ACA-Py (OpenWallet Foundation)** ✅ **RECOMMENDED**

**Full Name**: Aries Cloud Agent - Python

**Status**: ✅ Active, production-ready, OpenWallet Foundation

**Language**: Python (REST API for interoperability)

**Supported Protocols**:
- DIDComm v1 and v2
- OpenID4VC (Issuance and Presentation)
- Issue Credential Protocol 1.0 & 2.0
- Present Proof Protocol 1.0 & 2.0

**Supported Credential Formats**:
- AnonCreds (Hyperledger Indy legacy)
- W3C Verifiable Credentials (JWT-VC, JSON-LD)
- SD-JWT (Selective Disclosure JWT)

**Supported DID Methods**:
- `did:key`
- `did:peer`
- `did:web`
- `did:sov` (legacy Indy)

**Integration with HeroSSID**:
```csharp
// Phase 5: ACA-Py Integration
public class AcaPyClient : IVerifiableCredentialService
{
    private readonly HttpClient _httpClient;

    public async Task<string> IssueCredentialAsync(CredentialOffer offer)
    {
        // Call ACA-Py REST API
        var response = await _httpClient.PostAsync(
            "/issue-credential-2.0/send-offer",
            JsonContent.Create(new {
                connection_id = offer.ConnectionId,
                credential_preview = offer.Claims,
                filter = new {
                    indy = new {
                        cred_def_id = offer.CredentialDefinitionId
                    }
                }
            })
        );

        return await response.Content.ReadAsStringAsync();
    }
}
```

**Deployment Options**:
- Docker container (official image)
- Kubernetes
- Cloud services (AWS, Azure, GCP)

**HeroSSID Strategy**:
- Use ACA-Py as **backend credential engine** (Phase 5)
- HeroSSID .NET layer provides UI, business logic, multi-tenancy
- Communicate via REST API

#### **Option B: Credo-TS (OpenWallet Foundation)** 🔄 **ALTERNATIVE**

**Full Name**: Credo TypeScript Framework (formerly Aries Framework JavaScript)

**Language**: TypeScript/JavaScript

**Advantages**:
- Modern JavaScript/TypeScript ecosystem
- React Native support for mobile
- Browser compatibility

**HeroSSID Strategy**:
- Consider for **web wallet** frontend (Phase 5)
- Complementary to ACA-Py backend

#### **Option C: Custom .NET Implementation** 🔄 **CURRENT PATH**

**Status**: What HeroSSID is currently building

**Advantages**:
- ✅ Full control over architecture
- ✅ .NET ecosystem integration
- ✅ Educational value
- ✅ No external dependencies

**Disadvantages**:
- ⚠️ Reimplementing complex protocols
- ⚠️ Slower time-to-market
- ⚠️ Maintenance burden

**Recommendation**: **Hybrid approach**
- **Phase 2-4**: Build core DID/VC capabilities in .NET (learning, control)
- **Phase 5**: Integrate ACA-Py for production protocols (DIDComm, OpenID4VC)
- **Best of both worlds**: .NET business logic + battle-tested protocols

---

### 3. Credential Formats

#### **Primary: W3C Verifiable Credentials (JWT-VC)** ✅ **RECOMMENDED**

**Format**: JSON Web Token Verifiable Credentials

**Example**:
```json
{
  "iss": "did:web:issuer.example.com",
  "sub": "did:web:holder.example.com",
  "iat": 1707264000,
  "exp": 1738800000,
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1"
    ],
    "type": ["VerifiableCredential", "EmploymentCredential"],
    "credentialSubject": {
      "id": "did:web:holder.example.com",
      "jobTitle": "Software Engineer",
      "employer": "Example Corp"
    }
  }
}
```

**Advantages**:
- ✅ W3C standard
- ✅ Compact format
- ✅ Wide tooling support
- ✅ OAuth/OIDC ecosystem integration

#### **Secondary: SD-JWT (Selective Disclosure JWT)** 🔄 **FUTURE**

**Purpose**: Privacy-preserving selective disclosure

**Example**: Prove age > 18 without revealing birthdate

**Status**: IETF draft, gaining adoption

#### **Legacy: AnonCreds** ⚠️ **PHASE OUT**

**Status**: Hyperledger Indy's credential format

**Disadvantages**:
- Tied to Indy ledger
- Limited ecosystem support
- Complex implementation

**Strategy**: Support for backward compatibility only

---

### 4. Storage & Ledger Strategy

#### **Phase 2-3: PostgreSQL (Current)** ✅

**Purpose**:
- DID storage
- Credential storage
- Key management (encrypted)

**Advantages**:
- Production-ready
- ACID transactions
- SQL Server alternative available

#### **Phase 4-5: Hybrid Storage**

**DID Documents**:
- `did:web` → HTTPS endpoint (web server)
- `did:key` → No storage (computed on-the-fly)
- `did:peer` → Local database only

**Credentials**:
- PostgreSQL for holder's wallet
- Optional: Encrypted cloud backup

**Revocation**:
- Status List 2021 (W3C standard)
- Hosted via HTTPS (no blockchain needed)

**No Blockchain Required** ✅

---

### 5. Protocol Support

#### **DIDComm v2** (Phase 5)

**Purpose**: Secure, private messaging between agents

**Use Cases**:
- Credential issuance flow
- Proof presentation requests
- Secure messaging

**Implementation**: Via ACA-Py integration

#### **OpenID4VC** (Phase 5)

**Components**:
- **OpenID4VCI**: Credential issuance
- **OpenID4VP**: Credential presentation
- **SIOPv2**: Self-issued OpenID Provider

**Advantages**:
- Enterprise SSO integration
- OAuth 2.0 familiarity
- EUDI Wallet compatibility

**Implementation**: Via ACA-Py or custom .NET OAuth libraries

---

## Updated HeroSSID Technology Roadmap

### Phase 2: DID Operations ✅ **COMPLETE**
- [x] Ed25519 keypair generation
- [x] `did:indy` format (for learning, deprecated)
- [x] W3C DID Document creation
- [x] Encrypted key storage
- [x] CLI interface

### Phase 3: Modern DID Methods & Credentials 🔄 **NEXT (UPDATED)**
- [ ] **`did:web` implementation** ← **PRIMARY FOCUS**
- [ ] **`did:key` implementation** ← **SECONDARY FOCUS**
- [ ] HTTPS DID Document serving
- [ ] W3C VC Data Model (JWT-VC format)
- [ ] Credential schema definitions
- [ ] Ed25519 signature generation
- [ ] Credential issuance service

### Phase 4: Verification & Presentation 🔄 **PLANNED**
- [ ] JWT-VC signature verification
- [ ] Proof request creation (DIF Presentation Exchange)
- [ ] Schema validation
- [ ] Status List 2021 for revocation
- [ ] did:web resolution

### Phase 5: Enterprise Integration 🔄 **PLANNED**
- [ ] **ACA-Py backend integration** ← **KEY DECISION**
- [ ] DIDComm v2 messaging
- [ ] OpenID4VC (VCI/VP) support
- [ ] Web wallet UI
- [ ] Multi-tenant architecture

### Phase 6: Advanced Features 🔄 **FUTURE**
- [ ] SD-JWT selective disclosure
- [ ] Mobile wallet (React Native + Credo-TS)
- [ ] `did:peer` for pairwise relationships
- [ ] Biometric authentication
- [ ] Hardware security module (HSM) support

### Phase 7: Production Deployment 🔄 **FUTURE**
- [ ] Kubernetes deployment
- [ ] High-availability configuration
- [ ] Monitoring and analytics
- [ ] EUDI Wallet compliance (if targeting EU)

---

## Migration Strategy from Indy

### For Existing `did:indy` Users

**Step 1: Dual-DID Support** (Phase 3)
```csharp
public class MultiMethodDidService
{
    public async Task<string> CreateDidAsync(DidMethod method)
    {
        return method switch
        {
            DidMethod.Indy => await _indyService.CreateDidAsync(),  // Legacy
            DidMethod.Web => await _webService.CreateDidAsync(),    // Modern
            DidMethod.Key => await _keyService.CreateDidAsync(),    // Modern
            _ => throw new NotSupportedException()
        };
    }
}
```

**Step 2: DID Aliasing** (Phase 4)
- Link `did:indy:...` to equivalent `did:web:...`
- Transparent resolution for existing credentials

**Step 3: Credential Re-issuance** (Phase 5)
- Tool to convert AnonCreds → JWT-VC
- Automated re-issuance from trusted issuers

**Step 4: Sunset Legacy** (Phase 6+)
- Read-only support for `did:indy`
- No new `did:indy` creation
- Full migration to modern methods

---

## Comparison: Indy vs Modern Stack

| Feature | Hyperledger Indy (Old) | Modern Stack (2025) |
|---------|------------------------|---------------------|
| **Status** | ❌ Deprecated | ✅ Active |
| **DID Methods** | `did:sov`, `did:indy` | `did:web`, `did:key`, `did:peer` |
| **Ledger Required** | ✅ Yes (Indy ledger) | ❌ No (ledger-optional) |
| **Credential Format** | AnonCreds | W3C VC (JWT, JSON-LD) |
| **Protocol** | Aries 1.0 | DIDComm v2, OpenID4VC |
| **Ecosystem** | Limited | Growing (EUDI, OpenWallet) |
| **Enterprise Adoption** | Medium | High (OAuth integration) |
| **Complexity** | High | Medium |
| **Operational Cost** | High (ledger nodes) | Low (web hosting) |
| **Privacy** | Excellent (ZKP) | Good (SD-JWT) |

---

## Recommended Architecture (Updated)

### Phase 3-5 Architecture

```
┌─────────────────────────────────────────────────────┐
│              HeroSSID .NET Layer                    │
│  (Business Logic, Multi-Tenancy, UI)                │
└────────────────┬────────────────────────────────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
┌───▼──────┐ ┌──▼─────┐ ┌────▼──────┐
│ did:web  │ │did:key │ │ ACA-Py    │
│ Service  │ │Service │ │ (REST API)│
└───┬──────┘ └──┬─────┘ └────┬──────┘
    │           │            │
    │  ┌────────┴────────────┘
    │  │
┌───▼──▼──────────────┐
│  PostgreSQL         │
│  (DID & VC Storage) │
└─────────────────────┘

    │
┌───▼────────────────┐
│ HTTPS Web Server   │
│ (did.json serving) │
└────────────────────┘
```

### Key Components

1. **did:web Service**: Creates and serves DID Documents via HTTPS
2. **did:key Service**: Generates self-contained DIDs
3. **ACA-Py Integration**: Handles complex protocols (DIDComm, OpenID4VC)
4. **PostgreSQL**: Stores DIDs, VCs, encrypted keys
5. **Web Server**: Serves `.well-known/did.json` for did:web resolution

---

## Implementation Priorities

### Immediate (Phase 3)
1. ✅ **Implement `did:web`** - Most practical for production
2. ✅ **Implement `did:key`** - Simplest, no infrastructure
3. ✅ **W3C VC JWT format** - Industry standard

### Short-term (Phase 4-5)
4. 🔄 **ACA-Py integration** - Leverage battle-tested protocols
5. 🔄 **OpenID4VC** - Enterprise SSO compatibility
6. 🔄 **Web wallet UI** - User-friendly interface

### Long-term (Phase 6+)
7. 🔄 **SD-JWT** - Advanced privacy
8. 🔄 **Mobile wallets** - Consumer adoption
9. 🔄 **EUDI compliance** - European market

---

## Decision Matrix: Custom vs. ACA-Py

### Build Custom .NET Implementation

**Pros**:
- ✅ Full architectural control
- ✅ .NET ecosystem integration
- ✅ Educational value
- ✅ No Python dependency

**Cons**:
- ⚠️ Complex protocol implementation
- ⚠️ Longer development time
- ⚠️ Ongoing maintenance burden
- ⚠️ Potential interoperability issues

### Integrate ACA-Py

**Pros**:
- ✅ Production-ready protocols
- ✅ Active OpenWallet Foundation support
- ✅ Proven interoperability
- ✅ Faster time-to-market
- ✅ Protocol updates handled

**Cons**:
- ⚠️ Python dependency
- ⚠️ Additional deployment complexity
- ⚠️ REST API overhead

### **Recommended Hybrid Approach** ✅

**Phase 2-3**: Build core DID/VC in .NET
- Learn the fundamentals
- Maintain control over data layer
- Build .NET-specific business logic

**Phase 4-5**: Integrate ACA-Py for protocols
- Use ACA-Py for DIDComm, OpenID4VC
- HeroSSID .NET layer orchestrates
- Best of both worlds

---

## Technology Decisions Summary

| Component | Technology Choice | Rationale |
|-----------|------------------|-----------|
| **Primary DID Method** | `did:web` | No blockchain, enterprise-friendly |
| **Secondary DID Method** | `did:key` | Self-contained, offline-capable |
| **Credential Format** | W3C VC (JWT-VC) | Industry standard, wide support |
| **Protocol Engine** | ACA-Py (Phase 5) | Battle-tested, OpenWallet Foundation |
| **Business Layer** | .NET 9.0 | HeroSSID core competency |
| **Storage** | PostgreSQL | Production-ready, ACID compliance |
| **Web Serving** | ASP.NET Core | did:web document hosting |
| **Future Privacy** | SD-JWT | Selective disclosure standard |

---

## References

### OpenWallet Foundation
- [ACA-Py Repository](https://github.com/openwallet-foundation/acapy)
- [Credo-TS Repository](https://github.com/openwallet-foundation/credo-ts)
- [OpenWallet Foundation Projects](https://openwallet.foundation/projects/)

### DID Methods
- [did:web Specification](https://w3c-ccg.github.io/did-method-web/)
- [did:key Specification](https://w3c-ccg.github.io/did-method-key/)
- [did:peer Specification](https://identity.foundation/peer-did-method-spec/)

### Standards
- [W3C Verifiable Credentials Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [DIDComm v2](https://identity.foundation/didcomm-messaging/spec/)
- [OpenID for Verifiable Credentials](https://openid.net/specs/openid-4-verifiable-credentials-1_0.html)
- [SD-JWT](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/)

### Market Research
- SSI Market: $1.9B (2025) → $38B (2030)
- eIDAS 2.0 and EUDI Wallet requirements

---

## Revision History

| Date | Version | Changes | Author |
|------|---------|---------|--------|
| 2025-10-17 | 1.0 | Initial modern SSI stack documentation | HeroSSID Team |

---

## Related Documents

- [SSI Technical Architecture](./ssi-technical-architecture.md) (Legacy reference)
- [Seven Laws of Identity](./seven-laws-of-identity.md)
- [Migration Guide: Indy to Modern Stack](./indy-migration-guide.md) (To be created)
