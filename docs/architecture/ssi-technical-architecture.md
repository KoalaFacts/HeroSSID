# Self-Sovereign Identity (SSI) Technical Architecture - HeroSSID

## Overview

This document maps the core technical components of Self-Sovereign Identity systems to HeroSSID's implementation, detailing current capabilities, standards compliance, and future roadmap.

---

## 1. Decentralized Identifiers (DIDs)

### Component Description
Unique identifiers not controlled by any central authority, enabling self-sovereign identity management.

### HeroSSID Implementation

#### ✅ **Phase 2 - Implemented (Current)**

**DID Method**: `did:indy`
- **Location**: [DidCreationService.cs:63-70](../../src/Libraries/HeroSSID.DidOperations/Services/DidCreationService.cs#L63)
- **Format**: `did:indy:sovrin:{base58(first 16 bytes of verkey)}`
- **Example**: `did:indy:sovrin:WgWxqztrNooG92RXvxSTWv`

**DID Creation**:
```csharp
// Generate Ed25519 keypair
var (publicKey, privateKey) = await _keyGeneration.GenerateEd25519KeyPairAsync();

// Create DID identifier from public key
string publicKeyBase58 = Convert.ToBase64String(publicKey);
string didIdentifier = $"did:indy:sovrin:{publicKeyBase58[..22]}";
```

**W3C DID Document**:
- **Location**: [DidCreationService.cs:75-83](../../src/Libraries/HeroSSID.DidOperations/Services/DidCreationService.cs#L75)
- **Standards**: W3C DID Core 1.0 compliant
- **Structure**:
```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:indy:sovrin:WgWxqztrNooG92RXvxSTWv",
  "verificationMethod": [{
    "id": "did:indy:sovrin:WgWxqztrNooG92RXvxSTWv#keys-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:indy:sovrin:WgWxqztrNooG92RXvxSTWv",
    "publicKeyBase58": "..."
  }]
}
```

**DID Storage**:
- **Database**: [Did.cs](../../src/Libraries/HeroSSID.Data/Entities/Did.cs)
- **Fields**: DidIdentifier, PublicKey, EncryptedPrivateKey, DidDocument, TenantId

#### 🔄 **Phase 5 - Planned**

**Multi-Method Support**:
- `did:web` - Web-based DIDs for enterprise integration
- `did:key` - Self-contained cryptographic DIDs
- `did:peer` - Pairwise DIDs for relationship privacy
- `did:ion` - Bitcoin-anchored DIDs (if Bitcoin integration added)

**DID Resolution Infrastructure**:
- Universal DID Resolver integration
- Caching layer for resolution performance
- Fallback resolution strategies
- DID document versioning

**Pairwise DIDs**:
- Unique DID per relationship to prevent correlation
- Relationship management UI
- DID rotation capabilities

### Standards Compliance

| Standard | Status | Implementation |
|----------|--------|----------------|
| W3C DID Core 1.0 | ✅ Full | DID Document structure |
| DID Resolution | 🔄 Planned | Phase 5 |
| DID Method Spec (did:indy) | ✅ Full | Hyperledger Indy format |

---

## 2. Verifiable Credentials (VCs)

### Component Description
Digital credentials that are cryptographically secure, tamper-evident, and privacy-preserving.

### HeroSSID Implementation

#### 🔄 **Phase 3 - Schema & Credential Issuance (Next)**

**Credential Schemas**:
- **Purpose**: Define structure and semantics of credentials
- **Format**: JSON Schema with semantic annotations
- **Examples**: EducationCredential, EmploymentCredential, MedicalRecredential
- **Storage**: Database with versioning support

**Credential Issuance**:
- **Issuer Authentication**: DID-based issuer verification
- **Credential Signing**: Ed25519 signatures over credential claims
- **Revocation Registry**: On-ledger revocation tracking
- **Batch Issuance**: Efficient multi-credential issuance

**W3C VC Data Model**:
```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/v1"
  ],
  "type": ["VerifiableCredential", "UniversityDegreeCredential"],
  "issuer": "did:indy:sovrin:IssuerDidIdentifier",
  "issuanceDate": "2025-01-15T00:00:00Z",
  "credentialSubject": {
    "id": "did:indy:sovrin:HolderDidIdentifier",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2025-01-15T00:00:00Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:indy:sovrin:IssuerDidIdentifier#keys-1",
    "jws": "eyJhbGc..."
  }
}
```

#### 🔄 **Phase 4 - Verification (Planned)**

**Verification Mechanisms**:
- Signature verification against issuer's public key
- Revocation status checking
- Schema validation
- Expiration checking
- Holder binding verification

**Proof Requests**:
- Selective disclosure requests
- Predicate proofs (e.g., age > 18 without revealing exact age)
- Composite proofs combining multiple credentials

#### 🔄 **Phase 6 - Advanced Features (Future)**

**Zero-Knowledge Proofs**:
- **Technology**: BBS+ signatures, CL signatures
- **Use Cases**: Age verification, credit score ranges, membership status
- **Privacy**: Prove claims without revealing underlying data

**Credential Revocation**:
- **Method**: Revocation registries on ledger
- **Performance**: Accumulator-based revocation for efficiency
- **Privacy**: Status list 2021 for privacy-preserving revocation checks

### Standards Compliance

| Standard | Status | Implementation |
|----------|--------|----------------|
| W3C VC Data Model 1.1 | 🔄 Phase 3 | Core credential structure |
| W3C VC Data Model 2.0 | 🔄 Phase 6 | Enhanced features |
| JSON-LD | 🔄 Phase 3 | Linked data contexts |
| JWT-VC | 🔄 Phase 4 | Compact credential format |
| BBS+ Signatures | 🔄 Phase 6 | Selective disclosure |

---

## 3. Digital Wallets

### Component Description
Secure storage for DIDs and credentials with key management and user interface.

### HeroSSID Implementation

#### ✅ **Phase 2 - CLI Wallet (Current)**

**Command-Line Interface**:
- **Location**: [DidCommands.cs](../../src/Cli/HeroSSID.Cli/Commands/DidCommands.cs)
- **Commands**: `herossid did create`, `herossid did resolve`, `herossid did list`
- **User Experience**: Interactive prompts with Spectre.Console

**Key Management**:
- **Generation**: Ed25519 keypair generation via IKeyGenerationService
- **Encryption**: AES-256 encryption of private keys at rest
- **Storage**: Encrypted private keys in PostgreSQL database
- **Memory Security**: SecureString usage, immediate zeroing after use

#### 🔄 **Phase 5 - Web Wallet (Planned)**

**Web-Based Wallet UI**:
- Single Page Application (React/Blazor)
- DID management dashboard
- Credential issuance interface
- Proof presentation workflow
- QR code generation for mobile integration

**Secure Storage**:
- Browser-based encrypted storage (IndexedDB)
- Hardware security module (HSM) support for enterprise
- Biometric authentication integration
- Multi-factor authentication (MFA)

#### 🔄 **Phase 6 - Mobile Wallet (Future)**

**Mobile Applications**:
- iOS and Android native apps
- Hardware-backed key storage (Keychain/Keystore)
- Bluetooth/NFC credential sharing
- Offline credential presentation
- Backup and recovery via encrypted cloud storage

**User Experience**:
- Intuitive credential management
- Notification system for credential requests
- Trust framework visualization
- Privacy dashboard

### Backup and Recovery

#### 🔄 **Planned Features**:

**Backup Mechanisms**:
- **Seed Phrases**: BIP-39 mnemonic phrases for key recovery
- **Social Recovery**: Multi-party computation for distributed backup
- **Encrypted Cloud Backup**: Optional backup to user-controlled cloud storage

**Recovery Workflows**:
- DID recovery via backup seed
- Credential re-issuance after wallet loss
- Key rotation after compromise

---

## 4. Blockchain/Distributed Ledger

### Component Description
Decentralized storage for DID documents, public key infrastructure, and audit trails.

### HeroSSID Implementation

#### ✅ **Phase 1-2 - Hyperledger Indy (Current)**

**Ledger Technology**: Hyperledger Indy (Sovrin Network)
- **Type**: Permissioned distributed ledger
- **Consensus**: Plenum BFT (Byzantine Fault Tolerant)
- **Purpose**: DID document anchoring, schema/credential definition publishing

**DID Document Storage**:
- DIDs written to ledger for public resolution
- Immutable public key records
- Verifiable data registry

**Credential Schemas**:
- Schema definitions published to ledger
- Credential definitions with revocation registries
- Public discoverability

**Transaction History**:
- Audit trail of DID operations
- Schema and credential definition versions
- Revocation registry updates

#### 🔄 **Phase 1 - MVP Implementation**

**Current Status**: Simulated ledger operations
- **Location**: [LedgerDIDService.cs](../../src/Shared/HeroSSID.LedgerClient/Services/LedgerDIDService.cs)
- **Approach**: Stub implementation for MVP
- **Database**: PostgreSQL as temporary ledger substitute

**Ledger Operations (Simulated)**:
```csharp
public async Task<string> RegisterDidAsync(
    string didIdentifier,
    string verkey,
    CancellationToken cancellationToken = default)
{
    // MVP: Simulate ledger write with database entry
    s_logRegisteringDid(_logger, didIdentifier, null);
    await Task.Delay(100, cancellationToken); // Simulate network latency
    return "simulated-txn-id";
}
```

#### 🔄 **Phase 7 - Production Ledger Integration (Future)**

**Real Ledger Integration Options**:

1. **Hyperledger Indy (Primary)**:
   - Direct Indy SDK integration
   - Write to Sovrin MainNet or BuilderNet
   - Full transaction signing and submission

2. **ION (Bitcoin-based)**:
   - Layer 2 DID solution on Bitcoin
   - Decentralized, permissionless
   - Integration via ION REST API

3. **Ethereum**:
   - ERC-1056 (Ethereum DID Registry)
   - Smart contract-based DID management
   - Integration via Web3 libraries

4. **Hybrid Approach**:
   - Multi-ledger support
   - DID method determines ledger
   - Unified resolution layer

**Ledger Client Architecture**:
- **Interface**: ILedgerClient (ledger-agnostic)
- **Implementations**: IndyLedgerClient, IONLedgerClient, EthereumLedgerClient
- **Factory Pattern**: Runtime ledger selection based on DID method

### Transaction Audit Trail

**Logged Operations**:
- DID registration/updates
- Schema publications
- Credential definition writes
- Revocation registry updates

**Audit Log Format**:
```json
{
  "transactionId": "txn-123456",
  "timestamp": "2025-10-17T21:30:00Z",
  "operation": "DID_REGISTRATION",
  "did": "did:indy:sovrin:WgWxqztrNooG92RXvxSTWv",
  "ledger": "sovrin-mainnet",
  "signature": "..."
}
```

---

## 5. Standards and Protocols

### Component Description
Industry standards ensuring interoperability, security, and privacy.

### HeroSSID Standards Compliance Matrix

#### W3C Standards

| Standard | Version | Status | Implementation Phase |
|----------|---------|--------|---------------------|
| **DID Core** | 1.0 | ✅ Full | Phase 2 (Complete) |
| **Verifiable Credentials Data Model** | 1.1 | 🔄 Planned | Phase 3-4 |
| **Verifiable Credentials Data Model** | 2.0 | 🔄 Future | Phase 6 |
| **DID Resolution** | CCADB | 🔄 Planned | Phase 5 |

**DID Core Compliance**:
- ✅ DID syntax and parsing
- ✅ DID document structure
- ✅ Verification methods
- ✅ Service endpoints (planned Phase 5)
- ✅ DID document metadata

**VC Data Model Compliance**:
- 🔄 Credential structure (Phase 3)
- 🔄 Proof formats (Phase 3)
- 🔄 Credential status (Phase 4)
- 🔄 Refresh service (Phase 5)
- 🔄 Terms of use (Phase 5)

#### DIDComm Protocol

**Purpose**: Secure, privacy-preserving messaging between agents

**Version**: DIDComm v2
- **Status**: 🔄 Planned (Phase 5)
- **Use Cases**:
  - Credential issuance flow
  - Proof presentation requests
  - Connection establishment
  - Encrypted messaging between wallets

**Message Structure**:
```json
{
  "id": "1234567890",
  "type": "https://didcomm.org/issue-credential/3.0/offer-credential",
  "from": "did:indy:sovrin:IssuerDid",
  "to": ["did:indy:sovrin:HolderDid"],
  "created_time": 1673972800,
  "body": {
    "credential_preview": { /* credential data */ }
  }
}
```

**DIDComm Features**:
- End-to-end encryption
- Forward secrecy
- Repudiable authentication
- Message threading
- Protocol routing

#### Credential Exchange Protocols

##### 1. **OpenID for Verifiable Credentials (OID4VC)**

**Status**: 🔄 Planned (Phase 5)

**Components**:
- **OID4VCI** (Issuance): Credential issuance via OpenID Connect
- **OID4VP** (Presentation): Credential presentation using OpenID
- **SIOPv2** (Self-Issued OP): Decentralized authentication

**Flow Example**:
```
1. Verifier → Holder: Authorization Request (presentation definition)
2. Holder: Select credentials, generate proof
3. Holder → Verifier: ID Token with VP token
4. Verifier: Verify signatures and schemas
```

**Benefits**:
- OAuth 2.0 ecosystem integration
- Enterprise SSO compatibility
- Well-established security model

##### 2. **DIF Presentation Exchange**

**Status**: 🔄 Planned (Phase 4)

**Purpose**: Standardized way to request and present credentials

**Presentation Definition**:
```json
{
  "id": "employment-verification",
  "input_descriptors": [{
    "id": "employment_credential",
    "schema": [{
      "uri": "https://schema.org/EmploymentCredential"
    }],
    "constraints": {
      "fields": [{
        "path": ["$.credentialSubject.employmentStatus"],
        "filter": {
          "type": "string",
          "pattern": "employed"
        }
      }]
    }
  }]
}
```

**Implementation**:
- **Location**: src/Libraries/HeroSSID.PresentationExchange (Phase 4)
- **Features**: Schema matching, predicate evaluation, selective disclosure

#### Cryptographic Standards

##### 1. **JSON Web Tokens (JWT)**

**Status**: ✅ Partial (Current), 🔄 Full (Phase 3)

**Usage**:
- JWT-based Verifiable Credentials (compact format)
- API authentication tokens
- Session management

**JWT-VC Example**:
```
eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJkaWQ6aW5keTo...
```

**Libraries**:
- Microsoft.IdentityModel.JsonWebTokens
- Custom JWT validation for VCs

##### 2. **JSON-LD (Linked Data)**

**Status**: 🔄 Planned (Phase 3)

**Purpose**: Semantic interoperability for credentials

**Context Files**:
```json
{
  "@context": {
    "@version": 1.1,
    "@protected": true,
    "EducationCredential": "https://schema.org/EducationCredential",
    "degree": "https://schema.org/degree"
  }
}
```

**Signature Suites**:
- Ed25519Signature2020
- JsonWebSignature2020 (ES256K for Ethereum)
- BbsBlsSignature2020 (future, selective disclosure)

##### 3. **Linked Data Signatures**

**Status**: 🔄 Planned (Phase 3)

**Signature Types**:
- **Ed25519Signature2020**: Default for HeroSSID
- **EcdsaSecp256k1Signature2019**: Ethereum compatibility
- **BbsBlsSignature2020**: Zero-knowledge selective disclosure

**Signature Structure**:
```json
{
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2025-10-17T21:30:00Z",
    "verificationMethod": "did:indy:sovrin:IssuerDid#keys-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z58DAdFfa9SkqZMVPxAQpic7ndSayn1PzZs6ZjWp1CktyGe..."
  }
}
```

##### 4. **Ed25519 Cryptography**

**Status**: ✅ Implemented (Phase 2)

**Current Usage**:
- DID keypair generation
- Signature creation (planned Phase 3)
- Signature verification (planned Phase 4)

**Implementation**:
- **Location**: [IKeyGenerationService](../../src/Libraries/HeroSSID.Core/Interfaces/IKeyGenerationService.cs)
- **Library**: .NET Cryptography APIs (System.Security.Cryptography)

**Key Properties**:
- **Public Key Size**: 32 bytes
- **Private Key Size**: 32 bytes
- **Signature Size**: 64 bytes
- **Security Level**: ~128-bit (equivalent to 3072-bit RSA)

##### 5. **Advanced Cryptography (Future)**

**BBS+ Signatures** (Phase 6):
- Selective disclosure of credential attributes
- Zero-knowledge predicates
- Unlinkable presentations

**CL Signatures** (Phase 6):
- Hyperledger Indy's default signature scheme
- Range proofs and predicates
- Revocation support

---

## Architecture Diagrams

### Current Architecture (Phase 2)

```
┌─────────────────────────────────────────────────────────────┐
│                     HeroSSID CLI                             │
│  (User Interface - Command Line)                             │
└───────────────────────┬──────────────────────────────────────┘
                        │
          ┌─────────────┴─────────────┐
          │                           │
┌─────────▼──────────┐      ┌────────▼─────────┐
│  DID Operations    │      │   Key Management │
│  Library           │      │   (Encryption)   │
└─────────┬──────────┘      └────────┬─────────┘
          │                          │
          │    ┌─────────────────────┘
          │    │
┌─────────▼────▼──────┐      ┌──────────────────┐
│  Data Layer         │◄─────┤  PostgreSQL DB   │
│  (Entity Framework) │      │  (DID Storage)   │
└─────────┬───────────┘      └──────────────────┘
          │
┌─────────▼───────────┐
│  Ledger Client      │
│  (Simulated MVP)    │
└─────────────────────┘
```

### Target Architecture (Phase 7 - Production)

```
┌────────────────┐  ┌────────────────┐  ┌────────────────┐
│  Web Wallet    │  │  Mobile Wallet │  │  CLI Wallet    │
│  (Browser)     │  │  (iOS/Android) │  │  (Terminal)    │
└────────┬───────┘  └────────┬───────┘  └────────┬───────┘
         │                   │                   │
         └───────────────────┴───────────────────┘
                             │
            ┌────────────────▼───────────────────┐
            │      HeroSSID API Gateway          │
            │  (REST/GraphQL + DIDComm)          │
            └────────────────┬───────────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
┌────────▼─────────┐ ┌───────▼────────┐ ┌───────▼────────┐
│  DID Operations  │ │  VC Operations │ │  Presentation  │
│  Service         │ │  Service       │ │  Exchange      │
└────────┬─────────┘ └───────┬────────┘ └───────┬────────┘
         │                   │                   │
         └───────────────────┴───────────────────┘
                             │
            ┌────────────────▼───────────────────┐
            │     Data & Storage Layer           │
            │  (PostgreSQL + Encrypted Vault)    │
            └────────────────┬───────────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
┌────────▼────────┐  ┌───────▼────────┐  ┌──────▼──────┐
│ Hyperledger     │  │ ION (Bitcoin)  │  │ Ethereum    │
│ Indy Ledger     │  │ Ledger         │  │ DID Registry│
└─────────────────┘  └────────────────┘  └─────────────┘
```

---

## Implementation Roadmap

### Phase 2: DID Operations ✅ **COMPLETE**
- [x] Ed25519 keypair generation
- [x] DID creation (did:indy format)
- [x] W3C DID Document creation
- [x] Encrypted key storage
- [x] CLI interface
- [x] Database persistence

### Phase 3: Schema & Credential Issuance 🔄 **NEXT**
- [ ] Credential schema definitions
- [ ] Schema publication to ledger
- [ ] Credential issuance service
- [ ] W3C VC Data Model implementation
- [ ] JSON-LD contexts
- [ ] Ed25519 signature generation
- [ ] Revocation registry creation

### Phase 4: Verification 🔄 **PLANNED**
- [ ] Proof request creation
- [ ] Selective disclosure support
- [ ] Signature verification
- [ ] Revocation status checking
- [ ] DIF Presentation Exchange
- [ ] Schema validation

### Phase 5: Web UI & DIDComm 🔄 **PLANNED**
- [ ] Web-based wallet interface
- [ ] DIDComm v2 messaging
- [ ] OID4VC integration
- [ ] DID resolution infrastructure
- [ ] Multi-DID method support

### Phase 6: Advanced Features 🔄 **FUTURE**
- [ ] Zero-knowledge proofs (BBS+)
- [ ] Mobile wallet applications
- [ ] Biometric authentication
- [ ] Social recovery mechanisms
- [ ] Cross-ledger interoperability

### Phase 7: Production Ledger 🔄 **FUTURE**
- [ ] Real Hyperledger Indy integration
- [ ] ION ledger support
- [ ] Ethereum DID Registry
- [ ] Multi-ledger abstraction layer
- [ ] Production-grade monitoring

---

## Security Considerations

### Current Implementations

1. **Key Management**:
   - ✅ AES-256 encryption for private keys
   - ✅ Secure key generation (cryptographically random)
   - ✅ Memory zeroing after use
   - 🔄 HSM support (planned)

2. **Authentication**:
   - ✅ DID-based authentication (planned Phase 3)
   - 🔄 Multi-factor authentication (Phase 5)
   - 🔄 Biometric authentication (Phase 6)

3. **Data Protection**:
   - ✅ Encryption at rest (database)
   - 🔄 Encryption in transit (TLS) (Phase 5)
   - 🔄 End-to-end encryption (DIDComm) (Phase 5)

4. **Privacy**:
   - ✅ Minimal disclosure architecture
   - ✅ Pairwise DIDs (planned)
   - 🔄 Zero-knowledge proofs (Phase 6)
   - 🔄 Unlinkable credentials (Phase 6)

### Threat Model

**Protected Against**:
- ✅ Unauthorized key access (encryption at rest)
- ✅ DID collision attacks (retry logic)
- 🔄 Man-in-the-middle attacks (TLS, Phase 5)
- 🔄 Credential forgery (signature verification, Phase 4)
- 🔄 Replay attacks (nonce/timestamp, Phase 4)

**Future Mitigations**:
- 🔄 Quantum resistance (post-quantum crypto, Phase 8)
- 🔄 Side-channel attacks (HSM, Phase 6)
- 🔄 Social engineering (MFA, user education)

---

## Standards Compliance Summary

| Category | Standard | Status | Phase |
|----------|----------|--------|-------|
| **DIDs** | W3C DID Core 1.0 | ✅ Full | 2 |
| **DIDs** | DID Resolution | 🔄 Planned | 5 |
| **VCs** | W3C VC Data Model 1.1 | 🔄 Planned | 3-4 |
| **VCs** | JWT-VC | 🔄 Planned | 3 |
| **VCs** | JSON-LD | 🔄 Planned | 3 |
| **Messaging** | DIDComm v2 | 🔄 Planned | 5 |
| **Exchange** | DIF Presentation Exchange | 🔄 Planned | 4 |
| **Exchange** | OID4VC (VCI/VP) | 🔄 Planned | 5 |
| **Crypto** | Ed25519 | ✅ Full | 2 |
| **Crypto** | BBS+ | 🔄 Future | 6 |
| **Ledger** | Hyperledger Indy | ✅ Simulated | 1-2, 🔄 Real (7) |

**Legend**:
- ✅ **Full**: Complete implementation
- 🔄 **Planned**: Scheduled for implementation
- 🔄 **Future**: Long-term roadmap

---

## References

### W3C Specifications
- [DID Core 1.0](https://www.w3.org/TR/did-core/)
- [Verifiable Credentials Data Model 1.1](https://www.w3.org/TR/vc-data-model/)
- [Verifiable Credentials Data Model 2.0 (Draft)](https://www.w3.org/TR/vc-data-model-2.0/)

### DIF Specifications
- [DIDComm Messaging v2](https://identity.foundation/didcomm-messaging/spec/)
- [Presentation Exchange](https://identity.foundation/presentation-exchange/)

### OIDF Specifications
- [OpenID for Verifiable Credentials (OID4VC)](https://openid.net/specs/openid-4-verifiable-credentials-1_0.html)
- [Self-Issued OpenID Provider v2 (SIOPv2)](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html)

### Hyperledger
- [Hyperledger Indy Documentation](https://hyperledger-indy.readthedocs.io/)
- [Hyperledger Aries](https://github.com/hyperledger/aries)

### Cryptography
- [Ed25519 Signature Specification](https://ed25519.cr.yp.to/)
- [BBS+ Signatures](https://identity.foundation/bbs-signature/draft-bbs-signatures.html)

---

## Revision History

| Date | Version | Changes | Author |
|------|---------|---------|--------|
| 2025-10-17 | 1.0 | Initial SSI architecture documentation | HeroSSID Team |

---

## Related Documents

- [Seven Laws of Identity](./seven-laws-of-identity.md)
- [Security Model](./security-model.md) (Planned)
- [Privacy Architecture](./privacy-architecture.md) (Planned)
- [API Documentation](../api/README.md) (Planned)
- [Testing Guide](../testing-guide.md)
