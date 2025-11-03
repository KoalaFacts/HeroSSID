# Cryptography Considerations for HeroSD-JWT Integration

## Summary

HeroSSID uses **Ed25519** (EdDSA) for signing JWTs and DIDs, while HeroSD-JWT v1.0.7 supports **HMAC (HS256)**, **RSA (RS256)**, and **ECDSA (ES256)**.

**Current Solution**: The integration uses **HMAC (HS256)** as a compatible fallback for SD-JWT operations.

**🎉 Update**: HeroSD-JWT is actively working on adding **Ed25519 (EdDSA)** support in an upcoming release, which will enable seamless integration with HeroSSID's existing cryptography infrastructure without requiring key conversion or separate key management.

## Algorithm Comparison

| Algorithm | HeroSSID Support | HeroSD-JWT Support | Use Case |
|-----------|------------------|-------------------|----------|
| **Ed25519** (EdDSA) | ✅ Primary | 🚧 Coming soon | Regular JWTs, DIDs, **Future SD-JWT** |
| **ECDSA** (ES256/P-256) | ❌ Not used | ✅ Supported | Alternative for SD-JWT |
| **HMAC** (HS256) | ⚠️ Fallback | ✅ Supported | **Current SD-JWT impl** |
| **RSA** (RS256) | ❌ Not used | ✅ Supported | Alternative for SD-JWT |

## Current Implementation (HMAC)

The current integration uses HMAC (HS256) for SD-JWT signing:

**Generator (HeroSdJwtGenerator.cs:77)**:
```csharp
var sdJwt = builder.SignWithHmac(signingKey).Build();
```

**Verifier (HeroSdJwtVerifier.cs:58)**:
```csharp
var result = verifier.VerifyPresentation(compactSdJwt, issuerPublicKey);
```

### Advantages of HMAC
- ✅ Works with byte[] keys (compatible with current interface)
- ✅ Supported by both HeroSSID and HeroSD-JWT
- ✅ Simple integration, no key conversion needed
- ✅ Fast performance
- ✅ Suitable for MVP and testing

### Limitations of HMAC
- ❌ Symmetric key (same key for signing and verification)
- ❌ Not ideal for distributed verification (requires sharing secret)
- ⚠️ Less common in DID/SSI ecosystems (usually use asymmetric)

## Upcoming Ed25519 Support

HeroSD-JWT maintainers are actively developing Ed25519 (EdDSA) support for an upcoming release. Once available, this will be the **ideal solution** for HeroSSID integration:

**Benefits**:
- ✅ Unified cryptography across all HeroSSID operations
- ✅ No need for separate key pairs (HMAC/ECDSA)
- ✅ Simplified key management
- ✅ Consistent with did:key and did:web Ed25519 implementations
- ✅ Better performance than RSA, smaller keys than ECDSA

**Migration Path**:
Once Ed25519 support is released in HeroSD-JWT:
1. Update HeroSD-JWT package to version with Ed25519 support
2. Replace `.SignWithHmac()` with `.SignWithEd25519()` in HeroSdJwtGenerator
3. Update verification to use Ed25519 public keys
4. No changes needed to existing Ed25519 key infrastructure

## Production Recommendations

For production deployment, choose one of these approaches based on your timeline:

### Option 1: Wait for Ed25519 Support [RECOMMENDED for HeroSSID]

**Best if**: You can wait for the HeroSD-JWT Ed25519 release

**Approach**: Continue using HMAC (HS256) in controlled environments until Ed25519 support is released, then migrate seamlessly to Ed25519 without changing key infrastructure.

### Option 2: Use ECDSA (ES256) for SD-JWT [RECOMMENDED for immediate production]

Use ECDSA (ES256 with P-256 curve) specifically for SD-JWT credentials while keeping Ed25519 for regular JWTs.

**Implementation**:
1. Generate separate ECDSA key pairs for SD-JWT operations
2. Update `ISdJwtGenerator` and `ISdJwtVerifier` to handle ECDSA keys
3. Use `.SignWithEcdsa()` in HeroSdJwtGenerator

**Example**:
```csharp
using System.Security.Cryptography;

// Generate ECDSA key pair
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var privateKey = ecdsa.ExportPkcs8PrivateKey();
var publicKey = ecdsa.ExportSubjectPublicKeyInfo();

// Sign SD-JWT
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("iss", issuerDid)
    .WithClaim("sub", holderDid)
    .WithClaim("email", "user@example.com")
    .MakeSelective("email")
    .SignWithEcdsa(privateKey)  // Use ECDSA instead of HMAC
    .Build();
```

**Advantages**:
- ✅ Asymmetric (public key can be shared freely)
- ✅ Well-supported in W3C/DID ecosystems
- ✅ Compatible with HeroSD-JWT
- ✅ Secure for distributed systems

**Changes Required**:
- Store/manage ECDSA keys alongside Ed25519 keys
- Update DID documents to reference both key types
- Modify credential issuance to use appropriate key type

### Option 2: Request EdDSA Support from HeroSD-JWT

Contact HeroSD-JWT maintainers to add Ed25519/EdDSA support.

**GitHub Issue Template**:
```markdown
Title: Feature Request: Add EdDSA (Ed25519) Signing Support

## Problem
Many SSI/DID implementations use Ed25519 for signing (did:key, did:web with Ed25519).
HeroSD-JWT currently supports HS256, RS256, and ES256 but not EdDSA.

## Proposed Solution
Add `.SignWithEdDsa(byte[] privateKey)` method supporting:
- Ed25519 signing algorithm
- RFC 8037 EdDSA signatures
- Alg header: "EdDSA"

## Use Case
Integrating with HeroSSID which uses Ed25519 for all credential operations.

## References
- RFC 8037: CFRG Elliptic Curve Signatures in JWTs
- https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms
```

### Option 3: Hybrid Approach (HMAC for Now)

Keep HMAC for initial rollout, plan migration to ECDSA:

**Phase 1 (Current)**: Use HMAC for SD-JWT
- ✅ Works immediately
- ⚠️ Document as "MVP implementation"
- ⚠️ Restrict to trusted scenarios (same issuer/verifier)

**Phase 2 (Future)**: Migrate to ECDSA
- Generate ECDSA keys
- Update implementations
- Migrate existing credentials

## Key Management Considerations

### Current HeroSSID Key Structure
```
DID Document (did:web:example.com)
├── Ed25519 Verification Method
│   ├── Private Key: 32 bytes (seed format)
│   └── Public Key: 32 bytes
└── Used for: Regular JWTs, DID signatures
```

### Recommended Enhanced Structure
```
DID Document (did:web:example.com)
├── Ed25519 Verification Method (#key-1)
│   ├── Purpose: Regular JWTs, DID operations
│   └── Type: Ed25519VerificationKey2020
├── ECDSA Verification Method (#key-2)
│   ├── Purpose: SD-JWT credentials
│   ├── Type: EcdsaSecp256r1VerificationKey2019
│   ├── Curve: P-256 (secp256r1)
│   └── Format: PKCS#8 (private), SubjectPublicKeyInfo (public)
```

## Code Examples

### Generate and Store ECDSA Keys

```csharp
public class KeyManager
{
    public (byte[] privateKey, byte[] publicKey) GenerateEcdsaKeyPair()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateKey = ecdsa.ExportPkcs8PrivateKey();
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        return (privateKey, publicKey);
    }

    public void AddEcdsaKeyToDid(string didUri, byte[] publicKey)
    {
        // Add ECDSA verification method to DID document
        // {
        //   "id": "did:web:example.com#key-sd-jwt",
        //   "type": "EcdsaSecp256r1VerificationKey2019",
        //   "controller": "did:web:example.com",
        //   "publicKeyBase58": "..." // Or publicKeyMultibase
        // }
    }
}
```

### Update Generator for ECDSA

```csharp
public SdJwtResult GenerateSdJwt(
    Dictionary<string, object> claims,
    string[] selectiveDisclosureClaims,
    byte[] ecdsaPrivateKey,  // PKCS#8 format
    string issuerDid,
    string holderDid)
{
    var builder = SdJwtBuilder.Create()
        .WithClaim("iss", issuerDid)
        .WithClaim("sub", holderDid);

    foreach (var claim in claims)
    {
        builder = builder.WithClaim(claim.Key, claim.Value);
    }

    foreach (var selectiveClaim in selectiveDisclosureClaims)
    {
        builder = builder.MakeSelective(selectiveClaim);
    }

    // Use ECDSA instead of HMAC
    var sdJwt = builder.SignWithEcdsa(ecdsaPrivateKey).Build();

    // ... rest of implementation
}
```

## Testing Considerations

### Current Tests (HMAC)
Existing tests should work with HMAC implementation:
- ✅ MockSdJwtGenerator tests
- ✅ MockSdJwtVerifier tests
- ✅ Integration tests

### Future Tests (ECDSA)
When migrating to ECDSA, add:
- Key generation tests
- ECDSA signing/verification tests
- Key format validation tests
- Interoperability tests with other ECDSA tools

## Security Notes

### HMAC Shared Secret
If using HMAC in production:
- 🔒 Use at least 32 bytes (256 bits) of cryptographically random data
- 🔒 Never expose the HMAC key in logs or error messages
- 🔒 Rotate keys periodically
- 🔒 Only use in scenarios where issuer == verifier or trust is established

### ECDSA Key Security
- 🔒 Use P-256 curve (nistP256) for ES256
- 🔒 Store private keys in hardware security modules (HSMs) if possible
- 🔒 Export keys in PKCS#8 format for portability
- 🔒 Validate public keys before use

## Migration Path

### Step 1: Continue with HMAC (Current)
- Use for development and testing
- Document limitations
- Plan for future migration

### Step 2: Prepare ECDSA Infrastructure
- Add ECDSA key generation
- Update DID documents
- Create ECDSA test suite

### Step 3: Implement ECDSA Support
- Update HeroSdJwtGenerator to use `.SignWithEcdsa()`
- Update HeroSdJwtVerifier to verify ECDSA signatures
- Update interfaces if needed

### Step 4: Migrate Existing Credentials
- Re-issue SD-JWT credentials with ECDSA
- Deprecate HMAC-signed credentials
- Update documentation

## References

- **HeroSD-JWT Documentation**: https://github.com/KoalaFacts/HeroSD-JWT
- **RFC 7518** (JWS Algorithms): https://datatracker.ietf.org/doc/html/rfc7518
- **RFC 8037** (EdDSA): https://datatracker.ietf.org/doc/html/rfc8037
- **W3C DID Core**: https://www.w3.org/TR/did-core/
- **IETF SD-JWT**: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/

---

**Last Updated**: 2025-11-03
**HeroSD-JWT Version**: 1.0.7
**Status**: Using HMAC as compatible fallback, ECDSA migration recommended for production
