# HeroSD-JWT Integration

This document describes the integration of the HeroSD-JWT NuGet package (v1.1.3) into HeroSSID for production-ready SD-JWT (Selective Disclosure JWT) functionality.

## Overview

The HeroSD-JWT package (https://github.com/KoalaFacts/HeroSD-JWT) implements the IETF draft-ietf-oauth-selective-disclosure-jwt specification, providing hash-based selective disclosure capabilities for JWTs with Ed25519 (EdDSA) signature support.

## What Changed

### 1. Package Reference Added

Added HeroSD-JWT NuGet package v1.1.3 to `HeroSSID.Credentials.csproj`:

```xml
<PackageReference Include="HeroSD-JWT" Version="1.1.3" />
```

### 2. Production Implementations Created

Created two new implementation classes in `src/Libraries/HeroSSID.Credentials/Implementations/`:

- **HeroSdJwtGenerator.cs** - Implements `ISdJwtGenerator` using the HeroSD-JWT library
- **HeroSdJwtVerifier.cs** - Implements `ISdJwtVerifier` using the HeroSD-JWT library

These replace the mock implementations that were used for MVP development.

### 3. Dependency Injection Updated

Updated `ServiceCollectionExtensions.cs` to register the production implementations:

```csharp
// Register production SD-JWT services using HeroSD-JWT NuGet package
services.AddScoped<ISdJwtGenerator, HeroSdJwtGenerator>();
services.AddScoped<ISdJwtVerifier, HeroSdJwtVerifier>();
```

The mock implementations (`MockSdJwtGenerator` and `MockSdJwtVerifier`) are retained in the codebase but are no longer used by default.

## Features

The HeroSD-JWT integration provides:

1. **Proper Selective Disclosure**: Claims marked as selectively disclosable are hashed and included in the JWT's `_sd` array
2. **Disclosure Tokens**: Separate tokens are generated for each selectively disclosable claim
3. **Privacy-Preserving Presentations**: Holders can choose which claims to disclose to verifiers
4. **IETF Compliance**: Follows the official SD-JWT specification (draft-22)
5. **Production-Ready**: Uses the HeroSD-JWT library with 277 passing tests

## Cryptography

The integration uses **Ed25519 (EdDSA)** for signing SD-JWT credentials, consistent with HeroSSID's primary cryptographic algorithm. This ensures:

- Uniform cryptography across all JWT operations (regular JWTs and SD-JWTs)
- High-performance elliptic curve signatures
- Compatibility with HeroSSID's DID infrastructure (did:key with Ed25519)

## Testing the Integration

### Manual Testing

```bash
# Restore and build
dotnet restore
dotnet build

# Run all tests
dotnet test
```

The existing unit and integration tests work with the new implementation since they use the `ISdJwtGenerator` and `ISdJwtVerifier` interfaces.

## Implementation Details

The integration uses the real HeroSD-JWT v1.1.3 API with Ed25519 signing:

**Generation**:
```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("iss", issuerDid)
    .WithClaim("sub", holderDid)
    .WithClaim("email", "user@example.com")
    .MakeSelective("email")
    .SignWithEd25519(privateKeyBytes)  // 32-byte Ed25519 private key
    .Build();
```

**Verification**:
```csharp
var verifier = new SdJwtVerifier();
var result = verifier.VerifyPresentation(compactSdJwt, publicKeyBytes);  // 32-byte Ed25519 public key
var email = result.DisclosedClaims["email"];
```

## Reverting to Mock Implementations (If Needed)

If you need to temporarily revert to the mock implementations for testing:

1. Edit `src/Libraries/HeroSSID.Credentials/DependencyInjection/ServiceCollectionExtensions.cs`
2. Change the registrations back to:

```csharp
services.AddScoped<ISdJwtGenerator, MockSdJwtGenerator>();
services.AddScoped<ISdJwtVerifier, MockSdJwtVerifier>();
```

3. Rebuild the project

## References

- **HeroSD-JWT Repository**: https://github.com/KoalaFacts/HeroSD-JWT
- **IETF SD-JWT Specification**: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/
- **W3C Verifiable Credentials**: https://www.w3.org/TR/vc-data-model-2.0/

## Support

If you encounter issues with the integration:

1. Check that the HeroSD-JWT package is properly restored: `dotnet restore`
2. Verify the package version: `dotnet list package`
3. Review the build output for any API mismatch errors
4. Check the HeroSD-JWT documentation for the correct API usage

---

**Last Updated**: 2025-11-15
**Version**: HeroSD-JWT v1.1.3
**Status**: ✅ Production Integration Complete - Using Ed25519 (EdDSA)
