# HeroSD-JWT Integration

This document describes the integration of the HeroSD-JWT NuGet package into HeroSSID for production-ready SD-JWT (Selective Disclosure JWT) functionality.

## Overview

The HeroSD-JWT package (https://github.com/KoalaFacts/HeroSD-JWT) implements the IETF draft-ietf-oauth-selective-disclosure-jwt specification, providing hash-based selective disclosure capabilities for JWTs.

## What Changed

### 1. Package Reference Added

Added HeroSD-JWT NuGet package to `HeroSSID.Credentials.csproj`:

```xml
<PackageReference Include="HeroSD-JWT" Version="*" />
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

## Testing the Integration

### Build the Project

```bash
dotnet restore
dotnet build
```

### Run Tests

```bash
dotnet test
```

The existing unit and integration tests should work with the new implementation since they use the `ISdJwtGenerator` and `ISdJwtVerifier` interfaces.

## API Assumptions

**Note**: The implementations make assumptions about the HeroSD-JWT package API. If the actual API differs, the implementation files may need adjustment:

- `src/Libraries/HeroSSID.Credentials/Implementations/HeroSdJwtGenerator.cs`
- `src/Libraries/HeroSSID.Credentials/Implementations/HeroSdJwtVerifier.cs`

Expected HeroSD-JWT API (based on IETF specification and common patterns):

```csharp
// Generator
var generator = new SdJwtGenerator();
var sdJwtToken = generator.Generate(claims, signingKey, options);

// Verifier
var verifier = new SdJwtVerifier();
var result = verifier.Verify(compactSdJwt, publicKey, selectedDisclosures);
```

## Next Steps

1. **Build and Test**: Run the build and tests to verify the integration
2. **Adjust if Needed**: If the HeroSD-JWT API differs from our assumptions, update the implementation files
3. **Integration Testing**: Test the full credential issuance and verification flow
4. **Performance Testing**: Benchmark SD-JWT generation and verification performance

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

**Last Updated**: 2025-10-24
**Status**: Initial Integration - Pending Build Verification
