# Using the Real HeroSD-JWT Package

This document explains how to discover and use the actual HeroSD-JWT package API to replace the placeholder implementations.

## Current Status

The HeroSD-JWT NuGet package has been released! We need to:
1. ✅ Add package reference (already done)
2. 🔍 Discover the actual API structure
3. 🔧 Update implementations to use real API
4. ✅ Test the integration

## Step 1: Discover the HeroSD-JWT API

We've created a discovery script that will inspect the actual HeroSD-JWT package and show us all available types, methods, and properties.

### Run the Discovery Script

```bash
./discover-herosd-jwt-api.sh
```

This script will:
1. Create a temporary project
2. Install the latest HeroSD-JWT package from NuGet.org
3. Use reflection to inspect all public types, methods, and properties
4. Display the complete API surface
5. Show the installed version number

### What to Look For

The discovery script will reveal:

#### 1. Available Namespaces
```
=== Namespace: HeroSdJwt.Issuance ===
=== Namespace: HeroSdJwt.Verification ===
=== Namespace: HeroSdJwt.Common ===
=== Namespace: HeroSdJwt.Core ===
```

#### 2. SdJwtBuilder Methods
Look for:
- `Create()` - Static method to start building
- `WithClaim(string, object)` - Add claims
- `MakeSelective(params string[])` - Mark claims as selective
- **Signing methods** - This is critical:
  - `SignWithHmac(byte[])`
  - `SignWithEd25519(byte[])` ← We need this!
  - `Sign(algorithm, byte[])`
- `Build()` - Build the SD-JWT

#### 3. SD-JWT Result Properties
After calling `Build()`, what properties are available:
- `ToString()` or `ToCompactFormat()` - Get compact serialization
- `Disclosures` or `DisclosureTokens` - Get disclosure tokens
- `ClaimDigests` or `Hashes` - Get claim digests

#### 4. Verification API
Look for:
- `SdJwtVerifier` class
- `Parse()` or `FromCompact()` methods
- `ToPresentation()` method signature
- `Verify()` method signature

## Step 2: Update Package Version

After running the discovery script, update the package reference:

```bash
# The script will tell you the installed version
# Update HeroSSID.Credentials.csproj with that version

# For example, if version is 1.0.0:
<PackageReference Include="HeroSD-JWT" Version="1.0.0" />
```

## Step 3: Update Implementations

Based on the discovery output, update these files:

### A. HeroSdJwtGenerator.cs

**Current placeholder code (lines 72-80):**
```csharp
// Using HMAC temporarily
var sdJwt = builder.SignWithHmac(signingKey).Build();

// Using reflection to get properties
var disclosures = ExtractDisclosures(sdJwt);
var claimDigests = ExtractClaimDigests(sdJwt);
var compactFormat = sdJwt.ToString();
```

**Update to real API:**
```csharp
// Use Ed25519 signing (if available)
var sdJwt = builder.SignWithEd25519(signingKey).Build();

// Use actual properties from discovery
var disclosures = sdJwt.Disclosures.ToArray();  // or DisclosureTokens
var claimDigests = sdJwt.ClaimDigests;  // or Hashes
var compactFormat = sdJwt.ToString();  // or ToCompactFormat()
```

**Then remove the helper methods** (lines 90-122):
```csharp
// DELETE these reflection-based methods:
private static string[] ExtractDisclosures(object sdJwt) { ... }
private static Dictionary<string, string> ExtractClaimDigests(object sdJwt) { ... }
```

### B. HeroSdJwtVerifier.cs

**Current placeholder code (lines 49-57):**
```csharp
var sdJwtToken = ParseSdJwt(compactSdJwt);
var presentation = CreatePresentation(sdJwtToken, selectedDisclosures);
var verifier = SdJwtVerifier.Create();
var isValid = verifier.Verify(presentation, issuerPublicKey);
```

**Update to real API** (based on discovery):
```csharp
// Use actual parsing method
var sdJwt = SdJwt.Parse(compactSdJwt);  // or SdJwtBuilder.Parse()

// Create presentation with actual API
var presentation = sdJwt.ToPresentation(selectedDisclosures);  // if it accepts array

// Verify with actual API
var verifier = new SdJwtVerifier();  // or SdJwtVerifier.Create()
var result = verifier.Verify(presentation, issuerPublicKey);
```

**Then remove the helper methods** (lines 113-180):
```csharp
// DELETE these reflection-based methods:
private static object ParseSdJwt(string compactSdJwt) { ... }
private static object CreatePresentation(object sdJwtToken, string[] selectedDisclosures) { ... }
private static Dictionary<string, object>? ExtractDisclosedClaims(object presentation) { ... }
private static string? ExtractClaim(object presentation, string claimName) { ... }
```

## Step 4: Test the Implementation

After updating the implementations:

```bash
# Run the integration test script
./test-herosd-jwt-integration.sh
```

This will:
1. Restore packages (including HeroSD-JWT)
2. Build with the updated implementations
3. Run all tests
4. Report success or show compilation errors

## Example: Complete Update Process

```bash
# 1. Discover the API
./discover-herosd-jwt-api.sh > api-discovery-output.txt

# 2. Review the output
cat api-discovery-output.txt

# 3. Update the package version (shown in output)
# Edit: src/Libraries/HeroSSID.Credentials/HeroSSID.Credentials.csproj

# 4. Update HeroSdJwtGenerator.cs based on actual API

# 5. Update HeroSdJwtVerifier.cs based on actual API

# 6. Test the changes
./test-herosd-jwt-integration.sh

# 7. Commit if successful
git add .
git commit -m "feat: Use real HeroSD-JWT API, remove placeholders"
git push
```

## Common API Patterns to Look For

### Pattern 1: Fluent Builder with Ed25519
```csharp
var sdJwt = SdJwtBuilder.Create()
    .WithClaim("iss", issuer)
    .WithClaim("sub", subject)
    .WithClaim("email", "user@example.com")
    .MakeSelective("email")
    .SignWithEd25519(privateKey)  // ← Look for this
    .Build();
```

### Pattern 2: Direct Property Access
```csharp
string compact = sdJwt.CompactFormat;  // or ToString()
string[] disclosures = sdJwt.Disclosures;
Dictionary<string, string> digests = sdJwt.ClaimDigests;
```

### Pattern 3: Presentation and Verification
```csharp
// Parse
var sdJwt = SdJwt.Parse(compactFormat);

// Create presentation
var presentation = sdJwt.ToPresentation("email", "name");  // params?

// Verify
var verifier = new SdJwtVerifier();
var result = verifier.Verify(presentation, publicKey);
bool isValid = result.IsValid;
Dictionary<string, object> claims = result.DisclosedClaims;
```

## Troubleshooting

### Build Fails with "Type not found"
- Check the namespace imports
- The discovery script shows exact namespace names

### Build Fails with "Method not found"
- Check the method name from discovery output
- Look for alternative method names (e.g., `ToCompact()` vs `ToString()`)

### Tests Fail After Update
- Check that the format/structure matches what tests expect
- Verify that disclosure tokens are in the correct format
- Ensure claim extraction returns the expected types

## Getting Help

If you get stuck:
1. Share the `api-discovery-output.txt` file
2. Share the specific compilation error
3. Share what the discovery showed for the problematic area

---

**Last Updated**: 2025-10-24
**Status**: Ready for API Discovery
