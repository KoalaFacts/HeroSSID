# HeroSD-JWT API Integration Notes

## Updated Implementation (2025-10-24)

The implementations have been updated based on the HeroSD-JWT API example:

```csharp
using HeroSdJwt.Issuance;
using HeroSdJwt.Common;
using HeroSdJwt.Core;

var sdJwt = SdJwtBuilder.Create()
    .WithClaim("sub", "user-123")
    .WithClaim("name", "Alice")
    .MakeSelective("email", "age")
    .SignWithHmac(key)
    .Build();

var presentation = sdJwt.ToPresentation("email");
```

## Confirmed API Elements

### Namespaces
- ✅ `HeroSdJwt.Issuance` - SD-JWT creation
- ✅ `HeroSdJwt.Common` - Common types
- ✅ `HeroSdJwt.Core` - Core functionality
- ❓ `HeroSdJwt.Verification` - Verification (assumed)

### SD-JWT Generation (Confirmed)
- ✅ `SdJwtBuilder.Create()` - Start building an SD-JWT
- ✅ `.WithClaim(key, value)` - Add claims (fluent API)
- ✅ `.MakeSelective(...claimNames)` - Mark claims as selectively disclosable
- ✅ `.SignWithHmac(key)` - Sign with HMAC key
- ✅ `.Build()` - Build the SD-JWT token
- ✅ `.ToPresentation(...claimNames)` - Create presentation with specific claims

### Key Questions That Need Verification

#### 1. Signing Methods
The example shows `.SignWithHmac(key)`. We need Ed25519 signing for DID integration:
- ❓ Is there a `.SignWithEd25519(privateKey)` method?
- ❓ Or do we use `.Sign(algorithm, privateKey)`?
- ❓ What's the format for Ed25519 keys (32 bytes seed, or 64 bytes full key)?

**Current workaround**: Using `SignWithHmac()` for now, but this needs to be changed to Ed25519 for production.

#### 2. SD-JWT Object Properties
After calling `.Build()`, we need to extract:
- ❓ How to get the compact serialization? (`.ToString()`? `.ToCompactFormat()`?)
- ❓ How to access disclosure tokens? (`.Disclosures`? `.DisclosureTokens`?)
- ❓ How to get claim digests? (`.ClaimDigests`? `.Hashes`?)

**Current approach**: Using reflection to find properties dynamically. This works but is not ideal.

#### 3. Parsing Existing SD-JWT
For verification, we need to parse a compact SD-JWT string:
- ❓ Is there a `SdJwtBuilder.Parse(compactSdJwt)` method?
- ❓ Or a separate `SdJwt.Parse()` method?
- ❓ Or a constructor: `new SdJwt(compactFormat)`?

**Current approach**: Using reflection to find Parse method, will throw NotImplementedException if not found.

#### 4. Verification API
- ❓ Is there a `SdJwtVerifier` class in `HeroSdJwt.Verification`?
- ❓ What's the verify method signature?
- ❓ Does it verify presentations or the original SD-JWT?

**Current assumption**:
```csharp
var verifier = SdJwtVerifier.Create();
var isValid = verifier.Verify(presentation, publicKey);
```

#### 5. Presentation with Multiple Disclosures
The example shows: `sdJwt.ToPresentation("email")` (single claim)

- ❓ How to disclose multiple claims?
  - `ToPresentation("email", "age")` (params)?
  - `ToPresentation(new[] { "email", "age" })` (array)?
  - Multiple calls: `sdJwt.ToPresentation("email").ToPresentation("age")`?

**Current approach**: Assuming array parameter, falls back to first disclosure if params.

#### 6. Extracting Claims from Presentation
- ❓ How to get disclosed claims from a presentation?
- ❓ Property name: `.Claims`, `.DisclosedClaims`, or `.RevealedClaims`?
- ❓ Type: `Dictionary<string, object>` or custom type?

## Recommended Next Steps

When the HeroSD-JWT package is available:

1. **Check Ed25519 Support**
   ```csharp
   // Try to find Ed25519 signing method
   var builder = SdJwtBuilder.Create()
       .WithClaim("test", "value")
       .SignWithEd25519(privateKey) // Does this exist?
       .Build();
   ```

2. **Inspect SD-JWT Object**
   ```csharp
   var sdJwt = builder.Build();

   // Check what properties are available
   Console.WriteLine($"Type: {sdJwt.GetType().FullName}");
   foreach (var prop in sdJwt.GetType().GetProperties())
   {
       Console.WriteLine($"  - {prop.Name}: {prop.PropertyType.Name}");
   }
   ```

3. **Test Parsing**
   ```csharp
   string compactFormat = sdJwt.ToString(); // or sdJwt.Compact?

   // Try to parse it back
   var parsed = SdJwt.Parse(compactFormat); // Does this work?
   ```

4. **Test Verification**
   ```csharp
   // Create a verifier
   var verifier = ???; // What's the correct way?

   // Verify a presentation
   var result = verifier.Verify(presentation, publicKey);
   ```

5. **Update Implementations**
   - Update `HeroSdJwtGenerator.cs` with correct property names
   - Update `HeroSdJwtVerifier.cs` with correct verification API
   - Add proper Ed25519 support
   - Remove reflection-based property access

## Files to Update After API Verification

1. `src/Libraries/HeroSSID.Credentials/Implementations/HeroSdJwtGenerator.cs`
   - Line 72: Change `SignWithHmac()` to Ed25519 method
   - Line 76-77: Replace `ExtractDisclosures()` and `ExtractClaimDigests()` with actual properties
   - Line 80: Confirm `ToString()` or use correct serialization method
   - Lines 90-122: Remove reflection helpers once API is confirmed

2. `src/Libraries/HeroSSID.Credentials/Implementations/HeroSdJwtVerifier.cs`
   - Line 49: Replace `ParseSdJwt()` with actual parsing method
   - Line 53: Confirm `CreatePresentation()` handles multiple disclosures correctly
   - Line 56: Confirm `SdJwtVerifier.Create()` is correct
   - Lines 113-180: Replace reflection-based methods with actual API

## Testing Checklist

Once the API is confirmed:

- [ ] SD-JWT generation with Ed25519 signing works
- [ ] Disclosures are properly extracted
- [ ] Claim digests are accessible
- [ ] Compact serialization format is correct
- [ ] Parsing existing SD-JWTs works
- [ ] Presentation creation with multiple claims works
- [ ] Verification validates signatures correctly
- [ ] Verification validates disclosure tokens against digests
- [ ] Disclosed claims are correctly extracted

## Contact

If you have the HeroSD-JWT documentation or source code, please share:
- API reference documentation
- XML documentation comments
- Sample code for verification scenarios
- Ed25519 integration examples

---

**Last Updated**: 2025-10-24
**Status**: Implementation updated with partial API knowledge, needs verification
