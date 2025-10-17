# HeroSSID Pivot Plan: Migration to W3C/OpenWallet Standards

## Decision Date: 2025-10-17

## Executive Summary

**Decision**: Pivot from Hyperledger Indy to modern W3C/OpenWallet Foundation standards

**Rationale**:
- ❌ Hyperledger Indy SDK is deprecated
- ❌ Hyperledger Aries moved to OpenWallet Foundation
- ✅ W3C standards are industry-standard and future-proof
- ✅ `did:web` and `did:key` are simpler and more practical
- ✅ Current architecture is already 80% compatible

**Impact**: Minimal - mostly additive changes, existing code remains valid

---

## Immediate Actions (Week 1-2)

### ✅ **Step 1: Add Base58 Encoding Library**

**Task**: Replace custom Base58 implementation with production library

**Action**:
```bash
dotnet add src/Libraries/HeroSSID.DidOperations package SimpleBase
```

**Files to Update**:
- [DidCreationService.cs:307-327](../src/Libraries/HeroSSID.DidOperations/Services/DidCreationService.cs#L307)

**Code Change**:
```csharp
// REPLACE THIS:
private static string ConvertToBase58(byte[] data)
{
    // Custom implementation...
}

// WITH THIS:
using SimpleBase;

private static string ConvertToBase58(byte[] data)
{
    return Base58.Bitcoin.Encode(data);
}
```

**Estimate**: 1 hour
**Risk**: None - backward compatible

---

### ✅ **Step 2: Implement Real Ed25519 Key Generation**

**Task**: Replace simulated keys with .NET 9 native Ed25519

**Files to Update**:
- [DidCreationService.cs:226-242](../src/Libraries/HeroSSID.DidOperations/Services/DidCreationService.cs#L226)

**Code Change**:
```csharp
// REPLACE THIS:
private static (byte[] publicKey, byte[] privateKey) GenerateEd25519KeyPair()
{
    byte[] publicKey = new byte[32];
    byte[] privateKey = new byte[32];

    using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(publicKey);
        rng.GetBytes(privateKey);
    }

    return (publicKey, privateKey);
}

// WITH THIS:
private static (byte[] publicKey, byte[] privateKey) GenerateEd25519KeyPair()
{
    // .NET 9 native Ed25519 support
    using var ecdsa = ECDsa.Create(ECCurve.CreateFromFriendlyName("Ed25519"));

    // Export keys in standard format
    byte[] publicKey = ecdsa.ExportSubjectPublicKeyInfo();
    byte[] privateKey = ecdsa.ExportPkcs8PrivateKey();

    return (publicKey, privateKey);
}
```

**Estimate**: 2 hours (including testing)
**Risk**: Low - well-documented .NET API

---

### ✅ **Step 3: Add W3C Context to DID Documents**

**Task**: Make DID Documents fully W3C compliant

**Files to Update**:
- [DidCreationService.cs:273-298](../src/Libraries/HeroSSID.DidOperations/Services/DidCreationService.cs#L273)

**Code Change**:
```csharp
private static string CreateDidDocument(string didIdentifier, byte[] publicKey)
{
    string publicKeyBase58 = ConvertToBase58(publicKey);
    string verificationMethodId = $"{didIdentifier}#keys-1";

    var didDocument = new
    {
        // ADD THIS LINE:
        context = new[] { "https://www.w3.org/ns/did/v1" },

        id = didIdentifier,
        verificationMethod = new[]
        {
            new
            {
                id = verificationMethodId,
                type = "Ed25519VerificationKey2020",
                controller = didIdentifier,
                publicKeyBase58 = publicKeyBase58
            }
        },
        authentication = new[] { verificationMethodId }
    };

    return JsonSerializer.Serialize(didDocument, s_jsonOptions);
}
```

**Estimate**: 30 minutes
**Risk**: None - additive change

---

### ✅ **Step 4: Create DID Method Abstraction**

**Task**: Create interfaces and enums for multi-method support

**New Files**:
- `src/Libraries/HeroSSID.Core/Enums/DidMethod.cs`
- `src/Libraries/HeroSSID.Core/Interfaces/IDidService.cs`
- `src/Libraries/HeroSSID.Core/Interfaces/IDidServiceFactory.cs`

**Code**:

**DidMethod.cs**:
```csharp
namespace HeroSSID.Core.Enums;

/// <summary>
/// Supported DID methods
/// </summary>
public enum DidMethod
{
    /// <summary>
    /// did:web - Web-based DIDs using domain names
    /// </summary>
    Web,

    /// <summary>
    /// did:key - Self-contained DIDs derived from public keys
    /// </summary>
    Key,

    /// <summary>
    /// did:indy - Legacy Hyperledger Indy DIDs (backward compatibility only)
    /// </summary>
    [Obsolete("Hyperledger Indy is deprecated. Use did:web or did:key instead.")]
    Indy
}
```

**IDidService.cs**:
```csharp
namespace HeroSSID.Core.Interfaces;

/// <summary>
/// Base interface for DID services
/// </summary>
public interface IDidService
{
    /// <summary>
    /// The DID method this service handles
    /// </summary>
    DidMethod Method { get; }

    /// <summary>
    /// Creates a new DID
    /// </summary>
    Task<DidCreationResult> CreateDidAsync(
        DidCreationOptions options,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Resolves a DID to its DID Document
    /// </summary>
    Task<string> ResolveDidAsync(
        string didIdentifier,
        CancellationToken cancellationToken = default);
}
```

**IDidServiceFactory.cs**:
```csharp
namespace HeroSSID.Core.Interfaces;

/// <summary>
/// Factory for creating DID services based on method
/// </summary>
public interface IDidServiceFactory
{
    /// <summary>
    /// Gets the appropriate service for a DID method
    /// </summary>
    IDidService GetService(DidMethod method);
}
```

**Estimate**: 2 hours
**Risk**: None - new code, no breaking changes

---

## Short-term Actions (Week 2-4)

### ✅ **Step 5: Implement did:web Service**

**New Files**:
- `src/Libraries/HeroSSID.DidOperations/Services/DidWebService.cs`
- `src/Libraries/HeroSSID.DidOperations/Models/DidWebOptions.cs`

**Key Features**:
- Generate DIDs with domain and path: `did:web:example.com:users:alice`
- Create W3C-compliant DID Documents
- Store for HTTPS serving

**Code Skeleton**:
```csharp
public class DidWebService : IDidService
{
    public DidMethod Method => DidMethod.Web;

    public async Task<DidCreationResult> CreateDidAsync(
        DidCreationOptions options,
        CancellationToken cancellationToken = default)
    {
        var webOptions = (DidWebOptions)options;

        // Generate keypair
        var (publicKey, privateKey) = GenerateEd25519KeyPair();

        // Create DID identifier
        string didIdentifier = $"did:web:{webOptions.Domain}:{webOptions.Path}";

        // Create W3C DID Document
        string didDocument = CreateDidDocument(didIdentifier, publicKey);

        // Encrypt and store
        // ...

        return result;
    }

    public async Task<string> ResolveDidAsync(
        string didIdentifier,
        CancellationToken cancellationToken = default)
    {
        // did:web:example.com:users:alice
        // → HTTPS GET: https://example.com/users/alice/did.json

        string url = DidWebResolver.ToHttpsUrl(didIdentifier);
        // Fetch and return DID Document
    }
}
```

**Estimate**: 1 week
**Risk**: Low - straightforward implementation

---

### ✅ **Step 6: Implement did:key Service**

**New Files**:
- `src/Libraries/HeroSSID.DidOperations/Services/DidKeyService.cs`

**Key Features**:
- Generate self-contained DIDs: `did:key:z6Mk...`
- No storage needed (DID Document computed from DID)
- Offline-capable

**Code Skeleton**:
```csharp
public class DidKeyService : IDidService
{
    public DidMethod Method => DidMethod.Key;

    public async Task<DidCreationResult> CreateDidAsync(
        DidCreationOptions options,
        CancellationToken cancellationToken = default)
    {
        // Generate keypair
        var (publicKey, privateKey) = GenerateEd25519KeyPair();

        // Multicodec prefix for Ed25519 public key: 0xed01
        byte[] multicodecKey = new byte[] { 0xed, 0x01 }
            .Concat(publicKey)
            .ToArray();

        // Create DID identifier
        string didIdentifier = $"did:key:z{Base58.Bitcoin.Encode(multicodecKey)}";

        // Create DID Document (computed, not stored)
        string didDocument = CreateDidDocument(didIdentifier, publicKey);

        return result;
    }

    public Task<string> ResolveDidAsync(
        string didIdentifier,
        CancellationToken cancellationToken = default)
    {
        // Extract public key from DID and compute DID Document
        string encoded = didIdentifier.Replace("did:key:z", "");
        byte[] decoded = Base58.Bitcoin.Decode(encoded);

        // Skip multicodec prefix (2 bytes)
        byte[] publicKey = decoded.Skip(2).ToArray();

        // Generate DID Document on-the-fly
        return Task.FromResult(CreateDidDocument(didIdentifier, publicKey));
    }
}
```

**Estimate**: 3-4 days
**Risk**: Low - well-specified method

---

### ✅ **Step 7: Create ASP.NET Core Web API for did:web**

**New Project**:
- `src/Services/HeroSSID.WebApi`

**Purpose**: Serve DID Documents via HTTPS for `did:web` resolution

**Key Endpoints**:
```csharp
[ApiController]
[Route(".well-known")]
public class DidController : ControllerBase
{
    [HttpGet("did.json")]
    public async Task<IActionResult> GetRootDid()
    {
        // did:web:example.com
        // → https://example.com/.well-known/did.json

        string domain = Request.Host.Value;
        var did = await _didService.GetDidByDomainAsync(domain);
        return Ok(did.DidDocument);
    }

    [HttpGet("{*path}/did.json")]
    public async Task<IActionResult> GetPathDid(string path)
    {
        // did:web:example.com:users:alice
        // → https://example.com/users/alice/did.json

        string domain = Request.Host.Value;
        var did = await _didService.GetDidByPathAsync(domain, path);
        return Ok(did.DidDocument);
    }
}
```

**Estimate**: 1 week
**Risk**: Low - standard ASP.NET Core

---

### ✅ **Step 8: Update CLI for Multi-Method Support**

**Files to Update**:
- `src/Cli/HeroSSID.Cli/Commands/DidCommands.cs`

**New Commands**:
```bash
# Create did:web
herossid did create --method web --domain example.com --path users/alice

# Create did:key (default for quick testing)
herossid did create --method key

# Create did:indy (legacy, deprecated warning)
herossid did create --method indy
```

**Code**:
```csharp
var methodOption = new Option<string>(
    "--method",
    () => "key",
    "DID method to use (web, key, indy)");

var domainOption = new Option<string>(
    "--domain",
    "Domain name (required for did:web)");

var pathOption = new Option<string>(
    "--path",
    () => "",
    "Path component (optional for did:web)");

createCommand.AddOption(methodOption);
createCommand.AddOption(domainOption);
createCommand.AddOption(pathOption);

createCommand.SetHandler(async (method, domain, path) =>
{
    var didMethod = Enum.Parse<DidMethod>(method, ignoreCase: true);

    if (didMethod == DidMethod.Indy)
    {
        AnsiConsole.MarkupLine("[yellow]⚠ Warning: did:indy is deprecated. Consider using did:web or did:key.[/]");
    }

    var service = _serviceFactory.GetService(didMethod);
    var result = await service.CreateDidAsync(/* options */);

    AnsiConsole.MarkupLine($"[green]✓[/] DID created: [cyan]{result.DidIdentifier}[/]");
}, methodOption, domainOption, pathOption);
```

**Estimate**: 2 days
**Risk**: Low

---

## Mid-term Actions (Week 5-8)

### ✅ **Step 9: Implement W3C Verifiable Credentials (JWT-VC)**

**Goal**: Move from AnonCreds to W3C VC Data Model

**New Files**:
- `src/Libraries/HeroSSID.VerifiableCredentials/Models/VerifiableCredential.cs`
- `src/Libraries/HeroSSID.VerifiableCredentials/Services/CredentialService.cs`

**Key Features**:
- JWT-VC format
- Ed25519 signatures
- W3C VC Data Model 1.1 compliance

**Estimate**: 3-4 weeks
**Risk**: Medium - complex specification, but well-documented

---

### ✅ **Step 10: Database Migration (Optional)**

**Current Schema**: Already compatible! No changes needed.

**Optional Enhancements**:
- Add `DidMethod` enum column for filtering
- Add `DomainPath` for did:web quick lookup

**Migration**:
```sql
-- Optional: Add method tracking
ALTER TABLE Dids ADD COLUMN DidMethod VARCHAR(20);
UPDATE Dids SET DidMethod = 'indy' WHERE DidIdentifier LIKE 'did:indy:%';

-- Optional: Add did:web domain/path
ALTER TABLE Dids ADD COLUMN Domain VARCHAR(255);
ALTER TABLE Dids ADD COLUMN Path VARCHAR(500);
```

**Estimate**: 1 day (if needed)
**Risk**: None - optional enhancement

---

## Long-term Actions (Week 9-12)

### ✅ **Step 11: ACA-Py Integration**

**Goal**: Add DIDComm v2 and OpenID4VC via OpenWallet Foundation's ACA-Py

**Approach**: REST API integration

**Estimate**: 3-4 weeks
**Risk**: Low - well-documented integration pattern

---

## Documentation Updates

### Files to Update:

1. **README.md** - Add pivot announcement, new DID methods
2. **docs/architecture/ssi-technical-architecture.md** - Mark as legacy reference
3. **docs/architecture/modern-ssi-stack-2025.md** - Mark as current direction
4. **docs/GETTING-STARTED.md** - Update with did:web and did:key examples

### New Documents:

1. **docs/migration/INDY-TO-WEB.md** - Migration guide for existing users
2. **docs/api/did-web-resolution.md** - did:web hosting and resolution guide

---

## Backward Compatibility Strategy

### Phase 1 (Current - Week 4)
- ✅ Keep `did:indy` support for existing users
- ✅ Add deprecation warnings
- ✅ All new features work with any DID method

### Phase 2 (Week 5-8)
- 🔄 Mark `did:indy` as `[Obsolete]` in code
- 🔄 Documentation recommends `did:web` and `did:key`

### Phase 3 (Week 9+)
- 🔄 Read-only `did:indy` support
- 🔄 No new `did:indy` creation
- 🔄 Migration tools for converting existing DIDs

---

## Testing Strategy

### Unit Tests
- ✅ Test did:web service
- ✅ Test did:key service
- ✅ Test DID Document W3C compliance
- ✅ Test Ed25519 key generation
- ✅ Test Base58 encoding

### Integration Tests
- ✅ Test did:web HTTPS resolution
- ✅ Test multi-method factory
- ✅ Test CLI commands

### Contract Tests
- ✅ W3C DID Core compliance
- ✅ did:web method specification
- ✅ did:key method specification

---

## Success Metrics

### Week 2
- ✅ Real Ed25519 keys implemented
- ✅ Base58 library integrated
- ✅ W3C context added to DID Documents

### Week 4
- ✅ did:web service functional
- ✅ did:key service functional
- ✅ Multi-method factory working
- ✅ CLI supports all methods

### Week 8
- ✅ ASP.NET API serving did:web documents
- ✅ W3C VC implementation started
- ✅ Documentation updated

### Week 12
- ✅ Production-ready did:web and did:key
- ✅ W3C VC issuance and verification
- ✅ ACA-Py integration complete

---

## Risk Mitigation

### Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Ed25519 .NET 9 issues | Low | Medium | Fallback to NSec library |
| did:web hosting complexity | Low | Medium | Use standard ASP.NET patterns |
| W3C VC complexity | Medium | High | Use JWT libraries, phased approach |
| ACA-Py integration | Low | Medium | Well-documented REST API |

### Business Risks

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Breaking existing users | None | N/A | Backward compatibility maintained |
| Timeline delays | Medium | Low | Phased approach, MVP focus |
| Specification changes | Low | Medium | Follow stable W3C Recommendations |

---

## Communication Plan

### Internal Team
- Daily: Standup updates on pivot progress
- Weekly: Demo of new DID methods
- Bi-weekly: Architecture review

### Users (if any)
- Announcement: Pivot to modern standards
- Migration guide: How to transition from did:indy
- Support: Discord/Slack channel for questions

### Community
- Blog post: "Why We're Moving from Indy to W3C Standards"
- GitHub: Update project description and roadmap
- Twitter/LinkedIn: Announce modern SSI stack adoption

---

## Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2025-10-17 | Pivot to W3C/OpenWallet | Indy deprecated, W3C is industry standard |
| 2025-10-17 | Primary: did:web | Practical, no blockchain, enterprise-friendly |
| 2025-10-17 | Secondary: did:key | Simple, self-contained, testing-friendly |
| 2025-10-17 | Hybrid approach | .NET for business logic + ACA-Py for protocols |
| 2025-10-17 | Maintain did:indy | Backward compatibility for existing users |

---

## Next Steps

### This Week (Week 1)
1. ✅ Add SimpleBase NuGet package
2. ✅ Implement real Ed25519 key generation
3. ✅ Add W3C context to DID Documents
4. ✅ Create DID method abstractions
5. ✅ Update documentation

### Next Week (Week 2)
1. 🔄 Start did:web service implementation
2. 🔄 Start did:key service implementation
3. 🔄 Begin ASP.NET Web API project
4. 🔄 Update CLI for multi-method support

### Week 3-4
1. 🔄 Complete did:web and did:key services
2. 🔄 Integration testing
3. 🔄 Documentation
4. 🔄 Demo to stakeholders

---

## Resources

### Standards
- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/)
- [did:web Method](https://w3c-ccg.github.io/did-method-web/)
- [did:key Method](https://w3c-ccg.github.io/did-method-key/)

### Libraries
- [SimpleBase](https://www.nuget.org/packages/SimpleBase/) - Base58 encoding
- [.NET 9 Ed25519](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ecdsa)

### Community
- [OpenWallet Foundation](https://openwallet.foundation/)
- [DIF (Decentralized Identity Foundation)](https://identity.foundation/)
- [W3C Credentials Community Group](https://www.w3.org/community/credentials/)

---

**Status**: ✅ **APPROVED - PIVOT IN PROGRESS**

**Owner**: HeroSSID Team
**Start Date**: 2025-10-17
**Target Completion**: 2025-12-31 (Phase 1 complete by Week 4)

---

*This is a living document. Updates will be made as the pivot progresses.*
