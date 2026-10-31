# VC1.1 verifier-owned emergency denylist (opt-in .NET 10 SDK)

**Problem:** An issuer's private signed revocation snapshot is not necessarily an independent source of truth. A stolen/retired Ed25519 signing key can sign a misleading clean status snapshot, and an issuer may be unreachable during an incident. The receiving verifier sometimes needs an immediate, independently controlled decision to **deny a specific previously issued VC1.1 `jwt_vc_json` token**, even if that token still has a valid genuine issuer signature and a separate retirement pin.

`JwtVcJsonVerifierDenylist.Check` and `CheckWithStatus` implement this verifier-local safety boundary. This is **not** an extension of the JWT wire format or a standard status registry.

## Executable SDK entry point

```csharp
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.JwtVcJson;

// An incident-response inventory controlled by the verifier, not supplied
// as self-service proof by the wallet or credential issuer.
string exactCompromisedJwt = previouslyVerifiedOriginalCompactJwt;
string deniedSha256 = Convert.ToHexStringLower(
    SHA256.HashData(Encoding.UTF8.GetBytes(exactCompromisedJwt)));

// Existing independently approved active DID set, and separately enrolled
// exact original-JWT retirement pins. Either collection may be empty, but
// the combined issuer trust policy must contain an eligible issuer.
JwtVcJsonVerifierPolicyResult result = JwtVcJsonVerifierDenylist.Check(
    submittedOriginalCompactJwt,
    [approvedCurrentIssuerDid],
    retiredCredentialPins,
    [deniedSha256],
    expectedHolderDid,
    "https://issuer.example/credentials#Membership",
    new Uri("https://issuer.example/contexts/membership/v1"),
    DateTimeOffset.UtcNow,
    out string authenticatedIssuer,
    out var authenticatedSubject);

if (result is not JwtVcJsonVerifierPolicyResult.SignedButStatusUnchecked)
{
    // Invalid, DeniedByVerifier or any other failure: do not release claims.
    return;
}

// The real issuer signature and verifier's local policy passed.
// Still require holder-key control, user consent, independent status policy
// and application-specific business authorization where relevant.
```

Call `CheckWithStatus` instead to also require the **actual original issuer** to have signed a valid private 60-second revocation snapshot. It returns `SignedNotListed` only when that signed snapshot does not list the token; that result does **not** prove a live/complete source of non-revocation. An authenticated revoked snapshot returns `IssuerReportedRevoked`, not `DeniedByVerifier`. A locally denied exact JWT is `DeniedByVerifier`, including when its issuer's snapshot is otherwise clean.

## Acceptance and security boundaries

- Every active/retired issuer policy, original JWT signature, expected holder DID, expanded HTTPS credential type and vocabulary, validity/expiry, and (if required) same-issuer status must authenticate **before a local denial decision can be reported as such**. An untrusted or expired token cannot use a digest match to masquerade as a real revoked issuer credential.
- The verifier configures up to **256** canonical lowercase SHA-256 hex digests for **exact original UTF-8 compact signed JWT strings**. All entries, even entries *after* an exact match, must be valid and unique. Uppercase, duplicate, malformed and oversized configurations fail closed with `Invalid`.
- A separate retirement pin for a genuine old credential cannot bypass a matching emergency deny. A clean issuer snapshot cannot bypass a matching verifier deny. A similar claim set, newly signed JWT or a different signature has a different digest and does not inherit the local deny.
- No authenticated issuer name or credential subject is returned on `Invalid`, `DeniedByVerifier` or `IssuerReportedRevoked`. A valid non-denied JWT can return its verified issuer/subject only on `SignedButStatusUnchecked` or `SignedNotListed`.
- Local denylist membership is **not** a cryptographic proof of theft, registry completeness, prior enrollment timing, official issuer revocation, holder private-key control or real identity. A clean local list also is **not proof of non-revocation**. Verifier administrators need a trusted incident intake and distribution path, and must persist/synchronize policy themselves across instances.
- These are full-disclosure VC1.1 issuer-JWT verifier decisions, not a holder Wallet, consent UI, hosted HTTP route, DB migration, credential revocation endpoint, OpenID4VCI/OpenID4VP conformance or independent third-party Wallet interoperability.

## Real negative/positive xUnit regression

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj \
  --configuration Release \
  --filter FullyQualifiedName~JwtVcJsonVerifierDenylistTests
```

The tests use separate real Ed25519 current, retired, outsider and holder keys, rather than accepting test-only cryptographic stubs. They exercise successful original signature verification and unchanged claims when allowed, emergency denial of both active and exact-pinned retired JWTs, status precedence, forged/untrusted/wrong-holder/expired rejection, malformed and duplicate policy fail-closed behavior and exact byte-level hash matching. The complete CI workflow remains authoritative for full Build/Test/Security evidence. No claim of an external security audit is made.

Related: [VC1.1 exact retirement pins](jwt-vc-json-retired-issuer-exact-pins.md), [VC1.1 trusted issuer verifier](jwt-vc-json-offline-trusted-issuer-profile.md), [HeroSSID vision](VISION.md).
