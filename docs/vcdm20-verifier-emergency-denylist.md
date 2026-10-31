# Opt-in direct VC2 verifier-owned exact-JWT emergency denial

The .NET 10 `Vcdm20VerifierDenylist` library allows an **independent relying party** to reject the exact original compact direct VC Data Model 2.0 JOSE JWT after authenticating its original Ed25519 issuer. This is an opt-in, offline local policy, not an issuer revocation registry, a W3C Bitstring Status List, an OpenID4VP wallet protocol, or production key recovery.

## Safe verifier-side example

The verifier must obtain issuer DID pins, original JWT fingerprints, expected holder DID, credential type and HTTPS vocabulary **from its own trusted policy**, never from an unverified JWT or wallet response. A canonical digest is exactly 64 **lowercase hexadecimal** SHA-256 characters of the UTF-8 bytes of the **original compact signed JWT string**.

```csharp
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.Vcdm20;

string digest = Convert.ToHexStringLower(
    SHA256.HashData(Encoding.UTF8.GetBytes(originalIssuerSignedJwt)));

// The verifier securely persists and distributes this entry only after its
// independent emergency-denial decision; user-provided digests are untrusted.
IReadOnlyCollection<string> denied = [digest];

Vcdm20VerifierPolicyResult result = Vcdm20VerifierDenylist.Check(
    candidateOriginalJwt, verifierPinnedIssuerDids, denied,
    expectedHolderDid, expectedCredentialType, expectedHttpsContext,
    TimeProvider.System.GetUtcNow(), out string actualIssuerDid,
    out var verifiedSubject);
```

A result of `DeniedByVerifier` means this authentic, otherwise matching signed JWT was blocked locally, with **empty issuer and undisclosed subject**. `Invalid` means the JWT, independent issuer pins, holder/type/context/expiry or denial policy failed validation. `SignedButStatusUnchecked` returns the *actual verified issuer* and claims only after all checks, but **does not indicate credential status**.

For issuer-provided short-lived status, `CheckWithStatus` takes an additional original issuer-signed `herossid-vc2-revocation-snapshot+jwt`. It requires the signature of the **actual authenticated issuer** of the original VC2 JWT, not merely any DID in the trusted issuer list. A verified issuer-revoked JWT returns `IssuerReportedRevoked`; a locally denied JWT with otherwise clean signed status returns `DeniedByVerifier`. Either rejection exposes no issuer or subject. An authentic missing entry yields `SignedNotListed` **only for the issuer-supplied set at observation time**, not a proof of its completeness or current non-revocation.

## Security boundaries and limitations

- The independent verifier accepts up to **16** individually pinned valid Ed25519 issuer `did:key` values and **256** unique canonical exact-JWT SHA-256 denials. Any duplicate, malformed, uppercase or oversized denial list fails closed. A removed issuer DID is untrusted regardless of the denial list; the issuer JWT's own header cannot elevate trust.
- Denial must be managed and synchronized by the verifier. The library does **not** provide a shared registry, durable storage, issuer notification, time-of-compromise proof, automatic issuer key succession, or live revocation.
- A genuine issuer statement is **not** holder private-key control, real-world identity verification, user consent or business authorization. Wallet consent and independently verified holder-signed presentations remain separate requirements. Local SDK tests do **not** prove third-party wallet interoperability or formal VC2 conformance.

Run `dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj --configuration Release`; authoritative full build, test, dependency security and CodeQL evidence is on the exact PR and main GitHub Actions runs.
