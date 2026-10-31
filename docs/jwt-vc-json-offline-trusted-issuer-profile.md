# Offline historical/current VC 1.1 issuer verification (opt-in)

`JwtVcJsonTrustedIssuerVerifier` provides an **offline .NET 10 API** for a relying party to verify the *original* W3C VC Data Model 1.1 `jwt_vc_json` issuer signature with a verifier-owned set of 1–16 independently enrolled current or historical Ed25519 `did:key` issuer DIDs. This is a bounded HeroSSID SDK profile, not issuer discovery, automatic key-successor trust, standard credentialStatus, independent third-party wallet interoperability or proof of authority.

## Concrete SDK call

```csharp
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;

// Both keys were independently enrolled by this verifier, NOT read from jwt.
string[] issuerTrust = [previousIssuerDid, currentIssuerDid];
Uri vocabulary = new("https://example.org/contexts/membership/v1");
DateTimeOffset now = DateTimeOffset.UtcNow;
var result = JwtVcJsonTrustedIssuerVerifier.Check(
    originalIssuerSignedJwt, issuerTrust, expectedHolderDid,
    "https://example.org/credentials#Member", vocabulary, now,
    out string actualIssuerDid, out JsonElement subject);
if (result != JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked)
{
    // Do not consume subject; the output is undefined on failure.
    throw new InvalidOperationException("Issuer credential rejected");
}

// actualIssuerDid identifies the authentically verified signer, but does not
// prove holder private-key control, legal identity or business authorization.
```

A relying party can reject credentials signed by a retired issuer simply by removing its DID from the independently maintained trust list. No credential is re-signed or reissued by HeroSSID. The verifier checks all trust pins (including duplicates, malformed and oversized lists) before examining any credential and does **not** trust the original JWT's unverified `iss` or `kid`. The inherited strict VC1.1 verifier checks real Ed25519 signature, exact `kid`, holder subject binding, pinned type/context, time bounds, JSON property uniqueness and the original nested `vc.@context` profile.

## Optional issuer status from the actual signer

If a relying party has separately obtained an issuer-provided **authoritative and complete** private 60-second revocation export, use:

```csharp
var status = JwtVcJsonTrustedIssuerVerifier.CheckWithStatus(
    originalIssuerSignedJwt, originalRevocationSnapshotJwt,
    issuerTrust, expectedHolderDid,
    "https://example.org/credentials#Member", vocabulary, now,
    out string actualSigner, out JsonElement verifiedSubject);
if (status != JwtVcJsonTrustedIssuerCheckResult.SignedNotListed)
{
    // Do not read actualSigner or verifiedSubject on rejection.
    throw new InvalidOperationException("Credential or status rejected");
}
```

The status is verified against the **actual cryptographic issuer of the original credential**, not any other allowed issuer. The four distinct outcomes are:

- `Invalid`: malformed, untrusted, wrongly signed, expired or policy-mismatched credential/status; **no signer or subject disclosure**.
- `Revoked`: valid issuer credential listed in a genuine, same-signer snapshot; **no signer or subject disclosure**.
- `SignedButStatusUnchecked`: original issuer signature and pinned policy pass, **without revocation checking** (only `Check`).
- `SignedNotListed`: original issuer signature and a fresh, same-signer private status pass, and its exact digest was not listed (only `CheckWithStatus`).

`SignedNotListed` is not independently verified completeness or live non-revocation. The SDK neither downloads status nor verifies the issuer's reporting completeness. A signature proves only the issuer's key control; separate, holder-signed one-use presentations and genuine disclosure consent are required for holder control, while identity vetting, organisational role and Agent business authorization are relying-party decisions.

No schema, database operation, remote resolution, enrollment, production deployment or package publication is performed by these SDK calls. See the [VC1.1 JWT credential format](jwt-vc-json-profile.md), [HTTP equivalent](jwt-vc-json-http-verify-profile.md) and [project vision](VISION.md).
