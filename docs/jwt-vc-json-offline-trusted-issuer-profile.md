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

A relying party can reject credentials signed by a retired issuer simply by removing its DID from the independently maintained trust list. No credential is re-signed or reissued by HeroSSID. The verifier checks all trust pins (including duplicates, malformed and oversized lists) before examining any credential and does **not** trust the original JWT's unverified `iss` or `kid`. The inherited strict VC1.1 verifier checks a genuine Ed25519 issuer signature under each independently trusted `did:key`; an **explicit** `kid` must match that DID exactly, while W3C VC1.1 `typ=JWT` may omit optional `kid` without selecting or changing the trust key. Legacy `vc+jwt` still requires exact `kid`. Holder subject binding, pinned type/context, time bounds, JSON property uniqueness and the original nested `vc.@context` profile remain enforced.

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

For an incident response, the offline caller can use
`JwtVcJsonTrustedIssuerVerifier.CheckWithStatusAfterObservationCutoff`
with an independently chosen `minimumObservedAt` after the `now` argument,
or `JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff` for raw
issuer-signed status checks. Both reject an authentic pre-cutoff
60-second snapshot; the issuer's signed `iat` has **whole-second** precision,
so a fractional cutoff cannot be rounded back to accept earlier state.
Invalid/revoked results release no authenticated signer or subject.
The cutoff is verifier-supplied policy; neither signature nor `iat` proves
the completeness or actual observation time of upstream status records.
See [the authenticated HTTP cutoff contract](jwt-vc-json-http-verify-profile.md#verifier-owned-post-incident-observation-cutoff-opt-in).

## Authenticated HTTP: verified original-signer metadata

The four authenticated `credential:verify` multi-issuer routes
(`verify-trusted-issuers` and `verify-trusted-issuers-for-audience`,
each with optional `-with-status`) now return signed
`verifiedCredentialId`, descriptive `verifiedIssuerName`,
`verifiedNotBefore` and `verifiedExpiresAt` on successful verification.
The authenticated issuer DID, verified subject and status are unchanged.
Missing signed optional fields return JSON `null`; validity preserves
the exact JWT `nbf`/`exp` at 100ns precision for downstream cache limits.

All metadata is rechecked against the original Ed25519 signature and the
**actual** independently trusted signer. Audience-bearing JWTs must also
match the relying party's separately pinned HTTPS recipient. The
`-with-status` routes release these fields **only after** valid
original-signer signed status; invalid, revoked, stale, forged, wrong
recipient and untrusted inputs disclose no subject, issuer or metadata.
`SignedButStatusUnchecked` does not check revocation and
`SignedNotListed` is not proof of live, complete status.

An issuer-signed name is descriptive, not a verified legal identity.
A JWT signature is not holder-key control, consent, Agent delegation or
business authorization. Internal HTTP contract tests are not third-party
wallet interoperation or general VC/OpenID4VP certification.

No schema, database operation, remote resolution, enrollment, production deployment or package publication is performed by these SDK calls. See the [VC1.1 JWT credential format](jwt-vc-json-profile.md), [HTTP equivalent](jwt-vc-json-http-verify-profile.md) and [project vision](VISION.md).
