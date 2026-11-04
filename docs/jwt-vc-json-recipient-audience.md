# Recipient-pinned VC 1.1 JWT (SDK, opt-in)

This is an **opt-in HeroSSID application profile** restricting the recipient of an issuer-signed JWT VC 1.1 using RFC 7519's registered `aud` claim. **It is not a standardized VC1.1 credential audience binding.** [VC Data Model 1.1 §6.3.1](https://www.w3.org/TR/vc-data-model-1.1/#json-web-token) assigns normative `aud` semantics to **verifiable presentations** (the verifier intended by the holder), not to issuer-signed credentials. This optional credential-level use is application-specific and cannot be advertised as standards-based third-party wallet interoperability. It is not a replacement for OpenID4VP signed requests, holder-signed presentations, revocation policy or actual user consent. Both signer and verifier must already know their trust anchors.

## Executable .NET 10 entry points

The issuer must control an Ed25519 seed corresponding to `issuerDid`. An integrating application obtains real claims and validates its issuance authority separately. The following call uses an already validated `JsonElement credentialSubject`, the corresponding holder DID and short validity timestamps:

```csharp
string jwt = JwtVcJsonCredential.CreateForAudience(
    issuerDid, holderDid, "MembershipCredential",
    new Uri("https://issuer.example/contexts/member/v1"),
    credentialSubject, issuerPrivateSeed,
    now.AddMinutes(-1), now.AddMinutes(5),
    new Uri("https://verifier.example/credential-intake"));
```

The relying party **independently configures** the trusted issuer DID, holder DID, exact type and HTTPS vocabulary, and its own exact HTTPS audience; it must NOT copy those trust decisions from the JWT.

```csharp
bool authenticatedForThisRecipient = JwtVcJsonCredential.TryVerifyForAudience(
    jwt, trustedIssuerDid, expectedHolderDid, "MembershipCredential",
    new Uri("https://issuer.example/contexts/member/v1"),
    new Uri("https://verifier.example/credential-intake"), now,
    out JsonElement verifiedSubject);
```

No subject claims are returned on failure. The ordinary `TryVerify` intentionally continues to **reject** JWTs carrying `aud`; callers must explicitly use the audience-bound API. No new HTTP endpoint, schema, persistence or release is included.

## Explicit multi-recipient issuance (SDK and authenticated HTTP)

For an issuer that intentionally wants **the same full-disclosure VC** to be usable by two to eight relying parties, `CreateForAudiencesWithMetadata` signs one original Ed25519 JWT with an RFC 7519 `aud` **array**, rather than issuing separate single-recipient credentials. Example:

```csharp
string jwt = JwtVcJsonCredential.CreateForAudiencesWithMetadata(
    issuerDid, holderDid, "MembershipCredential",
    new Uri("https://issuer.example/contexts/member/v1"),
    credentialSubject, issuerPrivateSeed,
    now.AddMinutes(-1), now.AddMinutes(5),
    [new Uri("https://verifier-a.example/intake"),
     new Uri("https://verifier-b.example/intake")],
    credentialId: null, issuerName: null, exactValidity: true);
```

The existing authenticated, tenant-owned `POST /api/v1/credentials/jwt-vc-json/issue-for-audience` also accepts `recipientAudiences` as an **exclusive alternative** to the existing singular `recipientAudience`:

```json
{
  "issuerDid": "<issuer did:key>",
  "holderDid": "<holder did:key>",
  "credentialType": "https://issuer.example/types/Membership",
  "subjectContextUri": "https://issuer.example/contexts/member/v1",
  "credentialSubject": {"membership": "active"},
  "validUntil": "2026-11-04T09:10:00Z",
  "recipientAudiences": [
    "https://verifier-a.example/intake",
    "https://verifier-b.example/intake"
  ]
}
```

The request additionally needs a genuine scoped bearer token with the tenant-owned issuer DID and any enforced per-client signing grant. Both audience fields together, neither field on the explicit route, any recipient policy on the legacy route, duplicates after URI normalization, insecure endpoints, fragments, userinfo and arrays outside the **2–8** range are rejected before signing. The independent recipient verifier and its HTTP variant already accept this signed array when the exact recipient URI, original issuer Ed25519 signature, holder, type, vocabulary and validity all match; other recipients get no claims. Existing single-audience SDK/HTTP behavior remains unchanged.

**Privacy warning:** Every included recipient can receive the *same fully disclosed* claims if the holder presents them. Multi-recipient `aud` is an issuer-signed statement of intended recipient(s), not a holder proof or consent grant. The integrating Wallet must independently obtain actual human/agent disclosure approval and sign any holder presentation. It is an **application-specific** VC-level restriction, not a claim of VC1.1-standard credential audience semantics, OpenID4VP wallet interop, revocation freshness, real identity, or business authorization.

## Verifier-owned historical/current issuer trust for recipient-bound JWTs (SDK)

A relying party accepting current and explicitly enrolled historical issuer keys can now
pin **both** its own HTTPS recipient and an independent list of up to 16
distinct valid Ed25519 `did:key` issuer DIDs. These methods do not infer
issuer trust from JWT `iss`/`kid`, and do not accept an `aud` token through
the pre-existing audience-free `Check` methods:

```csharp
JwtVcJsonTrustedIssuerCheckResult result =
    JwtVcJsonTrustedIssuerVerifier.CheckForAudience(
        jwt, trustedIssuerDids, expectedHolderDid,
        "https://issuer.example/credentials#Membership",
        new Uri("https://issuer.example/contexts/member/v1"),
        new Uri("https://verifier-a.example/intake"), now,
        out string verifiedIssuerDid, out JsonElement verifiedSubject);
```

`trustedIssuerDids`, recipient, type, vocabulary and holder identity all
come from **independent verifier policy**. `SignedButStatusUnchecked` means
the original JWT genuinely verifies under those pins. It is **not** a
holder-private-key proof, a real identity check or a revocation result.

When a verifier also has the **original signer's own** recent private
revocation snapshot, use `CheckForAudienceWithStatus(jwt, snapshot,
trustedIssuerDids, expectedHolderDid, type, context, recipient, now,
out issuer, out subject)`. For post-incident use, the separate
`CheckForAudienceWithStatusAfterObservationCutoff` adds a verifier-owned
`minimumObservedAt` immediately after `now`. A foreign issuer's status,
expired/stale status, incident-preceding observation, wrong audience, invalid
JWT signature or removed issuer pin cannot release issuer or subject outputs.
`SignedNotListed` assumes an independently established complete status
inventory and is never live non-revocation assurance.

These opt-in .NET SDK methods do **not** add a non-.NET HTTP variant; the
existing authenticated historical-issuer HTTP routes still reject
audience-bound JWTs rather than implicitly bypass the recipient policy.
Issuance remains the responsibility of the real issuer; the Wallet may hold
and present but cannot convert these claims into human consent or business
authorization. No independent third-party Wallet interoperability is claimed.

## Signed wire profile and independent tests

* Standard VC 1.1 `typ=JWT` (or absent `typ` on independently signed JWTs), Ed25519 `alg=EdDSA`; independently pinned issuer and holder `did:key`, HTTPS vocabulary and credential type; max 15-minute validity as elsewhere in the opt-in VC1.1 SDK.
* The signed `aud` is one canonical absolute HTTPS URI string or an RFC 7519 audience array with **1–8 distinct** canonical HTTPS URI strings. HTTPS, nonempty host, no userinfo/fragment and size bound are deliberate restrictions of this SDK profile, not a claim that arbitrary RFC 7519 JWTs are invalid.
* Verification requires an **exact ordinal match** to the relying party's independently configured HTTPS URI. Any malformed, duplicate, excessive or noncanonical array member rejects the complete credential even if another member matches.
* Genuine external NSec Ed25519 signing is exercised independently of the HeroSSID issuer serializer in `JwtVcJsonAudienceBoundaryTests`, including both audience forms, false audience, false issuer/holder, timestamp, malformed audience, and tampered signature. These are SDK tests, **not** independent third-party wallet interoperability or conformance certification.
* Issuer-signed, short-lived private revocation snapshots can still authenticate and hash the **original** audience-bound JWT. The snapshot checks signer and digest, **not** whether a particular verifier is an authorized audience; check the exact independently pinned audience and other credential policy separately. A signed absence does not establish complete/live non-revocation.
* Existing audience-free multi-issuer methods and the authenticated multi-issuer HTTP routes continue to **reject** `aud` credentials. The new explicit .NET SDK historical issuer audience methods require the relying party's own recipient URI and original signer status policy; there is no silent upgrade or HTTP bypass.

The issuer's signature proves a statement by a key. `aud` expresses *intended recipient* only. Neither is a proof of the recipient's legal identity, holder key control, end-user consent, a person's identity, an organisation's rights or an Agent's delegated business authorization.
