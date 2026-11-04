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

## Signed wire profile and independent tests

* Standard VC 1.1 `typ=JWT` (or absent `typ` on independently signed JWTs), Ed25519 `alg=EdDSA`; independently pinned issuer and holder `did:key`, HTTPS vocabulary and credential type; max 15-minute validity as elsewhere in the opt-in VC1.1 SDK.
* The signed `aud` is one canonical absolute HTTPS URI string or an RFC 7519 audience array with **1–8 distinct** canonical HTTPS URI strings. HTTPS, nonempty host, no userinfo/fragment and size bound are deliberate restrictions of this SDK profile, not a claim that arbitrary RFC 7519 JWTs are invalid.
* Verification requires an **exact ordinal match** to the relying party's independently configured HTTPS URI. Any malformed, duplicate, excessive or noncanonical array member rejects the complete credential even if another member matches.
* Genuine external NSec Ed25519 signing is exercised independently of the HeroSSID issuer serializer in `JwtVcJsonAudienceBoundaryTests`, including both audience forms, false audience, false issuer/holder, timestamp, malformed audience, and tampered signature. These are SDK tests, **not** independent third-party wallet interoperability or conformance certification.
* Issuer-signed, short-lived private revocation snapshots can still authenticate and hash the **original** audience-bound JWT. The snapshot checks signer and digest, **not** whether a particular verifier is an authorized audience; check the exact independently pinned audience and other credential policy separately. A signed absence does not establish complete/live non-revocation.
* Existing multi-issuer and HTTP verification routes do **not** automatically accept `aud` credentials; they remain fail-closed. Callers may compose the explicit SDK audience verification with their own enrolled issuer policy and revocation decision.

The issuer's signature proves a statement by a key. `aud` expresses *intended recipient* only. Neither is a proof of the recipient's legal identity, holder key control, end-user consent, a person's identity, an organisation's rights or an Agent's delegated business authorization.
