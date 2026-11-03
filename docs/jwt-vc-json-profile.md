# Opt-in JWT VC JSON (VC Data Model 1.1) credential profile

Reference: [OpenID4VP 1.0 Final, Appendix B.1.3.1, 9 July 2025](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-vc-signed-as-a-jwt-not-usi), and [W3C VC Data Model v1.1 Recommendation §6.3.1 (9 November 2021)](https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#jwt-encoding).

This is a **real issuer-signed JWT VC 1.1 credential** intended for the OpenID4VP format identifier **`jwt_vc_json`**. It is not the separate opt-in **VC 2.0 direct JOSE** profile (`Vcdm20JoseCredential`) and is not the existing HeroSSID legacy `vc.context` format. They cannot be silently substituted. The OpenID4VP 1.0 final specification's `jwt_vc_json` example uses a nested `vc.@context`, JWT `iss`/`sub`/`nbf` and a holder-signed VP. The old HeroSSID-issued `vc.context` is **not** that wire format.

## SDK contract

`HeroSSID.Credentials.JwtVcJson.JwtVcJsonCredential.Create(issuerDid, holderDid, credentialType, subjectContextUri, credentialSubject, issuerSeed, validFrom, validUntil)` creates a compact JWT with:

- Ed25519 JWS `alg=EdDSA`, W3C VC1.1 `typ=JWT`, and the exact `did:key` verification-method `kid` (VC1.1 §6.3.1 requires `JWT` when `typ` is present);
- signed `iss` as the issuer DID; `sub` as the holder DID; integer-second `iat=nbf` and `exp`;
- signed `vc.@context=["https://www.w3.org/2018/credentials/v1", pinnedVersionedHttpsVocabulary]` (not `vc.context`), `vc.type=["VerifiableCredential", expectedType]` and `vc.credentialSubject.id=holderDid`;
- a **15-minute maximum** encoded validity interval, a bounded subject and a bounded JWT. Normal `DateTimeOffset` fractional-second arguments are accepted: `iat` and `nbf` round **up** to the next whole second, and `exp` rounds **down**, so the JWT cannot be valid before the requested start or at/after the requested end. An interval that becomes empty, or exceeds 900 encoded seconds, is rejected. Near-second boundaries can shorten the usable interval by up to almost two seconds.

An independent verifier calls `JwtVcJsonCredential.TryVerify(jwt, trustedIssuerDid, expectedHolderDid, expectedCredentialType, expectedSubjectContextUri, clock, out claims)`. All policy parameters must be independently configured: **never use the credential's claimed issuer as its own trust anchor**. It checks the genuine Ed25519 signature under the **independently pinned issuer `did:key`**, and an exact matching `kid` **when present**, together with the bounded, unambiguous nested JSON structure, the expected holder/type/context, `nbf` and `exp` before returning any subject claims. Tampered, foreign, expired, premature, legacy/private and VC2-direct tokens fail closed. It does not network-fetch an arbitrary `@context` and does not perform JSON-LD expansion or semantic validation of the custom vocabulary; the relying party must have reviewed/pinned the specified context and vocabulary.

## Preventing subject-level vocabulary shadowing

The opt-in pinned-vocabulary `jwt_vc_json` profile rejects **all**
`@context` members inside `vc.credentialSubject`, including in nested
objects and arrays. Otherwise, JSON-LD local contexts could redefine a
signed claim without altering the exact, verifier-pinned outer
`vc.@context`. Issuance rejects these inputs and verification withholds
claims even when the issuer signature is genuine. Ordinary nested subject
data without contexts remains accepted.

This is a deliberate restriction of HeroSSID's **plain-JSON** profile,
not a claim that the W3C VC data model forbids scoped JSON-LD contexts.
General JSON-LD consumers that require such contexts need their own
validated semantic profile and trust policy. HeroSSID does not dereference,
integrity-protect, or expand even the pinned HTTPS vocabulary URI.

## Externally serialized VC1.1 JWTs (bounded verifier subset)

A verifier can now accept a **separately encoded and genuinely issuer-signed**
VC1.1 `jwt_vc_json` with an optional credential identifier in JWT `jti`,
even when JWT `iat` is absent. This is consistent with the
[OpenID4VP 1.0 final Appendix B.1.3.1 example](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-vc-signed-as-a-jwt-not-usi)
and the [W3C VC1.1 JWT mapping](https://www.w3.org/TR/vc-data-model/#jwt-encoding).
If `iat` is present it may precede `nbf` by up to 15 minutes; the
credential's actual validity remains controlled by signed `nbf` and `exp`
with a maximum 15-minute interval.

This remains a **deliberately constrained, fail-closed verifier**, not general
JWT-VC conformance. It accepts genuine W3C VC1.1 `typ=JWT` signed by the pinned
Ed25519 issuer and keeps older HeroSSID `typ=vc+jwt` JWTs valid as **legacy
inputs**; that older header is not represented as conforming to VC1.1 §6.3.1.
This is a deliberate on-wire change to new `Create` output: integrations
hardcoded to `typ=vc+jwt` must update their verifiers. `typ=vp+jwt`, arbitrary
types, **wrong explicit** DID key IDs and forged or foreign signatures remain rejected. For a W3C VC1.1 `typ=JWT` only, the Recommendation makes `kid` optional: a JWT omitting it is verified against the verifier's independently pinned Ed25519 `did:key`, **never** a key selected by token contents. Legacy `typ=vc+jwt` still requires exact `kid`. Optional `jti` must be a bounded absolute HTTPS URI without
userinfo and is not fetched or treated as issuer trust, holder-key proof,
identity, authorization or evidence of historical issuance. Every other
JWT payload member outside the five required fields and the optional
`iat`/`jti` remains rejected, as do untrusted issuers, altered JWTs, ambiguous
JSON properties, non-pinned vocabularies, premature/expired claims and
noncanonical Ed25519 JWS. Issuance by `Create` continues to produce the
original six-field bounded representation without `jti`; existing tokens
retain their verification result.

The real xUnit `JwtVcJsonCredentialTests` constructs its own JSON JWT
payload and compact JWS with NSec rather than calling the HeroSSID credential
issuer or signing helper. It verifies the standard optional-field variants and
negative signature/trust/id/timing cases. This **does not constitute an
independent third-party issuer, Wallet or OpenID4VP exchange test**.

## Example

```csharp
using HeroSSID.Credentials.JwtVcJson;
using System.Text.Json;
// issuerDid, holderDid, issuerSeed and trustedIssuerDid/expectedHolderDid
// are separately provisioned values; never derive verifier trust from jwt.

// Issuer: own, protect and clear issuerSeed; holderDid belongs to the recipient.
using var document = JsonDocument.Parse(JsonSerializer.Serialize(new
{
    id = holderDid, membership = "active"
}));
var vocabulary = new Uri("https://issuer.example/contexts/membership/v1");
// Supply a real holder did:key and an independently configured issuer key.
var now = DateTimeOffset.UtcNow;
string jwt = JwtVcJsonCredential.Create(
    issuerDid, holderDid, "MembershipCredential", vocabulary,
    document.RootElement, issuerSeed, now.AddSeconds(-1), now.AddMinutes(10));

// Verifier: issuerDid, holderDid, type and vocabulary are independently pinned.
bool issuerStatementVerified = JwtVcJsonCredential.TryVerify(
    jwt, trustedIssuerDid, expectedHolderDid, "MembershipCredential",
    vocabulary, DateTimeOffset.UtcNow, out JsonElement claims);
```

The `jwt_vc_json` format identifier is standardized by OpenID4VP, **but this SDK only creates and verifies its bounded credential representation**. The existing `OpenId4VpDirectPost` flow still advertises **`herossid_vc_jwt`**, not `jwt_vc_json`: do **not** claim that the current protocol adapter supports this format or that an independent third-party wallet has exchanged it. The existing HeroSSID legacy presentation creator and verifier **do not accept this JWT credential profile** (their private legacy JWT contract differs). The separate opt-in [JwtVcJsonPresentation nested holder-signed VP](jwt-vc-json-presentation-profile.md) now demonstrates real issuer and holder Ed25519 signatures and atomic one-use challenge checking through HeroSSID's **private signed verifier-request profile**; it does **not** enable the existing OpenID4VP adapter, standard signed authorization requests/DCQL, third-party wallet exchange, revocation or human consent UI. A genuine independent wallet integration remains necessary before claiming OpenID4VP `jwt_vc_json` interoperability.

**Trust boundaries:** An issuer signature is an issuer statement, not proof of holder-key control or consent. No holder private key is escrowed, no human identity is verified, no authorization is granted, and `TryVerify` does not consult a revocation registry. A relying party requiring holder control must separately verify a one-time holder-signed presentation. For credential validity or authorization, require independently trusted issuer and status policies. There is no new HTTP route, schema, database write, migration, hosted wallet, deployment or production attestation in this library-only feature.
