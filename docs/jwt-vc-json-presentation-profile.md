# Opt-in JWT VC 1.1 holder-signed nested presentation

References: [OpenID4VP 1.0 Final, Appendix B.1.3.1.5 (9 July 2025)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-presentation-response) and [W3C Verifiable Credentials Data Model 1.1](https://www.w3.org/TR/vc-data-model/). See the [original credential profile](jwt-vc-json-profile.md).

## What works

The `JwtVcJsonPresentation` SDK provides **full-disclosure** holder signing of exactly one unchanged, issuer-signed VC Data Model 1.1 `jwt_vc_json` JWT, and independent verification of both real Ed25519 signatures. The output has JOSE `alg=EdDSA`, `typ=vp+jwt` and the holder's exact self-certifying `did:key` verification-method `kid`. The signed payload contains the holder `iss`, verifier `aud`, fresh `nonce`, `iat`, `nbf`, `exp`, and nested:

```json
{
  "vp": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiablePresentation"],
    "verifiableCredential": ["<unchanged issuer-signed jwt_vc_json compact JWS>"]
  }
}
```

The holder signs **only after** its application checks an existing `herossid-request+jwt` from the verifier's separate `did:key`, its independently pinned expected verifier identity and audience, and the enclosed VC's *actual original issuer* signature with the request's trusted issuer. The invoking wallet/app **must display the disclosed information and obtain consent itself**; this SDK does not record human consent. It never signs an issuer assertion with a holder key to compensate for a missing issuer signature.

The verifier first uses `IPresentationChallengeStore.Find` to load its own tenant-bound, audience-bound, issuer-pinned, unexpired challenge. It validates the holder signature, embedded issuer signature, exact original subject `id`, context, credential type, timestamps, nonce and audience before invoking `TryConsume` to **atomically** spend that challenge. Signed subject claims are released only on `SignedButStatusUnchecked`. Failed/expired/forged/wrong-tenant/replayed proofs return `Invalid` and no claims. Check timing is repeated after a potentially blocking consume.

A standalone C# verifier may use `InMemoryPresentationChallengeStore(TimeProvider.System)` as a **singleton for one process**. Multiple HTTP replicas **must** share a durable, atomic challenge store such as the already-implemented PostgreSQL one. This feature does not change or migrate the database.

## C# flow

```csharp
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;

// Provision all four Ed25519 did:key identities and seeds independently.
// In a real wallet, show the whole credential to the human and obtain consent
// before calling Create; never derive the verifier DID/audience from JWT input.
var clock = TimeProvider.System;
var store = new InMemoryPresentationChallengeStore(clock);
var tenant = Guid.NewGuid(); // verifier's authenticated tenant identifier
var audience = "decentralized_identifier:" + verifierDid;
var challenge = store.Issue(tenant, audience, trustedIssuerDid);
var request = OfflineSignedPresentationRequest.Create(challenge, verifierDid, verifierSeed, clock);

// The unchanged VC was signed independently by issuerSeed using
// JwtVcJsonCredential.Create and belongs to holderDid.
string vpJwt = JwtVcJsonPresentation.Create(
    request, verifierDid, audience, issuerSignedCredentialJwt,
    "MembershipCredential", new Uri("https://issuer.example/contexts/membership/v1"),
    holderDid, holderSeed, clock);

var result = JwtVcJsonPresentation.Check(
    vpJwt, tenant, audience, challenge.Nonce,
    "MembershipCredential", new Uri("https://issuer.example/contexts/membership/v1"),
    store, clock, out var verifiedSubject);
if (result == JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked)
{
    // Issuer statement + holder signature + single-use challenge only.
    // Require independent status and business authorization before acting.
}
```

## Precise interoperability and trust limits

- **This is not yet an OpenID4VP exchange.** The signed verifier request is the private `herossid-request+jwt`, **not** a standard OpenID4VP Authorization Request Object with DCQL `format=jwt_vc_json` or a hosted `direct_post` callback. It is not supported by the existing `OpenId4VpDirectPost` adapter, whose format is still `herossid_vc_jwt`.
- The *VP's nested JWT shape* is modeled on OpenID4VP 1.0 Final Appendix B.1.3.1.5. Only HeroSSID-side issuer, holder and verifier tests have been executed. There is **no independently demonstrated third-party wallet interoperation, standards certification, JSON-LD expansion or external security audit**.
- Each `jwt_vc_json` is checked against a **separately selected trusted issuer DID, holder DID, exact credential type and versioned HTTPS subject vocabulary**. No context is downloaded by the library. Signed `iss`, `kid` or self-declared vocabulary cannot confer trust by themselves.
- Exactly one credential is presented in full. There is **no selective disclosure**, no credential-status list, no live revocation query, no issuer identity vetting, no account enrollment proof and no automatic business or agent delegation authorization.
- `SignedButStatusUnchecked` is intentionally **not** `Valid`, `Active`, `Unrevoked` or `Authorized`. A verifier needs independent issuer policy, freshness/status policy, holder consent and application authorization.

No new HTTP endpoint, schema change, deployment, NuGet package publication, production key use or migration is part of this opt-in library feature.
