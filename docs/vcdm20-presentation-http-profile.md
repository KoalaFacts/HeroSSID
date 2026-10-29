# Authenticated VC2 holder presentation over HTTP (opt-in)

This opt-in REST adapter exposes the **existing .NET 10** holder-signed VC2 JWT proof and issuer-signed status verification to an authenticated non-.NET verifier. It is not an OpenID4VP endpoint, wallet, identity proofing process, W3C status-list implementation or business authorization system. It requires the already-existing `presentation_challenges` PostgreSQL migration, with **no new schema in this change**.

## 1. Verifier retains its own trust decision and challenge

An OAuth client bearing an unambiguous validated tenant and `credential:verify` scope submits:

```http
POST /api/v1/credentials/vcdm20/presentation-challenge
Authorization: Bearer <verifier-access-token>
Content-Type: application/json
```

```json
{
  "audience": "https://verifier.example/present",
  "trustedIssuerDid": "did:key:<independently-pinned-issuer>",
  "lifetimeSeconds": 120
}
```

The response is **201** and includes `audience`, cryptographically random `nonce`, `trustedIssuerDid` and `expiresAt`. The challenge is owned by the authenticated tenant; the audience must be an exact HTTPS URL, issuer a valid Ed25519 `did:key`, lifetime 1–300 seconds. Only the verifier chooses which issuer it trusts; an issuer DID merely supplied by the holder cannot establish issuer trust. Malformed input is **400**; exceeded retained challenge capacity is **429**; a database availability failure is **503**.

**Signing requirement:** The challenge response itself is not a signed verifier request. A verifier with a distinct self-held Ed25519 signing seed and an independently known verifier DID uses `OfflineSignedPresentationRequest.Create(challenge, verifierDid, verifierPrivateKey, clock)` to sign the exact challenge. Never send the seed to the HeroSSID HTTP API. The holder must already pin that verifier DID and exact audience by its own trusted channel; DID information inside the request is not sufficient.

## 2. Holder independently authenticates the request and chooses disclosure

The holder app uses `OfflineSignedPresentationRequest.TryRead(requestJwt, pinnedVerifierDid, exactAudience, clock, out challenge)` to authenticate the real verifier signature and request expiry. It must display **all claims** and the destination, obtain affirmative full-disclosure consent and allow refusal before signing. After consent, `Vcdm20JosePresentation.Create(requestJwt, pinnedVerifierDid, exactAudience, issuerSignedCredential, expectedCredentialType, expectedHttpsContext, holderDid, holderOwnedSeed, clock)` creates a real holder-signed `vp+jwt` envelope preserving the original issuer-signed VC2 JWT. The issuer and holder keys remain independent.

The issuer separately signs a **complete** status snapshot using `Vcdm20RevocationSnapshot.Create`, based on its authoritative revocation data, with observation time recorded before any potentially slow status read. The present `/vcdm20/issue` HTTP endpoint **does not persist or revoke** short-lived VC2 credentials. HeroSSID does not publish VC2 snapshots automatically. No wallet UI, consent record, issuer status registry or hosted verifier signing endpoint is supplied here.

## 3. Verifier submits the proof and issuer snapshot

```http
POST /api/v1/credentials/vcdm20/verify-presentation
Authorization: Bearer <verifier-access-token>
Content-Type: application/json
```

```json
{
  "presentation": "<holder-signed-vp+jwt>",
  "revocationSnapshot": "<real-issuer-signed-HeroSSID-VC2-snapshot+jwt>",
  "audience": "https://verifier.example/present",
  "nonce": "<verifier-issued-one-use-nonce>",
  "expectedCredentialType": "MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1"
}
```

The **200** response returns one of:

- `{"status":"SignedNotListed","verifiedSubject":{...}}` only after holder and issuer Ed25519 checks, exact trusted issuer and type/context policy, unexpired challenge and signed status, and atomic nonce consumption.
- `{"status":"Revoked","verifiedSubject":null}` when the exact contained credential is listed in an authentic unexpired issuer snapshot.
- `{"status":"Invalid","verifiedSubject":null}` for spoofed, stale, cross-tenant, wrong-context, mismatched, replayed, unauthentic or otherwise invalid proof.

A presentation that reaches challenge consumption spends that nonce even if the status check is later rejected. The caller must never infer a successful identity enrollment or business permission from `SignedNotListed`. Invalid request shape is **400**, missing authorization **401**, wrong scope **403**, challenge-store unavailability **503**. HTTP payloads and lifetimes are bounded. The caller supplies type and context under its own authenticated verifier policy; do **not** derive these from the untrusted JWT.

## Distributed safety and limits

The API registers `PostgresPresentationChallengeStore` for every instance through the same configured PostgreSQL connection. It atomically consumes a challenge once across replicas and retains replay tombstones until expiry. Existing migration is required but is **not applied in production** by this change. The development-only in-memory store is suitable only for isolated SDK tests. If PostgreSQL is unavailable, verification fails closed.

The issuer-signed snapshot covers a maximum of 256 revoked JWT digests and expires no later than 60 seconds from observed status. `SignedNotListed` means only that the exact credential digest was absent from that signed set **at observation**; this is not proof of completeness, real-time unrevoked status, registration or authorization. The VC2 encoding remains the repository's narrow direct JOSE profile, not a third-party wallet interoperability or OpenID4VP 1.0 conformance claim. No production migration, deployment, NuGet release, genuine customer keys or license changes are part of this work.
