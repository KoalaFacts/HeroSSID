# VC1.1 JWT holder-control verification over HTTP (HeroSSID profile)

This opt-in, **authenticated verifier HTTP API** adds holder-signed W3C VC Data Model **1.1** `jwt_vc_json` presentation verification. It reuses the existing PostgreSQL `presentation_challenges` table (already migrated in the repository); **no schema changes or new migration** are part of this feature. This is a HeroSSID-specific challenge and short-lived issuer status format, **not** OpenID4VP, OpenID4VCI, a hosted wallet, a consent UI or independent external-wallet interoperability.

## Step 1: authenticated verifier issues a challenge

```http
POST /api/v1/credentials/jwt-vc-json/presentation-challenge
Authorization: Bearer <credential:verify scoped token>
Content-Type: application/json

{"audience":"https://verifier.example/membership","trustedIssuerDid":"did:key:z...","lifetimeSeconds":120}
```

Returns **201** with `audience`, an unpredictable one-use `nonce`, `trustedIssuerDid`, and `expiresAt`. The verifier tenant owns this challenge and independently chooses the trusted issuer. The audience must be a canonical HTTPS URL, the issuer a real Ed25519 `did:key`, and lifetime 1–300 seconds. **401** anonymous, **403** insufficient scope, **400** malformed, **429** challenge capacity reached, **503** PostgreSQL unavailable.

The challenge response is **not signed**. The verifier must authenticate it to the holder using a distinct verifier-controlled Ed25519 private key, for example `OfflineSignedPresentationRequest.Create`, and the holder must independently pin the verifier DID and exact audience before accepting it. A verifier's signature establishes control of that verifier key, **not** its organisation, trustworthiness or authority.

## Step 2: holder intentionally signs the original issuer statement

The holder must independently verify the signed verifier request and original issuer credential, show the **full list of claims and destination**, obtain affirmative full-disclosure consent, and permit rejection. The SDK `JwtVcJsonPresentation.Create` checks the signed request, independently pinned verifier DID and audience, expected HTTPS type/context, original issuer-signed `jwt_vc_json` and that the holder actually controls its separate Ed25519 key. It creates `vp+jwt` containing the unchanged original issuer JWT. **HeroSSID does not record consent and does not host a wallet.** Never upload holder private keys to the verifier.

The issuer separately produces a signed, at-most-60-second `JwtVcJsonRevocationSnapshot` from its *complete, authoritative* revoked credential set and distributes it to verifiers. HeroSSID does **not** automatically publish this private status; currently HTTP-issued VC1.1 JWTs are not persisted or revocable through the legacy database revoke route.

## Step 3: authenticated verifier checks holder, issuer, challenge and status

```http
POST /api/v1/credentials/jwt-vc-json/verify-presentation
Authorization: Bearer <credential:verify scoped token>
Content-Type: application/json

{
  "presentation": "<holder-signed-vp+jwt>",
  "revocationSnapshot": "<issuer-signed-HeroSSID-VC1.1-status+jwt>",
  "audience": "https://verifier.example/membership",
  "nonce": "<issued-nonce>",
  "expectedCredentialType": "https://issuer.example/credentials#MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1"
}
```

The verifier supplies its own expected HTTPS credential type and JSON-LD context, **never accepting them from the untrusted VP**. In a **200** result, `SignedNotListed` includes `verifiedSubject` only when the actual issuer **and** holder signatures, issuer policy, VC1.1 nested context, expiry, exact audience/nonce, atomic one-use consumption, and same-issuer signed status all pass. `Revoked` and `Invalid` return `verifiedSubject: null`. An authentic proof spends its nonce even when status denies; forged holder signatures do not release claims. Missing scope is **403**, anonymous **401**, invalid bounded request **400**, store unavailable **503**.

All API replicas must share the existing PostgreSQL challenge store; in-memory storage is only for isolated SDK tests. A request cannot be replayed or transferred between tenant challenges. Signed status lists at most 256 revoked credential digests. **`SignedNotListed` is only absent from one fresh issuer-signed snapshot**; it is not proof of snapshot completeness, present-day non-revocation, human identity, organisation registration, agent authority or business permission. Issuer statement, holder key control, independent reality-based identity checks and application authorization are separate decisions.

The integration acceptance tests run against isolated Docker/PostgreSQL with two independent HTTP application hosts. They test real Ed25519 issuer and holder signatures, revoked status, forgery, replay, scope, and negative policy; these are **not** third-party wallet conformance results. No production migration, deployment, packaging, user private keys or licence changes are in this PR.
