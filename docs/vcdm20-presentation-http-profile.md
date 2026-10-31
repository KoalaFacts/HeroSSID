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

**Signing options:** The basic challenge response itself is **not** signed. A verifier with an independent private seed can sign locally using `OfflineSignedPresentationRequest.Create(challenge, verifierDid, verifierPrivateKey, clock)`. Never send a locally held private key to the API.

Alternatively, a client authenticated with **both** `credential:verify` and `did:manage` scopes can sign and issue the same kind of one-use request under **its own active tenant-owned server DID** (not a holder DID or issuer key):

```http
POST /api/v1/credentials/vcdm20/signed-presentation-request
Authorization: Bearer <verifier-access-token>
Content-Type: application/json
```

```json
{
  "verifierDid": "did:key:<tenant-owned-active-verifier>",
  "audience": "https://verifier.example/present",
  "trustedIssuerDid": "did:key:<independently-chosen-issuer>",
  "lifetimeSeconds": 120
}
```

The **201** response contains `signedRequestJwt`, `verifierDid`, `audience`, `nonce`, `trustedIssuerDid` and `expiresAt`. The server verifies the verifier DID is active and **belongs to the authenticated tenant**, decrypts only that tenant's existing verifier seed, signs the durable one-use challenge with the genuine Ed25519 key, then zeroes the decrypted bytes. An unowned or inactive verifier DID returns **404**, anonymous **401**, wrong scope **403**, malformed policy **400**, retained challenge capacity exhaustion **429**, and key or challenge-store unavailability **503**. No new schema is required.

### Bind the verifier's credential type and subject vocabulary (opt-in)

For a new VC2 verifier request, send **both** `expectedCredentialType` and `subjectContextUri` alongside the existing active tenant-owned verifier DID, trusted issuer and HTTPS audience. A single field without the other is a **400**; type must be bounded and non-whitespace, and the context must be a versioned absolute HTTPS URI without credentials or a fragment.

```json
{
  "verifierDid": "did:key:<active-tenant-owned-verifier>",
  "audience": "https://verifier.example/present",
  "trustedIssuerDid": "did:key:<independently-chosen-issuer>",
  "expectedCredentialType": "MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/member/v1",
  "lifetimeSeconds": 120
}
```

The response is the same **201** JSON shape. Its actual Ed25519-signed `signedRequestJwt` now includes exact `credentialType` and `subjectContextUri` claims. They are the **verifier's requested policy**, not assertions about the holder. The issuer and holder still sign their respective separate artifacts. An external verifier with its own independent seed can also opt in when calling `OfflineSignedPresentationRequest.Create` on a challenge carrying `CredentialType` and `SubjectContextUri`; the original durable challenge store still retains tenant, issuer, audience and one-use nonce without new schema.

A Wallet integrating this profile should call `OfflineSignedPresentationRequest.TryReadPolicyBound` with its **independently pinned verifier DID, audience, expected credential type and exact HTTPS subject vocabulary**. To preview claims before using any holder key, call `Vcdm20WalletDisclosure.TryPrepareRequiringSignedPolicy` with these independent pins, the original issuer-signed VC2 JWT, and the expected holder DID. After the Wallet's own informed full-disclosure decision, call `CreateHolderPresentationAfterPreview`. It verifies exact artifacts and both signers again. A real credential for a different issuer, type or context is rejected even if it carries a mathematically valid issuer signature.

**Downgrade boundary:** the original six-claim `herossid-request+jwt` remains readable by the legacy `TryRead` and `TryPrepare` APIs, but can **never** pass `TryReadPolicyBound` or `TryPrepareRequiringSignedPolicy`. Conversely, a new eight-claim policy-bound request does not pass legacy `TryRead`; an integration that requires this signed policy must use the strict APIs, rather than falling back to the legacy parser. This is a private HeroSSID request subprofile, **not** an OpenID4VP request, W3C conformance, genuine consent proof, identity vetting or business delegation.

**Server-side authorization limit:** this signed policy is enforced at Wallet preview/signing time. The HTTP verification endpoint still receives the relying party's caller-specified credential type and context and checks issuer/holder signatures and the one-use challenge, whose durable record does **not** persist those two policy fields. A relying party requiring end-to-end verifier-policy proof must retain its own request/policy record and compare it when accepting the result; this change does not introduce a new server-side authorization decision or persistence contract.

This optional server-managed **verifier** signing is not holder key custody, holder consent, identity proofing or a hosted OpenID4VP Request Object. The holder must independently pin that verifier DID **and** audience through a trusted channel before accepting the signed JWT; a DID embedded in the request is not a trusted pin.

## 2. Explicitly cancel a declined or abandoned verifier challenge

A verifier backend holding a validated tenant bearer token with `credential:verify` may invalidate an outstanding request **without asking the holder to sign anything**. This works for both the plain verifier challenge and the optional service-signed request above.

```http
POST /api/v1/credentials/vcdm20/cancel-presentation-challenge
Authorization: Bearer <verifier-access-token-with-credential:verify>
Content-Type: application/json
```

```json
{
  "audience": "https://verifier.example/present",
  "nonce": "<exact-issued-43-character-nonce>"
}
```

The audience must match the exact canonical HTTPS audience originally retained in the verifier's challenge. The nonce must be the canonical base64url encoding of 32 bytes. A **204 No Content** reply deliberately does **not** disclose whether the challenge existed, was already consumed or expired, or was successfully cancelled. Invalid shape is **400**, anonymous **401**, missing `credential:verify` scope **403**, unavailable PostgreSQL challenge state **503**. Cancellation and a concurrently verified holder proof share the same atomic PostgreSQL consume operation across replicas: at most one can win. Once accepted, a presentation cannot be retracted by cancellation.

The security boundary is the **authenticated tenant**, not an individual OAuth client: any caller with `credential:verify` for that tenant and knowledge of the exact audience and nonce can cancel that tenant's challenge. Keep nonces confidential and use isolated tenants when verifiers must not interfere. Consumed challenges remain replay tombstones until expiry, rather than immediately freeing capacity. The endpoint neither proves the holder refused nor records genuine informed consent. No production migration or new database schema is involved.

## 3. Holder independently authenticates the request and chooses disclosure

The holder app uses `OfflineSignedPresentationRequest.TryRead(requestJwt, pinnedVerifierDid, exactAudience, clock, out challenge)` to authenticate the real verifier signature and request expiry. It must display **all claims** and the destination, obtain affirmative full-disclosure consent and allow refusal before signing. After consent, `Vcdm20JosePresentation.Create(requestJwt, pinnedVerifierDid, exactAudience, issuerSignedCredential, expectedCredentialType, expectedHttpsContext, holderDid, holderOwnedSeed, clock)` creates a real holder-signed `vp+jwt` envelope preserving the original issuer-signed VC2 JWT. The issuer and holder keys remain independent.

The issuer separately signs a **complete** status snapshot using `Vcdm20RevocationSnapshot.Create`, based on its authoritative revocation data, with observation time recorded before any potentially slow status read. The present `/vcdm20/issue` HTTP endpoint **does not persist or revoke** short-lived VC2 credentials. HeroSSID does not publish VC2 snapshots automatically. No wallet UI, consent record or issuer status registry is supplied here. The optional server-managed verifier signer is limited to the tenant's own existing DID; holder private keys remain external.

## 4. Verifier submits the proof and issuer snapshot

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

## 5. Verify the original verifier-signed policy (strict opt-in)

The original `/verify-presentation` endpoint checks caller-supplied type and context.
For a relying party that requires the original **verifier-signed** type/context
policy, submit that same compact JWT alongside the holder proof to the separate
opt-in endpoint. Do not silently fall back to the legacy route on failure.

```http
POST /api/v1/credentials/vcdm20/verify-signed-policy-presentation
Authorization: Bearer <verifier-access-token-with-credential:verify>
Content-Type: application/json
```

```json
{
  "signedRequestJwt": "<original-eight-claim-verifier-JWS>",
  "verifierDid": "did:key:<active-tenant-owned-verifier>",
  "audience": "https://verifier.example/present",
  "expectedCredentialType": "MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/member/v1",
  "presentation": "<holder-signed-vp+jwt>",
  "revocationSnapshot": "<issuer-signed-VC2-status-JWS>"
}
```

The service requires the verifier DID to be **active and owned by the authenticated
tenant**, re-derives it from the stored public key and verifies the original
Ed25519 JWS against that DID and the exact HTTPS audience. It refuses unbound
legacy six-field requests, forged requests and type/context mismatches **before**
spending the nonce. The signed issuer DID, nonce and expiry must match the
same tenant's durable one-use challenge. The nonce is taken from the authenticated
request, not accepted from a separate caller field. The existing issuer + holder
Ed25519, VC2 policy, issuer-signed status and atomic consumption checks then run.
Only `SignedNotListed` returns signed subject claims; other statuses expose null
subjects. Invalid proof returns `200` / `Invalid`, bad input shape `400`,
missing authentication `401`, wrong scope `403` and unavailable state `503`.

**Trust limit:** the challenge database still retains the issuer, tenant,
audience, nonce and expiry, **not** the original signed credential type/context
or its JWT digest. This endpoint proves that the supplied request was genuinely
signed by an active tenant-owned verifier DID and matches the retained challenge;
it cannot distinguish a *different also-authentic* policy JWT that the same
trusted signer might later create for the same nonce. Relying parties needing
immutable transaction-specific policy must also retain and pin the original
request JWT/digest themselves. This is not authorization, reality identity
proof, status-list completeness, live non-revocation, actual holder consent,
OpenID4VP conformance or independent Wallet interoperability.

## Distributed safety and limits

The API registers `PostgresPresentationChallengeStore` for every instance through the same configured PostgreSQL connection. It atomically consumes a challenge once across replicas and retains replay tombstones until expiry. Existing migration is required but is **not applied in production** by this change. The development-only in-memory store is suitable only for isolated SDK tests. If PostgreSQL is unavailable, verification fails closed.

The issuer-signed snapshot covers a maximum of 256 revoked JWT digests and expires no later than 60 seconds from observed status. `SignedNotListed` means only that the exact credential digest was absent from that signed set **at observation**; this is not proof of completeness, real-time unrevoked status, registration or authorization. The VC2 encoding remains the repository's narrow direct JOSE profile, not a third-party wallet interoperability or OpenID4VP 1.0 conformance claim. No production migration, deployment, NuGet release, genuine customer keys or license changes are part of this work.
