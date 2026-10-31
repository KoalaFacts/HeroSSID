# Authenticated OpenID4VP 1.0 `jwt_vc_json` HTTP bridge

This opt-in HTTP adapter makes the existing [VC 1.1 `jwt_vc_json` signed-request/`direct_post` SDK](jwt-vc-json-openid4vp-direct-post-profile.md) callable by non-.NET verifier backends. It **does not host the public HTTPS `response_uri`**, discover wallets, prompt for user consent, publish status, perform real identity vetting or grant business authorization. The requesting application must own an actual HTTPS callback, forward the unmodified `application/x-www-form-urlencoded` body to the authenticated verify API and manage its own authorization, consent and trust policy. Do **not** call this complete OpenID4VP conformance or independent third-party wallet interoperability.

The request uses the OpenID4VP 1.0 Final signed Request Object and DCQL `jwt_vc_json` subset described by the linked SDK profile, including its private issuer/context extensions. PostgreSQL retains a verifier-tenant-bound one-time challenge using the existing `presentation_challenges` table. No new schema or migration is introduced.

## Issue an authenticated verifier request

The backend first chooses a trusted issuer DID, expanded HTTPS credential type and exact HTTPS claim context through independent policy, and selects an existing **active, tenant-owned verifier did:key**. It must have both `credential:verify` and `did:manage` scopes.

```http
POST /api/v1/credentials/jwt-vc-json/openid4vp/signed-request
Authorization: Bearer <credential:verify and did:manage token>
Content-Type: application/json

{
  "verifierDid": "did:key:<active-tenant-owned-verifier>",
  "responseUri": "https://verifier.example/direct-post",
  "trustedIssuerDid": "did:key:<separately-trusted-issuer>",
  "credentialType": "https://issuer.example/credentials#MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1",
  "lifetimeSeconds": 120
}
```

The **201 Created** JSON returns `signedRequestJwt`, `clientId` (`decentralized_identifier:<verifierDid>`), `verifierDid`, `responseUri`, `nonce`, `trustedIssuerDid`, `expiresAt` and `walletInvocationUri`. HeroSSID verifies the active verifier signer belongs to the authenticated tenant, decrypts its existing Ed25519 seed only to sign, verifies the signature and zeroes the temporary key bytes. The stored challenge is bound to the tenant, client ID, trusted issuer and nonce. A wallet or independent holder must **independently pin** the verifier DID, exact HTTPS callback, requested type and context, cryptographically check the signed Request Object, display the complete disclosure and obtain real consent *before* signing its own presentation. A DID supplied inside the untrusted request is not itself a trustworthy pin.

Missing authentication is **401**, insufficient scope **403**, foreign/inactive verifier DID **404**, malformed HTTPS/issuer/type/context/lifetime **400**, retained challenge capacity **429**, signing/store failure **503**.

## Signed by-value wallet invocation (same-device launch)

The HTTP response now includes a **wallet-invocation URI** containing the **unchanged, genuine verifier Ed25519-signed** Request Object:

```text
openid4vp://?client_id=decentralized_identifier%3Adid%3Akey%3A<verifier>&request=<original-compact-signed-request-JWT>
```

This follows the OpenID4VP 1.0 [wallet-invocation custom-scheme mechanism](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-wallet-invocation) and its *by-value* `request` parameter. This URL is intended primarily for same-device app deep linking. Full signed Request Objects can be too large for reliable cross-device QR codes. There is **no public `request_uri` endpoint** or built-in app/QR handler.

An integrating holder wallet can use the SDK's `OpenId4VpJwtVcJsonDirectPost.TryReadWalletInvocation` to recover the original signed JWT **only after** an *independently pinned* verifier DID, HTTPS callback URI, credential type, context, signature and expiry all match. The URL's own `client_id`, unsigned query parameters or embedded DID are never independent sources of trust. Exact canonical parameter order, escaping and the single signed `request` are required by this bounded parser. Altered/duplicated fields, forged signatures, stale requests and mismatched pinning fail without releasing claims. Once verified, the wallet application must display the **entire full-disclosure credential** and obtain meaningful user consent **before** calling `CreateHolderResponseForm`.

This is a real standards-shaped by-value invocation surface, **not evidence that any third-party Wallet supports our private issuer/context policy extensions, credential constraints or VP response format**. It does not demonstrate OpenID4VP conformance, human consent, identity vetting, live revocation or business authorization. The verifier's actual HTTPS `response_uri` remains externally hosted by its application, with the separate authenticated backend verification endpoint below.

## Verify the forwarded direct_post form

An application (not HeroSSID) receives the actual holder `direct_post` form at its own trusted `response_uri`. Its authenticated backend forwards the **entire original form string** as `form`, along with an independently retained verifier DID, nonce, expected credential type/context and the issuer's private-profile 60-second signed status export. This endpoint requires `credential:verify` and **is not a publicly callable wallet callback**.

```http
POST /api/v1/credentials/jwt-vc-json/openid4vp/verify-response
Authorization: Bearer <credential:verify token>
Content-Type: application/json

{
  "verifierDid": "did:key:<verifier>",
  "nonce": "<original-43-character-nonce>",
  "form": "vp_token=<url-encoded-json>&state=<original-nonce>",
  "revocationSnapshot": "<issuer-signed-herossid-jwt-vc-json-revocations+jwt>",
  "expectedCredentialType": "https://issuer.example/credentials#MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1"
}
```

A **200 OK** result returns only `{"status":"SignedNotListed","verifiedSubject":{...}}` after checking authentic **original issuer and independent holder Ed25519 signatures**, exact verifier-owned challenge/state, retained issuer trust policy, type/context, nonce atomic consumption and a timely same-issuer status snapshot for the **actual enclosed issuer JWT**. It returns `{"status":"Revoked","verifiedSubject":null}` for authentic revoked proofs, or `{"status":"Invalid","verifiedSubject":null}` for malformed, forged, foreign-issuer, expired, replayed, mismatched or untrusted proof/status. The nonce is consumed before snapshot rejection to avoid retry under that challenge. The endpoint fails closed when PostgreSQL is unavailable (**503**), and rejects unsupported request shape (**400**). Missing authentication/scope yields **401/403**.

`SignedNotListed` says that a valid signed issuer credential was not present in that issuer's supplied complete revoked digest set *at observation time*. It **does not** prove status is current or that the issuer supplied a complete authoritative set. HTTP issuance does not persist or revoke this format. There is no automatic status publication, independent wallet testing, public callback hosting, end-user consent evidence, real-world identity verification or business authorization. None of these trust responsibilities can be inferred from a signature.

## Cancel an outstanding signed request (backend only)

When the holder declines, the verifier abandons the transaction, or an application no longer wants to accept the response, its **authenticated backend** can invalidate the pending one-time challenge. The backend requires both `credential:verify` and `did:manage`, just like issuing the signed request. A wallet has no access to this privileged route; the relying-party application must translate its cancellation/decline event into this call.

```http
POST /api/v1/credentials/jwt-vc-json/openid4vp/cancel-request
Authorization: Bearer <credential:verify and did:manage token>
Content-Type: application/json

{
  "verifierDid": "did:key:<the-original-verifier>",
  "nonce": "<the-original-43-character-nonce>"
}
```

The route uses the existing tenant-bound PostgreSQL one-time challenge store and atomic consume operation. It returns **204 No Content** for a matching unexpired challenge, an already-consumed challenge or an unknown challenge, deliberately not exposing which case occurred. A different verifier DID, tenant or nonce cannot consume the original challenge. Missing auth/scope returns **401/403**, malformed input **400**, and store unavailability **503**. Repeated cancellation does not reactivate a request; a later otherwise-valid holder proof for a cancelled challenge is rejected without claims. No schema migration is necessary.

Cancellation is *not* a cryptographic consent record, proof of holder intent or guarantee that a response has not **already been accepted**: if verification wins the atomic race first, disclosed information cannot be retracted. Applications must prevent use of already-delivered claims and obtain explicit human disclosure consent in their own wallet/user experience.

## Executable acceptance

```bash
dotnet test tests/Integration/HeroSSID.Integration.Tests/HeroSSID.Integration.Tests.csproj --configuration Release --filter FullyQualifiedName~JwtVcJsonOpenId4VpHttpIntegrationTests
```

The integration suite uses disposable PostgreSQL and real independent Ed25519 issuer/holder/verifier keys, tests signed request validation and one-use status-aware verification, replay rejection, and authentication, scope, foreign DID and callback constraints. Local code tests do **not** establish independent OpenID4VP standards conformance or wallet interoperability.
