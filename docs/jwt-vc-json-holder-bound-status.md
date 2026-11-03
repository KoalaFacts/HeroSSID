# VC1.1 holder-bound `direct_post` with signed issuer status (opt-in SDK)

HeroSSID offers a **combined** verifier entrypoint for a full-disclosure W3C VC Data Model 1.1 `jwt_vc_json` issuer JWT in the bounded OpenID4VP 1.0 `direct_post` SDK profile:

`JwtVcJsonDirectPostRevocation.CheckHolderBoundResponseForm(form, snapshotJwt, signedRequestJwt, verifierRetainedRequestSha256, trustedVerifierDid, expectedResponseUri, tenantId, expectedClientId, expectedNonce, credentialType, subjectContextUri, challengeStore, clock, out verifiedSubject)`

The relying verifier must first **independently retain** the exact original compact verifier-signed Request Object and lowercase SHA-256 under its own trusted tenant/challenge state, and pin the verifier DID, HTTPS callback, credential type and HTTPS subject context without reading that policy from holder-controlled data. The Wallet must authenticate the genuine signed verifier request and issuer credential, display every disclosed claim and obtain actual application-layer consent **before** it calls `OpenId4VpJwtVcJsonDirectPost.CreateHolderBoundResponseForm` using its own Ed25519 seed. This SDK does not supply a consent UI or evidence of consent.

The combined verifier validates the exact verifier-retained hash, genuine verifier Ed25519 signature, signed challenge/policy, independent tenant challenge, the **holder-signed exact request hash**, the genuine issuer's unchanged VC JWT, actual holder key control, nonce and atomic one-time consumption. After successful bound presentation verification, it checks the **same actual issuer's** 60-second private signed revocation snapshot against the original enclosed VC JWT; only `NotListed` releases the verified subject. `Revoked` or `Invalid` returns an undefined subject. An absent status or invalid verifier challenge/pin fails before consumption; a valid bound proof consumes the nonce even when the signed status subsequently reports revocation or fails verification. This prevents retrying a valid presentation under the same nonce with a different status.

Do **not** combine the existing unbound `CheckResponseForm` with an independently invoked bound verifier; both paths use a one-use challenge. The strict combined method is the opt-in entrypoint when both controls are required. The older unbound entrypoints remain supported for compatibility but do **not** provide the holder-signed original-request binding guarantee. No new database schema or hosted public HTTPS callback is introduced.

`NotListed` means only that the real issuer's signed, caller-supplied snapshot did not list this credential at its claimed observation instant. It cannot prove truthful list completeness, live non-revocation, issuer trust enrollment, actual user consent, legal identity, Agent delegation or business authorization. The `herossidRequestSha256` holder claim and issuer-status envelope are HeroSSID extensions; this implementation is **not** a third-party Wallet interoperability test, complete OpenID4VP conformance or an external cryptographic audit.

## Post-incident issuer observation cutoff (strict opt-in)

Use `JwtVcJsonDirectPostRevocation.CheckHolderBoundResponseFormWithObservationCutoff(..., minimumStatusObservedAt, out verifiedSubject)` when the relying verifier has independently recorded an incident/compromise time. This combines the existing genuine verifier-request/holder signature, exact-original-request pin and atomic one-use challenge with the **same genuine issuer's** signed status whose `iat` (claimed observation timestamp) must be **at or after** the verifier's cutoff. The pre-existing `CheckHolderBoundResponseForm` remains available without incident cutoff; it must not be used when incident policy requires one.

The verifier must choose and retain `minimumStatusObservedAt` from its own incident policy, not from the Wallet, signed Request Object, credential, form, or issuer's claimed time. An authentic still-fresh pre-incident snapshot fails and discloses no claims. Invalid cutoff values before the Unix epoch or in the future fail *before* consuming a challenge; valid holder proof spends its challenge even if signed status is pre-incident, revoked, malformed or unavailable. A new request and fresh one-time challenge are necessary to try a later snapshot; a used nonce cannot be revived.

Status timestamps are signed whole seconds. A cutoff at 10:00:00.500 UTC requires a signed issuer observation at 10:00:01 UTC or later; rounding a cutoff down would admit an older snapshot. `NotListed` is only a private signed assertion about a caller-provided revocation set at its claimed observation instant. It does not prove the issuer actually observed that set after the incident, its completeness, the private key remained safe, or live non-revocation. It is not a W3C status-list protocol, a user consent UI, legal identity proof or business authorization.

Acceptance test:

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj --configuration Release --filter FullyQualifiedName~JwtVcJsonDirectPostRevocationTests
```

See [original-request binding](jwt-vc-json-holder-bound-original-request.md), [status snapshot](jwt-vc-json-revocation-direct-post-profile.md), [OpenID4VP SDK](jwt-vc-json-openid4vp-direct-post-profile.md) and [VISION](VISION.md).
