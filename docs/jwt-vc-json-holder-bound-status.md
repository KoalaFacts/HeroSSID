# VC1.1 holder-bound `direct_post` with signed issuer status (opt-in SDK)

HeroSSID offers a **combined** verifier entrypoint for a full-disclosure W3C VC Data Model 1.1 `jwt_vc_json` issuer JWT in the bounded OpenID4VP 1.0 `direct_post` SDK profile:

`JwtVcJsonDirectPostRevocation.CheckHolderBoundResponseForm(form, snapshotJwt, signedRequestJwt, verifierRetainedRequestSha256, trustedVerifierDid, expectedResponseUri, tenantId, expectedClientId, expectedNonce, credentialType, subjectContextUri, challengeStore, clock, out verifiedSubject)`

The relying verifier must first **independently retain** the exact original compact verifier-signed Request Object and lowercase SHA-256 under its own trusted tenant/challenge state, and pin the verifier DID, HTTPS callback, credential type and HTTPS subject context without reading that policy from holder-controlled data. The Wallet must authenticate the genuine signed verifier request and issuer credential, display every disclosed claim and obtain actual application-layer consent **before** it calls `OpenId4VpJwtVcJsonDirectPost.CreateHolderBoundResponseForm` using its own Ed25519 seed. This SDK does not supply a consent UI or evidence of consent.

The combined verifier validates the exact verifier-retained hash, genuine verifier Ed25519 signature, signed challenge/policy, independent tenant challenge, the **holder-signed exact request hash**, the genuine issuer's unchanged VC JWT, actual holder key control, nonce and atomic one-time consumption. After successful bound presentation verification, it checks the **same actual issuer's** 60-second private signed revocation snapshot against the original enclosed VC JWT; only `NotListed` releases the verified subject. `Revoked` or `Invalid` returns an undefined subject. An absent status or invalid verifier challenge/pin fails before consumption; a valid bound proof consumes the nonce even when the signed status subsequently reports revocation or fails verification. This prevents retrying a valid presentation under the same nonce with a different status.

Do **not** combine the existing unbound `CheckResponseForm` with an independently invoked bound verifier; both paths use a one-use challenge. The strict combined method is the opt-in entrypoint when both controls are required. The older unbound entrypoints remain supported for compatibility but do **not** provide the holder-signed original-request binding guarantee. No new database schema or hosted public HTTPS callback is introduced.

`NotListed` means only that the real issuer's signed, caller-supplied snapshot did not list this credential at its claimed observation instant. It cannot prove truthful list completeness, live non-revocation, issuer trust enrollment, actual user consent, legal identity, Agent delegation or business authorization. The `herossidRequestSha256` holder claim and issuer-status envelope are HeroSSID extensions; this implementation is **not** a third-party Wallet interoperability test, complete OpenID4VP conformance or an external cryptographic audit.

Acceptance test:

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj --configuration Release --filter FullyQualifiedName~JwtVcJsonDirectPostRevocationTests
```

See [original-request binding](jwt-vc-json-holder-bound-original-request.md), [status snapshot](jwt-vc-json-revocation-direct-post-profile.md), [OpenID4VP SDK](jwt-vc-json-openid4vp-direct-post-profile.md) and [VISION](VISION.md).
