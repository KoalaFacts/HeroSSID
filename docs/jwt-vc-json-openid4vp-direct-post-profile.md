# Bounded OpenID4VP 1.0 `jwt_vc_json` direct_post SDK

This opt-in SDK connects the **W3C VC Data Model 1.1** `jwt_vc_json` issuer and holder-signed presentation APIs to an **OpenID4VP 1.0** signed Request Object, DCQL Credential Query and `application/x-www-form-urlencoded` `direct_post` response.

Normative format/transport reference: [OpenID4VP 1.0 final, Appendix B.1.3.1](https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#name-w3c-verifiable-credential). The exact credential serialization is the independent, issuer-signed JWT produced by `JwtVcJsonCredential.Create`. The VP is the original issuer JWT inside a separately signed holder `vp+jwt`; neither signature replaces the other.

**This is a constrained SDK profile, not a complete OpenID4VP implementation or independently demonstrated third-party wallet interoperability.** The signed request additionally carries two explicitly private parameters, `herossid_trusted_issuer_did` and `herossid_subject_context_uri`, to make a verifier-selected issuer and claim vocabulary unambiguous. External wallets are not obliged to understand them; do not advertise general conformance.

## End-to-end signing boundaries

1. A verifier independently chooses a trusted issuer DID, credential type and versioned HTTPS subject context. It creates and retains a random, one-use `PresentationChallenge` in a verifier-owned `IPresentationChallengeStore`: `store.Issue(verifierTenantId, "decentralized_identifier:" + verifierDid, trustedIssuerDid)`. The verifier signs that exact challenge with **its own** Ed25519 verifier key using `OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest(challenge, verifierDid, verifierSeed, responseUri, credentialType, subjectContext, clock)`.
2. The holder application must independently pin the **verifier DID**, exact **HTTPS response URI**, expected **credential type**, and **HTTPS claim vocabulary**. It calls `TryReadSignedRequest`, verifies the Ed25519 signature and signed DCQL `jwt_vc_json` request, then displays the complete credential and disclosure destination and obtains real informed full-disclosure consent. The library **cannot prove consent**.
3. Only after consent, the holder calls `CreateHolderResponseForm(requestJwt, pinnedVerifierDid, pinnedResponseUri, credentialType, subjectContext, originalCredentialJwt, holderDid, holderSeed, clock)`. This checks the issuer's original JWT signature against the issuer DID from the authenticated verifier request, proves holder key control with **a distinct Ed25519 seed**, and returns a `vp_token=<url-encoded JSON>&state=<nonce>` body. The JSON object has exactly one `jwt_vc_json_credential` key, containing exactly one holder-signed `vp+jwt`. Send it only to the *already verified* HTTPS response URI with Content-Type `application/x-www-form-urlencoded`.
4. The verifier uses `CheckResponseForm(form, verifierTenantId, expectedClientId, expectedNonce, expectedCredentialType, expectedSubjectContextUri, store, clock, out var subject)`. It checks exact state, standard VP Token shape, issuer and holder signatures, independent persisted issuer trust policy, audience/nonce, credential type/context and expiry, then **atomically consumes** the challenge. Only `SignedButStatusUnchecked` returns the signed subject claims; `Invalid` returns none. A shared atomic store is mandatory across HTTP replicas.

The SDK does not deploy or operate a trusted `response_uri` endpoint, fetch Request Objects, provide wallet discovery, UI, login, OpenID4VCI issuance, interoperable status-list verification, optional DCQL alternatives, selective disclosure, `direct_post.jwt`, or consent evidence. The calling application must implement these separately.

## Deliberately supported subset

- Request Object JOSE `typ=oauth-authz-req+jwt`, `alg=EdDSA`, and `kid` exactly bound to the verifier's self-certifying `did:key`; `client_id=decentralized_identifier:<verifier DID>` and `response_type=vp_token`.
- `response_mode=direct_post`, one pre-pinned HTTPS `response_uri`, `state=nonce`, bounded numeric `iat/exp`, and a **single** non-optional DCQL Credential Query: `format=jwt_vc_json`, `meta.type_values=[[ "https://www.w3.org/2018/credentials#VerifiableCredential", "<absolute HTTPS credential type IRI>" ]]`, `require_cryptographic_holder_binding=true`. Metadata advertises `jwt_vc_json.alg_values=["EdDSA"]`.
- **DCQL expanded type rule (OpenID4VP 1.0 §B.1.1):** W3C VC 1.1 `VerifiableCredential` is expanded by the standard 2018 credentials context to `https://www.w3.org/2018/credentials#VerifiableCredential`, so the DCQL query uses this full IRI rather than the literal short term. In this bounded SDK, the other `credentialType` must be an **absolute HTTPS IRI**, such as `https://issuer.example/credentials#MembershipCredential`. This avoids guessing a custom term's JSON-LD expansion. A bare `MembershipCredential` is rejected by this transport bridge even though the separate issuer-only SDK may accept it. The bridge does not download or expand the supplied subject context; it does not claim general JSON-LD processing or third-party wallet compatibility.
- Independent issuer trust policy enforced by the verifier's retained challenge record, not by accepting the presented issuer as a trust anchor. Unknown, expired, foreign-tenant, replayed or maliciously re-signed claims fail closed.
- The basic `OpenId4VpJwtVcJsonDirectPost.CheckResponseForm` **does not check status** and returns `SignedButStatusUnchecked`. Opt-in `JwtVcJsonDirectPostRevocation.CheckResponseForm` requires a fresh, issuer-signed, format-specific status snapshot and matches it to the **actual nested issuer JWT** before releasing claims. This private snapshot is not a W3C Status List, and `NotListed` never proves the issuer exported every revocation or that no revocation happened since observation. Neither API establishes identity, consent or business authority. See [the status profile](jwt-vc-json-revocation-direct-post-profile.md).

## Evidence

The new xUnit `OpenId4VpJwtVcJsonDirectPostTests` exercises separate real verifier, issuer and holder keys, exact OpenID4VP DCQL/VP Token fields, original issuer JWT preservation, wallet pinning of callback/type/context, foreign issuer, tampered issuer JWT, wrong holder key, one-use challenge, wrong tenant, duplicate state and expiry. These are **in-process contract tests**, not a test against any third-party wallet.

Run locally under .NET 10 with:

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj --configuration Release --filter FullyQualifiedName~OpenId4VpJwtVcJsonDirectPostTests
```

No new database schema or migration is introduced. Production PostgreSQL, publishing and deployment are outside this delivery.
