# Full-disclosure presentation profile

## Scope

This is a HeroSSID development library profile. It presents one complete JWT credential whose issuer and holder are enrolled in the same HeroSSID database. They may belong to different tenants, and the verifier may belong to a third tenant. It is not SD-JWT, a general W3C presentation conformance claim, or an OpenID4VP HTTP implementation.

The issuer's JWT is embedded unchanged. Every original claim is visible to the verifier. A holder signature proves control of the enrolled holder key for a particular verifier request; it does not replace issuer authentication.

## API and policy

`CreateChallenge(verifierContext, audience, trustedIssuerDid, lifetime)` issues a random 256-bit nonce. The store retains the authenticated verifier tenant, exact audience, trusted issuer DID and expiry. Default lifetime is two minutes, with a one-second minimum and five-minute maximum. The default store permits at most 1,024 outstanding challenges per process and rejects new issuance at capacity without evicting live requests.

The trusted issuer is a verifier policy choice. A holder cannot change it by modifying challenge metadata or JWT claims. The credential type and application-specific claim requirements still need to be checked by the relying application after a valid presentation result. The verifier must validate the original JWT against those requirements as part of its acceptance workflow; a valid generic presentation alone does not grant business access.

`CreatePresentationAsync(holderContext, credentialJwt, holderDidId, challenge, cancellationToken)` first verifies the credential and holder ownership, then decrypts the tenant-owned holder key to sign. Its plaintext buffer is cleared after use. It never filters or re-signs issuer claims.

`VerifyPresentationAsync(verifierContext, presentationJwt, expectedAudience, expectedNonce, cancellationToken)` requires the verifier's retained request values. Values read from the submitted JWT must not be used as the application's expected values. The store is consumed atomically only after checks succeed, with an expiry recheck at consumption. Separate application/database scopes must share the store.

## Envelope

Header:

```json
{"alg":"EdDSA","typ":"vp+jwt"}
```

Payload:

```json
{
  "iss": "<holder DID>",
  "aud": "<exact verifier audience>",
  "nonce": "<issued nonce>",
  "iat": 1792800000,
  "exp": 1792800120,
  "vp": {"verifiableCredential": ["<complete original credential JWT>"]}
}
```

The illustrative timestamps are not reusable challenges. The outer payload must have exactly these six properties, `vp` exactly one property, and the credential array exactly one string. Unknown headers and duplicate JSON properties are rejected. Both JWTs require canonical, unpadded base64url encoding. Maximum compact lengths are 65,536 characters for the original credential and 131,072 for the presentation; JSON nesting is limited to 16 levels.

The original credential must use `alg=EdDSA`, `typ=vc+jwt`, a trusted enrolled `iss`, `sub` matching the holder, integer `iat` not in the future, and an object `vc.credentialSubject`. If the subject has an `id`, it must equal the holder DID. Optional `nbf` is enforced. Missing or null `exp` is allowed for compatibility with existing issuance; a supplied expiration must be a valid future integer timestamp after issuance. Both enrolled identities must have an active, correctly sized public key.

The outer `iat`/`exp` interval must be positive, no more than five minutes, unexpired and not issued in the future. It cannot outlive the challenge or credential. This profile has no clock-skew allowance; hosts exchanging requests must maintain synchronized clocks.

Local credential verification checks the original issuer signature and whether any record for the same issuer tenant and exact JWT is revoked. Canonical encoding prevents an equivalent signature representation from missing that lookup. Multiple identical issuance records do not override a revoked match. This is local status enforcement, not an interoperable status-list service.

Presentation verification reads public identity/status columns, not encrypted private keys. Failure results have no disclosed claims, holder DID or issuer DIDs. The direct credential-verifier library has an older result shape that can include parsed fields on failure; callers must always check `IsValid`. REST credential verification already suppresses identity fields on failure.

## Request accounting

The credential verifier records a request before JWT parsing and signature work, including malformed or forged credentials that reach that verifier. The `CREDENTIAL_VERIFY` charge belongs to the actual requester: the holder during presentation creation and the verifier during presentation acceptance. The issuer's tenant scopes public DID and revocation lookups; naming an issuer must never let a caller spend that issuer's quota. Creation and verification each perform one original-credential check. If both requesters belong to the same tenant, they consume two operations in that tenant's window.

`VerifyCredentialAsync(tenantContext, credentialJwt)` remains tenant-local for both data lookup and accounting. The presentation service instead uses `VerifyCredentialFromIssuerAsync(requesterContext, issuerTenantId, credentialJwt)` after resolving the enrolled issuer and enforcing its stored trust policy. This public-record verification primitive grants no authority to act for the issuer. Both tenant identities must be non-empty. HTTP callers cannot select an alternate issuer tenant through the tenant-local REST endpoint.

## Migration from the mock presentation API

The legacy `CreatePresentationAsync` overload with `claimsToDisclose` always throws `NotSupportedException`, including when the selection is null. The legacy `VerifyPresentationAsync` overload taking disclosure tokens always returns an invalid challenge result for a nonempty input. Migrate to the challenge-based overloads and obtain explicit agreement to disclose the whole credential.

`SelectedDisclosures` remains an empty compatibility property. `DisclosedClaimNames` lists all subject claims. The service constructor now takes `ICredentialVerificationService`, `IPresentationChallengeStore` and `TimeProvider` in place of mock SD-JWT dependencies. `AddCredentialsServices()` registers the complete profile and no `ISdJwtGenerator`/`ISdJwtVerifier` mock.

Custom `ICredentialVerificationService` implementations must implement the new `VerifyCredentialFromIssuerAsync` member and preserve the separation between requester accounting and issuer lookup. Do not emulate it by replacing the requester context with an issuer context.

## Operational release gates

The default process-local store invalidates outstanding challenges after restart and does not coordinate across replicas. A production shared store must preserve owner/audience binding, bounded issuance, expiry, and one atomic consume operation. Do not replace it with separate distributed read/delete calls.

The default rate limiter is also process-local. Its separate allow and record calls are not an atomic reservation, so strict quotas under concurrent load require further implementation work. Cross-instance atomic quotas remain a production gate.

The current database enrollment/key-custody model, local revocation lookup and request model need further lifecycle and operational work before production use. State checks are not a distributed transaction spanning a relying party's later business action. This profile supplies proof validation; applications must define how promptly status changes affect their own authorization decisions.

Reference protocols for subsequent interoperability work: [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) and [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
