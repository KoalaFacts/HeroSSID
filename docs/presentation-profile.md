# Full-disclosure presentation profile

## Scope

This is a HeroSSID development library profile. It presents one complete JWT credential whose issuer and holder are enrolled in the same HeroSSID database. They may belong to different tenants, and the verifier may belong to a third tenant. It is not SD-JWT, a general W3C presentation conformance claim, or an OpenID4VP HTTP implementation.

The issuer's JWT is embedded unchanged. Every original claim is visible to the verifier. A holder signature proves control of the enrolled holder key for a particular verifier request; it does not replace issuer authentication.

## API and policy

`CreateChallenge(verifierContext, audience, trustedIssuerDid, lifetime)` issues a random 256-bit nonce. The store retains the authenticated verifier tenant, exact audience, trusted issuer DID and expiry. Default lifetime is two minutes, with a one-second minimum and five-minute maximum. Audience and issuer identifiers are limited to 2,048 characters. Nonces must be the canonical 43-character, unpadded base64url encoding of 32 bytes.

Both stores default to a global capacity of 1,024 and a per-tenant capacity of `min(128, global capacity)`. Constructors accept an explicit `tenantCapacity` between one and the global capacity. These caps do not evict live requests. Memory counts outstanding entries and removes consumed entries immediately. PostgreSQL counts **all retained rows**, including consumed replay tombstones, until expiry. Therefore a PostgreSQL caller cannot free storage capacity by rapidly issuing and consuming challenges; at capacity it must wait for expiry. The per-tenant limit protects space for other tenants when global capacity exceeds that limit; it is not a reservation or Sybil-resistance guarantee.

The trusted issuer is a verifier policy choice. A holder cannot change it by modifying challenge metadata or JWT claims. The credential type and application-specific claim requirements still need to be checked by the relying application after a valid presentation result. The verifier must validate the original JWT against those requirements as part of its acceptance workflow; a valid generic presentation alone does not grant business access.

`CreatePresentationAsync(holderContext, credentialJwt, holderDidId, challenge, cancellationToken)` first verifies the credential and holder ownership, then decrypts the tenant-owned holder key to sign. Its plaintext buffer is cleared after use. It never filters or re-signs issuer claims.

`VerifyPresentationAsync(verifierContext, presentationJwt, expectedAudience, expectedNonce, cancellationToken)` requires the verifier's retained request values. Values read from the submitted JWT must not be used as the application's expected values. Separate application/database scopes must share the store. Successful validation consumes the challenge atomically; expiry is checked again after potentially blocking consumption. If the proof expires during that operation, no identity fields are returned and the consumed challenge stays spent.

## Envelope and time precision

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
  "iat": 1792800000.999,
  "exp": 1792800001.999,
  "vp": {"verifiableCredential": ["<complete original credential JWT>"]}
}
```

The illustrative timestamps are not reusable challenges. Outer NumericDates accept integer or fractional JSON numbers. Expiry is retained at PostgreSQL's microsecond precision, rather than rounded down to whole seconds; normalization loses less than one microsecond. Callers parsing outer timestamps must support fractional NumericDates. Older integer envelopes are still accepted if all lifetime and binding checks pass.

The outer payload must have exactly these six properties, `vp` exactly one property, and the credential array exactly one string. Unknown headers and duplicate JSON properties are rejected. Both JWTs require canonical, unpadded base64url encoding. Maximum compact lengths are 65,536 characters for the original credential and 131,072 for the presentation; JSON nesting is limited to 16 levels.

The original credential must use `alg=EdDSA`, `typ=vc+jwt`, a trusted enrolled `iss`, `sub` matching the holder, integer `iat` not in the future, and an object `vc.credentialSubject`. If the subject has an `id`, it must equal the holder DID. Optional `nbf` is enforced. Missing or null `exp` is allowed for compatibility with existing issuance; a supplied expiration must be a valid future integer timestamp after issuance. This change does not broaden the original-credential timestamp profile. Both enrolled identities must have an active, correctly sized public key.

The outer `iat`/`exp` interval must be positive, no more than five minutes, unexpired and not issued in the future. It cannot outlive the challenge or credential. This profile has no clock-skew allowance. Application replicas and PostgreSQL must maintain synchronized UTC clocks. The PostgreSQL store combines the injected application clock with the database's actual `clock_timestamp()` for conservative expiry rejection; a lagging application clock cannot extend acceptance past the database's clock. Test clocks are explicit test dependencies, not a mechanism for operating unsynchronized production hosts.

Direct local credential verification also enforces the issuer-signed `sub`, nonfuture integer `iat`, `vc.type` containing `VerifiableCredential` and at least two non-blank entries (the existing issuer may emit the base type twice), an object `vc.credentialSubject`, an optional `credentialSubject.id` matching `sub`, and any supplied `nbf` before treating the signature as a valid credential. This is the local JWT profile rather than a claim of full VC 2.0 validation. Local credential verification checks the original issuer signature and whether any record for the same issuer tenant and exact JWT is revoked. Canonical encoding prevents an equivalent signature representation from missing that lookup. Multiple identical issuance records do not override a revoked match. This is local status enforcement, not an interoperable status-list service.

Presentation verification reads public identity/status columns, not encrypted private keys. Failure results have no disclosed claims, holder DID or issuer DIDs. The direct credential-verifier library and REST credential verification suppress identity fields on failure; callers must always check `IsValid` and still apply issuer-trust and application authorization policy.

## Request accounting

After cheap input validation and before challenge-store work, `CreateChallenge` atomically reserves `PRESENTATION_CHALLENGE_CREATE` for the verifier tenant. `VerifyPresentationAsync` reserves `PRESENTATION_VERIFY` for that same actual requester before querying the challenge store, including attempts with well-formed but unknown nonces. Oversized presentations/audiences and noncanonical nonces are rejected without store I/O. Quota exhaustion throws `InvalidOperationException`; hosts must map that deliberately rather than treating it as an accepted proof.

Presentation creation also reserves `PRESENTATION_CREATE` for the holder. The embedded-credential verifier separately reserves `CREDENTIAL_VERIFY` before its parsing and signature work. That charge belongs to the actual requester: the holder during creation and the verifier during acceptance. The issuer tenant scopes public DID and revocation lookups only; naming an issuer never permits spending its quota. If both requesters belong to one tenant, their original-credential checks spend two operations in that tenant's window.

`CreateChallenge` and the store interface remain synchronous. The service invokes an asynchronous limiter on the thread pool before synchronously waiting for its result, avoiding capture of the calling synchronization context; this is not an asynchronous issuance API. Hosts must account for blocking connection/lock waits and thread-pool demand. Direct store consumers bypass service request quotas and must enforce their own admission policy; storage ceilings still apply.

`VerifyCredentialAsync(tenantContext, credentialJwt)` remains tenant-local for data lookup and accounting. The presentation service uses `VerifyCredentialFromIssuerAsync(requesterContext, issuerTenantId, credentialJwt)` only after resolving the enrolled issuer and enforcing verifier trust policy. This grants no authority to act for the issuer. Both tenant identities must be non-empty. HTTP callers cannot select an alternate issuer tenant through the tenant-local REST endpoint.

## Migration and PostgreSQL operation

The opt-in store uses the separate `presentation_challenges` table. Apply migration `20261025033000_PresentationChallenges` explicitly before registering the store ahead of `AddCredentialsServices()`. It stores only verifier tenant, policy identifiers, random nonce, expiry and consumed timestamp, not credentials or keys. The nonce primary key and audience column use `C` collation to match ordinal SQL comparisons independently of database defaults.

Every replica must use the same database, schema and global/per-tenant capacity configuration. A Read Committed transaction and transaction-scoped advisory lock serialize expired-row cleanup, retained-row accounting and issuance. The issuance clock is sampled after admission waits, with expiry derived immediately before insertion. Consumption first obtains the matching row lock, then samples time and conditionally updates the still-live unconsumed row; concurrent consumers cannot both succeed. Database outages throw/fail closed, never fall back to an accepting in-memory store.

Consumed rows remain until their original expiry; expired rows are cleaned on the next successful issuance transaction. There is no background deletion job: an idle table can retain expired rows, but successful issuance cannot exceed the configured retained-row ceiling. PostgreSQL MVCC dead tuples/index bloat are not identical to retained live-row count; normal autovacuum, connection limits, timeouts and database monitoring remain operational responsibilities. Do not replace atomic consumption with separate distributed read/delete calls.

This migration is still an unreleased draft migration. Its ordinal column definitions were corrected before merge; a disposable database created from an earlier draft must be recreated or explicitly reconciled before testing the final schema. Do not assume `Migrate()` reapplies an already-recorded migration. `Down` drops the table and destroys outstanding/replay state; rollback after activation requires a reviewed operational plan. No production application of this migration is implied by CI or a code merge.

Integration tests use disposable PostgreSQL 17, independent connections and explicit observed advisory/row locks. Store-object replacement is not an independent-machine restart or outage-recovery certification. Operational multi-host/restart and failover exercises remain required.

## Migration from the mock presentation API

The legacy `CreatePresentationAsync` overload with `claimsToDisclose` always throws `NotSupportedException`, including when selection is null. The legacy verification overload taking disclosure tokens always returns an invalid challenge result for nonempty input. Use the challenge-based overloads and obtain agreement to disclose the whole credential.

`SelectedDisclosures` remains empty. `DisclosedClaimNames` lists all subject claims. The service constructor takes `ICredentialVerificationService`, `IPresentationChallengeStore` and `TimeProvider` instead of mock SD-JWT dependencies. `AddCredentialsServices()` registers no SD-JWT mock. Custom credential verifiers must preserve requester accounting versus issuer lookup; do not replace the requester context with issuer context.

## Remaining operational release gates

The default store invalidates challenges after restart and does not coordinate across replicas. PostgreSQL provides shared storage, not its deployment, recovery or production certification. The default `IRateLimiter.TryAcquireAsync` implementation is atomic only within one process; distributed request quotas remain unfinished. Legacy `IsAllowedAsync` plus `RecordOperationAsync` must not be combined for enforcement.

Enrollment/key custody, local revocation and request handling need further lifecycle and operational work. State checks are not one transaction spanning a relying party's later business action; the application must define how promptly status changes affect authorization. Signature validation alone does not establish real-world identity or business permission.

Reference protocols for subsequent interoperability: [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) and [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
