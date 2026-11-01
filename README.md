# HeroSSID

**Trustworthy, portable identity credentials for people, organisations and agents.**

HeroSSID is a development-stage .NET foundation for issuing, holding and verifying identity credentials. A wallet can hold credentials and obtain holder-signed presentations through the library. The current implementation uses locally enrolled identities; external wallet interoperability and production operation remain release gates.

## Implemented capabilities and boundaries

| Area | Implemented | Current boundary |
|---|---|---|
| Identities | `did:key` creation, Ed25519 keys, locally stored DID resolution | Remote DID resolution, signing-key rotation and recovery are unfinished |
| Issuer key succession (SDK + authenticated HTTP verifier) | Two independent Ed25519 issuer keys cross-sign an exact verifier-specific five-minute successor statement; verifiers may sign their own challenge using an active tenant-owned Ed25519 DID, and retain the previous trusted DID while atomically consuming a purpose-separated PostgreSQL nonce across replicas | DID keys are immutable; no automatic trust promotion, original-key compromise detection, issuer registration, lost-key recovery or wallet standard interoperability |
| Opt-in direct VC2 retired-issuer exact-JWT trust (.NET SDK) | Verifier independently pins SHA-256 of each original genuine retired-issuer VC2 JWT while allowing separately pinned active issuers; optional authentic same-signer short-lived status | No retroactive enrollment or trust promotion: new/backdated JWTs from retired keys fail without exact pins; caller owns the trusted inventory (up to 256 exact pins and 16 distinct issuer DIDs). A hash does not prove issue time, revocation freshness, holder control, real identity, authority or Wallet interoperability. See [VC2 retirement](docs/vcdm20-retired-issuer-exact-pins.md) |
| Opt-in retired VC2 issuer holder proof (SDK) | Full-disclosure VP with genuine holder Ed25519 proof and verifier-owned one-use nonce, followed by independent active/retired issuer exact-JWT pins, optional same-issuer signed status, and no claim release on failure | No user consent UI, standard OpenID4VP hosted exchange, third-party Wallet test, historical issue-time proof, live revocation, identity vetting or business authority; see [retired issuer holder proof](docs/vcdm20-retired-issuer-holder-proof.md) |\n| Explicit VC2 historical issuer trust (SDK) | `Vcdm20TrustedIssuerVerifier.TryVerify` accepts direct VC2 JWTs signed by up to 16 **independently pinned** historical/current issuer Ed25519 DIDs and returns only the authenticated signer/claims | No automatic promotion from key-successor attestation or untrusted JWT header, no lost-key recovery, issuer registration, holder proof, revocation, real identity or authorization; see [issuer trust transition](docs/vcdm20-explicit-issuer-trust.md) |
| REST ownership | Validated bearer `tenant_id`, exact operation scopes, tenant-owned DID creation and issuer lookup | An issuance-scope client can use any issuer DID owned by its tenant; per-client DID grants are future work |
| Credential issuance | Ed25519-signed JWT credentials and PostgreSQL persistence | Existing payloads use the 2018 credentials context; full VC 2.0 conformance is not established |
| Opt-in W3C VC 1.1 `jwt_vc_json` credential SDK and HTTP issue | Independent Ed25519 issuer signing, pinned offline verification and authenticated tenant-owned short-lived HTTP issue for unenrolled holders | HTTP issuance is not persisted or revocable through the legacy database route; no holder control, live status, identity vetting, OpenID4VCI or independent wallet interoperability | 
| VC1.1 retired issuer exact-JWT trust (SDK and authenticated HTTP, opt-in) | Verifier pins independently registered SHA-256 of each original `jwt_vc_json` JWT from a retired Ed25519 DID; still-valid historical credentials pass genuine original signature/policy checks, while freshly signed or backdated credentials from that retired key fail. Active issuer DIDs remain independently trusted; optional exact-signer private status. | Caller must establish trustworthy pin inventory before retirement; at most 256 exact pins, 16 distinct issuer DIDs, and each JWT still has a 15-minute maximum validity. A compromised old key may forge status; this does not prove issuance time, live non-revocation, holder control or authority. See [retired-key exact pins](docs/jwt-vc-json-retired-issuer-exact-pins.md) and [non-.NET HTTP verifier](docs/jwt-vc-json-retired-issuer-http-profile.md) |\n| Opt-in VC1.1 issuer-signed HTTP revocation export | An authenticated tenant-owned Ed25519 issuer can sign a bounded caller-observed complete revoked VC1.1 JWT set for non-.NET clients using both `credential:revoke` and `did:manage` | Private 60-second issuer-provided status; input completeness and observation honesty cannot be proven by HeroSSID, and HTTP-issued VC1.1 JWTs are not persisted/revocable through the legacy route |\n| Opt-in VC1.1 `jwt_vc_json` authenticated HTTP verification | Non-.NET verifiers pin one issuer or an independently enrolled list of 1–16 historical/current Ed25519 DID issuers; original VC1.1 JWT, holder, HTTPS type/context and optional **same actual signer** short-lived private status are authenticated before releasing signer and claims | Removing a DID from verifier trust rejects old credentials. `SignedNotListed` needs an authoritative complete status set and is not live non-revocation, holder control, identity vetting, authorization or wallet interoperability; see [HTTP trust contract](docs/jwt-vc-json-http-verify-profile.md#historical-and-current-issuer-verification-with-verifier-owned-trust-opt-in) |
| VC1.1 verifier-owned emergency exact-JWT denylist (.NET SDK, opt-in) | An independent relying party can block a specific authentic active-issuer or exact-pinned retired-issuer original JWT by its SHA-256, even when the issuer reports clean status; denial never releases issuer/subject claims | Verifier-local policy only; 256 canonical exact digests maximum, no automatic intake, shared-store synchronization, network revocation, proof of compromise, holder possession or authority. Distinguishes local denial from issuer-reported revocation. See [emergency denylist](docs/jwt-vc-json-verifier-emergency-denylist.md) |
| VC1.1 verifier-owned emergency denial over authenticated HTTP (opt-in) | Non-.NET relying parties can enforce their own canonical SHA-256 denylist of exact current/retired original VC1.1 JWTs through two explicit `credential:verify`-protected routes, with optional genuine same-issuer private status; denied, revoked and untrusted credentials release no issuer or subject claims | Verifier caller must provision, store and synchronize its own 0–256 exact SHA-256 fingerprints; legacy routes reject submitted denial policy instead of ignoring it. No shared/hosted denial registry, live revocation, holder control, identity or independent wallet interoperability. See [HTTP emergency denial](docs/jwt-vc-json-http-verifier-denylist.md) |
| Opt-in VC 1.1 `jwt_vc_json` holder-signed VP | Full-disclosure holder Ed25519 `vp+jwt` around unchanged issuer-signed VC1.1 JWT; authenticated HTTP signing of an active tenant-owned verifier DID request, independent holder pinning, shared one-use PostgreSQL challenge and both real signatures | Private `herossid-request+jwt` verifier handshake, **not** OpenID4VP 1.0 transport, real holder consent UI, external wallet interoperability or business authority |
| Opt-in `jwt_vc_json` OpenID4VP 1.0 direct_post SDK and HTTP launch | Ed25519 verifier request, authenticated HTTP issuance with canonical signed by-value `openid4vp://` wallet-invocation URI, independently pinned verifier/callback/issuer/type, holder-signed VP, atomic challenge; optional short-lived issuer-signed status for the exact enclosed VC1.1 JWT | Private issuer status needs an authoritative complete set; no public callback or `request_uri`, QR-length promise, live-status guarantee, third-party wallet conformance, actual consent UI, identity vetting or business authority |
| Opt-in VCDM 2.0 JOSE issuance/verification | Real Ed25519 direct VC 2.0 JWT; in-memory SDK, authenticated tenant-owned short-lived HTTP issue and independently pinned HTTP verify | HTTP issue is limited to 15 minutes and not persisted/revocable; no JSON-LD expansion, external conformance, holder proof or third-party wallet exchange |
| Opt-in direct VC2 verifier-owned emergency JWT denial (.NET SDK + authenticated HTTP) | Independently pinned historical/current Ed25519 issuer statements plus up to 256 verifier-owned exact original-JWT SHA-256 denials; opt-in `credential:verify`-protected non-.NET HTTP endpoints enforce the same policy, optionally checking the exact signer's 60-second status; invalid, denied and revoked statements disclose no issuer or subject | Verifier must provision and synchronize its own local denial list; legacy HTTP routes reject an unexpected denial policy. No shared registry, live revocation, holder control, identity vetting, authority or wallet interoperability; see [SDK](docs/vcdm20-verifier-emergency-denylist.md) and [HTTP contract](docs/vcdm20-http-verifier-denylist.md) |
| Opt-in VC2 historical issuer trust over HTTP | Authenticated non-.NET verifier can pin 1–16 independently enrolled historical/current Ed25519 issuer DIDs, verify original direct VC2 signatures and optional exact-signer issuer status, and receive the actual verified signer only after full verification | Verifier must separately protect and update its trust list; signed absence is not live non-revocation, holder control, identity vetting or authorization; see [HTTP trust policy](docs/vcdm20-http-verify-profile.md#explicit-historicalcurrent-issuer-http-verification-opt-in) |
| Opt-in VC2 holder presentation | Holder-signed direct `vp+jwt` with actual VC2 EnvelopedVerifiableCredential, signed verifier request pinning and atomic one-use challenge verification; opt-in verifier Ed25519 signed credential type and exact HTTPS context protect Wallet previews against substitution | Private HeroSSID request format; legacy requests do not bind type/context, and the server's durable challenge does not retain these policy fields. Full disclosure only; `SignedButStatusUnchecked` is not revocation, enrollment, identity verification, business authorization or third-party wallet conformance |
| Opt-in VC2 Wallet full-disclosure preflight | Authentic issuer-signed VC2 claims and the independently pinned verifier's real signed request are previewed without a holder key; an optional same-issuer signed 60-second status snapshot must be authentic and `SignedNotListed` before claims are exposed or the key is used; exact signed artifacts, status and claims are rechecked after Wallet-owned consent | Local opt-in SDK; issuer status set completeness and live non-revocation remain unproven; no consent evidence, selective disclosure, identity verification, authorization, standard OpenID4VP exchange or third-party wallet interoperability |
| Opt-in issuer-owned VC2 HTTP signed-status export | An authenticated tenant can sign an independently observed bounded complete list of original direct VC2 JWTs using its active owned Ed25519 issuer DID (both `credential:revoke` and `did:manage` required); non-.NET verifiers can check the exact signer and snapshot | Caller completeness and 60-second observation are not proven; no automatic revocation source, shared registry, live status, holder proof, third-party wallet or business authority; see [HTTP issuer contract](docs/vcdm20-http-signed-status-export.md) |
| Opt-in VC2 issuer-signed revocation snapshot | Separate `herossid-vc2-revocation-snapshot+jwt` authenticates a bounded, 60-second digest set of revoked direct VC2 JWTs; verifier can check exact holder-signed VP and signed status together before releasing claims | Private issuer-distributed profile, not W3C `credentialStatus`/Bitstring Status List, an authoritative revocation registry, real-time status or external wallet conformance |
| Credential verification | Enrolled issuer signature, required holder/issuance/type/subject structure, optional enforced `nbf`/expiration, local revocation checks; no identity fields on rejection | Local `vc+jwt` profile only; REST lookup is tenant-scoped, not independent issuer trust or business authorization |
| Presentation library and opt-in VC2 HTTP proof | Full-disclosure holder-signed VC2 `vp+jwt`; authenticated HTTP nonce issuance, explicit verifier cancellation and issuer+holder signature/status verification using a tenant-bound, one-use PostgreSQL challenge | Cancellation is tenant-scoped, not client-scoped, and cannot undo accepted disclosures; caller must obtain holder consent; status is a private issuer snapshot, not live or independently wallet-tested |
| OAuth | Client-credentials tokens with configured HS256 signing and validated tenant/scopes | Full OpenID4VCI issuance and OpenID4VP exchange are unfinished |
| Key storage | Encrypted private-key storage through ASP.NET Data Protection; plaintext buffers cleared after signing | Managed signer/HSM integration and signing-key lifecycle are unfinished |
| Revocation | Issuer-only `POST /api/v1/credentials/revoke` atomically revokes the exact locally issued JWT; subsequent credential and presentation verification reject it | Local issuer database only: no signed/public interoperable status-list publication, independent wallet lookup or external trust policy |
| Selective disclosure | Legacy calls fail closed; mock SD-JWT implementations are not registered by default | Real selective disclosure and independent interoperability tests are unfinished |

New `did:key` documents use the [Ed25519VerificationKey2020 document profile](docs/did-key-profile.md), including a multicodec-prefixed key and `assertionMethod`. Already persisted documents are **not** rewritten. Scoped clients can explicitly request `GET /api/v1/dids/{did}/canonical` to derive a current-format DID document from a stored public key **only after verifying that the key matches the exact DID**. Missing, foreign, deactivated, invalid-key records are not published by this path; the ordinary DID resolution path still returns the stored historical representation. This does not establish a public DID resolver or wallet interoperability. See the [legacy compatibility boundary](docs/did-key-profile.md).

Identity credentials express what an issuer attests. Whether that issuer is trusted for a particular claim, and what business actions a holder may take, remain explicit relying-party decisions. Enrollment alone does not establish a person's real-world identity.

## VC2 Wallet authenticated disclosure preflight (opt-in)

A Wallet integration can use Vcdm20WalletDisclosure.TryPrepare to independently verify its pinned HeroSSID verifier request and the unchanged original issuer-signed direct VC2 JWT **without a holder private key**, then show the full authenticated subject claims and destination. Following the Wallet application's own genuine informed-consent UI, CreateHolderPresentationAfterPreview revalidates the original signatures, challenge expiry and exact SHA-256-bound request/credential/subject before producing the real holder-signed VC2 VP. Swapped authentic credentials, changed requests, wrong signer and replay are rejected; verifier-side one-use challenge enforcement is unchanged. This is the private HeroSSID request profile, **not** OpenID4VP transport or evidence of consent, credential revocation, real-world identity, business authorization or independent third-party wallet interoperability. See [VC2 Wallet preflight and exact call examples](docs/vcdm20-wallet-disclosure-preflight.md).

For optional issuer-signed VC2 status enforcement **before the Wallet can preview claims or touch its private seed**, use `Vcdm20WalletDisclosure.TryPrepareWithStatus` and, after a fresh full-disclosure user decision, `CreateHolderPresentationAfterStatusPreview`. This binds an independently signed 60-second snapshot to the original verifier request and credential; a revoked, forged, missing, swapped or expired status fails closed. `SignedNotListed` is only a statement from an issuer-supplied set—not proof of complete or live non-revocation. See [the concrete status-aware Wallet example](docs/vcdm20-wallet-disclosure-preflight.md#optional-issuer-signed-status-before-the-holder-key).

## Offline historical/current VC1.1 issuer verification (opt-in)

`.NET 10` relying parties can now call `JwtVcJsonTrustedIssuerVerifier.Check` or `CheckWithStatus` against their **own** 1–16 independently pinned historical/current issuer Ed25519 `did:key` entries, with no HTTP or issuer database. The original VC1.1 `jwt_vc_json` signature and pinned holder/type/context are checked before returning actual signer and claims; optional private 60-second status must be signed by that **same actual issuer**. Revoked/invalid results release neither signer nor subject. Removing an issuer DID rejects its old credentials. This neither promotes trusted successors automatically nor establishes holder possession, complete/live revocation, identity, consent, authority or third-party Wallet interoperability. See the [offline verifier example and exact outcomes](docs/jwt-vc-json-offline-trusted-issuer-profile.md).

## Opt-in JWT VC JSON (VC Data Model 1.1) credential SDK

`JwtVcJsonCredential.Create` and `TryVerify` issue and independently validate an issuer-signed, short-lived **`jwt_vc_json`** nested VC 1.1 JWT with the standards-required `vc.@context` property, strict pinned issuer, holder, type and context, and genuine Ed25519 verification. This deliberately **does not change the current HeroSSID `vc.context` issuance paths or the existing `herossid_vc_jwt` OpenID4VP transport**. The separate opt-in `JwtVcJsonPresentation` now checks an actual holder Ed25519 signature and one-use verifier challenge **for this VC1.1 JWT**; the signed verifier request remains HeroSSID-specific, without an OpenID4VP exchange, consent UI, revocation or independently demonstrated third-party wallet interoperability. See [the VC1.1 issuer JWT profile](docs/jwt-vc-json-profile.md) and [the holder-signed nested VP contract](docs/jwt-vc-json-presentation-profile.md).

Authenticated non-.NET issuers can now `POST /api/v1/credentials/jwt-vc-json/issue` with `credential:issue` to sign a real short-lived VC1.1 `jwt_vc_json` for an **unenrolled external holder DID** using an active tenant-owned Ed25519 issuer. It enforces the shared issuance quota, matching subject ID, absolute HTTPS credential type, bounded context and validity, and private-key cleanup. The response is **issuer-signed only**; there is no credential persistence, database revocation, holder proof, live status or independent wallet interoperability. See the [exact HTTP issuance request and trust boundary](docs/jwt-vc-json-http-issue-profile.md).

## Issuer-signed VC1.1 revocation status export for external clients\n\nAuthorized non-.NET issuer backends can now `POST /api/v1/credentials/jwt-vc-json/sign-revocation-snapshot` with **both** `credential:revoke` and `did:manage` to sign an explicitly observed, bounded set of original issuer-signed VC1.1 JWTs. The active issuer DID and signing key must belong to the requesting tenant. The resulting private, 60-second snapshot can be supplied to existing VC1.1 verification or OpenID4VP HTTP flows; forged or foreign-issuer entries are rejected without signing. **The caller, not HeroSSID, must establish that the provided revoked set and observation time are complete and honest**; an omitted digest is not real-time clearance. No automatic persistence, revocation or status publication occurs. See [the HTTP export contract and limits](docs/jwt-vc-json-http-status-export-profile.md).\n\n## Authenticated VC1.1 `jwt_vc_json` verification for external relying parties

Non-.NET clients with `credential:verify` can now `POST /api/v1/credentials/jwt-vc-json/verify` to check the original issuer Ed25519 signature against independently pinned DID, holder DID, HTTPS credential type and subject vocabulary, returning signed subject claims only on `SignedButStatusUnchecked`. For a separate issuer-signed HeroSSID-specific 60-second revocation export, `POST /api/v1/credentials/jwt-vc-json/verify-with-status` returns claims only on `SignedNotListed`; `Revoked` and `Invalid` release no claims. A missing snapshot fails closed. These are authenticated **issuer-statement verification** endpoints, not holder-key proofs, OpenID4VP hosting, a standards-based revocation endpoint, live status, identity proof or business authority. `SignedNotListed` requires a complete authoritative issuer revocation set. See [the concrete HTTP verification contract](docs/jwt-vc-json-http-verify-profile.md).

## Opt-in `jwt_vc_json` OpenID4VP 1.0 direct_post SDK

`OpenId4VpJwtVcJsonDirectPost` now connects the separate real VC1.1 issuer and holder Ed25519 JWT signatures to a signed OpenID4VP 1.0 request and DCQL `jwt_vc_json` `vp_token` over `direct_post`. The verifier retains its own one-use challenge, the holder pins the verifier DID and HTTPS callback independently and must obtain informed full-disclosure consent, and the verifier checks both signatures and consumes the challenge atomically. This is an **SDK-only controlled subset**: the signed request still has private issuer/context policy fields. The optional `JwtVcJsonRevocationSnapshot` and `JwtVcJsonDirectPostRevocation.CheckResponseForm` bind a short-lived issuer-signed status export to the **exact issuer JWT inside the authenticated holder presentation**, returning subject claims only when its digest is `NotListed`. This is a private, issuer-distributed status profile: the caller must supply a complete authoritative revocation set, and `NotListed` is **not** a live non-revocation guarantee. There is no hosted endpoint, consent UI or independently demonstrated wallet interoperability. See [the exact protocol contract](docs/jwt-vc-json-openid4vp-direct-post-profile.md) and [the status-aware verification profile](docs/jwt-vc-json-revocation-direct-post-profile.md).

## Authenticated HTTP bridge for VC1.1 OpenID4VP `direct_post` (opt-in)

Non-.NET verifiers may now `POST /api/v1/credentials/jwt-vc-json/openid4vp/signed-request` with both `credential:verify` and `did:manage` scopes to issue a real verifier Ed25519-signed OpenID4VP 1.0 `jwt_vc_json` request, backed by an existing PostgreSQL one-use challenge. After their **separately hosted** HTTPS callback receives the holder's original `direct_post` body, they may forward it to the `credential:verify`-protected `/jwt-vc-json/openid4vp/verify-response` endpoint with a fresh issuer-signed private status snapshot; it releases subject claims only after real issuer and holder signatures, status and atomic challenge consumption. If the holder declines or a transaction is cancelled, the authenticated verifier backend can call `/jwt-vc-json/openid4vp/cancel-request` with both `credential:verify` and `did:manage` scopes to atomically invalidate the outstanding nonce; cancellation cannot retract an already accepted disclosure. The verification backend is **not** a public wallet callback and does not produce human-consent evidence. `SignedNotListed` is not a live non-revocation guarantee, and no independent third-party wallet interoperability or complete OpenID4VP conformance is claimed. See [the exact HTTP bridge contract](docs/jwt-vc-json-openid4vp-http-profile.md).

## Wallet full-disclosure preflight for VC1.1 OpenID4VP (opt-in)

A holder Wallet integrating the existing `jwt_vc_json` OpenID4VP `direct_post` SDK can call `OpenId4VpJwtVcJsonWalletDisclosure.TryPrepare` to verify the genuine Ed25519-signed **verifier request and unchanged issuer credential** against independently pinned verifier DID, HTTPS callback, trusted issuer, holder DID, credential type and context **before using any holder private key**. The result exposes all signed subject claims and the complete verifier/issuer policy for the application's real full-disclosure consent UI. Only after meaningful consent may the application call `CreateHolderResponseFormAfterPreview`, which revalidates both signed artifacts and rejects even legitimately signed credential/request swaps against the displayed preview. This is a usable wallet-SDK integration step, **not** a wallet UI, human-consent proof, live status check, real-world identity verification, authorization, selective disclosure, complete OpenID4VP conformance or evidence of third-party-wallet interoperability. See [wallet preflight and exact-artifact signing](docs/jwt-vc-json-wallet-disclosure-preflight.md).

A stricter opt-in VC1.1 Wallet path now calls `TryPrepareWithStatus` and `CreateHolderResponseFormAfterStatusPreview`. Before previewing claims or touching the holder seed, it authenticates a fresh **same-issuer, issuer-signed** private 60-second status snapshot for the unchanged original JWT; it rejects revoked, forged, expired, substituted and absent status, and rechecks the exact snapshot before and after signing. The verifier still must enforce its own one-use challenge and status. `NotListed` does **not** prove completeness or live non-revocation; the issuer-provided status is not a standard W3C status-list mechanism. See [the status-aware VC1.1 Wallet example](docs/jwt-vc-json-wallet-disclosure-preflight.md#optional-issuer-signed-vc11-status-before-any-wallet-disclosure).

## Opt-in W3C VC Data Model 2.0 JOSE signed credential library

`Vcdm20JoseCredential.Create` now creates a **direct** VC 2.0 JSON JWT with a genuine issuer `did:key` Ed25519 signature (not the legacy JWT `vc` object). Independently configured verifiers can call `TryVerify` to pin the issuer, subject, credential type and versioned HTTPS claim vocabulary before receiving signed claims. Incorrect keys, tampering, expired credentials and legacy tokens fail closed. This does not establish holder consent, reality-based identity, business authorization, revocation, JSON-LD expansion, standard conformance or external wallet interoperability. The existing database issuance and presentation APIs remain on their previous private format. See [the exact supported profile and usage](docs/vcdm20-jose-profile.md).

## VC2 verifier-request policy binding (opt-in)

An authenticated verifier using its active, tenant-owned Ed25519 DID may now include `expectedCredentialType` and `subjectContextUri` **together** when requesting `/api/v1/credentials/vcdm20/signed-presentation-request`. Both are signed into the original private `herossid-request+jwt`. A Wallet demanding verifier-bound type and vocabulary calls `OfflineSignedPresentationRequest.TryReadPolicyBound` or `Vcdm20WalletDisclosure.TryPrepareRequiringSignedPolicy` with independent trusted pins. Legitimate issuer-signed credentials of a different type/context cannot be substituted before full-disclosure preview or holder signing. Legacy six-field request compatibility remains, but cannot satisfy these strict policy-required calls. The original `/vcdm20/verify-presentation` endpoint still relies on the authenticated relying party's submitted type/context; the opt-in `/vcdm20/verify-signed-policy-presentation` additionally requires the genuine eight-field verifier-signed JWT, validates active tenant-owned verifier key and exactly matches its issuer/nonce/expiry to the retained challenge before accepting holder proof and issuer-signed status. The database still does not persist type/context or signed-request digest, so relying parties must themselves pin the exact originally requested JWT to prevent an alternate authentic request signed by the same verifier key for the same nonce. This is not OpenID4VP, external Wallet interoperability, human consent, identity verification or business authorization. See the [complete HTTPS verifier/Wallet example and security boundary](docs/vcdm20-presentation-http-profile.md#bind-the-verifiers-credential-type-and-subject-vocabulary-opt-in).

## Opt-in VC2 holder-signed EnvelopedVerifiableCredential

An independent holder can now use its own Ed25519 key to sign a direct VC2 `vp+jwt` around an unchanged issuer-signed VC2 JWT. `Vcdm20JosePresentation.Create` first verifies the pinned verifier signed request and real issuer signature. An independent verifier uses `Check` with its own issuer/context/type policy and one-use challenge store to verify issuer and holder signatures and consume the nonce atomically. **The result is `SignedButStatusUnchecked`, not active or unrevoked.** This library has no consent UI, hosted OpenID4VP endpoint or independent external-wallet validation. The caller still needs status, informed full-disclosure consent, real-world identity policy and business authorization. See [the exact supported profile](docs/vcdm20-jose-presentation-profile.md).

## Opt-in VC2 issuer-signed status for independent verifiers

The issuer can use `Vcdm20RevocationSnapshot.Create` with its own Ed25519 seed, a **complete externally maintained set** of revoked direct VC2 JWTs and the clock time recorded *before* the external status read. This signs an issuer-bound, at-most-60-second, at-most-256-entry digest snapshot. The independently configured verifier may call `Check` for the original credential or `CheckPresentation` to combine holder signature, one-use verifier challenge, the authentic original issuer VC2 and signed status, releasing claims only on `SignedNotListed`. The library has **no VC2 database revocation workflow or automatic publication**, so upstream completeness and issuer authorization remain essential. This is a HeroSSID-specific proof and **not** a standard W3C status-list mechanism. See [the full status, trust and privacy limits](docs/vcdm20-revocation-snapshot-profile.md).

## Authenticated short-lived direct VC2 issuance (opt-in)

A tenant with `credential:issue` can now `POST /api/v1/credentials/vcdm20/issue` to sign a **real** direct VC2 JWT with its active, self-certifying `did:key` issuer for an external, unenrolled holder. The `credentialSubject.id` must match that holder, and validity is limited to 15 minutes; issuer ownership, key match and the existing shared issuance quota are enforced. **This path does not persist credentials or support revocation.** `SignedButStatusUnchecked` verifies an issuer statement only, not holder control, current status, real-world identity or authorization. See [the precise HTTP issuance contract and limits](docs/vcdm20-http-issue-profile.md).

## Authenticated HTTP verification of direct VC2 JWTs (opt-in)

Non-.NET clients may now POST to `/api/v1/credentials/vcdm20/verify` with `credential:verify` scope, the original issuer-signed direct VC2 JWT and **independently pinned** expected issuer DID, subject DID, credential type and HTTPS claim vocabulary. Only authentic signed claims are returned with status `SignedButStatusUnchecked`; malformed/tampered/expired/foreign credentials fail without disclosing unverified claims. This verifies an issuer **statement only**: no holder proof, consent, active status, identity vetting, authorization or independent wallet interoperability is implied. See [the HTTP request and response contract](docs/vcdm20-http-verify-profile.md).

## Authenticated direct VC2 credential and issuer status verification (opt-in)

Non-.NET relying parties can now POST to `/api/v1/credentials/vcdm20/verify-with-status` with `credential:verify` scope. A real direct VC2 issuer JWT and a separate, no-older-than-60-second HeroSSID issuer-signed status snapshot are checked against the caller's **independently pinned** issuer DID, holder DID, credential type and HTTPS claim vocabulary. Only `SignedNotListed` returns the verified subject; `Revoked` and `Invalid` disclose no claims. This is a usable HTTP adapter for the already-implemented VC2 signature and issuer status checks, **not** a VC2 issuer status publication service, a W3C Bitstring Status List or a proof of holder-key control. An omitted digest could still reflect an incomplete issuer-maintained status set; an accepted result does not establish live non-revocation, real-world identity or business authorization. See [the request contract and threat boundaries](docs/vcdm20-http-status-verify-profile.md).

## Authenticated VC1.1 jwt_vc_json holder-proof HTTP verification (opt-in)

Authenticated verifiers can now obtain a **genuine verifier-signed** one-use VC1.1 request through `POST /api/v1/credentials/jwt-vc-json/signed-presentation-request` using their active, tenant-owned DID and **both** `credential:verify` and `did:manage` scopes. This reuses the existing format-neutral Ed25519 request signer and durable PostgreSQL nonce, so the holder can independently pin the verifier DID and HTTPS audience before signing. Alternatively, clients holding their own verifier signing key can issue an unsigned tenant-bound challenge through `POST /api/v1/credentials/jwt-vc-json/presentation-challenge` and sign it themselves using `OfflineSignedPresentationRequest.Create`; an unsigned challenge alone is never a verifier proof. Either flow can verify a genuine **holder-signed** `vp+jwt`, the unchanged issuer-signed `jwt_vc_json`, and same-issuer signed short-lived status via `POST /api/v1/credentials/jwt-vc-json/verify-presentation`. Unlike issuer-only `/jwt-vc-json/verify`, this validates **both** signing keys and atomically consumes a shared PostgreSQL challenge. Only `SignedNotListed` releases subject claims. The verifier independently pins the issuer/type/context and the holder must separately pin the verifier and affirmatively consent to full disclosure. This is a **private HTTP profile**, not a hosted OpenID4VP endpoint, real-time non-revocation, identity verification, authorization or third-party wallet interoperability; see [the exact HTTP contract](docs/jwt-vc-json-presentation-http-profile.md).

## Authenticated VC2 holder-control HTTP verification (opt-in)

A non-.NET verifier with an authenticated `credential:verify` client can now issue its own tenant-bound challenge via `POST /api/v1/credentials/vcdm20/presentation-challenge` and submit a holder-signed VC2 presentation to `POST /api/v1/credentials/vcdm20/verify-presentation`. Unlike the direct credential `/vcdm20/verify` endpoint, this path verifies **the holder's real Ed25519 signature and single-use challenge as well as the issuer's signature and separate short-lived issuer-signed revocation snapshot**. Only `SignedNotListed` includes verified subject claims; revoked, forged, expired, foreign-tenant or replayed presentations return no claims. All HTTP replicas must share the **existing migrated PostgreSQL** `presentation_challenges` table, not an in-memory challenge store.

For non-.NET verifier clients, the new `POST /api/v1/credentials/vcdm20/signed-presentation-request` signs and retains a one-time challenge using an **active verifier did:key owned by the authenticated verifier tenant**, never using a holder key. It requires **both** `credential:verify` and `did:manage` (verification alone cannot authorize server-side key use), enforces tenant ownership and bounded HTTPS audience/issuer/expiry, and returns a real Ed25519 signed `herossid-request+jwt`. Alternatively, a verifier with its own separately controlled seed can continue signing a `/presentation-challenge` response locally using `OfflineSignedPresentationRequest.Create`. Either way, the holder pins the verifier DID and exact audience independently, checks all claims, obtains informed full-disclosure consent, and signs via `Vcdm20JosePresentation.Create` with the holder's **own** key. HeroSSID still does not host a wallet or prove consent. The issuer must separately publish a complete, authentic 60-second HeroSSID VC2 status snapshot. See [the HTTP contract, signing choreography and trust limits](docs/vcdm20-presentation-http-profile.md). `SignedNotListed` does **not** imply live status, reality-based identity, business authority, OpenID4VP conformance or third-party wallet interoperability.

## HTTP ingress and caller isolation

HTTP requests now have distinct budgets for validated tenant/client identities instead of relying on the usually absent `Identity.Name`; anonymous requests are bounded by the connecting peer IP, with a separate process-wide ceiling. In a TLS-terminating reverse-proxy deployment, `Ingress:ForwardedHeaders:Enabled=true` requires an explicit list of trusted proxy addresses or networks; only then are one-hop forwarded client IP and HTTPS scheme accepted **before** redirection and rate limiting. No arbitrary caller-supplied forwarded header is trusted. The ingress proxy itself must sanitize headers, and limits are process-local, not distributed. See [the exact deployment configuration, threat model and limitations](docs/ingress-rate-limits.md).

## Local development

Prerequisites: .NET 10 SDK (LTS; projects target `net10.0`), a reachable PostgreSQL instance, and Docker for the container-backed integration/HTTP contract tests. The examples below bind development services to localhost.

```bash
git clone https://github.com/KoalaFacts/HeroSSID.git
cd HeroSSID
dotnet restore
dotnet build --configuration Release

# In a separate terminal, start a disposable development database.
docker run --rm --name herossid-dev-db \
  -e POSTGRES_DB=herossid -e POSTGRES_PASSWORD=postgres \
  -p 127.0.0.1:5432:5432 postgres:17
```

Configure the API and start it:

```bash
export ASPNETCORE_ENVIRONMENT=Development
export ConnectionStrings__HeroDb='Host=localhost;Port=5432;Database=herossid;Username=postgres'
export HEROSSID_DB_PASSWORD=postgres
export Jwt__Secret="$(openssl rand -base64 48)"
dotnet run --project src/Services/HeroSSID.Api --no-launch-profile --urls http://localhost:5139
```

`Jwt__Secret` is required in every environment. Missing, whitespace, shorter-than-32-byte UTF-8 values, NUL-containing values and the previous placeholder are rejected at startup. Use a stable managed secret outside disposable development; changing it invalidates outstanding access tokens. `Jwt__Issuer` and `Jwt__Audience` must be explicitly configured outside Development. In Development they default to `https://herossid.api`. They identify access-token validation policy, not a requirement that the local HTTP server use that hostname.

Development startup creates `test_client` / `test_secret` with `did:manage credential:issue credential:verify credential:revoke`. These are deliberately public local-development credentials. Existing seed rows are not overwritten: a retained development database needs any new operation scopes explicitly provisioned to its test client; seeding does not elevate existing clients. Production client provisioning is a separate operational responsibility.

```bash
curl http://localhost:5139/oauth2/token \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'client_id=test_client' \
  --data-urlencode 'client_secret=test_secret' \
  --data-urlencode 'scope=did:manage credential:issue credential:verify credential:revoke'
```

Use the returned `access_token` as `Authorization: Bearer <access_token>` on every identity/credential REST operation. Tokens must contain exactly one scalar JSON string `tenant_id` containing a non-empty GUID; duplicate raw JSON members and tenant arrays are rejected. Missing or invalid bearer identities receive 401; valid identities lacking the operation scope receive 403. Repeated `scope` claims and a space-separated scope claim are accepted with exact, case-sensitive matching.

| Operation | Required scope |
|---|---|
| `POST /api/v1/dids` | `did:manage` |
| `GET /api/v1/dids/{did}` | `did:manage` |
| `POST /api/v1/credentials/issue` | `credential:issue` |
| `POST /api/v1/credentials/verify` | `credential:verify` |
| `POST /api/v1/credentials/revoke` | `credential:revoke` |

DID creation accepts `{"method":"did:key","keyType":"Ed25519"}`. Issuance accepts `issuerDid`, `holderDid`, `credentialType` and a non-empty `claims` object. Verification and issuer revocation both accept `{"credential":"<issued JWT>"}`. Revocation requires its **own** scope, not simply `credential:issue` or possession of the JWT; only exact credentials stored under the authenticated tenant and its issuer DID can be revoked. It returns `204` on first or repeated revocation, `404` for unknown/foreign credentials without distinguishing them, and `400` on malformed inputs. Revoked credentials fail closed during local direct verification and library presentation; a remote wallet/verifier is **not** independently notified. This operation is not a W3C status list. Verification accepts `{"credential":"<issued JWT>"}`. Both issuer and holder must already be enrolled locally, and issuance uses only an issuer belonging to the token's tenant. See [the HTTP request examples](src/Services/HeroSSID.Api/HeroSSID.Api.http).

## Issuer-signed revocation snapshot export (HeroSSID profile)

An issuer with `credential:revoke` scope can call `POST /api/v1/credentials/revocation-snapshot`
with `{"issuerDid":"did:key:z..."}` after issuing and optionally revoking JWT credentials.
The API returns a **one-minute Ed25519-signed JWS snapshot** of the complete set
of revoked credential JWT SHA-256 digests for that active, tenant-owned
self-certifying issuer DID. It never returns the original JWTs or holder claims.
An issuer may explicitly distribute the resulting artifact to independent
verifiers, who can use `IssuerRevocationSnapshot.Check` offline with a previously
trusted issuer DID/public key and the original credential. `Revoked` means
that JWT's digest appears in the signed set; `NotListed` is **not**
proof of valid issuance or active status. Verifiers must separately validate
the original credential's signature, expiry, holder binding, issuer trust
and business authorization; publication is not automatic.

Snapshots contain a maximum of 256 revoked records; exports above that
limit fail with HTTP 409 rather than sign a partial list. Snapshots expire at most 60 seconds after the revocation-status read begins,
not 60 seconds after signing completes. Database and signing delays shorten
usable lifetime; exports that exceed this budget return HTTP 503 without a
snapshot. The issuer must refresh after each revocation; old exported copies
can remain stale until their expiry. Revoked
JWT digests are linkable by parties who possess those JWTs, and the count
is disclosed to recipients. This is a bounded **HeroSSID-specific signing
and offline-check profile**, not a W3C Bitstring Status List, a hosted
public status endpoint, general non-revocation proof or independent wallet
conformance result. The database schema is unchanged. See
[the threat model and verification instructions](docs/revocation-snapshot-profile.md).

## OpenID4VP 1.0 direct_post library subset (not independently interoperable)

Independent verifier and holder apps can exchange a real DID:key/Ed25519-signed
OpenID4VP 1.0 JAR request and a form-encoded `vp_token` response using
`OpenId4VpDirectPost`. The verifier stores its own one-use nonce, the holder
pins its verifier DID and exact HTTPS callback before full-disclosure consent,
and the verifier checks the issuer, holder, signed status and replay state.
This is a **development library wire profile** using a deployment-defined
`herossid_vc_jwt` credential format because existing issuer credentials are
not conforming `jwt_vc_json`. There is **no hosted HTTP endpoint, no consent
UI and no independently tested third-party wallet**. See the
[exact 1.0 exchange and trust boundaries](docs/openid4vp-direct-post-profile.md).

## Authenticated offline verifier request (HeroSSID profile)

A separately operated verifier can issue a verifier-owned challenge using
`IPresentationChallengeStore.Issue`, and sign its exact nonce, audience, trusted
issuer DID and fractional expiry with
`OfflineSignedPresentationRequest.Create(challenge, verifierDid, verifierPrivateSeed, clock)`.
The resulting `herossid-request+jwt` is verifiable by a holder without contacting
HeroSSID or the issuer. A holder pins **both** the verifier's `did:key` and
the expected audience from independently trusted configuration and calls
`OfflineSignedPresentationRequest.TryRead` before displaying the complete
credential claims and requesting consent. After consent,
`CreatePresentation` validates the signed request again and produces the
existing holder-signed full-disclosure `vp+jwt`. The verifier still checks
the response using its own retained one-use challenge and a fresh signed issuer
revocation snapshot; no verifier policy is taken from the holder.

Unlike the previous unauthenticated challenge copy, a modified request or
impersonating signer is now rejected **before a holder signs or discloses**.
A syntactically valid self-certifying verifier DID is not proof of a trustworthy
organisation, real identity or business authority. Verifier trust must be
established independently; a caller must not trust `iss` copied from the
request, and a UI/transport must honour the pinned destination and obtain
full-disclosure consent. This is a HeroSSID-specific offline JWS request
artifact, **not** OpenID4VP, a hosted exchange endpoint or independent wallet
interoperability. See [the request threat model](docs/presentation-profile.md#offline-signed-verifier-requests).

## Offline issuer credential and revocation verification

A separate .NET relying party can now call `OfflineCredentialVerifier.Check`
with its **independently trusted issuer `did:key`**, an original signed
`vc+jwt`, and a short-lived signed snapshot. It derives the self-certifying
Ed25519 key from that DID and checks both signatures, credential structure,
issuance/not-before/expiry, and status without the issuing database.
Outcomes are `Invalid`, `Revoked`, or `SignedNotListed`; the last
means **signed and absent from this snapshot**, not registered, unrevoked
in real time, proof of holder control, or business authorization. See
[the offline verifier acceptance and limitations](docs/offline-credential-verification.md).
This remains the HeroSSID private JWT profile, not independent-wallet or
VC-standard conformance.

## Offline holder-signed presentation verification (HeroSSID profile)

A separate .NET verifier can now validate **the actual holder's Ed25519
signature** over a full-disclosure `vp+jwt`, the *unchanged* issuer-signed
`vc+jwt` inside it, and a fresh **issuer-signed** revocation snapshot,
without issuer database access. The verifier first chooses a trusted issuer
under its own policy and issues an unpredictable single-use challenge:

```csharp
// The verifier provisions and owns the same challenge store for issuance and checks.
// Use a shared PostgreSQL implementation for replay protection across replicas.
var clock = TimeProvider.System;
IPresentationChallengeStore challenges = new InMemoryPresentationChallengeStore(clock);
var verifierTenantId = Guid.NewGuid(); // replace with the authenticated verifier tenant
var request = challenges.Issue(verifierTenantId,
    "https://verifier.example/check", independentlyTrustedIssuerDid);

// Give request.Audience, request.Nonce and request.ExpiresAt to the holder.
// Receive a full-disclosure holder-signed vp+jwt and a separately issued
// short-lived issuer-signed revocation snapshot through a trusted workflow.
var outcome = OfflinePresentationVerifier.Check(
    holderPresentationJwt, issuerSignedSnapshotJwt, verifierTenantId,
    request.Audience, request.Nonce, challenges, clock);
```

`SignedNotListed` means the **real issuer and holder signatures** and
challenge binding passed, the revocation snapshot does not list the original
JWT, and the challenge was consumed **atomically exactly once**. `Revoked`
means the verified original JWT appears in the authentic snapshot. All other
errors including forgery, wrong subject/issuer, replay, tampering, expired
proof/status or mismatched audience fail closed as `Invalid`. No rejected
claims or holder identifiers are returned. A valid `did:key` is a
self-certifying public key, **not** evidence that a real-world person was
enrolled. A relying party still needs issuer trust, claim policy and business
authorization; `SignedNotListed` is not proof of live issuer status.

This is a **library integration** of the HeroSSID full-disclosure profile,
not a deployed endpoint, independent third-party wallet test, SD-JWT or
OpenID4VP implementation. Direct consumers must limit request volume and
handle challenge-store failures; the memory store loses pending challenges on
restart and cannot prevent cross-process replay. See
[the presentation profile](docs/presentation-profile.md) and
[offline issuer verification limits](docs/offline-credential-verification.md).

## Offline holder-side presentation creation

A holder with its **own Ed25519 private seed** can now create the
full-disclosure HeroSSID `vp+jwt` proof *without a HeroSSID account,
holder-key escrow, issuer database or network call*. This closes the
previous library-only-verifier gap: the separately controlled holder
can actually sign a response to the verifier's retained challenge.

```csharp
// The verifier independently chooses its trusted issuer and issues the
// challenge from its own IPresentationChallengeStore.
PresentationChallenge request = verifierChallenges.Issue(
    verifierTenantId, verifierAudience, trustedIssuerDid);

// The holder MUST examine and consent to the destination, requested issuer
// and disclosure of every claim in originalCredentialJwt.
string presentationJwt = OfflinePresentationCreator.Create(
    request, originalCredentialJwt, holderDid, holderOwnedEd25519Seed,
    TimeProvider.System);

// Transfer the unchanged issuer-signed credential inside the holder proof.
// The relying party validates with OfflinePresentationVerifier.Check and its
// OWN stored request, trusted issuer policy and fresh signed status snapshot.
```

The creator checks the original credential's actual issuer signature,
holder/issuer DID binding, credential timestamps, the challenge nonce and
expiry, and that the holder's seed really controls its `did:key`. It
preserves the **exact original credential** and fractional challenge
expiry. The caller owns the private-key buffer and must clear it after
use; the creator neither persists it nor wipes caller-owned memory.
The verifier still checks all signatures, status and atomic replay
protection independently. The challenge object by itself is **not a
signed request or authenticated verifier**; a wallet must confirm
recipient and full-claim disclosure out of band.

This is a C# library profile, **not OpenID4VP**, SD-JWT, third-party
wallet interoperability, live revocation proof, identity verification
or business authorization. See [holder-side and verifier
boundaries](docs/presentation-profile.md#offline-holder-side-creation).

## Full-disclosure presentation library

Register `AddCredentialsServices()` alongside the database, key-encryption and rate-limiter dependencies. It registers a singleton challenge store and `TimeProvider.System`; a host can register its own implementations before this call.

```csharp
// Contexts come from trusted application authentication, never a request body's tenant ID.
var challenge = presentations.CreateChallenge(
    verifierContext, "https://verifier.example/credentials", trustedIssuerDid);

// This discloses the entire original credential, including every subject claim.
var presentation = await presentations.CreatePresentationAsync(
    holderContext, originalCredentialJwt, holderDidId, challenge, cancellationToken);

var result = await presentations.VerifyPresentationAsync(
    verifierContext, presentation.PresentationJwt,
    challenge.Audience, challenge.Nonce, cancellationToken);
```

Issuer, holder and verifier may belong to three different tenants. The verifier retains its own challenge and trusted-issuer policy. Successful verification consumes the challenge once; failed presentations return no disclosed claims or identity fields. Applications still need to evaluate credential type and business-specific claims before granting access.

Outer presentation timestamps support fractional NumericDates so a one-second challenge does not lose nearly its entire lifetime at a second boundary. Old integer timestamps remain accepted. Both proof and credential expiry are rechecked after blocking consumption; rejection after consumption leaves the nonce spent. The original credential timestamp profile is unchanged.

Read [the presentation profile and migration notes](docs/presentation-profile.md) before integrating. This local full-disclosure profile is not SD-JWT or an OpenID4VP implementation.

## Credential verification result safety

A successful direct `vc+jwt` verification now requires signed, non-empty `iss` and `sub`, integer `iat` no later than the verification clock, and an object `vc.credentialSubject`. The `vc.type` array must contain `VerifiableCredential` and every entry must be a non-blank string. Existing signed singleton-base credentials remain valid, as does the issuer API’s duplicate-base output when that credential type is requested. This structural check does not itself establish a specific qualification or business authorization. If the subject has an `id`, it must equal `sub`. A supplied integer `nbf` must not be in the future. Missing or `null` expiration remains supported; a supplied expiration must be a valid integer and must not have passed. Violations return `MalformedJwt`, except expired credentials return `Expired`. These checks establish neither independent wallet compatibility nor the verifier's authorization to act for the holder.

`VerifyCredentialAsync` and `VerifyCredentialFromIssuerAsync` return `CredentialSubject`, `IssuerDid` and `ExpiresAt` only for successful verification. Every rejected result leaves those fields null, while preserving `IsValid=false`, its status and diagnostic errors. Expiry errors no longer echo the parsed timestamp. This is an intentional tightening of the library contract: integrations that previously used parsed metadata from rejected results must stop relying on those values. Valid credential results are unchanged; consumers must still check `IsValid` and apply issuer trust and business authorization policy.

The `.NET 10` retarget changes the required runtime and patched ASP.NET Core, EF Core, Npgsql, Aspire and OpenIddict dependencies. Before upgrading an existing deployment, review runtime/container image compatibility and test the prior database schema and persisted token/credential behaviour in an isolated environment; upgrading a production runtime or applying migrations is not part of the source-code change.

## Verification and development

```bash
# Focused credential/auth suites (no PostgreSQL container required)
dotnet test tests/Unit/HeroSSID.Credentials.Tests --configuration Release
dotnet test tests/Unit/HeroSSID.Api.Tests --configuration Release

# Full solution: Docker must be available for PostgreSQL-backed suites.
dotnet test HeroSSID.sln --configuration Release
```

DID key creation relies on NSec's cryptographic provider for randomness. It no longer draws and rejects a separate 256-byte sample using chi-square/uniqueness thresholds: a statistically unusual but legitimate CSPRNG sample is not evidence that its provider failed. Provider errors still abort creation, and exported Ed25519 keys must have the correct lengths, contain no all-zero key material and pass a real sign/verify self-check before storage; failed exported-key checks scrub both buffers. These are operational safeguards, not a certification of the host RNG or external wallet interoperability.

The default in-memory limiter reserves permits atomically per tenant and operation. Challenge creation and presentation verification now also reserve permits before challenge-store I/O, including unknown-nonce attempts. Issuance and presentation creation charge attempts before costly work, even on failure. This protects one process only, not multiple replicas; alternative `IRateLimiter` implementations must provide atomic `TryAcquireAsync`. Legacy `IsAllowedAsync` plus `RecordOperationAsync` is for observation/recording, not enforcement.

The repository currently contains xUnit v2 and v3 projects. The credential suite retains two pre-existing skipped concurrency tests that use a shared DbContext; the presentation replay test uses separate database scopes and a shared challenge store. PostgreSQL tests exercise real advisory/row-lock waits and check that verification SQL does not select private-key columns. Test names containing “OpenID4VC” cover existing HTTP contracts, not certification. Replacement store objects and connections are not independent-machine restart/failover tests.

A PostgreSQL challenge store is an opt-in alternative to the process-local default. Apply the `PresentationChallenges` migration explicitly before enabling it, then register the shared data source and store **before** `AddCredentialsServices()`:

```csharp
services.AddSingleton(Npgsql.NpgsqlDataSource.Create(postgresConnectionString));
services.AddSingleton<IPresentationChallengeStore, PostgresPresentationChallengeStore>();
services.AddCredentialsServices();
```

Every replica must use the same database and capacity configuration. Defaults are 1,024 globally and 128 per verifier tenant (or the smaller global limit). PostgreSQL counts **all retained rows**, including consumed replay tombstones, until expiry; memory removes consumed entries immediately. Constructors allow an explicit `tenantCapacity`. Admission serializes cleanup, counting and insertion under a transaction/advisory lock. Consumption obtains the matching row lock and performs a fresh-time conditional update. Both operations fail closed on database failure; application and database clocks must be synchronized.

The nonce primary key and audience storage use `C` collation to match ordinal queries. The unreleased migration was amended during review: recreate or explicitly reconcile disposable databases that applied an earlier draft; migration history does not automatically reapply changed definitions. Do not apply or roll back a production migration merely because CI passes. Public synchronous store methods block on PostgreSQL; synchronous challenge creation also waits for limiter admission. Account for thread-pool demand, database timeouts, cleanup and autovacuum. Distributed request quotas and OpenID4VP HTTP remain unfinished.

Production readiness still requires shared challenge deployment and operations, distributed request quotas, complete signing-key and revocation lifecycles, interoperability testing, operational controls and independent security review. No production-readiness or standards-conformance certification is claimed.

## Documentation

- [Vision and delivery milestones](docs/VISION.md)
- [Presentation profile and migration](docs/presentation-profile.md)
- [Trust foundation design](docs/superpowers/specs/2026-10-24-credential-trust-design.md)
- [Implementation and verification plan](docs/superpowers/plans/2026-10-24-credential-trust-foundation.md)
- [Challenge remediation evidence](docs/verification/2026-10-27-challenge-review.md)
- [Testing guide](docs/testing-guide.md)

The applicable upstream specifications include [DID Core](https://www.w3.org/TR/did-core/), [VC Data Model](https://www.w3.org/TR/vc-data-model-2.0/), [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) and [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html). These are implementation targets; linking them is not a conformance assertion.
