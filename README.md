# HeroSSID

**Trustworthy, portable identity credentials for people, organisations and agents.**

HeroSSID is a development-stage .NET foundation for issuing, holding and verifying identity credentials. A wallet can hold credentials and obtain holder-signed presentations through the library. The current implementation uses locally enrolled identities; external wallet interoperability and production operation remain release gates.

For issuer-only checks without a hosted service, the .NET 10 CLI supports
[VC1.1 `jwt_vc_json`](docs/cli-vc11-issuer-check.md),
[separately pinned `did:web` VC1.1 issuer keys](docs/cli-vc11-didweb-issuer-check.md),
[separately pinned `did:web` direct VC2 issuer keys and opt-in exact signed HTTPS recipient](docs/cli-vc2-didweb-issuer-check.md),
[an exact signed VC2 did:web recipient-scoped membership claim](docs/cli-vc2-didweb-recipient-claim.md),
[direct VCDM 2.0 `vc+jwt` JOSE](docs/cli-vc2-jose-issuer-check.md), and a
[recipient-bound direct VC2 JWT with exact signed credential ID](docs/cli-vc2-recipient-bound-check.md),
and [an exact issuer-signed VC2 string claim under verifier-pinned recipient policy](docs/cli-vc2-recipient-claim-check.md).
All require independently verifier-pinned trust policy and real Ed25519 issuer
signatures. Even signed recipient binding does **not** prove holder private-key
control, consent, current status, identity vetting, Agent authority or
independent wallet interoperability.

## Implemented capabilities and boundaries

| Area | Implemented | Current boundary |
|---|---|---|
| Identities | `did:key` creation, Ed25519 keys, locally stored DID resolution | Remote DID resolution, signing-key rotation and recovery are unfinished |
| Opt-in offline `did:web` document preparation (.NET SDK) | A caller with its own Ed25519 public key and independently controlled DNS/HTTPS domain can construct a restricted `did:web` identifier, the matching DID Core JSON-LD document, and its exact `.well-known` or path-based publication URI; see [publishing guide](docs/did-web-offline-publishing.md) | No hosting, TLS/DNS/domain ownership verification, remote DID resolution, key custody, credential verifier trust enrollment, organisation identity proof, Agent authority or third-party interoperability; existing `did:key` verification policies stay unchanged |
| Opt-in operator-pinned root `did:web` publication (trusted operator configuration; public HTTP GET) | `HeroSSID.Api` serves a canonical DID Core 1.0 JSON-LD document at `/.well-known/did.json` with one approved public Ed25519 key, an **explicit independently pinned two-key overlap** (`#key-1` and `#key-2`) or explicit **successor-only retirement** preserving `#key-2`; route absent by default, startup fails closed on incomplete/unknown configuration, exact HTTPS Host/port enforced. See [HTTP publication guide](docs/did-web-http-publishing.md). | Not production deployment, DNS/TLS ownership proof, private-key custody, remote DID resolution, issuer trust enrollment, private-key possession, automatic rotation/retirement, human/organisation identity, Agent authorization or independent wallet interoperability. Independently configure trusted proxy ingress and preapproved verification policy. |
| Opt-in pinned `did:web` HTTPS document fetch (.NET SDK) | Fetch the canonical HTTPS `did.json` for an **independently preapproved DID and Ed25519 public key**, then require an exact bounded, credential-free single-key DID document match; supports an isolated public-DNS-only, non-redirecting transport and injectable audited `HttpClient`. See [published document verification](docs/did-web-offline-publishing.md#opt-in-pinned-https-get-of-the-published-document) | Not general remote DID resolution or automatic issuer trust. The isolated handler rejects private/special DNS answers before TCP connection and avoids a second DNS lookup; operators still enforce network routing/egress/SSRF and independently enroll trusted keys. Injected redirecting transports can contact other hosts before final-response rejection. No domain ownership, key-possession, human/Agent identity, business authority or third-party wallet proof. |
| Opt-in did:web two-key publishing overlap (.NET SDK) | `DidWebPinnedKeyTransition.CreateTransitionDocument` prepares a DID Core document for one unchanged did:web URI with two distinct Ed25519 assertion/authentication keys; `MatchesExpectedTransitionDocument` checks the externally obtained document against **both independently pinned keys** and rejects added delegations, key/relationship substitutions, duplicate members or malformed JSON. See [two-key overlap guide](docs/did-web-offline-publishing.md#offline-two-key-publication-overlap-opt-in) | Offline publication/verification only: both keys become advertised for authentication and assertion during overlap, but no private-key custody, domain ownership, automatic issuer trust update, historical signature trust, holder proof, real identity, business authority, hosting, or third-party Wallet interoperability is established. The one-key fetch remains separate; an opt-in dual-pin HTTPS fetch reuses the bounded isolated transport to check both independently pinned keys without automatically promoting successor trust. |
| Opt-in did:web successor-only retirement (.NET SDK) | After an independently pinned two-key overlap, `DidWebPinnedKeyRetirement` prepares, exactly validates and safely fetches a same-DID successor-only `did.json` retaining `#key-2` and excluding the old `#key-1` verification method and relationships; see [operator retirement guide](docs/did-web-offline-publishing.md#successor-only-retirement-after-two-key-overlap-opt-in) | Operator-controlled publication and independent old/new pin approval only; no automatic trust promotion, historical VC validity decision, key-possession proof, DNS ownership, identity, Agent authority or external wallet conformance |
| Opt-in did:web retired successor publication + signer control (SDK) | Independently pinned old and successor keys, exact canonical successor-only HTTPS `did.json`, real one-use `#key-2` Ed25519 signer proof and process-local atomic challenge consumption; [retirement admission guide](docs/did-web-key-control-one-use.md#successor-only-retirement-admission-and-key-2-signer-proof) | Does not prove DNS ownership, issuer trust, prior enrollment, legal identity, business/Agent authority, durable multi-replica replay protection, third-party Wallet interoperability or production readiness |
| Opt-in lost issuer-key guardian recovery evidence (SDK + authenticated HTTP) | Separately pre-pinned 2-of-3 (up to five) guardian Ed25519 signers and an independently controlled new issuer key sign the same exact verifier/nonce/purpose-bound, five-minute statement without needing the lost old private key; [distributed SDK signing](docs/issuer-guardian-distributed-signing.md) keeps each guardian seed at its own signer boundary | This is privately defined **evidence only**; caller must separately prove pre-enrollment, atomically consume the one-use nonce, apply organization recovery authority and manually decide whether its own trust policy changes. No DID ownership transfer, old-key compromise detection, automatic issuer trust promotion, business authorization or external wallet interoperability; authenticated HTTP verifier can atomically consume or incident-cancel a pending tenant/purpose-bound nonce across hosts (cancellation does not undo already accepted evidence), but guardian pins supplied in HTTP policy are not independently enrolled by HeroSSID; see [guardian recovery](docs/issuer-guardian-recovery.md) and [HTTP adapter](docs/issuer-guardian-recovery-challenges.md) |\n| Opt-in guardian policy binding | SDK and authenticated HTTP recovery challenge issuance can commit the exact pre-enrolled guardian DID set and quorum, rejecting signed recovery against changed policy while preserving one-use cancellation | Does not enroll guardians or prove business authority; legacy unbound issuance remains for compatibility; see [bound guardian challenges](docs/issuer-guardian-recovery-challenges.md#opt-in-guardian-policy-bound-challenges-sdk-and-http) |
| Issuer key succession (SDK + authenticated HTTP verifier) | Two independent Ed25519 issuer keys cross-sign an exact verifier-specific five-minute successor statement; verifiers may sign their own challenge using an active tenant-owned Ed25519 DID; opt-in SDK **and authenticated HTTP host-pinned endpoints** require an operator-preapproved successor DID **before** spending a purpose-separated atomic nonce across replicas; operators can now cancel a pending host-pinned nonce with both verifier and DID-management scopes | DID keys are immutable; the optional successor pin comes from verifier-controlled prior enrollment, never a supplied proof/HTTP override. The original HTTP verifier remains an **unpinned key-control-only** route; no proof of independent pre-incident enrollment, automatic trust promotion, compromise detection, lost-key recovery or wallet interoperability. See [HTTP successor policy](docs/issuer-key-successor-http-profile.md#4-opt-in-verifier-host-owned-successor-policy-http). No automatic trust promotion, original-key compromise detection, lost-key recovery or wallet standard interoperability |
| Opt-in direct VC2 retired-issuer exact-JWT trust (.NET SDK) | Verifier independently pins SHA-256 of each original genuine retired-issuer VC2 JWT while allowing separately pinned active issuers; optional authentic same-signer short-lived status | No retroactive enrollment or trust promotion: new/backdated JWTs from retired keys fail without exact pins; caller owns the trusted inventory (up to 256 exact pins and 16 distinct issuer DIDs). A hash does not prove issue time, revocation freshness, holder control, real identity, authority or Wallet interoperability. See [VC2 retirement](docs/vcdm20-retired-issuer-exact-pins.md) |
| Opt-in retired VC2 issuer holder proof (SDK) | Full-disclosure VP with genuine holder Ed25519 proof and verifier-owned one-use nonce, followed by independent active/retired issuer exact-JWT pins, optional same-issuer signed status with a verifier-owned post-incident observation cutoff, and no claim release on failure | No user consent UI, standard OpenID4VP hosted exchange, third-party Wallet test, historical issue-time proof, live revocation, identity vetting or business authority; see [retired issuer holder proof](docs/vcdm20-retired-issuer-holder-proof.md) |\n| Opt-in VC2 retired issuer incident-cutoff verification over HTTP | An authenticated non-.NET verifier may supply independently registered active Ed25519 issuer DIDs or exact original retired VC2 JWT SHA-256 pins, the genuine signer's private status and its own post-incident observation cutoff; only a genuine non-listed issuer statement releases issuer and subject | No automatic pin enrollment, attested observation completeness, live revocation, holder proof, consent, identity, business authority or Wallet interoperability; see [incident HTTP contract](docs/vcdm20-retired-issuer-incident-http.md) |
| Opt-in signed VCDM 2.0 issuer object (SDK) | `Vcdm20JoseCredential.CreateWithNamedIssuer` signs `issuer: {id, name}` with a genuine issuer Ed25519 key; `TryVerifyNamedIssuer` releases claims only after separately pinned signer DID **and exact descriptive name**, holder, type, context, validity and signature all match. Legacy string-only verifiers remain strict. See [issuer object guide](docs/vcdm20-named-issuer-object.md) | The issuer-signed name is a descriptive assertion, **not** independently verified organisation/legal identity, domain ownership or business authority. No holder proof, consent, status, standard JSON-LD validation, independent Wallet interoperability or production readiness. |
| Opt-in VC2 named issuer + signed credential ID combination (SDK) | `Vcdm20JoseCredential.CreateWithNamedIssuerAndId` authenticates issuer `{id,name}` and exact top-level HTTPS credential `id` in one Ed25519-signed direct VC2 JWT. `TryVerifyNamedIssuerWithId` independently pins issuer DID/name, original signed credential ID, holder, type, context and validity; legacy profiles reject the new combined form. See [named issuer guide](docs/vcdm20-named-issuer-object.md#named-issuer-plus-exact-signed-credential-identifier). | Signed display name and credential ID are assertions, not proof of a legal entity, holder key possession, current status, consent or authority. Credential ID can correlate presentations; no third-party wallet or JSON-LD conformance claim. |
| Opt-in VC2 recipient-bound signed credential + ID (SDK) | `CreateForAudienceWithId` signs an exact HTTPS credential ID and one RFC 7519 `aud` in the original real Ed25519 direct `vc+jwt`; `TryVerifyForAudienceWithId` independently pins issuer, holder, type, context, ID and its own recipient before exposing claims; legacy verifiers reject this profile | Recipient binding does not establish holder key proof, consent, anti-replay, legal identity, live status, Agent authority or third-party Wallet interoperability. See [recipient-bound VC2 JWT](docs/vcdm20-recipient-bound-jwt.md) |\n| Opt-in VC2 recipient-bound holder proof with issuer status (SDK) | `CheckRecipientBoundPresentationWithIssuerStatus` composes real verifier/issuer/holder Ed25519 signatures, the verifier-retained exact request hash, issuer-signed recipient and credential ID, an atomic one-use nonce and same-issuer fresh private signed status **before** exposing subject claims | An authentic `SignedNotListed` is not proof of complete/live non-revocation, consent, legal identity or Agent/business authorization. No public endpoint or independently tested third-party Wallet; see [recipient status-gated holder profile](docs/vcdm20-recipient-bound-jwt.md#single-use-recipient-bound-status-gate-sdk-opt-in) |
| Explicit VC2 historical issuer trust (SDK) | `Vcdm20TrustedIssuerVerifier.TryVerify` accepts direct VC2 JWTs signed by up to 16 **independently pinned** historical/current Ed25519 issuer DIDs. The opt-in `TryVerifyWithId` additionally requires one exact, verifier-pinned signed HTTPS credential identifier and releases actual signer/subject only after full signature and policy validation | No automatic promotion from key-successor attestation, signed credential ID or untrusted JWT header; no lost-key recovery, holder proof, revocation, real identity or authorization; see [issuer trust transition](docs/vcdm20-explicit-issuer-trust.md) and [signed ID profile](docs/vcdm20-issuer-signed-id.md#explicit-historicalcurrent-issuer-allowlist-with-exact-credential-id-pin) |
| Opt-in VC2 verifier-owned exact signed string claim policy (SDK) | `Vcdm20TrustedIssuerVerifier.TryVerifyWithIdAndRequiredClaims` requires 1–16 independently configured top-level string claim/value pairs (such as `membership=active`) after verifying genuine Ed25519 issuer signature, explicitly pinned issuer DIDs, exact signed HTTPS credential ID, holder, context, type and validity; rejects inactive/missing/nested/non-string values without releasing identity | A signed claim is not a holder possession proof, status/revocation, current membership entitlement, identity vetting or business authorization; caller owns the independently enrolled context semantics and policy. See [signed claim policy](docs/vcdm20-required-signed-claims.md) |\n| REST ownership and opt-in issuer signing grants | Validated bearer `tenant_id`, exact operation scopes and tenant DID ownership; operator-provisioned exact client + issuer DID + credential type + top-level subject claim-name grants can deny unauthorized issuance before signing on all three HTTP issue routes | Legacy tenant-wide issuance remains unless operators enforce per-client grants. Claim-name restriction does not validate values, nested claims, actual identity or business authority. See [signing grants](docs/issuer-client-signing-grants.md) |
| Opt-in VC2 signed-ID membership status with genuine holder proof (SDK) | `Vcdm20SignedClaimPresentation.CheckWithIssuerStatus` composes a one-use genuine Ed25519 holder proof, exact independently pinned issuer/holder/credential ID and membership claims, and same-actual-issuer 60-second private signed status with verifier-owned observation cutoff; signed-ID originals now support exact-digest status | `SignedNotListed` never means complete/live non-revocation, current entitlement, independently verified identity, actual holder consent, business authorization, standard W3C status or third-party Wallet interoperability. No schema or hosted endpoint; see [status-bound membership](docs/vcdm20-holder-bound-claim-policy.md#opt-in-exact-same-issuer-status-for-a-signed-id-membership-presentation) |
| Opt-in VC2 signed-ID membership Wallet full-disclosure preflight (SDK) | Before holder signing, independently pinned verifier, issuer, holder, exact credential ID and membership string claims, plus genuine fresh same-issuer signed status are checked; after actual app-owned consent, the unchanged three signed JWTs are reauthenticated and the holder signs a VP accepted by the existing one-use membership verifier | No consent UI/attestation, selective disclosure, live or complete revocation, identity vetting, current entitlement, business/Agent authority, independent third-party wallet interoperability or production deployment; see [holder preview](docs/vcdm20-signed-id-wallet-preflight.md) |\n| Credential issuance | Ed25519-signed JWT credentials and PostgreSQL persistence | Existing payloads use the 2018 credentials context; full VC 2.0 conformance is not established |
| Opt-in W3C VC 1.1 `jwt_vc_json` credential SDK and HTTP issue | Independent Ed25519 issuer signing, pinned offline verification and authenticated tenant-owned short-lived HTTP issue for unenrolled holders, including explicit opt-in exact 100ns JWT validity (legacy whole-second clients unchanged) | HTTP issuance is not persisted or revocable through the legacy database route; no holder control, live status, identity vetting, OpenID4VCI or independent wallet interoperability | 
| Opt-in issuer-pinned `did:web` VC1.1 JWT signature check (SDK) | `JwtVcJsonPinnedDidWebIssuerVerifier.TryVerify` verifies the **original** W3C VC1.1 `jwt_vc_json` Ed25519 JWT against an independently enrolled restricted `did:web` issuer DID, exact `#key-1` or `#key-2` assertion method and pinned raw public key, with the same strict VC/holder/type/context/expiry checks as the `did:key` path. Existing `did:key` APIs remain unchanged. See [offline did:web issuer verification](docs/jwt-vc-json-pinned-didweb-issuer.md) | This never fetches or enrolls a DID document, proves DNS control, authenticates legal identity, automatically trusts a rotation, establishes holder-key possession, consent, live status, Agent/business authorization or independent Wallet interoperability. Caller must independently pre-enroll the authorized assertion key. |
| Opt-in did:web VC1.1 exact original-JWT issuer status (.NET SDK) | `JwtVcJsonPinnedDidWebIssuerStatus.Create` issues a 60-second genuine same-Ed25519-issuer signed `revoked=true/false` observation for a particular unchanged VC1.1 JWT SHA-256; `CheckPresentation` requires separately pinned did:web issuer key/method, name, HTTPS credential ID, authentic holder-signed VP and atomic one-use verifier nonce, and releases claims only on genuine fresh `NotListed`. See [exact status guide](docs/jwt-vc-json-pinned-didweb-issuer-status.md) | This is a private per-credential observation, not a W3C status list, complete/live non-revocation, issuer key-compromise recovery, real identity, consent UI, business authorization or independent Wallet interoperability. The publisher owns the authoritative status record, verifier independently owns trust policy and shared atomic challenges. |
| Opt-in did:web VC1.1 Wallet issuer-status preflight (.NET SDK) | `JwtVcJsonPinnedDidWebWalletPreflight.TryPrepare` verifies a pinned did:web issuer's original VC1.1 JWT plus exact fresh same-key signed not-revoked status **before** showing full claims without a holder seed; `CreateAfterPreview` rechecks original credential, status, issuer key, verifier challenge and displayed subject before wallet-approved holder VP signing. See [wallet preflight guide](docs/jwt-vc-json-pinned-didweb-wallet-status-preflight.md). | The Wallet must independently authenticate the verifier request, establish issuer pins and obtain meaningful full-disclosure consent. Private 60-second issuer status is neither standard revocation nor live non-revocation; no hosted endpoint, independent Wallet interop, legal identity or business/Agent authorization. |
| Opt-in did:web VC1.1 Wallet pinned HTTPS issuer-status fetch (.NET SDK) | `JwtVcJsonPinnedDidWebIssuerStatusTransport.FetchVerifiedStatusWithIsolatedTransportAsync` retrieves a bounded, genuine same-key Ed25519-signed 60-second status JWT for the **exact unchanged original VC1.1 JWT**, using an independently preapproved public HTTPS URI, original-issuer key pin and isolated credential-free GET. Returns a typed `Revoked`/`NotListed` observation for the existing full-disclosure Wallet preflight; see [HTTPS status retrieval](docs/did-web-issuer-status-wallet-https-fetch.md). | Operators must publish the status and separately enroll both trust pins; an issuer's signed `NotListed` is not complete/live non-revocation. No hosted issuer endpoint, user consent UI, third-party wallet conformance, legal identity or business/Agent authorization. |
| Opt-in did:web VC1.1 holder admission with **both** local emergency denial and issuer status (.NET SDK) | `JwtVcJsonPinnedDidWebIssuerAdmission.Check` verifies real issuer and holder signatures once, consumes one verifier-owned challenge atomically, validates the entire verifier-owned exact-JWT SHA-256 denylist and the issuer's fresh same-key signed exact-JWT status, and releases claims only when both pass. It distinguishes local denial, actual issuer `revoked=true`, invalid proof/status and signed `revoked=false`. See [composite admission contract](docs/jwt-vc-json-pinned-didweb-issuer-admission.md). | Requires separately pinned issuer DID/method/name/credential ID/key, application-authenticated verifier request and holder consent, operator-maintained 0–256 canonical digests and shared atomic nonce store. Private 60-second status is not a W3C status list or live/complete non-revocation; no hosted endpoint, independent Wallet interoperability, real-world identity or business/Agent authorization. |
| Opt-in VC1.1 organisation-name + credential-ID verifier pins (SDK) | `TryVerifyWithPinnedIssuerNameAndId` authenticates a genuine Ed25519 `jwt_vc_json` and independently configured issuer DID, exact signed descriptive organisation name, original HTTPS JWT `jti`, expected holder, type, vocabulary and validity before releasing subject claims; forged, foreign, wrong-name/ID, incomplete and expired credentials fail closed. See [VC1.1 named issuer pins](docs/jwt-vc-json-profile.md#independently-pinned-issuer-name-and-credential-id-before-claim-release-sdk-opt-in). | A signed display name / membership identifier does not prove legal organisation identity, holder key control, user consent, revocation, current entitlement, Agent/business authorization or independent Wallet interoperability. |
| Opt-in VC1.1 exact issuer-name + signed credential-ID authenticated HTTP verifier | Non-.NET callers can now request an issuer/holder/type/context plus independently pinned signed issuer name and original HTTPS JWT `jti` before any claim release; an opt-in same-actual-issuer private signed-status variant distinguishes `Revoked`, `Invalid` and `SignedNotListed`, while legacy single-issuer endpoints refuse silently ignored name/ID policy. See [HTTP pin contract](docs/jwt-vc-json-http-pinned-issuer-name-id.md). | Signed issuer name/ID are not legal identity, holder-key possession, user consent, live non-revocation, current membership or business/Agent authority; no independent third-party Wallet interoperability, schema, release or deployment. |
| Opt-in VC1.1 JWT recipient audience binding (SDK + authenticated HTTP issuance/verifier) | The issuer can sign a canonical HTTPS RFC 7519 `aud` for a relying party via SDK or an authenticated, tenant-owned `issue-for-audience` HTTP route, optionally composing a signed HTTPS credential ID, descriptive issuer name and exact 100ns validity in the original JWT; a verifier must separately pin its own exact HTTPS recipient URI, trusted issuer, holder, type and context. Original Ed25519 issuer-signed JWTs remain usable by the private signed-status digest checker. See [recipient-audience SDK profile](docs/jwt-vc-json-recipient-audience.md) and [authenticated HTTP verifier](docs/jwt-vc-json-audience-http-profile.md) | Only the explicit API accepts bounded `aud` string or array; default and existing HTTP routes remain fail-closed. Audience does not establish recipient identity, holder key possession, end-user consent, live non-revocation or business authority; no external Wallet test. |
| VC1.1 retired issuer exact-JWT trust (SDK and authenticated HTTP, opt-in) | Verifier pins independently registered SHA-256 of each original `jwt_vc_json` JWT from a retired Ed25519 DID; still-valid historical credentials pass genuine original signature/policy checks, while freshly signed or backdated credentials from that retired key fail. Active issuer DIDs remain independently trusted; optional exact-signer private status. | Caller must establish trustworthy pin inventory before retirement; at most 256 exact pins, 16 distinct issuer DIDs, and each JWT still has a 15-minute maximum validity. A compromised old key may forge status; this does not prove issuance time, live non-revocation, holder control or authority. See [retired-key exact pins](docs/jwt-vc-json-retired-issuer-exact-pins.md) and [non-.NET HTTP verifier](docs/jwt-vc-json-retired-issuer-http-profile.md) |\n| Opt-in VC1.1 issuer-signed HTTP revocation export | An authenticated tenant-owned Ed25519 issuer can sign a bounded caller-observed complete revoked VC1.1 JWT set for non-.NET clients using both `credential:revoke` and `did:manage` | Private 60-second issuer-provided status; input completeness and observation honesty cannot be proven by HeroSSID, and HTTP-issued VC1.1 JWTs are not persisted/revocable through the legacy route |\n| Opt-in VC1.1 `jwt_vc_json` authenticated HTTP verification | Non-.NET verifiers pin one issuer or an independently enrolled list of 1–16 historical/current Ed25519 DID issuers; original VC1.1 JWT, holder, HTTPS type/context and optional **same actual signer** short-lived private status are authenticated before releasing signer and claims | Removing a DID from verifier trust rejects old credentials. `SignedNotListed` needs an authoritative complete status set and is not live non-revocation, holder control, identity vetting, authorization or wallet interoperability; see [HTTP trust contract](docs/jwt-vc-json-http-verify-profile.md#historical-and-current-issuer-verification-with-verifier-owned-trust-opt-in) |
| VC1.1 verifier-owned emergency exact-JWT denylist (.NET SDK, opt-in) | An independent relying party can block a specific authentic active-issuer or exact-pinned retired-issuer original JWT by its SHA-256, even when the issuer reports clean status; denial never releases issuer/subject claims | Verifier-local policy only; 256 canonical exact digests maximum, no automatic intake, shared-store synchronization, network revocation, proof of compromise, holder possession or authority. Distinguishes local denial from issuer-reported revocation. See [emergency denylist](docs/jwt-vc-json-verifier-emergency-denylist.md) |
| VC1.1 verifier-owned emergency denial over authenticated HTTP (opt-in) | Non-.NET relying parties can enforce their own canonical SHA-256 denylist of exact current/retired original VC1.1 JWTs through two explicit `credential:verify`-protected routes, with optional genuine same-issuer private status; denied, revoked and untrusted credentials release no issuer or subject claims | Verifier caller must provision, store and synchronize its own 0–256 exact SHA-256 fingerprints; legacy routes reject submitted denial policy instead of ignoring it. No shared/hosted denial registry, live revocation, holder control, identity or independent wallet interoperability. See [HTTP emergency denial](docs/jwt-vc-json-http-verifier-denylist.md) |
| Opt-in VC 1.1 `jwt_vc_json` holder-signed VP | Full-disclosure holder Ed25519 `vp+jwt` around unchanged issuer-signed VC1.1 JWT; authenticated HTTP signing of an active tenant-owned verifier DID request, independent holder pinning, shared one-use PostgreSQL challenge and both real signatures | Private `herossid-request+jwt` verifier handshake, **not** OpenID4VP 1.0 transport, real holder consent UI, external wallet interoperability or business authority |
| Opt-in VC1.1 Wallet post-incident status preflight (.NET SDK) | A Wallet can reject genuine but pre-incident issuer status before exposing any VC1.1 claims, require its own current independent cutoff again after consent, and holder-sign the exact original verifier Request Object SHA-256; verifier independently enforces cutoff and atomic one-use challenge | Private signed 60-second issuer status; no proof of truthful observation or complete/live non-revocation, actual consent UI, legal identity, business authority, full OpenID4VP conformance or external Wallet interoperability; see [VC1.1 Wallet incident gate](docs/jwt-vc-json-wallet-incident-status.md) |\n| Opt-in `jwt_vc_json` OpenID4VP 1.0 direct_post SDK and HTTP launch | Ed25519 verifier request, authenticated HTTP issuance with canonical signed by-value `openid4vp://` wallet-invocation URI, independently pinned verifier/callback/issuer/type, holder-signed VP, atomic challenge; optional short-lived issuer-signed status for the exact enclosed VC1.1 JWT; Wallet can now POST the approved form to the pinned HTTPS callback with an isolated credential-free, non-redirecting transport and bounded JSON receipt (see [direct_post profile](docs/jwt-vc-json-openid4vp-direct-post-profile.md)) | Private issuer status needs an authoritative complete set; no public callback, multi-instance durable `request_uri` hosting, QR-length promise, live-status guarantee, third-party wallet conformance, actual consent UI, identity vetting or business authority |
| Opt-in VC1.1 OpenID4VP `request_uri` GET Wallet transport (.NET SDK + single-instance HTTP host) | Generate compact by-reference launches for authentic Ed25519 verifier Request Objects, fetch unchanged signed JWTs from independently pinned HTTPS URIs, or opt into an authenticated API publisher and anonymous bounded original-JWT GET while the tenant's challenge is live; reuse holder-bound VP and atomic replay protection; server-issued hosted-purpose nonces now reject legacy unbound responses on upgraded replicas/restarts; optional hosted-only mode also rejects all by-value responses | Hosted references are **volatile single-process only** (256-entry cap), require an operator-pinned public HTTPS base and same-instance routing; hosted-only mode must be enabled consistently on all verifier replicas to prevent compatibility-route downgrade, no distributed durability, public `direct_post` callback, independent Wallet interoperability, complete conformance, actual user consent, identity vetting or business authorization. Wallet retrieval has an SDK-isolated credential-free/non-redirecting transport; custom injected clients still require caller audit, and the safe default deliberately disables proxies; see [GET profile](docs/jwt-vc-json-request-uri-get.md) |
| Opt-in VCDM 2.0 JOSE issuance/verification | Real Ed25519 direct VC 2.0 JWT; in-memory SDK, authenticated tenant-owned short-lived HTTP issue and independently pinned HTTP verify; opt-in SDK issuer-signed canonical HTTPS credential `id` with explicit strict verifier output ([profile](docs/vcdm20-issuer-signed-id.md)) | HTTP issue is limited to 15 minutes and not persisted/revocable; the signed identifier is not dereferenced or a status/authority grant, and can correlate presentations; no JSON-LD expansion, external conformance, holder proof or third-party wallet exchange |
| Opt-in direct VC2 verifier-owned emergency JWT denial (.NET SDK + authenticated HTTP) | Independently pinned historical/current Ed25519 issuer statements plus up to 256 verifier-owned exact original-JWT SHA-256 denials; opt-in `credential:verify`-protected non-.NET HTTP endpoints enforce the same policy, optionally checking the exact signer's 60-second status; invalid, denied and revoked statements disclose no issuer or subject | Verifier must provision and synchronize its own local denial list; legacy HTTP routes reject an unexpected denial policy. No shared registry, live revocation, holder control, identity vetting, authority or wallet interoperability; see [SDK](docs/vcdm20-verifier-emergency-denylist.md) and [HTTP contract](docs/vcdm20-http-verifier-denylist.md) |
| Opt-in host-owned VC2 issuer verification, signed status and emergency denial over HTTP | A verifier operator preconfigures tenant-scoped trusted Ed25519 issuer DIDs, exact VC2 credential type, HTTPS vocabulary and optionally up to 256 original-JWT SHA-256 denials; authenticated non-.NET callers cannot replace or bypass server-held trust and denial. A separate route requires the actual issuer's fresh signed HeroSSID status snapshot and can enforce an optional host-owned minimum signed observation timestamp after a verifier incident before releasing claims | Authentic denied or issuer-listed JWTs release no issuer or subject; a still-fresh pre-cutoff snapshot also fails closed. Operator must protect and redeploy policy across replicas. A signed observation timestamp or non-listing cannot prove truthful observation, list completeness or live revocation. No holder-key proof, consent, identity vetting, business authorization or independent wallet conformance. See [HTTP host trust profile](docs/vcdm20-host-trusted-issuer-http.md) |
| Opt-in VC2 historical issuer trust over HTTP | Authenticated non-.NET verifier can pin 1–16 independently enrolled historical/current Ed25519 issuer DIDs, verify original direct VC2 signatures and optional exact-signer issuer status, and receive the actual verified signer only after full verification | Verifier must separately protect and update its trust list; signed absence is not live non-revocation, holder control, identity vetting or authorization; see [HTTP trust policy](docs/vcdm20-http-verify-profile.md#explicit-historicalcurrent-issuer-http-verification-opt-in) |
| Opt-in VC2 holder presentation | Holder-signed direct `vp+jwt` with genuine original VC2 issuer proof, independent Ed25519 holder control and atomic one-use challenge; opt-in authenticated [host-pinned presentation verification](docs/vcdm20-host-trusted-issuer-http.md#verify-a-holder-signed-vc2-presentation-with-the-hosts-trust-policy-opt-in) additionally enforces verifier-owned tenant issuer/type/context, authentic signed status, incident cutoff and emergency exact-JWT denial before disclosing subject | Full disclosure only; private signed-status/handshake profiles, no hosted standard OpenID4VP or independent third-party Wallet proof. Signed unlisted status is not live non-revocation, consent evidence, identity vetting or business authorization |
| Opt-in VC2 verifier-owned original signed-request pin (.NET SDK) | Checks the **exact verifier-retained SHA-256 of the original signed eight-field policy request**, its actual Ed25519 verifier signature, independently pinned DID/type/HTTPS context, same-tenant issuer/nonce/expiry, real issuer and holder proofs, and one-use challenge; optional same-signer short-lived issuer status checked path | Relying verifier must independently persist/retrieve the exact request digest from its own trusted state, not holder input; existing challenge store does not persist this digest or vocabulary. No hosted endpoint, new schema, consent, live revocation, legal identity, authority, OpenID4VP conformance or independent Wallet interoperability; see [original request pin](docs/vcdm20-original-request-pin.md) |
| Opt-in VC2 holder-signed original verifier-request digest (.NET SDK) | The Wallet's real Ed25519 holder signature now covers the SHA-256 of the **exact** policy-bound signed verifier request, while the verifier separately checks its own retained original request pin, issuer/holder/verifier signatures, tenant nonce, vocabulary and atomic one-use challenge. A strict opt-in status variant also checks the actual issuer-signed private snapshot. | Legacy unbound proof APIs remain unchanged and MUST NOT be mistaken for this stronger binding. The `herossidRequestSha256` claim is private, not a standardized W3C/OpenID4VP request hash; no hosted endpoint, automatic original pin persistence, Wallet consent proof, status completeness, legal identity, Agent authority or independent interoperability. See [holder-bound request contract](docs/vcdm20-holder-bound-original-request.md) |\n| Opt-in VC2 Wallet full-disclosure preflight | Authentic issuer-signed VC2 claims and the independently pinned verifier's real signed request are previewed without a holder key; an optional same-issuer signed 60-second status snapshot must be authentic and `SignedNotListed` before claims are exposed or the key is used; exact signed artifacts, status and claims are rechecked after Wallet-owned consent | Local opt-in SDK; issuer status set completeness and live non-revocation remain unproven; no consent evidence, selective disclosure, identity verification, authorization, standard OpenID4VP exchange or third-party wallet interoperability |
| Opt-in VC2 Wallet strict post-consent request binding (SDK) | Independent no-key full-disclosure preview of original verifier/issuer Ed25519 signatures, exactly signed credential type/HTTPS context and all subject claims; after the integrating Wallet obtains consent, the actual holder Ed25519 signature covers SHA-256 of the exact original request, checked with verifier-retained pin and one-use challenge | No actual user consent UI or consent evidence; old unbound signing APIs remain compatible and are rejected by strict verifiers. No automatic pin persistence, live status guarantee, real identity, Agent authorization, standard OpenID4VP holder claim or third-party Wallet interoperability; see [strict Wallet integration](docs/vcdm20-wallet-disclosure-preflight.md#strict-full-disclosure-consent--holder-signed-original-request-opt-in) |
| Opt-in VC2 Wallet post-incident status cutoff | Independently pinned Wallet incident time rejects a genuine but pre-incident 60-second issuer-signed snapshot **before disclosing any subject claims or using the holder seed**. After Wallet-owned consent, the strict post-consent signer rechecks current operator cutoff, exact signed status, original verifier request/type/context, original VC2 issuer proof and actual holder request-bound Ed25519 signature; changed incident policy requires a fresh preview and consent. | Private SDK signed status, not complete/live revocation, actual consent UI, real identity, business/Agent authorization or external Wallet interoperability; see [Wallet incident cutoff](docs/vcdm20-wallet-incident-status.md) |\n| Opt-in issuer-owned VC2 HTTP signed-status export | An authenticated tenant can sign an independently observed bounded complete list of original direct VC2 JWTs using its active owned Ed25519 issuer DID (both `credential:revoke` and `did:manage` required); non-.NET verifiers can check the exact signer and snapshot | Caller completeness and 60-second observation are not proven; no automatic revocation source, shared registry, live status, holder proof, third-party wallet or business authority; see [HTTP issuer contract](docs/vcdm20-http-signed-status-export.md) |
| Opt-in VC2 issuer-signed revocation snapshot | Separate `herossid-vc2-revocation-snapshot+jwt` authenticates a bounded, 60-second digest set of revoked direct VC2 JWTs; verifier can check exact holder-signed VP and signed status together before releasing claims | Private issuer-distributed profile, not W3C `credentialStatus`/Bitstring Status List, an authoritative revocation registry, real-time status or external wallet conformance |
| Credential verification | Enrolled issuer signature, required holder/issuance/type/subject structure, optional enforced `nbf`/expiration, local revocation checks; no identity fields on rejection | Local `vc+jwt` profile only; REST lookup is tenant-scoped, not independent issuer trust or business authorization |
| Presentation library and opt-in VC2 HTTP proof | Full-disclosure holder-signed VC2 `vp+jwt`; authenticated HTTP nonce issuance, explicit verifier cancellation and issuer+holder signature/status verification using a tenant-bound, one-use PostgreSQL challenge | Cancellation is tenant-scoped, not client-scoped, and cannot undo accepted disclosures; caller must obtain holder consent; status is a private issuer snapshot, not live or independently wallet-tested |
| OAuth | Client-credentials tokens with configured HS256 signing and validated tenant/scopes | Full OpenID4VCI issuance and OpenID4VP exchange are unfinished |
| Key storage | Encrypted private-key storage through ASP.NET Data Protection; plaintext buffers cleared after signing | Managed signer/HSM integration and signing-key lifecycle are unfinished |
| Revocation | Issuer-only `POST /api/v1/credentials/revoke` atomically revokes the exact locally issued JWT; subsequent credential and presentation verification reject it | Local issuer database only: no signed/public interoperable status-list publication, independent wallet lookup or external trust policy |
| Selective disclosure | Legacy calls fail closed; mock SD-JWT implementations are not registered by default | Real selective disclosure and independent interoperability tests are unfinished |

New `did:key` documents use the [Ed25519VerificationKey2020 document profile](docs/did-key-profile.md), including a multicodec-prefixed key and `assertionMethod`. Already persisted documents are **not** rewritten. Scoped clients can explicitly request `GET /api/v1/dids/{did}/canonical` to derive a current-format DID document from a stored public key **only after verifying that the key matches the exact DID**. Missing, foreign, deactivated, invalid-key records are not published by this path; the ordinary DID resolution path still returns the stored historical representation. This does not establish a public DID resolver or wallet interoperability. See the [legacy compatibility boundary](docs/did-key-profile.md).

Identity credentials express what an issuer attests. Whether that issuer is trusted for a particular claim, and what business actions a holder may take, remain explicit relying-party decisions. Enrollment alone does not establish a person's real-world identity.

## Independently pinned pre-incident guardian enrollment (opt-in)

An issuer can pre-sign an exact guardian roster and quorum with its **original** Ed25519 key while the key is still available. The verifier separately approves and stores the exact original signed enrollment SHA-256 **before any loss incident**; recovery then verifies that signed policy and pin before issuing or atomically consuming a purpose-separated, tenant-bound challenge. A claimant cannot replace the previously pinned guardian set or quorum using a newly signed envelope. This private evidence does **not** approve the guardians, automatically transfer DID control, establish organization identity/authority or prove an external Wallet exchange. An opt-in authenticated HTTP adapter also exposes exact-JWT-bound challenge issuance and proof verification for non-.NET relying-party backends, using the existing shared atomic challenge store. **The caller must independently retrieve its own pre-incident approved pin:** merely submitting a matching JWT and hash over HTTP does not establish prior enrollment. See [the pre-enrollment SDK and HTTP flow and guarantees](docs/issuer-guardian-preenrollment.md).

## Host-owned pre-incident guardian enrollment (opt-in authenticated HTTP)

In addition to the caller-supplied exact signed-policy recovery endpoints,
an operator may separately provision and protect pre-incident approved
original issuer-signed guardian JWTs and SHA-256 pins **inside the verifier
host configuration**. The new authenticated `host-pinned-challenge` and
`host-pinned-verify` endpoints select those records only by validated bearer
tenant, original did:key issuer and exact HTTPS audience; clients cannot
supply or replace the trusted enrollment. Real issuer, successor and guardian
Ed25519 signatures and one-use shared PostgreSQL nonce are required. Missing
or altered host trust configuration fails closed. No database schema change.
**Operators must independently approve and consistently synchronize the
pre-incident configuration across hosts**, revoke compromised enrollment and
authorize actual recovery; no DID trust transfer, identity vetting, business
authority or independent Wallet interoperability follows from signatures.
See [host-controlled recovery setup and requests](docs/issuer-guardian-preenrollment.md#host-controlled-pre-incident-enrollment-over-authenticated-http-opt-in).

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

## Opt-in per-client issuer signing grants

An operator may independently grant an OAuth client permission to use only specific
active tenant-owned Ed25519 issuer DIDs. For explicitly enrolled tenants, all
three authenticated HTTP credential issuance routes fail closed on ungranted
client/DID pairs before private-key access. Each approved client/DID grant can
also opt in to an exact, case-sensitive credential-type allowlist, rejecting
unapproved assertion types before signing. Unconfigured tenants retain the
existing tenant-wide `credential:issue` scope. This is host-owned signing-key
and type access control, not a credential trust decision or business authorization.
See [configuration, boundaries and rollout](docs/issuer-client-signing-grants.md).
