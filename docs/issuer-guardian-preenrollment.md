# Pre-enrolled guardian recovery policy (opt-in .NET 10 SDK and authenticated HTTP)

An issuer that **still controls its old Ed25519 did:key** can pre-sign its
verifier-specific guardian roster and threshold before losing its original key.
The relying party independently approves and stores the **exact SHA-256 of
that signed enrollment JWT in its own trust registry before the incident**.
At incident time, the server must retrieve this independently stored digest
and its unchanged signed JWT; neither may come exclusively from a claimant.

This solves a specific key-recovery policy-substitution risk: the previous
[guardian recovery](issuer-guardian-recovery.md) can require a caller-owned
guardian list and [bind it to a nonce](issuer-guardian-recovery-challenges.md),
but a freshly supplied guardian list is not itself evidence of pre-enrollment.
The new opt-in route verifies the **actual old issuer's signature** AND the
independently pinned exact enrollment digest before issuing or consuming a
recovery challenge.

## Real SDK flow

```csharp
using HeroSSID.Credentials.Vcdm20;

// BEFORE LOSS: old issuer signs once with its own seed (clear seed after use).
string enrollmentJwt = IssuerGuardianRecoveryEnrollment.Create(
    oldIssuerDid, oldIssuerSeed, preApprovedGuardianDids,
    requiredGuardianSignatures: 2,
    new Uri("https://verifier.example/recovery"),
    DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMonths(6));
string digest = IssuerGuardianRecoveryEnrollment.Fingerprint(enrollmentJwt);

// INDEPENDENT, AUTHENTICATED VERIFIER ENROLLMENT:
// Approve and persist enrollmentJwt and digest out of band in the verifier's
// own trust policy BEFORE any issuer-key-loss incident.
// Do not derive this trust pin from an incoming recovery request.

// AFTER LOSS: verifier loads the original approved pin and original signed
// artifact, and supplies its trusted old issuer / HTTPS audience.
var challenge = IssuerGuardianRecoveryEnrollment.IssueChallenge(
    verifierOwnedSharedChallengeStore, verifierTenantId,
    independentlyStoredEnrollmentJwt, independentlyApprovedDigest,
    trustedOldIssuerDid, trustedVerifierAudience, TimeProvider.System);

// A separate successor and independent guardians sign one matching nonce
// with IssuerGuardianRecoveryDistributed (or Create for local test signers).
string recoveryProof = independentlyCollectedGuardianProof;
bool accepted = IssuerGuardianRecoveryEnrollment.TryVerifyAndConsume(
    verifierOwnedSharedChallengeStore, verifierTenantId,
    recoveryProof, independentlyStoredEnrollmentJwt,
    independentlyApprovedDigest, trustedOldIssuerDid,
    trustedVerifierAudience, challenge.Nonce, TimeProvider.System,
    out string candidateSuccessorDid);

// Only here, after acceptance, may the relying party apply its own separate
// incident investigation, organization recovery authorization and trust update.
```

The enrollment is an exact, old-issuer Ed25519-signed bounded JWT containing
version, purpose, trusted previous issuer DID, HTTPS verifier audience, a
canonical sorted and distinct 2–5 guardian did:key set, quorum and UTC
`iat`/`exp`. It remains usable for at most 365 days. Verification rejects
a different exact-JWT digest, wrong signature, added guardians, changed quorum,
wrong audience, future/expired enrollment or malformed/duplicate JSON; no
guardian set or candidate successor DID is returned on failure. Exact pins
must come from verifier-owned prior records rather than the claimant. The
signed policy's own `iat` is **not** an independent timestamp; the verifier's
prior authenticated record establishes when the digest was approved.

The SDK now commits the **exact original enrollment JWT SHA-256** into
a distinct v3 verifier-owned one-use recovery challenge. The same guardian
DIDs and quorum are **not** sufficient to substitute a different signed
enrollment after the nonce was issued, even if that alternate enrollment
has a valid old-issuer signature and a separate independently approved pin.
A legacy unbound v1 or guardian-only v2 challenge can still be verified via
its existing explicit SDK entry point, but it **cannot** be redeemed through
`IssuerGuardianRecoveryEnrollment.TryVerifyAndConsume`. Nor may a v3
pre-enrollment challenge be redeemed by the legacy generic entry point
without validating its exact signed enrollment. This fail-closed boundary
means any outstanding v2 challenge initiated through an older version of
this opt-in enrollment SDK must be **reissued** after upgrading; these
recovery challenges have a maximum five-minute lifetime.

The nonce remains tenant/audience/old-issuer/purpose separated and
single-use through the existing `IPresentationChallengeStore`; a cluster
uses the shared atomic PostgreSQL implementation and existing approved
schema. A recovery proof with wrong signers or a mismatched enrollment
fails **without consuming** the challenge, allowing the original enrolled
artifact to be used if still valid. An enrollment expiring before
consumption fails closed even when its nonce is pending. Exact v3
challenges remain cancelable through the existing issuer/purpose-bound
`IssuerGuardianRecoveryChallenges.TryCancel` operation.

This feature adds no database table, schema, migration, hosted key custody,
Wallet consent UI, package publication or deployment. Its optional authenticated
HTTP adapter exposes the existing pre-enrollment checks without independently
storing or validating policy approval. An issuer
signature proves old-key possession; a guardian signature proves possession
of its signing key, **not** the physical identity or business authority of
its operator. Neither signed enrollment nor completed quorum proves a key
was lost, DID ownership transferred, issuer trust should change, a holder
approved disclosure, or third-party wallet interoperability. The exact JWT
and fingerprint are a private HeroSSID enrollment evidence profile, **not**
W3C VC/standard OpenID4VP enrollment credentials.

## Authenticated HTTP verification for non-.NET relying parties (opt-in)

The existing .NET 10 SDK remains the source of the signing and verifier
semantics. The authenticated API now exposes the same **v3 exact original-JWT
fingerprint-bound recovery challenge** without any new PostgreSQL table.

**Before an incident:** an issuer with its old Ed25519 private key creates a
signed enrollment using the SDK (or an independently compatible implementation).
The relying party separately approves and durably stores the original JWT,
its exact uppercase SHA-256 fingerprint, the old issuer DID and HTTPS audience.
An arbitrary fingerprint calculated from an incident request **does not count**
as independent pre-enrollment. Neither HTTP endpoint stores or proves the
independent approval record.

**During a recovery incident:** the relying-party backend retrieves its own
previously approved data and calls these authenticated endpoints, both under
`/api/v1/credentials`:

1. `POST /issuer-guardian-recovery/enrolled-challenge` requires **both**
   `credential:verify` and `did:manage` bearer scopes. JSON body:

   ```json
   {
     "audience": "https://verifier.example/recovery",
     "trustedPreviousIssuerDid": "did:key:...",
     "signedEnrollmentJwt": "<original old-issuer-signed compact JWT>",
     "independentlyPinnedSha256": "<uppercase SHA-256 approved before incident>",
     "lifetimeSeconds": 120
   }
   ```

   The verifier validates the genuine old DID signature, exact JWT fingerprint,
   HTTPS audience, live enrollment validity, two-to-five distinct guardian
   policy and quorum before creating any challenge. Returns **201** with
   `nonce`, `expiresAt`, `audience`, `trustedPreviousIssuerDid`, and
   `exactEnrollmentBound: true`. Incorrect/forged/expired enrollments return
   400 and allocate no nonce; absent scopes return 401/403.

2. An independent successor key and the enrolled guardian keys sign the exact
   audience/nonce-bound evidence using
   `IssuerGuardianRecoveryDistributed` or a compatible signer. Then
   `POST /issuer-guardian-recovery/enrolled-verify` requires
   `credential:verify` and accepts:

   ```json
   {
     "audience": "https://verifier.example/recovery",
     "nonce": "<issued nonce>",
     "trustedPreviousIssuerDid": "did:key:...",
     "signedEnrollmentJwt": "<same original approved JWT>",
     "independentlyPinnedSha256": "<same original approved SHA-256>",
     "evidenceJson": "<exact assembled guardian/successor signature JSON>"
   }
   ```

   On success this returns HTTP **200**
   `{"status":"ValidRecoveryEvidence","successorIssuerDid":"did:key:..."}`.
   Failure returns `{"status":"Invalid","successorIssuerDid":null}`,
   without releasing a candidate. The verifier rechecks enrollment and all
   genuine Ed25519 signatures before atomically consuming the nonce in the
   shared challenge store. A signed alternative with identical guardians and
   threshold cannot redeem it; an old v1/v2 challenge cannot masquerade as v3.
   Wrong evidence does not consume a good challenge.

3. The existing `POST /issuer-guardian-recovery/cancel` (both scopes)
   can atomically cancel the pending v3 nonce using the exact tenant, old issuer,
   HTTPS audience and recovery purpose. As with other recovery types, a 204 is
   not proof of winning a race against verification and cannot undo previously
   accepted evidence.

Invalid inputs return 400, storage unavailability 503 and challenge-capacity
exhaustion on issuance 429. HTTP integration exercises two independent hosts,
genuine key signatures, an isolated real PostgreSQL challenge store, signed
policy substitution, legacy bypass denial, replays, scopes and cancellation.
The adapter never handles issuer/guardian/successor signing seeds.

**Critical boundary:** the authenticated requester supplies the JWT and digest;
HeroSSID cannot tell whether the caller truly loaded the pin from the
independent, pre-incident trust registry rather than computing it from
attacker-controlled input. The relying-party application MUST enforce that
provenance, approval, incident recovery authorization, audit, operator access
and pin revocation. The API proves **signature and nonce consistency only**,
not real-world guardian identity, DID control transfer, issuer trust promotion,
business authority, end-user consent, W3C enrollment conformance or independent
wallet interoperability.

## Host-controlled pre-incident enrollment over authenticated HTTP (opt-in)

For backends that cannot reliably enforce the preceding *caller-supplied* pin
provenance, HeroSSID also offers two opt-in **host-pinned** recovery routes.
Unlike `enrolled-challenge` / `enrolled-verify`, these **never accept the
signed enrollment JWT or approved SHA-256 from the HTTP request**. The host
operator must securely install an independently approved original old-issuer
JWT and its exact uppercase SHA-256 **before issuer-key loss**, in the verifier
deployment's protected configuration. Startup refuses malformed or duplicate
registrations rather than treating the caller's payload as a fallback.

Operator-controlled `IConfiguration` (supply via a secret/config provider rather
than checking actual organization policy into source control):

```text
IssuerGuardianEnrollmentTrust:Registrations:0:TenantId = <verifier tenant GUID>
IssuerGuardianEnrollmentTrust:Registrations:0:TrustedPreviousIssuerDid = <old did:key>
IssuerGuardianEnrollmentTrust:Registrations:0:Audience = https://verifier.example/issuer-guardian-recovery
IssuerGuardianEnrollmentTrust:Registrations:0:SignedEnrollmentJwt = <original old-key-signed enrollment JWT>
IssuerGuardianEnrollmentTrust:Registrations:0:ApprovedSha256 = <pre-incident approved uppercase SHA-256>
```

At most 256 records are supported, with unique exact
`(tenant_id, previous issuer DID, HTTPS audience)` keys. An absent record
fails closed. **Before serving HTTP**, each configured record is checked
against the exact approved JWT SHA-256, genuine old-issuer Ed25519 signature,
issuer DID, signed HTTPS audience, distinct guardian quorum and the current
signed validity window. A forged, mistimed or mismatched record now **prevents
the host from starting**, instead of allowing a broken recovery configuration
to remain latent until an incident. Every issuance and verification still
rechecks the signed policy and expiration. Operators must install a currently
valid policy and renew it before expiry, or a restart will fail closed.
Records are loaded as an immutable process-local
snapshot; every verifier instance must have the **same protected, independently
approved policy inventory**. Registry changes require a controlled host
restart/rollout and an operator-owned incident and revocation process. The
JWT is not a signing seed, but its trust approval and integrity are sensitive.

1. `POST /api/v1/credentials/issuer-guardian-recovery/host-pinned-challenge`
   needs **both** `credential:verify` and `did:manage`. Body:
   ```json
   {
     "audience": "https://verifier.example/issuer-guardian-recovery",
     "trustedPreviousIssuerDid": "did:key:...",
     "lifetimeSeconds": 120
   }
   ```
   The authenticated tenant and the exact DID/audience select a host-approved
   enrollment. A genuine old-key-signed enrollment and pinned original digest
   are verified again. A purpose-bound v3 one-use challenge is returned as 201,
   including `nonce` and `exactEnrollmentBound: true`; missing/mismatched
   registrations or invalid input return 400.

2. The independent successor and enrolled guardians sign the bound recovery
   challenge. `POST /api/v1/credentials/issuer-guardian-recovery/host-pinned-verify`
   needs `credential:verify`. Body:
   ```json
   {
     "audience": "https://verifier.example/issuer-guardian-recovery",
     "trustedPreviousIssuerDid": "did:key:...",
     "nonce": "<issued nonce>",
     "evidenceJson": "<successor and guardian signed evidence>"
   }
   ```
   The server independently reloads its own original enrollment and digest,
   validates all old-issuer, successor and guardian Ed25519 signatures and the
   exact policy, then atomically consumes the shared PostgreSQL challenge.
   Only successful validation returns `ValidRecoveryEvidence` and a
   *candidate* new DID; otherwise `Invalid` with a null candidate. Invalid
   shape is 400 and unavailable shared storage is 503.

The existing tenant/purpose-bound `/issuer-guardian-recovery/cancel` route
still cancels a pending v3 nonce across hosts. A 204 cannot undo an already
accepted proof or prove which side won a concurrent race. Legacy v1/v2
verification cannot redeem host-pinned v3 challenges. Additional unrecognized
request members are rejected instead of silently accepting caller-provided
policy fields.

**Trust limit:** protected server configuration is stronger than accepting a
claimant's self-computed pin, but HeroSSID still cannot independently attest
that a *human operator* actually approved the enrollment before the incident,
or that the configured registry has not been compromised. Operation scopes,
real Ed25519 proof and one-time nonce are **not** proof of DID ownership
transfer, business recovery authority, legal or human identity, Wallet consent,
W3C conformance or external wallet interoperability. Relying-party governance,
incident approvals, audit, rate limiting and any eventual trust-list update
remain separate requirements.

Tests: `dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj`
and the full repository Build/Test/Security/CodeQL gates.
