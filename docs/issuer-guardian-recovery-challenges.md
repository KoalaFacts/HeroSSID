# One-use verifier challenge for guardian issuer-key recovery (.NET 10 SDK)

This opt-in adapter connects [distributed guardian signatures](issuer-guardian-distributed-signing.md) to an existing verifier-owned atomic challenge store. It closes a **replay and purpose-confusion integration gap** for the private [issuer guardian recovery](issuer-guardian-recovery.md) evidence profile. It is not a standardized wallet exchange, an identity-verification service or an automatic recovery authorization endpoint.

## Real entry points

```csharp
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;

// The verifier owns the tenant, trusted previous issuer DID, guardian pins
// and exact HTTPS audience. Never copy them from untrusted signed evidence.
// For multiple replicas, inject the already-configured shared atomic
// IPresentationChallengeStore (e.g. PostgresPresentationChallengeStore).
IPresentationChallengeStore challenges = verifierOwnedSharedStore;
var audience = new Uri("https://verifier.example/recover-issuer");

PresentationChallenge issued = IssuerGuardianRecoveryChallenges.Issue(
    challenges, verifierTenantId, pinnedOldIssuerDid, audience,
    TimeSpan.FromMinutes(2));

// Send ONLY issued.Nonce and the independently approved policy to the
// successor and each guardian over authenticated application channels.
// Each signer retains its own Ed25519 private seed. After collecting the
// signed proposal and two independent signed guardian approvals:
string assembledEvidence = IssuerGuardianRecoveryDistributed.AssembleEvidence(
    signedSuccessorProposal, new[] { firstApproval, secondApproval });

bool consumedAndVerified = IssuerGuardianRecoveryChallenges.TryVerifyAndConsume(
    challenges, verifierTenantId, assembledEvidence, pinnedOldIssuerDid,
    independentlyEnrolledGuardianDids, requiredGuardianSignatures: 2,
    audience, issued.Nonce, TimeProvider.System, out string candidateDid);

// candidateDid is nonempty only for a real signature quorum and successful
// atomic one-use consumption. The organization must then perform separate
// recovery/incident authorization before updating ANY trust registry.
```

The adapter internally stores a **recovery-purpose marker plus the old issuer DID** in the challenge store's `TrustedIssuerDid` metadata field. This marker is **not a real issuer DID**. It can never be interpreted as issuer enrollment. Ordinary credential-presentation nonces and even valid signed guardian evidence cannot be combined to recover a key unless the original verifier-owned challenge explicitly had this recovery purpose and old issuer.

The verifier checks its own tenant, HTTPS audience, original old-issuer pin, nonce, expiry, real successor Ed25519 signature and at least two distinct **independently pre-enrolled** guardian Ed25519 signatures. It atomically consumes the challenge before returning the candidate successor. Malformed evidence, wrong tenant/purpose/issuer/guardian, wrong audience, expired challenge or losing a concurrent consume race fails closed with an empty candidate. A failed signature check does not burn an otherwise valid nonce; the relying party should additionally apply attempt limits and authenticated incident reporting.

## Incident cancellation before recovery acceptance

An authorized relying party can revoke a **pending** guardian recovery nonce
without collecting a signature or changing issuer trust. The verifier must pin
the same tenant, old issuer DID and exact HTTPS audience used at issuance:

```csharp
bool cancelled = IssuerGuardianRecoveryChallenges.TryCancel(
    challenges, verifierTenantId, pinnedOldIssuerDid, audience, issued.Nonce);
```

The method checks the challenge store's **recovery-only** purpose marker before
atomically consuming the nonce. Wrong tenant, old issuer, audience, expired or
already consumed nonce returns false without consuming a different challenge.
Normal presentation and issuer-successor challenges cannot be cancelled through
this method. Concurrent cancellation and valid proof verification race for the
same atomic store transition, so at most one succeeds; neither success path
by itself grants issuer trust or organizational authority. An incident response
must separately freeze trust promotion and investigate any proof previously
accepted. Cancellation does **not** reverse accepted evidence.

## Storage and operational boundaries

`InMemoryPresentationChallengeStore` is thread-safe for a single process only and loses outstanding challenges on restart. A multi-replica verifier must use the already available **shared atomic implementation**, such as `PostgresPresentationChallengeStore`, with its existing approved schema. This adapter adds **no new table, migration or production database changes** and does not itself deploy any service. The caller must guarantee that challenge issuance is available only to appropriately authenticated recovery operators and that the trusted guardian policy was enrolled separately *before* old-key loss.

Valid signatures prove control of **those signing private keys**, not the real-world identities of their custodians or organizational authority. The signed statement cannot establish that the previous key was actually lost or compromised. A successful returned candidate is **never** a DID transfer, automatic issuer trust promotion, permission to issue credentials, business authorization, holder consent or third-party Wallet interoperability. External verification and formal protocol conformance remain unproven.


## Authenticated non-.NET HTTP adapter (opt-in)

An authenticated relying-party backend can use the existing PostgreSQL-backed
challenge store without handling guardian private keys or changing its schema.
Both endpoints are under `/api/v1/credentials`:

- `POST /issuer-guardian-recovery/challenge` requires **both**
  `credential:verify` and `did:manage`. JSON:
  `{"audience":"https://verifier.example/recovery","previousIssuerDid":"did:key:...","lifetimeSeconds":120}`.
  Returns 201 with `audience`, `nonce`, `trustedPreviousIssuerDid` and `expiresAt`.
  The verifier must authenticate the recovery operator **before** making this
  request and convey the unsigned challenge over a trusted authenticated channel.
- `POST /issuer-guardian-recovery/cancel` requires **both**
  `credential:verify` and `did:manage`. JSON:
  `{"audience":"https://verifier.example/recovery","nonce":"<issued nonce>","trustedPreviousIssuerDid":"did:key:..."}`.
  Returns **204 with no body** for a validly shaped request, even if the
  challenge does not exist, was expired, or was already consumed. It checks
  the existing stored recovery-purpose marker before atomic consumption, so
  it cannot cancel other-purpose challenges. 400 rejects malformed input,
  401/403 deny unauthorized operators and 503 fails closed if storage is
  unavailable. **204 is deliberately not confirmation cancellation beat a
  concurrent valid verification** and cannot retract earlier acceptance.
- `POST /issuer-guardian-recovery/verify` requires `credential:verify`.
  JSON: `{"evidenceJson":"<exact assembled JSON>","audience":"https://verifier.example/recovery","nonce":"<issued nonce>","trustedPreviousIssuerDid":"did:key:...","trustedGuardianDids":["did:key:...","did:key:..."],"requiredGuardianSignatures":2}`.
  Returns `{"status":"ValidRecoveryEvidence","successorIssuerDid":"did:key:..."}`
  only after real successor and independent guardian Ed25519 signatures and
  successful **atomic** purpose-separated challenge consumption. Otherwise
  returns `{"status":"Invalid","successorIssuerDid":null}`; malformed
  policies fail with 400, and unavailable shared storage fails closed with 503.

The `trustedGuardianDids` list is **caller-owned trust policy**, not a
server-side guardian registry. The verifier must retrieve already enrolled
guardian pins and the old issuer pin from trusted application storage and
must never accept them blindly from the proposed recovery evidence or an
untrusted requester. A `credential:verify` bearer can supply its own pins to
this cryptographic verification service: signature verification alone cannot
prove that a guardian was pre-enrolled or possesses organization authority.
Production callers must enforce operator authorization, rate limiting and
incident controls separately. No automatic DID ownership transfer, issuer
enrollment, trust-registry mutation, human identity proof, business authority
or third-party Wallet interoperability is performed.

Real integration tests use two independent HTTP hosts, genuine successor and
guardian Ed25519 keys, isolated PostgreSQL/Testcontainers storage, a forged
guardian policy that does not consume the challenge, cross-host replay denial,
cross-purpose refusal, anonymous/scope denial and invalid-input denial.

## Opt-in guardian-policy-bound challenges (SDK and HTTP)

The original `Issue` API and HTTP challenge payload remain supported for
compatibility, but their recovery-only marker binds the old issuer, tenant and
audience **without freezing the guardian trust policy**. Callers that already
have an authoritative, separately enrolled guardian list should use the
stronger opt-in `IssuerGuardianRecoveryChallenges.IssueBoundToGuardians`:

```csharp
PresentationChallenge issued = IssuerGuardianRecoveryChallenges.IssueBoundToGuardians(
    challenges, verifierTenantId, pinnedOldIssuerDid,
    independentlyEnrolledGuardianDids, requiredGuardianSignatures: 2,
    audience, TimeSpan.FromMinutes(2));
```

This keeps the same `TryVerifyAndConsume` and `TryCancel` entry points.
The existing challenge metadata stores a domain-separated SHA-256 commitment
to the **sorted distinct guardian did:key pins and exact threshold**. Guardian
array order does not matter, but replacing a guardian or changing the quorum
cannot spend the nonce, even if the alternative keys genuinely sign. The
original policy must be independently supplied again at verification; the
store does **not** disclose or enroll guardian pins. Cancellation still checks
the old issuer, tenant, audience and purpose and atomically consumes the nonce.
No new schema or migration is needed.

The HTTP `/issuer-guardian-recovery/challenge` body may additionally supply
both `trustedGuardianDids` (two to five pre-enrolled distinct pins) and
`requiredGuardianSignatures` (two up to the pin count). Supplying only one,
duplicate/invalid guardian DIDs, the old issuer as guardian, or an invalid
threshold returns 400. The 201 response includes `guardianPolicyBound: true`
for the new mode and `false` for legacy mode. Recovery verification fails
closed with `Invalid` and a null successor if its caller-supplied policy
differs from the policy committed at issuance.

This commitment proves **policy consistency across issuance and verification**,
not policy provenance or recovery authorization. An authorized HTTP caller
could still nominate its own arbitrary pins at issuance; HeroSSID does not
provide a guardian enrollment registry. Production relying parties must load
the trusted pins from their own previously approved registry, authorize the
operator separately, and never treat genuine signatures alone as proof of
identity, real-world custody, DID transfer or business authority.
