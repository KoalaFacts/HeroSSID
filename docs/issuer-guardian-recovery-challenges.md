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

## Storage and operational boundaries

`InMemoryPresentationChallengeStore` is thread-safe for a single process only and loses outstanding challenges on restart. A multi-replica verifier must use the already available **shared atomic implementation**, such as `PostgresPresentationChallengeStore`, with its existing approved schema. This adapter adds **no new table, migration or production database changes** and does not itself deploy any service. The caller must guarantee that challenge issuance is available only to appropriately authenticated recovery operators and that the trusted guardian policy was enrolled separately *before* old-key loss.

Valid signatures prove control of **those signing private keys**, not the real-world identities of their custodians or organizational authority. The signed statement cannot establish that the previous key was actually lost or compromised. A successful returned candidate is **never** a DID transfer, automatic issuer trust promotion, permission to issue credentials, business authorization, holder consent or third-party Wallet interoperability. External verification and formal protocol conformance remain unproven.
