# Pre-enrolled guardian recovery policy (opt-in .NET 10)

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

The recovery nonce remains tenant/audience/old-issuer/policy separated and
single-use through the existing `IPresentationChallengeStore`; a cluster
uses the shared atomic PostgreSQL implementation and existing approved
schema. A recovery proof with wrong signers fails without consuming the
challenge. An enrollment that expires before consumption fails closed, even
when a nonce is still pending. Existing cancellation remains available.

This feature adds no database table, schema, migration, hosted key custody,
HTTP route, Wallet consent UI, package publication or deployment. An issuer
signature proves old-key possession; a guardian signature proves possession
of its signing key, **not** the physical identity or business authority of
its operator. Neither signed enrollment nor completed quorum proves a key
was lost, DID ownership transferred, issuer trust should change, a holder
approved disclosure, or third-party wallet interoperability. The exact JWT
and fingerprint are a private HeroSSID enrollment evidence profile, **not**
W3C VC/standard OpenID4VP enrollment credentials.

Tests: `dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj`
and the full repository Build/Test/Security/CodeQL gates.
