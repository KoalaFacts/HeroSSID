# Distributed issuer guardian recovery signing (opt-in SDK)

This is a separate-keys signing path for the existing private [guardian recovery evidence](issuer-guardian-recovery.md) profile. Previously the convenience `IssuerGuardianRecovery.Create` method accepted **every guardian seed in one process**, unsuitable for independently controlled custodians. `IssuerGuardianRecoveryDistributed` lets each actual signer keep its Ed25519 private key on its **own** machine or approved signing boundary. Only compact, issuer/guardian-signed JWS strings are exchanged.

## Executable .NET 10 flow

```csharp
using HeroSSID.Credentials.Vcdm20;

// 1. At the proposed successor's signing boundary, no guardian seed is present.
// All audience/nonce values must originate from an independent verifier.
string signedProposal = IssuerGuardianRecoveryDistributed.CreateSuccessorSignature(
    previousIssuerDid, successorIssuerDid, successorOwnedSeed,
    new Uri("https://verifier.example/recover-issuer"),
    verifierOwnedOneUseNonce, TimeProvider.System);

// 2. Run independently at each guardian's signing boundary.
// The guardian MUST fetch the pinned old/new issuer DIDs, audience and nonce
// through its OWN authenticated recovery request, not copy them from the JWS.
bool accepted = IssuerGuardianRecoveryDistributed.TryCreateGuardianApproval(
    signedProposal, guardianPinnedPreviousIssuerDid, guardianApprovedSuccessorDid,
    guardianDid, guardianOwnedSeed, guardianPinnedVerifierAudience,
    guardianIndependentlyReceivedNonce, TimeProvider.System.GetUtcNow(),
    out string guardianApproval);

// 3. A seedless coordinator collects signatures from different guardians.
string evidence = IssuerGuardianRecoveryDistributed.AssembleEvidence(
    signedProposal, new[] { firstGuardianApproval, secondGuardianApproval });

// 4. The relying party verifies original signatures against independently
// pre-enrolled guardians and threshold (>= 2); only then does its own
// separate challenge/organization authorization policy decide what to do.
bool signaturesValid = IssuerGuardianRecovery.TryVerify(
    evidence, relyingPartyPinnedOldIssuerDid, relyingPartyPinnedGuardianDids,
    requiredGuardianSignatures: 2, relyingPartyAudience,
    relyingPartyStoredOneUseNonce, TimeProvider.System.GetUtcNow(),
    out string candidateSuccessorDid);
```

A proposal has one genuine Ed25519 successor signature on the exact `version=1`, `purpose=issuer-key-guardian-recovery`, previous/successor DID, HTTPS audience, nonce, and fractional-second `iat/exp` statement (maximum 300 seconds). Each guardian independently authenticates **that successor signature**, strict JSON/JOSE, old issuer and successor expectation, exact audience/nonce, and current lifetime **before** signing the original bytes. It also checks its own key controls the named guardian DID. Both signer paths reject their own old/new issuer key being used as a guardian. The assembler only packages signed artefacts: it neither computes trust nor validates authorization.

## Required relying-party policy and limits

A valid assembled envelope still requires the original `IssuerGuardianRecovery.TryVerify`, using **verifier-owned, pre-enrolled** two-to-five guardian DIDs, a separate threshold of at least two, and a verifier-owned nonce and audience. Exact statement identity and distinct guardian signatures are enforced there, so duplicated, untrusted, spliced and forged approvals cannot satisfy the quorum. The relying party must **atomically consume** the one-use challenge before any administrative trust-policy change and apply independent organizational authority, guardian compromise and incident policy. The opt-in [purpose-bound recovery challenge SDK](issuer-guardian-recovery-challenges.md) provides an executable verifier-owned one-use integration with the existing shared challenge store.

This is *evidence only*. It cannot recover a missing private key, reassign a `did:key`, prove a person's or organisation's identity, establish real custodian authorization, grant an agent business permission, enroll a new trusted issuer automatically, or assert OpenID4VP/VC interoperability. The caller owns all private-key memory and custody; the SDK does not store, delete or transmit any guardian seeds. Existing centralized `Create` remains for explicitly co-located test/trust configurations; distributed production custodians should use this independent-signature API.
