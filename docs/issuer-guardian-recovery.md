# Verifier-pinned issuer guardian recovery evidence (opt-in)

HeroSSID .NET 10 exposes `IssuerGuardianRecovery.Create` and `TryVerify` as a **private offline recovery-evidence profile** for a lost Ed25519 issuer signing key. This deliberately addresses the case where the previous issuer seed **cannot sign** a normal two-key successor attestation. It does not replace `did:key`, reassign DID ownership, recover the lost seed, or grant rights.

## Trust and prerequisites

Before losing the old key, each relying party must **independently authenticate and enroll** a fixed set of guardian Ed25519 `did:key` public identities, the old issuer DID, its own HTTPS verification audience, and a policy threshold of at least two independent guardians (maximum five). Two signatures from the same guardian never meet a two-guardian threshold. The proposed successor must sign the **same** short-lived statement to prove control of its own new key.

The verifier must generate a fresh unpredictable nonce, bind it to a pending recovery request, enforce its own expiry and **atomically consume the nonce once** before carrying out any separate administrative enrollment decision. `TryVerify` is stateless and intentionally **does not consume a challenge**. No existing credential automatically starts trusting the successor.

## SDK entry points

```csharp
using HeroSSID.Credentials.Vcdm20;

// Offline evidence creation. These are example variables supplied by the caller,
// not test keys to reuse. Each signer owns and protects its real Ed25519 seed.
string evidence = IssuerGuardianRecovery.Create(
    previousIssuerDid, proposedIssuerDid, successorSeed,
    new Dictionary<string, byte[]>(StringComparer.Ordinal)
    {
        [guardianOneDid] = guardianOneSeed,
        [guardianTwoDid] = guardianTwoSeed
    },
    new Uri("https://verifier.example/recover-issuer"),
    verifierIssuedUnpredictableNonce,
    TimeProvider.System);

// The verifier retrieves these pins and threshold from its *own*
// previously authenticated policy, never from the recovery envelope.
bool signaturesAndStatementValid = IssuerGuardianRecovery.TryVerify(
    evidence, independentlyPinnedPreviousIssuerDid,
    new[] { pinnedGuardianOneDid, pinnedGuardianTwoDid, pinnedGuardianThreeDid },
    requiredGuardianSignatures: 2,
    new Uri("https://verifier.example/recover-issuer"),
    independentlyStoredNonce,
    TimeProvider.System.GetUtcNow(),
    out string proposedSuccessorDid);

// This is not an approval. The application must now check that the separate
// trusted challenge is still pending, atomically consume it exactly once,
// require its organization/account recovery authorization process, and only
// then decide whether its own issuer trust registry should change.
```

The envelope includes `successorSignature` and `guardianSignatures`. Each signed `herossid-issuer-guardian-recovery+jwt` carries the **identical** JSON statement with version, purpose, pinned old issuer, proposed successor, HTTPS verifier audience, nonce, and fractional-second UTC `iat`/`exp` (at most five minutes). Verification checks all original Ed25519 signatures, key IDs, strong canonical compact JWT representation, exact signed bytes, unique trusted guardians, exact purpose and original issuer binding, and expiry. Any invalid/unknown signer, duplicate, mixed statement or stale/future evidence fails closed without returning the proposed successor.

## Threat and product boundaries

The proof is only evidence that independently pinned guardian **keys** and a new candidate key agreed at a particular time. It does **not** prove those keys belong to legitimate employees, that pre-enrollment was uncompromised, that a lost old key was actually lost, that the organization approved the transition, that a subject controls a holder key, that an issuer's credentials are valid, or that a verifier should trust the successor. There is no server storage, recovery UI, challenge lifecycle endpoint, status publication, identity-vetting, business authorization, OpenID4VP exchange or third-party wallet conformance.

If a guardian key is compromised, a verifier must apply its own independent incident policy and rotate or remove that guardian pin. Applications must keep the recovery threshold independent from the presented proof, and must never treat a successful cryptographic verification as automatic authority to issue credentials.

See [vision](VISION.md) and [existing old/new key continuity attestation](../src/Libraries/HeroSSID.Credentials/Vcdm20/IssuerKeySuccessorAttestation.cs). The latter is preferable when the previous key remains available; guardian evidence is an opt-in recovery path and cannot substitute for trustworthy enrollment.
