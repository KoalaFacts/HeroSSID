# Opt-in exact-JWT did:web issuer status before holder claim disclosure

A separately enrolled `did:web` VC Data Model 1.1 issuer can make a **60-second, issuer-signed observation** for one exact original issuer JWT using `JwtVcJsonPinnedDidWebIssuerStatus.Create` (.NET 10 SDK). The verifier can combine this with the independently pinned issuer-name/HTTPS credential-ID policy and a genuine `did:key` holder-signed one-use VP using `JwtVcJsonPinnedDidWebIssuerStatus.CheckPresentation`.

The issuer signs the lower-case SHA-256 of the UTF-8 bytes of the **unchanged compact original issuer credential**, the exact `did:web` issuer, the fixed `#key-1` or `#key-2` assertion method, one boolean `revoked`, and the original observation time. The snapshot is signed by the **same independently configured Ed25519 key** that signed the credential, not a key discovered in a JWT or a wallet-provided status URL. It is a small HeroSSID-private status envelope with `typ=herossid-didweb-vc11-exact-status+jwt`; **not** a W3C Bitstring Status List, third-party Wallet protocol or formal issuer-status standard.

## Execution

```csharp
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;

// Issuer-side: these original issuer keys and source-of-truth revocation
// observations must come from independently controlled issuer infrastructure.
string statusJwt = JwtVcJsonPinnedDidWebIssuerStatus.Create(
    originalIssuerJwt, issuerDid, assertionMethodId, issuerPublicKey,
    issuerSeed, revoked: isRevoked, observedAt: issuerObservedAt,
    clock: TimeProvider.System);

// Verifier-side: the verifier owns all issuer/name/credential-ID pins,
// audience, tenant, outstanding challenge and trusted atomic store.
RevocationSnapshotCheckResult result =
    JwtVcJsonPinnedDidWebIssuerStatus.CheckPresentation(
        holderSignedVpJwt, statusJwt, verifierTenantId,
        expectedAudience, expectedNonce, enrolledIssuerDid, enrolledMethodId,
        enrolledIssuerPublicKey, expectedIssuerName, expectedCredentialId,
        expectedCredentialType, expectedContext, sharedChallengeStore,
        TimeProvider.System, out var verifiedSubject);

if (result == RevocationSnapshotCheckResult.NotListed)
{
    // Release only these authenticated signed claims to further application
    // identity, purpose and authorization policies. Not a live status proof.
}
```

`NotListed` means the same real issuer explicitly signed `revoked=false` for that *exact credential hash* at its claimed fresh observation instant. `Revoked` means an authentic same-issuer `revoked=true` status and **no claims**. `Invalid` covers missing, stale, forged, wrong-key/wrong-method, wrong-original, malformed or replayed proofs and **no claims**. A valid holder VP consumes its verifier-owned challenge even if subsequent signed status is rejected or reports revocation. Missing/oversized status is checked before consuming the challenge; it does not imply successful status checking.

This is not an assertion that the issuer actually observed the correct backend record, its status remains current beyond 60 seconds, or an old compromised issuer key is safe. If an issuer key is suspected compromised, an authenticated operator must change independently enrolled policy rather than trusting a freshly signed `revoked=false` from that key. No automatic key succession, enrollment, domain ownership proof, hosted HTTP endpoint, public distribution, consent UI, identity verification or Agent/business authorization is supplied. The Wallet still only holds and presents; the application must authenticate a verifier request, fully disclose claims to the holder and obtain consent before signing the VP.

Use a shared atomic challenge store for multiple verifier replicas. No database schema, production migration, deployment, real-user signing key, license or publishing changes are part of this SDK work package.

## Test

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj --configuration Release --filter FullyQualifiedName~JwtVcJsonPinnedDidWebIssuerStatusTests
```

See [pinned issuer issuance](jwt-vc-json-pinned-didweb-issuer.md), [one-use holder presentation](jwt-vc-json-pinned-didweb-presentation-denylist.md), [trust and status limits](VISION.md).
