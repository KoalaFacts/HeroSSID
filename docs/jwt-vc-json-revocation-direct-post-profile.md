# VC1.1 `jwt_vc_json` issuer status bound to OpenID4VP `direct_post`

The .NET 10 SDK now provides **opt-in, issuer-signed short-lived status checking** for the exact W3C VC Data Model 1.1 `jwt_vc_json` issuer JWT nested inside a holder-signed `vp+jwt` presentation. It extends [the bounded signed-request/`direct_post` transport](jwt-vc-json-openid4vp-direct-post-profile.md), without claiming general OpenID4VP conformance or third-party wallet interoperability.

This is a **private HeroSSID status export**, `herossid-jwt-vc-json-revocations+jwt`, **not** a W3C `credentialStatus` / Bitstring Status List. It does not replace [the existing VCDM 2.0 status format](vcdm20-revocation-snapshot-profile.md) or the legacy issuer database's snapshot format.

## Usable issuer/verifier calls

1. The issuer must independently know its authoritative **complete** revoked VC1.1 JWT set for one specific `did:key` issuer. Record `observedAt` **before** reading its external status source, then call `JwtVcJsonRevocationSnapshot.Create(issuerDid, revokedCredentialJwts, issuerSeed, observedAt, clock)`. The signed export is at most 60 seconds old and contains at most 256 SHA-256 digests; a larger or forged set is refused, never silently truncated. It authenticates that the issuer **signed this list**, not that its underlying revocation source is complete.
2. The verifier independently pins its trusted issuer DID, expected verifier client ID, nonce, credential type and HTTPS subject context. After retaining a challenge in a verifier-owned atomic `IPresentationChallengeStore`, it verifies the holder's `direct_post` body and issuer-provided snapshot together:

```csharp
RevocationSnapshotCheckResult result = JwtVcJsonDirectPostRevocation.CheckResponseForm(
    form, snapshotJwt, verifierTenantId, expectedClientId, expectedNonce,
    expectedCredentialType, expectedSubjectContextUri, challenges, clock,
    out JsonElement verifiedSubject);
```

3. `Revoked` means that the exact unchanged issuer-signed JWT from the verified holder VP appeared in the signed set; `Invalid` covers absent, stale, forged, foreign, malformed, expired, replayed or wrongly bound evidence. **Neither releases claims.** Only `NotListed` releases the signed subject claims **after** both real Ed25519 signatures, the verifier trust policy and the atomic one-use challenge pass. A valid presentation spends the challenge even if status subsequently fails; do not retry that nonce.

The verifier must use a **shared atomic challenge store** across HTTP replicas. Never accept a wallet-provided issuer trust root or substitute a caller-supplied second credential for the signed JWT inside the VP. Status transport/publication, wallet consent UI and authoritative revocation collection remain responsibilities of calling applications.

## Trust limits and evidence

`NotListed` is **not** proof of current non-revocation: an issuer may have omitted a revoked JWT, or revoked it after the observed snapshot. Neither status signatures nor a holder's Ed25519 proof establish human identity, organisation enrollment, physical presence, consent or permission to take a business action. Verifiers must enforce independent application authorization.

The xUnit `JwtVcJsonDirectPostRevocationTests` uses distinct issuer/holder/verifier keys to prove revoked rejection with challenge consumption; unlisted exact JWT acceptance; foreign issuer, tampered/expired status and foreign-tenant denial. These are **in-process contract tests**, not independent external-wallet conformance or external security certification. Run:

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj --configuration Release --filter FullyQualifiedName~JwtVcJsonDirectPostRevocationTests
```

No database schema, production data, key custody, issuer publication endpoint, hosted callback or package release is changed.
