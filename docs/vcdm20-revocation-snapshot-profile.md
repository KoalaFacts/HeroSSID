# VC2 issuer-signed bounded revocation snapshot (HeroSSID private profile)

This optional .NET10 library adds issuer-controlled status to the direct VC Data Model 2.0 JOSE credential and full-disclosure holder presentation paths. It is **not** a W3C Bitstring Status List, a `credentialStatus` implementation, a network status service or an independent-wallet interoperability claim. W3C VC Data Model 2.0 permits status schemes via `credentialStatus`; this implementation is a distinct, explicitly private signed adjunct and does not pretend to be one of those standard status formats.

## Usable issuer-to-verifier flow

The issuer retains its own authoritative, **complete** set of revoked *direct VC2* JWTs. Before reading that set, record `observedAt = clock.GetUtcNow()`. After reading the records, call:

```csharp
string snapshot = Vcdm20RevocationSnapshot.Create(
    issuerDid, completeRevokedVc2Jwts, issuerOwnedSeed, observedAt, clock);
```

The library checks every listed credential's real Ed25519 issuer signature and direct VC2 shape, then signs sorted unique SHA-256 hashes of their **exact compact JWT bytes**. The signature is pinned to the exact self-certifying issuer `did:key`. An export over 256 input records, an invalid/foreign revoked credential, a wrong signing key, a future observation time, or an elapsed 60-second window is rejected. This prevents accidental partial-list publication by this API, but **cannot attest that an upstream caller supplied all revoked credentials**. An empty list is meaningful only when the issuer has independently established that nothing is revoked.

The issuer may deliver this private snapshot through its own authenticated distribution channel to a verifier that independently pins the issuer DID. The library has no DB, API-hosted publication endpoint, tenant administration, refresh scheduler or trusted issuer registry. An issuer MUST use its tenant-specific ownership and authorization policy before signing or releasing any snapshot. The source of revocation truth, publication cadence and failures remain the issuer's responsibility.

An independent verifier can check an original issued JWT with:

```csharp
var status = Vcdm20RevocationSnapshot.Check(
    snapshot, originalIssuerSignedVc2Jwt, independentlyTrustedIssuerDid, clock.GetUtcNow());
```

`Revoked` means the digest appears in a fresh authentic issuer-signed snapshot; `SignedNotListed` means only that the authentic snapshot omitted it. A forged/wrong-issuer/malformed/expired snapshot returns `Invalid`. This check is **not** a replacement for `Vcdm20JoseCredential.TryVerify` (holder, context, type, credential validity), real-world identity checks, or business authorization.

For a full holder presentation, the verifier can perform one atomic, fail-closed operation:

```csharp
var result = Vcdm20RevocationSnapshot.CheckPresentation(
    holderSignedVpJwt, snapshot, verifierTenantId, expectedAudience,
    verifierIssuedNonce, expectedCredentialType, pinnedContextUri,
    verifierChallengeStore, clock, out var signedSubject);
```

This verifies the original issuer-signed direct VC2 JWT inside the holder-signed VP, real holder key control, the verifier-owned one-use challenge and snapshot membership of **that exact enclosed credential**. Claims are returned only on `SignedNotListed`; replay, wrong tenant/issuer, invalid/expired status or a revoked VC return no claims. Even rejected statuses spend the challenge after cryptographic validation. A multi-instance verifier must use a durable shared atomic challenge store, not the process-local default.

## Wire and security boundary

- JWS type: `herossid-vc2-revocation-snapshot+jwt`, signed with EdDSA by the claimed issuer DID. Distinct from legacy `herossid-revocation-snapshot+jwt`.
- Payload: `version:1`, exact `iss`, `format:"vcdm20-direct-jose"`, integer `iat` and `exp` (maximum 60 seconds), `revoked` as an ascending, unique, lowercase hex SHA-256 digest array, max 256.
- Snapshot signatures, exact issuer DID, token structure, time bounds, digest syntax/order and actual issuer credential signatures are checked. No raw holder attributes are included. An observer possessing the original JWT can check whether its digest is listed; set size and membership are linkable.
- The verifier must choose trusted issuers from an independent policy. A signature proves key control, not enrollment, real-world identity or authority. **`SignedNotListed` is neither live non-revocation nor an affirmative business permission.** Old snapshots can remain stale until expiry; if status cannot be fetched or has expired, verification fails closed.
- No production database migration, schema, deployment, key custody, automatic VC status publication, JSON-LD semantic expansion or independent wallet conformance is implied.

A future standard status-list publisher must be separately specified and tested using a genuinely interoperable `credentialStatus` profile rather than relabeling this private proof.
