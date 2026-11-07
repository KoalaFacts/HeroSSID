# One-use did:web VC1.1 admission: verifier denial **and** issuer status

Independent verifiers often need two *separate* vetoes: an operator-maintained emergency denial for a specific original credential, and a recent issuer-signed status observation. The two pre-existing SDK gates each consume a one-use holder nonce, so invoking them **sequentially is not correct**: the second check will reject a valid presentation as replay. `JwtVcJsonPinnedDidWebIssuerAdmission.Check` is a dedicated **single-check** SDK path that enforces both policies while consuming the challenge once.

## Working SDK entry point

```csharp
using HeroSSID.Credentials.JwtVcJson;

// The calling verifier has independently authenticated the verifier request,
// enrolled the trusted did:web issuer DID and #key-1/#key-2 assertion method,
// pinned its 32-byte Ed25519 issuer key, descriptive issuer name, HTTPS
// credential ID, type and context, and owns a shared atomic challenge store.
// The original holder presentation and signed issuer status are unchanged.
JwtVcJsonPinnedDidWebIssuerAdmissionResult outcome =
    JwtVcJsonPinnedDidWebIssuerAdmission.Check(
        holderSignedPresentationJwt, issuerSignedStatusJwt, verifierTenantId,
        expectedAudience, expectedNonce, trustedIssuerDid,
        trustedIssuerAssertionMethodId, independentlyPinnedIssuerPublicKey,
        expectedIssuerName, expectedCredentialId, expectedCredentialType,
        expectedSubjectContextUri, verifierOwnedDeniedOriginalJwtSha256,
        sharedChallengeStore, TimeProvider.System, out var verifiedSubject);

if (outcome == JwtVcJsonPinnedDidWebIssuerAdmissionResult.SignedNotRevoked)
{
    // ONLY here: release the authenticated subject to the relying application's
    // own identity, membership and business-authorization decision.
}
```

The issuer signs the **unchanged original VC1.1 `jwt_vc_json`** and a separate HeroSSID-private, 60-second `herossid-didweb-vc11-exact-status+jwt` statement using the same independently pinned real Ed25519 assertion method. The holder separately signs a full-disclosure `vp+jwt` with its real `did:key` Ed25519 key. The verifier must obtain its issuer keys and local emergency denylist from trusted operator policy, **not** any JWT, wallet or untrusted request. The local denylist contains 0–256 unique canonical lowercase SHA-256 hex fingerprints of the **original compact issuer JWT UTF-8 bytes**, never fingerprints of a holder presentation or issuer status.

## Exact return behavior

| Result | When | Release claims? | Spend an authentic challenge? |
|---|---|---|---|
| `SignedNotRevoked` | Original issuer and holder signatures valid; live verifier challenge; local denylist clean; same issuer signs a fresh `revoked=false` exact-JWT status | Yes | Yes |
| `DeniedByVerifier` | Fully verified authentic proof/status, but exact original credential is in verifier's local emergency denylist | No | Yes |
| `RevokedByIssuer` | Fully verified authentic proof, clean local denylist and issuer signs a fresh `revoked=true` exact-JWT status | No | Yes |
| `Invalid` | Forgery, changed original JWT, wrong issuer/method/key/metadata/tenant/nonce, replay, stale/missing/foreign status, or invalid operator policy | No | Genuine valid VP with a forged/wrong status is spent; missing/oversized status or malformed local policy fails before spending |

If both local denial and issuer revocation apply, this implementation reports `DeniedByVerifier` once the issuer status signature is authenticated. This is a diagnostic distinction, **not** permission to release claims. A valid status signed for another original JWT cannot clear the one inside the holder's authenticated VP. A forged status cannot reveal local denial results before the issuer-status signature is accepted.

`SignedNotRevoked` means only that the same real pinned issuer signed a fresh assertion that its own source of truth observed `revoked=false`. It does **not** prove that the observation was honest, complete or still current, nor that the issuer signing key is not compromised. If a key is suspected compromised, the relying party must update its independent issuer trust policy, not rely on `revoked=false` from that key. A verifier-owned denial is **not** an issuer revocation. No W3C Bitstring Status List, hosted protocol, remote DID resolution, Wallet UI, human consent evidence, legal identity, Agent authority or independent third-party Wallet interop is provided.

## Real-key regression

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj --configuration Release --filter FullyQualifiedName~JwtVcJsonPinnedDidWebIssuerStatusTests
```

The real-key cases include clean disclosure, replay rejection, local deny override and nonce consumption, issuer revocation, invalid/duplicate local policy without spending, missing status, wrong independently pinned issuer key, same-issuer status for a different JWT and forged status before disclosure. All repository Build/Test/Security and CodeQL gates remain required. No database schema, production migration, deployment, keys, NuGet publication or license change is involved.
