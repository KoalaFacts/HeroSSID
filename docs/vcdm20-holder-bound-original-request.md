# Holder-signed exact VC2 verifier request binding (opt-in .NET 10 SDK)

A verifier-owned SHA-256 of the original signed request is necessary but **does
not, by itself, prove which signed request the holder actually received and
signed for**. Two genuine verifier Ed25519-signed requests could carry the
same issuer, audience, nonce, expiry, type and HTTPS context but differ in
signing time or other signed bytes. The original [verifier-side pin
profile](vcdm20-original-request-pin.md) intentionally did not bind this
digest into the holder signature.

The new strict, opt-in API closes **that specific proof substitution gap**.
The holder signs a private `herossidRequestSha256` VP JWT claim containing
the lowercase hex SHA-256 of the *exact original compact verifier request*.
A relying verifier separately retrieves its **own** original signed request
and digest (never a presenter-provided pin), authenticates the verifier
Ed25519 signature, matches the live one-use tenant challenge and the
credential vocabulary, then verifies the issuer and holder signatures and
the holder's digest **before consuming** the nonce or releasing subject
claims. The status-aware entry point can additionally require a genuine
short-lived issuer-signed private revocation snapshot for that same VC2 JWT.

## Exact API contract

```csharp
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.Vcdm20;

// The verifier issues and retains the policy-bound original request and
// its SHA-256 under independently trusted, tenant-owned transaction state.
string retainedSha256 = Convert.ToHexStringLower(
    SHA256.HashData(Encoding.UTF8.GetBytes(originalRequestJwt)));

// The Wallet separately pins the verifier DID and audience, checks the
// signed request and original issuer credential, displays all claims and
// obtains its own real disclosure consent BEFORE accessing its seed.
string holderProof = Vcdm20JosePresentation.CreateWithSignedRequestBinding(
    originalRequestJwt, walletPinnedVerifierDid, walletPinnedAudience,
    originalIssuerSignedCredentialJwt, pinnedCredentialType, pinnedContextUri,
    holderDid, walletOwnedHolderSeed, TimeProvider.System);

// Verifier: retrieve *both* originalRequestJwt and retainedSha256 from
// verifier-controlled storage, not from the incoming holder payload.
var result = Vcdm20JosePresentation.CheckWithHolderBoundSignedVerifierRequest(
    holderProof, originalRequestJwt, retainedSha256, verifierPinnedDid,
    verifierTenantId, verifierPinnedAudience, retainedNonce,
    pinnedCredentialType, pinnedContextUri, sharedAtomicChallenges,
    TimeProvider.System, out var verifiedSubject);

// SignedButStatusUnchecked checks real issuer/holder signatures and original
// request binding, but it does NOT prove revocation or authorization.
```

To additionally check actual issuer-signed private status for the enclosed
credential, call:

```csharp
var status = Vcdm20RevocationSnapshot
    .CheckPresentationWithHolderBoundSignedVerifierRequest(
        holderProof, originalRequestJwt, retainedSha256, verifierPinnedDid,
        actualIssuerSignedStatusJwt, verifierTenantId, verifierPinnedAudience,
        retainedNonce, pinnedCredentialType, pinnedContextUri,
        sharedAtomicChallenges, TimeProvider.System, out var statusSubject);
```

Only `SignedNotListed` releases claims from this status-aware entry point.
It means the authentic issuer's stated, bounded list does not include this
credential. Its completeness or real-time accuracy is NOT established.

## Failure and compatibility semantics

- The strict verifier rejects legacy eight-field VPs with no holder-signed
  request digest, another genuinely signed request for the same nonce, a
  changed digest, forged verifier/issuer/holder signatures, a wrong tenant,
  invalid vocabulary, expiry and replay. Invalid proof/pin does not consume
  the nonce or expose claims; a valid one-use proof consumes it.
- The original `Create`, `Check`, `CheckWithPinnedSignedVerifierRequest`
  and status methods **retain their historical behavior**. They do not
  automatically gain holder-signed exact request binding. A relying party
  must opt into the pair of new strict methods rather than mix the legacy
  verifier with the strict holder proof.
- The holder-signed digest is a **HeroSSID private JWT extension**, not a
  W3C or OpenID4VP standardized request-hash claim. Direct VC 2.0 JWT
  issuance is based on [W3C VC JOSE/COSE Recommendation
  (13 October 2026)](https://www.w3.org/TR/2026/REC-vc-jose-cose-20261013/),
  but this additional private request handshake and verifier pin do **not**
  establish complete W3C VC conformance, OpenID4VP interoperability or any
  independent third-party Wallet compatibility.
- The verifier must secure and synchronize original request pins and its
  atomic one-use challenge store across replicas. No new schema, hosted
  endpoint, wallet key escrow, consent evidence, status completeness,
  real-world identity check, Agent delegation or business authorization.
  A valid holder signature proves control of the corresponding private
  seed, not informed consent or the truth of the issuer's attestation.

## Reproduction

```sh
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj --configuration Release --filter FullyQualifiedName~Vcdm20SignedVerifierRequestTests
```

The test set creates genuinely distinct Ed25519 verifier, issuer, holder and
attacker keys, checks true successful one-use verification, a different
authentic verifier-signed request with the same challenge, missing hash,
invalid verifier-held digest, issuer-signed status and replay. These are
internal SDK regressions, not third-party Wallet interoperability tests.
