# VC2 verifier-owned exact signed-request pin (opt-in .NET SDK)

The verifier can now require **both** the original Ed25519-signed, eight-field
`herossid-request+jwt` and its independently retained **exact compact JWT
SHA-256** before accepting a direct VC Data Model 2.0 full-disclosure holder
presentation. This protects against a later, also-genuine request signed by
the same verifier for the same nonce but a different request body.

This is a **private HeroSSID protocol**, not a W3C OpenID4VP 1.0 transport,
independent Wallet interoperability, user-consent evidence, identity checking
or application authorization. Wallets hold and disclose; issuer trust, original
request custody and challenge replay policy belong to the verifier.

## Verifier-owned integration

1. Issue a one-use, tenant-bound challenge with a shared atomic
   `IPresentationChallengeStore`, using the independently trusted issuer DID.
2. Sign **one original** request with `OfflineSignedPresentationRequest.Create`
   and the verifier's own Ed25519 DID seed. Set both
   `CredentialType` and `SubjectContextUri` on the transient challenge
   *before signing*. Never take type/context or trusted issuer from the holder.
3. Persist the **exact original signed compact JWT SHA-256**, alongside the
   transaction reference, under verifier operator control. The challenge store
   retains tenant/nonce/issuer/audience/expiry, **not** this digest nor the
   transient vocabulary. Supply the digest from the verifier's own state and
   **never** from the incoming presentation/HTTP body.
4. Disclose the request to the Wallet app, which verifies the issuer and
   verifier signatures and displays **every** requested/credential claim
   before obtaining genuine informed consent. No library call proves consent.
5. On return, load the original request and independently retained digest
   from verifier storage. Run the opt-in signed-request check with exactly the
   previously pinned verifier DID, audience, nonce, type and HTTPS context.

```csharp
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.Vcdm20;

// At issuance, retain this digest in YOUR verifier-controlled transaction store:
// The original request JWT was created from the retained one-use challenge.
string retainedRequestSha256 = Convert.ToHexStringLower(
    SHA256.HashData(Encoding.UTF8.GetBytes(originalSignedRequestJwt)));

// Later, load both artifacts from YOUR verifier-controlled state.
// Never set retainedRequestSha256 from holder-submitted input.
Vcdm20PresentationCheckResult holderResult =
    Vcdm20JosePresentation.CheckWithPinnedSignedVerifierRequest(
        holderSignedVc2PresentationJwt, originalSignedRequestJwt,
        retainedRequestSha256, independentlyPinnedVerifierDid,
        verifierTenantId, pinnedAudience, retainedNonce, pinnedCredentialType,
        pinnedContextUri, sharedAtomicChallenges, TimeProvider.System,
        out var verifiedSubject);

// Only SignedButStatusUnchecked exposes an issuer/holder-authenticated subject.
// It NEVER proves current non-revocation.
```

To require a genuine same-issuer short-lived private revocation snapshot
for the exact VC2 JWT inside the holder proof, use:

```csharp
Vcdm20RevocationCheckResult status =
    Vcdm20RevocationSnapshot.CheckPresentationWithPinnedSignedVerifierRequest(
        holderSignedVc2PresentationJwt, originalSignedRequestJwt,
        retainedRequestSha256, independentlyPinnedVerifierDid,
        issuerSignedStatusSnapshotJwt, verifierTenantId, pinnedAudience,
        retainedNonce, pinnedCredentialType, pinnedContextUri,
        sharedAtomicChallenges, TimeProvider.System,
        out var verifiedSubjectWithStatus);
```

Only `SignedNotListed` releases subject claims on the status-aware route.
It is a genuine issuer signature over a short-lived private digest list, not
proof of complete or real-time issuer revocation observation. A rejected
request does not spend the nonce; an accepted real holder proof atomically
spends it, including when the subsequent status check rejects the credential.
Never treat an unchecked issuer signature, possession proof or status
non-listing as real-world identity or business authorization.

## Precisely bounded guarantees

- The exact original request **bytes** are pinned by lowercase, 64-digit
  SHA-256. Alternate genuine requests for the same issuer, nonce, audience,
  type and context still fail if the original request digest differs.
- The Ed25519 request signature must authenticate the separately pinned
  verifier DID, explicit credential type and exact HTTPS context. The
  tenant-bound durable challenge must match signed nonce, issuer and expiry.
- Both real issuer and independent holder Ed25519 signatures are checked
  before any claims are released. Verifier retains atomic nonce consumption;
  wrong tenant, altered request, expired proof, malformed digest and replay
  fail closed.
- This SDK **does not persist** the digest or the original request; a client
  that takes the digest from the presenter or does not preserve it cannot
  claim exact-original request binding. Multi-instance deployments must
  synchronize verifier-owned request pins and use an atomic shared challenge
  store. No new schema, endpoint, remote trust registry or key custody.
- No standardized W3C credentialStatus, live revocation, selectively
  disclosed claims, hosted OpenID4VP exchange, consent record, legal identity
  or independent third-party-wallet test is provided.

## Reproducible regressions

```shell
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj --configuration Release --filter FullyQualifiedName~Vcdm20SignedVerifierRequestTests
```

The suite uses distinct real Ed25519 verifier, issuer, holder and attacker
keys. It checks genuine one-use positive paths, issuer-signed status, legacy
unbound downgrade, substituted authentic credential vocabulary, unrelated
authentic issuer/expiry, forged verifier signer, an alternate genuinely
verifier-signed request for the **same exact nonce and policy**, malformed pin
and replay. These are internal .NET SDK regressions, not independent
wallet/protocol conformance. See [vision](VISION.md), [VC2 presentation
profile](vcdm20-jose-presentation-profile.md) and [current capability
boundaries](../README.md#implemented-capabilities-and-boundaries).
