# Signed-ID VC2 membership: status-gated Wallet preview and holder proof (opt-in)

This .NET 10 SDK feature completes the **holder-facing half** of the independently pinned VC2 membership proof verified by `Vcdm20SignedClaimPresentation.CheckWithIssuerStatus`. Before the holder private key is used, the Wallet can authenticate the original issuer's Ed25519 VC2 JWT, its **exact top-level HTTPS credential `id`**, selected `membership=active` subject values, the verifier's real policy-bound Ed25519 request and a genuine status snapshot from that **same issuer**.

## Exact integration boundary

The Wallet must independently enroll the verifier DID and audience, issuer DID, holder DID, VC type, versioned HTTPS subject context, credential ID, required string-claim policy and minimum status observation instant. **Do not copy these trust anchors from an incoming QR code, request or credential.**

```csharp
using HeroSSID.Credentials.Vcdm20;

var requiredClaims = new Dictionary<string, string>
{
    ["membership"] = "active"
};

// All expected values and cutoff are Wallet-owned, previously approved policy.
if (!Vcdm20SignedIdWalletDisclosure.TryPrepare(
        signedVerifierRequestJwt, pinnedVerifierDid, pinnedAudience,
        "MembershipCredential", pinnedContextUri, pinnedIssuerDid,
        originalSignedVc2Jwt, holderDid, pinnedCredentialId,
        requiredClaims, originalIssuerSignedSnapshotJwt,
        walletMinimumObservedAtUtc, TimeProvider.System, out var preview)
    || preview is null)
{
    // Invalid/revoked/stale/wrong signer/wrong id/inactive: no claims or seed use.
    return;
}

// The Wallet app displays preview.VerifiedSubject in FULL, all verified
// signers/identifiers, destination and expiry, and obtains actual consent.
if (!await ShowCompleteDisclosureAndObtainConsentAsync(preview))
{
    return;
}

string vpJwt = Vcdm20SignedIdWalletDisclosure.CreateAfterPreview(
    preview, signedVerifierRequestJwt, originalSignedVc2Jwt,
    originalIssuerSignedSnapshotJwt, holderOwnedEd25519Seed,
    TimeProvider.System);

// Transmit to the independently approved relying verifier.
```

The verifier must retain and atomically consume its own tenant-owned single-use challenge. It calls `Vcdm20SignedClaimPresentation.CheckWithIssuerStatus` with its **own** issuer allowlist, holder DID, credential ID, exact claim values and independently required observation cutoff; only `SignedNotListed` may release signer and subject. An invalid or revoked proof releases nothing. A replay fails even if genuine.

### Required protections

- `TryPrepare` only accepts a genuine eight-claim `herossid-request+jwt` where the verifier **signed** its requested VC type and HTTPS context; the older unbound request is refused.
- The original seven-field `vc+jwt` must have a real issuer Ed25519 signature, exactly pinned issuer/holder/credential ID, type, context, lifetime and exact top-level string claims. The issuer signature alone does not approve the signed `membership` value.
- The original `herossid-vc2-revocation-snapshot+jwt` must be genuine, current, signed by the **same** verified issuer, and meet the independently configured observation cutoff. Revoked, omitted, stale, invalid or foreign status prevents even a preview.
- Before holder signing, `CreateAfterPreview` independently reauthenticates **all three unchanged signed artifacts**, SHA-256 fingerprints, complete previewed subject, policy and expiry. It rejects another genuinely signed credential/status or a wrong holder key. It rechecks the signed request and issuer status after signing so an expiry during signing cannot yield a successful status-gated return.
- The integrating Wallet owns the private signing seed and must clear it. Neither the preview nor the library can prove a human actually saw or consented to the disclosure. **Every signed subject claim is disclosed.** A hostile or misconfigured host application can deliberately bypass the UI.

### Limits

The issuer's private, short-lived `SignedNotListed` report only states that its supplied digest set omitted the exact JWT. HeroSSID cannot prove that the list was complete, that its declared observation time was honest, or that revocation was checked live. A signed `membership=active` claim is not a current entitlement, independently validated real identity, business authority or Agent delegation. This feature does not add a W3C Bitstring Status List, a standards-conformant OpenID4VP exchange, selective disclosure, third-party wallet interoperability, hosted consent UI, production deployment or database schema change.

The existing six-field VC2 Wallet preview and signatures are unchanged. This new signed-ID path is explicitly **opt-in** and uses HeroSSID's private request and status formats. The underlying direct VC2 JOSE format follows a constrained profile; independent conformance/interop remains unproven.

## Real acceptance test

```shell
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj \
  --configuration Release \
  --filter FullyQualifiedName~Vcdm20SignedIdWalletDisclosureTests
```

Distinct genuine Ed25519 issuer, holder, verifier and attacker keys exercise full preview → holder signature → verifier acceptance → one-use replay refusal, revoked/wrong-signer/stale status, inactive membership, wrong signed ID, swapped authentic credential/status and wrong holder seed. These are internal tests, not independent Wallet conformance.

See [signed-ID issuer profile](vcdm20-issuer-signed-id.md), [holder-bound verifier policy](vcdm20-holder-bound-claim-policy.md), [VC2 JOSE profile](vcdm20-jose-profile.md), and [vision](VISION.md).
