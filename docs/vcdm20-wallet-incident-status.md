# VC2 Wallet post-incident issuer-status cutoff (opt-in SDK)

A verifier can reject authentic VC2 issuer status that was signed before a security incident, even if its normal 60-second lifetime has not elapsed. A Wallet must not disclose a credential to that verifier merely because a pre-incident snapshot remains cryptographically valid. The opt-in `Vcdm20WalletIncidentDisclosure` API applies the same **minimum issuer observation time** before revealing full-disclosure subject claims or accessing the holder's Ed25519 seed.

This is the existing **HeroSSID-private** VC2 JOSE and signed-status profile. It is **not** a W3C Bitstring Status List, OpenID4VP interoperability, human consent proof, issuer completeness guarantee or real-time non-revocation check.

## Integration sequence

The Wallet operator obtains `minimumObservedAt` from its own independently trusted incident policy, not a value supplied by the issuer JWT, verifier request or holder. It must pin a trusted verifier DID, HTTPS audience, issuer DID, holder DID, credential type and HTTPS context. The verifier has already issued a retained one-time challenge containing that signed credential type/context and signed the request using `OfflineSignedPresentationRequest.Create`.

```csharp
using HeroSSID.Credentials.Vcdm20;

// Values below come from independently pinned Wallet/operator policy.
DateTimeOffset minimumObservedAt = walletIncidentPolicy.MinimumIssuerObservedAt;

if (!Vcdm20WalletIncidentDisclosure.TryPrepare(
        signedVerifierRequestJwt, expectedVerifierDid, expectedAudience,
        expectedCredentialType, expectedContextUri, expectedIssuerDid,
        originalIssuerVc2Jwt, holderDid, issuerSignedStatusSnapshotJwt,
        minimumObservedAt, TimeProvider.System, out var preview) ||
    preview is null)
{
    // A forged, revoked, pre-incident, expired or unbound artifact cannot
    // expose authenticated subject claims. No holder private key was used.
    return;
}

// Show the destination, trusted issuer, expiry and EVERY verified claim.
// This is full disclosure, not selective disclosure.
if (!await ShowAllClaimsAndObtainActualConsentAsync(preview.Status.Disclosure))
{
    return; // Wallet consent/cancellation is the integrating app's responsibility.
}

// Re-read the Wallet operator's incident policy AFTER consent; it might have
// advanced during the user's decision. Never take this value from preview.
DateTimeOffset currentlyRequired = walletIncidentPolicy.MinimumIssuerObservedAt;

string holderSignedVp =
    Vcdm20WalletIncidentDisclosure.CreateHolderBoundPresentationAfterPreview(
        preview, signedVerifierRequestJwt, originalIssuerVc2Jwt,
        issuerSignedStatusSnapshotJwt, currentlyRequired,
        holderOwnedEd25519Seed, TimeProvider.System);

// Only deliver to the independently trusted verifier. It must separately
// retain the exact original signed-request SHA-256, check authentic issuer,
// verifier and holder signatures, signed status and atomically consume nonce.
```

The preflight first verifies real issuer Ed25519 status authenticity against the independently pinned issuer and rejects pre-incident `iat`, including a fractional-second cutoff that a second-precision snapshot cannot satisfy. It then validates the genuine verifier-signed credential type/context and unchanged issuer credential through the existing strict status-aware Wallet API. Only authentic `SignedNotListed` status releases the entire subject to the Wallet UI.

After consent, the signer independently compares the newly supplied operator cutoff against the preview's cutoff, rechecks the unchanged signed status, the original verifier request, the signed issuer credential, the entire displayed subject and the holder's real Ed25519 seed. It signs the exact original request digest, then checks issuer status again after signing. If the minimum observation time changed while the user considered disclosure, the old preview fails and the app must obtain a **new preview and fresh consent**. Refreshed status is not silently substituted.

For a relying verifier, use `Vcdm20RevocationSnapshot.CheckPresentationWithHolderBoundSignedVerifierRequest` with the independently retained original request and its lowercase SHA-256, correct trusted verifier DID, tenant, issuer-signed snapshot and shared one-use challenge store. The verifier must enforce its own incident cutoff separately; this Wallet-side protection does not substitute for verifier policy.

**Limitations:** The issuer controls the truth and completeness of the private signed status. A genuine signed timestamp can be false; an omitted credential does not establish live non-revocation. The Wallet still needs its own consent UI, trust-pin management and secure holder seed custody. No production database, new schema, HTTP endpoint, release, standards conformance claim, real identity validation or business/Agent authorization is added.
