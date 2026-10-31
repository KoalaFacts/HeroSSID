# VC Data Model 2.0 wallet full-disclosure preflight (opt-in)

A holder Wallet integrating HeroSSID's **direct VC2 JOSE** library can inspect the entire original issuer-authenticated credential before accessing its signing seed. The caller must supply independently trusted verifier, audience, issuer, holder and credential-vocabulary policy; do not copy trust configuration from untrusted request metadata. This is a local SDK, **not** OpenID4VP, an actual wallet UI, independent interoperability or conformance certification.

## Concrete holder journey

The verifier issues and retains a one-use challenge and signs it using OfflineSignedPresentationRequest.Create with its Ed25519 did:key. This remains HeroSSID's private herossid-request+jwt, **not** an OpenID4VP Request Object. An issuer independently signs the original direct VC Data Model 2.0 vc+jwt credential. The holder must not replace that real issuer signature.

    using HeroSSID.Credentials.Vcdm20;

    // The expected values and holderDid come from independently trusted
    // Wallet policy, not from a QR code or untrusted JWT.
    if (!Vcdm20WalletDisclosure.TryPrepare(
            signedVerifierRequestJwt, expectedVerifierDid, expectedAudience,
            expectedCredentialType, expectedSubjectContextUri, expectedIssuerDid,
            originalIssuerSignedDirectVc2Jwt, holderDid, TimeProvider.System,
            out var preview) || preview is null)
    {
        // Reject: do not display unverified subject claims.
        return;
    }

    // Show verifier, audience, issuer, type, context, request expiry and EVERY
    // property in preview.VerifiedSubject. This is full disclosure.
    if (!await ShowEveryClaimAndObtainInformedConsentAsync(preview))
    {
        // No private-key operation on cancellation.
        return;
    }

    string holderSignedVp = Vcdm20WalletDisclosure.CreateHolderPresentationAfterPreview(
        preview, signedVerifierRequestJwt, originalIssuerSignedDirectVc2Jwt,
        holderOwnedEd25519Seed, TimeProvider.System);

    // Send only to the independently trusted verifier; apply status and
    // business authorization separately after holder/issuer proof checks.

TryPrepare validates the verifier's real Ed25519 request signature against the pinned DID and exact audience, its signed trusted-issuer policy, one-use challenge expiry and the original issuer's direct VC2 Ed25519 signature. The credential is verified against independently pinned issuer DID, credential type, holder DID, claim context and validity. Only after **both** checks does it expose authenticated subject JSON. No holder seed or challenge-store access is needed for preview.

The preview retains SHA-256 digests of each **exact compact signed JWT** and the authenticated full subject. CreateHolderPresentationAfterPreview cryptographically revalidates request and credential at the current time; compares their original bytes (digests), expiry and whole displayed subject; then invokes the existing real Vcdm20JosePresentation.Create holder signer. Another genuine issuer credential, a substituted signed request, a forged subject, wrong holder seed or expired request is rejected. A failed attempt does not consume the verifier's challenge. Final Vcdm20JosePresentation.Check atomically consumes it and rejects replay.

## Trust and product boundaries

- Authenticated issuer claims alone do not establish holder private-key control. The holder signs only after its integrating app decides to call signing, and the application must provide genuine disclosure and user consent itself. Digest matching is not evidence the user saw the claims. The original direct signing entry point remains available.
- SignedButStatusUnchecked does not establish real-time non-revocation, business authorization, identity verification, issuer trust discovery or agency delegation. The verifier retains those responsibilities.
- Direct VC2 context values are exact pinned URI comparisons, not JSON-LD expansion. There is no independent third-party wallet test, hosted callback, selective disclosure, OpenID4VP exchange, actual consent UI or managed holder private key.
- Every property in VerifiedSubject is exposed in the full-disclosure presentation. Do not portray this as claim minimization or selective disclosure.

## Reproducible acceptance

    dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj \
      --configuration Release \
      --filter FullyQualifiedName~Vcdm20WalletDisclosureTests

Tests use distinct real Ed25519 verifier, issuer, holder and attacker keys: authentic preview before signing; exact-artifact binding; forged signatures; wrong verifier, audience, issuer, holder and type/context; swapped genuine credentials and requests; expiry; real holder proof; one-time verifier acceptance and replay denial. These are internal SDK tests, not independent wallet or standards conformance. See [VC2 credential profile](vcdm20-jose-profile.md), [VC2 presentation profile](vcdm20-jose-presentation-profile.md) and [current limits](../README.md#implemented-capabilities-and-boundaries).
