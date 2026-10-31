# VC1.1 wallet full-disclosure preflight (opt-in)

A third-party holder Wallet integrating HeroSSID's bounded OpenID4VP 1.0 `jwt_vc_json` / `direct_post` SDK can now **show the exact issuer-authenticated claims before it uses the holder's private key**. This is a library capability; no wallet app, consent UI, public callback, key custody service, third-party interoperability or independent protocol conformance has been delivered.

## Two distinct trust checks before the user sees anything

The wallet application must obtain the following values through its **own trusted configuration or user-confirmed relationship**, not simply copy them from an untrusted QR link, JWT or callback:

- verifier `did:key`, exact HTTPS `response_uri`, requested HTTPS credential type and subject context;
- issuer `did:key` trusted for that *particular credential*; and
- holder `did:key` whose credential the wallet possesses.

After parsing a canonical `openid4vp://?client_id=...&request=...` link with `OpenId4VpJwtVcJsonDirectPost.TryReadWalletInvocation`, the Wallet can call:

```csharp
using HeroSSID.Credentials.VerifiablePresentations;

// All expected values below must come from independently trusted wallet policy.
if (!OpenId4VpJwtVcJsonWalletDisclosure.TryPrepare(
        requestJwt, expectedVerifierDid, expectedResponseUri,
        expectedCredentialType, expectedSubjectContextUri,
        expectedIssuerDid, originalIssuerSignedCredentialJwt,
        holderDid, TimeProvider.System, out var preview) ||
    preview is null)
{
    // Reject: no unverified subject information may be disclosed.
    return;
}

// Show verifier DID, response URI, issuer DID, type, subject context,
// request expiry AND every property in preview.VerifiedSubject.
// This is full disclosure, not selective disclosure.
// The wallet application must acquire meaningful human consent itself.
if (!await ShowFullDisclosureAndObtainConsentAsync(preview))
{
    // Do not call a holder signing API.
    return;
}

string form = OpenId4VpJwtVcJsonWalletDisclosure.CreateHolderResponseFormAfterPreview(
    preview, requestJwt, originalIssuerSignedCredentialJwt,
    holderPrivateSeed, TimeProvider.System);

// Send only to the independently authenticated HTTPS response URI.
```

`TryPrepare` verifies the genuine verifier's Ed25519 Request Object signature against the independently pinned verifier, its exact callback/issuer/type/context policy and expiry; it then verifies the **unchanged original issuer Ed25519-signed** VC1.1 JWT against the independently pinned issuer, requested credential type/context, holder DID and validity. Only authenticated subject JSON is returned; no holder private key or challenge store is needed for preview.

The preview includes uppercase hexadecimal SHA-256 digests of both **original compact signed JWT strings**. `CreateHolderResponseFormAfterPreview` cryptographically revalidates the request and issuer statement, checks their exact digests and displayed subject against the preview, and only then calls the existing genuine holder Ed25519 signer. An accidentally substituted (even properly issuer-signed) credential or new verifier challenge is rejected. Expired or forged evidence is rejected on both occasions. A failed preview or signing attempt does not consume the verifier's challenge; the verifier's existing final `direct_post` verification consumes it atomically.


## Optional issuer-signed VC1.1 status before any Wallet disclosure

For applications that must **not even show issuer-authenticated claims** until an issuer status statement has been checked, use the separate opt-in `TryPrepareWithStatus` API. It authenticates the original verifier request, original issuer credential and an issuer-signed **private 60-second** revocation snapshot before returning a preview. A missing, expired, revoked, forged, changed, or foreign-issuer snapshot fails closed; no holder seed or challenge consumption is involved at this stage.

```csharp
using HeroSSID.Credentials.VerifiablePresentations;

// All expected values come from Wallet-owned, independently pinned policy.
// issuerSignedSnapshotJwt is provided through an independently trusted issuer
// status channel; its authoritative completeness is NOT established here.
if (!OpenId4VpJwtVcJsonWalletDisclosure.TryPrepareWithStatus(
        requestJwt, expectedVerifierDid, expectedResponseUri,
        expectedCredentialType, expectedSubjectContextUri,
        expectedIssuerDid, originalIssuerSignedCredentialJwt,
        holderDid, issuerSignedSnapshotJwt, TimeProvider.System,
        out var statusPreview) || statusPreview is null)
{
    return; // No claims may be revealed to the Wallet UI.
}

// Display the complete statusPreview.Disclosure.VerifiedSubject,
// verifier DID, callback, issuer DID, type and vocabulary.
// Obtain real informed FULL-DISCLOSURE consent in the Wallet app.
if (!await ShowFullDisclosureAndObtainConsentAsync(statusPreview.Disclosure))
{
    return;
}

// Only the exact previously authenticated request, issuer JWT and SAME
// live signed status may be used; the holder's own seed signs the VP.
string form = OpenId4VpJwtVcJsonWalletDisclosure
    .CreateHolderResponseFormAfterStatusPreview(
        statusPreview, requestJwt, originalIssuerSignedCredentialJwt,
        issuerSignedSnapshotJwt, holderPrivateSeed, TimeProvider.System);

// Send only to the independently authenticated HTTPS response URI.
```

The snapshot's uppercase SHA-256 digest is part of `JwtVcJsonWalletStatusDisclosurePreview`. At signing time the library rechecks this exact digest, original request and credential signatures, full displayed subject, holder key and snapshot freshness. It checks status *again* after signing, so a proof created across the 60-second status expiry boundary is not returned as status-gated. The verifier must still call the existing status-aware `JwtVcJsonDirectPostRevocation.CheckResponseForm` and atomically consume its challenge. That verifier, not the Wallet preview, decides whether proof is accepted.

**Do not interpret `NotListed` as proof of complete or current non-revocation.** The external issuer alone is responsible for observing and signing a complete revoked set. This profile is private and issuer-distributed, not the W3C Bitstring Status List standard. `TryPrepare` and `CreateHolderResponseFormAfterPreview` remain deliberately **status-unchecked** compatibility methods; callers requiring status must explicitly choose the new pair. Neither pair is evidence of user consent, physical identity, business authorization, selective disclosure, full OpenID4VP conformance or third-party Wallet interoperability.

## Security and product boundaries

A digest match **does not prove that a person saw or approved the claims**. These methods cannot require the calling app to display the UI, and the earlier `CreateHolderResponseForm` API remains usable. The wallet must actively block holder signing until its own user has seen the full disclosure and consented, must protect its own private key and must send the result only to its independently authenticated HTTPS callback.

Preview validates issuer authenticity, not live revocation, trusted status-set completeness, real-world identity, authority to act or a valid holder private-key proof. The last of those exists only once the Wallet signs its VP; a verifier must still validate holder binding, one-use challenge and the separate issuer-signed revocation snapshot. A request can be cancelled or consumed by another response after a preview, and the final verifier can then reject the VP. HeroSSID still has no built-in public hosted callback, selective disclosure, human-consent attestation or independently demonstrated third-party Wallet interoperability.

## Reproducible acceptance

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj \
  --configuration Release \
  --filter FullyQualifiedName~OpenId4VpJwtVcJsonWalletDisclosureTests
```

The unit tests use distinct real Ed25519 verifier, issuer and holder keys. They cover verified full-claim preview before any holder signing, exact-previewed artifact binding, valid signed VP acceptance, replay rejection, forged issuer signature, foreign holder, unpinned verifier/callback/type/context/issuer, expired requests and post-preview replacement. They are **local interoperability prerequisites, not independent external-wallet testing**.
