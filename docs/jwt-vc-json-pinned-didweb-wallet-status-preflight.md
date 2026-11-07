# did:web VC1.1 Wallet preflight: signed exact status before full disclosure

A holder wallet that uses an independently authenticated `PresentationChallenge` can now preview the **entire authenticated VC1.1 subject** without receiving or using a holder signing key. `JwtVcJsonPinnedDidWebWalletPreflight.TryPrepare` requires both the unchanged original `jwt_vc_json` signed by the independently enrolled `did:web` Ed25519 assertion key and a genuine **fresh, issuer-signed, exactly matching `revoked=false`** status for those original compact JWT bytes. A revoked, missing, stale, forged, foreign-issuer or different-original status produces no preview.

The preview is for the integrating wallet UI; the SDK never asks the human, attests consent or verifies the verifier's real-world identity. The wallet application **must authenticate the verifier's actual challenge out of band, independently pin the issuer's DID/method/public key/name/credential ID, display every field that will be disclosed, and obtain meaningful consent before calling** `CreateAfterPreview`. The wallet only holds and presents; it cannot rewrite the original issuer statement or gain business authorization.

## SDK use

```csharp
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;

// Obtained from a separately authenticated verifier channel.
// Challenge metadata is not itself proof of verifier authentication.
PresentationChallenge authenticatedChallenge = /* verify independently */;
byte[] pinnedIssuerEd25519PublicKey = /* operator-enrolled 32-byte key */;
string originalIssuerJwt = /* unchanged issuer-signed VC1.1 JWT */;
string issuerSignedExactStatusJwt = /* issuer's fresh 60-second JWT */;
string holderDid = /* wallet's enrolled did:key */;

bool safeToPreview = JwtVcJsonPinnedDidWebWalletPreflight.TryPrepare(
    authenticatedChallenge, originalIssuerJwt, issuerSignedExactStatusJwt,
    "did:web:issuer.example:members", "did:web:issuer.example:members#key-2",
    pinnedIssuerEd25519PublicKey, "Example Membership Office",
    new Uri("https://issuer.example/credentials/membership-42"),
    "MembershipCredential",
    new Uri("https://issuer.example/contexts/membership/v1"), holderDid,
    TimeProvider.System, out var preview);

if (safeToPreview && preview is not null)
{
    // Display ALL fields in preview.VerifiedSubject; record real user consent
    // in your Wallet application. A preview is NOT consent evidence.
    byte[] holderSeed = /* unlock only after real consent */;
    string holderSignedVp = JwtVcJsonPinnedDidWebWalletPreflight.CreateAfterPreview(
        preview, authenticatedChallenge, originalIssuerJwt,
        issuerSignedExactStatusJwt, pinnedIssuerEd25519PublicKey,
        holderSeed, TimeProvider.System);
    // Deliver only to the verifier/channel previously authenticated by the app.
}
```

`CreateAfterPreview` recomputes the authenticated issuer claim and status, checks the same signer key, original compact credential hash, status JWT hash, original challenge and exact displayed claims, and calls the existing **real holder Ed25519 VP signer** only after the caller has obtained consent. It rejects changed or expired artifacts, wrong keys and swapped challenges. The challenge is not spent by the wallet; the verifier's separate atomic challenge store consumes it on acceptance. The issuance/verification of actual domain ownership, issuer status truth, holder identity and Agent authorization remain outside this SDK.

The private 60-second `herossid-didweb-vc11-exact-status+jwt` says **only that the same pinned issuer signed a current observation**. It is not a W3C Bitstring Status List, continuous real-time non-revocation, a hosted endpoint, third-party Wallet interoperability, a complete OpenID4VP flow or an external security audit. A compromised issuer signing key defeats this status; the verifier and wallet must independently change trust policy upon compromise.

## Regression

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj --configuration Release --filter FullyQualifiedName~JwtVcJsonPinnedDidWebIssuerStatusTests
```

Real-key scenarios cover preview-before-holder-key and post-consent original issuer/holder signatures, forged or revoked issuer status, wrong issuer key, changed issuer credential/status/challenge, stale status and expired request. This work package does not introduce a database migration, hosted API, NuGet publication, deployment, private production keys or license changes.
