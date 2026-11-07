# Pinned did:web Wallet online full-disclosure preflight (.NET 10)

This SDK-only opt-in flow combines independent issuer/credential/request trust
checks, Wallet emergency denial and a short-lived issuer-signed exact-original
JWT status fetched by safe-default HTTPS. It uses the existing VC Data Model
1.1 `jwt_vc_json` issuer JWT and private
`herossid-didweb-vc11-exact-status+jwt` status assertion; the status protocol
is **not** W3C Bitstring Status List, a live non-revocation guarantee, a
third-party Wallet exchange or real-world identity/business authority proof.

## Calling the Wallet boundary

An integrating Wallet must independently authenticate the verifier's request,
pin the issuer did:web DID and exact Ed25519 method/key, the signed name,
credential ID/type/context, holder DID, its own locally approved emergency
denial inventory and the separately approved public HTTPS status URL.
**Never use credential metadata or a remote DID document to enroll trust.**

```csharp
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;

// App-enrolled policy inputs; NOT read from the untrusted credential.
PresentationChallenge verifiedVerifierRequest = /* authenticated by app */;
string issuerJwt = /* unchanged original issuer-signed VC1.1 JWT */;
string trustedIssuerDid = "did:web:issuer.example:members";
string pinnedMethod = trustedIssuerDid + "#key-2";
byte[] enrolledIssuerPublicKey = /* 32-byte Ed25519 key */;
string holderDid = /* Wallet holder's separately known did:key */;
IReadOnlyCollection<string> currentWalletDeniedSha256 = /* current operator policy */;

var preview = await JwtVcJsonPinnedDidWebWalletOnlinePreflight
    .TryPrepareWithIsolatedTransportAsync(
        new Uri("https://issuer.example/status/member-42.jwt"),
        verifiedVerifierRequest, issuerJwt, trustedIssuerDid, pinnedMethod,
        enrolledIssuerPublicKey, "Example Membership Office",
        new Uri("https://issuer.example/credentials/membership-42"),
        "MembershipCredential",
        new Uri("https://issuer.example/contexts/membership/v1"),
        holderDid, currentWalletDeniedSha256, TimeProvider.System);
if (preview is null)
{
    // Fail closed; never display subject claims or request a holder signature.
    return;
}

// Show ALL preview.Disclosure.Disclosure.VerifiedSubject claims and the
// recipient/issuer to the holder; obtain actual app-owned informed consent.
// A successful library call is NOT evidence that the user consented.
byte[] holderSeed = /* obtained only after the real consent step */;
string holderVp = JwtVcJsonPinnedDidWebWalletOnlinePreflight.CreateAfterPreview(
    preview, verifiedVerifierRequest, issuerJwt, enrolledIssuerPublicKey,
    currentWalletDeniedSha256, holderSeed, TimeProvider.System);
// Send the VP only to the independently authenticated verifier transport.
// Verifier checks genuine issuer + holder keys, its own one-use challenge,
// its current local denial policy, fresh issuer status and authorization.
```

The Wallet online preflight returns `null` on invalid, revoked, unavailable,
forged or stale status, mismatched pinned metadata, expired request or denied
credential. No subject escapes on failure. It checks issuer signature, holder
binding, exact issuer name, credential ID, type, context and validity and the
app-authenticated challenge **before any status network request**. Local
emergency policy is also checked before the request and again after the
network await. The exact original JWT and same-issuer signed status are
reverified before releasing preview claims. The status JWT bytes are carried
inside the result and the post-consent signer uses them unchanged.

The post-consent signer rechecks original issuer signature, exact status,
presented claims, challenge expiry and entire Wallet denial policy. Changes
require a fresh preview/consent; a foreign holder seed fails. Verifier-owned
single-use nonce consumption happens only when the relying party verifies
the eventual holder VP, **not** during Wallet preview or signing.

The safe default uses an isolated public-DNS-only, credential-free HTTPS
transport with no ambient proxy, cookies, authentication, automatic redirects,
decompression or trace propagation, and validates TLS server certificates.
The injected `HttpClient` overload is suitable only for independently audited,
non-redirecting public-only transports. The SDK cannot inspect an injected
handler. A valid status GET still exposes requested path and timing to the
remote operator, so status URIs must not contain JWTs, user secrets or private
identifiers. The status observation lasts at most 60 seconds and must be
fresh when preview is shown and again after signing. Do not interpret
`NotListed` as real-time authoritative revocation completeness.

## Tests and boundaries

`JwtVcJsonPinnedDidWebWalletOnlinePreflightTests` in
`tests/Unit/HeroSSID.Credentials.Tests` uses real independent Ed25519
issuer/holder/verifier keys and an injected HTTP probe for valid disclosure,
replay rejection, forged/revoked status, local denial, wrong issuer/holder
policy, expired challenge, and changed-policy/seed refusal. The probe is not
a third-party Wallet interoperability test. Complete .NET 10 Build, Test,
Security Scan and CodeQL gates remain mandatory.

This API does not host the issuer status service, validate a real person's
or organisation's identity, confer Agent authority, implement user consent
UI or claim full OpenID4VP/VC wallet interoperability. Wallets hold and
present originals; they do not manufacture issuer claims.
