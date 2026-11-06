# Opt-in VC1.1 JWT verification with an independently pinned did:web issuer

A verifier that already trusts an organisation's restricted `did:web` issuer
and **its actual Ed25519 assertion key** can authenticate an externally
issued W3C VC Data Model 1.1 `jwt_vc_json` without converting the original
signature or treating the key in an untrusted JWT as a trust anchor.

This is an SDK-only, offline, **verifier-owned trust policy**. It is not DID
resolution, remote trust discovery, DID-web hosting, publication validation,
legal identity, holder proof, revocation or business authorization.

## Exact supported format

- W3C [Verifiable Credentials Data Model 1.1 JWT encoding](https://www.w3.org/TR/vc-data-model/#json-web-token): `alg: EdDSA`, `typ: JWT` (or omitted), a **required exact** JOSE `kid`, signed `iss`, `sub`, `nbf`, `exp` and `vc` containing the actual `@context`, `type` and subject. Legacy `vc+jwt` and HeroSSID's private `vc.context` are deliberately excluded from this opt-in.
- Issuer DID: restricted, canonical lowercase ASCII `did:web:issuer.example` or `did:web:issuer.example:department` (up to eight safe ASCII path segments), as used by HeroSSID's existing offline publisher. No automatic DID document lookup.
- Verification method: exactly the independently enrolled issuer DID plus `#key-1` or `#key-2`; **32-byte Ed25519 public key**, separately provisioned and trusted for the issuer's `assertionMethod` policy. Signing with a successor key does not enroll/promote it.
- Holder remains a separately pinned `did:key`; type, vocabulary and the <=15-minute signed validity interval must pass the existing strict VC1.1 parser before releasing original claims.

## Call from a relying party

```csharp
using HeroSSID.Credentials.JwtVcJson;

string issuerDid = "did:web:issuer.example:members";
// Obtain both of these from YOUR independently verified, enrolled issuer policy,
// NOT from the JWT or an untrusted HTTP/DID document.
string assertionMethod = issuerDid + "#key-2";
byte[] preEnrolledIssuerEd25519PublicKey = /* 32 raw public-key bytes */;
string originalJwt = /* original independently issued VC1.1 signed JWT */;

bool authenticatedIssuerStatement = JwtVcJsonPinnedDidWebIssuerVerifier.TryVerify(
    originalJwt, issuerDid, assertionMethod, preEnrolledIssuerEd25519PublicKey,
    expectedHolderDid, "MembershipCredential",
    new Uri("https://issuer.example/contexts/membership/v1"),
    DateTimeOffset.UtcNow, out var authenticatedClaims);

if (!authenticatedIssuerStatement)
{
    // Invalid signature, expired JWT, wrong issuer/holder/claim vocabulary
    // or untrusted verification method: do not release or act on claims.
}
```

Unlike a self-certifying `did:key`, a `did:web` identifier is **not bound
cryptographically to its claimed HTTPS domain**. The integrating verifier
must separately validate and retain the exact issuer DID document,
`assertionMethod` authorization, HTTPS/DNS ownership and operator-approved
historical/current key lifecycle; passing the raw key in the call is not proof
of any of those facts. Key-1 and key-2 only name slots from the repository's
restricted offline did:web publisher, not universal did:web key names.
No general standards conformance or third-party wallet interoperability is claimed.

## Tests and evidence

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj \
  --configuration Release --filter FullyQualifiedName~JwtVcJsonPinnedDidWebIssuerTests
```

Unit tests use independent real Ed25519 issuer/attacker/holder keys. Positive
cases cover root and path-based `did:web` methods including explicit
successor key trust. Negative cases reject foreign signer, DID/key-ID pin,
holder, expiry, forged payload and mismatched embedded issuer. These tests
do not prove actual HTTPS publication, real key-enrollment legitimacy,
revocation-set completeness, holder consent, Agent authority or independent
wallet interoperability.
