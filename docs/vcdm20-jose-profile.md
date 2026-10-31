# VC Data Model 2.0: direct JOSE Ed25519 profile (opt-in)

This is a **bounded, real-signature .NET library capability**, based on the
[W3C VC Data Model 2.0 Recommendation (15 May 2025)](https://www.w3.org/TR/vc-data-model/)
and [VC-JOSE-COSE Recommendation](https://www.w3.org/TR/vc-jose-cose/).
It does **not** claim general W3C conformance, JSON-LD expansion/canonicalisation,
OpenID4VC interoperability or third-party wallet tests.

## Issuer and verifier behavior

`HeroSSID.Credentials.Vcdm20.Vcdm20JoseCredential.Create` signs a **direct**
VC 2.0 JSON object as a compact Ed25519 JWS. Its `typ` is `vc+jwt`,
`cty` is `vc` and `kid` identifies the issuer's Ed25519 `did:key`
verification method, matching the content-type recommendation in
[W3C VC-JOSE-COSE Recommendation §3.1.1 (13 October 2026)](https://www.w3.org/TR/2026/REC-vc-jose-cose-20261013/#securing-json-ld-verifiable-credentials-with-jose).
The verifier accepts older authentic direct `vc+jwt` tokens with no optional
`cty`, but rejects a *present* mismatched, duplicate or malformed content type.
This is a bounded profile improvement, **not** independent VC conformance or wallet interoperability.
Unlike the existing local credential, the payload directly contains
`@context`, `type`, `issuer`, `validFrom`, `validUntil` and
`credentialSubject`. It MUST NOT contain the legacy JWT `vc` or `vp` member.

The API accepts a versioned HTTPS vocabulary context URI, a credential type
and subject JSON supplied by the issuer. The first `@context` entry is
`https://www.w3.org/ns/credentials/v2`, followed by the caller's context.
The array of types is `["VerifiableCredential", "<caller type>"]`.
The subject must have an exact `id` equal to the holder `did:key`.
Both issuer and subject are self-certifying Ed25519 DID keys. The issuer's
32-byte seed must actually match its DID or issuance fails; the caller owns
the seed and must clear it after use. Issuance operates in memory and **does
not persist, register or revoke** the credential.

`TryVerify` independently pins the issuer DID, holder DID, context URI and
credential type. It checks strict compact JWS format, real issuer signature,
correct key identifier, exact direct VCDM payload shape, duplicate JSON
members, bounded subject size and UTC validity bounds. Only success releases
the verified `JsonElement` subject to the caller. Alterations, incorrect
signer, context or subject, a legacy `vc`-nested JWT, invalid dates and
expired/future credentials fail closed.

Example (where `issuerSeed` belongs to the independently trusted `issuerDid`):

```csharp
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;

Uri vocabulary = new("https://issuer.example/contexts/membership/v1");
using var claims = JsonDocument.Parse(
    JsonSerializer.Serialize(new { id = holderDid, membership = "active" }));
string issued = Vcdm20JoseCredential.Create(
    issuerDid, holderDid, "MembershipCredential", vocabulary,
    claims.RootElement, issuerSeed, DateTimeOffset.UtcNow,
    DateTimeOffset.UtcNow.AddHours(1));

if (Vcdm20JoseCredential.TryVerify(
    issued, issuerDid, holderDid, "MembershipCredential", vocabulary,
    DateTimeOffset.UtcNow, out var verifiedClaims))
{
    // Claims are now signed under the pinned issuer's key; decide authorization separately.
}
```

## Embedded context restrictions

This **strict JSON / pinned-vocabulary profile** rejects any additional `@context`
within `credentialSubject`, including descendants inside nested objects or
arrays. A JSON-LD local context could otherwise override the meaning of a
claim while the outer pinned context still matches. Issuance rejects such
subjects; verification also rejects otherwise genuinely issuer-signed tokens
and releases no claims. Ordinary nested data **without** local contexts
remains supported.

This is deliberately narrower than general JSON-LD, which permits local
contexts ([JSON-LD 1.1](https://www.w3.org/TR/json-ld11/#the-context)).
A credential that relies on legitimate scoped contexts needs a distinct,
reviewed JSON-LD processing profile. The URI-pinning check still does **not**
fetch contexts, verify their actual contents, expand terms or establish
semantic interoperability.

## Security and standards boundary

The caller MUST independently determine which issuer DID is trusted to issue
this credential type, keep its context-to-meaning mapping under its own
control, and decide the actions allowed by verified claims. The implementation
**does not fetch or expand** HTTPS JSON-LD contexts. It checks their exact
pinned identifiers only, so it cannot establish semantic W3C conformance.
A signer could also control the vocabulary URI; trusting the signer alone
does not make all claims meaningful or authoritative.

Signature proves issuer-key control, **not** real-world identity,
holder-key control, user consent or delegated business authorization.
This method is not a holder-signed VP and does not check revocation/status:
a successful result is a cryptographically signed, time-valid statement only.
The existing private JWT issuer database, revoke API, snapshots, and
OpenID4VP `herossid_vc_jwt` direct_post workflow are unchanged and cannot
silently accept this different format. A later, separately reviewed path
must connect standard credential encoding to status and VP exchange with
independent wallet/conformance tests.
