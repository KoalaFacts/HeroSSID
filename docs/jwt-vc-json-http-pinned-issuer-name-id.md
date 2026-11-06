# Pinned issuer-name and credential-ID HTTP verifier (VC1.1, opt-in)

This authenticated endpoint lets a non-.NET relying party require **both** an
exact issuer-signed descriptive organisation name and an original signed
credential ID before receiving any authenticated subject claim. It checks
W3C VC Data Model 1.1 JWT encoding, not legacy private vc.context, and
does not constitute full OpenID4VP conformance or external Wallet interoperability.

## Request

An authenticated caller with OAuth scope **credential:verify** POSTs to:

/api/v1/credentials/jwt-vc-json/verify-pinned-issuer-name-and-id

~~~json
{
  "credential": "<original issuer-signed VC1.1 compact JWT>",
  "trustedIssuerDid": "did:key:z...independently-trusted",
  "expectedHolderDid": "did:key:z...expected-holder",
  "expectedCredentialType": "https://issuer.example/credentials#Membership",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1",
  "expectedIssuerName": "Australasian Membership Registry",
  "expectedCredentialId": "https://issuer.example/credentials/member-041"
}
~~~

The DIDs are illustrative. **All expectations must come from the relying
party's independent policy**, never be copied from the presented JWT.
The server authenticates the actual Ed25519 issuer signature, exact pinned
issuer, holder, type, vocabulary, time bounds, issuer-signed vc.issuer
{id,name} and original signed JWT jti **before** releasing subject claims.
The name is an exact ordinal signed descriptive value (nonblank, control-free,
up to 128 characters), not a verified legal identity. The signed credential
ID and expected pin must be a bounded absolute HTTPS URI without userinfo.
Both signed values must exist and match. No URI is dereferenced.

Successful verification returns HTTP 200 status "SignedButStatusUnchecked",
the verified subject, exact original signed credential ID, issuer name,
and original signed not-before and expiry times (up to 100-nanosecond precision)
so the relying party can bound caching. An authentic but wrong-name/wrong-ID
JWT, forgery, foreign signer, expired JWT or wrong holder returns HTTP 200
status "Invalid" with **null** subject, credential ID, issuer name and dates.
Malformed/incomplete/unsafe policy returns HTTP 400; anonymous calls 401;
insufficient verification scope 403.

## Same-issuer signed private status

/api/v1/credentials/jwt-vc-json/verify-pinned-issuer-name-and-id-with-status

Supply the same independent policy plus "revocationSnapshot": the original
issuer's 60-second private signed snapshot over the **exact original JWT**.
An optional verifier-owned "minimumStatusObservedAt" rejects older observed
status. The status route requires a snapshot. A genuine same-issuer
non-listing returns "SignedNotListed" with claims; a listed JWT returns
"Revoked" with **no claims**. Foreign, malformed or stale snapshots return
"Invalid" without exposing claims. A non-listing is not live or complete
proof of non-revocation, identity or current entitlement; snapshot
completeness is the integrating application's responsibility.

The unchecked route refuses supplied revocation data or an observation
cutoff rather than dropping them. Both pinned-name/ID routes refuse an
"expectedAudience" field; this profile does not accept recipient-bound JWTs.
The existing single-issuer /verify, /verify-with-status, /verify-for-audience
and /verify-for-audience-with-status routes now refuse independently
submitted "expectedIssuerName"/"expectedCredentialId" policy instead of
silently ignoring it. Other trust profiles remain separate.

A signed statement is not proof that a legal organisation was vetted,
that a holder controls the holder's seed, that a person consented to
disclose, that an Agent has delegated business authority, or that a
third-party Wallet interoperates. This only adds an opt-in HTTP adapter
and authenticated contract tests; no schema, migration, publishing,
production deployment or user-key custody change.

References: [VC1.1 normative JWT encoding](https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#jwt-encoding),
[SDK signed metadata profile](jwt-vc-json-profile.md#independently-pinned-issuer-name-and-credential-id-before-claim-release-sdk-opt-in),
[base HTTP verifier](jwt-vc-json-http-verify-profile.md), and [Vision](VISION.md).
