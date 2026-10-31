# Authenticated VC1.1 exact retired-issuer JWT verification over HTTP

This opt-in HTTP adapter exposes HeroSSID's existing
`JwtVcJsonRetiredIssuerVerifier` policy to non-.NET relying parties.
The original credential representation is the bounded W3C VC Data Model
**1.1 `jwt_vc_json`**, signed with Ed25519. These HeroSSID JSON HTTP routes
are **not an OpenID4VP endpoint or evidence of independent wallet interoperability**.

## Explicit verifier-owned trust inputs

An authenticated caller with the exact OAuth scope `credential:verify` uses:

- `POST /api/v1/credentials/jwt-vc-json/verify-active-and-retired`
- `POST /api/v1/credentials/jwt-vc-json/verify-active-and-retired-with-status`

Example for the non-status route (DID strings and JWT are placeholders, **not**
real cryptographic keys):

```json
{
  "credential": "<original issuer-signed VC1.1 JWT>",
  "activeIssuerDids": ["did:key:z...current-issuer"],
  "retiredCredentialPins": [
    {
      "issuerDid": "did:key:z...retired-issuer",
      "credentialSha256": "<64 lowercase hex digits>"
    }
  ],
  "expectedHolderDid": "did:key:z...holder",
  "expectedCredentialType": "https://issuer.example/credentials#MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1"
}
```

The verifier must independently establish **all** of the issuer, holder, type
and approved versioned HTTPS vocabulary inputs. In particular, a retired
credential pin is the lowercase hexadecimal SHA-256 of the **exact originally
issued compact JWT string**, registered from an independently trusted issuance
inventory. Never derive the trusted DID or enroll a digest merely from the
submitted credential, QR code, Wallet or token `iss`/`kid`. The API does
**not** persist, establish the enrollment time of or authenticate the caller's
inventory. The credential remains limited to its original 15-minute maximum
validity window. A digest pin does not extend expiry.

Active issuer DIDs may authenticate new JWTs. A retired issuer may
authenticate **only** the exact original credential separately pinned by the
verifier; newly signed or backdated JWTs using a retired key are rejected,
even if their Ed25519 signature itself is valid. Active and retired policies
must be disjoint or the exact pin guarantee could be bypassed.

A valid result is HTTP 200 with status `SignedButStatusUnchecked` and
`verifiedIssuerDid` (the **actual authenticated signer**) plus the exact
`verifiedSubject`. An otherwise well-formed verification request with a
forged, unpinned, expired, wrong-holder, wrong-type or wrong-context JWT returns
HTTP 200 with `{"status":"Invalid","verifiedIssuerDid":null,"verifiedSubject":null}`.

The issuer policy is bounded to **16 distinct Ed25519 issuer DIDs total**,
**16 active** and **256 retired exact JWT pins**. Invalid/overlapping/duplicated
policies, non-lowercase/incorrect SHA-256 pins, missing independent holder/type/
context, oversized credential or unexpected status on the non-status route
return **400**. Anonymous access returns **401**, insufficient scope **403**.
Both routes are POST-only and perform no database, migration or key changes.

## Require actual issuer-signed private status separately

The `-with-status` endpoint requires the same request **plus** the exact
original `revocationSnapshot` JWT, independently acquired from the **actual
issuer**. The SDK verifies its Ed25519 signature, same-issuer provenance,
expiry and exact credential hash before releasing subject claims:

- `SignedNotListed`: authentic JWT and a fresh same-issuer signed snapshot
  that does not contain its digest; signer and subject returned.
- `Revoked`: signed snapshot includes the submitted credential digest;
  `verifiedIssuerDid` and `verifiedSubject` are both **null**.
- `Invalid`: forged, wrong-issuer, missing/expired or malformed signed
  status; both fields **null**. A missing snapshot input returns HTTP 400.

`SignedNotListed` **does not mean live non-revocation**. This is the private
HeroSSID 60-second issuer-signed snapshot, **not** W3C Bitstring Status List.
A compromised retired signing key could also forge status evidence. The caller
must independently trust the snapshot's distribution and completeness.

## Provenance and authority limits

Issuer signature authenticates an issuer's statement. It does **not** prove
holder private-key possession, real person or organisation identity, deliberate
human disclosure/consent, agent delegation or authority to perform any action.
A relying party must separately verify a holder-signed one-use VP and apply
its own identity and business authorization policy. The HTTP caller may
choose policy inputs; the server **does not provision or certify** those
inputs, or supply a hosted Wallet, independent OpenID4VP conformance, a trust
registry or production security certification.

For independent library policy details, see
[retired exact JWT pins](jwt-vc-json-retired-issuer-exact-pins.md),
[VC1.1 authenticated HTTP verification](jwt-vc-json-http-verify-profile.md),
and [VISION](VISION.md). Integration tests use real issuer/holder Ed25519 keys
and genuine authorized HTTP requests with isolated Testcontainers PostgreSQL;
internal HTTP tests are not independent third-party Wallet interoperability.
