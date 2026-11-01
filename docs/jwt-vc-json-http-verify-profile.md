# Authenticated VC 1.1 `jwt_vc_json` HTTP verification (opt-in)

This endpoint exposes HeroSSID's existing real Ed25519-signed W3C VC Data Model **1.1** `jwt_vc_json` issuer-signature checks to a **non-.NET relying party**. It does not implement OpenID4VP exchange, a hosted wallet or a standard revocation-list endpoint.

## Independently pinned verification policy

An authenticated caller with the exact OAuth scope **`credential:verify`** sends:

`POST /api/v1/credentials/jwt-vc-json/verify`

```json
{
  "credential": "<issuer-signed VC1.1 compact JWT>",
  "trustedIssuerDid": "did:key:z...issuer",
  "expectedHolderDid": "did:key:z...holder",
  "expectedCredentialType": "https://issuer.example/credentials#MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1"
}
```

These DIDs are placeholders, not real signing keys. The verifier **must obtain the trusted issuer DID, expected subject and type, and approved versioned HTTPS context from its own policy**, never from the JWT it is checking. The custom type is a globally expanded HTTPS IRI (rather than an undefined JSON-LD compact term). The subject context must be an absolute HTTPS URI without user-info or fragment. Neither endpoint downloads or JSON-LD-expands arbitrary contexts.

The server verifies the actual Ed25519 issuer signature and exact `did:key` key ID, nested VC1.1 `vc.@context`/`vc.type` and matching `vc.credentialSubject.id`, strict JWT shape, signed time bounds, holder DID, type and vocabulary before releasing verified subject JSON.

A successful signature verification responds with HTTP **200**:

```json
{
  "status": "SignedButStatusUnchecked",
  "verifiedSubject": {"id": "did:key:z...holder", "membership": "active"}
}
```

A malformed, forged, expired, wrong-issuer, wrong-holder, wrong-type or wrong-vocabulary **credential** with otherwise valid bounded request parameters returns HTTP **200** with `{"status":"Invalid","verifiedSubject":null}`. Missing/oversized credential or malformed policy inputs return **400**; anonymous requests return **401** and insufficient-scope requests **403**. The JWT and status snapshot are limited to 65,536 characters each, issuer/holder inputs to 255 characters, custom type to 128 and vocabulary URI to 2,048.

## Optional issuer-signed private revocation snapshot

To check *the same* authenticated issuer statement against a **separately obtained** short-lived, issuer-signed revocation export, call:

`POST /api/v1/credentials/jwt-vc-json/verify-with-status`

Use the same request with one additional field:

```json
{ 
  "credential": "<issuer-signed VC1.1 compact JWT>",
  "trustedIssuerDid": "did:key:z...issuer",
  "expectedHolderDid": "did:key:z...holder",
  "expectedCredentialType": "https://issuer.example/credentials#MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1",
  "revocationSnapshot": "<issuer-signed HeroSSID-specific snapshot JWT>"
}
```

The server first authenticates the original credential using the caller's pinned issuer/holder/type/context policy. It then authenticates the snapshot signed by **that same pinned issuer**, with its format, freshness (60-second limit) and digest of the **exact signed credential bytes**. The snapshot cannot choose its own trusted issuer. Responses:

- `SignedNotListed` — authentic credential and fresh issuer-signed snapshot without its digest; releases the verified subject.
- `Revoked` — authentic credential's digest occurs in the signed snapshot; **never** releases the subject.
- `Invalid` — credential or snapshot cannot be authenticated, is stale or has incorrect policy/format; **never** releases the subject.

A missing snapshot fails **400**. This is a private issuer-distributed export, **not** W3C Bitstring Status List or live non-revocation verification. Even `SignedNotListed` depends on the issuer supplying a **complete authoritative revocation set**, which HeroSSID cannot infer or publish from this request. No snapshot is created or stored by these verification endpoints.

## Historical and current issuer verification, with verifier-owned trust (opt-in)

An authenticated **non-.NET** verifier with the exact OAuth scope credential:verify
may independently enroll up to **16 distinct** current/historical Ed25519
did:key issuers. Call one of the separate endpoints:

- POST /api/v1/credentials/jwt-vc-json/verify-trusted-issuers
- POST /api/v1/credentials/jwt-vc-json/verify-trusted-issuers-with-status

The existing one-issuer HTTP API contracts are unchanged. Example non-status
request (placeholder DIDs, not real signing keys):

~~~json
{
  "credential": "<original issuer-signed VC1.1 jwt_vc_json>",
  "trustedIssuerDids": ["did:key:<old issuer>", "did:key:<new issuer>"],
  "expectedHolderDid": "did:key:<holder>",
  "expectedCredentialType": "https://issuer.example/credentials#MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1"
}
~~~

The server runs the existing **complete strict VC1.1 Ed25519 verification**
against each independently pinned issuer key. The JWT's untrusted iss or kid
never enrolls an issuer; a successor attestation never automatically promotes
one. An authenticated success with status SignedButStatusUnchecked includes
verifiedIssuerDid equal to the **actual real signer** and verifiedSubject equal
to the signed full-disclosure JSON subject. Removing the old DID from the
verifier's own list makes that issuer's old credentials Invalid without
reissuing the new issuer's credentials. Invalid responses provide **null** for
both verifiedIssuerDid and verifiedSubject.

The -with-status route additionally requires
revocationSnapshot containing an original private issuer-signed HeroSSID
VC1.1 snapshot. The snapshot must be fresh and signed by the **same issuer
whose real signature authenticated the exact submitted credential**. A clean
snapshot from a different issuer—even one still independently enrolled—cannot
clear the credential. The return status is SignedNotListed with signer and
subject only when the same issuer's snapshot genuinely omits the digest.
Revoked and Invalid return no signer and no subject.

Issuer trust lists must contain 1–16 unique, valid Ed25519 did:key DIDs;
duplicate, missing, oversized or invalid policies fail HTTP 400. The unchecked
endpoint refuses any supplied revocationSnapshot rather than silently ignoring
a caller-requested status check. Anonymous calls fail 401, unauthorized scopes
403. Both routes are POST-only, do not persist credentials, and do not change
schema, keys or revocation registries.

**Trust limitations:** issuer signature verification is not holder-key control,
real identity, human consent, agent delegation or business authorization.
The private SignedNotListed snapshot does not prove completeness or live
non-revocation. This supports the narrow VC Data Model 1.1 jwt_vc_json
encoding, but is not proof of independent third-party Wallet interoperability,
complete OpenID4VP or standard W3C credentialStatus / Bitstring Status List.

## Verifier-owned post-incident observation cutoff (opt-in)

A relying party can require a **new issuer observation after an incident**
without changing the issuer's signature or private snapshot format. Supply
`minimumStatusObservedAt` (an ISO 8601 timestamp with timezone) **only**
to `/jwt-vc-json/verify-with-status` or
`/jwt-vc-json/verify-trusted-issuers-with-status`:

```json
{
  "credential": "<original signed jwt_vc_json>",
  "trustedIssuerDids": ["did:key:<independently-pinned-issuer>"],
  "expectedHolderDid": "did:key:<holder>",
  "expectedCredentialType": "https://issuer.example/credentials#MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1",
  "revocationSnapshot": "<signed private issuer status JWT>",
  "minimumStatusObservedAt": "2026-11-01T01:00:00Z"
}
```

This is an illustrative timestamp, **not** evidence that the issuer truly
observed its source at that time. The verifier must retain its independent
incident/cutoff policy. A correctly signed 60-second snapshot with `iat`
**earlier** than the requested instant returns `Invalid`, even when the
issuer reported no revocations; it releases neither subject nor (on the
multi-issuer route) signer. A fresh same-signer snapshot can return
`SignedNotListed`, while a genuinely revoked exact JWT still returns
`Revoked` without claims. Fractional seconds are compared against the
signed whole-second `iat` **without rounding the cutoff backward**. A
future or pre-Unix-epoch cutoff is invalid input (HTTP 400); the no-status
routes reject this field rather than downgrade to unchecked verification.

The cutoff only applies to the **two named VC1.1 status-verification routes**
and the opt-in .NET APIs; other HeroSSID status endpoints do not yet
implement it. It does not establish live revocation, completeness of the
issuer-reported list, a timestamping authority, holder key control,
identity vetting, informed consent, OpenID4VP interoperability or business
authorization. All such judgments remain external.

## Trust, deployment and security limits

- Authenticated `credential:verify` protects the HTTP interface; it does not automatically grant authority to credentials or their subject. These endpoints are independent issuer statement validators, **not holder private-key proofs**. A relying party requiring possession must verify a separate one-time holder-signed presentation with actual informed consent.
- Neither verified signature nor absent revocation digest proves the holder's real-world identity, organisation ownership, agent delegation or permission to perform a business action. The receiving application must implement those separately.
- This opt-in HTTP adapter does not store credentials, manage keys, perform identity onboarding, issue a status snapshot, add schema/migrations, or alter existing legacy or VC2 routes.
- The `jwt_vc_json` label identifies the VC1.1 JWT credential representation used by the controlled SDK, **not** independently tested third-party wallet interoperability or full OpenID4VP / OpenID4VCI protocol conformance.

See [the issuer-signed VC1.1 JWT format](jwt-vc-json-profile.md), [HTTP issuance](jwt-vc-json-http-issue-profile.md), [private revocation status contract](jwt-vc-json-revocation-direct-post-profile.md), and [vision](VISION.md).
