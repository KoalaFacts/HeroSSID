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

## Trust, deployment and security limits

- Authenticated `credential:verify` protects the HTTP interface; it does not automatically grant authority to credentials or their subject. These endpoints are independent issuer statement validators, **not holder private-key proofs**. A relying party requiring possession must verify a separate one-time holder-signed presentation with actual informed consent.
- Neither verified signature nor absent revocation digest proves the holder's real-world identity, organisation ownership, agent delegation or permission to perform a business action. The receiving application must implement those separately.
- This opt-in HTTP adapter does not store credentials, manage keys, perform identity onboarding, issue a status snapshot, add schema/migrations, or alter existing legacy or VC2 routes.
- The `jwt_vc_json` label identifies the VC1.1 JWT credential representation used by the controlled SDK, **not** independently tested third-party wallet interoperability or full OpenID4VP / OpenID4VCI protocol conformance.

See [the issuer-signed VC1.1 JWT format](jwt-vc-json-profile.md), [HTTP issuance](jwt-vc-json-http-issue-profile.md), [private revocation status contract](jwt-vc-json-revocation-direct-post-profile.md), and [vision](VISION.md).
