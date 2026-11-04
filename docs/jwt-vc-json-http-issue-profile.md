# VC 1.1 `jwt_vc_json` HTTP issuance (opt-in)

This endpoint makes the existing **issuer-signed W3C VC Data Model 1.1 JWT** available to an authenticated non-.NET caller. It does **not** turn HeroSSID into an OpenID4VCI credential issuer, wallet, hosted OpenID4VP verifier or identity-verification authority.

## Request

`POST /api/v1/credentials/jwt-vc-json/issue` with an OAuth bearer token containing the exact `credential:issue` scope. The issuer must be an **active, tenant-owned** Ed25519 `did:key` already enrolled in HeroSSID. The holder may be an **unenrolled external** Ed25519 `did:key`.

```json
{
  "issuerDid": "did:key:z...issuer",
  "holderDid": "did:key:z...holder",
  "credentialType": "https://issuer.example/credentials#MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1",
  "credentialId": "https://issuer.example/credentials/member-123",
  "credentialSubject": {
    "id": "did:key:z...holder",
    "membership": "active"
  },
  "validUntil": "2026-10-31T03:00:00.1234567Z",
  "exactValidity": true
}
```

The example DIDs are placeholders and are not valid real keys. Use a genuinely generated DID and choose a future `validUntil` **no more than 15 minutes after the server's current time**. The supplied `credentialSubject` may omit its nested `id` because W3C VC Data Model 1.1 JWT encoding represents that identifier in the genuine signed JWT `sub` claim. If an explicit nested `id` is supplied, it **must exactly equal** `holderDid`; conflicting, null or empty values are rejected (400). HeroSSID does not invent a nested `id` in the signed subject. Both forms, with or without optional `credentialId`/signed `jti`, are exercised through the authenticated HTTP contract tests. The custom type must be an absolute HTTPS IRI rather than an undefined compact term, matching the controlled OpenID4VP DCQL type policy. The HTTPS subject context is a versioned vocabulary pinned independently by the relying party; the library does not fetch or JSON-LD-expand it.

### Optional exact JWT validity for non-.NET issuers

Set `"exactValidity": true` when the authenticated caller needs the JWT's
signed `nbf=iat` to equal the actual server issuance instant, and `exp`
to equal the exact supplied `validUntil`, including RFC 7519 fractional
NumericDate values at .NET's 100-nanosecond precision. This route does not
accept a caller-controlled start: the server still chooses `nbf`, and
`validUntil` must be strictly future and at most 15 minutes from the server
clock. Issuance fails closed if this window expires during signing.

When `exactValidity` is omitted or `false`, the existing whole-second
contract is unchanged: `nbf=iat` are set to the server's current whole second
(so can predate signing by less than one second), and `exp` is rounded down
to the previous whole second. The exact opt-in eliminates that start
backdating and preserves a fractional expiry. Optional issuer-signed
`credentialId`/`jti` works in both modes. This is an encoding/validity
feature, **not** independent Wallet interoperability, proof of holder
possession, real-world identity validation or business authorization.

The optional `credentialId` is an issuer-assigned absolute HTTPS URI, at most 2,048 characters, with no userinfo. If supplied, it is signed into the original VC1.1 JWT `jti` claim, following VC Data Model 1.1 §6.3.1. If omitted, the legacy HTTP issuance path continues to emit no `jti`. Invalid HTTP, credential-bearing userinfo, or oversized identifiers are rejected with 400 **before signing**. A valid HTTPS identifier is only a statement assigned by the issuer: HeroSSID does **not** prove domain ownership, fetch the identifier, register it, or grant business authority.

A successful response is **201 Created**:

```json
{
  "credential": "<issuer-signed compact JWT>",
  "status": "SignedButStatusUnchecked"
}
```

The JWT has a real Ed25519 issuer signature and `vc.@context` / `vc.type` / `vc.credentialSubject` nested under `vc`; its issuer, subject, type, context and validity are verified by `JwtVcJsonCredential.TryVerify`. By default, with no caller-supplied start time, the server uses the **current whole UTC second** as the JWT start (at most one second before actual signing). The opt-in `exactValidity=true` instead starts at the exact server clock instant and retains the requested fractional expiry, without changing legacy clients. The lower-level legacy SDK `Create` still rounds any explicitly requested fractional start **up**; the default HTTP expiry rounds **down**, never extending validity beyond the requested interval. Incorrect key material, untrusted issuer policy, tampering, missing holder subject, invalid HTTPS type/context and invalid lifetime are rejected.

## HTTP security and persistence boundaries

- Authentication and the `credential:issue` authorization policy apply before signing. An issuer is looked up only within the authenticated tenant. Another tenant's issuer, an inactive issuer or a mismatched public-key/DID record is not used.
- This route consumes the **existing** `CREDENTIAL_ISSUE` per-tenant quota shared with the legacy and VC2 endpoints. Decrypted signer seed bytes are zeroed in a `finally` block. No new table, schema, migration or third-party service is required.
- Anonymous calls return **401**, insufficient-scope callers **403**, unavailable issuers **404**, invalid request parameters **400**, rate limits **429**; unexpected infrastructure errors do not echo keys or subject claims. A signing operation whose requested lifetime expires before completion returns **503**.
- The signed VC1.1 JWT is **not persisted** to the existing issuance database and is **not revocable** using the existing `/credentials/revoke` database route. If independent status is needed, an issuer must manage a complete authoritative revoked set and separately sign a HeroSSID-specific `JwtVcJsonRevocationSnapshot`; an omitted digest is not real-time proof of non-revocation.
- No holder private key is accepted. Issuer signature authenticates an issuer's **statement**, not the holder's private-key control, human identity, consent or business authority. To prove holder control, use a separately consented holder-signed presentation with a one-use verifier challenge and independent issuer trust policy.

The `jwt_vc_json` output may be used by the existing **controlled SDK** `OpenId4VpJwtVcJsonDirectPost`, but neither that protocol subset nor this HTTP issuance API has been independently tested against a third-party wallet or certified as OpenID4VCI/OpenID4VP conformant. Production policy, signing-key custody and real issuer/claim verification remain caller responsibilities.

The separately authenticated single-issuer [HTTP verifier](jwt-vc-json-http-verify-profile.md) now returns `verifiedCredentialId` from the **genuine signed** `jti` only when the independent issuer/holder/type/context/time checks succeed (and, with private status, only when the exact credential is `SignedNotListed`). Revoked and invalid responses release neither identifier nor claims. Other multi-issuer/retired/denylist response shapes are unchanged.

See [VC1.1 JWT profile](jwt-vc-json-profile.md), [controlled OpenID4VP direct_post](jwt-vc-json-openid4vp-direct-post-profile.md), [status-aware verification limits](jwt-vc-json-revocation-direct-post-profile.md), [README](../README.md), and [vision](VISION.md).
