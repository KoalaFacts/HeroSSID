# Authenticated direct VC2 issuance (opt-in, short-lived)

`POST /api/v1/credentials/vcdm20/issue` lets an authenticated tenant
sign a **direct** VC Data Model 2.0 JSON/JWS credential with a locally
stored active Ed25519 `did:key` issuer. It is separate from the legacy
`/issue` database issuance and revocation lifecycle. No new schema,
credential row or automatic publication is created.

The OAuth bearer token needs `credential:issue`. The issuer DID must
belong to that **exact authenticated tenant**, be active, and have a
stored public key matching the self-certifying DID. The endpoint shares
the existing `CREDENTIAL_ISSUE` rate-limit bucket. An arbitrary
`did:key` holder can receive the token without being enrolled in
HeroSSID: the signer is making an assertion *about* that holder key,
**not proving that the holder controls it**.

## Request and response

```http
POST /api/v1/credentials/vcdm20/issue HTTP/1.1
Authorization: Bearer <client-credentials token with credential:issue>
Content-Type: application/json

{
  "issuerDid": "did:key:z<tenant issuer key>",
  "holderDid": "did:key:z<external holder key>",
  "credentialType": "MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1",
  "credentialSubject": {
    "id": "did:key:z<external holder key>",
    "membership": "active"
  },
  "validUntil": "<UTC timestamp no more than 15 minutes from issuance>"
}
```

A successful request returns HTTP **201** with:

```json
{
  "credential": "<signed direct VC2 JWT>",
  "status": "SignedButStatusUnchecked"
}
```

The returned JWT uses the direct `@context`, `type`, `issuer`,
`validFrom`, `validUntil`, `credentialSubject` layout described in
[the .NET profile](vcdm20-jose-profile.md), and does **not** include the
legacy `vc` nested claim. The issuer seed is decrypted only while
signing and the plaintext buffer is cleared after use. No private key is
returned.

HTTP **401** means unauthenticated, **403** means missing issuance
scope, **404** hides inactive/unknown/foreign issuer records, **400**
rejects invalid DID, mismatched subject ID, unsupported type/context,
unbounded subject or invalid/over-15-minute lifetime, and **429**
denotes the shared issuance quota. If a signing operation outlives the
requested validity deadline, no credential is returned.

The verifier must independently pin which issuer may make a particular
claim, plus expected holder, type and versioned HTTPS vocabulary. It
can use `POST /api/v1/credentials/vcdm20/verify` with its own
`credential:verify` scope or the independent .NET library.

## Security and lifecycle limitations

This endpoint is intended for **short-lived, full-disclosure assertions**.
**These specific JWTs are not written to the existing issuance table
and cannot be revoked through the existing `/revoke` endpoint.** They
expire after at most 15 minutes but can be re-presented until expiry
unless a relying-party verifier adds a real holder-signed, single-use
presentation. Signature and signed claims do not prove holder control,
real-world identity vetting, informed consent, business authorization
or current non-revocation. The `SignedButStatusUnchecked` marker is
deliberate; it is not a claim of active entitlement.

An HTTPS context URI is a verifier-pinned vocabulary identifier here,
not a fetched and JSON-LD-expanded trust source. These are local
contract/integration tests, **not** external standards conformance or
third-party wallet interoperability. A long-lived, revocable,
independently consumable VC2 issuance workflow requires a separately
authorized status lifecycle and more interoperability evidence.
