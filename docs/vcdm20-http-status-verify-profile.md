# Authenticated direct VC2 signature + signed-status HTTP verification

`POST /api/v1/credentials/vcdm20/verify-with-status` is an **opt-in
HTTP adapter** for the existing genuine Ed25519 direct VC2 JWT verifier
and the separate `Vcdm20RevocationSnapshot.Check` library. Non-.NET
relying parties do not need to call .NET code or enroll a remote DID
in the HeroSSID database. This endpoint is distinct from the issuer-only
credential `/vcdm20/verify` (which does not check status) and the holder
`/vcdm20/verify-presentation` endpoint (which checks a holder-signed
one-use challenge). No production DB access, schema, migration, hosted
wallet or snapshot publication is introduced.

An OAuth bearer token must have **`credential:verify`**. The verifier
MUST determine trusted issuer DID, expected holder DID, credential type
and versioned HTTPS subject vocabulary from its **own business policy**,
not from untrusted JWTs. It also needs an authentic, complete, fresh
issuer-published HeroSSID VC2 revocation snapshot; HeroSSID does not
automatically create or publish one for direct VC2 issuers.

```http
POST /api/v1/credentials/vcdm20/verify-with-status HTTP/1.1
Authorization: Bearer <token with credential:verify>
Content-Type: application/json

{
  "credential": "<original issuer-signed direct VC2 JWT>",
  "trustedIssuerDid": "did:key:z<independently pinned issuer>",
  "expectedHolderDid": "did:key:z<expected holder>",
  "expectedCredentialType": "MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1",
  "revocationSnapshot": "<issuer-signed herossid-vc2-revocation-snapshot+jwt>"
}
```

Successful authenticated HTTP validation returns **200** with exactly
one of these deliberately narrow states:

- `SignedNotListed`: authentic issuer VC2 JWT matches the independently
  pinned issuer, holder, type, HTTPS vocabulary, and current validity;
  a matching issuer-signed, unexpired snapshot does **not** list its exact
  credential digest. `verifiedSubject` is returned.
- `Revoked`: all issuer and snapshot authenticity gates passed, and
  the signed snapshot lists this exact credential. `verifiedSubject`
  is **null**.
- `Invalid`: malformed, tampered, expired, wrong-policy, wrong-issuer,
  foreign-key, missing/expired/forged snapshot or otherwise unacceptable
  proof. `verifiedSubject` is **null**.

Missing required inputs and overlong inputs (credential/snapshot over
65,536 characters, issuer/holder DID over 255, type over 128, or an
invalid/non-HTTPS vocabulary URI) return **400**. Missing authentication
returns **401**, absent verification scope **403**, request throttling
**429**. No unverified subject claims are returned.

## Trust and lifecycle boundary

A signed status snapshot is **at most 60 seconds old**, not live status.
The issuer remains responsible for the completeness and freshness of its
externally maintained revoked-credential set. `SignedNotListed` is not
a guarantee of non-revocation if the issuer omitted revoked credentials,
nor proof of enrolment or authorization. The snapshot is a
**HeroSSID-private signature profile**, not W3C Bitstring Status List
or an independent standards conformance certificate. Even a verified
issuer-signed VC2 statement does **not** prove that its named holder
controls a private key or consented to a disclosure. For holder control
and replay resistance, use the signed-presentation HTTP challenge flow
and obtain genuine user consent in a holder application.

The exact positive/negative HTTP contracts use real NSec Ed25519
signatures and disposable PostgreSQL Testcontainers. These are internal
integration tests, **not** independent third-party wallet interoperability.
See [direct VC2 format](vcdm20-jose-profile.md),
[issuer status cryptography](vcdm20-revocation-snapshot-profile.md),
[holder presentation](vcdm20-presentation-http-profile.md)
and [the project vision](VISION.md).
