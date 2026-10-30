# Authenticated VC1.1 `jwt_vc_json` issuer status export (private profile)

This opt-in endpoint allows an issuer's **non-.NET backend** to produce the
actual Ed25519-signed, 60-second `herossid-jwt-vc-json-revocations+jwt`
snapshot already required by HeroSSID's status-aware VC1.1 verification and
OpenID4VP `direct_post` bridge. It is **not** W3C Bitstring Status List,
a live revocation query, independently verified completeness, automatic
publication or third-party wallet interoperability.

## Authenticated signer and input

The caller must possess a bearer token containing **both**
`credential:revoke` **and** `did:manage`, and select an **active issuer
`did:key` owned by its authenticated tenant**. The signer checks that the
stored public Ed25519 key derives the same DID, decrypts the issuer's private
key only for signing, and zeroes the temporary key bytes. A foreign, inactive
or unknown issuer cannot produce a signature.

```http
POST /api/v1/credentials/jwt-vc-json/sign-revocation-snapshot
Authorization: Bearer <credential:revoke and did:manage token>
Content-Type: application/json

{
  "issuerDid": "did:key:<tenant-owned-issuer>",
  "observedAt": "2026-10-31T00:00:00Z",
  "revokedCredentials": [
    "<authentic-original-issuer-signed-jwt_vc_json-credential>"
  ]
}
```

The timestamp is illustrative: **replace it with the actual time the issuer
completed its authoritative revocation observation**, not a stale event
timestamp updated just before sending. `revokedCredentials` must contain
the **entire** set of revoked issuer-signed VC1.1 compact JWTs at that
observation point, including previously revoked unexpired credentials. An
empty array is allowed but is not proof that nothing was revoked.

The endpoint checks the timestamp is no more than 60 seconds old and not in
the future, caps the list at **256** original JWTs, caps individual input
JWTs at **65,536 characters** and aggregate JWT characters at **180,000**,
and refuses non-authentic or foreign-issuer JWT entries. It never signs a
silently truncated list. If the authoritative set exceeds these bounds, the
issuer must use a different status mechanism rather than claim an incomplete
set is complete.

A **201 Created** response contains:

```json
{"snapshotJwt":"<issuer-signed-HeroSSID-private-status-JWT>"}
```

A separate verifier pins the issuer DID and evaluates the exact signed
credential using `JwtVcJsonRevocationSnapshot.Check` or
`POST /api/v1/credentials/jwt-vc-json/verify-with-status`. For a
holder-signed `direct_post`, the verifier backend supplies this snapshot
to its authenticated `/jwt-vc-json/openid4vp/verify-response` route.
The snapshot's signed `iat` and `exp` establish a **maximum 60-second
observation-to-expiry window**. Do not cache or reissue an old observation
under a later timestamp.

## Explicit failure and trust rules

Anonymous **401**, either missing scope **403**, missing/invalid input,
future or stale observation or unauthentic listed JWT **400**, foreign or
inactive issuer **404**, rate cap **429**, and cryptographic/storage
unavailability **503**. No rejected response includes claims or signed
status. The issuer does not store, mutate or revoke credentials through this
endpoint, and no new schema is used.

**The server cannot prove that caller-supplied `revokedCredentials` is
the complete authoritative issuer registry, or that `observedAt` was
honestly reported.** These must be established by the issuer's operational
controls. `SignedNotListed` proves only that the signed *supplied* list
omitted this particular authentic credential at the stated observation
time, not that it is currently valid, that a real person was identified,
that the holder controls a private key, that a user consented, or that
any business action is authorized. Those proofs belong to independent
holder-presentation and relying-party policies.

For the issuer JWT format see [VC1.1 issuer profile](jwt-vc-json-profile.md);
for verifier and holder boundaries see [HTTP verification](jwt-vc-json-http-verify-profile.md)
and the [OpenID4VP HTTP bridge](jwt-vc-json-openid4vp-http-profile.md).
