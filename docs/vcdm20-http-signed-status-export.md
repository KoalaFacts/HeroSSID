# Issuer-owned direct VC2 signed status export over authenticated HTTP

A tenant owning an active Ed25519 `did:key` issuer can now produce the **existing private** `herossid-vc2-revocation-snapshot+jwt` with a scoped HTTP call. This is useful to a non-.NET issuer integration that manages its own revoked original VC2 JWTs, and to a separately trusted verifier using `Vcdm20RevocationSnapshot.Check` or `/api/v1/credentials/vcdm20/verify-with-status`. This is **not** W3C Bitstring Status List, `credentialStatus`, a hosted status registry, independent wallet interoperability or evidence of identity/authority.

## HTTP issuer operation

`POST /api/v1/credentials/vcdm20/sign-revocation-snapshot`

The caller must be authenticated for **both** `credential:revoke` and `did:manage`. The issuer DID must be **active and owned by the authenticated tenant**. HeroSSID checks its persisted public key matches the self-certifying DID before decrypting the seed, signs with that issuer's real Ed25519 key, and clears plaintext seed memory. A forged JWT or JWT of another issuer is not accepted into the list.

Example JSON body (replace values with the real original compact signed credentials and the issuer's observation):

```json
{
  "issuerDid": "did:key:z...",
  "observedAt": "2026-11-01T00:00:00Z",
  "revokedCredentials": ["header.payload.signature"]
}
```

The issuer **must record `observedAt` before independently reading the complete authoritative revocation set**, then send the exact original compact JWT strings. The endpoint cannot prove that this list is complete, that the observation was genuine or that the status remains current. An empty set is **not** proof nothing was revoked. No database-stored or HTTP-issued VC2 credentials are automatically consulted or revoked.

Successful response: `201 Created` with `{ "snapshotJwt": "<issuer-signed-JWS>" }`. The signer emits only sorted unique SHA-256 digests, not subject attributes. For a valid issuer JWT, the independent verifier may receive `Revoked` or `SignedNotListed`; the latter is **not** live non-revocation or business authorization. Signature alone does not prove possession of the holder's private key, real-world identity, actual user consent or any permission.

## Fail-closed input and operational limits

- At most **256** revoked input JWTs; each at most **65,536 characters** and total input credential characters at most **180,000**. The issued snapshot itself remains bounded by the library.
- `observedAt` must not be in the future or older than 60 seconds at signing. Signing latency **shortens** the observation window; an already stale result is never returned.
- Malformed DID, malformed/foreign/forged revoked JWT, stale observation and oversized requests receive 400. Missing/foreign/inactive tenant issuer receives 404. Anonymous or insufficient scopes receive 401/403; issuer signing backend unavailable receives 503. Rate limiting is shared with the existing VC1.1 signed-status export.
- Per-process limiter and caller-supplied list completeness are deployment/operator responsibilities, not a coordinated revocation service. No new schema, migration or release is required to compile this route, but production deployment was **not** performed.

The exact private wire format and SDK verifier/holder presentation behavior are documented in [VC2 issuer-signed revocation snapshots](vcdm20-revocation-snapshot-profile.md) and [VC2 HTTP status verification](vcdm20-http-status-verify-profile.md). Use the original issuer signature and an independently pinned issuer trust decision; never accept issuer identity solely from an untrusted status JWT.
