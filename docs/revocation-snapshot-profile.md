# Issuer-signed revocation snapshot (HeroSSID-specific v1)

This feature lets an authenticated issuer export a **short-lived signed artifact** of known revoked JWT credentials, and a separate verifier check the artifact **without network/database access**. It is an interim small lifecycle component, **not** W3C Bitstring Status List v1.0, OpenID4VP, a public hosted status API, or a claim of wallet interoperability.

## Producer

1. Authenticate a token with the exact `credential:revoke` scope and the issuer's tenant. Only its active `did:key` issuer can export.
2. `POST /api/v1/credentials/revocation-snapshot` with `{"issuerDid":"did:key:z..."}` (see `HeroSSID.Api.http`).
3. Receive `{"snapshot":"<compact JWS>"}`. Explicitly publish or transfer the JWS to your intended verifier **over a channel of your choice**. The API does not auto-publish, provide discovery, or change existing issued JWTs. Refresh it whenever a credential is revoked and at least once per minute while in use.

The producer queries the issuer's existing tenant-owned revoked rows and signs a sorted, duplicate-free SHA-256 digest set (lowercase hex) using the **real issuer Ed25519 key**, which is decrypted only for signing and cleared afterward. The JWT header has `alg=EdDSA` and `typ=herossid-revocation-snapshot+jwt`. The payload has `version=1`, `iss`, `iat`, `exp`, and `revoked`. The publisher timestamps the observation **before** reading the revoked set and signs with that timestamp; the deadline is at most 60 seconds from this boundary, including database, decryption and signing latency. If the work exhausts the budget it returns HTTP 503 with no snapshot, not a fresh timestamp for old data. The exact-snapshot cap is **256 revoked database rows**; more rows fail with 409. It never signs a partial set or includes raw credentials/subjects. Source records have their own tenant and issuer checks; every included compact JWT must verify under the issuer key and bind the issuer. No new schema, status list table or migration.

## Independent offline check

An external .NET verifier with the original JWT, signed snapshot and an **independently trusted issuer DID/public key** can run:

```csharp
var result = IssuerRevocationSnapshot.Check(
    snapshot, originalCredentialJwt, expectedIssuerDid, trustedIssuerPublicKey,
    DateTimeOffset.UtcNow);

if (result != RevocationSnapshotCheckResult.NotListed)
{
    // Revoked OR Invalid: deny the operation.
}
```

The verifier must independently establish that its trusted key is the key controlled by the expected issuer DID (for did:key, decode the self-certifying multicodec representation), verify original credential validity, time, holder control, intended purpose and business authorization. The offline check cryptographically binds the original signed credential and snapshot to exactly that key and DID, rejects ambiguous JSON, wrong algorithms/types, altered signatures, invalid order/encoding and expired/future timestamps. This method is **only a status adjunct**: `NotListed` deliberately is not named `Valid` or `Active`. Unknown locally unregistered credentials may be not listed; no proof of issuer database registration is issued.

## Threat and operational boundaries

- A verifier may receive a pre-revocation snapshot for up to one minute after a change. Reject stale/invalid snapshots; request a fresh one. Distributing a newer snapshot does not invalidate older still-unexpired signed copies. A strong real-time guarantee needs another protocol.
- A malicious distributor can withhold snapshots. Their content cannot be changed without invalidating the issuer signature, but freshness and availability must be enforced by the verifier.
- Publishing even one-way credential hashes allows recipients who possess a JWT to test membership and link revocations. The number of revoked entries is visible. The issuer explicitly decides distribution.
- Key loss/deactivation disables new snapshots; rotating DID keys, retention/purging historic JWTs and distributed status publication have no complete recovery lifecycle here.
- This snapshot is bounded to 256 revoked records per issuer. Exceeding the cap is a hard failure, not truncation. High-volume issuers require a separately designed status service.
- PostgreSQL issuer/tenant row queries are trusted operational state. No external attestation exists for database integrity, clock synchronization or issuer registration. Tests using PostgreSQL Testcontainers and offline .NET signature checking are not independent wallet/protocol conformance.
