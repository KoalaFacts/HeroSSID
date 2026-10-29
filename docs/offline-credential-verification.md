# Offline credential and signed-status verification (HeroSSID profile)

A separately deployed .NET relying party can now verify a HeroSSID `vc+jwt`
credential **and** a short-lived issuer-signed revocation snapshot using the
self-certifying Ed25519 public key in an explicitly trusted `did:key`. There
is no issuing database, HTTP request or server-side DID enrollment needed at
verification time. This is not OpenID4VP, W3C Bitstring Status List, holder
proof, external wallet interoperability or real-world identity certification.

```csharp
using HeroSSID.Credentials.CredentialVerification;

// Configure this trust anchor independently of JWT claims or an untrusted
// snapshot; NEVER discover it by blindly copying an incoming 'iss'.
string allowedIssuerDid = trustedIssuerFromVerifierPolicy;
OfflineCredentialCheckResult status = OfflineCredentialVerifier.Check(
    originalCredentialJwt,
    issuerSignedSnapshotJwt,
    allowedIssuerDid,
    DateTimeOffset.UtcNow);

if (status != OfflineCredentialCheckResult.SignedNotListed)
{
    // Invalid status/proof/credential OR explicitly revoked: deny.
    return;
}

// A correctly signed HeroSSID credential was not found in a valid current
// revocation snapshot. This is NOT a proof of issuer registration, possession,
// personal identity, qualification or permission. Check holder proof, intended
// use, and relying-party business authorization before any privileged action.
```

## Exact checks and limitations

- The caller selects the trusted `did:key:z...` DID through its own issuer
  trust policy. The verifier decodes the canonical Base58BTC Ed25519
  multicodec (0xed01), derives the 32-byte key, and ensures both the original
  credential and snapshot are signed by that exact key and bind the same
  trusted issuer. An attacker cannot select an arbitrary untrusted key by
  adding a new `iss` to an incoming JWT.
- The original local credential must be a strictly encoded EdDSA `vc+jwt`
  with unique JSON names, a non-empty holder `sub`, non-future integral
  `iat`, optional non-future integral `nbf`, valid unexpired integral
  `exp` when provided, a `vc.type` containing `VerifiableCredential`,
  an object `vc.credentialSubject`, and consistent subject `id` if present.
  This preserves the existing profile's missing/null expiration behavior.
- The snapshot must independently have a real valid Ed25519 signature,
  matching issuer, supported version, strictly sorted digest set, and be
  neither future-dated nor expired. Its observation-to-expiry window is at
  most 60 seconds. Any invalid credential or snapshot returns `Invalid`;
  an exact listed JWT returns `Revoked`; a signed credential not listed
  returns `SignedNotListed`. Rejection exposes no subject claims.
- `SignedNotListed` does **not** certify that the issuer stored/registered the
  JWT, that an earlier unexpired snapshot is the newest, that a holder
  controls a key, or that any specific business action is permitted. A
  distributor can withhold fresh snapshots, and status can be stale for up to
  the snapshot's remaining lifetime. The verifier must fail closed on
  missing/expired status and separately authenticate the holder and authorize
  the requested action.
- This reuses HeroSSID's own cryptographic library, not an independently
  implemented third-party wallet/verifier. No network publishing, schema
  changes, runtime deployment, external audit or conformance result is
  included in this deliverable.

See [the producer and status threat model](revocation-snapshot-profile.md).
