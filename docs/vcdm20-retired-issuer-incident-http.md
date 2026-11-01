# VC2 incident-cutoff HTTP verification (opt-in)

This authenticated HTTP route allows a non-.NET relying party to verify an **issuer statement** signed as a direct VCDM 2.0 JOSE JWT while applying independently enrolled active issuers or exact original-JWT SHA-256 pins for retired Ed25519 issuers. The verifier additionally demands an authentic status snapshot signed by the actual issuer, with the signed observation timestamp at or after the verifier's independently chosen incident cutoff.

**POST** `/api/v1/credentials/vcdm20/verify-active-and-retired-after-incident` with a validated bearer token granting `credential:verify`.

```http
POST /api/v1/credentials/vcdm20/verify-active-and-retired-after-incident HTTP/1.1
Authorization: Bearer <verifier-tenant-token>
Content-Type: application/json

{
  "credential": "<unchanged-original-direct-vc2-jwt>",
  "activeIssuerDids": ["did:key:<current-ed25519-issuer>"],
  "retiredCredentialPins": [
    {
      "issuerDid": "did:key:<retired-ed25519-issuer>",
      "credentialSha256": "<64-lowercase-hex-sha256-of-exact-original-jwt>"
    }
  ],
  "expectedHolderDid": "did:key:<pinned-holder>",
  "expectedCredentialType": "MembershipCredential",
  "subjectContextUri": "https://issuer.example/context/membership/v2",
  "revocationSnapshot": "<original-issuer-signed-vc2-status-jwt>",
  "minimumObservedAt": "2026-11-01T11:59:50Z"
}
```

These identifiers are placeholders; use independently established exact keys and policy, not DIDs, digests or status copied from an untrusted credential or Wallet. The endpoint accepts at most 16 active DIDs, 256 retired original JWT pins and 16 distinct total issuers. An issuer may not be both active and retired. Each canonical fingerprint is SHA-256 over the **exact compact JWT string's UTF-8 bytes**, not its decoded JSON, and uses 64 lowercase hexadecimal characters. An empty retired list is allowed if the active issuer list is nonempty, and conversely. The provided status must be signed by the **actual authenticated credential issuer** and still be within the private 60-second profile; its signed observation time must also meet the supplied post-incident lower bound, including fractional-second boundaries.

A successful `200` result has `"status":"SignedNotListed"`, `verifiedIssuerDid` and `verifiedSubject`. Issuer-reported revocation has `"status":"IssuerReportedRevoked"`; a forged, unknown, expired, wrong-issuer or stale artifact has `"status":"Invalid"`. Both failures return **null** issuer and subject. Malformed verifier policy, missing status, missing/future/pre-epoch cutoff, noncanonical digests, duplicate or overlapping trust entries return `400` before interpretation of credential claims. The route requires bearer authentication and exact `credential:verify` authorization.

This route does **not** prove that the issuer's revoked set is complete, the observation timestamp reflects an independent witness, or that an old compromised signing key remains safe. Pin inventories must be established before retiring a key and maintained by the relying party. This route does **not** verify a holder's private-key possession, human or organisation identity, consent, agent delegation, business authority, live revocation or third-party Wallet/OpenID4VP interoperability. For true holder proof, use the separately signed, single-use VC2 presentation APIs and the [retired issuer holder-proof SDK](vcdm20-retired-issuer-holder-proof.md); do not interpret this issuer-only response as authorization.
