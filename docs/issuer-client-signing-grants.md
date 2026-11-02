# Operator-owned per-client issuer DID signing grants (opt-in)

HeroSSID's existing OAuth `credential:issue` scope is tenant-wide. A tenant may own
multiple Ed25519 issuer DIDs. A scoped client must not be mistaken for the issuer
itself, or for a business decision about what the client may attest.

An operator can now require an **exact client ID + exact issuer DID** permission
within selected tenants. This is a server-side signing-key access gate, not
proof of an organisation's real identity or the contents of a credential.

## Configure before serving HTTP

Add the following to the **verifier/issuer host's trusted app configuration**
(not to the request body). Replace the tenant UUID, client ID and DID with real,
independently approved values:

```json
{
  "IssuerSigningGrants": {
    "EnforcedTenants": [
      "11111111-1111-1111-1111-111111111111"
    ],
    "Grants": [
      {
        "TenantId": "11111111-1111-1111-1111-111111111111",
        "ClientId": "membership-issuer",
        "IssuerDid": "did:key:z6Mkj..."
      }
    ]
  }
}
```

The DID above is only illustrative: use a complete canonical Ed25519
`did:key` matching an active tenant-owned key, or startup rejects the policy.

- **No enforced tenants configured:** legacy tenant-wide `credential:issue`
  remains unchanged. This avoids an unannounced breaking change.
- **Tenant explicitly enforced, zero matching grants:** issuance fails closed
  for every client and DID in that tenant.
- **Tenant explicitly enforced with exact grants:** all three HTTP issuance
  routes (`/issue`, `/jwt-vc-json/issue`, `/vcdm20/issue`) check the
  authenticated bearer token's unique matching `client_id` and `sub`,
  its `tenant_id`, the exact issuer DID and the host grant before any key
  access or signing. A denied issuer is returned as 404, indistinguishable from
  an unknown issuer DID.
- Invalid, duplicate, nested, orphaned, unknown-field and over-capacity
  policies fail startup rather than being silently skipped. At most 128
  enforced tenants and 512 exact grants are accepted.

The same operator config must be deployed to **every** replica and protected
from application clients. This uses no new database schema, does not remotely
enrol clients, and does not automatically revoke already-issued JWTs.
OAuth token issuance remains bound to the client's registered scopes and
existing tenant DID ownership checks remain in place.

A valid signature establishes possession of the issuer signing key by the
HeroSSID service. It does **not** establish holder possession, real identity,
true subject claims, informed disclosure, automatic key continuity trust,
relying-party authorization or third-party Wallet interoperability.

See [vision](VISION.md) and [implemented limitations](../README.md).
