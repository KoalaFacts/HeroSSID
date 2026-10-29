# Generated `did:key` document profile

HeroSSID's **newly generated** `did:key` documents use the CCG did:key Ed25519 / `Ed25519VerificationKey2020` profile (version 0.9 of the community DID method description). The identifier and public key represent the **same** 32-byte Ed25519 key:

- DID: `did:key:z` + Base58btc(`0xed01` + raw Ed25519 public key)
- `verificationMethod[0].id`: `<did>#<full multibase suffix>`
- `verificationMethod[0].publicKeyMultibase`: the same full multibase suffix, including the `0xed01` multicodec prefix
- `authentication` and `assertionMethod`: arrays referencing this verification method, which is used for identity authentication and issuer credential assertions
- No `keyAgreement`, `capabilityInvocation`, `capabilityDelegation` or `service` is claimed; unconfigured relationships are omitted, not serialized as JSON null
- Constructing a document with a DID that does not derive from the supplied public key fails

This is a local DID document formatting/consistency improvement. It does **not** implement X25519 key agreement, remote DID resolution, issuer trust policy, selective disclosure, or independently tested wallet interoperability. A valid DID signature alone never grants business authorization or verifies a person's real-world identity.

## Already persisted DID documents

Older stored DID JSON can contain `#keys-1`, a raw 32-byte `publicKeyMultibase` without its multicodec prefix, missing `assertionMethod`, or JSON null for relationships. This change **does not** mutate historical database records. `DidResolutionService` continues to return stored JSON, so a previously created DID may still expose the legacy representation.

For a **read-only, explicit** canonical representation of an already stored and tenant-owned active did:key, an authenticated client with `did:manage` can call `GET /api/v1/dids/{did}/canonical`. The endpoint regenerates the 2020 profile from the **persisted public key only**, checks that the exact DID derives from that key, and returns 404 for unknown, deactivated, cross-tenant, or mismatched records. The original `GET /api/v1/dids/{did}` still returns the unmodified stored JSON. This is a local REST convenience, not a standards-defined DID resolution endpoint, independent wallet interoperability claim or database repair. It is not accessible without a valid scoped bearer token.

Before any separately authorized compatibility repair, inventory affected records without exporting private keys, check external consumers of `#keys-1`, check whether verifier logic uses the stored document and its verification relationships, and test behavior with existing credentials. Regenerate only from the **stored public key** after verifying its derived DID; preserve the original DID identifier and key material. Do not silently rewrite historical documents or run a production migration.

Specification context: [CCG did:key](https://w3c-ccg.github.io/did-key-spec/), [DID Core assertion methods](https://www.w3.org/TR/did-core/#assertion), and [Ed25519VerificationKey2020](https://www.w3.org/TR/2023/WD-vc-di-eddsa-20230420/).
