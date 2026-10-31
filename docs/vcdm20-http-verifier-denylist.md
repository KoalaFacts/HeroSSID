# Direct VC2 HTTP verification with verifier-owned exact-JWT denial

This **opt-in .NET 10 HTTP adapter** exposes the existing direct VC Data Model 2.0 JOSE credential verification and verifier-owned local emergency denial policy to non-.NET clients. It is **not** credential registration, holder-key proof, real-world identity verification, business authorization, OpenID4VP interoperability or live revocation.

## Authenticated entry points

All endpoints use POST under `/api/v1/credentials` and require a valid bearer token with `credential:verify`. The additional routes are:

- `/vcdm20/verify-trusted-issuers-with-denylist` — validate original issuer Ed25519 signature, independently pinned issuer/holder/type/HTTPS context/expiry and local exact original-JWT SHA-256 denial. Status remains unchecked.
- `/vcdm20/verify-trusted-issuers-with-denylist-and-status` — additionally require an authentic issuer-signed, no-older-than-60-second private VC2 revocation snapshot **from the actual signer of that exact credential**. A clean snapshot does not override an independent denial.

A representative request (the placeholders must be replaced with independently obtained values):

```http
POST /api/v1/credentials/vcdm20/verify-trusted-issuers-with-denylist
Authorization: Bearer <token-with-credential:verify>
Content-Type: application/json

{
  "credential": "<original compact direct VC2 JWT>",
  "trustedIssuerDids": ["did:key:z<independently-pinned-issuer>"],
  "deniedCredentialSha256": [
    "<64 lowercase hex characters: SHA-256 of original compact JWT UTF-8 bytes>"
  ],
  "expectedHolderDid": "did:key:z<pinned-holder>",
  "expectedCredentialType": "MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1"
}
```

Supply the same fields plus `"revocationSnapshot": "<signed-issuer-snapshot-JWT>"` on the `-and-status` route. Use `"deniedCredentialSha256": []` to explicitly request verification without a locally denied JWT. **Omitting the field is an invalid request**, not an implicit empty policy. Only the issuer and relying party can authoritatively determine their respective trust policies; never build the trusted DID list or denial policy by accepting arbitrary untrusted credential assertions.

## Response and security boundary

Successful validation with no status request yields HTTP 200 and `{"status":"SignedButStatusUnchecked","verifiedIssuerDid":"did:key:z...","verifiedSubject":{...}}`. Authentic status not listing the JWT yields `SignedNotListed` with those authenticated fields, but requires an authoritative *complete* issuer set to interpret status meaningfully.

HTTP 200 `DeniedByVerifier`, `IssuerReportedRevoked` or `Invalid` always has JSON null issuer and subject fields. A matching SHA-256 digest **does not authenticate a forged or untrusted JWT**: original issuer Ed25519 verification and all pinned policy checks occur first. A snapshot from another independently trusted issuer cannot clear it. A malformed, missing, duplicated, non-lowercase or oversized denial list is HTTP 400, never silently truncated or ignored. The two earlier `/vcdm20/verify-trusted-issuers` routes **reject** any submitted `deniedCredentialSha256` field, including `[]`, instead of dropping its security meaning.

Limits: original JWT and snapshot maximum 65,536 characters; 1–16 distinct independently pinned valid Ed25519 `did:key` issuers; 0–256 **unique canonical 64-character lowercase hexadecimal SHA-256** fingerprints. The relying party is responsible for protected, consistent distribution and withdrawal of its policy across replicas. The library stores no shared denylist and performs no network revocation lookup.

Issuer signing proves a credential statement, **not** possession of the holder's private key; a presentation must establish the latter separately. Neither proves real-world identity, informed disclosure consent or right to perform an application action. Local denial is not a credential-status registry, and `SignedNotListed` is not independently assured real-time non-revocation. No production deployment, issuer status registry, or third-party wallet conformance is implied.
