# Opt-in direct VC2 verification over authenticated HTTP

A holder or verifier that already possesses an issuer-signed **direct VC Data Model 2.0 JOSE** credential can submit it to `POST /api/v1/credentials/vcdm20/verify` with an OAuth bearer token having the `credential:verify` scope. This endpoint adds a non-.NET HTTP entry point to the existing `Vcdm20JoseCredential.TryVerify` cryptographic checker. It does not sign, persist, revoke, disclose a presentation or publish credentials.

The caller **must independently choose and pin** the expected `trustedIssuerDid`, `expectedHolderDid`, `expectedCredentialType` and versioned HTTPS `subjectContextUri` from its own verification policy. None is discovered or trusted from the submitted JWT or endorsed by HeroSSID. For example:

```json
{
  "credential": "<original issuer-signed direct VC2 JWT>",
  "trustedIssuerDid": "did:key:<pinned issuer>",
  "expectedHolderDid": "did:key:<expected subject>",
  "expectedCredentialType": "MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1"
}
```

A successful HTTP 200 response has `{"status":"SignedButStatusUnchecked","verifiedSubject":{...}}`. An invalid signature, wrong issuer/subject/type/context, expired token or unsupported legacy nested `vc` JWT returns `{"status":"Invalid","verifiedSubject":null}`; malformed policy input returns HTTP 400. Anonymous calls receive 401 and requests without `credential:verify` receive 403. Signature and issuer checks happen **before** any claims are returned.

**Meaning of success:** only authentic issuer signature, fixed known issuer DID and exact profile/vocabulary/subject/time constraints have been checked. The requester provided the issuer trust decision. No holder proof of key control, consent, revocation/status, reality-based identity vetting, enrollment or business authorization has occurred. The API may not be used alone as an access grant or assertion of an unrevoked credential. For full-disclosure holder control and separate signed status, see [VC2 holder presentation](vcdm20-jose-presentation-profile.md) and [signed issuer snapshot](vcdm20-revocation-snapshot-profile.md).

This is the existing narrow direct VC2 JOSE encoding. It does not claim JSON-LD expansion, third-party wallet interoperability, OID4VC conformance, W3C status lists, remote trust discovery or key rotation. No new DB schema, production deployment or issuer key handling is added.


## Explicit historical/current issuer HTTP verification (opt-in)

Non-.NET relying parties with `credential:verify` can use either
`POST /api/v1/credentials/vcdm20/verify-trusted-issuers` or
`POST /api/v1/credentials/vcdm20/verify-trusted-issuers-with-status`.
These are separate from the original single-issuer endpoints and do not
change their contracts. A verifier must independently enroll and protect
its own **1–16 distinct Ed25519 did:key issuer DIDs**; it may remove an old
issuer at any time. No issuer is trusted merely because it appears in a
credential, JWT header, Wallet response or key-successor statement.

```json
{
  "credential": "<original direct VC2 signed JWT>",
  "trustedIssuerDids": ["did:key:<old pinned issuer>", "did:key:<new pinned issuer>"],
  "expectedHolderDid": "did:key:<expected subject>",
  "expectedCredentialType": "MembershipCredential",
  "subjectContextUri": "https://issuer.example/contexts/membership/v1"
}
```

For the `-with-status` route, supply `revocationSnapshot` containing
the original issuer-signed HeroSSID VC2 snapshot in the same request.
An authenticated successful response provides
`{"status":"SignedButStatusUnchecked","verifiedIssuerDid":"did:key:<actual cryptographic signer>","verifiedSubject":{...}}`,
or `SignedNotListed` for the status-enforcing route. The exact verified
credential signer **must also be the original signer of the supplied
snapshot**. A valid snapshot issued by a *different trusted issuer* cannot
clear a credential issued by the first one. `Revoked` or `Invalid`
responses contain null signer **and** null subject; the verifier must not
grant access on either. A missing snapshot, malformed/duplicated/empty or
oversized trust policy, unbounded input or a status field erroneously sent
to the non-status route yields HTTP 400. Missing bearer authentication
is 401; insufficient scope is 403.

This authenticates only an issuer statement and optionally the authenticity
and membership of an issuer-provided, 60-second private revocation snapshot.
`SignedNotListed` cannot prove that the issuer's revoked set is complete
or that the credential is live-valid. The caller is responsible for its
independent issuer enrollment, trust-list custody, holder control, user
consent, identity vetting and business authorization. No hosted public
callback, DID rotation, database migration, W3C Bitstring Status List
or independently demonstrated third-party Wallet interop is provided.
