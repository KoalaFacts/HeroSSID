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
