# Server-owned VC2 issuer trust over authenticated HTTP

This optional API lets a relying verifier authenticate a direct W3C VC Data Model
2.0 JOSE JWT using its **own** issuer/type/context policy, instead of accepting
an issuer DID picked by the HTTP client. The signed payload uses the bounded
HeroSSID `vc+jwt` / `cty: vc` Ed25519 `did:key` profile. This does **not**
establish general JSON-LD or independent wallet interoperability.

## Configure a verifier before accepting claims

Install each policy via protected deployment configuration, not request JSON:

```text
Vcdm20VerifierTrust:Policies:0:TenantId = <authenticated verifier tenant GUID>
Vcdm20VerifierTrust:Policies:0:PolicyId = membership-v1
Vcdm20VerifierTrust:Policies:0:CredentialType = MembershipCredential
Vcdm20VerifierTrust:Policies:0:SubjectContextUri = https://issuer.example/contexts/membership/v1
Vcdm20VerifierTrust:Policies:0:TrustedIssuerDids:0 = did:key:<operator-approved issuer>
# Optionally add :1 through :15 for independently approved historical/current issuers
```

The service validates every configured policy before accepting HTTP traffic:
at most 128 policies, no duplicate tenant/profile selectors, at most 16
distinct valid Ed25519 issuer DIDs in each policy, a bounded unambiguous profile
identifier and HTTPS subject vocabulary. Invalid configuration prevents host
startup. A missing policy for a tenant never falls back to an HTTP-supplied
issuer. Policies are immutable for the lifetime of the process; to change
issuer trust, protect the authorization process and redeploy/restart all replicas.

## Verify from a non-.NET relying client

Obtain a validated tenant bearer token with `credential:verify`, then call:

```http
POST /api/v1/credentials/vcdm20/verify-host-pinned
Authorization: Bearer <valid tenant access token>
Content-Type: application/json

{
  "policyId": "membership-v1",
  "credential": "<original direct VC2 compact issuer JWT>",
  "expectedHolderDid": "did:key:<expected holder>"
}
```

If the issuer's real Ed25519 signature, expiry, exact holder, credential type,
and exact HTTPS subject vocabulary all match a policy selected by the host,
the result is `{"status":"SignedButStatusUnchecked","verifiedIssuerDid":"did:key:...","verifiedSubject":{...}}`.
Otherwise the result is `{"status":"Invalid","verifiedIssuerDid":null,"verifiedSubject":null}`.
Malformed requests return 400; authentication and scope failures return 401/403.
Unexpected JSON fields (including a claimant's `trustedIssuerDids`,
`credentialType`, `subjectContextUri` or denylist) are rejected.

This endpoint checks **issuer statements only**. A valid signature does not
prove possession of the holder key, consent, current non-revocation, independent
identity vetting, organization membership beyond the issuer's signed claim, or
business authorization. The response is deliberately
`SignedButStatusUnchecked`, never "safe", "live", or "authorized". The
operator must independently approve, protect, withdraw and synchronize trusted
issuers and their business meanings. Legacy caller-policy verification routes
remain for applications that already enforce their own independent trust
boundary. No database schema, migration, key custody or new issuer enrollment.
