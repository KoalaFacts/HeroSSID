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
# Operator-controlled emergency refusal, optional; SHA-256 of the ORIGINAL JWT UTF-8 bytes:
Vcdm20VerifierTrust:Policies:0:DeniedCredentialSha256:0 = <64 lowercase hexadecimal characters>
# Up to 256 distinct exact-JWT digests per policy; omission means no local denial
```

The service validates every configured policy before accepting HTTP traffic:
at most 128 policies, no duplicate tenant/profile selectors, at most 16
distinct valid Ed25519 issuer DIDs in each policy, at most 256 distinct canonical
lowercase SHA-256 original-JWT digests (or none), a bounded unambiguous profile
identifier and HTTPS subject vocabulary. Malformed, duplicated or oversized
operator denial configuration fails startup, never silently disables denial. Invalid configuration prevents host
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
An authentic original JWT whose SHA-256 is in that host policy's emergency
denylist returns `{"status":"DeniedByVerifier","verifiedIssuerDid":null,"verifiedSubject":null}`.
Otherwise the result is `{"status":"Invalid","verifiedIssuerDid":null,"verifiedSubject":null}`.
A denial hash never authenticates a forged JWT; actual trusted-issuer signing,
expiry, type, holder and vocabulary validation precede the denial result.
Malformed requests return 400; authentication and scope failures return 401/403.
Unexpected JSON fields (including a claimant's `trustedIssuerDids`,
`credentialType`, `subjectContextUri` or `deniedCredentialSha256`) are rejected.
An HTTP caller cannot bypass operator denial by omitting a body field.

## Require genuine, fresh issuer-signed status as well (opt-in)

For relying parties that require issuer status, use the separate, authenticated
`POST /api/v1/credentials/vcdm20/verify-host-pinned-with-status` route.
It uses the **same verifier-operated tenant issuer/type/vocabulary policy
and emergency denial inventory**. The caller cannot select or replace that
policy, and cannot omit issuer status:

```http
POST /api/v1/credentials/vcdm20/verify-host-pinned-with-status
Authorization: Bearer <valid tenant access token>
Content-Type: application/json

{
  "policyId": "membership-v1",
  "credential": "<original direct VC2 issuer JWT>",
  "expectedHolderDid": "did:key:<expected holder>",
  "revocationSnapshot": "<fresh original-issuer-signed HeroSSID VC2 status JWT>"
}
```

The verifier validates the original JWT against its own trusted issuer set,
type, HTTPS vocabulary, holder and expiry. It then checks a **separate,
genuine Ed25519 signature by that actual issuer**, exact original-JWT SHA-256
membership and the private 60-second snapshot format. A fresh authentic
non-listing with no operator denial returns `SignedNotListed` with the
authenticated signer and subject; an issuer-listed JWT returns
`IssuerReportedRevoked`, an authentic operator-denied JWT returns
`DeniedByVerifier`, and malformed, expired, foreign-signed, tampered or
untrusted inputs return `Invalid`. Every rejection withholds issuer and
subject. Missing or oversized snapshot input returns HTTP 400.

The *issuer*, not the HTTP caller, signs the contents of the snapshot, but
the caller supplies its bytes; the signature **cannot attest that the list
is complete, current beyond its 60-second window, or retrieved from an
authoritative issuer distribution channel**. There is no live polling,
network registry, holder key challenge, consent UI or independent Wallet
interop. Operators must separately assure distribution/completeness and
manage their host policy across replicas. This is a private HeroSSID status
profile, **not** W3C Bitstring Status List.

Both endpoints check **issuer statements only**. A valid signature does not
prove possession of the holder key, consent, current non-revocation, independent
identity vetting, organization membership beyond the issuer's signed claim, or
business authorization. The response is deliberately
`SignedButStatusUnchecked`, never "safe", "live", or "authorized". The
operator must independently approve, protect, withdraw and synchronize trusted
issuers, denied original-JWT fingerprints and their business meanings. Existing
processes hold immutable snapshots: emergency withdrawal requires a controlled
configuration rollout/restart across replicas; this is not live revocation,
a hosted registry or a guarantee of instantaneous revocation. Legacy caller-policy verification routes
remain for applications that already enforce their own independent trust
boundary. No database schema, migration, key custody or new issuer enrollment.
