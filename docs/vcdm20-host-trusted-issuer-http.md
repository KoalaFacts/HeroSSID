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
# Optional operator-enforced issuer status observation lower bound, UTC round-trip format:
Vcdm20VerifierTrust:Policies:0:MinimumStatusObservedAtUtc = 2026-11-02T08:00:00.0000000+00:00
# Omit the cutoff to preserve the existing 60-second issuer status-only behavior
```

The service validates every configured policy before accepting HTTP traffic:
at most 128 policies, no duplicate tenant/profile selectors, at most 16
distinct valid Ed25519 issuer DIDs in each policy, at most 256 distinct canonical
lowercase SHA-256 original-JWT digests (or none), a bounded unambiguous profile
identifier and HTTPS subject vocabulary. Malformed, duplicated or oversized
operator denial configuration fails startup, never silently disables denial.
If supplied, the minimum status observation time must be a canonical UTC
round-trip timestamp (`O` in .NET) at or after 1970-01-01; malformed,
non-UTC, negative or nested values fail startup. The seven supported
per-policy keys are exactly `TenantId`, `PolicyId`, `CredentialType`,
`SubjectContextUri`, `TrustedIssuerDids`, `DeniedCredentialSha256`, and
`MinimumStatusObservedAtUtc`. Unexpected keys (including typos such as
`MinimumStatusObservationUtc` and `DeniedCredentialsSha256`) and nested values
under scalar keys **fail startup**, rather than silently disabling an operator
safeguard. List children remain confined to the two documented issuer/denial
collections. This protects against misconfigured policy deployment, but
cannot attest that the configured issuer trust, cutoff or denial inventory
is complete or correctly approved. Invalid configuration prevents host
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

### Optional host-owned incident observation cutoff

An operator may set `MinimumStatusObservedAtUtc` on the selected tenant
policy **before** accepting the signed-status verification response. Only the
`verify-host-pinned-with-status` route uses it; the status-unchecked route
continues to report `SignedButStatusUnchecked` regardless of this setting.
The cutoff never comes from request JSON. A valid issuer-signed status snapshot
whose signed `iat` is *before* the operator cutoff returns `Invalid`, with
no issuer or subject, **even if it remains inside its ordinary 60-second
validity window**. A status signed at/after the bound can be considered only
after all original Ed25519 signature, credential, issuer, holder, type,
context, 60-second freshness and verifier emergency-denial checks pass.
Issuer snapshots encode whole-second `iat`; a fractional UTC cutoff
conservatively rejects a snapshot rounded down below the cutoff. A
future cutoff fails closed until status is old enough to satisfy it.

The cutoff is a relying-party **policy for the signed timestamp**, not proof
that an issuer honestly observed a complete revocation list at that time.
A compromised issuer key can forge a timestamp; status distribution and
list-completeness guarantees still require an independent authoritative
service and operational controls. The verifier must consistently deploy
the same policy to every replica, and it remains immutable until restart.

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
