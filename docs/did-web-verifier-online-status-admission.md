# Opt-in did:web verifier admission with live HTTPS status retrieval

.NET 10 SDK profile: `JwtVcJsonPinnedDidWebOnlineAdmission` combines
the existing verified issuer-status HTTPS transport with the composite
holder/issuer **single-use verifier challenge** policy.

## Operator-controlled inputs

Before receiving the VP, the verifier independently enrolls:

- The restricted `did:web` issuer and its exact `#key-1` or `#key-2` Ed25519
  assertion method **and 32-byte public key**, not learned from JWT claims.
- Signed issuer name, exact HTTPS credential ID, VC type, subject context and
  holder policy for this request.
- A fixed, independently approved HTTPS status URI. Never derive this URI
  from the credential, presentation, or a redirect.
- Tenant-bound audience/nonce using one shared/atomic
  `IPresentationChallengeStore`, and its own canonical lowercase SHA-256
  incident-denial digest set (up to 256 distinct entries).

The verifier receives the original issuer-signed compact JWT and the separate
holder-signed VP. Supply both: the implementation rejects an original JWT
different from the one embedded in the VP **before network access**.

## One-call SDK entrance

```csharp
var result = await JwtVcJsonPinnedDidWebOnlineAdmission
    .CheckWithIsolatedTransportAsync(
        independentlyPinnedStatusUri, originalCredentialJwt,
        holderPresentationJwt, verifierTenantId, expectedAudience,
        expectedNonce, trustedIssuerDid, trustedAssertionMethodId,
        independentlyPinnedIssuerEd25519Key, expectedIssuerName,
        expectedCredentialId, expectedCredentialType,
        expectedSubjectContextUri, currentVerifierDenylist,
        sharedAtomicChallengeStore, TimeProvider.System);

if (result.Result ==
    JwtVcJsonPinnedDidWebIssuerAdmissionResult.SignedNotRevoked)
{
    // Only now use result.VerifiedSubject. Check business authorization separately.
}
```

The secure-default method creates a dedicated public-only HTTPS transport with
TLS certificate validation, no redirects, cookies, proxy, ambient credentials
or secondary DNS lookup. HTTP is a bounded, credential-free GET expecting
`application/jwt`. Status bodies exceeding 8192 bytes are refused.

For isolated tests or an independently audited handler, `CheckAsync` also
accepts a caller-owned `HttpClient`. The caller is responsible for disabling
redirects, proxy, auth headers and private-network access in that handler;
the SDK cannot introspect its internals.

## Fail-closed outcomes and replay

1. Pre-network: reject inconsistent original JWT/VP, malformed local policy,
   and an issuer JWT whose **genuine pinned did:web Ed25519 signature, exact
   issuer name/credential ID/type/context or validity** fails the independently
   configured verifier policy. No HTTP request, nonce consumption or subject
   disclosure occurs for these mismatches. The signed credential's `sub` is
   used only as a candidate for validating issuer-signed holder binding; it
   never selects the issuer DID, method, verification key or verifier policy.
2. Fetch: verify the issuer's real Ed25519 signature over the exact original
   JWT and independently pinned method; authenticate the issuer's 60-second
   signed status and exact original JWT SHA-256. An unavailable, redirected,
   forged or stale response returns `Invalid` without spending the nonce.
3. Admission: verify the independent holder `did:key` Ed25519 signature,
   issuer-signed metadata, verifier audience/nonce and both verifier-owned
   emergency denial and issuer status. An authentic proof spends its one-use
   challenge once even when denied or issuer-revoked. Never release subject
   on `Invalid`, `DeniedByVerifier` or `RevokedByIssuer`.

Callers must rate-limit inbound presentations and status fetches, own trusted
network egress policy and serialize incident denylist updates with admission.
An injected handler is not automatically safe. The explicit issuer status
is a **point-in-time 60-second signed assertion**, not evidence of current
non-revocation after acceptance, an RFC/W3C status protocol, DID/domain
ownership or a legal identity claim. The holder signature proves control of
the holder key, not informed consent or a business/Agent permission.

No hosted issuer status endpoint, production provisioning, third-party wallet
exchange, external security audit or independent standard conformance is
provided by this SDK path. The wallet only holds and presents; it does not
issue or rewrite issuer statements.

## Verification

The real-key regression suite is
`JwtVcJsonPinnedDidWebOnlineAdmissionTests` under
`tests/Unit/HeroSSID.Credentials.Tests`. It covers accepted, replayed,
revoked, verifier-denied, forged-status, wrong-key and wrong-original cases,
and the no-network/no-nonce-consumption prerequisites. The injected HTTP
contract probe is not a third-party interoperability test. Run full repository
.NET 10 Build/Test/Security and CodeQL gates, not only this suite.
