# VC2 holder-bound, verifier-pinned signed membership check

This opt-in .NET 10 SDK API composes **three distinct assertions** for a relying party: (1) an organisation signed the original VC Data Model 2.0 JOSE `vc+jwt`; (2) the independently identified holder signed a full-disclosure `vp+jwt` for the verifier's one-use challenge; (3) the verifier's **own** issuer / holder / credential ID / vocabulary / signed claim policy accepts both artifacts.

## End-to-end SDK entry point

1. Enroll the issuer's exact Ed25519 `did:key` out of band; independently enroll the expected holder DID and exact HTTPS credential ID. Enroll the type, HTTPS context and exact required top-level string values from a trusted source, **never** from the presented JWT.
2. The verifier issues a tenant-scoped, one-use nonce through `IPresentationChallengeStore` and creates an Ed25519 signed verifier request using `OfflineSignedPresentationRequest.Create`; it retains the challenge in its own store.
3. A holder-facing application pins the verifier DID and audience, **shows all claims and obtains genuine informed consent**, and invokes the opt-in `Vcdm20JosePresentation.CreateWithSignedCredentialId` with its independently pinned expected credential ID and its *own* holder signing key and the issuer's original, unchanged signed VC2 JWT.
4. The verifier calls `Vcdm20SignedClaimPresentation.Check` with the holder's `vp+jwt`, its tenant / audience / nonce / type / context, its own challenge store, trusted issuer DID list, expected holder DID, exact credential ID, 1–16 expected top-level string claims, and clock.

For example, the verifier's policy can require `{ ["membership"] = "active" }` plus `{ ["tier"] = "standard" }` for an **exact identified** membership credential. The legacy `Vcdm20JosePresentation.Create` / `Check` methods intentionally remain six-field-only and **do not accept** a signed-ID VC2 credential; the opt-in signed-ID constructor and composite checker are the explicit upgrade path. The output `verifiedIssuerDid` and `verifiedSubject` are released **only** after both genuine Ed25519 signatures, tenant-owned nonce and audience, one-use atomic consumption, credential type/context/expiry, independent issuer and holder pins, signed credential ID, and exact case-sensitive string values all pass. A failed call returns `Invalid` with empty signer and undefined subject. A valid but disallowed `inactive` credential is rejected; its correctly authenticated one-use presentation remains spent.

Immediately before releasing any signer or subject, the composite checker takes
a final verification-clock sample *after* the original issuer/holder signatures
and claim checks. It rechecks the authenticated holder VP's signed fractional
`exp` (already bounded by the retained challenge and original VC expiry).
The status-aware path also rechecks the issuer-authenticated snapshot's signed
60-second `exp` at that same instant. A deadline crossed during checking
rejects with empty outputs; the consumed challenge stays spent. A successful
return is only a point-in-time result, not future validity.

The successful result is `SignedButStatusUnchecked`: **it does not attest current membership, non-revocation, reliable identity enrollment, genuine consent, entitlement or business authorization.** The application must separately enforce revocation freshness, identity-vetting requirements and an independent purpose-specific authorization decision. This SDK cannot prove a human actually saw a consent screen. The issuer context is checked by exact URI only; there is **no JSON-LD semantic expansion** or independent Wallet interoperability test. Do not call this a standard OpenID4VP 1.0 hosted transport.

The SDK's `InMemoryPresentationChallengeStore` is process-local. A multi-replica service requires a shared, atomic, durable challenge store; no new schema, database migration or remote endpoint is provided by this package. Never accept a verifier policy supplied by the Wallet itself.

See [VC2 JOSE signed ID](vcdm20-issuer-signed-id.md), [verifier-owned exact string policy](vcdm20-required-signed-claims.md), and [VISION](VISION.md).

## Opt-in exact same-issuer status for a signed-ID membership presentation

The existing `Check` remains explicitly **status-unchecked**. A verifier that
requires original credential status can call
`Vcdm20SignedClaimPresentation.CheckWithIssuerStatus` with the same
verifier-owned enrollment policy plus the issuer's original
`herossid-vc2-revocation-snapshot+jwt` and an **independently configured**
`minimumObservedAtUtc`.

The helper consumes the genuine holder's challenge once, verifies the
original VC2 Ed25519 issuer signature, exact signed HTTPS credential ID,
independently pinned issuer/holder, context/type/lifetime and required
top-level string claims. It then checks the genuine 60-second signed status
for **that exact original JWT from the verified actual issuer** and requires
the signed observation to be no earlier than the caller's cutoff. An
authentic but revoked original returns `Revoked`, a wrong signer's status,
stale observation, invalid claim or replay returns `Invalid`; all refusals
release empty signer and undefined claims. Only `SignedNotListed` returns
verified issuer and claims; the challenge is spent even if issuer status
or claim policy fails.

The private issuer snapshot checker now accepts either the existing
six-field direct VC2 original or the explicit seven-field direct VC2 with a
canonical signed HTTPS top-level `id`, without accepting unknown additional
policy fields. It continues checking the original Ed25519 signature and
exact digest. This is **not** a W3C Bitstring Status List implementation.
A real issuer can sign an incomplete or dishonest status set; an old
compromised key can sign apparently fresh evidence. `SignedNotListed` is
not proof of complete or live revocation, current membership, informed
consent, reality-vetted identity, entitlement or business authorization.
There is no new hosted endpoint, externally tested Wallet compatibility
or automatic verifier policy enrollment.
