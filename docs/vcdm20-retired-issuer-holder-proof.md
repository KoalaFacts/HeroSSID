# Retired VC2 issuer with genuine holder proof (opt-in .NET 10 SDK)

A relying party can now verify a **single full-disclosure, holder-signed VC2 presentation** while independently enforcing its own active/retired Ed25519 issuer policy. Previously the issuer-retirement verifier authenticated the issuer's exact credential, but did not itself prove that a presenter controlled the holder DID. The new composition avoids treating a stolen JWT as holder authentication.

## Working SDK sequence

1. Independently establish trusted active issuer DIDs. Before retiring an older issuer, register the canonical lowercase SHA-256 digest of each **original compact VC2 JWT** you wish to continue accepting, paired with the old issuer DID. The digest alone never establishes when or by whom a credential was issued.
2. The verifier creates a tenant-owned, nonce-bound `IPresentationChallengeStore` challenge whose `TrustedIssuerDid` is the actual intended signer of that original JWT, and signs its request with `OfflineSignedPresentationRequest.Create`. Use a **shared atomic** store (for example the existing PostgreSQL implementation) across replicas, not an in-memory store per replica.
3. The Wallet app independently pins the real verifier DID and destination, verifies the issuer statement, obtains genuine full-disclosure consent through its own UI, then creates `Vcdm20JosePresentation.Create(...)` with the holder's **own** Ed25519 seed. The SDK cannot independently prove that consent occurred.
4. The verifier calls `Vcdm20RetiredIssuerPresentation.Check(presentationJwt, tenantId, audience, challenge.Nonce, type, contextUri, challengeStore, activeIssuerDids, retiredCredentialPins, clock, out verifiedIssuerDid, out verifiedSubject)`. An optional `CheckWithStatus` variant additionally requires an authentic issuer-signed snapshot from the actual VC signer. Neither operation needs new database schema or hosted exchange.

The new SDK first validates the issuer's **original signature**, the holder's **separate real signature**, the tenant/nonce/audience challenge, its time limits and atomic single use; it never returns authenticated credential bytes to an untrusted caller. It then authenticates the same original JWT against the **entire** independently supplied issuer retirement policy. If that policy or status fails, no signer or subject claims are released. A successfully consumed signed holder proof remains spent even when retirement policy, private revocation, or status freshness subsequently rejects it; request a **new** verifier challenge for a genuinely new attempt.

## Verifier-owned post-incident status observation cutoff

When an incident requires a **new issuer status observation**, use
`Vcdm20RetiredIssuerVerifier.CheckWithStatusAfterObservationCutoff` for
issuer-only validation, or
`Vcdm20RetiredIssuerPresentation.CheckWithStatusAfterObservationCutoff`
for the full holder-signed presentation. Both opt-in methods retain the
active/retired issuer policy and exact original compact JWT SHA-256 checks;
they require the separate **actual issuer's** authentic 60-second status
snapshot, with signed observation `iat` no earlier than the verifier's
independently chosen `minimumObservedAt`. No existing `Check` or
`CheckWithStatus` call changes behavior.

```csharp
var result = Vcdm20RetiredIssuerPresentation.CheckWithStatusAfterObservationCutoff(
    presentationJwt, signedStatusJwt, tenantId, audience, challenge.Nonce,
    credentialType, subjectContext, challengeStore, activeIssuerDids,
    retiredCredentialPins, minimumObservedAt, TimeProvider.System,
    out string actualIssuerDid, out JsonElement authenticatedSubject);
```

If a properly signed snapshot is still within its usual 60-second lifetime
but predates the verifier's cutoff, the result is `Invalid`, and the
authenticated issuer/subject outputs remain empty. A fresh clean snapshot
can yield `SignedNotListed`; a fresh snapshot listing the exact JWT yields
`IssuerReportedRevoked` without claims. Signed `iat` stores **whole
seconds**, so fractional-second cutoffs are compared conservatively, never
rounded down. Future or pre-Unix-epoch cutoffs fail closed **before** the
one-use holder challenge is consumed; after a valid holder proof is consumed,
a stale, forged or revoked status still leaves it spent to prevent replay.

The relying party must retain its own incident cutoff and trustworthy
status source. The issuer controls signed `iat`; it is **not** proof of
the true upstream observation time, complete records, an uncompromised
retired key, or live non-revocation. The existing raw
`Vcdm20RevocationSnapshot.CheckWithObservationCutoff` supplies the
underlying status check. This change is a private .NET SDK composition,
**not** a new W3C status-list format or OpenID4VP/Wallet interoperability
claim. Genuine holder signatures still do not prove user consent, real
identity or business authorization.

## Outcome contract

- `SignedButStatusUnchecked`: actual holder and issuer proofs, single-use challenge and verifier trust policy were checked; **no revocation status**.
- `SignedNotListed`: additionally, the actual issuer signed a valid recent private list which omitted this exact JWT; list completeness and current non-revocation remain **unproven**.
- `IssuerReportedRevoked`: the actual issuer's valid signed private snapshot listed the JWT; **no claims are returned**.
- `Invalid`: malformed or replayed VP, wrong holder, issuer, pin, tenant, audience, nonce, expired request/credential, forged status, or invalid full policy; **no claims are returned**.

This is a **HeroSSID opt-in SDK profile**, not a published OpenID4VP endpoint, independent third-party wallet interoperability or standard W3C status list. Signing an issuer statement is not proof of real identity or organisational registration. The holder's genuine Ed25519 proof is not evidence of human informed consent, delegated agent authority or application-level business authorization.
