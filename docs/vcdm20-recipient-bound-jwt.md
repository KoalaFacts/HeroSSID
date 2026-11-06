# Opt-in VC2 single-recipient signed credential

An issuer can sign an exact HTTPS credential identifier **and** one canonical
HTTPS RFC 7519 `aud` recipient in the same original Ed25519 direct `vc+jwt`
credential. A relying verifier independently pins its own recipient, exact
credential ID, issuer DID, holder DID, type, context and verification time
before exposing any subject claims.

```csharp
Uri id = new("https://issuer.example/credentials/member/001");
Uri recipient = new("https://verifier.example/membership");
string jwt = Vcdm20JoseCredential.CreateForAudienceWithId(
    issuerDid, holderDid, "MembershipCredential", contextUri,
    subjectJson, issuerSeed, validFrom, validUntil, id, recipient);

bool accepted = Vcdm20JoseCredential.TryVerifyForAudienceWithId(
    jwt, independentlyTrustedIssuerDid, independentlyExpectedHolderDid,
    "MembershipCredential", independentlyPinnedContextUri,
    independentlyPinnedCredentialId, independentlyPinnedRecipient,
    verificationTime, out JsonElement verifiedSubject);
```

The direct signed VC2 payload has eight top-level members: `@context`,
`type`, `issuer`, `validFrom`, `validUntil`, `credentialSubject`,
`id` and `aud`. The audience is a **single** canonical HTTPS URI string,
not an array. User-info, fragments, non-HTTPS schemes, oversized values,
additional signed members and unexpected header fields fail closed. The issuer
must control its own Ed25519 DID: using another seed fails at issuance.
A genuinely issuer-signed credential addressed to a different verifier is
rejected even if its credential ID and subject are otherwise correct.
The existing audience-free verification APIs stay strictly unchanged and
reject this new eight-member shape.

**Boundaries:** signed `aud` implements an RFC 7519 JWT recipient assertion,
not evidence the recipient controls that URL, a holder signature, consent,
replay resistance, independent issuer identity vetting, status or authorization.
This is a bounded HeroSSID SDK policy subset, **not** independently certified
W3C VC/JSON-LD conformance or OpenID4VP/third-party wallet interoperability.
For holder control, add a separate one-time holder-signed presentation and
the receiving application's own status and business/Agent authorization checks.

References: [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/),
[W3C VC JOSE/COSE](https://www.w3.org/TR/vc-jose-cose/),
[RFC 7519 §4.1.3](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3).

## Holder-signed, one-use presentation (opt-in SDK)

The recipient-bound issuer JWT above is **not** a holder possession proof.
`Vcdm20JosePresentation.CreateForAudienceWithIdAndSignedRequest` connects
it to an independently signed, policy-bound verifier request and creates a
real Ed25519 holder-signed `vp+jwt` only after the Wallet's application
has shown every disclosed claim and obtained the holder's consent.

```csharp
// Verifier issues a tenant-bound challenge into its own atomic store.
var challenge = challenges.Issue(verifierTenantId, recipient.AbsoluteUri, trustedIssuerDid);
string request = OfflineSignedPresentationRequest.Create(
    challenge with { CredentialType = "MembershipCredential", SubjectContextUri = contextUri },
    verifierDid, verifierSeed, clock);
// Verifier retains the exact original request SHA-256 on its own trusted side.
string requestPin = Convert.ToHexStringLower(
    SHA256.HashData(Encoding.UTF8.GetBytes(request)));

// Wallet independently pins the verifier DID, type/context, issuer/holder,
// recipient and exact credential ID; it must separately obtain actual consent.
string vp = Vcdm20JosePresentation.CreateForAudienceWithIdAndSignedRequest(
    request, verifierDid, recipient.AbsoluteUri, issuerSignedJwt,
    "MembershipCredential", contextUri, credentialId, recipient,
    holderDid, holderSeed, clock);

// Verifier: use its original pin, not the holder's claimed pin.
var result = Vcdm20JosePresentation.CheckForAudienceWithIdAndSignedRequest(
    vp, request, requestPin, verifierDid, verifierTenantId,
    recipient.AbsoluteUri, challenge.Nonce, "MembershipCredential",
    contextUri, credentialId, recipient, challenges, clock,
    out JsonElement verifiedClaims);
```

The VP includes the exact verifier request SHA-256 signed by the holder;
the verifier checks both the original verifier Ed25519 signature and its
independently stored hash. The issuer signed the exact credential ID and
HTTPS `aud`, which must match the verifier's independently pinned request
audience. The verifier authenticates the issuer and holder keys and uses
an atomic one-use challenge store. A replay, mismatched signed audience,
different credential ID, swapped authentic issuer JWT, wrong request digest,
expired request, invalid holder signature or reused nonce fails **without
releasing claims**. Use a shared atomic challenge store across replicas.

`SignedButStatusUnchecked` deliberately does **not** assert current
revocation status, legal identity, consent attestation, business/Agent
delegation, or authorization. Integrators still need issuer status validation
and local authorization before acting. This is a bounded HeroSSID SDK flow,
not proof of external OpenID4VP wallet interoperability or conformance.

## Original recipient-bound credential status

The issuer's existing private 60-second signed digest snapshot now accepts the
same **exact issuer-signed eight-field original** used by
`CreateForAudienceWithId`: both its canonical HTTPS `id` and the single
canonical HTTPS `aud` must be present. The issuer can list it by exact JWT
bytes in `Vcdm20RevocationSnapshot.Create`; a separately configured verifier
can evaluate those exact bytes with `Check` or `CheckWithObservationCutoff`.

```csharp
string statusJwt = Vcdm20RevocationSnapshot.Create(
    issuerDid, [recipientBoundCredentialJwt], issuerSeed, observedAt, clock);
Vcdm20RevocationCheckResult result = Vcdm20RevocationSnapshot.Check(
    statusJwt, recipientBoundCredentialJwt, independentlyTrustedIssuerDid,
    clock.GetUtcNow());
```

Two genuinely issued JWTs addressed to different `aud` values are
independent revocation entries even if they share an issuer, holder, subject
and credential `id`. Arrays, HTTP/noncanonical recipients, missing signed
IDs and unknown extra top-level members remain invalid. The status helper
does not itself enforce verifier recipient policy or holder possession:
applications must use the independently pinned VC verifier and holder-signed
one-use proof as separate gates before releasing claims. `SignedNotListed`
only asserts absence from this signed snapshot, not a complete or live
revocation inventory, legal identity, consent or business authorization.

## Single-use recipient-bound status gate (SDK opt-in)

`Vcdm20RevocationSnapshot.CheckRecipientBoundPresentationWithIssuerStatus`
composes the existing real Ed25519 verifier-signed **original request**,
issuer-signed credential with exact HTTPS `id` and `aud`, holder-signed
full-disclosure VP, verifier-owned atomic one-use nonce and the **same actual
issuer's** private, signed 60-second exact-token status. The verifier must
independently retain the exact signed request SHA-256, expected recipient,
credential ID, vocabulary, trusted issuer key and minimum signed status
observation time; none may be supplied as trust policy by the holder.

```csharp
// request, requestPin, vp, challenges and statusJwt are obtained separately.
// The verifier supplies its OWN enrolled original request and trust pins.
Vcdm20RevocationCheckResult decision =
    Vcdm20RevocationSnapshot.CheckRecipientBoundPresentationWithIssuerStatus(
        vp, request, requestPin, verifierDid, statusJwt, verifierTenantId,
        recipient.AbsoluteUri, challenge.Nonce, "MembershipCredential",
        contextUri, credentialId, recipient, minimumObservedAtUtc,
        challenges, clock, out JsonElement verifiedClaims);

if (decision == Vcdm20RevocationCheckResult.SignedNotListed)
{
    // Claims are authenticated and this status snapshot did not list
    // the exact original token. Apply separate business authorization here.
}
```

A failed verifier request digest, recipient or credential ID pin is rejected
**without** consuming the challenge. After a genuine issuer/holder proof spends
the challenge, a revoked, stale, forged, foreign-issuer or missing snapshot
rejects disclosure **and the nonce stays spent**; the verifier may not retry
the same proof with a different status token. Before releasing claims the SDK
rechecks both signed VP and status expiration against one final clock sample
to prevent a processing-delay expiry race.

`SignedNotListed` means only that this specific, genuine, short-lived issuer
snapshot omitted the exact signed JWT digest. It does **not** certify a complete
or live revocation inventory, valid business entitlement, issuer legal identity,
holder consent, third-party Wallet interoperability or Agent authorization.
The Wallet UI must obtain actual human consent separately; integrations need
their own enrollment, status-observation and authorization policies.
