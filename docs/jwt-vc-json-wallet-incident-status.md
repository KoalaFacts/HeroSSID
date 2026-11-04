# VC1.1 Wallet post-incident issuer status gate (opt-in .NET 10 SDK)

This is a **Wallet-only**, full-disclosure safety path for HeroSSID's bounded
OpenID4VP 1.0 `jwt_vc_json`/`direct_post` subset. It is NOT proof of
third-party Wallet interoperability or full OpenID4VP conformance.

A Wallet may possess an authentic original issuer-signed VC 1.1 JWT and a
genuinely signed but **pre-incident** issuer revocation snapshot that is still
within the private 60-second freshness window. For applications requiring an
issuer observation *after* an operator-known incident, that snapshot must not
be treated as sufficient to disclose the holder's claims or invoke the holder
private key.

## Consumer entrypoints and independent policy

The integrating Wallet must obtain an independently pinned verifier DID,
HTTPS response URI, credential type, HTTPS subject context, trusted issuer
DID, holder DID, and `minimumObservedAt`. None of those are inferred from an
unsigned launch URL, the credential, issuer's status claim or a self-asserted
request policy. The Wallet must maintain the **current** cutoff as operator
policy and use it both before and after the user's consent interaction.

```csharp
using HeroSSID.Credentials.VerifiablePresentations;

if (!JwtVcJsonWalletIncidentDisclosure.TryPrepare(
        requestJwt, expectedVerifierDid, expectedResponseUri,
        expectedCredentialType, expectedSubjectContextUri, expectedIssuerDid,
        originalIssuerJwt, holderDid, issuerSignedSnapshotJwt,
        currentWalletIncidentCutoff, TimeProvider.System,
        out var preview) || preview is null)
{
    return; // Never show unverified subject claims or use the holder key.
}

// Show ALL fields in preview.Status.Disclosure.VerifiedSubject,
// the verifier/callback, issuer, type/context and status/cutoff limitation.
// The application must obtain real, meaningful full-disclosure consent.
if (!await ShowFullDisclosureAndObtainConsentAsync(preview.Status.Disclosure))
{
    return;
}

// Read the LATEST Wallet-owned cutoff again; an incident during consent
// must invalidate the earlier preview. Do not fetch it from Wallet input.
string form = JwtVcJsonWalletIncidentDisclosure
    .CreateHolderBoundResponseFormAfterPreview(
        preview, requestJwt, originalIssuerJwt, issuerSignedSnapshotJwt,
        currentWalletIncidentCutoffAfterConsent, holderPrivateSeed,
        TimeProvider.System);

// Post only to the independently verified HTTPS callback URI.
```

`TryPrepare` authenticates the real verifier Ed25519 signature, exact
signed request issuer/type/context/HTTPS callback, original VC1.1 Ed25519
issuer signature, holder DID, expiry and the same genuine issuer's private
signed status. It requires the issuer's **signed observation timestamp** (now preserved
to 100ns for newly issued private snapshots) at or after the independent
cutoff before returning any subject claims. A cutoff at `10:00:00.500Z`
can accept a genuine observation at `10:00:00.500Z` or later without
waiting for the next whole second. Previously issued whole-second snapshots
remain readable but cannot claim a later fractional observation; the verifier
never rounds its own cutoff backwards.

After the Wallet application's consent UI, the signing method rejects changed
cutoff, request, issuer credential, signed status, claims, holder key or
expiry. It **repeats** authenticity and cutoff checks before holder signing
and verifies the issuer status once more afterwards to avoid returning a
proof that crossed the 60-second expiry boundary. The holder's real Ed25519
signature commits to the SHA-256 of the **unchanged exact original signed
verifier request** using `CreateHolderBoundResponseForm`. The private
`herossidRequestSha256` claim is not standardized holder binding.

## Separate relying-party verification

The verifier must independently retain its **own** lowercase SHA-256 of the
original compact signed Request Object, keep the original request under
verifier control, and atomically consume its tenant-bound challenge. It must
also apply its own *current* incident observation cutoff. Its strict
`JwtVcJsonDirectPostRevocation.CheckHolderBoundResponseFormWithObservationCutoff`
checks the real issuer and holder signatures, pinned verifier request hash,
actual enclosed issuer JWT, independently trusted issuer, current signed
status, nonce and one-time challenge. A successful result is only
`RevocationSnapshotCheckResult.NotListed`; failed verification releases no
subject. The Wallet preview is neither a verifier decision nor a status
authority.

The two cutoffs are independently controlled: the Wallet's cutoff prevents
an unsafe **disclosure/signing attempt**; the verifier's cutoff prevents
acceptance. Neither can be safely derived from holder-provided data.

## Real acceptance and limitations

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj \
  --configuration Release \
  --filter FullyQualifiedName~JwtVcJsonWalletIncidentDisclosureTests
```

Real distinct issuer, verifier and holder Ed25519 keys cover positive
holder-bound `direct_post`, one-time replay rejection, genuine but
pre-cutoff status, changed policy between preview and consent, an incorrect
holder key, changed credential, fractional-second cutoff, future/pre-epoch
cutoff and signed revocation. The independent verifier's final policy remains
its own responsibility.

An authentic signed snapshot can lie about observation time or omit revoked
items. `NotListed` is **not** live non-revocation, status-list completeness,
a recorded user-consent event, an assertion of real-world identity, Agent
delegation or business authorization. The SDK does not provide a Wallet app,
hosted public callback, selective disclosure, standard W3C status-list
publication or an independently tested third-party Wallet exchange. Older
unchecked and unbound methods remain available for compatibility and must
not be substituted for the strict incident-aware flow.
