# Opt-in VCDM 2.0 issuer object

The direct `vc+jwt` signing API has an opt-in issuer **object**
representation from [W3C VC Data Model 2.0 §4.7](https://www.w3.org/TR/vc-data-model-2.0/#issuer).
It signs `"issuer": {"id": "<issuer did:key>", "name": "<descriptive name>"}`
instead of the legacy string issuer. This SDK subset has **exactly two issuer
object properties**: `id` and `name`. Any additional issuer object member
fails closed, including a genuine issuer-signed member whose semantics the
profile has not implemented.

## Example

```csharp
string signed = Vcdm20JoseCredential.CreateWithNamedIssuer(
    issuerDid, "Example Membership Issuer", holderDid,
    "MembershipCredential", subjectContextUri, subjectJson,
    issuerPrivateSeed, validFrom, validUntil);

bool accepted = Vcdm20JoseCredential.TryVerifyNamedIssuer(
    signed, independentlyTrustedIssuerDid, "Example Membership Issuer",
    independentlyExpectedHolderDid, "MembershipCredential",
    independentlyPinnedSubjectContextUri, verificationTime,
    out JsonElement verifiedSubject);
```

Here `subjectJson` is a `JsonElement` object with `id` equal to the
holder DID. The issuer keeps and protects its own Ed25519 seed. The relying
verifier independently enrolls the issuer DID, the **exact** expected
descriptive name, holder DID, credential type and HTTPS context; no trust
is inferred from the submitted JWT. Name comparison is case-sensitive and
ordinal, with no whitespace normalization. Name validation rejects blank,
leading/trailing whitespace, control characters and length above 128
characters.

The signed JWT preserves the bounded VC2 direct-JOSE shape and its genuine
Ed25519 signature, `typ=vc+jwt`, `cty=vc`, explicit validFrom/validUntil,
exact type, context and holder. On any failed verification the returned
subject remains undefined. The existing `Create` and `TryVerify` accept
only the **old string form**; they are not broadened or silently changed.

## Named issuer plus exact signed credential identifier

A separate opt-in profile combines the same **two-member signed issuer object**
with a canonical HTTPS `id` at the **top level** of the signed VC2 payload.
This is the credential identifier, not `credentialSubject.id`; it is a
potential cross-presentation correlation identifier, not an issuer enrollment
record or trust anchor.

```csharp
string signed = Vcdm20JoseCredential.CreateWithNamedIssuerAndId(
    issuerDid, "Example Membership Issuer", holderDid,
    "MembershipCredential", subjectContextUri, subjectJson,
    issuerPrivateSeed, validFrom, validUntil,
    new Uri("https://issuer.example/credentials/member/001"));

bool accepted = Vcdm20JoseCredential.TryVerifyNamedIssuerWithId(
    signed, independentlyTrustedIssuerDid, "Example Membership Issuer",
    independentlyExpectedHolderDid, "MembershipCredential",
    independentlyPinnedSubjectContextUri,
    independentlyPinnedCredentialId, verificationTime,
    out JsonElement verifiedSubject);
```

The verifier independently pins the full HTTPS credential ID as well as the
exact issuer DID, signed descriptive name, holder DID, type, HTTPS context and
verification time. It checks the original Ed25519 JWT signature before
releasing claims. An unrelated genuinely signed credential ID, a mismatched
issuer name, invalid time interval, wrong holder, malformed payload or
tampered signature must fail closed with an undefined subject. The signing
method also verifies its newly produced JWT against the same strict policy
and rejects a seed that does not control the issuer DID.

This **eight-member** direct-VC2 subset is separate from both legacy
string-issuer verification and the previous six/seven-member issuer-object /
signed-ID profiles. Those verifiers deliberately continue to reject the
combined shape instead of silently accepting additional signed members.
The profile does not independently certify VCDM 2.0 JSON-LD semantics or
third-party wallet interoperability. Credential ID and issuer name still
provide no proof of legal identity, holder possession, actual informed consent,
live revocation or business authorization.

## Security and interoperability boundaries

An issuer-signed **name** is a descriptive assertion, not independent proof
of legal name, organisation identity, domain ownership, issuer registration,
real-world holder identity or business authority. A VC signature does not
prove holder private-key control or user consent. This feature alone does
not check revocation, status freshness or Agent delegation, and it does not
introduce selective disclosure or a hosted OpenID4VC exchange.

No independent wallet or external VCDM 2.0/JSON-LD conformance verification
has been performed for this new profile. Its evidence is a local real-key
Ed25519 positive/negative SDK test matrix, plus exact-head repository CI.
Consumers requiring possession must separately use an actual challenge-bound
holder signature and independently verify their membership/status and
authorization policies. The distinct signed-ID and status-aware opt-in
profiles continue to require their own explicit API calls.
