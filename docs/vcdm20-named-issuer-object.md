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
