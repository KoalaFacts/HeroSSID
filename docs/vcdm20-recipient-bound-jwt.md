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
