# Opt-in VCDM 2.0 issuer-signed credential identifier

HeroSSID's `Vcdm20JoseCredential.CreateWithId` signs the optional **top-level** `id` of a direct-payload VC Data Model 2.0 JOSE credential with the issuer's Ed25519 key. It remains separate from `credentialSubject.id`, which identifies the subject/holder in the existing restricted profile. `TryVerifyWithId` checks the original signature, independently pinned issuer DID, holder DID, credential type, subject vocabulary, validity interval and exactly seven supported top-level fields before it releases **both** the subject claims and signed identifier.

This is a deliberately restricted SDK profile: identifiers must be canonical absolute HTTPS URLs with no userinfo and at most 2,048 characters. VC Data Model 2.0 §4.4 permits a broader range of URL identifiers; this implementation does **not** claim full format or independent wallet conformance.

```csharp
string signed = Vcdm20JoseCredential.CreateWithId(
    issuerDid, holderDid, "MembershipCredential",
    new Uri("https://issuer.example/contexts/member/v1"),
    credentialSubject, issuerSeed, validFrom, validUntil,
    new Uri("https://issuer.example/credentials/serial-12"));

bool accepted = Vcdm20JoseCredential.TryVerifyWithId(
    signed, independentlyPinnedIssuerDid, expectedHolderDid,
    "MembershipCredential",
    new Uri("https://issuer.example/contexts/member/v1"),
    now, out JsonElement verifiedSubject, out string? signedCredentialId);
```

The **original** six-field `Create` and `TryVerify` behavior is unchanged. The old `TryVerify` rejects a seven-field `id`-bearing credential rather than silently ignoring a signed field. Conversely, `TryVerifyWithId` requires an identifier and rejects a legacy six-field credential. Malformed `id`, unrecognized policy fields, signature changes, wrong issuer/holder or expired credentials fail closed, leaving both outputs empty.

The identifier is an issuer assertion, **not** a verified URL, trusted registry record, bearer capability, automatic revocation or authorization handle. HeroSSID never dereferences it. Publicly reusable identifiers can correlate presentations; choose an identifier only when the product's privacy policy explicitly needs it. An actual Wallet still needs holder-key proof and meaningful consent; relying parties must enforce issuer enrollment, issuer status/revocation, credential scope and business authorization separately.

Standards references: [W3C Verifiable Credentials Data Model v2.0, Identifiers](https://www.w3.org/TR/vc-data-model-2.0/#identifiers), [Securing Verifiable Credentials using JOSE and COSE, JOSE](https://www.w3.org/TR/vc-jose-cose/#with-jose). There is no third-party wallet interop result, JSON-LD expansion or production certification.
