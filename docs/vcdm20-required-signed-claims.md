# Verifier-owned exact signed subject claim policy (VC Data Model 2.0 / JOSE)

This **opt-in .NET 10 SDK** entry point addresses a narrow relying-party need: accept an organisation's signed membership credential only when the *independently configured* expected **top-level JSON string claims** are present with exact values. The verifier must not treat an authentic but `inactive` membership as the required `active` one.

## Entry point

`Vcdm20TrustedIssuerVerifier.TryVerifyWithIdAndRequiredClaims` accepts:

- An original, compact, directly signed VC Data Model 2.0 `vc+jwt` produced by `Vcdm20JoseCredential.CreateWithId`.
- An independently enrolled 1–16 element set of issuer `did:key` values (current or historical), the expected holder DID, credential type, HTTPS context URI and exact signed **top-level credential ID** URI.
- A verifier-owned `IReadOnlyDictionary<string,string>` containing 1–16 exact required claim/value pairs, and the verification instant.

A typical caller, having obtained its trusted values **out of band**, can use:

```csharp
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;

bool verified = Vcdm20TrustedIssuerVerifier.TryVerifyWithIdAndRequiredClaims(
    issuerSignedJwt: credentialJwt,
    trustedIssuerDids: enrolledIssuerDids,
    expectedHolderDid: expectedMemberDid,
    expectedCredentialType: "MembershipCredential",
    expectedSubjectContextUri: new Uri("https://issuer.example/context/membership/v1"),
    expectedCredentialId: expectedEnrollmentCredentialId,
    requiredSubjectClaims: new Dictionary<string, string>
    {
        ["membership"] = "active",
        ["tier"] = "standard"
    },
    now: DateTimeOffset.UtcNow,
    out string verifiedIssuerDid,
    out JsonElement verifiedSubject);
```

Caller variables `credentialJwt`, `enrolledIssuerDids`, `expectedMemberDid` and `expectedEnrollmentCredentialId` are **application-supplied values**. Do not derive expected policy, issuer pins, or credential ID from the unverified JWT. The example context URI is illustrative, not a registered vocabulary or a claim that the verifier dereferences and validates the remote context.

The routine validates the issuer's real Ed25519 signature, pinned DID, holder, type, context, dates and exact signed top-level credential ID using the existing verifier. Only then does it inspect the authenticated `credentialSubject`. All requirements must match **ordinal, case-sensitive, top-level JSON string properties**. Policy names must be 1–64 characters, start with an ASCII letter, contain only ASCII letters/digits/`_`/`-`, be unique under ordinal matching, and cannot be `id`. Expected values must contain non-whitespace text and be no longer than 256 characters. Empty, too-large, malformed or duplicate policies fail closed. No subject or issuer is returned on *any* failure.

No nested JSON value, alternate spelling, JSON boolean, numeric value or missing property is accepted as a string claim. Signature success is necessary but not sufficient. The holder's `credentialSubject.id` is verified separately against the caller's expected holder DID and cannot be used as a required policy field.

## Trust and interoperability limits

This API enforces literal JSON string equality over a specifically pinned signed profile. It **does not perform JSON-LD expansion** or independent validation of context vocabulary semantics; the issuer and verifier must agree on a versioned vocabulary outside this function. It is not a generalized VC semantic or authorization engine.

This does **not** establish that the holder currently controls the subject private key, supplied informed consent, owns a domain, has an independently verified real-world identity, or possesses current membership/role authority. Expiry is not revocation. A separate relying-party application must enforce its own revocation freshness, verified holder presentation, consent and authorization policy. No independent Wallet interoperability, official standards-conformance certification, production identity attestation or external security audit is claimed.

The legacy `TryVerify`, direct `TryVerifyWithId` and earlier JWT verification APIs remain separate; this additional policy is explicitly opt-in.

See [explicit historical/current issuer allowlists](vcdm20-explicit-issuer-trust.md), [signed credential ID](vcdm20-issuer-signed-id.md), [VISION](VISION.md) and [README capability boundaries](../README.md#implemented-capabilities-and-boundaries).
