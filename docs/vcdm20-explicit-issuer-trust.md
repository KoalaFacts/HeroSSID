# VC2 issuer trust across a controlled did:key transition

HeroSSID's opt-in `Vcdm20TrustedIssuerVerifier.TryVerify` allows a verifier
to accept older **direct VC Data Model 2.0 JOSE** issuer signatures alongside
separately approved replacement-issuer credentials. It does not rotate a
`did:key`, re-sign old credentials, or automatically migrate a trust list.

## Verifier entry point

The verifier independently enrolls 1–16 canonical Ed25519 `did:key` values
that it already authorizes to attest the requested credential type and
versioned HTTPS vocabulary. The list is never inferred from a JWT `issuer`,
JOSE `kid`, holder, Wallet or successor proof.

```csharp
using HeroSSID.Credentials.Vcdm20;

string[] independentlyEnrolledIssuers = [previousIssuerDid, successorIssuerDid];
bool authenticated = Vcdm20TrustedIssuerVerifier.TryVerify(
    originalDirectVc2Jwt, independentlyEnrolledIssuers, holderDid,
    "MembershipCredential",
    new Uri("https://issuer.example/contexts/membership/v1"),
    DateTimeOffset.UtcNow,
    out string actualVerifiedIssuerDid, out var verifiedSubject);

if (authenticated)
{
    // Only now inspect the actual cryptographically verified signer/claims;
    // decide revocation, issuer status and business authorization separately.
}
```

The method snapshots, validates and de-duplicates the **entire** allowlist
before validating a credential. Empty, duplicated, malformed and oversized
policies fail without returning a signer or subject. For each independently
trusted DID, it uses the established genuine Ed25519 direct VC2 verification
path, including pinned holder, credential type, context, strict JWT shape,
issuer binding, and lifetime. Forgery, altered tokens, wrong issuer, wrong
type/context/holder and expiration fail closed. Removing the previous issuer
from verifier policy immediately stops accepting the old-key credential; that
is a local trust decision, not cryptographic revocation.

See [the separately signed issuer successor proof](issuer-key-successor-profile.md).
It can inform manual enrollment, but it does **not** automatically grant trust.
A compromised previous seed can sign a fraudulent successor statement.
Lost previous keys cannot produce two-key continuity evidence; recovery
requires the relying party's independent out-of-band enrollment policy.

This is issuer-signature verification, **not** holder-key control, Wallet
consent, live or complete revocation, real-world identity, delegation,
business authorization, W3C JSON-LD semantic conformance, full OpenID4VP,
or tested third-party Wallet interoperability. No key escrow, database
schema, migration, deployment or trust-store write is performed.
