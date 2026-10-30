# Issuer did:key successor attestation (opt-in, private SDK profile)

An issuer's `did:key` is derived from one immutable Ed25519 public key.
Replacing its private seed **cannot rotate the same DID**. HeroSSID now
provides `IssuerKeySuccessorAttestation` for one narrowly scoped transition:
an independently configured relying party can check that **both** a previously
trusted issuer key and a proposed successor key signed **the exact same**
five-minute, verifier-audience-and-nonce-bound statement.

This is not W3C DID key rotation, a DID method update, an OpenID protocol,
an automatic trust-list change, reality-based identity verification, agent
delegation, or recovery when the previous signing seed is already lost.

## Calling it

The verifier must authenticate the issuer's previous DID from its **own**
trust policy and issue a fresh unpredictable 20–128-character base64url-style
nonce with an exact HTTPS audience. Both the previous and successor key
controllers must consent to signing the exact transition. Each signer keeps
its own 32-byte Ed25519 seed; the sample shows both in one process only for
clarity. HeroSSID does not persist, export or escrow the seeds.

```csharp
using HeroSSID.Credentials.Vcdm20;

Uri verifier = new("https://verifier.example/issuer-successor");
string nonce = freshVerifierGeneratedNonce;
string artifact = IssuerKeySuccessorAttestation.Create(
    previouslyTrustedIssuerDid, proposedSuccessorDid,
    oldIssuerSeed, newIssuerSeed, verifier, nonce, TimeProvider.System);

// On the independently configured verifier:
if (IssuerKeySuccessorAttestation.TryVerify(
    artifact, previouslyTrustedIssuerDid, verifier, nonce,
    DateTimeOffset.UtcNow, out string successor))
{
    // Both keys controlled the same statement; NOT trust-list promotion.
    // Atomically consume your nonce, investigate possible old-key compromise,
    // require your own issuer-enrollment policy, then decide whether to trust successor.
}
```

The bounded JSON envelope has `previousSignature` and `successorSignature`
compact Ed25519 JWS values. Each protected header has `alg: EdDSA`,
`typ: herossid-issuer-successor+jwt`, and the corresponding self-certifying
issuer `did:key` verification-method `kid`. Both JWS payload bytes must
match and include exactly version 1, `previousIssuer`, `successorIssuer`,
`aud`, `nonce`, numeric `iat` and numeric `exp`.
The identifiers must differ; the expiration is at most 300 seconds after
issuance, and verifier-supplied audience/nonce must match exactly.

## Critical trust boundary

A successful check proves only possession of two signing keys **at signing
time**, with an assertion relating the two DIDs. It cannot establish that
either human or organisation is who they say they are, that the original
key was not compromised, that issuer registration or business authorization
has been transferred, or that any credential issued by the successor is
trusted. An attacker controlling the previous key can sign a fake successor
transition; requiring the successor signature does **not** prevent this.
Issuer trust policies MUST therefore review changes and independently
authenticate critical ownership changes. Because the proof itself has no
shared state, the verifier MUST atomically consume its own nonce if it treats
the transition as a one-time admission operation. Rechecking the same signed
artifact is not a proof of a new authorization event.

The library does not change stored DID records, credential signatures,
revocation snapshots, database schemas or REST issuer ownership. Existing
credentials must continue to be validated with the original issuer's key;
this artifact is not a credential re-signature or revocation notice.
