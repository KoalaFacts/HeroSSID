# One-use pinned `did:web` Ed25519 key-control challenge (.NET 10 SDK)

This is an **opt-in, process-local verifier** for a caller that has already **independently enrolled** a `did:web` identifier, its `#key-1` or `#key-2` verification method, a 32-byte raw Ed25519 public key and its own HTTPS verifier audience. A valid result says **only** that the responder possessed the matching private key for this exact challenge. It does not prove control of the DNS domain, legal identity, trusted VC issuance, consent or business/Agent authorization.

The earlier `DidWebPinnedKeyControlProof.CreateSigningInput` and `TryVerify` APIs check signature bytes but **do not** consume a challenge. The new `DidWebPinnedKeyControlChallengeVerifier` provides the missing bounded nonce lifecycle for a single verifier process.

## Runnable test-style example

The following *single-process test fixture* intentionally creates the signer inline. **Real deployments keep the signing key at an independent signer boundary**, and derive the pinned public key from separately approved enrollment, not from a self-asserted response or a remote DID document.

```csharp
using HeroSSID.DidOperations.DidMethods;
using NSec.Cryptography;

using Key externalSigner = Key.Create(SignatureAlgorithm.Ed25519);
byte[] independentlyPinnedPublicKey =
    externalSigner.PublicKey.Export(KeyBlobFormat.RawPublicKey);

var verifier = new DidWebPinnedKeyControlChallengeVerifier(
    "did:web:issuer.example.org",
    "#key-2",
    new Uri("https://verifier.example.org/check-key"),
    independentlyPinnedPublicKey,
    TimeProvider.System,
    capacity: 128,
    lifetime: TimeSpan.FromMinutes(2));

// The verifier sends the challenge's signing bytes to the independent signer.
DidWebPinnedKeyControlChallenge challenge = verifier.Issue();
byte[] signature = SignatureAlgorithm.Ed25519.Sign(
    externalSigner, challenge.GetSigningInput());

// On return, accept at most once, and only for this verifier's original nonce.
bool accepted = verifier.TryVerifyAndConsume(challenge.GetNonce(), signature);
bool rejectedReplay = !verifier.TryVerifyAndConsume(challenge.GetNonce(), signature);
```

Use the real [xUnit scenarios](../tests/Unit/HeroSSID.DidOperations.Tests/DidWebPinnedKeyControlChallengeVerifierTests.cs) as a reproducible entry point. In the repository, run:

```sh
dotnet test tests/Unit/HeroSSID.DidOperations.Tests/HeroSSID.DidOperations.Tests.csproj --configuration Release
```

The tests exercise genuine independent Ed25519 keys, a forged signature, a changed nonce, replay under concurrency, expiry, bounded capacity, defensive-copy outputs and different verifier instances. These are local tests, **not** external wallet interoperability or third-party conformance evidence.

## Security and operational boundary

- Constructor pins exact DID, method, HTTPS verifier audience and public key. A remote document or proof **cannot override any of those**. The verifier owns the time source, expiry and cryptographically random 32-byte nonce. `#key-1` and `#key-2` are separate pins and must be approved independently.
- A failed signature or mismatched nonce **does not consume** a live challenge. Input nonce bytes are snapshotted before lookup so a concurrently mutated caller buffer cannot substitute a different signed nonce. A successful signature consumes it under the same lock as verification; simultaneous duplicate submissions produce at most one success. Challenge lifetime defaults to two minutes and cannot exceed five minutes; expiration uses both signed UTC times and the verifier-owned monotonic elapsed timer, preventing backward wall-clock changes from extending a challenge. Pending capacity defaults to 1,024 and cannot exceed 4,096.
- The challenge store is **in memory only**. A process restart invalidates all pending challenges. Multiple workers/replicas **must not** independently share this contract as if it were a durable replay barrier: use a shared, atomic challenge store and its own tests before permitting load-balanced production verification. Keep server-side request rate limits, network rules and audit logging.
- A valid Ed25519 signature is a **private-key control proof**, not a DID domain ownership attestation or proof that the DID document was served over an owned HTTPS domain. For publication checks see [the pinned HTTPS document verification guide](did-web-offline-publishing.md#opt-in-pinned-https-get-of-the-published-document), which also does **not** automatically enroll issuer trust.
- No personal identity enrollment, verified organisation membership, wallet UX/consent, VC validity/revocation decision, delegated Agent authority or business permission is provided. Make these decisions separately at the relying-party boundary. This is a **private HeroSSID proof format**, not a W3C VC proof or OpenID4VP exchange.

No database schema, migration, production deployment or package publication is required or implied.
