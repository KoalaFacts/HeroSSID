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

## Opt-in combined live publication + one-use signer proof (#key-1)

`DidWebPinnedPublishedKeyControlVerifier` is an **additional admission option** for the *unrotated, exact single-key* `did:web` document profile. It combines the formerly separate checks into one fail-closed entry point: (1) a canonical bounded HTTPS GET must match the **independently operator-pinned** `did:web` and `#key-1` Ed25519 public key; (2) the independently operated signer must produce a real Ed25519 signature over the verifier-issued challenge; (3) that exact nonce is atomically consumed only after both checks pass.

```csharp
// Application has already approved DID, public key and verifier audience;
// externalSigner is separate from the verifier in a real deployment.
using Key externalSigner = Key.Create(SignatureAlgorithm.Ed25519);
byte[] operatorApprovedPin = externalSigner.PublicKey.Export(KeyBlobFormat.RawPublicKey);
var admission = new DidWebPinnedPublishedKeyControlVerifier(
    "did:web:issuer.example.org",
    new Uri("https://verifier.example.org/key-check"),
    operatorApprovedPin, TimeProvider.System, capacity: 128);

DidWebPinnedKeyControlChallenge offered = admission.Issue();
byte[] externallySigned = SignatureAlgorithm.Ed25519.Sign(
    externalSigner, offered.GetSigningInput());

// Succeeds only when the operator independently publishes exactly this
// one-key document over valid HTTPS AND the key-holder signed this nonce.
bool admitted = await admission.TryVerifyAndConsumeWithIsolatedTransportAsync(
    offered.GetNonce(), externallySigned);
```

The code above is an **illustrative single-process setup**, not a live example-domain endpoint. The issuer must publish its own exact DID document first. For deterministic tests without a network, inject a credential-free, **non-redirecting** `HttpClient` into `TryVerifyAndConsumeAsync`; those tests do not establish third-party interoperability. The isolated transport should be the deployment default because injected handlers cannot be inspected for redirect/proxy/credential behavior.

An invalid HTTP document, unavailable host, stale/substituted key, wrong signature or replay fails; an HTTP failure **does not burn a valid pending nonce**, allowing a later retry before its hard expiry. The remote fetch happens before signature checking, so authenticate and rate-limit callers and control network egress. Concurrent successful responses remain at most one per verifier instance; neither a restart nor multiple replicas share the in-memory replay barrier. **This combined profile is only for `#key-1` single-key publication**, not `#key-2` overlap/successor retirement. A failed or successful result must not itself alter issuer trust or authorize business/Agent actions.

## Successor-only retirement admission and #key-2 signer proof

`DidWebPinnedRetiredKeyControlVerifier` is an opt-in **single-process** admission for an operator that has independently preapproved a `did:web` DID, the **distinct old and successor** Ed25519 public keys, and its own HTTPS verifier audience. It checks the original canonical HTTPS publication URI for an exact **successor-only** DID document retaining `#key-2` with no `#key-1`, extra key, authentication or assertion; independently verifies the real successor's Ed25519 signature over the verifier-issued one-use nonce; and atomically consumes it only after both checks pass. Old-key signatures, old-only documents, overlap documents, wrong keys, and replays fail. A failed fetch or forged proof does **not** burn an unexpired challenge.

```csharp
// Fixture only: production independently enrolls both public pins and keeps
// the old and successor private keys outside the verifier.
using Key old = Key.Create(SignatureAlgorithm.Ed25519);
using Key successor = Key.Create(SignatureAlgorithm.Ed25519);
var admission = new DidWebPinnedRetiredKeyControlVerifier(
    "did:web:issuer.example.org",
    new Uri("https://verifier.example.org/retirement-admission"),
    old.PublicKey.Export(KeyBlobFormat.RawPublicKey),
    successor.PublicKey.Export(KeyBlobFormat.RawPublicKey),
    TimeProvider.System);
DidWebPinnedKeyControlChallenge challenge = admission.Issue();
byte[] signature = SignatureAlgorithm.Ed25519.Sign(
    successor, challenge.GetSigningInput());
bool accepted = await admission.TryVerifyAndConsumeWithIsolatedTransportAsync(
    challenge.GetNonce(), signature);
```

The example succeeds only after the operator has **actually published** its successor-only DID document at the canonical HTTPS URI and the key holder controls `#key-2`. The [independent-key xUnit cases](../tests/Unit/HeroSSID.DidOperations.Tests/DidWebPinnedRetiredKeyControlVerifierTests.cs) use an injected fake `HttpClient` for deterministic testing; run `dotnet test tests/Unit/HeroSSID.DidOperations.Tests/HeroSSID.DidOperations.Tests.csproj --configuration Release`. These tests do not demonstrate actual public DNS/TLS hosting or third-party wallet interoperability.

Use the built-in isolated, non-redirecting public-IP-only HTTPS transport in applications. Authenticate/rate-limit callers, enforce independent network egress, and keep the verifier instance alive; its nonce store is **not durable or multi-instance**. An exact published document match is point-in-time, not a domain ownership attestation. Valid signature is private-key control evidence, not proof of organisation identity, issuer trust, credential revocation, historical signing authority or Agent/business authorization. Any trust change must be separately decided and audited by the relying party. This is a private HeroSSID challenge format, not a W3C VC proof or complete OpenID4VP exchange.

## Security and operational boundary

- Constructor pins exact DID, method, HTTPS verifier audience and public key. A remote document or proof **cannot override any of those**. The verifier owns the time source, expiry and cryptographically random 32-byte nonce. `#key-1` and `#key-2` are separate pins and must be approved independently.
- A failed signature or mismatched nonce **does not consume** a live challenge. Input nonce bytes are snapshotted before lookup so a concurrently mutated caller buffer cannot substitute a different signed nonce. A successful signature consumes it under the same lock as verification; simultaneous duplicate submissions produce at most one success. Challenge lifetime defaults to two minutes and cannot exceed five minutes; expiration uses both signed UTC times and the verifier-owned monotonic elapsed timer, preventing backward wall-clock changes from extending a challenge. Pending capacity defaults to 1,024 and cannot exceed 4,096.
- The challenge store is **in memory only**. A process restart invalidates all pending challenges. Multiple workers/replicas **must not** independently share this contract as if it were a durable replay barrier: use a shared, atomic challenge store and its own tests before permitting load-balanced production verification. Keep server-side request rate limits, network rules and audit logging.
- A valid Ed25519 signature is a **private-key control proof**, not a DID domain ownership attestation or proof that the DID document was served over an owned HTTPS domain. For publication checks see [the pinned HTTPS document verification guide](did-web-offline-publishing.md#opt-in-pinned-https-get-of-the-published-document), which also does **not** automatically enroll issuer trust.
- No personal identity enrollment, verified organisation membership, wallet UX/consent, VC validity/revocation decision, delegated Agent authority or business permission is provided. Make these decisions separately at the relying-party boundary. This is a **private HeroSSID proof format**, not a W3C VC proof or OpenID4VP exchange.

No database schema, migration, production deployment or package publication is required or implied.
