# Offline verifier-owned VC1.1 request and one-use presentation check

The .NET 10 CLI now permits a **single-machine verifier** to sign a private
HeroSSID request, persist its own short-lived challenge, and independently
verify one holder-signed VC1.1 `vp+jwt` containing an unchanged, genuinely
issuer-signed `jwt_vc_json`. The wallet **only holds and presents**; issuer
provenance, holder key control and verifier challenge ownership are different
cryptographic checks.

This is **not** a hosted service, an OpenID4VP-compliant exchange, a third-party
wallet interoperability test, selective disclosure, a real identity check, a
revocation check, consent evidence, or business authorization.

## Preconditions and trust ownership

- The verifier chooses and separately pins its own Ed25519 `did:key`, a
  nonempty tenant GUID, the exact audience, an approved issuer `did:key`,
  credential type and HTTPS vocabulary. Never derive policy from a JWT or VP.
- Operate inside one owner-controlled directory on a **local filesystem**
  providing atomic same-directory rename. Use one host and trusted local users.
  Do not use an NFS/network share, sync folder, shared volume, restored backup
  of spent challenges, or this offline profile as a multi-replica service.
  Shared verifiers must use a durable transactional
  `IPresentationChallengeStore`, such as the separate PostgreSQL integration.
- Give the verifier its own independently protected 32-byte Ed25519 signing
  seed encoded as 64 hex characters. Redirect it via **stdin**, never through
  command arguments, a shell history, a repository or the presented VP.
  The output request and the challenge state are created new with Unix
  owner-only read/write permissions; they are never overwritten.
- The issuing organisation, wallet holder and verifier must have **different**
  private signing keys. The holder separately reviews **all** original
  credential claims and approves full disclosure before invoking the holder
  CLI. A CLI acknowledgement flag is not evidence that approval occurred.

## Operate the three-party flow

From the repository root, substitute real, independently enrolled DID pins,
GUID and file paths (the values below are illustrative placeholders).

**1. Verifier issues and retains a request:**

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential request-vc11-didkey \
  --verifier-did 'did:key:zVERIFIER_PIN' \
  --tenant-id '52bb1e4a-f419-4e13-9e12-a539bed81f02' \
  --audience 'decentralized_identifier:did:key:zVERIFIER_PIN' \
  --trusted-issuer 'did:key:zISSUER_PIN' \
  --credential-type 'MembershipCredential' \
  --context 'https://issuer.example/vocab/membership' \
  --output-request-file ./signed-request.jwt \
  --session-file ./private-challenge.json \
  --lifetime-seconds 120 < /secure/verifier-ed25519-seed.hex
```

Only share `signed-request.jwt` with the holder. Keep
`private-challenge.json` private to the verifier. The request includes one
cryptographically random nonce, the verifier's genuine signature, an issuer
pin, audience and expiry. Type/context are verifier-owned policy in its
protected state; the holder must pin them independently.

**2. Holder creates a presentation** using the separate
[`present-vc11-didkey`](cli-vc11-didkey-holder-presentation.md) command,
an authentic issuer-signed VC1.1 JWT, independent verifier/issuer pins,
and the holder's **own** private signing seed. The full disclosure VP contains
the unchanged original issuer-signed JWT.

**3. Verifier authenticates and atomically consumes its own challenge:**

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc11-didkey-vp \
  --verifier-did 'did:key:zVERIFIER_PIN' \
  --tenant-id '52bb1e4a-f419-4e13-9e12-a539bed81f02' \
  --audience 'decentralized_identifier:did:key:zVERIFIER_PIN' \
  --trusted-issuer 'did:key:zISSUER_PIN' \
  --credential-type 'MembershipCredential' \
  --context 'https://issuer.example/vocab/membership' \
  --request-jwt-file ./signed-request.jwt \
  --session-file ./private-challenge.json \
  --presentation-jwt-file ./holder-vp.jwt
```

The verifier rejects changed request/presentation signatures, unrelated
issuer/verifier/type/context policy, expired or missing state, and repeated
presentations. It checks the genuine Ed25519 signatures of **both** the issuer
and the distinct holder, and the verifier's authentically signed request,
audience and nonce. After successful verification, the state file is
**atomically renamed** to `private-challenge.json.used`; only one local
verifier process can succeed. Keep the spent marker until the original
request expires and retain the audit trail required by your application.
Never restore an old unspent state file or recycle the same file path.

A failed check emits no credential claims and does not consume a valid
challenge. A success emits **no credential claims**, either: consuming the
one-use challenge proves a specific cryptographic response, not current
membership, consent, physical/legal identity or business permission. The
caller is responsible for separately evaluating issuer authority, current
status, applicable identity enrolment and business-level authorization.
