# Offline VC1.1 holder-signed presentation CLI

The .NET 10 holder-operated `credential present-vc11-didkey` command
creates a real Ed25519 `vp+jwt` carrying the **unchanged original** W3C
VC Data Model **1.1** `jwt_vc_json` credential. The holder signs only a
presentation: **the wallet does not issue the credential**. This is the
HeroSSID private signed-verifier-request profile, not full OpenID4VP
conformance or proven third-party wallet interoperability.

## Required independent actors and policy

1. The issuer separately signs a real VC1.1 `jwt_vc_json`, such as one
   from [`issue-vc11-didkey`](cli-vc11-didkey-issuer-issue.md).
2. The verifier issues and retains a one-use nonce using its trusted
   `IPresentationChallengeStore` (shared atomic storage across replicas)
   and signs a short-lived request with
   `OfflineSignedPresentationRequest.Create`. The signed request states
   one trusted issuer DID and one exact verifier audience. Its private
   signing seed never goes to the holder.
3. The holder application **independently enrolls** the expected verifier
   `did:key`, audience, issuer `did:key`, issuer-signed name and HTTPS
   credential ID, credential holder DID, type and HTTPS vocabulary. Never
   learn trust pins from the request or from the credential being presented.
4. The holder application must **display every original credential claim**
   to the human holder and obtain informed approval for full disclosure
   **before** passing `--ack-full-disclosure`. This CLI flag only records an
   operator assertion. It is **not proof of a UI, human consent, identity
   vetting or legal/business authority**.

For example, from the repository root, with the private 32-byte holder
Ed25519 seed encoded as **64 hexadecimal characters** and stored in a
separately protected secret source:

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential present-vc11-didkey \
  --request-jwt-file ./signed-verifier-request.jwt \
  --credential-jwt-file ./original-issuer-credential.jwt \
  --trusted-verifier 'did:key:zVERIFIER_PIN' \
  --audience 'decentralized_identifier:did:key:zVERIFIER_PIN' \
  --trusted-issuer 'did:key:zISSUER_PIN' \
  --issuer-name 'Independent Issuer Name Pin' \
  --credential-id 'https://issuer.example/credentials/member-123' \
  --holder 'did:key:zHOLDER_PIN' \
  --credential-type 'MembershipCredential' \
  --context 'https://issuer.example/vocab/membership' \
  --output-jwt-file ./holder-full-disclosure-vp.jwt \
  --ack-full-disclosure < /secure/holder-seed.hex
```

DIDs above are placeholders, not usable keys. Never put a seed in CLI
arguments, shell history, Git, diagnostics or a token passed to another
participant. The CLI rejects missing/nonredirected seed stdin, a missing
acknowledgement, forged or expired verifier requests, foreign issuer policy,
forged/expired original issuer JWT, a wrong holder seed, invalid formats,
oversized inputs, and output-file overwrite. It creates new output only,
with owner read/write mode on Unix; the resulting VP embeds **all** original
credential claims. Handle and transmit the VP as sensitive material.

The **verifier**, not the holder, checks the resulting VP using
`JwtVcJsonPresentation.Check` with its original tenant, audience, nonce,
type, vocabulary, trusted issuer and **verifier-owned atomic nonce store**.
Only a successful verifier-side check consumes the challenge. Retries with
the same nonce must be rejected. A separate hosted service or direct-post
transport is **not** delivered by this command.

## What a successful VP means

An authentic issuer-signed VC1.1 credential, an authentic pinned verifier
request, and a genuine holder Ed25519 signature bound to that verifier's
short-lived nonce were verified before writing the VP. That establishes
cryptographic control of the stated holder key **for this signed response**,
not the holder's real-world identity. The issuer's membership or role
declaration is still only an issuer-signed claim: policy, issuer
authorization, status freshness, user consent, account access and business
authority remain separate decisions. No live revocation or independent
external wallet exchange is tested or implied.
