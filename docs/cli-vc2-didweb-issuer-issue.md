# Issue a recipient-bound did:web VC2 JWT from the offline CLI

The .NET 10 CLI `credential issue-vc2-didweb-recipient` provides an **operator-invoked** companion to the
[restricted did:web VC2 SDK issuer](vcdm20-didweb-issuer-issuance.md) and
[independent CLI verifier](cli-vc2-didweb-recipient-claim.md).
It genuinely signs one W3C VCDM 2.0 / VC-JOSE-COSE direct `vc+jwt` with
an Ed25519 issuer key. The signed credential is **not** a holder proof,
proof of legal identity, live entitlement, authorization, or independently
confirmed third-party Wallet compatibility.

## Inputs and invocation

The issuer—not a caller presenting an untrusted token—must choose all
parameters. `--subject-file` must contain a bounded UTF-8 JSON object
whose `id` is the **actual** intended holder's `did:key`.
All additional properties must use the issuer's versioned HTTPS subject
vocabulary. Duplicate property names (including nested ones), local
`@context` replacements and malformed JSON are rejected.

The only private seed input is **redirected standard input**, containing
exactly 64 ASCII hexadecimal characters representing the 32-byte Ed25519
raw seed, with at most CRLF/LF at the end. This is deliberately **not**
an argv option, environment variable, JSON property or seed file path.
The command rejects an interactive terminal for seed input, and clears
its temporary raw seed buffers after signing. It cannot attest that an
upstream secret provider is secure. Do not put literal seed bytes in shell
history, logs or a repository; do not use real production keys in examples
or CI.

Provide a protected operator-owned pipe from an approved seed source to:

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential issue-vc2-didweb-recipient \
  --issuer-did did:web:issuer.example:members \
  --verification-method did:web:issuer.example:members#key-1 \
  --public-key-hex PUBLIC_ED25519_KEY_64_HEX \
  --issuer-name "Example Membership Issuer" \
  --credential-id https://issuer.example/credentials/42 \
  --audience https://verifier.example/membership \
  --holder ACTUAL_HOLDER_DID_KEY \
  --credential-type MembershipCredential \
  --context https://issuer.example/vocab/member \
  --subject-file /protected/subject.json \
  --valid-from 2026-11-08T00:00:00.0000000+00:00 \
  --valid-until 2026-11-08T00:10:00.0000000+00:00 \
  --output-jwt-file /protected/credential.jwt
```

The displayed identifiers are placeholders. Substitute approved values and
a current UTC validity interval; do not run this command without securely
piping the seed to standard input. Both dates use .NET round-trip ISO-8601
(`O`) with UTC offset zero; the issued credential must be currently valid.

The output path must **not exist**. The CLI writes the original compact JWT
to a newly created file rather than stdout, and never silently overwrites
an existing credential. On Unix its new file creation mode is owner
read/write only (`0600`); on Windows secure the destination directory and
its ACL before use. Treat output as sensitive personal credential data
and deliver only through an approved holder-controlled channel. A process
crash or file-system failure may require operator inspection and cleanup
of a partial file.

On success the SDK has independently checked the JWT signature with the
**explicit issuer-supplied** public key and strict signed issuer, method,
name, credential ID, holder, type, context, audience and validity. The CLI
accepts only `did:web` `#key-1` or `#key-2` with separately approved
issuer configuration. It does **not** fetch `did.json`, establish domain
ownership, enroll a verifier's trust or operate a key-management service.

The receiving verifier must still independently pin the issuer DID,
assertion method, original issuer public key, descriptive issuer name,
exact ID, audience, holder, type and subject context before inspecting a
claim. For example, use `credential verify-vc2-didweb-recipient-claim` as
documented in the verifier guide; a matching signed
`membership=active` is **not** present-day authorization.

## Tests and limits

The unit suite exercises a real Ed25519 seed through a synthetic in-memory
pipe, independently verifies the produced signed JWT, and rejects mismatched
seeds, incorrect recipient policies, invalid seed input, output overwrite,
and duplicate subject properties. These local tests are **not** third-party
VC JOSE conformance or cross-wallet interoperability tests.

This feature performs no DB migration, external network call, hosted issuer,
hardware-key custody, consent UX, revocation check or deployment.
