# Verify an externally enrolled did:web VC1.1 issuer (CLI)

The .NET 10 CLI can verify the **original**, unchanged VC Data Model 1.1
`jwt_vc_json` JWT signed by an organisation's `did:web` Ed25519 assertion key.
The verifier must independently enroll the issuer DID, the exact
`#key-1` or `#key-2` verification method, **raw 32-byte Ed25519 public key**,
descriptive issuer name, HTTPS credential ID, expected holder DID, credential
type and HTTPS subject vocabulary **before** inspecting the credential.
Nothing is trusted merely because it appears in a signed JWT or DID URL.

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc11-didweb-issuer \
  --jwt-file ./original-issued-vc11.jwt \
  --trusted-issuer 'did:web:issuer.example:members' \
  --verification-method 'did:web:issuer.example:members#key-1' \
  --public-key-hex 'REPLACE_WITH_64_HEX_CHARACTERS_OF_ENROLLED_ED25519_PUBLIC_KEY' \
  --issuer-name 'Example Membership Issuer' \
  --credential-id 'https://issuer.example/credentials/1234' \
  --holder 'did:key:z6Mk...' \
  --credential-type MembershipCredential \
  --context 'https://issuer.example/contexts/membership/v1'
```

The sample is a **template**, not a valid public key or credential; substitute
your own independently enrolled, canonical policy. `--public-key-hex` is
**not** a private seed, `did:key` multicodec/base58 string or a public JWK:
pass only 64 hexadecimal characters encoding the raw Ed25519 public key.
Never pass a private key to this command.

Success (exit code 0) means the library checked the actual original JWT's
Ed25519 signature and **all** independently pinned policy fields and
validity. Invalid, tampered, expired, wrong-key, wrong-method, wrong-holder,
wrong-context, wrong-issuer-name or wrong-ID credentials, missing pins and
invalid or oversize files exit nonzero. Neither success nor failure prints
claims or the original token. The bounded local JWT file read allows a
trailing newline and rejects files larger than 65,536 bytes.

This command does **not** fetch a DID document, discover issuer keys, check
domain ownership, prove that the descriptive name corresponds to a legal
organisation, establish that the holder controls its private key, collect
holder consent, check revocation, demonstrate current membership/Agent
authority or validate business authorization. A successful issuer-signed
claim is not a permission grant. Rotated `#key-2` is accepted **only** after
separately pre-enrolling that exact method and public key; it is never
auto-promoted from `#key-1`.

The restricted `did:web` form mirrors the SDK's
`JwtVcJsonPinnedDidWebIssuerVerifier.TryVerifyWithPinnedIssuerNameAndId`
contract. The original did:key-only `verify-issuer` and direct VC2
`verify-vc2-issuer` commands remain separate, and the command is not
a hosted OpenID4VP transaction, full JSON-LD conformance validation,
external independent-wallet compatibility test or production certification.

See [VC1.1 issuer verification](cli-vc11-issuer-check.md),
[did:web issuer key enrollment](jwt-vc-json-pinned-didweb-issuer.md),
[README](../README.md) and [vision/release gates](VISION.md).
