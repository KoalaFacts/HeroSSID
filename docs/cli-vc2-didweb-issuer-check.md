# Verify a directly signed VC2 JWT from a pinned did:web issuer

An independent relying party can use the .NET 10 CLI to verify an **original,
unchanged direct VCDM 2.0 / VC-JOSE-COSE `vc+jwt`** that an organisation
signed with its own Ed25519 `did:web` assertion key. This is a deliberately
limited, offline issuer-authenticity check, **not** OpenID4VP exchange or
independent VC/JWT conformance certification.

The relying party must independently enroll the restricted `did:web` issuer
identifier, its exact `#key-1` or `#key-2` assertion method, the matching
**raw 32-byte Ed25519 public key**, descriptive signed issuer name, signed
HTTPS VC ID, expected holder DID, credential type and HTTPS vocabulary
**before** processing the JWT. The JWT `kid` is checked against that pin;
the JWT or a DID URL cannot enroll, rotate or substitute a trusted key.

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc2-didweb-issuer \
  --jwt-file ./original-direct-vc2.jwt \
  --trusted-issuer 'did:web:issuer.example:members' \
  --verification-method 'did:web:issuer.example:members#key-1' \
  --public-key-hex 'REPLACE_WITH_64_HEX_CHARACTERS_OF_ENROLLED_ED25519_PUBLIC_KEY' \
  --issuer-name 'Example Membership Issuer' \
  --credential-id 'https://issuer.example/credentials/member/1234' \
  --holder 'did:key:z6Mk...' \
  --credential-type MembershipCredential \
  --context 'https://issuer.example/vocab/membership/v1'
```

This command is a template, **not** a working credential or real public key.
The `--public-key-hex` value is the separately verified public key, never a
private signing seed, did:key multicodec, or JWK. Do not paste private keys.
Rotated `#key-2` must be enrolled through the relying party's own trusted
policy: it is not promoted automatically from a JWT or DID document.

Exit 0 means the original compact JWT's Ed25519 signature, **exact JOSE
header `typ=vc+jwt`, `cty=vc` and pinned `kid`**, direct VC2 shape,
exact issuer object name and ID, holder, type, HTTPS `@context`, and
validity checks succeeded. Incorrect/expired/replaced claims, method, key
or metadata, invalid UTF-8, or an original JWT file above 65,536 bytes fail
closed with a nonzero exit status. The CLI does **not** print the JWT or
credential subject. The signed descriptive issuer name does not establish
the organisation's legal identity.

The underlying SDK entry is
`Vcdm20JoseCredential.TryVerifyPinnedDidWebIssuerNameAndId`, which returns
a verified subject only on total success; existing `did:key` verification
remains separate. The positive test uses original genuine Ed25519-signed
direct VC2 JWTs for both `#key-1` and `#key-2`, with forgery, incorrect
pins and expired inputs rejected.

**Limitations:** no DNS/HTTPS domain ownership proof, DID document
resolution, issuer enrollment, issuer private-key management, credential
status/revocation check, recipient `aud` binding, holder private-key proof,
consent UI, real-person/organisation identity vetting, Agent delegation,
current membership or business authorization. A real issuer signature
only proves the enrolled key signed that statement. This does not establish
third-party Wallet interoperability or full JSON-LD processing.

See [VC2 did:key issuer CLI](cli-vc2-jose-issuer-check.md),
[VC1.1 did:web issuer CLI](cli-vc11-didweb-issuer-check.md),
[trust boundaries](VISION.md) and the [capability inventory](../README.md).
