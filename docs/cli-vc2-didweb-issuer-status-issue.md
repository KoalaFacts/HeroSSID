# Issue offline pinned did:web VC2 revocation status from the CLI

The .NET 10 `credential issue-vc2-didweb-status` command is the **issuer-operated**
companion to [offline status verification](cli-vc2-didweb-issuer-status.md).
It signs the existing **private HeroSSID** 60-second
`herossid-vc2-revocation-snapshot+jwt` using the original issuer's
Ed25519 key. It does not issue a W3C Bitstring Status List or establish
independent Wallet interoperability.

## Issuer prerequisites

The issuer controls and securely maintains an **authoritative, complete**
set of its revoked, unchanged original recipient-bound VC2 `vc+jwt`
credentials. Record the UTC observation instant **before** reading that
inventory, not after. The input is a newline-separated text file containing
the exact compact original revoked JWT on each line, with no prefixes,
quotes, JSON, added whitespace or altered bytes; an empty file explicitly
claims there are currently no revoked JWTs. The CLI accepts at most 256
entries, each at most 65,536 characters and the entire input at most
4 MiB. Every entry must authenticate under the **same** enrolled issuer
DID, assertion method and Ed25519 public key. This list is not downloaded
or inferred from the holder's Wallet.

Supply a protected operator-controlled **redirected stdin** stream
containing exactly the issuer's 32-byte private Ed25519 seed represented
by 64 ASCII hexadecimal characters (optional trailing LF/CRLF). The CLI
does **not** take seeds from argv, environment variables or a file path.
Avoid putting private keys in shell history, pipelines logged by CI, or
a source repository. Run with securely provisioned test keys initially.

For example, with an approved secret provider supplying stdin (not
shown or stored in this example):

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential issue-vc2-didweb-status \
  --issuer-did did:web:issuer.example:members \
  --verification-method did:web:issuer.example:members#key-1 \
  --public-key-hex PUBLIC_ED25519_KEY_64_HEX \
  --issuer-name "Example Membership Issuer" \
  --revoked-jwt-list-file /protected/revoked-original-jwts.txt \
  --observed-at 2026-11-08T00:00:00.0000000+00:00 \
  --output-jwt-file /protected/issuer-status.jwt
```

These identifiers and timestamp are **illustrative**, not reusable
credentials or valid current observation times. Use the real, independently
enrolled issuer configuration and current UTC round-trip (`O`) timestamp
within 60 seconds of the observation. Both `#key-1` and `#key-2` are
supported; arbitrary methods, wrong seed, mismatched public key,
forged/foreign JWT, expired observation, malformed list and existing
output all fail closed.

The output JWT is written only to a **new file** with Unix `0600`
creation mode and no overwrite; protect the destination directory/ACL
on Windows and check for a partial artifact after abrupt process failure.
Success reports the path operation but not the signed contents, private
seed, revoked inventory or credential subjects. No network or database
lookup is performed.

The relying verifier must independently enroll and pin the issuer DID,
method, public key, signed descriptive issuer name, exact credential ID,
HTTPS recipient, subject DID, VC type, context and its **own** minimum
acceptable observation time. Use
[`credential verify-vc2-didweb-status`](cli-vc2-didweb-issuer-status.md)
to test the *unchanged original* VC2 JWT and new signed status. A
`SignedNotListed` result is only a signature-authenticated, time-bounded
statement about the issuer's supplied list; the CLI cannot prove that
the inventory was complete or that revocation has not changed since.

Neither issuing nor checking the status proves the holder controls a
private key, gave meaningful disclosure consent, is a legally identified
person or organisation, or has business/Agent authority. It does not
deploy an issuer service, publish a package, rotate keys, or operate
production databases.
