# Verify an issuer-signed VC2 credential for one recipient with HeroSSID CLI

The .NET 10 `credential verify-vc2-recipient` command checks the **original
issuer-signed, direct VCDM 2.0 / VC-JOSE compact `vc+jwt`** with an opt-in,
single canonical HTTPS RFC 7519 `aud` and signed top-level HTTPS credential
`id`. It is deliberately separate from the audience-free VC2 issuer
verification command. This is a *restricted HeroSSID JSON/JWS profile*,
not general VCDM conformance or third-party Wallet interoperability.

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc2-recipient \
  --jwt-file ./original-recipient-bound-vc2.jwt \
  --trusted-issuer 'did:key:z6Mk...' \
  --holder 'did:key:z6Mk...' \
  --credential-type MembershipCredential \
  --context https://issuer.example/contexts/membership/v2 \
  --credential-id https://issuer.example/credentials/member/42 \
  --audience https://verifier.example/checks/membership
```

**All six trust-policy values** (issuer, holder, credential type, vocabulary
context, exact credential ID and recipient) are configured independently by
the verifier; none is learned from the untrusted JWT. `--audience` is the
receiving service's independently approved HTTPS recipient, not an
issuer-controlled trust discovery endpoint. The two URI pins must be canonical
HTTPS URLs without user information or fragments, at most 2,048 characters.

The verifier checks the real issuer Ed25519 signature and `did:key` signer,
the direct `vc+jwt` header, exactly eight signed payload members (including
`aud` and `id`), strictly expected issuer/holder/type/context/validity,
and an exact single signed recipient and ID. A genuinely issuer-signed VC2
JWT for another recipient **fails** even if every other claim matches.
Audience-free VC2 JWTs, VC1.1 nested JWTs, unsupported extra payload fields,
expired credentials and edited signatures also fail.

A UTF-8 JWT file is bounded to 65,536 bytes and may have a trailing line
ending. **Exit 0** means only that an issuer signed the time-valid statement
for this exact credential ID and verifier-owned recipient. A failed check exits
nonzero; neither outcome echoes the JWT or credential subject claims.

A signed `aud` is a recipient assertion, **not** proof the recipient owns
its HTTPS domain. The command does **not** authenticate the holder's private-key
control, obtain human consent, check live or issuer revocation, establish
real-world identity, confirm current membership, grant Agent business powers
or perform a replay-resistant presentation. Receiving applications must
separately enforce those decisions and their own trusted issuer enrollment.
This CLI does not fetch or expand JSON-LD contexts or perform independent
wallet, OpenID4VP or standards conformance testing.

The issuance-side .NET SDK accepts this profile using
`Vcdm20JoseCredential.CreateForAudienceWithId`; see
[issuer-signed VC2 audience profile](vcdm20-recipient-bound-jwt.md).
The separate [VC2 issuer-only CLI](cli-vc2-jose-issuer-check.md) explicitly
rejects recipient-bound JWTs rather than ignoring signed `aud`.
