# Verify a signed membership claim from a pinned did:web issuer

The .NET 10 CLI can make an **offline, issuer-assertion-only** admission
decision using the original direct W3C VCDM 2.0 / VC-JOSE-COSE `vc+jwt`.
The relying party independently enrolls the issuer DID, exact Ed25519 public
key and `#key-1` or `#key-2` assertion method, issuer-signed name, original
credential ID, expected holder DID, credential type and subject context,
**its own HTTPS recipient**, and an exact required subject string property
and value. Nothing is learned as a trust anchor from the JWT itself.

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc2-didweb-recipient-claim \
  --jwt-file ./original-direct-vc2.jwt \
  --trusted-issuer 'did:web:issuer.example:members' \
  --verification-method 'did:web:issuer.example:members#key-1' \
  --public-key-hex 'REPLACE_WITH_64_HEX_CHARACTERS_OF_PREAPPROVED_PUBLIC_KEY' \
  --issuer-name 'Example Membership Issuer' \
  --credential-id 'https://issuer.example/credentials/member/1234' \
  --audience 'https://verifier.example/membership/admission' \
  --holder 'did:key:z6Mk...' \
  --credential-type MembershipCredential \
  --context 'https://issuer.example/vocab/membership/v1' \
  --claim-name membership \
  --claim-value active
```

The example is a **template**, not an actually issued credential. The
`--public-key-hex` value is a separately approved **public** key (never
paste the private signing seed). The relying party must register all these
exact pins *before* processing any presented JWT. A signed issuer name,
JWT `kid`, DID URL, or subject claim cannot register or rotate trust.

Exit **0** means the genuine original Ed25519 issuer signature, pinned
`did:web` assertion key and method, `vc+jwt` header, VCDM 2.0 shape,
time window, expected issuer name, original signed HTTPS credential ID,
expected holder DID, type/context, **signed HTTPS recipient**, and exactly
one top-level string claim were validated against independent policy.

A nonzero exit means at least one check failed. Wrong issuer/public key,
wrong/absent recipient, foreign holder, changed signed metadata, expired
credential, unsigned/forged claim, missing/numeric/nested/duplicate subject
property, reserved `id`, empty/unbounded unsafe claim or oversize JWT
file all fail closed. The CLI never prints the JWT or subject claim values.
The original file is bounded to 65,536 bytes and read as strict UTF-8.
Only one exact required claim is supported here; it is not a general JSON
policy interpreter.

The implementation uses
`Vcdm20JoseCredential.TryVerifyPinnedDidWebIssuerForAudienceWithId`,
then compares a separately supplied bounded string claim only after
successful issuer authentication. Both the underlying SDK and the CLI are
real .NET implementations; they do not prove that an independent wallet
can consume or produce this format.

**Limits:** A valid issuer-signed `membership=active` is **only the
issuer's statement at issuance**. It proves neither current membership
nor completeness/freshness of revocation, nor holder private-key control,
consent, legal identity, organisation authority, Agent delegation or
business authorization. The relying application must decide those
independently and avoid treating exit 0 as unconditional access.
No DID document resolution/domain ownership certification, live
status, hosted exchange or independent wallet-interoperability claim.

See [issuer and recipient pins](cli-vc2-didweb-issuer-check.md),
[vision and boundaries](VISION.md), and
[VC2 recipient claim for did:key](cli-vc2-recipient-claim-check.md).
