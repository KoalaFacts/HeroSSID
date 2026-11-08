# Offline did:web VC2 original JWT + signed issuer status CLI

The .NET 10 `HeroSSID.Cli` command `credential verify-vc2-didweb-status`
checks **two separate original JWTs**: the unchanged issuer-signed VCDM 2.0
`vc+jwt` and the issuer's independent, **private HeroSSID-format**
`herossid-vc2-revocation-snapshot+jwt` 60-second revocation observation.
The CLI requires verifier-owned trust for the exact issuer DID, method,
32-byte Ed25519 public key, signed name, credential ID, HTTPS recipient,
holder DID, credential type, subject context and earliest acceptable
status observation. It never fetches or enrolls a DID key automatically.

Supply the two original JWTs as separate local UTF-8 files (maximum
65,536 bytes each). A snapshot must be issued by the **same original issuer
and pinned key** and remain valid at verification time. The verifier chooses
its own UTC minimum observation instant: it is not copied from the JWT,
snapshot, issuing service or a default of zero. Use a valid ISO 8601 UTC
round-trip timestamp such as `2026-11-08T00:00:00.0000000+00:00`:

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc2-didweb-status \
  --jwt-file ./issued-original.jwt \
  --snapshot-file ./issuer-status-original.jwt \
  --trusted-issuer did:web:issuer.example:members \
  --verification-method did:web:issuer.example:members#key-1 \
  --public-key-hex "$APPROVED_ISSUER_ED25519_PUBLIC_KEY_HEX" \
  --issuer-name "Example Membership Issuer" \
  --credential-id https://issuer.example/credentials/42 \
  --audience https://verifier.example/check \
  --holder "$APPROVED_HOLDER_DID" \
  --credential-type MembershipCredential \
  --context https://issuer.example/vocab/member \
  --minimum-observed-at 2026-11-08T00:00:00.0000000+00:00
```

Both timestamps, both files and all pins must be real values from the
relying party's own trust policy. The sample time is **illustrative only**
and would not make a November 8 snapshot valid indefinitely.

Exit code `0` means `SignedNotListed`: the original credential's issuer
signature, metadata, recipient and the issuer's signed, recent non-listing
observation passed. Nonzero means fail closed (including revoked, forged,
invalid, stale, missing, oversized, or mismatched evidence). Neither outcome
prints credential claims or the original JWTs. The verifier must not
interpret a non-listed status as a complete or real-time revocation check.

This is an **offline issuer-provenance check**, not a holder presentation.
It does not prove possession of the subject's private key, holder disclosure
consent, human or organisation identity, an Agent's delegated authority,
current business membership or permission, domain ownership, W3C Bitstring
Status List conformance, independent Wallet interoperability, or full
OpenID4VP compliance. See the [SDK status profile](vcdm20-didweb-issuer-status.md).
