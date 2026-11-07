# Verify a pinned, issuer-signed VC2 subject claim with HeroSSID CLI

The .NET 10 `credential verify-vc2-recipient-claim` command is a **verifier-configured acceptance check** on the original direct VCDM 2.0 / VC-JOSE `vc+jwt`. It rejects an issuer-signed statement if the verifier's exact, independently required **top-level string property** of `credentialSubject` does not match. Unlike issuer-signature-only checks, it can answer a narrow question such as *did this issuer sign `membership: "active"` for this exact credential, subject and recipient?*

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc2-recipient-claim \
  --jwt-file ./original-recipient-bound-vc2.jwt \
  --trusted-issuer 'did:key:z6Mk...' \
  --holder 'did:key:z6Mk...' \
  --credential-type MembershipCredential \
  --context https://issuer.example/contexts/membership/v2 \
  --credential-id https://issuer.example/credentials/member/42 \
  --audience https://verifier.example/checks/membership \
  --claim-name membership \
  --claim-value active
```

All nine values are supplied independently by the relying verifier. The command reads at most 65,536 bytes of UTF-8 JWT input, allows a final line ending and checks the real issuer Ed25519 signature, correct `did:key`, strict direct VC2 format, signed `credentialSubject.id`, type, vocabulary context, time validity, exact canonical signed HTTPS credential ID and the one recipient's exact canonical HTTPS `aud`. **Only after that** does it test the required claim by ordinal string equality.

`--claim-name` permits a simple case-sensitive ASCII property name of at most 64 characters, beginning with a letter and continuing with letters, digits, `_` or `-`. The reserved `id` is not accepted as an independent claim: the holder DID already has its own pinned check. `--claim-value` is a nonempty, trimmed string of at most 256 characters without control characters. Missing keys, duplicated property names, unexpected types (including JSON numbers and booleans), mismatched values, invalid signatures and wrong recipients fail closed; no JSON coercion, case folding or nested path matching takes place.

**Exit 0** means only that a trusted issuer genuinely signed the expected string statement for the specified holder DID, signed credential ID, recipient and validity interval. Failure exits nonzero. The CLI never prints the JWT or credential-subject data, even on rejection.

This is a deliberately restricted HeroSSID direct JOSE profile, **not** third-party Wallet interoperability, JSON-LD semantic verification or a complete conformance certification. This operation does **not** demonstrate holder private-key control, human informed consent, current revocation status, issuer real-world identity, up-to-date membership, authorization to enter a venue, or any Agent's right to perform an action. The relying application still owns those checks, approval rules and downstream business authorization.

For the issuer-signed recipient format and SDK issuance use `Vcdm20JoseCredential.CreateForAudienceWithId` and [recipient-bound CLI verification](cli-vc2-recipient-bound-check.md). A verifier needing holder proof and a non-replayable presentation must instead use a separately provisioned challenge-store-backed verifier path; it must not infer possession from this CLI exit status.
