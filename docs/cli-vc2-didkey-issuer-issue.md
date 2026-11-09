# Offline issuer-signed direct VC Data Model 2.0 JWT (did:key)

The .NET 10 CLI `credential issue-vc2-didkey` creates an original direct VCDM 2.0 `vc+jwt` with `@context`, `type`, `issuer`, `validFrom`, `validUntil`, and `credentialSubject`. It uses an issuer-controlled Ed25519 seed for an exact `did:key` issuer. The SDK performs **real signature self-verification** against that DID, rather than accepting the supplied issuer name as proof.

## Operator invocation

Prepare a subject JSON (maximum 16 KiB, depth 16), for example:

```json
{"id":"did:key:z<holder DID>", "membership":"active"}
```

Replace the placeholder with a real independent holder DID. The subject must include the exact `id`, must not contain duplicate keys (including nested keys), and must use terms from a **preapproved HTTPS vocabulary**.

Provide the issuer seed only through **redirected stdin** as exactly 64 ASCII hex characters, optionally followed by CRLF or LF. Obtain those bytes from a controlled issuer secret source without placing them in an argument, shell history, environment, or repository. An illustrative pipeline (the key provider is operator-supplied, not part of HeroSSID):

```sh
issuer-key-provider --stdout-hex | dotnet run --project src/Cli/HeroSSID.Cli -- credential issue-vc2-didkey \
  --issuer-did "$ISSUER_DID" \
  --holder "$HOLDER_DID" \
  --credential-type MembershipCredential \
  --context https://issuer.example/vocab/membership \
  --subject-file ./subject.json \
  --valid-from 2026-11-09T04:00:00.0000000+00:00 \
  --valid-until 2026-11-09T04:10:00.0000000+00:00 \
  --output-jwt-file ./issued.jwt
```

Times above are **illustrative**; use a current valid UTC interval, at most 24 hours. A preexisting output file is never replaced. New files are private (`0600` on Unix). Invalid inputs, wrong issuer seed, invalid subject and expired intervals fail without releasing any JWT or claims to stdout. The CLI attempts to clear transient seed and subject buffers; operators remain responsible for the source's lifecycle and secure custody.

## Independent verifier

The relying party must independently enroll its trusted issuer DID and approve the expected holder, type, vocabulary and time. It can then check the **unchanged** JWT using the separate command:

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc2-issuer \
  --jwt-file ./issued.jwt \
  --trusted-issuer "$ISSUER_DID" \
  --holder "$HOLDER_DID" \
  --credential-type MembershipCredential \
  --context https://issuer.example/vocab/membership
```

The embedded issuer `did:key` is never sufficient to enroll trust. This format is deliberately different from legacy `jwt_vc_json` with a nested private `vc.context`. Its direct `@context` profile does not perform generalized JSON-LD expansion, remote context verification, full W3C conformance testing or independent Wallet interoperability. It does not prove holder private-key control, human identity, issuer's legal status, fresh non-revocation, consent or receiving-system authorization. The verifier must implement those checks independently.
