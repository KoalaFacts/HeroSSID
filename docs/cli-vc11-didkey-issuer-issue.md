# Issue a W3C VC Data Model 1.1 JWT from the .NET 10 CLI

An issuer can sign an original `jwt_vc_json` credential with its own Ed25519 `did:key` signing seed. This is **VC Data Model 1.1** with the normative `vc.@context` and `typ: JWT` profile, not HeroSSID's older private `vc.context`, VCDM 2.0 JOSE, or a third-party wallet interoperability claim.

Prerequisites: a separately enrolled issuer `did:key` and corresponding 32-byte Ed25519 seed, the independently agreed holder `did:key`, and an issuer-approved HTTPS subject vocabulary. The issuer is responsible for establishing the truth of each statement. The signing seed must be supplied as exactly 64 hex digits, optionally with a newline, **only via redirected standard input**; never pass it as an argument or environment variable.

Create an UTF-8 `subject.json` file with, for example:

```json
{
  "id": "did:key:z6Mk...FULL_HOLDER_DID",
  "membership": "active"
}
```

Replace the placeholder with a genuine holder DID. The following example assumes `issuer-key-provider` is your existing, trusted key-provider command, configured outside HeroSSID to write the issuer seed to a pipe. It is a **placeholder**, not a bundled HeroSSID executable.

```sh
issuer-key-provider --export-hex | dotnet run --project src/Cli/HeroSSID.Cli -- \
  credential issue-vc11-didkey \
  --issuer-did 'did:key:z6Mk...FULL_ISSUER_DID' \
  --issuer-name 'Example Membership Issuer' \
  --credential-id 'https://issuer.example/credentials/member-123' \
  --holder 'did:key:z6Mk...FULL_HOLDER_DID' \
  --credential-type MembershipCredential \
  --context 'https://issuer.example/vocab/membership' \
  --subject-file ./subject.json \
  --valid-from '2026-11-08T07:00:00.0000000+00:00' \
  --valid-until '2026-11-08T07:08:00.0000000+00:00' \
  --output-jwt-file ./issued-credential.jwt
```

Supply a **current** UTC validity interval when actually running the example; the fixed 2026-11-08 timestamps illustrate the round-trip format, not a live credential. `--issuer-name` and `--credential-id` are optional; when provided they become issuer-signed metadata. The signed validity interval must not exceed 15 minutes. This command requires an existing JSON subject file at most 16,384 bytes and a fresh output file; it refuses duplicates, mismatched subject IDs, stale/future intervals, incorrect private seeds, symbolic-link destinations, and existing output. On Unix the output is created with mode `0600`; secrets and claims are never printed by the command.

The separate verifier must enroll and independently pin the issuer DID, holder DID, vocabulary and type, rather than inferring trust from the signed JWT. `credential verify-issuer` checks issuer provenance only; applications requiring signed name and ID must also use `JwtVcJsonCredential.TryVerifyWithPinnedIssuerNameAndId` against their independently approved policy.

Issuance proves only that the specified issuer private key signed a statement. It **does not** prove control of the holder's private key, human consent, real-world identity, an unrevealed revocation state, authority to act for an organisation, or third-party wallet compatibility. No hosted issuance endpoint, wallet UI, independent conformance certification or credential exchange is added by this command.

References: [W3C Verifiable Credentials Data Model 1.1 JWT encoding](https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#jwt-encoding), [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

## Independently verify the original JWT with signed issuer metadata pins

The matching offline .NET 10 verifier command operates with **separately established** pins; never extract expected values from the JWT being checked. After creating an original JWT as above, the verifier can run:

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- \
  credential verify-vc11-didkey-pinned \
  --jwt-file ./issued-credential.jwt \
  --trusted-issuer 'did:key:z6Mk...FULL_ISSUER_DID' \
  --issuer-name 'Example Membership Issuer' \
  --credential-id 'https://issuer.example/credentials/member-123' \
  --holder 'did:key:z6Mk...FULL_HOLDER_DID' \
  --credential-type MembershipCredential \
  --context 'https://issuer.example/vocab/membership'
```

The CLI reads at most 65,536 JWT file bytes and verifies the **original** issuer signature plus the issuer DID, signed issuer name and credential ID, expected subject DID, type, HTTPS vocabulary and validity at verification time. Invalid, oversized, tampered, expired and mismatched credentials return failure without printing the JWT or claims. Both signed name and ID must be present and exactly equal to independent verifier policy; issuer-controlled metadata is not itself a trust anchor.

A successful issuer-signature check **is not** proof of holder private-key control, human consent, revocation freshness, real-world identity, organisation registration or authorization to perform an action. This command does not implement OpenID4VP, a W3C conformance suite, third-party-wallet compatibility or user disclosure consent.
