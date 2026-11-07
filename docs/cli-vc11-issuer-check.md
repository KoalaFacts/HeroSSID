# Verify a W3C VC 1.1 issuer signature with HeroSSID CLI

Use the .NET 10 CLI to check an original Ed25519 `jwt_vc_json` credential against **independently enrolled** issuer policy. This is deliberately issuer-only, not a holder proof, live status result, identity onboarding or authorization.

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-issuer \
  --jwt-file ./issued-credential.jwt \
  --trusted-issuer 'did:key:z6Mk...' \
  --holder 'did:key:z6Mk...' \
  --credential-type MembershipCredential \
  --context https://issuer.example/contexts/membership/v1
```

The DID, holder, credential type and HTTPS vocabulary arguments are **verifier-owned pins**, never copied from untrusted JWT metadata. The command bounds the local UTF-8 file read to 65,536 bytes; genuine issuer Ed25519 signature, JWT VC1.1 context, holder/type and expiry are checked before exit 0. The original JWT is never rewritten or its claims printed.

Missing policy, invalid/forged/expired JWT, mismatch, missing file or excessive input exits nonzero with no claims. A text-file trailing newline is tolerated. The former simulated `credential issue` and `credential verify` actions are removed: they never actually issued or verified and must not claim success.

Only independently pinned `did:key` VC1.1 JWT issuers are supported by this CLI path. It is not did:web key discovery, legacy `vc.context`, VC2 JOSE, OpenID4VP exchange or independent wallet interoperability. The CLI does not verify holder private-key control, user consent, revocation, legal identity, delegated Agent authority or business authorization.

Reference: [W3C VC Data Model 1.1 JWT](https://www.w3.org/TR/2021/REC-vc-data-model-20211109/#jwt-encoding) and OpenID4VP 1.0 `jwt_vc_json`; no independent conformance certification is claimed.
