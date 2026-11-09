# Direct VC2 did:key: holder full-disclosure CLI

The .NET 10 CLI now lets a **holder** sign an original issuer-issued, direct VCDM 2.0 `vc+jwt` credential into a separate Ed25519 `vp+jwt`. The holder must control its own `did:key` Ed25519 seed. The original issuer JWT is embedded **unchanged** in an `EnvelopedVerifiableCredential`; the holder never becomes an issuer. This is a local HeroSSID signed-request profile, **not OpenID4VP interoperability** or JSON-LD conformance testing.

## What each operator must already have

- **Issuer:** signs a genuine direct VC2 credential, for example with [`credential issue-vc2-didkey`](cli-vc2-didkey-issuer-issue.md). Issuer DID, subject holder DID, credential type and HTTPS context are independently reviewed by the holder.
- **Verifier:** issues and retains a short-lived single-use challenge with `InMemoryPresentationChallengeStore` (or a shared atomic equivalent) and signs its policy-bound form with `OfflineSignedPresentationRequest.Create`. Set `CredentialType` and `SubjectContextUri` on the challenge with the exact intended type and HTTPS context. Retain verifier-owned nonce, tenant, issuer and original SHA-256 request pin. The CLI holder does **not** create or consume the verifier session.
- **Holder:** independently pins the verifier DID, HTTPS recipient, issuer DID, its own holder DID, credential type and context. The holder UI must show **all original signed claims** and the recipient and obtain disclosure approval; `--ack-full-disclosure` is only the caller's acknowledgement, **not independently verified consent**.

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential present-vc2-didkey \
  --request-jwt-file ./verifier-request.jwt \
  --credential-jwt-file ./original-issuer-vc2.jwt \
  --trusted-verifier 'did:key:zPINNED_VERIFIER' \
  --audience 'https://verifier.example/credential-check' \
  --trusted-issuer 'did:key:zPINNED_ISSUER' \
  --holder 'did:key:zMY_HOLDER_KEY' \
  --credential-type 'MembershipCredential' \
  --context 'https://issuer.example/vocab/membership/v1' \
  --output-jwt-file ./holder-vp.jwt \
  --ack-full-disclosure < /secure/holder-seed.hex
```

The DID values are illustrative placeholders, not real signing identities. Stdin must contain the raw **32-byte holder seed encoded as hex**, ending with a newline. Never supply keys in CLI arguments, logs or a source repository. The CLI requires redirected input, rejects forged verifier requests or original issuer credentials, verifies independently pinned type/context/holder/issuer and rejects a seed for a different holder. It signs the original request's exact SHA-256 into the VP, writes to a create-new private output file (Unix owner-only permissions), and never prints claims or seed material.

The verifier must authenticate both signatures, independently check the original signed request hash, tenant, nonce, audience, type and context, and **atomically consume** its own one-use challenge. The SDK entry point `Vcdm20JosePresentation.CheckWithHolderBoundSignedVerifierRequest` provides these checks with a verifier-owned `IPresentationChallengeStore`; success is `SignedButStatusUnchecked`, **not** an authorization result. The positive test demonstrates a real verifier, issuer and holder key pair plus replay rejection. Host/distributed verifier deployment, live revocation and full credential lifecycle remain separate delivery gates.

**Limits:** Full disclosure, no selective disclosure or real consent proof. The holder key signature demonstrates control of the signing seed, not real-world identity; the issuer signature proves only what that issuer asserted. No current revocation check, business authorization, trust registry, independent wallet interoperability, OpenID4VP conformity or external security certification is established.
