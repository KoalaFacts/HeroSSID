# Issuer-operated offline VC2 Agent scope issuance (CLI)

The .NET 10 CLI now allows an **actual issuer**, not a holder Wallet, to
sign one short-lived W3C VC Data Model 2.0 direct JOSE `vc+jwt` credential
using an authentic Ed25519 `did:key` seed supplied through redirected stdin.
This complements the independent no-SDK
[VC2 Agent scope verifier](cli-vc2-agent-scope.md).

The `AgentScopeCredential` subject vocabulary is **application-specific**.
It names one Agent DID, one exact action, one exact canonical HTTPS resource,
one verifier recipient and an exact credential ID. This is not a general
delegation or authorization standard; external Wallet interoperability and
full JSON-LD expansion/conformance remain unverified.

```sh
# In a controlled issuer environment only: provide one 64-character hex
# issuer Ed25519 seed on redirected stdin from an approved key provider.
# Do not type the seed in argv, shell history, environment variables,
# logs, files in the repository or documentation examples.
issuer-key-provider | dotnet run --project src/Cli/HeroSSID.Cli -- \
  credential issue-vc2-agent-scope \
  --issuer-did 'did:key:zISSUER_ENROLLED_SEPARATELY' \
  --agent 'did:key:zAGENT_EXPECTED_SEPARATELY' \
  --context 'https://issuer.example/vocab/agent-scope/v1' \
  --credential-id 'https://issuer.example/credentials/agent/42' \
  --audience 'https://verifier.example/agent-requests' \
  --resource 'https://api.example/projects/42' \
  --action 'invoices.read' \
  --valid-from '2026-11-09T00:00:00.0000000+00:00' \
  --valid-until '2026-11-09T00:05:00.0000000+00:00' \
  --output-jwt-file ./new-agent-scope.jwt
```

The timestamps above illustrate syntax; use a current **UTC** window
starting no later than issuance, ending in the future, and no longer than
**15 minutes**. Use genuine separately owned and enrolled DIDs.
The signer rejects a foreign private seed, malformed action, noncanonical
resource, excessive/expired/future window or conflicting output. The original
signature is independently rechecked before saving. The output is created
with non-overwriting create-new semantics and owner-only Unix permissions.
A successful command exits **0** and prints no JWT, claim values or seed.
Failure exits nonzero and does not release an issued credential. Protect the
output and the issuer's key custody according to the issuer's policy.

A separate relying party must verify the **original, unchanged** signed
JWT and independently configured issuer, Agent, action, resource, recipient,
credential ID, subject context and lifetime. Example:

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- \
  credential verify-vc2-agent-scope \
  --jwt-file ./new-agent-scope.jwt \
  --trusted-issuer 'did:key:zISSUER_ENROLLED_SEPARATELY' \
  --agent 'did:key:zAGENT_EXPECTED_SEPARATELY' \
  --context 'https://issuer.example/vocab/agent-scope/v1' \
  --credential-id 'https://issuer.example/credentials/agent/42' \
  --audience 'https://verifier.example/agent-requests' \
  --resource 'https://api.example/projects/42' \
  --action 'invoices.read'
```

**Trust boundaries:** issuance proves only that the issuer's Ed25519 private
key signed this restricted statement. The issuer must be authorized in the
receiver's **own** policy to assert that scope. The receiver must separately
check real Agent private-key possession, replay protection, revocation or
incident status, relevant organisation enrollment and actual application
ACL/tenant/approval rules before doing any work. Neither the signature nor
the credential alone verifies a human, organization, consent or business
authorization. The CLI does not act as a Wallet, hosted API or real-time
revocation registry.

References: [W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/),
[W3C VC JOSE/COSE (13 October 2026 Recommendation)](https://www.w3.org/TR/vc-jose-cose/),
[Agent scope SDK](vcdm20-agent-scope-assertion.md).
