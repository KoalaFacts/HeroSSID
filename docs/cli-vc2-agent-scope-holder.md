# Offline VC2 Agent holder full-disclosure CLI

An Agent holder can create a genuine Ed25519 full-disclosure VCDM 2.0 direct `vc+jwt` presentation **without an SDK caller**. The Agent signs its VP with its own private seed, and never re-signs or changes the original issuer-signed AgentScopeCredential.

## Preconditions

The verifier independently creates the policy-bound request and one-use session using [`request-vc2-agent-scope`](cli-vc2-agent-scope-vp-status.md). The issuer independently signs the original scope using [`issue-vc2-agent-scope`](cli-vc2-agent-scope-issue.md).

The holder application must independently pin the verifier DID, issuer DID, Agent DID, HTTPS recipient, subject vocabulary, signed credential ID, resource and action, then **display all issuer-signed claims and the recipient** and obtain approval before setting the full-disclosure acknowledgement. The flag does **not** independently prove informed human consent.

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential present-vc2-agent-scope \
  --request-jwt-file ./verifier-request.jwt \
  --credential-jwt-file ./issuer-signed-agent-scope.jwt \
  --trusted-verifier 'did:key:zVERIFIER_FROM_HOLDER_TRUST' \
  --audience 'https://verifier.example/agent-requests' \
  --trusted-issuer 'did:key:zISSUER_FROM_HOLDER_TRUST' \
  --agent 'did:key:zAGENT_CONTROLLED_BY_HOLDER_SEED' \
  --context 'https://issuer.example/vocab/agent-scope/v1' \
  --credential-id 'https://issuer.example/credentials/agent/42' \
  --resource 'https://api.example/projects/42' \
  --action 'invoices.read' \
  --output-jwt-file ./agent-signed-vp.jwt \
  --ack-full-disclosure < /secure/agent-seed.hex
```

DID placeholders are examples, **not** valid keys. The holder's actual raw 32-byte Ed25519 private seed is entered as hex using redirected stdin only; never pass it in argv, logs or source control. The CLI validates both real Ed25519 signatures and independently pinned policies, matches the seed to the Agent DID, then signs the exact original verifier request SHA-256 into a private, non-overwriting holder VP file. Neither JWT nor claims are printed.

The verifier independently checks the original issuer signature, holder signature, one-use verifier-owned session and separately obtained same-issuer signed private status using [`verify-vc2-agent-scope-vp-status`](cli-vc2-agent-scope-vp-status.md). This holder command **does not consume** the verifier's challenge.

**Boundary:** A signed assertion, Agent key-control proof and `SignedNotListed` snapshot are distinct facts. None establishes real-world/legal identity, genuine business delegation, authorization, completeness of revocation inventory or current unrevoked status. This is an application-defined HeroSSID single-machine offline profile, **not** external Wallet interop, hosted OpenID4VP, selective disclosure or independent certification.
