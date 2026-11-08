# Offline no-SDK verifier for one VC2 Agent scope issuer assertion

HeroSSID's .NET 10 CLI now checks an original issuer-signed **VC Data Model
2.0 direct JOSE `vc+jwt`** `AgentScopeCredential` without writing application
code. The verifier independently supplies the trusted Ed25519 `did:key`
issuer and agent, the exact versioned HTTPS subject vocabulary, original
HTTPS credential ID, single HTTPS recipient, canonical HTTPS resource and
one exact action. The verifier does **not** obtain these pins from the JWT.

This is an **application-defined VC2 vocabulary**, not a general capability
or delegation standard; external Wallet interchange is not established.

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- \
  credential verify-vc2-agent-scope \
  --jwt-file ./issuer-signed-agent-scope.jwt \
  --trusted-issuer 'did:key:zISSUER_FROM_VERIFIER_CONFIGURATION' \
  --agent 'did:key:zAGENT_FROM_VERIFIER_CONFIGURATION' \
  --context 'https://issuer.example/vocab/agent-scope/v1' \
  --credential-id 'https://issuer.example/credentials/agent-scope/42' \
  --audience 'https://verifier.example/agent-requests' \
  --resource 'https://api.example/projects/42' \
  --action 'invoices.read'
```

Use actual separately enrolled DIDs and pins; the above identifiers are
illustrative, not valid keys. Exit code **0** means the real Ed25519 issuer
signature and all exact pins, subject shape, restricted action/resource and
**at most 15-minute signed validity interval** match at verification time.
Any invalid, long-lived, expired, tampered or untrusted JWT exits nonzero.
JWT and subject claims are never printed. The file is read once with a
65,536-byte input bound to avoid verifying one JWT and acting on a second.

**Trust boundaries:** this is an *issuer-only assertion check*. A signed
statement naming an Agent does not prove control of the Agent's private key.
A receiver must authenticate the actual caller with a separately signed,
verifier-bound one-use holder proof and replay protection; check incident and
revocation status according to its own trust policy; and enforce its own
organisation identity enrollment, tenant ACL, issuer-to-resource authority,
policy, approvals and business authorization. It also provides no human
consent evidence, standard revocation status, real-time non-revocation,
independent Wallet interoperability or full JSON-LD conformance.

For an SDK caller that needs the distinct holder signature, verifier-owned
nonce and same-issuer signed private status together, use
[`Vcdm20AgentScopePresentation.CheckWithIssuerStatus`](vcdm20-agent-scope-assertion.md#issuer-scope--real-agent-proof--one-use-verifier-request--signed-status).
