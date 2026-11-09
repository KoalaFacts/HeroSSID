# Offline VC2 Agent scope proof, one-use verifier challenge and issuer status

The .NET 10 CLI now offers a **single-machine verifier** for HeroSSID's opt-in
VCDM 2.0 direct `vc+jwt` `AgentScopeCredential`. It binds together four
**independently signed or retained** objects: the issuer's original short-lived
Agent scope JWT, the agent holder's genuine Ed25519-signed full-disclosure VP,
the verifier's signed policy-bound request and private one-use challenge, and
the independently obtained same-issuer signed private status snapshot.

**No step delegates business authority merely by verifying a signature.**
The issuer attests one agent/action/resource for a recipient. The Agent holder
proves control of the named private key, not real-world identity or legal
delegation. The verifier must already trust that issuer and separately enforce
its own issuer-to-resource authorization, tenant ACL and incident policy.

## One verifier-owned offline challenge

The verifier, not the Agent, selects and securely retains all trust pins. Issue
a genuine eight-field policy-bound request with an actual verifier Ed25519 seed
read from redirected stdin (the CLI never accepts a seed on its command line):

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential request-vc2-agent-scope \
  --verifier-did 'did:key:zVERIFIER_FROM_VERIFIER_CONFIGURATION' \
  --tenant-id '52bb1e4a-f419-4e13-9e12-a539bed81f02' \
  --audience 'https://verifier.example/agent-requests' \
  --trusted-issuer 'did:key:zISSUER_FROM_VERIFIER_CONFIGURATION' \
  --context 'https://issuer.example/vocab/agent-scope/v1' \
  --output-request-file ./request.jwt \
  --session-file ./verifier-private-challenge.json \
  --lifetime-seconds 120 < /secure/verifier-seed.hex
```

These identifiers and paths are illustrative; the DID placeholders are **not**
valid keys. Keep the verifier seed out of logs, shell history, repositories,
and unprotected files. Request and session files must not pre-exist; the CLI
creates private, non-overwriting artifacts and a single-local-filesystem
replay record. It does not host an HTTP endpoint.

The issuer creates the original signed credential using
[`issue-vc2-agent-scope`](cli-vc2-agent-scope-issue.md). The Agent holder
application independently pins the actual verifier DID, audience, issuer DID,
context, credential ID and signed recipient, displays the **entire credential
and disclosures**, then calls
`Vcdm20JosePresentation.CreateForAudienceWithIdAndSignedRequest` using the
Agent's **own** Ed25519 seed. This holder operation currently requires an SDK
caller; the verifier CLI is **not** a third-party Wallet interoperability claim.
The verifier obtains a signed same-issuer private VC2 status JWT separately
from the Agent.

## Verify exact Agent scope and consume the challenge

```sh
dotnet run --project src/Cli/HeroSSID.Cli -- credential verify-vc2-agent-scope-vp-status \
  --verifier-did 'did:key:zVERIFIER_FROM_VERIFIER_CONFIGURATION' \
  --tenant-id '52bb1e4a-f419-4e13-9e12-a539bed81f02' \
  --audience 'https://verifier.example/agent-requests' \
  --trusted-issuer 'did:key:zISSUER_FROM_VERIFIER_CONFIGURATION' \
  --agent 'did:key:zAGENT_FROM_VERIFIER_CONFIGURATION' \
  --context 'https://issuer.example/vocab/agent-scope/v1' \
  --credential-id 'https://issuer.example/credentials/agent/42' \
  --resource 'https://api.example/projects/42' \
  --action 'invoices.read' \
  --request-jwt-file ./request.jwt \
  --session-file ./verifier-private-challenge.json \
  --presentation-jwt-file ./agent-holder-vp.jwt \
  --snapshot-file ./independently-obtained-issuer-status.jwt \
  --minimum-observed-at '2026-11-09T00:00:00.0000000+00:00'
```

Set the UTC observation cutoff from the verifier's **actual** independently
chosen current policy, not the example, untrusted holder, or issuer alone.
Exit code `0` means the original issuer and holder Ed25519 signatures,
verifier's signed-request hash pin, exact recipient, credential ID, Agent DID,
one literal action and canonical HTTPS resource, at-most-15-minute signed
Agent scope, and current same-issuer `SignedNotListed` private observation
were verified. It does **not** print JWTs or claims, execute any business
operation, or grant a permission.

A genuinely holder-signed but wrong, revoked or stale status/scope attempt
spends the verifier-owned one-use challenge before returning nonzero. A
forged holder proof, foreign verifier or mutated signed request cannot consume
a legitimate challenge. Successful verification atomically renames the private
session file to `.used`; retries and concurrent local processes fail closed.
Do not restore spent sessions from backups, run this on NFS/shared volumes,
or treat single-host rename as multi-replica transactional replay protection.

This is HeroSSID's own tightly restricted **offline full-disclosure** profile,
not hosted OpenID4VP, a W3C standard delegation format, W3C Bitstring Status
List, current/live non-revocation or independent Wallet interoperability.
A genuine status snapshot is only a time-bounded signed observation and can
be incomplete. No human consent evidence, organisation identity vetting,
legally valid delegation or business authorization is established. For a
multi-instance verifier, integrate the SDK with an actual shared atomic
challenge store and independently enrolled issuer/status trust.
