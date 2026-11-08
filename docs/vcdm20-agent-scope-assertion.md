# Verifier-pinned, short-lived VC2 agent scope assertion (.NET SDK)

This is an **opt-in, application-specific credential profile** based on the
W3C VC Data Model 2.0 direct JOSE `vc+jwt` representation. It adds a
single recipient-bound agent action assertion to HeroSSID's existing issuer
credential signing and independent verifier pinning. The JWT uses the already
implemented direct VC2 layout, not HeroSSID's older private `vc.context` JWT
or a newly claimed industry standard.

An independently enrolled issuer key may assert that a particular agent
`did:key` is associated with **one** literal action over **one** HTTPS
resource for **one** HTTPS recipient. The application supplies a **versioned,
HTTPS vocabulary context** defining the exact `action` and `resource`
terms. The encoded subject has precisely `id`, `action` and `resource`.
The original issuer-signed JWT also carries the single signed `aud`, signed
HTTPS credential `id`, issuer DID, type and bounded validity period.

## Issuer and verifier entry points

```csharp
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;

Uri context = new("https://issuer.example/vocab/agent-scope/v1");
Uri credentialId = new("https://issuer.example/credentials/agent/123");
Uri recipient = new("https://verifier.example/agent-requests");
Uri resource = new("https://api.example/projects/42");
DateTimeOffset now = DateTimeOffset.UtcNow;

// Only the genuine issuer passes in its private Ed25519 seed.
string originalJwt = Vcdm20AgentScopeAssertion.Create(
    issuerDid, agentDid, context, credentialId, recipient, resource,
    "invoices.read", issuerOwnedSeed, now, now.AddMinutes(5));

// Verifier: policy inputs MUST originate from its own enrollment/configuration,
// not be copied from the unverified JWT or an agent-supplied request.
bool validIssuerStatement = Vcdm20AgentScopeAssertion.TryVerify(
    originalJwt, independentlyPinnedIssuerDid, independentlyPinnedAgentDid,
    independentlyPinnedContext, independentlyPinnedCredentialId,
    independentlyPinnedRecipient, independentlyPinnedResource,
    "invoices.read", DateTimeOffset.UtcNow, out JsonElement signedScope);
```

The public API is in `HeroSSID.Credentials.Vcdm20` targeting .NET 10.
The issuer must genuinely possess the Ed25519 seed matching its independently
trusted `did:key`. Verification checks its original signature, exact JOSE
profile, issuer, agent subject DID, type, context, credential ID, canonical
recipient, action, resource and current validity. Both issuance and
verification cap the **signed** validity interval to 15 minutes; verification
also rejects an authentic general VC2 credential that exceeds that limit.
Rejected results return no subject claims.

The action grammar is one case-sensitive lowercase ASCII token of up to 64
characters, with `.`, `:` and `-` internal separators and no repeated
or trailing separator. It is not a wildcard, multiple permissions or an
interpreted expression. The resource must be one exact canonical HTTPS URI
without credentials, query or fragment. The issuer must not encode secrets in
the credential subject, which is fully disclosed if presented.

## Separate mandatory trust gates

An **issuer-signed statement is not executable business authority**.
In particular:

- It does **not** prove the issuer is a legal organisation, or that it is
  entitled to grant access to a resource. Verifiers must independently enroll
  the issuer DID and maintain their own issuer-to-resource authority policy.
- It does **not** prove that a caller possesses the named agent's key.
  Before accepting an agent's request, authenticate a distinct holder-signed
  presentation bound to a verifier-owned one-use challenge (and enforce
  replay protection) using the applicable HeroSSID presentation APIs.
- It does **not** check revocation, suspension or incident status. Integrate
  a suitable independently pinned issuer status policy when relevant;
  `SignedNotListed` is only a bounded signed observation.
- It does **not** prove human consent, delegated legal rights, or application
  authorization. The recipient must check its **own** ACL, account/tenant,
  approval history, requested action and resource, and any revocation or
  incident overrides before performing a business operation.

This helper does not host issuance, migrate a database, publish a credential,
test any independent third-party Wallet or certify JSON-LD/VC conformance.
It is a tightly bounded profile using existing W3C VC2/JOSE structures with
application-defined subject terms.

References: [VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/),
[VC JOSE/COSE](https://www.w3.org/TR/vc-jose-cose/),
[existing recipient-bound VC2 and one-use holder presentation](vcdm20-recipient-bound-jwt.md).
