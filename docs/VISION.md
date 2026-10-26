# HeroSSID vision

## Mission

**Build a trustworthy, portable identity credential foundation for people, organisations and agents.**

A useful credential lets its holder prove an issuer's statement to a relying party. That proof must retain the real issuer, bind to the right holder, disclose information deliberately, and respect expiry, revocation and the verifier's trust policy. HeroSSID should make that lifecycle understandable and dependable for developers and users.

A wallet holds credentials and creates presentations. HeroSSID supplies the identity, issuance and verification foundation beneath that experience. The project will be judged by verified credential flows and independent interoperability, rather than unsupported adoption targets or feature names.

## Product principles

1. **Preserve provenance.** A holder signature cannot turn an unsigned or forged statement into an issuer's credential.
2. **Make trust explicit.** A valid signature establishes who signed a statement. The verifier decides whether that issuer is trusted for the requested purpose.
3. **Keep authority contextual.** An identity or qualification does not itself authorize every business action. Agent delegation needs its own limits, expiry and revocation, interpreted by the receiving application.
4. **Give the holder meaningful control.** Explain what information will be sent. Full disclosure must be labeled honestly; selective disclosure requires a real cryptographic implementation.
5. **Support the whole lifecycle.** Issuance, possession, presentation, rejection, expiry, revocation, key changes and recovery must all have usable paths.
6. **Earn interoperability.** Test against independent issuers, wallets and verifiers using a clearly identified protocol/profile version.
7. **Make claims traceable.** Documentation should distinguish implemented behavior, measured results, development limitations and planned capabilities.

## First complete use case

An organisation issues a membership or role credential to a holder. A separately authenticated verifier requests proof from a specific trusted issuer. The holder explicitly presents it; the verifier checks original issuance, holder control, request binding and current validity. A repeated submission, forged credential, different holder, expired request or revoked credential fails.

The present trust-foundation delivery implements a local full-disclosure library profile for this use case. Identity enrollment and private-key custody remain server-side. It does not yet provide a user wallet, remote trust discovery, selective disclosure or an OpenID credential exchange endpoint.

## Delivery milestones and evidence

| Milestone | Deliverable | Acceptance evidence |
|---|---|---|
| Trust foundation | Authenticated tenant/scopes, issuer-preserving presentation, explicit verifier policy and single-use challenges | Real HTTP isolation tests, distinct real signing keys, malicious signed-envelope regressions, concurrent replay rejection |
| Operable lifecycle | Public revocation operations/status publication, durable challenge consumption, key rotation and recovery | Multi-instance replay races, crash/restart tests, revoked/rotated-key behavior, recovery and ownership tests; optional PostgreSQL backend is an initial step |
| Independent exchange | A supported OpenID4VCI/OpenID4VP profile integrated with an independent wallet | Versioned conformance/interop cases for issuance and presentation, including rejection and cancellation |
| Privacy and holder control | A real selective-disclosure format, clear consent and export/migration | Disclosure-binding/tampering tests, independent verification, proof that omitted claims remain undisclosed |
| Pilot readiness | One institution, one credential type, a usable holder and verifier journey | Task completion, recovery/expiry/revocation outcomes, documented operational limits and external security review |

The milestones are evidence gates rather than calendar promises. The [README capability table](../README.md#implemented-capabilities-and-boundaries) is the current implementation inventory. The next engineering priority should be the highest-risk missing part of the lifecycle, after resolving regressions in the current work.

## People, organisations and agents

The same provenance and holder-control principles apply to different subjects, but each needs an appropriate enrollment and issuance policy. A human qualification, an organisation's registration and an agent's delegated role are different statements. No shared identifier or signature makes those statements equivalent.

Agent credentials should eventually express who issued them, what entity or key they identify, and what limited delegation they carry. Receiving applications remain responsible for checking that delegation against local authorization policy. This is a target capability, not a completed delegation subsystem.

## Continuous improvement

Each improvement should start from current code and reproducible evidence, finish a small coherent work package, and preserve testable security boundaries. Existing PRs and their actual CI failures take priority over duplicate implementations. A completed PR advances one milestone; it does not end development.

Progress reports should state what changed, what was actually tested, where the evidence lives, and the next concrete gap. Production-readiness, user-adoption and compliance claims require evidence beyond repository code.
