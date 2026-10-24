# Identity Credential Trust Foundation Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans for the owned task; maintain failing-test evidence and a task report.

**Goal:** Close the current tenant/authorization and presentation-provenance defects with a usable, honest credential foundation.

**Architecture:** Authenticated REST operations resolve tenant identity from validated tokens. A full-disclosure presentation embeds the original credential and binds a holder signature to a verifier-issued, single-use challenge. Public identity records and the existing credential verifier support the closed-system trust boundary.

**Tech Stack:** C#/.NET 9, ASP.NET Core, EF Core/PostgreSQL, NSec Ed25519, xUnit.

**Spec:** `docs/superpowers/specs/2026-10-24-credential-trust-design.md`

## Global Constraints

- Retain existing target frameworks and production dependencies; no migrations or production database writes.
- Preserve issuer signatures and holder ownership; never trust decoded claims before verification.
- Use xUnit and real cryptographic signatures in security tests.
- Do not call mock selective disclosure a supported capability.
- Work in isolated branches; root integrates and publishes the coherent result.

## Review Focus

- Token tenant claim missing, repeated, malformed or empty must not fall back to a default tenant.
- A valid token with the wrong scope must not authorize a protected operation.
- Correct holder signature cannot make a forged, revoked or unrelated credential valid.
- A presentation for one verifier/challenge cannot be accepted by another or reused.
- Invalid requests must not return partially trusted identity claims or burn a valid challenge before verification.

### Task 1: REST identity and operation authorization

**Files:** API `Program.cs`, OAuth/token configuration, DID/credential endpoints, development seeder, a request tenant context, API tests and affected HTTP/integration fixtures.

**Interfaces:** Continue using `ITenantContext.GetCurrentTenantId()`. Replace its HTTP registration with a validated-claim implementation. Require `did:manage` for DID creation/resolution, `credential:issue` for issuance and `credential:verify` for verification. Scopes can be repeated claims or a space-delimited scope claim. Issuer access remains tenant-scoped.

- [x] Add real HTTP/auth regression tests for missing/wrong scope, two distinct tenants, invalid tenant claims and JWT configuration failures; run against baseline to record failure.
- [x] Implement tenant resolution, named scope policies and startup JWT validation; use one validated configuration for issuance and validation. Use fixed-time secret comparison and reject malformed stored hash lengths.
- [x] Update existing fixtures/examples for explicitly authenticated requests; retain unauthenticated and wrong-token negative assertions.
- [x] Run API tests and full solution build; report unavailable PostgreSQL execution accurately.
- [x] Commit and provide changed-file/test evidence to root for independent review.

### Task 2: Issuer-preserving, challenge-bound presentations

**Files:** Credentials `VerifiablePresentations/*`, new challenge store in that feature, credential DI registration, unit presentation tests and presentation integration tests.

**Interfaces:** Explicit challenge issuance binds verifier tenant and audience. Creation requires original JWT credential, holder tenant/id and challenge context. Verification requires verifier tenant, expected audience and nonce and consumes the stored challenge after all cryptographic and state checks. Retain source-compatible legacy calls only as fail-closed compatibility overloads if necessary.

- [x] Add regressions that demonstrate forged original credentials and unrelated holder credentials currently succeed; record failures before modifying production code.
- [x] Implement full-disclosure envelopes containing original signed credentials; verify issuer and holder signatures, subject, times, local active identities and revocation; strictly reject unsupported selective disclosure.
- [x] Implement bounded, expiring, atomic one-use challenges with injectable time and tests for replay, wrong audience/tenant, expiry, malformed inputs and failed-verification non-consumption.
- [x] Update integration coverage to exercise real issuer/holder/verifier relationships with distinct keys; remove default mock SD-JWT registration.
- [x] Run credential tests and build; document closed-system and process-local limits.

### Task 3: Delivery and honest capability documentation

**Files:** `README.md`, `docs/VISION.md`, selected first-use instructions and roadmap.

- [x] Replace conflicting production-ready/completed claims with an implementation-backed capability matrix and the user's focused identity credential mission.
- [ ] Run full local verification, independent branch review and ordinary CI on the published candidate; resolve findings.
- [ ] Deliver the branch/PR and verified results; merge only after established verification/review requirements are satisfied. No release or deployment.
