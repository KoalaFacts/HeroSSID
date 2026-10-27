# Verification Failure Disclosure Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task by task.

**Goal:** Ensure rejected credential results contain no subject, issuer or expiration fields.
**Architecture:** Change only the private failure-result factory and its call sites; retain success behavior and status codes.
**Tech Stack:** Existing C#/.NET 9, xUnit and NSec; EF InMemory tests only.
**Spec:** `docs/superpowers/specs/2026-10-25-verification-failure-disclosure-design.md`

## Global constraints
Do not change PR #16, database schemas/migrations, PostgreSQL tests or normal CI gates. No dependency upgrades, release or production action. Preserve requester quotas and issuer lookup separation.

## Review focus
Tampered real signatures; failure serialization; explicit issuer-tenant entry point; valid no-expiration credentials; consumers that previously relied on rejected parsed metadata.

## Task 1: Reproduce and fix rejected result disclosure
- [ ] Add `CredentialVerificationFailureDisclosureTests.cs`: twelve failure scenarios across both verification entry points and four positive controls, with independently generated Ed25519 keys.
- [ ] Run the focused tests against unchanged production code; observe identity-field assertions fail, not compile/setup failures.
- [ ] In `CredentialVerificationService.cs`, make `CreateFailedResult` accept only status and error message. Remove parsed identity arguments from all rejection paths and use a generic expiry message.
- [ ] Update `CredentialVerificationResult.cs` XML documentation and README to describe the null-on-failure contract without implying signature verification alone grants trust or authority.
- [ ] Run all existing non-PostgreSQL suites with warnings-as-errors unchanged. Preserve original skips and report the unexecuted real-DB suites.
- [ ] Request independent review, record exact commits and run results, and leave a focused draft PR if full merge gates are not met.
