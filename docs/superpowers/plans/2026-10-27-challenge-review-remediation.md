# Challenge Review Remediation Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement these tasks in the existing PR #16.

**Goal:** Close the reviewed lifetime and resource-boundary defects in the opt-in PostgreSQL presentation challenge store.
**Architecture:** Preserve the existing store interface and opt-in registration. Keep issuance admission transactional and serialized; sample time only after admission locks. Preserve subsecond lifetimes. Consume under an owned row lock with a fresh time check and a database wall-clock guard. Bound retained records globally and per tenant, and meter presentation requests before store/cryptographic work.
**Tech Stack:** Existing .NET 9, C#, xUnit, Npgsql 9 and PostgreSQL 17 Testcontainers. No dependency/framework upgrade.
**Spec:** PR #16's table/migration proposal and recorded review findings. Direct owner approval received on 2026-10-27 is recorded at https://github.com/KoalaFacts/HeroSSID/pull/16#issuecomment-6428558421.

## Global constraints
- Resume `feat/postgres-presentation-challenges-20261025`, initially `1149bc82`; do not create a competing PR or change #17.
- Only temporary isolated CI databases may be exercised; no production data, migration, deployment or package publication.
- Do not suppress warnings, weaken security assertions or treat historical green CI as validation of new source.
- Native workspace has neither .NET nor GitHub DNS. Make leased Git object updates on the existing branch and use ordinary CI/Testcontainers for actual runtime evidence.
- All previously recorded technical gates remain; authorization does not itself establish correctness.

## Review focus
- Advisory-lock and row-lock waits must not reuse old timestamps.
- One-second challenges issued just before a second boundary remain usable for their requested lifetime; proof timestamps must not silently undo precision.
- Retained consumed records cannot bypass storage caps; a single verifier tenant cannot exhaust the default global allowance.
- Invalid, overlong and noncanonical lookup inputs must not reach PostgreSQL; failed verification attempts must spend the requesting tenant's quota.
- Collation, rollback, database-unavailability and independent-connection replay behavior must remain fail-closed.

## Task 1 — deterministic regressions, then lifetime fix
- [ ] Add PostgreSQL regressions that hold the real advisory/row lock, observe the waiting worker through pg_stat_activity, advance an injectable clock, release the lock and assert actual service behavior.
- [ ] Add fractional-second lifetime and retained-row ceiling regressions, plus invalid-input no-I/O cases.
- [ ] Run the ordinary Release/full test CI against unchanged production code; inspect failing test logs, not just job conclusions.
- [ ] Fix admission and consumption time sampling and timestamp precision without weakening replay binding.
- [ ] Run exact-head CI and check every failure.

## Task 2 — bounded resources and compatibility
- [ ] Add/observe regressions for tenant-retained capacity, request admission before lookups, and exact ordinal nonce/audience behavior.
- [ ] Implement bounded global/per-tenant retention and request admission, preserve original issuer/holder/verifier separation, and align index collation with comparisons.
- [ ] Update existing assertions only where the deliberately tightened contract changes; keep positive controls and full failure coverage.
- [ ] Update profile/README with precise synchronous I/O, clock, retention and quota limitations.

## Task 3 — integration gate
- [ ] Freeze candidate scope, run all normal CI jobs on the exact head, read actual logs and investigate failures.
- [ ] Obtain an independent review of the final source and resolve every blocking finding with tests.
- [ ] Mark ready and merge only with current-source evidence and review; verify main afterward. Otherwise preserve the draft with an exact handoff, not a false completion claim.
