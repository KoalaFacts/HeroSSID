# PR #16 challenge review remediation evidence

Scope: previously proposed optional PostgreSQL challenge backend and its known review defects. Direct owner approval on 2026-10-27 permits changes, temporary isolated Testcontainers tests and merge only after current-source tests and independent review pass. No production migration, database access, deployment or release.

## Observed failure evidence

- `135c63e32c4d8fd015ff344d98a08f3bae4e2b77`, [CI 40411181309](https://github.com/KoalaFacts/HeroSSID/actions/runs/40411181309): new regression source compiled under unchanged warning policy. Eight added integration cases failed; 17 existing integration cases passed. Failures exercised actual advisory/row locks, stale expiry/cleanup, 1ms lifetime instead of 1s, consumed-row capacity bypass and overlong lookups opening the database.
- `66a8adaf947e0c086ce8649a0ea0c1f45985900e`, [CI 40412326310](https://github.com/KoalaFacts/HeroSSID/actions/runs/40412326310), test job `121886478738`: Release 0 warnings/0 errors. Credentials 214 passed, seven new failed, two existing skipped. All seven new real-proof/admission cases failed at behavior assertions. Later suites were skipped by the normal fail-fast workflow, not claimed as tested.
- `f1f34c5538084a5352dabb02f8f0499b212f89d3` adds three acceptance cases for tenant ceilings and real PostgreSQL column collations. Do not claim these three were observed failing if the prior unit-test failure stopped CI before integration execution.

## Implementation candidate

`d8033baeee89de719dd829e04aa84a05caddfc64` repairs issuance/consumption timing, shared bounds, precision through the outer proof, post-consumption expiry checks, requester admission before store work and migration collation. The existing concurrent capacity test deliberately now asserts consumed rows remain charged until expiry and confirms cleanup/reissue and replay rejection. No warning suppression, filtered failure, new skip, framework or package upgrade.

At the time this evidence file was written, exact-candidate full CI and independent review were still pending. Subsequent authoritative completion evidence must name the exact source SHA and corresponding run/review, rather than treating this file or earlier green runs as certification.

## Rulings and limits

- Global storage ceiling counts all retained PostgreSQL rows, not only outstanding challenges. Memory removes consumed entries immediately; the stricter PostgreSQL retention behavior is documented.
- Default per-tenant cap is min(128, global cap), configurable by the constructor. All replicas must use the same settings.
- Outer proof timestamps use fractional NumericDates; original credential timestamp rules are unchanged. PostgreSQL expiry normalization loses less than one microsecond.
- Sync challenge creation uses a thread-pool bridge for the async limiter, preserving the existing synchronous API without capturing the caller synchronization context. It is not a scalability claim or asynchronous backend redesign.
- Application and database clocks must be synchronized. PostgreSQL checks actual wall-clock time in addition to the injected application clock; post-consumption verification rejects identity disclosure after proof/credential expiry.
- Disposable connections and replacement store objects are not independent-host restart/failover tests. Distributed request quotas, live operational recovery and wallet interoperability remain separate release gates.
- The native workspace has no .NET SDK or working GitHub DNS. Runtime evidence comes from the explicitly authorized ordinary CI and isolated PostgreSQL fixtures, not a claimed local build.
