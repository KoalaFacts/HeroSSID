# Identity credential trust foundation: verification record

Baseline: `243f2617a1ed4535359703db83a13c48eba167e1` (main). Scope: authenticated tenant/scopes and issuer-preserving full-disclosure presentations. No database migration, package release or deployment is included.

## Failures reproduced before fixes

| Regression | Observed before the fix |
|---|---|
| Forged original credential wrapped by holder | Presentation verification returned valid |
| Credential issued to a different holder | Presentation verification returned valid |
| Revoked JWT with equivalent padded signature encoding | Direct credential verification returned valid |
| Real HTTP tenant/scopes/configuration matrix | 19 failed / 2 passed: fixed tenant, missing enforcement, unsafe JWT defaults and an overlong stored secret hash |
| Malformed Unicode in header/payload/subject | Three unhandled decoding exceptions and one accepted invalid nested subject |
| Duplicate exact-token records, one active and one revoked | A correctly signed presentation was accepted when the active record was selected first |
| Signed raw duplicate tenant members or a singleton tenant array | 4 failed / 5 passed: ambiguous requests created DIDs rather than returning 401 |
| Request-accounting follow-up charged issuer during cross-tenant presentations | Three new regressions failed: forged creation/verification exhausted a different issuer's quota; a valid three-tenant flow failed with a quota of one |

Regression tests use real Ed25519 or HS256 signatures and real HTTP middleware. Malicious presentations are signed independently of the legitimate creation service, so creation-side rejection cannot conceal a verification defect.

## Verification approach

- Restore and build the complete .NET 9 solution with repository analyzers and warnings-as-errors enabled.
- Run credential, API, general, data, DID unit tests and pure DID contracts locally.
- Run PostgreSQL-backed integration and HTTP contracts through ordinary CI; the local environment has no Docker daemon.
- Independently review presentation and authorization changes. Reproduce review findings, fix them and obtain a narrow recheck.
- Check the final candidate commit's CI before integration. No test exclusions or relaxed security assertions were introduced to obtain a pass.

At the integrated checkpoint `6ed40d8`, before the request-accounting follow-up below, concurrent main commit `b92ec65b8b3f2e66fdee7038efbab3fa204baddf` (PRs #11–#13) was retained. The complete local runnable set reported **389 passed, 0 failed, 2 pre-existing skips**:

| Suite | Passed | Skipped |
|---|---:|---:|
| Credentials | 199 | 2 |
| API | 101 | 0 |
| General unit | 21 | 0 |
| Data unit | 3 | 0 |
| DID unit | 58 | 0 |
| Pure DID contracts | 7 | 0 |

The full merged Release build reports **0 warnings and 0 errors**. Upstream canonical-signature/pad-bit tests, NUL-key rejection, production issuer/audience requirements and issuance authorization coverage are retained. The authentication integration received an additional independent review with no remaining blocker. [PR #14](https://github.com/KoalaFacts/HeroSSID/pull/14) records final PostgreSQL CI and integration status.

That checkpoint's [ordinary cloud CI](https://github.com/KoalaFacts/HeroSSID/actions/runs/40102925879) subsequently passed **435 tests with zero failures and two existing skips**, including 33 OpenID4VC HTTP contracts and 13 PostgreSQL integration tests. Both push and PR test jobs produced those counts. These results apply to `6ed40d8`; subsequent commits require their own CI checks.

The two existing credential skips concern concurrent operations sharing one DbContext. New presentation concurrency coverage uses separate database scopes with a singleton challenge store and requires exactly one successful acceptance. The PostgreSQL presentation test also inspects executed SELECT commands to ensure verification does not retrieve encrypted private-key columns.

## Independent review and resolutions

The presentation review confirmed stored verifier policy, original issuer signature preservation, holder binding, public-only verification queries and atomic challenge consumption. It found deferred malformed-Unicode decoding and duplicate-record revocation ambiguity. Both were reproduced and corrected; the reviewer rechecked the fixes without a remaining blocker. Added tests also cover time advancing during verification, credential-bounded outer expiry and nested duplicate claims.

The authorization review confirmed validated token ownership, exact scopes, consistent signing configuration and fixed-time client-secret comparison. It identified duplicate raw `tenant_id` JSON member normalization as a strict acceptance gap. The follow-up rejects ambiguous raw representations before accepting normalized claims. Its API suite passes 66 tests; the independent reviewer reran the original HTTP reproduction, observed 401 and approved the narrow recheck. The delivery PR records final integrated test results.

## Request-accounting follow-up

Commit `a7039e2` correctly began recording credential-verification attempts before parsing, but independent review reproduced a cross-tenant accounting regression. Presentation delegation used the enrolled issuer's tenant for data lookup; recording against that same context let forged requests exhaust the issuer's allowance. The PR was returned to draft while this concrete finding was fixed. The original malformed/valid-request accounting tests are retained.

The corrected implementation separates requester accounting from issuer lookup in one shared verification core. The original tenant-local method passes the same trusted tenant for both roles; the presentation method receives the original holder/verifier context and the issuer tenant resolved from its enrolled public record. Both DID and revoked-token predicates retain the issuer tenant filter. Empty tenant identities fail closed. The REST endpoint remains tenant-local, and its test double rejects any accidental call to the cross-issuer method.

Three real-key, real-limiter regression tests were observed failing before this correction, then passing. An independent .NET 9 harness also verified both forgery paths: two invalid attempts exhaust only the attacker requester, a third is blocked, the victim issuer remains usable, and the challenge/unrelated tenant remain intact. A legitimate three-tenant create/verify/direct-verification flow succeeds with one operation available to each tenant. The focused re-review found no remaining blocker.

After the correction, the full Release solution builds with **zero warnings and zero errors**. The credential suite reports **208 passed, zero failed and two existing skips**; the API suite reports **101 passed and zero failed**. Final cloud CI and current-commit automated review remain recorded on [PR #14](https://github.com/KoalaFacts/HeroSSID/pull/14), rather than inferred from the earlier checkpoint.

## Remaining boundaries

The new presentation profile discloses one entire credential and uses local issuer/holder enrollment and process-local challenge storage. Remote DID trust, full OpenID4VCI/OpenID4VP exchange, real selective disclosure, production shared challenges and atomic request quotas, signing-key rotation/recovery and a complete revocation/status-list API remain unfinished. No standards certification or production-readiness claim follows from this verification.

Direct credential-verifier library results retain their older parsed-field behavior on some failures; callers must require `IsValid`. The REST adapter and all presentation failure results suppress identity fields. Business credential-type/claim policy remains the relying application's responsibility.
