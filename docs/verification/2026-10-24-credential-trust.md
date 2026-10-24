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

Regression tests use real Ed25519 or HS256 signatures and real HTTP middleware. Malicious presentations are signed independently of the legitimate creation service, so creation-side rejection cannot conceal a verification defect.

## Verification approach

- Restore and build the complete .NET 9 solution with repository analyzers and warnings-as-errors enabled.
- Run credential, API, general, data, DID unit tests and pure DID contracts locally.
- Run PostgreSQL-backed integration and HTTP contracts through ordinary CI; the local environment has no Docker daemon.
- Independently review presentation and authorization changes. Reproduce review findings, fix them and obtain a narrow recheck.
- Check the final candidate commit's CI before integration. No test exclusions or relaxed security assertions were introduced to obtain a pass.

At the integrated presentation checkpoint, the credential suite reports **196 passed, 0 failed, 2 pre-existing skips**; general unit **21**, data unit **3**, DID unit **58** and pure DID contract **7** pass. The final authorization slice reports **66 passed**, including raw-JSON duplicate-tenant and HS384 rejection cases. The full solution build reports **0 warnings and 0 errors**. The delivery PR records final counts and exact-commit CI results.

The two existing credential skips concern concurrent operations sharing one DbContext. New presentation concurrency coverage uses separate database scopes with a singleton challenge store and requires exactly one successful acceptance. The PostgreSQL presentation test also inspects executed SELECT commands to ensure verification does not retrieve encrypted private-key columns.

## Independent review and resolutions

The presentation review confirmed stored verifier policy, original issuer signature preservation, holder binding, public-only verification queries and atomic challenge consumption. It found deferred malformed-Unicode decoding and duplicate-record revocation ambiguity. Both were reproduced and corrected; the reviewer rechecked the fixes without a remaining blocker. Added tests also cover time advancing during verification, credential-bounded outer expiry and nested duplicate claims.

The authorization review confirmed validated token ownership, exact scopes, consistent signing configuration and fixed-time client-secret comparison. It identified duplicate raw `tenant_id` JSON member normalization as a strict acceptance gap. The follow-up rejects ambiguous raw representations before accepting normalized claims. Its API suite passes 66 tests; the independent reviewer reran the original HTTP reproduction, observed 401 and approved the narrow recheck. The delivery PR records final integrated test results.

## Remaining boundaries

The new presentation profile discloses one entire credential and uses local issuer/holder enrollment and process-local challenge storage. Remote DID trust, full OpenID4VCI/OpenID4VP exchange, real selective disclosure, production shared challenges, signing-key rotation/recovery and a complete revocation/status-list API remain unfinished. No standards certification or production-readiness claim follows from this verification.

Direct credential-verifier library results retain their older parsed-field behavior on some failures; callers must require `IsValid`. The REST adapter and all presentation failure results suppress identity fields. Business credential-type/claim policy remains the relying application's responsibility.
