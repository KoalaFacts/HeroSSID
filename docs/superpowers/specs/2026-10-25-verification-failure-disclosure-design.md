# Fail-closed credential verification results

## Goal and authority
The owner requested continued, independently verifiable identity-credential improvements and explicitly included information exposure on failure. This small change removes identity data from rejected credential results. It does not expand issuance or business authority.

## Existing behavior and approach
`CredentialVerificationService.CreateFailedResult` currently accepts and returns parsed subject claims, issuer DID and expiration after expiration/issuer/signature/revocation rejection. REST already hides those fields; direct library callers do not get that safeguard.

Alternatives: retain the documented caller-side check; sanitize the public result object's getters; or fix the producer. Choose the producer: remove identity arguments from the private failure factory and its call sites. Keep the successful result and the public result shape unchanged. Failure still carries `IsValid=false`, the precise status and diagnostic messages, but `CredentialSubject`, `IssuerDid` and `ExpiresAt` are null. Expiry errors should not echo the parsed timestamp.

## Scope
No database schema, migration, challenge-store implementation, protocol, framework or dependency change relative to main. PR #16 has merged at `b101b56ada49313be646d0cb6cf8565a68c918eb`; its existing CI fixtures are unchanged by this PR. No production database action, release, deployment or merge on partial evidence.

## Acceptance
Both tenant-local and explicit-issuer-tenant verification reject tampered real signatures, expired credentials, unknown/deactivated issuers, revoked credentials and malformed inputs without returning identity fields. Serializing those failure results must not reveal the subject marker or issuer DID. Valid real signatures, including credentials without expiration, must still return their verified data. Existing quota and tenant isolation behavior stays unchanged.

## Verification boundary
The original environment lacked a usable .NET SDK and GitHub DNS; the historical focused Actions comparison did not constitute full CI acceptance. The resumed local environment has SDK 9.0.319/runtime 9.0.21. After integrating main, strict Release compilation and all separable non-PostgreSQL suites must pass, including the new EF InMemory/real-NSec tests. The expired numeric-date regression must assert no returned identity fields; signed positive controls preserve nested subject coverage. Existing normal hosted CI, including its unchanged isolated PostgreSQL fixtures, remains applicable. Do not weaken CI or describe local non-PostgreSQL evidence as full integration acceptance. Keep the product PR draft until final-source validation and independent review are satisfied.
