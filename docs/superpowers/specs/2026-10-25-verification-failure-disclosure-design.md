# Fail-closed credential verification results

## Goal and authority
The owner requested continued, independently verifiable identity-credential improvements and explicitly included information exposure on failure. This small change removes identity data from rejected credential results. It does not expand issuance or business authority.

## Existing behavior and approach
`CredentialVerificationService.CreateFailedResult` currently accepts and returns parsed subject claims, issuer DID and expiration after expiration/issuer/signature/revocation rejection. REST already hides those fields; direct library callers do not get that safeguard.

Alternatives: retain the documented caller-side check; sanitize the public result object's getters; or fix the producer. Choose the producer: remove identity arguments from the private failure factory and its call sites. Keep the successful result and the public result shape unchanged. Failure still carries `IsValid=false`, the precise status and diagnostic messages, but `CredentialSubject`, `IssuerDid` and `ExpiresAt` are null. Expiry errors should not echo the parsed timestamp.

## Scope
No database schema, migration, PostgreSQL execution, challenge-store implementation, protocol, framework or dependency change. PR #16 and its database approval hold remain untouched. No release, deployment or merge on partial evidence.

## Acceptance
Both tenant-local and explicit-issuer-tenant verification reject tampered real signatures, expired credentials, unknown/deactivated issuers, revoked credentials and malformed inputs without returning identity fields. Serializing those failure results must not reveal the subject marker or issuer DID. Valid real signatures, including credentials without expiration, must still return their verified data. Existing quota and tenant isolation behavior stays unchanged.

## Verification boundary
The current local execution environment has no .NET SDK and cannot resolve GitHub. Use a separate, read-only-permissions GitHub Actions verification branch to run only the existing non-PostgreSQL suites and the new EF InMemory/real-NSec tests. Ordinary push/PR runs must not be triggered while database permission is unresolved. Do not weaken the repository's normal CI or claim this focused evidence is full CI. The product PR remains draft until required integration evidence and review are satisfied.
