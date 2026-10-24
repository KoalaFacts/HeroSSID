# Identity credential trust foundation

## Intent

HeroSSID provides trustworthy, portable identity credentials for people, organisations and agents. The user authorised implementation after reviewing the current gaps and explicitly delegated routine implementation choices. This first delivery closes existing trust-boundary defects; it does not claim OpenID4VC interoperability or selective disclosure is complete.

## Design decisions

- Retain C#/.NET 9, existing xUnit projects, PostgreSQL schema and existing Ed25519 primitives. Do not introduce migrations, payment features or cryptographic algorithms.
- Authenticate REST DID/credential operations with validated OAuth bearer tokens. Derive tenant identity from exactly one non-empty GUID `tenant_id` claim. Enforce explicit operation scopes. OAuth clients with issuance scope act for their tenant's issuers; finer per-client DID grants remain future work.
- Require configured JWT signing secrets; reject missing, placeholder, NUL-containing or short keys at startup. Require explicit issuer/audience outside Development and preserve upstream secret-safe diagnostics. Keep issuer/audience configuration consistent between token issuance and validation.
- Replace the misleading mock presentation path with an explicitly documented, full-disclosure JWT presentation profile that embeds the original signed credential. A holder signature wraps the original issuer signature; it never replaces it. Reject selective-disclosure requests until a real implementation is integrated.
- Require verifier audience and a fresh verifier challenge that names the issuer the verifier trusts for this request. Validate the original credential, subject-to-holder binding, both active keys, expiry and revocation. Verification consumes an issued challenge atomically only after all checks succeed. A process-local bounded challenge store is suitable only for this development profile; restart rejects outstanding challenges, and multi-instance persistence remains a release gate.
- Presentation verification uses the locally enrolled issuer and holder public records. It must not retrieve their private keys. Enrolment is an explicit closed-system trust boundary; remote trust resolution remains future work.
- Require canonical compact JWT encoding and reject duplicate JSON fields. This prevents alternate signature encodings from escaping the existing exact-token revocation lookup. Credential issuance time is required by this profile; optional expiration/not-before values are enforced. The outer proof lasts at most five minutes and never outlives its challenge or credential.

## Alternatives considered

1. Disable presentation support completely: smallest safe change but no usable credential lifecycle demonstration.
2. Preserve the original credential in a holder-signed full-disclosure presentation: selected by the implementer because existing signing primitives can support a meaningful, testable trust boundary without pretending to implement SD-JWT.
3. Implement all SD-JWT and OpenID4VC flows now: wider scope with external dependencies and interoperability requirements; tracked as follow-up work.

## Acceptance

Two authenticated tenants create identities without crossing ownership boundaries. A valid issuance-scope token can issue only from its tenant. Missing/malformed tenant claims and missing scopes are rejected. A holder presents an unmodified issuer-signed credential to a verifier's challenge. Forged issuer signatures, wrong holders, wrong audience/nonce, expired/deactivated/revoked identities or credentials and repeated submissions fail without exposing verified claims. Valid full-disclosure presentations preserve the actual issuer identity. No mock SD-JWT service is registered by the default credential registration.

## Verification and limits

Use real Ed25519 keys and application-level tests. Observe regression failures before fixes, then targeted tests, full local build and available suites, followed by ordinary CI for PostgreSQL integration coverage and independent review. No released package, deployed service, external identity registration or production database mutation is authorised by this implementation step. The owner already authorised routine code delivery and existing merge policy remains applicable.
