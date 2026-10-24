# HeroSSID

**Trustworthy, portable identity credentials for people, organisations and agents.**

HeroSSID is a development-stage .NET foundation for issuing, holding and verifying identity credentials. A wallet can hold credentials and obtain holder-signed presentations through the library. The current implementation uses locally enrolled identities; external wallet interoperability and production operation remain release gates.

## Implemented capabilities and boundaries

| Area | Implemented | Current boundary |
|---|---|---|
| Identities | `did:key` creation, Ed25519 keys, locally stored DID resolution | Remote DID resolution, signing-key rotation and recovery are unfinished |
| REST ownership | Validated bearer `tenant_id`, exact operation scopes, tenant-owned DID creation and issuer lookup | An issuance-scope client can use any issuer DID owned by its tenant; per-client DID grants are future work |
| Credential issuance | Ed25519-signed JWT credentials and PostgreSQL persistence | Existing payloads use the 2018 credentials context; full VC 2.0 conformance is not established |
| Credential verification | Issuer signature, optional expiration and local revocation checks | REST verification resolves issuers within the authenticated tenant; direct library callers must inspect `IsValid` before using parsed result fields |
| Presentation library | Original issuer JWT embedded unchanged in a holder-signed `vp+jwt`; subject binding; verifier-owned trusted issuer, audience and single-use challenge | Full disclosure of one credential, local issuer/holder enrollment, process-local challenge storage; no presentation HTTP protocol endpoints |
| OAuth | Client-credentials tokens with configured HS256 signing and validated tenant/scopes | Full OpenID4VCI issuance and OpenID4VP exchange are unfinished |
| Key storage | Encrypted private-key storage through ASP.NET Data Protection; plaintext buffers cleared after signing | Managed signer/HSM integration and signing-key lifecycle are unfinished |
| Revocation | Verification rejects locally recorded revoked JWTs, including duplicate records | Revocation service API and interoperable status-list publication are unfinished |
| Selective disclosure | Legacy calls fail closed; mock SD-JWT implementations are not registered by default | Real selective disclosure and independent interoperability tests are unfinished |

Identity credentials express what an issuer attests. Whether that issuer is trusted for a particular claim, and what business actions a holder may take, remain explicit relying-party decisions. Enrollment alone does not establish a person's real-world identity.

## Local development

Prerequisites: .NET 9 SDK, a reachable PostgreSQL instance, and Docker for the container-backed integration/HTTP contract tests. The examples below bind development services to localhost.

```bash
git clone https://github.com/KoalaFacts/HeroSSID.git
cd HeroSSID
dotnet restore
dotnet build --configuration Release

# In a separate terminal, start a disposable development database.
docker run --rm --name herossid-dev-db \
  -e POSTGRES_DB=herossid -e POSTGRES_PASSWORD=postgres \
  -p 127.0.0.1:5432:5432 postgres:17
```

Configure the API and start it:

```bash
export ASPNETCORE_ENVIRONMENT=Development
export ConnectionStrings__HeroDb='Host=localhost;Port=5432;Database=herossid;Username=postgres'
export HEROSSID_DB_PASSWORD=postgres
export Jwt__Secret="$(openssl rand -base64 48)"
dotnet run --project src/Services/HeroSSID.Api --no-launch-profile --urls http://localhost:5139
```

`Jwt__Secret` is required in every environment. Missing, whitespace, shorter-than-32-byte UTF-8 values, NUL-containing values and the previous placeholder are rejected at startup. Use a stable managed secret outside disposable development; changing it invalidates outstanding access tokens. `Jwt__Issuer` and `Jwt__Audience` must be explicitly configured outside Development. In Development they default to `https://herossid.api`. They identify access-token validation policy, not a requirement that the local HTTP server use that hostname.

Development startup creates `test_client` / `test_secret` with `did:manage credential:issue credential:verify`. These are deliberately public local-development credentials. Existing seed rows are not overwritten: a retained development database needs `did:manage` explicitly granted to its test client. Production client provisioning is a separate operational responsibility.

```bash
curl http://localhost:5139/oauth2/token \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'client_id=test_client' \
  --data-urlencode 'client_secret=test_secret' \
  --data-urlencode 'scope=did:manage credential:issue credential:verify'
```

Use the returned `access_token` as `Authorization: Bearer <access_token>` on every identity/credential REST operation. Tokens must contain exactly one scalar JSON string `tenant_id` containing a non-empty GUID; duplicate raw JSON members and tenant arrays are rejected. Missing or invalid bearer identities receive 401; valid identities lacking the operation scope receive 403. Repeated `scope` claims and a space-separated scope claim are accepted with exact, case-sensitive matching.

| Operation | Required scope |
|---|---|
| `POST /api/v1/dids` | `did:manage` |
| `GET /api/v1/dids/{did}` | `did:manage` |
| `POST /api/v1/credentials/issue` | `credential:issue` |
| `POST /api/v1/credentials/verify` | `credential:verify` |

DID creation accepts `{"method":"did:key","keyType":"Ed25519"}`. Issuance accepts `issuerDid`, `holderDid`, `credentialType` and a non-empty `claims` object. Verification accepts `{"credential":"<issued JWT>"}`. Both issuer and holder must already be enrolled locally, and issuance uses only an issuer belonging to the token's tenant. See [the HTTP request examples](src/Services/HeroSSID.Api/HeroSSID.Api.http).

## Full-disclosure presentation library

Register `AddCredentialsServices()` alongside the database, key-encryption and rate-limiter dependencies. It registers a singleton challenge store and `TimeProvider.System`; a host can register its own implementations before this call.

```csharp
// Contexts come from trusted application authentication, never a request body's tenant ID.
var challenge = presentations.CreateChallenge(
    verifierContext, "https://verifier.example/credentials", trustedIssuerDid);

// This discloses the entire original credential, including every subject claim.
var presentation = await presentations.CreatePresentationAsync(
    holderContext, originalCredentialJwt, holderDidId, challenge, cancellationToken);

var result = await presentations.VerifyPresentationAsync(
    verifierContext, presentation.PresentationJwt,
    challenge.Audience, challenge.Nonce, cancellationToken);
```

Issuer, holder and verifier may belong to three different tenants. The verifier retains its own challenge and trusted-issuer policy. Successful verification consumes the challenge once; failed presentations return no disclosed claims or identity fields. Applications still need to evaluate credential type and business-specific claims before granting access.

Read [the presentation profile and migration notes](docs/presentation-profile.md) before integrating. This local full-disclosure profile is not SD-JWT or an OpenID4VP implementation.

## Verification and development

```bash
# Focused credential/auth suites (no PostgreSQL container required)
dotnet test tests/Unit/HeroSSID.Credentials.Tests --configuration Release
dotnet test tests/Unit/HeroSSID.Api.Tests --configuration Release

# Full solution: Docker must be available for PostgreSQL-backed suites.
dotnet test HeroSSID.sln --configuration Release
```

The default in-memory operation limiter now reserves permits atomically per tenant and operation. Issuance and presentation creation charge an attempt before costly work, even if it later fails. This protects one process only, not multiple replicas; alternative `IRateLimiter` implementations must provide atomic `TryAcquireAsync`. Legacy `IsAllowedAsync` plus `RecordOperationAsync` is for observation/recording, not enforcement.

The repository currently contains xUnit v2 and v3 projects. The credential suite retains two pre-existing skipped concurrency tests that use a shared DbContext; the new presentation replay test uses separate database scopes and a shared challenge store. PostgreSQL presentation tests also check that verification SQL does not select private-key columns. Test names containing “OpenID4VC” cover existing HTTP contracts and do not certify the unfinished protocols.

Production readiness requires durable shared challenge consumption, complete signing-key and revocation lifecycles, interoperability testing, operational controls and independent security review. No production-readiness or standards-conformance certification is claimed.

## Documentation

- [Vision and delivery milestones](docs/VISION.md)
- [Presentation profile and migration](docs/presentation-profile.md)
- [Trust foundation design](docs/superpowers/specs/2026-10-24-credential-trust-design.md)
- [Implementation and verification plan](docs/superpowers/plans/2026-10-24-credential-trust-foundation.md)
- [Testing guide](docs/testing-guide.md)

The applicable upstream specifications include [DID Core](https://www.w3.org/TR/did-core/), [VC Data Model](https://www.w3.org/TR/vc-data-model-2.0/), [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) and [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html). These are implementation targets; linking them is not a conformance assertion.
