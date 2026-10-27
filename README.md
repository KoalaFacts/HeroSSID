# HeroSSID

**Trustworthy, portable identity credentials for people, organisations and agents.**

HeroSSID is a development-stage .NET foundation for issuing, holding and verifying identity credentials. A wallet can hold credentials and obtain holder-signed presentations through the library. The current implementation uses locally enrolled identities; external wallet interoperability and production operation remain release gates.

## Implemented capabilities and boundaries

| Area | Implemented | Current boundary |
|---|---|---|
| Identities | `did:key` creation, Ed25519 keys, locally stored DID resolution | Remote DID resolution, signing-key rotation and recovery are unfinished |
| REST ownership | Validated bearer `tenant_id`, exact operation scopes, tenant-owned DID creation and issuer lookup | An issuance-scope client can use any issuer DID owned by its tenant; per-client DID grants are future work |
| Credential issuance | Ed25519-signed JWT credentials and PostgreSQL persistence | Existing payloads use the 2018 credentials context; full VC 2.0 conformance is not established |
| Credential verification | Enrolled issuer signature, required holder/issuance/type/subject structure, optional enforced `nbf`/expiration, local revocation checks; no identity fields on rejection | Local `vc+jwt` profile only; REST lookup is tenant-scoped, not independent issuer trust or business authorization |
| Presentation library | Original issuer JWT embedded unchanged in a holder-signed `vp+jwt`; subject binding; verifier-owned trusted issuer, audience and single-use challenge | Full disclosure of one credential, local issuer/holder enrollment, process-local challenge storage by default (opt-in PostgreSQL shared store available); no presentation HTTP protocol endpoints |
| OAuth | Client-credentials tokens with configured HS256 signing and validated tenant/scopes | Full OpenID4VCI issuance and OpenID4VP exchange are unfinished |
| Key storage | Encrypted private-key storage through ASP.NET Data Protection; plaintext buffers cleared after signing | Managed signer/HSM integration and signing-key lifecycle are unfinished |
| Revocation | Issuer-only `POST /api/v1/credentials/revoke` atomically revokes the exact locally issued JWT; subsequent credential and presentation verification reject it | Local issuer database only: no signed/public interoperable status-list publication, independent wallet lookup or external trust policy |
| Selective disclosure | Legacy calls fail closed; mock SD-JWT implementations are not registered by default | Real selective disclosure and independent interoperability tests are unfinished |

Identity credentials express what an issuer attests. Whether that issuer is trusted for a particular claim, and what business actions a holder may take, remain explicit relying-party decisions. Enrollment alone does not establish a person's real-world identity.

## Local development

Prerequisites: .NET 10 SDK (LTS; projects target `net10.0`), a reachable PostgreSQL instance, and Docker for the container-backed integration/HTTP contract tests. The examples below bind development services to localhost.

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

Development startup creates `test_client` / `test_secret` with `did:manage credential:issue credential:verify credential:revoke`. These are deliberately public local-development credentials. Existing seed rows are not overwritten: a retained development database needs any new operation scopes explicitly provisioned to its test client; seeding does not elevate existing clients. Production client provisioning is a separate operational responsibility.

```bash
curl http://localhost:5139/oauth2/token \
  --data-urlencode 'grant_type=client_credentials' \
  --data-urlencode 'client_id=test_client' \
  --data-urlencode 'client_secret=test_secret' \
  --data-urlencode 'scope=did:manage credential:issue credential:verify credential:revoke'
```

Use the returned `access_token` as `Authorization: Bearer <access_token>` on every identity/credential REST operation. Tokens must contain exactly one scalar JSON string `tenant_id` containing a non-empty GUID; duplicate raw JSON members and tenant arrays are rejected. Missing or invalid bearer identities receive 401; valid identities lacking the operation scope receive 403. Repeated `scope` claims and a space-separated scope claim are accepted with exact, case-sensitive matching.

| Operation | Required scope |
|---|---|
| `POST /api/v1/dids` | `did:manage` |
| `GET /api/v1/dids/{did}` | `did:manage` |
| `POST /api/v1/credentials/issue` | `credential:issue` |
| `POST /api/v1/credentials/verify` | `credential:verify` |
| `POST /api/v1/credentials/revoke` | `credential:revoke` |

DID creation accepts `{"method":"did:key","keyType":"Ed25519"}`. Issuance accepts `issuerDid`, `holderDid`, `credentialType` and a non-empty `claims` object. Verification and issuer revocation both accept `{"credential":"<issued JWT>"}`. Revocation requires its **own** scope, not simply `credential:issue` or possession of the JWT; only exact credentials stored under the authenticated tenant and its issuer DID can be revoked. It returns `204` on first or repeated revocation, `404` for unknown/foreign credentials without distinguishing them, and `400` on malformed inputs. Revoked credentials fail closed during local direct verification and library presentation; a remote wallet/verifier is **not** independently notified. This operation is not a W3C status list. Verification accepts `{"credential":"<issued JWT>"}`. Both issuer and holder must already be enrolled locally, and issuance uses only an issuer belonging to the token's tenant. See [the HTTP request examples](src/Services/HeroSSID.Api/HeroSSID.Api.http).

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

Outer presentation timestamps support fractional NumericDates so a one-second challenge does not lose nearly its entire lifetime at a second boundary. Old integer timestamps remain accepted. Both proof and credential expiry are rechecked after blocking consumption; rejection after consumption leaves the nonce spent. The original credential timestamp profile is unchanged.

Read [the presentation profile and migration notes](docs/presentation-profile.md) before integrating. This local full-disclosure profile is not SD-JWT or an OpenID4VP implementation.

## Credential verification result safety

A successful direct `vc+jwt` verification now requires signed, non-empty `iss` and `sub`, integer `iat` no later than the verification clock, and an object `vc.credentialSubject`. The `vc.type` array must contain `VerifiableCredential` and every entry must be a non-blank string. Existing signed singleton-base credentials remain valid, as does the issuer API’s duplicate-base output when that credential type is requested. This structural check does not itself establish a specific qualification or business authorization. If the subject has an `id`, it must equal `sub`. A supplied integer `nbf` must not be in the future. Missing or `null` expiration remains supported; a supplied expiration must be a valid integer and must not have passed. Violations return `MalformedJwt`, except expired credentials return `Expired`. These checks establish neither independent wallet compatibility nor the verifier's authorization to act for the holder.

`VerifyCredentialAsync` and `VerifyCredentialFromIssuerAsync` return `CredentialSubject`, `IssuerDid` and `ExpiresAt` only for successful verification. Every rejected result leaves those fields null, while preserving `IsValid=false`, its status and diagnostic errors. Expiry errors no longer echo the parsed timestamp. This is an intentional tightening of the library contract: integrations that previously used parsed metadata from rejected results must stop relying on those values. Valid credential results are unchanged; consumers must still check `IsValid` and apply issuer trust and business authorization policy.

The `.NET 10` retarget changes the required runtime and patched ASP.NET Core, EF Core, Npgsql, Aspire and OpenIddict dependencies. Before upgrading an existing deployment, review runtime/container image compatibility and test the prior database schema and persisted token/credential behaviour in an isolated environment; upgrading a production runtime or applying migrations is not part of the source-code change.

## Verification and development

```bash
# Focused credential/auth suites (no PostgreSQL container required)
dotnet test tests/Unit/HeroSSID.Credentials.Tests --configuration Release
dotnet test tests/Unit/HeroSSID.Api.Tests --configuration Release

# Full solution: Docker must be available for PostgreSQL-backed suites.
dotnet test HeroSSID.sln --configuration Release
```

DID key creation relies on NSec's cryptographic provider for randomness. It no longer draws and rejects a separate 256-byte sample using chi-square/uniqueness thresholds: a statistically unusual but legitimate CSPRNG sample is not evidence that its provider failed. Provider errors still abort creation, and exported Ed25519 keys must have the correct lengths, contain no all-zero key material and pass a real sign/verify self-check before storage; failed exported-key checks scrub both buffers. These are operational safeguards, not a certification of the host RNG or external wallet interoperability.

The default in-memory limiter reserves permits atomically per tenant and operation. Challenge creation and presentation verification now also reserve permits before challenge-store I/O, including unknown-nonce attempts. Issuance and presentation creation charge attempts before costly work, even on failure. This protects one process only, not multiple replicas; alternative `IRateLimiter` implementations must provide atomic `TryAcquireAsync`. Legacy `IsAllowedAsync` plus `RecordOperationAsync` is for observation/recording, not enforcement.

The repository currently contains xUnit v2 and v3 projects. The credential suite retains two pre-existing skipped concurrency tests that use a shared DbContext; the presentation replay test uses separate database scopes and a shared challenge store. PostgreSQL tests exercise real advisory/row-lock waits and check that verification SQL does not select private-key columns. Test names containing “OpenID4VC” cover existing HTTP contracts, not certification. Replacement store objects and connections are not independent-machine restart/failover tests.

A PostgreSQL challenge store is an opt-in alternative to the process-local default. Apply the `PresentationChallenges` migration explicitly before enabling it, then register the shared data source and store **before** `AddCredentialsServices()`:

```csharp
services.AddSingleton(Npgsql.NpgsqlDataSource.Create(postgresConnectionString));
services.AddSingleton<IPresentationChallengeStore, PostgresPresentationChallengeStore>();
services.AddCredentialsServices();
```

Every replica must use the same database and capacity configuration. Defaults are 1,024 globally and 128 per verifier tenant (or the smaller global limit). PostgreSQL counts **all retained rows**, including consumed replay tombstones, until expiry; memory removes consumed entries immediately. Constructors allow an explicit `tenantCapacity`. Admission serializes cleanup, counting and insertion under a transaction/advisory lock. Consumption obtains the matching row lock and performs a fresh-time conditional update. Both operations fail closed on database failure; application and database clocks must be synchronized.

The nonce primary key and audience storage use `C` collation to match ordinal queries. The unreleased migration was amended during review: recreate or explicitly reconcile disposable databases that applied an earlier draft; migration history does not automatically reapply changed definitions. Do not apply or roll back a production migration merely because CI passes. Public synchronous store methods block on PostgreSQL; synchronous challenge creation also waits for limiter admission. Account for thread-pool demand, database timeouts, cleanup and autovacuum. Distributed request quotas and OpenID4VP HTTP remain unfinished.

Production readiness still requires shared challenge deployment and operations, distributed request quotas, complete signing-key and revocation lifecycles, interoperability testing, operational controls and independent security review. No production-readiness or standards-conformance certification is claimed.

## Documentation

- [Vision and delivery milestones](docs/VISION.md)
- [Presentation profile and migration](docs/presentation-profile.md)
- [Trust foundation design](docs/superpowers/specs/2026-10-24-credential-trust-design.md)
- [Implementation and verification plan](docs/superpowers/plans/2026-10-24-credential-trust-foundation.md)
- [Challenge remediation evidence](docs/verification/2026-10-27-challenge-review.md)
- [Testing guide](docs/testing-guide.md)

The applicable upstream specifications include [DID Core](https://www.w3.org/TR/did-core/), [VC Data Model](https://www.w3.org/TR/vc-data-model-2.0/), [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) and [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html). These are implementation targets; linking them is not a conformance assertion.
