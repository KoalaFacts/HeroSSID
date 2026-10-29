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
| Presentation library | Original issuer JWT embedded unchanged in a holder-signed `vp+jwt`; local and standalone offline Ed25519 holder + issuer signature verification; verifier-owned trusted issuer, audience and single-use challenge | Full disclosure of one credential; offline check needs an independently trusted issuer policy and a verifier-owned replay store; process-local default, opt-in shared PostgreSQL; no presentation HTTP exchange endpoint |
| OAuth | Client-credentials tokens with configured HS256 signing and validated tenant/scopes | Full OpenID4VCI issuance and OpenID4VP exchange are unfinished |
| Key storage | Encrypted private-key storage through ASP.NET Data Protection; plaintext buffers cleared after signing | Managed signer/HSM integration and signing-key lifecycle are unfinished |
| Revocation | Issuer-only `POST /api/v1/credentials/revoke` atomically revokes the exact locally issued JWT; subsequent credential and presentation verification reject it | Local issuer database only: no signed/public interoperable status-list publication, independent wallet lookup or external trust policy |
| Selective disclosure | Legacy calls fail closed; mock SD-JWT implementations are not registered by default | Real selective disclosure and independent interoperability tests are unfinished |

New `did:key` documents use the [Ed25519VerificationKey2020 document profile](docs/did-key-profile.md), including a multicodec-prefixed key and `assertionMethod`. Already persisted documents are **not** rewritten. Scoped clients can explicitly request `GET /api/v1/dids/{did}/canonical` to derive a current-format DID document from a stored public key **only after verifying that the key matches the exact DID**. Missing, foreign, deactivated, invalid-key records are not published by this path; the ordinary DID resolution path still returns the stored historical representation. This does not establish a public DID resolver or wallet interoperability. See the [legacy compatibility boundary](docs/did-key-profile.md).

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

## Issuer-signed revocation snapshot export (HeroSSID profile)

An issuer with `credential:revoke` scope can call `POST /api/v1/credentials/revocation-snapshot`
with `{"issuerDid":"did:key:z..."}` after issuing and optionally revoking JWT credentials.
The API returns a **one-minute Ed25519-signed JWS snapshot** of the complete set
of revoked credential JWT SHA-256 digests for that active, tenant-owned
self-certifying issuer DID. It never returns the original JWTs or holder claims.
An issuer may explicitly distribute the resulting artifact to independent
verifiers, who can use `IssuerRevocationSnapshot.Check` offline with a previously
trusted issuer DID/public key and the original credential. `Revoked` means
that JWT's digest appears in the signed set; `NotListed` is **not**
proof of valid issuance or active status. Verifiers must separately validate
the original credential's signature, expiry, holder binding, issuer trust
and business authorization; publication is not automatic.

Snapshots contain a maximum of 256 revoked records; exports above that
limit fail with HTTP 409 rather than sign a partial list. Snapshots expire at most 60 seconds after the revocation-status read begins,
not 60 seconds after signing completes. Database and signing delays shorten
usable lifetime; exports that exceed this budget return HTTP 503 without a
snapshot. The issuer must refresh after each revocation; old exported copies
can remain stale until their expiry. Revoked
JWT digests are linkable by parties who possess those JWTs, and the count
is disclosed to recipients. This is a bounded **HeroSSID-specific signing
and offline-check profile**, not a W3C Bitstring Status List, a hosted
public status endpoint, general non-revocation proof or independent wallet
conformance result. The database schema is unchanged. See
[the threat model and verification instructions](docs/revocation-snapshot-profile.md).

## Offline issuer credential and revocation verification

A separate .NET relying party can now call `OfflineCredentialVerifier.Check`
with its **independently trusted issuer `did:key`**, an original signed
`vc+jwt`, and a short-lived signed snapshot. It derives the self-certifying
Ed25519 key from that DID and checks both signatures, credential structure,
issuance/not-before/expiry, and status without the issuing database.
Outcomes are `Invalid`, `Revoked`, or `SignedNotListed`; the last
means **signed and absent from this snapshot**, not registered, unrevoked
in real time, proof of holder control, or business authorization. See
[the offline verifier acceptance and limitations](docs/offline-credential-verification.md).
This remains the HeroSSID private JWT profile, not independent-wallet or
VC-standard conformance.

## Offline holder-signed presentation verification (HeroSSID profile)

A separate .NET verifier can now validate **the actual holder's Ed25519
signature** over a full-disclosure `vp+jwt`, the *unchanged* issuer-signed
`vc+jwt` inside it, and a fresh **issuer-signed** revocation snapshot,
without issuer database access. The verifier first chooses a trusted issuer
under its own policy and issues an unpredictable single-use challenge:

```csharp
// The verifier provisions and owns the same challenge store for issuance and checks.
// Use a shared PostgreSQL implementation for replay protection across replicas.
var clock = TimeProvider.System;
IPresentationChallengeStore challenges = new InMemoryPresentationChallengeStore(clock);
var verifierTenantId = Guid.NewGuid(); // replace with the authenticated verifier tenant
var request = challenges.Issue(verifierTenantId,
    "https://verifier.example/check", independentlyTrustedIssuerDid);

// Give request.Audience, request.Nonce and request.ExpiresAt to the holder.
// Receive a full-disclosure holder-signed vp+jwt and a separately issued
// short-lived issuer-signed revocation snapshot through a trusted workflow.
var outcome = OfflinePresentationVerifier.Check(
    holderPresentationJwt, issuerSignedSnapshotJwt, verifierTenantId,
    request.Audience, request.Nonce, challenges, clock);
```

`SignedNotListed` means the **real issuer and holder signatures** and
challenge binding passed, the revocation snapshot does not list the original
JWT, and the challenge was consumed **atomically exactly once**. `Revoked`
means the verified original JWT appears in the authentic snapshot. All other
errors including forgery, wrong subject/issuer, replay, tampering, expired
proof/status or mismatched audience fail closed as `Invalid`. No rejected
claims or holder identifiers are returned. A valid `did:key` is a
self-certifying public key, **not** evidence that a real-world person was
enrolled. A relying party still needs issuer trust, claim policy and business
authorization; `SignedNotListed` is not proof of live issuer status.

This is a **library integration** of the HeroSSID full-disclosure profile,
not a deployed endpoint, independent third-party wallet test, SD-JWT or
OpenID4VP implementation. Direct consumers must limit request volume and
handle challenge-store failures; the memory store loses pending challenges on
restart and cannot prevent cross-process replay. See
[the presentation profile](docs/presentation-profile.md) and
[offline issuer verification limits](docs/offline-credential-verification.md).

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
