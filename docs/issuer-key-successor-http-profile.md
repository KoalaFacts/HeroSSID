# Issuer key successor verification over HTTP (private HeroSSID profile)

This authenticated verifier API turns the existing
[`IssuerKeySuccessorAttestation` dual-Ed25519 SDK proof](issuer-key-successor-profile.md)
into an **operable one-time HTTP verifier check**. It reuses the existing
PostgreSQL `presentation_challenges` storage. There is **no new schema,
migration, production enrollment, trusted-issuer list mutation or key custody**.

This is **not** DID key rotation: a `did:key` never changes its public key.
The verifier must already trust the *previous* issuer DID through independent
policy, and an accepted successor remains a **proposed** DID only.

## 1. Verifier issues a short-lived challenge

```http
POST /api/v1/credentials/issuer-successor/challenge
Authorization: Bearer <credential:verify scoped verifier token>
Content-Type: application/json

{"audience":"https://verifier.example/issuer-successor","previousIssuerDid":"did:key:z...","lifetimeSeconds":120}
```

**201 Created** returns `audience`, a random one-use `nonce`,
`trustedPreviousIssuerDid` and `expiresAt`. The nonce is stored under
the authenticated verifier tenant with a separate `issuer-successor:`
storage-purpose namespace, so a holder-presentation challenge cannot be
consumed as a key-successor challenge. All replicas must share the PostgreSQL
store and the already-migrated challenge table. The verifier chooses the
**old** issuer identity. A caller cannot replace it in the later verify call.

The challenge response is **unsigned**. Before either key controller signs,
the issuer must independently authenticate the verifier, its HTTPS audience,
the old issuer policy, and the fresh nonce. An untrusted party can otherwise
ask two keys to sign a misleading transition.

An anonymous request returns **401**, missing `credential:verify` **403**,
an invalid issuer DID/HTTPS audience/lifetime **400**, retained challenge
capacity exhaustion **429**, and a store outage **503**. The audience must be
canonical HTTPS without userinfo or URL fragment; lifetime is 1–300 seconds.

## Optional: verifier-authenticated signed successor challenge

When the verifier manages an active tenant-owned Ed25519 `did:key` in HeroSSID,
it can request a **signed** one-use challenge rather than independently
signing the unsigned response. This additional route requires both
`credential:verify` and `did:manage` permissions, and never accepts a
signing seed from the HTTP caller:

```http
POST /api/v1/credentials/issuer-successor/signed-challenge
Authorization: Bearer <credential:verify and did:manage scoped token>
Content-Type: application/json

{"verifierDid":"did:key:z...","audience":"https://verifier.example/issuer-successor","previousIssuerDid":"did:key:z...","lifetimeSeconds":120}
```

**201 Created** returns `signedRequestJwt`, `verifierDid`, exact public
`audience`, `nonce`, `trustedPreviousIssuerDid` and `expiresAt`.
The server signs `herossid-issuer-successor-request+jwt` with the real
active verifier DID's Ed25519 key. JWT claims bind `iss`, `aud`,
`previousIssuerDid`, `nonce`, `iat`, `exp` and the fixed
`purpose: issuer-key-successor`. The separate internal PostgreSQL audience
prefix is never included in the public signed payload. Its nonce is still
atomically consumed by the same existing `/issuer-successor/verify` endpoint.

**Each old and new issuer key controller must first independently authenticate
and pin the expected verifier DID, exact HTTPS audience and previous issuer
DID**, then call `IssuerSuccessorVerifierRequest.TryRead` with those pinned
values and the JWT. Neither a valid signature nor a `did:key` taken from
the untrusted JWT proves verifier legitimacy, domain control or the
business right to migrate an issuer. Each controller must explicitly decide
whether to sign. This is a private HeroSSID format, **not** OpenID4VP,
wallet interoperability, recovery or automatic trust promotion.

Missing authentication is **401**, missing either permission **403**, invalid
inputs **400**, foreign/inactive/nonmatching verifier DID **404**,
challenge capacity **429**, and storage/key-signing failure **503**.
The verifier signing key remains server-side and decrypted seed buffers are
zeroed after use. This path introduces no new database tables or migration.

## 2. Old and new issuer keys sign the same statement

The two controllers create a single `IssuerKeySuccessorAttestation.Create`
artifact with distinct `did:key` Ed25519 seeds, the verifier's exact audience
and the issued nonce. Each actual private key signs the **same** five-minute
statement with its own verification-method `kid`. Neither private key is
uploaded to the verification API.

The attestation does **not** sign old credentials again, replace existing
issuers, attest real-world organizational continuity, recover a lost old seed,
or grant successor business authority.

## 3. Verifier validates and atomically spends the nonce

```http
POST /api/v1/credentials/issuer-successor/verify
Authorization: Bearer <credential:verify scoped verifier token>
Content-Type: application/json

{"attestation":"<dual-signed-JSON-artifact>","audience":"https://verifier.example/issuer-successor","nonce":"<issued-nonce>"}
```

A **200** response with `{"status":"ValidKeyContinuity",
"successorIssuerDid":"did:key:z..."}` means the original verifier-owned
challenge was live, the trusted old and proposed new public keys each
verified a separate real Ed25519 signature over the *identical* statement,
and PostgreSQL atomically consumed this tenant/audience/purpose-bound nonce.

Invalid signatures, wrong old issuer, wrong audience, expired/unknown nonce,
or replay yield **200** with `{"status":"Invalid","successorIssuerDid":null}`.
They do not reveal unverified successor identity, and invalid signatures do
not consume otherwise-live challenges. Bad request shape is **400**, anonymous
**401**, missing scope **403**, unavailable store **503**. Both issuer signatures
can be valid but a parallel second acceptance is rejected by the shared
store's atomic consume.

A successful response is **evidence of two signing-key controls**, not proof
of unbroken custody or real-world issuer continuity. An attacker holding the
old key can nominate their own new key. The verifier MUST separately assess
key compromise, issuer registration and the application-specific trust/
authorization policy before independently admitting a successor. Existing
credentials remain signed under the original DID; nothing is transferred or
automatically reissued.

The integration tests use disposable PostgreSQL and independent ASP.NET
HTTP hosts with distinct real Ed25519 old/new keys. They test successful
verification, cross-host replay rejection, foreign old-key rejection without
nonce consumption, auth and malformed requests. They are not a third-party
wallet test, external security certification or production migration.


## 4. Opt-in verifier-host-owned successor policy (HTTP)

The original `/issuer-successor/verify` route above deliberately checks
**dual signing-key control only**, not an enrolled new issuer. Relying parties
that have independently pre-enrolled an expected **new** issuer DID can use
the separate **host-pinned** challenge and verify pair instead. This closes
the gap between the SDK-only `TryVerifyAndConsumePinnedSuccessor` policy and
authenticated non-.NET HTTP clients.

The verifier operator configures `IssuerSuccessorTrust:Policies` **before**
serving requests, not through a credential, signed claim or HTTP input.
Example environment/configuration keys (values are illustrative, not real
enrollment evidence):

```text
IssuerSuccessorTrust__Policies__0__TenantId=<verifier-tenant-GUID>
IssuerSuccessorTrust__Policies__0__PolicyId=issuer-migration
IssuerSuccessorTrust__Policies__0__Audience=https://verifier.example/host-pinned-successor
IssuerSuccessorTrust__Policies__0__TrustedPreviousIssuerDid=did:key:z...
IssuerSuccessorTrust__Policies__0__PreapprovedSuccessorIssuerDid=did:key:z...
```

Each policy is an exact tenant + policy ID + canonical HTTPS audience +
distinct old/new Ed25519 `did:key` pair, with at most 128 entries. Unknown,
nested, duplicate, malformed or insecure configuration **fails startup**.
A policy ID selects an existing operator inventory record but conveys no
approval by itself. The actual operator must independently obtain and secure
evidence for *when* and *by whom* the successor was approved: a configuration
file alone does not prove pre-incident enrollment or business authority.

With an authenticated `credential:verify` scoped token, issue a challenge
using **only** the registered policy ID:

```http
POST /api/v1/credentials/issuer-successor/host-pinned-challenge
Authorization: Bearer <credential:verify scoped token>
Content-Type: application/json

{"policyId":"issuer-migration","lifetimeSeconds":120}
```

**201 Created** returns the pinned `audience`, `trustedPreviousIssuerDid`,
random `nonce` and `expiresAt`. The HTTP caller cannot choose either issuer
DID or audience. The old and proposed new controllers separately authenticate
the expected verifier and sign the exact nonce/audience statement using
their distinct Ed25519 keys; neither sends its signing seed to this API.

```http
POST /api/v1/credentials/issuer-successor/host-pinned-verify
Authorization: Bearer <credential:verify scoped token>
Content-Type: application/json

{"policyId":"issuer-migration","nonce":"<issued-nonce>",
 "attestation":"<original-dual-signed-json-artifact>"}
```

A valid proof and still-live challenge yield **200**
`{"status":"ValidPinnedKeyContinuity","successorIssuerDid":"did:key:z..."}`.
An authentic two-key proof for a *different* new DID, a mismatched old DID,
wrong verifier audience, foreign tenant, expired/replayed challenge, missing
host inventory or invalid signature yields **200**
`{"status":"Invalid","successorIssuerDid":null}`. In particular, an
authentic but **unapproved** successor is rejected **before** the shared
PostgreSQL nonce is consumed, so the approved controller can still respond.
A successful acceptance atomically consumes the one-use nonce across hosts.

Unknown policy at issuance, wrong request shape, or any attempt to add a
request-field trust override is **400**; anonymous **401**, missing verifier
scope **403**, capacity **429** at issuance, durable store failure **503**.
No new PostgreSQL schema, migration, credential issuance or trust mutation
occurs. Hosts must deploy the **same operator policy inventory** and durable
challenge store; a missing inventory rejects rather than authenticates.

This is **privately defined HeroSSID key-continuity evidence**, not DID
rotation, independently proven historical enrollment, automatic issuer trust,
key compromise detection, real-person identity verification, agent delegation,
business authorization, OpenID4VP compliance or third-party Wallet
interoperability. The older unpinned endpoints remain available for
key-control-only checks and their result **must not be interpreted** as a
host-pinned successor acceptance.
