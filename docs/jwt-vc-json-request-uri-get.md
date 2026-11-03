# VC1.1 OpenID4VP request_uri GET transport (opt-in .NET 10 SDK)

This is the **by-reference request retrieval** portion of OpenID4VP 1.0
[`request_uri`](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
It improves practical QR/deep-link size for HeroSSID's existing signed
`jwt_vc_json` + `direct_post` library profile. The retrieval mechanism is
standard GET with `Accept: application/oauth-authz-req+jwt`, but the signed
Request Object contains HeroSSID-specific trust-policy extensions and the
holder-bound VP uses private request-hash binding. There is **no claim of full
OpenID4VP interoperability or third-party Wallet conformance**.

## Verifier host contract

1. Issue/retain an independent, tenant-bound, one-use **hosted-purpose nonce**
   through `IHostedPresentationChallengeStore.IssueHosted` (implemented by the
   in-memory and PostgreSQL challenge stores). This nonce carries a reserved,
   versioned purpose marker with 192 random bits; ordinary `Issue` nonces
   deliberately exclude that marker. Create the **original** verifier
   Ed25519-signed request using `OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest`.
   Do not reuse a by-value nonce for by-reference hosting.
2. Host **those exact JWT bytes** at a public HTTPS `request_uri` (GET, HTTP
   200, `Content-Type: application/oauth-authz-req+jwt`, at most 16,384 bytes).
   For the manual-hosting path, the SDK does *not* create or operate the endpoint,
   its storage or TLS; the optional single-process API host below is separate.
3. Call `OpenId4VpJwtVcJsonRequestUri.CreateWalletInvocation` with the signed
   JWT, actual endpoint, trusted verifier DID, pinned response URI and type and
   context to obtain the compact `openid4vp://?client_id=...&request_uri=...`
   invocation. A successful call verifies the genuine signed request; it does
   **not** prove the hosted content is configured, reachable or still current.
4. Independently retain the original signed JWT and its lowercase SHA-256
   digest so the stricter holder-bound verifier can authenticate the final
   response and atomically consume the original nonce. Do not trust a
   presenter-supplied replacement hash or snapshot.

## Wallet consumption

The integrating Wallet must independently trust the **exact** HTTPS request
URI, verifier DID, HTTPS response callback, credential type, subject context
and issuer; a URI appearing only in a QR/deep link is *not* trusted policy.
Use a dedicated, unauthenticated, non-redirecting `HttpClient`:

```csharp
using HeroSSID.Credentials.VerifiablePresentations;

using var handler = new HttpClientHandler
{
    AllowAutoRedirect = false,
    UseCookies = false
};
using var http = new HttpClient(handler);
string? signedRequest = await OpenId4VpJwtVcJsonRequestUri
    .FetchVerifiedRequestAsync(
        deepLink, independentlyTrustedRequestUri, http,
        trustedVerifierDid, trustedCallback, trustedType, trustedContext,
        TimeProvider.System, cancellationToken: cancellationToken);

if (signedRequest is null)
{
    return; // No credential claims released or holder key used.
}

// Continue with an authenticated Wallet preview (optionally the incident-aware
// signed-status gate), show ALL claims, and obtain actual user consent.
// Only then call CreateHolderBoundResponseFormAfterPreview or the stricter
// incident-aware holder-signing method and POST to the pinned HTTPS callback.
```

The adapter rejects untrusted or noncanonical launches before any GET,
non-HTTPS endpoints, non-200/redirect responses, wrong content types,
unexpected/oversized bodies (even absent Content-Length), body streams that
stall past the default **15-second total header-and-body deadline** (with an
optional caller-selected deadline of at most 30 seconds), invalid verifier
signatures, issuer/type/callback/context mismatches and expired challenges.
It returns the **unchanged original compact JWT**, so existing holder
signatures and verifier-owned request-hash pins are preserved.

**Security deployment boundary:** A caller-provided HttpClient may have an
automatic-redirect handler, cookies, default credentials, proxies or other
ambient configuration. The adapter verifies the final response URI but
cannot prevent an earlier automatically followed redirect. Pass a dedicated
`HttpClientHandler` with `AllowAutoRedirect=false` and no credentials, and
independently restrict the host to an approved verifier before triggering a
network request. DNS, TLS, proxy and SSRF policy remain the application host's
responsibility.

Run focused acceptance:

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj \
  --configuration Release \
  --filter FullyQualifiedName~OpenId4VpJwtVcJsonRequestUriTests
```

A real mocked HTTP GET and separate Ed25519 issuer/holder/verifier keys
demonstrate the bounded launch, signed request retrieval, actual holder-signed
VP, verifier-retained request hash, successful one-use acceptance and replay
denial. Negative tests cover wrong URI or launch parameters, forged request,
redirects, HTML response, excessive response size, a body that never finishes
and an expired request.

The manual-hosting SDK adapter does not itself provide an HTTP endpoint.
For the opt-in volatile host see below. Neither path demonstrates independent
Wallet interoperability, selective disclosure, actual consent, live revocation,
legal identity vetting, business authority or standard third-party holder binding.

## Optional SDK/API-hosted GET for a single process

An opt-in **volatile, single-instance** hosting adapter is available without
any PostgreSQL schema change. Its usefulness is limited to a deployment that
can route the public HTTPS GET to **the same API process** that published the
Request Object. It is not a distributed or durable request store. Loss on
process restart, round-robin load balancing, expired/cancelled challenges or
a dead instance makes the reference unavailable. Do not market this as a
production multi-replica OpenID4VP host.

The operator, not a caller-controlled Host header, must configure the exact
externally reachable HTTPS URL prefix including the trailing slash:

```
OpenId4Vp__PublicRequestUriBase=https://verifier.example/api/v1/credentials/jwt-vc-json/openid4vp/requests/
```

On the **authenticated** `POST /api/v1/credentials/jwt-vc-json/openid4vp/signed-request`
(with both `credential:verify` and `did:manage` scopes and an owned active
verifier DID), set `publishRequestUri: true` alongside the normal signed
request parameters. The response includes `referenceWalletInvocationUri`
as an additional `openid4vp://?client_id=...&request_uri=...` launch. The
legacy by-value `walletInvocationUri` and original `signedRequestJwt` are
unchanged. With no configured HTTPS base, publication fails closed rather
than synthesizing a URL from untrusted inbound HTTP headers.

The holder Wallet may send an **anonymous GET** to
`/api/v1/credentials/jwt-vc-json/openid4vp/requests/{opaqueReference}`.
Only an unguessable 256-bit, 43-character opaque reference generated by the
server selects a stored, genuinely signed, still-live tenant/verifier request.
Success returns the **original unchanged** compact JWT with media type
`application/oauth-authz-req+jwt` and no-store/no-cache headers; unknown,
expired and cancelled challenges return 404, and challenge-store failures
return 503 without returning JWT bytes. A GET does not itself consume the
verifier challenge so a Wallet can retry; the final VP remains subject to the
existing separate, atomic verifier consumption gate. The store holds up to
256 entries and rejects excess rather than evicting active requests.
The host reserves an opaque publication slot **before** issuing the durable
PostgreSQL verifier challenge, so a full host returns 429 without consuming
the independent challenge quota. Failed signing/issuance releases uncommitted
slots and abandoned reservations expire after five minutes.

This GET route publishes a signed **verifier request**, not a credential
or sensitive subject claims. An integrating Wallet still needs to pin the
exact verifier, HTTPS URL, callback and requested credential policy, validate
its Ed25519 signature, display the whole credential and obtain actual
informed consent. The caller remains responsible for **hosted TLS**, routing,
rate controls, reverse-proxy security, DNS/SSRF rules, request-hash retention
and any public `direct_post` callback; the API does **not** host the latter.

The integration suite exercises real authenticated issuance, anonymous
GET preserving exact JWT bytes, absent/unknown reference, and cancellation
against isolated PostgreSQL challenge storage.
Authorized cancellation now also immediately retires the matching volatile
Request Object by exact tenant, verifier audience and nonce. This releases
host capacity without waiting for its JWT expiry; the same applies to an
accepted holder proof (including a correctly signed but revoked credential)
after atomic challenge consumption. Malformed presentation attempts must not
retire a still-live challenge, and unrelated active requests remain available.
Recovery applies to the publishing process only. It does
not change the independent PostgreSQL challenge or make the host distributed.

Neither the HTTP integration suite nor this fix establishes independent
Wallet interoperability, a full OpenID4VP conformance test, user consent,
live non-revocation, personal identity proof or business authorization.

## Opt-in server-retained original-request verification over authenticated HTTP

A verifier that publishes a `request_uri` Request Object may now forward a
holder's unchanged `direct_post` form to authenticated
`POST /api/v1/credentials/jwt-vc-json/openid4vp/verify-hosted-response`
(`credential:verify` scope). The JSON contract matches `verify-response`:
`verifierDid`, `nonce`, `form`, `revocationSnapshot`,
`expectedCredentialType` and `subjectContextUri`.

Unlike the older `verify-response` compatibility route, this **strict** route
uses only the server's own published original Ed25519-signed Request Object
and independently retained tenant-bound challenge. The server derives its own
SHA-256 of those **original JWT bytes**, pinned HTTPS callback, credential type
and subject vocabulary. It rejects an unsigned/unbound holder VP, another
signed request for the same nonce, changed policy, unknown/expired/cancelled
challenge or missing/ambiguous original publication **without consuming** a
valid pending challenge or disclosing claims. A successful genuine holder
Ed25519 proof atomically spends the nonce; only a separately authenticated,
fresh issuer status `SignedNotListed` releases verified subject claims.
Correctly signed but revoked credentials release no subject data. It never
trusts a request hash or response URI forwarded by the holder.

This is **opt-in**: the older authenticated `verify-response` route
continues to accept **unpublished** by-value requests. It now returns
`Invalid`, reveals no claims and **does not consume the challenge** when
the same process retains a live, published original Request Object for the
tenant, verifier audience and nonce. This prevents a genuine but unbound
holder response from bypassing the strict hosted verification route during
that live publication; a properly bound holder proof must use
`verify-hosted-response`. An independent PostgreSQL/HTTP negative test
reproduced the original claim disclosure before this guard.

**Hosted nonce purpose is now encoded in the original durable challenge.**
The built-in stores emit a reserved versioned marker for hosted challenges and
exclude it from ordinary by-value challenges. Every upgraded verifier replica
rejects marked nonces on the compatibility route even without the hosted-only
configuration switch, including after losing the volatile original. The SDK
also refuses to publish or fetch an unmarked by-value challenge as a hosted
Request Object. Legacy already-issued unmarked references cannot be upgraded.
Old binaries do not understand the marker and remain a downgrade risk in mixed
fleets, so roll out all verifier replicas together and retain hosted-only
enforcement as defence in depth. Strict verification still requires the
**same process** retaining the original request: this does not make hosting
distributed or durable. No public
`direct_post` callback, informed user consent, selective disclosure,
independent Wallet interoperability, full OpenID4VP conformance, identity
vetting or business authorization is provided.

The real PostgreSQL/HTTP integration suite exercises both success and replay,
unbound holder proof rejection before spending a challenge, changed policy
and explicit no-downgrade for an unpublished by-value request. SDK unit tests
also reject cross-tenant and ambiguous original-request references.

## Operator-enforced hosted-only verifier (opt-in, no new schema)

A published `request_uri` is a **process-local** object, while the one-use
challenge is shared through PostgreSQL. Without an operator-enforced policy, a
second API replica (or a restarted process) that has lost the hosted original
can still accept an authentic but **unbound** response on the legacy
`verify-response` route. The original instance's local downgrade check does
not protect another instance. This was reproduced with two independent HTTP
test hosts, a shared real PostgreSQL challenge and three genuine Ed25519
signers: the legacy route returned `SignedNotListed` and disclosed claims.

For deployments that require hosted Request Object binding, set the following
**server-owned configuration on every verifier replica**, before admitting
hosted traffic:

```text
OpenId4Vp__RequireHostedResponseBinding=true
```

When enabled, the authenticated legacy
`POST /api/v1/credentials/jwt-vc-json/openid4vp/verify-response`
returns `{ "status": "Invalid", "verifiedSubject": null }` for *all*
presentations, independently of any process-local publication and **before
consuming** the shared challenge. Even without the flag, upgraded replicas
reject every hosted-purpose nonce before consuming the shared challenge. The same server refuses
`publishRequestUri: false` issuance with HTTP 400 to prevent unusable by-value
requests. Only the strict `verify-hosted-response` route can accept a
holder's original-request-bound presentation after authenticating the
server-retained signed JWT, pinned verifier, issuer, policy, signed status,
holder key and one-use nonce. A missing original (including a restarted
instance or a different replica) remains `Invalid`.

The setting defaults to `false` for existing by-value integrations. **All
replicas receiving verifier traffic must be configured consistently**:
even one legacy-enabled instance remains a downgrade path when it shares
the challenge database. Enable this as a deliberate verifier deployment
boundary, and drain or cancel outstanding by-value requests before rollout;
do not silently switch existing callback integrations. The independent
public GET and strict verification of a particular request must still route
to the original publishing process. This mode prevents legacy downgrade;
it **does not make Request Objects distributed/durable**, nor prove user
consent, issuer status completeness, actual identity, business authority,
third-party Wallet interoperability or full OpenID4VP conformance.

The integration regression for the hosted-only mode is
`HostedOnlyVerifierReplicaRejectsLegacyFallbackWithoutLocalRequestObject`
in `JwtVcJsonOpenId4VpHttpIntegrationTests`, requiring isolated PostgreSQL.
