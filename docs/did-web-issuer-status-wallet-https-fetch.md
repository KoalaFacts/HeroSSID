# Opt-in did:web issuer status HTTPS fetch for Wallets (.NET 10)

**Scope:** SDK-only retrieval of the already supported private
`herossid-didweb-vc11-exact-status+jwt` format. The issuer publishes a separately
signed, 60-second, SHA-256-bound observation at an operator-chosen public HTTPS
endpoint. This is **not** the W3C Bitstring Status List standard, a new VC format,
an OpenID4VP hosted wallet or evidence of live non-revocation.

## Runnable SDK integration

The operator first provisions its independently approved issuer `did:web`,
exact `#key-1` or `#key-2` method, raw 32-byte Ed25519 public key and
**exact** public status URI. These pins are not learned from a JWT, a remote
DID document, the verifier's request or a redirect. The issuer uses the
existing `JwtVcJsonPinnedDidWebIssuerStatus.Create` to sign a status for the
exact original VC1.1 compact JWT and publishes the resulting ASCII bytes
with `Content-Type: application/jwt` (registered by RFC 7519 §10.3).

```csharp
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;

// These are operator-enrolled trust inputs, not claims from the JWT.
Uri pinnedPublicStatusUri = new("https://issuer.example/status/credential-42.jwt");
string originalIssuerJwt = /* the unchanged genuine signed original VC1.1 JWT */;
string trustedIssuerDid = "did:web:issuer.example:members";
string trustedIssuerMethod = trustedIssuerDid + "#key-2";
byte[] independentlyPinnedIssuerPublicKey = /* 32 bytes enrolled by Wallet operator */;

var fetched = await JwtVcJsonPinnedDidWebIssuerStatusTransport
    .FetchVerifiedStatusWithIsolatedTransportAsync(
        pinnedPublicStatusUri, originalIssuerJwt, trustedIssuerDid,
        trustedIssuerMethod, independentlyPinnedIssuerPublicKey,
        TimeProvider.System);

if (fetched is null || fetched.Status != RevocationSnapshotCheckResult.NotListed)
{
    // Refuse to display signed claims or sign a holder presentation.
    return;
}

// Continue with the existing independent verifier-request authentication,
// JwtVcJsonPinnedDidWebWalletPreflight.TryPrepareWithEmergencyDenylist,
// full subject disclosure + real application-owned user consent, and
// CreateAfterEmergencyDenylistPreview. Supply fetched.SignedStatusJwt;
// re-check current status/policy AFTER consent and before holder signing.
```

The transport verifies the original issuer's signature/provenance before a
network request, then checks the status JWT's **real Ed25519 signature from the
same independently pinned method**, issuer DID, exact original compact JWT
digest, 60-second time bounds and unmodified response bytes. It distinguishes
`Revoked` from `NotListed` as a typed result. Forged, stale, wrong-JWT,
oversized, non-ASCII, redirected, wrong-content-type or improperly pinned
replies return `null`. The original credential's complete signed holder,
issuer name, HTTPS credential ID, vocabulary and validity are still checked
by the existing Wallet preflight **before any claims are displayed**.

## Network and privacy boundary

The safe default creates a fresh isolated `SocketsHttpHandler`: no redirects,
cookies, proxies, ambient authentication, Activity trace headers, automatic
decompression or automatic client certificates; HTTPS server certificate
validation remains enabled, with online revocation checks. DNS answers are
restricted to public addresses before connection. The exact URI must use
public-domain HTTPS on the default port, without userinfo/query/fragment;
it is bounded to 2,048 characters. Download and read are bounded to
8,192 bytes and a single 15-second deadline (caller may choose 1–30 seconds).
External cancellation is not reinterpreted as success.

The injected-`HttpClient` overload is for independently audited handlers;
the SDK cannot inspect such a handler's redirect/proxy/cookie behavior.
The exact final response URI is verified, but a redirecting handler might
already have contacted an attacker before that rejection. Never pass a shared
authenticated application's `HttpClient`. Even a legitimate public status
GET discloses the **requested path and timing** to the issuer/CDN; do not
embed the original JWT, user secrets or private identifiers into the URL.

A `NotListed` result means only that the independently pinned signer
authentically reported `revoked=false` for that exact JWT within the 60-second
window. It cannot prove that the operator's authoritative source was complete,
that the issuer private key was uncompromised or that revocation remains
unchanged. Wallet emergency denials override issuer-reported non-revocation.
There is no automatic issuer trust enrollment, legal identity check, human
consent proof, proof of holder key control, business/Agent permission,
independent wallet interoperability, deployment or new database schema.

## Regression

Run `dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj
--configuration Release` and the repository CI/Security/CodeQL gates.
Tests use genuine Ed25519 credentials and status signatures with an injected
probe HTTP handler, including independent revoked/not-listed outcomes, forged
status, exact JWT mismatch, expiry, unsafe network targets, credential-bearing
headers, wrong media type, oversized body and redirect refusal. No production
issuer key or external endpoint is required.
