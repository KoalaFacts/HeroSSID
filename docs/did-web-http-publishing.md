# Opt-in root did:web HTTPS publication

HeroSSID.Api can serve one **operator-enrolled, public** DID Core JSON-LD document at `/.well-known/did.json`. The route is **absent by default** and never exposes a signing key. Operators may explicitly enable a two-key public overlap with an independently approved successor public key. It is an alternative to publishing an offline-generated file on your own host, not a general DID resolver or key-trust service.

## Configuration (example)

First provision your own Ed25519 key pair securely, keep the private key outside this endpoint, and obtain the 32-byte **raw public key**. Provision these two configuration values in the server's trusted configuration (environment variables use double underscores):

```sh
DidWebPublication__Domain=issuer.example
DidWebPublication__PublicKeyHex=<lowercase hex of 32 raw Ed25519 public-key bytes>
```

For an explicit **two-key overlap**, keep the existing `Domain` and `PublicKeyHex` values and add a third value:

```sh
DidWebPublication__SuccessorPublicKeyHex=<lowercase hex of a distinct 32-byte public Ed25519 successor key>
```

The same DID now advertises both `#key-1` and `#key-2` for authentication and assertion, using the exact SDK `DidWebPinnedKeyTransition.CreateTransitionDocument` format. Both public keys must be separately operator-approved and nonzero; an identical old/new key, absent or malformed third value, unexpected fourth field or invalid DNS name fails startup. Omitting the successor setting preserves the existing one-key response without changing any trusted verifier enrollment. This HTTP route does **not** yet implement the successor-only retirement publication stage; it must not silently switch back to the one-key profile to attempt retirement.

Use your **real, already-controlled DNS hostname** instead of the example. The domain must be a canonical lowercase ASCII DNS name accepted by the restricted offline `DidWebMethod`, with at least two labels. Also add this exact hostname to the application's **independent** `AllowedHosts` configuration; the checked-in `appsettings.json` initially allows only `localhost;herossid.au;*.herossid.au`. Preserve the other genuinely needed hosts and do **not** disable the host filter or use `*` to make publication work. For example, an operator may set `AllowedHosts=localhost;herossid.au;*.herossid.au;issuer.example` after separately controlling that name. `PublicKeyHex` is exactly 64 lowercase hex characters and cannot be all zero. Do **not** place a private seed or a bearer credential in this setting.

At application startup an absent `DidWebPublication` section disables the route; partial, malformed or unexpected fields fail startup instead of silently changing public identity. This publisher supports only the root-domain DID `did:web:issuer.example`, one public key or an explicit **two-key overlap**, not arbitrary extra keys or automatic retirement. For path-specific DIDs and the successor-only retirement stage, continue using offline publication APIs under an explicitly controlled HTTPS host.

## HTTP contract

- Public GET: `https://issuer.example/.well-known/did.json`; expected media type `application/did+ld+json`, `Cache-Control: no-store`.
- In single-key mode the API serves `DidWebMethod.CreateDidDocument`; in explicit overlap mode it serves `DidWebPinnedKeyTransition.CreateTransitionDocument`. The `id`, `verificationMethod`, `authentication` and `assertionMethod` identify the operator-configured **public** Ed25519 key(s); they do not issue credentials or prove private-key control. Independent verifiers must separately pin and authorize either key before relying on it.
- Only the exact expected HTTPS request authority (canonical domain alone or with explicit `:443`) is accepted by this endpoint. For HTTPS requests that pass ASP.NET Core's separate AllowedHosts middleware, an unapproved host, malformed/overflowed port or alternate port receives 404; a hostname blocked by the global host filter can instead receive HTTP 400 before reaching this endpoint. The application also runs HTTPS redirection before endpoint routing: HTTP requests can receive a redirect when an HTTPS port is configured, not necessarily 404. A redirect is not DID document publication. An empty/missing policy does not register the route at all.
- Deploy behind independently controlled DNS, HTTPS/TLS certificate, reverse-proxy trust and network policy. If TLS is terminated at a proxy, ensure `Request.Scheme` and `Request.Host` are derived only from an authenticated/trusted proxy; otherwise the route refuses requests. Avoid exposing a route whose host can be spoofed through untrusted forwarded headers.
- Take the operator-owned publication address to an **independent** DID resolver/client and verify the published bytes and pinned public key. Do not call tests inside HeroSSID independent third-party interoperability.

This endpoint does **not** establish that the operator owns the domain, possesses either private key, is a legally verified organisation/person, is a trusted VC issuer, or may authorize an Agent. It does not prove consent, change an application's independently pre-enrolled issuer trust, retire a compromised key, perform automatic key rotation, serve multiple DIDs or modify credential revocation. Operations (DNS, TLS, signing key custody, pre-approved trust, revocation and key retirement) remain separately owned.

See [offline DID preparation](did-web-offline-publishing.md), the [project vision](VISION.md) and [README](../README.md). No database/schema change, production deployment or package publication is implied.
