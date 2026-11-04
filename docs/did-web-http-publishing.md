# Opt-in root did:web HTTPS publication

HeroSSID.Api can now serve one **operator-enrolled, public** DID Core JSON-LD document at `/.well-known/did.json`. The route is **absent by default** and never exposes a signing key. It is an alternative to publishing an offline-generated file on your own host, not a general DID resolver.

## Configuration (example)

First provision your own Ed25519 key pair securely, keep the private key outside this endpoint, and obtain the 32-byte **raw public key**. Provision these two configuration values in the server's trusted configuration (environment variables use double underscores):

```sh
DidWebPublication__Domain=issuer.example
DidWebPublication__PublicKeyHex=<lowercase hex of 32 raw Ed25519 public-key bytes>
```

Use your **real, already-controlled DNS hostname** instead of the example. The domain must be a canonical lowercase ASCII DNS name accepted by the restricted offline `DidWebMethod`, with at least two labels. `PublicKeyHex` is exactly 64 lowercase hex characters and cannot be all zero. Do **not** place a private seed or a bearer credential in this setting.

At application startup an absent `DidWebPublication` section disables the route; partial, malformed or unexpected fields fail startup instead of silently changing public identity. This particular publisher supports only the root-domain DID `did:web:issuer.example`. To publish path-specific or multi-key/rotated DIDs, continue using the offline publication APIs under an explicitly controlled HTTPS host.

## HTTP contract

- Public GET: `https://issuer.example/.well-known/did.json`; expected media type `application/did+ld+json`, `Cache-Control: no-store`.
- The API serves the same document constructed using `DidWebMethod.CreateDidDocument`. The `id`, `verificationMethod`, `authentication` and `assertionMethod` identify the operator-configured **public** Ed25519 key; they do not issue credentials.
- Only the exact expected HTTPS request host with the ordinary HTTPS port is accepted. An unapproved host, HTTP or alternate port receives 404. An empty/missing policy does not register the route at all.
- Deploy behind independently controlled DNS, HTTPS/TLS certificate, reverse-proxy trust and network policy. If TLS is terminated at a proxy, ensure `Request.Scheme` and `Request.Host` are derived only from an authenticated/trusted proxy; otherwise the route refuses requests. Avoid exposing a route whose host can be spoofed through untrusted forwarded headers.
- Take the operator-owned publication address to an **independent** DID resolver/client and verify the published bytes and pinned public key. Do not call tests inside HeroSSID independent third-party interoperability.

This endpoint does **not** establish that the operator owns the domain, possesses the configured private key, is a legally verified organisation/person, is a trusted VC issuer, or may authorize an Agent. It does not prove consent, change an application's independently pre-enrolled issuer trust, rotate signing keys, serve multiple DIDs or modify credential revocation. Operations (DNS, TLS, signing key custody, pre-approved trust, revocation and key retirement) remain separately owned.

See [offline DID preparation](did-web-offline-publishing.md), the [project vision](VISION.md) and [README](../README.md). No database/schema change, production deployment or package publication is implied.
