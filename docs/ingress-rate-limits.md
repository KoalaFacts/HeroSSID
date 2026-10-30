# HTTP ingress, trusted proxies and rate-limit identity

HeroSSID applies a fixed-window HTTP budget **per validated tenant/client identity** (100 requests/minute) or, for anonymous requests such as `/oauth2/token`, per actual network peer address. A separate process-wide 10,000 requests/minute ceiling prevents an attacker from multiplying their budget by changing token/client/IP partitions. These are process-local availability controls, **not distributed quotas** or an internet-facing DDoS service. Existing credential issuance limits remain separate.

## Direct Kestrel

When Kestrel receives the actual caller TCP connection, leave `Ingress:ForwardedHeaders:Enabled` unset or false. User-supplied `X-Forwarded-For` or `X-Forwarded-Proto` must not determine the caller address or scheme. Authentication is validated before rate limiting; the partition never comes from an unverified bearer payload or an arbitrary `X-Client-Id` header.

## TLS termination at one explicitly trusted reverse proxy

When and only when the operator controls the immediate proxy and knows its network address, configure e.g.:

```bash
export Ingress__ForwardedHeaders__Enabled=true
export Ingress__ForwardedHeaders__KnownProxies__0=10.0.2.15
# Alternatively, pin a deliberately narrow known proxy CIDR:
# export Ingress__ForwardedHeaders__KnownNetworks__0=10.0.2.0/28
```

The application refuses to enable proxy forwarding with no explicitly configured trusted proxy IP or bounded CIDR. Wildcard peers and /0 networks are refused. With this opt-in configuration, ASP.NET Core's forwarded-headers middleware runs **before** HTTPS redirection, authentication and rate limiting, processes at most one hop and requires matching `X-Forwarded-For`/`X-Forwarded-Proto` header counts. Only an explicitly trusted connecting peer can update the interpreted client IP/scheme. Unknown peers' forwarded headers are ignored.

**Proxy duty:** At the public edge, remove incoming client-supplied forwarded headers and set/overwrite `X-Forwarded-For` and `X-Forwarded-Proto` from the genuine client and TLS connection. Merely marking a proxy address as trusted does not defend against a proxy that blindly accepts caller-chosen forwarded headers. Multiple proxy hops are **not** supported by the one-hop profile; configure an appropriately controlled immediate ingress rather than increasing trust breadth without review. Keep direct Kestrel access firewalled when operating behind the proxy.

Validated JWTs issued by HeroSSID have an authenticated `tenant_id` and `client_id`, so two clients behind the same proxy or NAT receive independent budgets. Validated identities without an unambiguous client identifier share their tenant budget. Anonymous token requests are still IP-partitioned. A network peer cannot forge a new authenticated partition by writing an HTTP header. The process-wide ceiling also bounds many changing authenticated clients, but deliberate denial of service, shared public NAT, proxies with non-sanitized forwarding, multi-region traffic and horizontal replicas require separate ingress infrastructure/monitoring.

The focused `IngressProtectionTests` exercise real in-memory HTTP middleware with simulated TCP peers and validated principal claims; they do **not** prove the live reverse-proxy configuration, production rate capacity, shared/distributed limiting or third-party wallet interoperability. No PostgreSQL schema, production key, deployment, license or credential trust decisions change.
