# Offline did:web DID document preparation (opt-in SDK)

HeroSSID can now prepare an Ed25519 `did:web` document for an
**operator-owned HTTPS domain**, without registering an identity or
accessing the network. This is an intentionally bounded subset of the
[W3C CCG did:web method specification](https://w3c-ccg.github.io/did-method-web/).
It is separate from the existing `did:key` issuance and independent issuer
verification paths.

## Executable SDK entry

```csharp
using HeroSSID.DidOperations.DidMethods;

// publicKey is the 32-byte Ed25519 public key of a keypair already held
// securely by the domain operator. Never put a private seed in a DID document.
var method = new DidWebMethod();
var options = new Dictionary<string, object>
{
    ["domain"] = "issuer.example.org",
    ["path"] = "organizations/acme"
};

string did = method.GenerateDidIdentifier(publicKey, options);
// did:web:issuer.example.org:organizations:acme

Uri publicationUri = DidWebMethod.GetDocumentUri(did);
// https://issuer.example.org/organizations/acme/did.json

string didJson = method.CreateDidDocument(did, publicKey, options);
// Publish didJson unchanged at publicationUri using operator-controlled HTTPS.
```

With just `["domain"] = "issuer.example.org"`, the output DID is
`did:web:issuer.example.org`, and its document belongs at
`https://issuer.example.org/.well-known/did.json`. Both documents contain
the exact Ed25519 multicodec public key as `publicKeyMultibase`, a
`#key-1` verification method, and `authentication` and `assertionMethod`
references. They do not declare unrelated key-agreement or authorization
capabilities.

## Deliberate scope and security boundary

- Domain must be lowercase ASCII DNS with at least two labels. IP addresses,
  loopback-only hostnames, credentials, ports, mixed case and ambiguous
  host encodings are not accepted.
- Optional `path` uses 1–8 slash-separated, nonempty ASCII letters/digits
  with internal hyphen or underscore, each at most 64 characters. Dot
  segments, percent encodings, backslashes, queries, empty segments and
  arbitrary URLs are rejected. These restrictions are **stricter than the
  general did:web method**, not a claim of exhaustive compliance.
- This library only constructs the document and expected HTTPS location.
  It **does not publish** it, fetch the domain, verify HTTPS/TLS or DNS,
  resolve the document remotely, prove the publisher owns the domain, test
  independent DID resolvers, rotate hosted keys or create server identities.
  `did:web` is location-based, unlike a self-certifying `did:key`.
- A generated document does **not** make its key an issuer trusted by
  HeroSSID's existing credential verifiers: they still require their own
  independently pinned, supported issuer policy. Nor does the document
  prove legal organisation identity, human identity, Agent delegation,
  user consent or business authorization.
- Operators must keep their Ed25519 private keys protected, control the HTTPS
  hosting location, ensure the live document matches the desired DID and
  test resolution with an **independent** DID resolver before relying on it.

No database schema, network service, production DNS/TLS configuration,
issuance policy or packaging is changed by this feature.


## Opt-in check of retrieved content against a pinned DID and public key

An integrator can independently retrieve `did.json` from the **exact** URI
returned by `DidWebMethod.GetDocumentUri(did)` and check whether its content
matches the original single-key document profile and a **previously pinned**
Ed25519 public key, without enrolling it as a trusted credential issuer.

```csharp
using HeroSSID.DidOperations.DidMethods;

// did and publicKey must already be pinned by your application.
// retrievedJson must come from a safely configured HTTPS fetch of the
// precise publication URI, not from an untrusted claimant.
bool matches = DidWebPublishedKeyMatch.MatchesExpectedDocument(
    did, publicKey, retrievedJson);
if (!matches)
{
    // Stop: the content is not this application's pinned single-key profile.
}
```

The check ignores JSON whitespace and property order but requires an exact
DID, expected Ed25519 multicodec key, the `#key-1` controller and
`authentication`/`assertionMethod` references, and both declared JSON-LD
contexts. It rejects duplicate JSON properties, unrequested capabilities,
malformed, deeply nested or oversized content, key substitution, altered
relationships and different identifiers. Other legitimate did:web profiles,
including multi-key, rotated-key and service-bearing documents, are
**intentionally unsupported by this narrow equality check**, not necessarily
invalid DIDs.

The SDK check **does not fetch HTTP content** and cannot prove which
domain served the bytes, domain ownership, private-key control, issuer trust,
user consent, legal identity or business authorization. The caller must pin
both the input DID and expected public key independently, secure its own
DNS/TLS/redirect/SSRF boundary, fetch from the canonical URL, and decide
its own trust and key-rotation policy. No external DID resolver or third-party
Wallet interoperability has been tested.


## Opt-in pinned HTTPS GET of the published document

An integrating verifier which **already trusts and pins the exact did:web DID
and 32-byte Ed25519 public key** may now fetch the operator's actual published
DID document and require the same bounded single-key profile. This is an
HTTP transport convenience over the existing offline
`DidWebPublishedKeyMatch.MatchesExpectedDocument` comparison, not general
DID resolution or automated trust discovery.

```csharp
using HeroSSID.DidOperations.DidMethods;

// did and pinnedIssuerPublicKey were independently approved by the operator.
// Do not accept them from a token, caller-supplied URI or attacker input.
bool publishedKeyIsStillPinned =
    await DidWebPinnedDocumentHttpTransport.FetchAndMatchWithIsolatedTransportAsync(
        did, pinnedIssuerPublicKey, cancellationToken: cancellationToken);
if (!publishedKeyIsStillPinned)
{
    // Reject an absent, wrong, substituted or malformed published document.
}
```

For integration tests or applications with an independently audited transport,
`FetchAndMatchAsync(did, pinnedKey, http, ...)` accepts a supplied
`HttpClient`. Its handler **must** have auto-redirects, cookies, proxy,
credentials and Activity baggage disabled. The library rejects default request
headers before connecting and detects a different final response URI, but
**cannot prevent an injected redirecting handler from contacting a different
host before that check**. Prefer the provided isolated handler where suitable.

**Default network egress guard (isolated handler only):** The SDK resolves
the preapproved hostname for each new TCP connection, refuses empty or mixed
public/private DNS answer sets, and establishes TCP directly to a validated
public IPv4/IPv6 address without a second DNS lookup. Loopback, RFC1918,
shared/metadata/link-local, documentation, benchmark, multicast and selected
tunnel/overlay destinations are denied before connect. The entire IETF
protocol-assignment block `2001::/23` is also denied, **including its
globally reachable specific-purpose exceptions**, rather than silently trusting
future registry additions. Ordinary public issuer hosts should use globally
allocated unicast ranges outside this block. Normal HTTPS SNI and certificate
validation continue to use the original domain. This deliberately
conservative filter may reject split-horizon/private-only issuers; use an
independently audited caller-supplied transport only under explicit network
controls. `IsPublicEgressAddress(IPAddress)` exposes the exact filter for
operator preflight; this is not a dynamic IANA registry or a proof that an
allowed public address is safe. Public IPs routed to internal services by
local NAT or proxies, malicious public endpoints, DNS poisoning, and egress
outside this handler remain operator/network policy concerns.

The request is a credential-free GET to the exact URI returned by
`DidWebMethod.GetDocumentUri(did)`. Responses must be HTTP 200 with
`application/did+ld+json`, `application/did+json` or `application/json`,
an optional UTF-8 charset, no compression, and no more than 16 KiB of strictly
decoded UTF-8. A single 15-second deadline (configurable up to 30 seconds)
covers headers and body. Redirects, malformed or oversized JSON, changed key,
wrong controller/relationships or nonmatching DID fail closed. Caller-requested
cancellation propagates.

**Network trust boundary:** Do not use this as an open DID-to-URL proxy.
Restrict calling applications to pre-approved domain/DID sets. The isolated
handler rejects non-public DNS destinations and connects only to vetted
addresses, but operators must still control DNS integrity, network routes,
egress and SSRF policy independently, and maintain ordinary TLS validation. The API does not prove DNS ownership, historical key control,
a trusted issuer, actual private-key possession, legal identity, live
revocation, human consent, Agent authority or third-party wallet
interoperability. It neither changes existing `did:key` issuer verification
nor automatically promotes a retrieved key into trust.

## Offline two-key publication overlap (opt-in)

For an operator-planned `did:web` key change, the SDK can prepare a **DID
Core 1.0** document that explicitly lists both the old and successor Ed25519
verification methods at the same DID. The established `did:web` and its
canonical HTTPS publication URI remain unchanged. This is a deliberately
restricted dual-key overlap profile, not a signing-key recovery, private-key
possession proof, permission to use a key, or automatic trust transition.

```csharp
using HeroSSID.DidOperations.DidMethods;

// Both 32-byte public keys and this DID must be preapproved by your operator.
// The caller separately retains and protects the corresponding private keys.
const string did = "did:web:issuer.example.org:organisations:acme";
string documentToPublish = DidWebPinnedKeyTransition.CreateTransitionDocument(
    did, pinnedOldPublicKey, pinnedSuccessorPublicKey);
Uri uri = DidWebMethod.GetDocumentUri(did);
// https://issuer.example.org/organisations/acme/did.json
// Operator publishes documentToPublish at this exact URI, via controlled HTTPS.

// A different verifier, after independently fetching the document using
// audited HTTPS/DNS/SSRF protections, can check both *pre-enrolled* pins:
bool exactOverlap = DidWebPinnedKeyTransition.MatchesExpectedTransitionDocument(
    did, pinnedOldPublicKey, pinnedSuccessorPublicKey, fetchedDocument);
if (!exactOverlap)
{
    // Reject substitution, reordered key identities, extra capabilities, etc.
}
```

The generated `verificationMethod` set uses `#key-1` for the previously
pinned key and `#key-2` for the independently pinned successor. **Both are
advertised as active** by the DID document's `authentication` and
`assertionMethod` arrays throughout the overlap. Operators must decide
**when** to publish the dual-key document, prove their private key possession
separately, and retire the old method and update relying-party key trust under
their own policy. The library does not automatically enable a verifier to
trust a successor or accept credentials signed by either method.

Only the precise generated two-key profile passes the opt-in matcher:
unexpected capability delegation, any extra service or key, changed
controllers/references, duplicate JSON properties, substituted bytes and
malformed/oversized documents are rejected. The original one-key
`DidWebPublishedKeyMatch` **does not** silently accept dual-key documents.
The existing isolated `FetchAndMatchWithIsolatedTransportAsync` is still a
**single-key** fetch. For overlap documents, use your own audited HTTP
transport and pass the returned bytes to the offline matcher; the SDK
does not host or retrieve dual-key documents on your behalf.

This implements a constrained shape permitted by the W3C
[DID Core 1.0 Recommendation](https://www.w3.org/TR/did-core/#verification-relationships),
**not** proof of complete DID/did:web method conformance, key custody,
issuer trust, legal identity, Agent delegation, business authorisation or
third-party Wallet interoperability. No database/schema, production
publishing, actual DNS, secrets, deployment or package release is involved.
