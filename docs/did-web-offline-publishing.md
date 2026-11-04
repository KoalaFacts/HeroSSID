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
