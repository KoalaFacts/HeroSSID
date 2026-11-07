# Issue a genuine pinned did:web VC2 credential (.NET 10 SDK)

HeroSSID can now produce the **original**, issuer-signed direct W3C
Verifiable Credentials Data Model 2.0 / VC-JOSE-COSE `vc+jwt` profile
accepted by its preexisting `did:web` recipient + exact-claim verifier.
This is an issuer-operated SDK API, not a hosted issuer service or a
third-party wallet interoperability claim.

The issuer must already control its signing key and the matching public
Ed25519 assertion key for one restricted `did:web` DID. Never infer key
ownership, an approved issuer, a member's real identity or business
authority from a self-asserted JWT, DID URL or descriptive name.

```csharp
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;

// Values must come from the issuer's secure configuration/key custody,
// not a user-provided untrusted token. Never log, commit or put seed bytes
// on the CLI command line. issuerSeed and issuerPublicKey are 32 bytes each.
string did = "did:web:issuer.example:members";
string method = did + "#key-1"; // or explicitly approved #key-2
string holder = "did:key:z6Mk..."; // replace with a REAL holder DID
using var subject = JsonDocument.Parse(
    JsonSerializer.Serialize(new { id = holder, membership = "active" }));
DateTimeOffset now = DateTimeOffset.UtcNow;
string jwt = Vcdm20JoseCredential.CreateForPinnedDidWebIssuerAudienceWithId(
    did, method, issuerSeed, issuerPublicKey,
    "Example Membership Issuer",
    new Uri("https://issuer.example/credentials/member/1234"),
    new Uri("https://verifier.example/membership/admission"),
    holder, "MembershipCredential",
    new Uri("https://issuer.example/vocab/membership/v1"),
    subject.RootElement, now.AddMinutes(-1), now.AddMinutes(10));

// Deliver jwt confidentially to the intended holder. Issuing a signed
// claim is NOT a proof of holder key possession or present entitlement.
```

The snippet is a **template**, not an issued credential. The caller must
provide genuine independently managed key material and valid DIDs. HeroSSID
does not create, import, store, rotate, protect or publish the issuer's keys
in this API. The caller owns and clears the private seed. The issuer signs
the exact `@context`, type, issuer `{id,name}`, issuance validity, subject
`id`, one HTTPS `id` and one HTTPS `aud`; `kid` is the exact selected
`#key-1` or `#key-2` method.

The method rejects invalid DID/method combinations, malformed subjects,
wrong/zero signing keys, wrong independently approved public keys, invalid
time windows, unsafe HTTP audiences and unsupported profile extensions.
Before returning, the SDK **verifies its own just-issued JWT** using the
provided public key and existing strict VC2 verifier; mismatched keys
never produce a released credential.

A *separate relying party* must still pre-enroll the actual issuer DID,
approved key and method, signed issuer name, exact credential ID, holder
DID, type, context and intended recipient, and choose whether any signed
membership value is relevant to its application. The existing
[CLI did:web recipient-claim verifier](cli-vc2-didweb-recipient-claim.md)
can check the resulting unchanged JWT; positive and negative real CLI
integration cases are included in the .NET tests.

**Boundary:** This narrow direct-JOSE profile does not perform JSON-LD
processing, VC/JOSE independent conformance, third-party Wallet exchange,
user consent, holder private-key proof, current revocation or status,
DNS/HTTPS domain ownership certification, legal identity, or Agent/business
authorization. A signed `membership=active` is an issuer's statement,
not a current access grant. No production keys, deployment or release
are involved in this change.
