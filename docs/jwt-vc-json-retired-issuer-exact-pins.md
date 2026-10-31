# VC1.1 exact-credential pins when retiring issuer signing keys (opt-in)

A verifier may need to accept a few still-valid, previously registered W3C VC Data Model 1.1 `jwt_vc_json` credentials after retiring an issuer's Ed25519 `did:key`. Simply retaining that old DID in the general trust list also accepts **new or deliberately backdated credentials** signed with that old key. If the key has leaked, signed `iat` is not independent issuance-time evidence.

`JwtVcJsonRetiredIssuerVerifier` separates two verifier-owned policies:

1. **Active issuer DID set**: independently pinned Ed25519 keys allowed to sign *new* accepted credentials.
2. **Retired issuer exact-credential pins**: each is the retired issuer DID **and the lowercase hexadecimal SHA-256 of the exact original compact JWT string** registered from an independent trusted inventory, ideally before retiring the key. A retired signature on any *other* JWT is rejected even if it contains a valid-looking earlier `iat`.

Both original issuer signature and exact holder DID, expanded HTTPS credential type, HTTPS context, VC1.1 JWT structure and expiry are still independently verified. A pin is never a substitute for those checks, nor is it derived from the presented JWT's untrusted header. When no longer needed, the verifier removes the pin. Up to 16 distinct issuer DIDs total and 256 retired JWT pins are accepted by this bounded offline SDK.

```csharp
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.JwtVcJson;

// Obtain the original signed JWTs from a trusted, independently verified
// issuance inventory. Never blindly register a fingerprint offered by a holder.
string historicalSignedJwt = trustedIssuerInventoryCredential;
string digest = Convert.ToHexStringLower(
    SHA256.HashData(Encoding.UTF8.GetBytes(historicalSignedJwt)));

JwtVcJsonRetiredCredentialPin[] retired =
[
    new(retiredIssuerDid, digest)
];

var outcome = JwtVcJsonRetiredIssuerVerifier.Check(
    submittedOriginalSignedJwt,
    [currentIssuerDid],
    retired,
    expectedHolderDid,
    "https://issuer.example/credentials#Membership",
    new Uri("https://issuer.example/contexts/membership/v1"),
    TimeProvider.System.GetUtcNow(),
    out string actualIssuerDid,
    out var authenticSubject);

if (outcome != JwtVcJsonTrustedIssuerCheckResult.SignedButStatusUnchecked)
{
    return; // No verified issuer or subject claims are released.
}

// Separately check current revocation policy, holder control and authorization.
```

For a genuine, issuer-signed **private 60-second status snapshot**, call `CheckWithStatus` with the original JWT and original issuer's snapshot. Results are `SignedNotListed`, `Revoked` or `Invalid`. A signed absence does **not** prove completeness or real-time non-revocation. A compromised retired issuer key may also sign misleading status; applications need an independently trustworthy status source.

## Security boundary

- An independently enrolled **exact original JWT** from a retired signer succeeds while it remains valid. A newly signed/backdated JWT with the *same retired key* is denied because its byte-level signed-JWT hash differs. A current issuer's independently trusted signature remains acceptable.
- Invalid, duplicated, overlapping active/retired, too-large, malformed DID or malformed digest policies fail closed. Every entry is validated before accepting a credential, including entries after the matching active issuer. On `Invalid` or `Revoked`, no issuer identity or subject claims are returned.
- The inventory and its enrollment time are **not authenticated by this SDK**. A malicious party controlling that external list can register its own JWT. This feature cannot reconstruct a trusted historical issuance inventory, prove that a pin preceded compromise, prevent stolen credentials from being replayed with the rightful holder's private key, or guarantee recovery from lost/compromised signing keys.
- A VC1.1 JWT in this profile is valid for **at most 15 minutes**; pins cannot extend its original expiry. The format and signatures remain the original `jwt_vc_json` subprofile, not a new JWT format or third-party interoperability proof. This is a verifier-side offline trust policy, not an HTTP endpoint, wallet UI, revocation service, human identity proof or business authorization.

## Real xUnit verification

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj \
  --configuration Release \
  --filter FullyQualifiedName~JwtVcJsonRetiredIssuerVerifierTests
```

The tests use distinct real Ed25519 retired, current, outsider and holder keys. They exercise authentic old/new acceptance, adversarial newly signed/backdated old-key JWT rejection, malformed/overlapping/oversized policy, issuer-specific status and revoked/foreign/expired negative paths. Local SDK tests do not establish independent Wallet compatibility or external cryptographic audit.
