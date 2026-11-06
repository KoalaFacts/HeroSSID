# Opt-in verifier emergency denial for a did:web VC1.1 holder presentation

A verifier that has independently enrolled an issuer's `did:web` assertion method and raw Ed25519 public key may need to immediately refuse one **exact original issuer-signed credential JWT**, even while that issuer is offline. The `JwtVcJsonPinnedDidWebPresentationDenylist.Check` SDK adds a local, explicitly provisioned SHA-256 blocklist to the #215 signed holder-VP flow.

The verifier must maintain the blocked set under its own authenticated administrative policy and share that policy across replicas; the holder never supplies trusted denylist entries. Digests use the lowercase 64-character hexadecimal SHA-256 of the **UTF-8 bytes of the original unmodified compact issuer JWT**, not the holder's VP or a parsed/reserialized credential. Maximum 256 distinct canonical entries. A malformed/duplicated list returns `Invalid` without consuming a valid nonce.

After validating the complete denylist, the method calls the existing `JwtVcJsonPinnedDidWebIssuerPresentation.Check`, which verifies the separately pinned issuer public key, DID assertion method, signed issuer name, exact HTTPS `jti` credential ID, credential type/context/holder, independent holder Ed25519 signature and verifier-owned tenant/audience/nonce. The shared challenge store atomically consumes the nonce before the verifier evaluates the original-JWT digest; an otherwise valid **blocked** presentation returns `DeniedByVerifier` with **no claims** and cannot replay. An unlisted valid presentation returns `SignedButStatusUnchecked` with signed subject claims.

## Example use

```csharp
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.JwtVcJson;

// Provision independently, before accepting a submitted holder proof.
// An administrator marks the exact trusted original issuer JWT as blocked.
string blockedHash = Convert.ToHexStringLower(
    SHA256.HashData(Encoding.UTF8.GetBytes(blockedOriginalIssuerJwt)));
IReadOnlyCollection<string> denied = [blockedHash];

// The caller has a verifier-owned tenant/session, separately enrolled did:web
// issuer DID, #key-2, 32-byte public key, exact signed name and credential ID,
// the same verifier challenge store and expected type/subject context.
var decision = JwtVcJsonPinnedDidWebPresentationDenylist.Check(
    submittedHolderVpJwt, verifierTenantId, expectedAudience, expectedNonce,
    enrolledIssuerDid, enrolledIssuerMethod, enrolledIssuerPublicKey,
    enrolledIssuerName, enrolledCredentialId, expectedCredentialType,
    expectedSubjectContextUri, denied, sharedAtomicChallengeStore,
    TimeProvider.System, out var claims);

if (decision == JwtVcJsonPinnedDidWebDenylistResult.SignedButStatusUnchecked)
{
    // Signed statements only; require status policy and application authority.
}
```

**Security boundary:** This is *verifier-local emergency refusal*, not issuer revocation, issuer-signed status, live non-revocation, proof of DID domain control, identity vetting, holder consent or delegated Agent/business authority. An empty local denylist does not imply any issuer status has been checked. It is not an OpenID4VP HTTP endpoint or third-party wallet interoperability. The original SDK issuer and holder signing APIs are unchanged.

The challenge store must be shared and atomic across verifier instances (for example, the existing PostgreSQL-backed store), and the administrator-managed list must be consistent across instances. No production database operations, schema changes, keys, deployment, packaging or license change are included.

Run the real-key positive and negative coverage under .NET 10:

```bash
dotnet test tests/Unit/HeroSSID.Credentials.Tests/HeroSSID.Credentials.Tests.csproj --configuration Release --filter FullyQualifiedName~JwtVcJsonPinnedDidWebPresentationDenylistTests
```
