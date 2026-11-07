# Opt-in pinned did:web VC2 issuer status (private JWT profile)

The .NET 10 SDK `Vcdm20PinnedDidWebIssuerStatus` now connects the
issuer-operated direct VCDM 2.0 `vc+jwt` signing path to **same-original-issuer,
same-pinned-Ed25519-key** revocation statements. This is deliberately the
existing private HeroSSID `herossid-vc2-revocation-snapshot+jwt` profile,
**not** a W3C Bitstring Status List, independent Wallet interoperability,
an authoritative network service, or live non-revocation.

The issuer retains its `did:web` identifier, exact preapproved
`#key-1` or `#key-2` assertion method and private Ed25519 seed. Its
independently approved 32-byte public key is passed separately; the
SDK rejects a mismatched signing seed. The issuer operates its **own**
authoritative revocation inventory, records `observedAt` *before*
reading that inventory, and provides the complete list of original,
unchanged signed VC2 JWTs known revoked. Every listed JWT is authenticated
with that exact same pinned issuer method/key and requires the restricted
signed VC2 recipient-bound profile. Only genuine original bytes are
hashed; digest sets are bounded to 256 entries, sorted and deduplicated.

```csharp
// All values come from preapproved operator policy and issuer key custody.
string snapshot = Vcdm20PinnedDidWebIssuerStatus.Create(
    issuerDid, assertionMethodId, issuerSeed, issuerPublicKey, issuerName,
    revokedOriginalVc2Jwts, observedBeforeStatusRead, TimeProvider.System);

// Independently trusted verifier-owned parameters, not copied from the JWT:
var result = Vcdm20PinnedDidWebIssuerStatus.Check(
    snapshot, originalCredentialJwt, trustedIssuerDid,
    trustedAssertionMethodId, trustedIssuerPublicKey, expectedIssuerName,
    expectedCredentialId, expectedRecipient, expectedHolderDid,
    expectedCredentialType, expectedContext,
    verifierMinimumIssuerObservationUtc, DateTimeOffset.UtcNow,
    out JsonElement authenticatedSubject);

if (result == Vcdm20RevocationCheckResult.SignedNotListed)
{
    // Issuer signature and declared fresh non-listed status verified.
    // Do not treat this as holder control or business authorization.
}
```

The verifier **independently pins** original issuer DID, exact assertion
method and public key, descriptive signed name, credential ID, HTTPS
recipient, holder DID, credential type and HTTPS subject vocabulary.
It validates the original issuer signature/expiry and the matching
Ed25519-signed, non-expired status with an independently required minimum
issuer observation timestamp. `SignedNotListed` alone exposes the
issuer-authenticated subject. `Revoked`, invalid original issuer, wrong
key/method/name/ID/recipient/holder, future-dated, forged, malformed,
stale or pre-cutoff status expose no claims.

Status precision is whole Unix seconds and at most **60 seconds from
the issuer's recorded pre-read observation time**. The issuer still has
to ensure revocation inventory completeness, safe key custody, status
distribution and freshness. No code here verifies DNS/domain ownership,
private-key control by the holder, human consent, legal identity, Agent
authority, W3C standard status-list semantics or third-party Wallet
interoperability. Verifier applications must independently enforce all
of those policies as applicable.
