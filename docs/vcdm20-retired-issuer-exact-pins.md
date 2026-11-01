# Direct VC2 retired-issuer exact-JWT trust (opt-in SDK)

A relying party can independently enroll the exact original signed JWTs it still trusts from a retired Ed25519 issuer. Newly signed or backdated credentials from that retired key do **not** inherit trust. Independently enrolled active issuer DIDs still work normally.

This is a bounded .NET 10 SDK feature, **not** an HTTP endpoint, status registry, OpenID4VP certification or demonstrated third-party wallet interoperability.

## Entrypoint

The verifier acquires the original, unmodified compact VC2 JWT through its own trusted channel and registers its lowercase SHA-256 digest with the retired issuer DID. With System.Security.Cryptography and System.Text:

    var digest = Convert.ToHexStringLower(
        SHA256.HashData(Encoding.UTF8.GetBytes(historicalOriginalJwt)));
    var pin = new Vcdm20RetiredCredentialPin(retiredIssuerDid, digest);

A credential then undergoes the **real** original-issuer signature check and all independently pinned holder, type, HTTPS context and expiry checks:

    Vcdm20VerifierPolicyResult result = Vcdm20RetiredIssuerVerifier.Check(
        credentialJwt, [activeIssuerDid], [pin], expectedHolderDid,
        expectedCredentialType, pinnedContextUri, DateTimeOffset.UtcNow,
        out string authenticatedIssuer, out JsonElement verifiedClaims);

Only SignedButStatusUnchecked returns the authenticated issuer and claims here; no revocation was checked. The CheckWithStatus overload additionally requires an authentic, current, exact-signer private 60-second status snapshot. It returns SignedNotListed on a properly signed snapshot that does not contain the exact JWT, IssuerReportedRevoked when listed, and Invalid for untrusted/invalid/stale/foreign status. Failed calls disclose no issuer or subject claims.

## Security and operational limits

- The verifier **must** obtain and securely persist its own prior exact-JWT inventory; neither a submitted bearer JWT nor a cross-signed successor statement automatically enrolls a retired credential. A digest does not prove when an artifact was first issued or when the pin was registered. A compromised old signing key could still create convincing artifacts if a verifier independently enrolls them.
- Active and retired issuers must be disjoint. At most 16 active DIDs, 16 distinct issuer DIDs across both groups, and 256 exact retired credential pins are accepted. Every lowercase 64-hex digest and every DID is validated before checking the token. Duplicates, overlaps, malformed entries or an empty trust policy fail closed.
- A matching digest by itself cannot authenticate the JWT; real Ed25519 issuer signature, subject binding, direct VC2 type, pinned HTTPS vocabulary and time validity must still pass.
- The optional status snapshot must be signed by the exact authenticated issuer. SignedNotListed is not evidence of completeness, live non-revocation, or integrity of a key known to be compromised.
- A direct VC2 JWT issuer signature alone does not establish holder possession, real identity, human consent, delegated agent permission or business authorization. Use a separately authenticated, nonce-bound holder presentation when holder control matters.
- No key rotation, lost-key recovery, public discovery, trusted pin acquisition or persistence is supplied here. This is a private operational policy, not a W3C Bitstring Status List.

See [the architecture vision](VISION.md), [the capabilities inventory](../README.md#implemented-capabilities-and-boundaries), and [the VC1.1 variant](jwt-vc-json-retired-issuer-exact-pins.md). Local runtime regressions are not independent security certification.
