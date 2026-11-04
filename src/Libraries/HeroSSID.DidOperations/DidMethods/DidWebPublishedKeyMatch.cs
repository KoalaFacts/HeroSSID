namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Checks whether an externally retrieved did:web DID document matches the
/// independently pinned DID and Ed25519 public key. This is not an HTTP
/// fetch, domain-ownership check, issuer trust decision, or authorization.
/// </summary>
public static class DidWebPublishedKeyMatch
{
    /// <summary>
    /// Returns true only for an exact single-key did:web document profile.
    /// The caller must retrieve content from the pinned publication URL.
    /// </summary>
    public static bool MatchesExpectedDocument(
        string didIdentifier, byte[] expectedPublicKey, string retrievedDocumentJson)
    {
        ArgumentNullException.ThrowIfNull(didIdentifier);
        ArgumentNullException.ThrowIfNull(expectedPublicKey);
        ArgumentNullException.ThrowIfNull(retrievedDocumentJson);

        // Red-stage implementation: tests must exercise the runtime failure.
        return false;
    }
}
