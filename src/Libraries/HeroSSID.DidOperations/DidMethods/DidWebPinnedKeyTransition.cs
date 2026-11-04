namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Offline two-key did:web transition document for an operator-pinned old and
/// new Ed25519 public key. This is not private-key control proof or trust
/// promotion; callers independently enroll both keys and verify publication.
/// </summary>
public static class DidWebPinnedKeyTransition
{
    public static string CreateTransitionDocument(
        string didIdentifier, byte[] oldPublicKey, byte[] newPublicKey) =>
        throw new NotSupportedException("Test-first runtime RED: transition not implemented.");

    public static bool MatchesExpectedTransitionDocument(
        string didIdentifier, byte[] pinnedOldPublicKey,
        byte[] pinnedNewPublicKey, string publishedDocumentJson) =>
        throw new NotSupportedException("Test-first runtime RED: transition not implemented.");
}
