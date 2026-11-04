using System.Net.Http;

namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Explicit finalisation of a did:web two-key overlap. Both original and
/// successor Ed25519 public keys are preapproved by the operator.
/// Retiring a document method never changes credential trust policy.
/// </summary>
public static class DidWebPinnedKeyRetirement
{
    public static string CreateRetirementDocument(
        string didIdentifier, byte[] pinnedOldPublicKey, byte[] pinnedSuccessorPublicKey) =>
        throw new NotSupportedException("Retirement document generation is not implemented.");

    public static bool MatchesExpectedRetirementDocument(
        string didIdentifier, byte[] pinnedOldPublicKey,
        byte[] pinnedSuccessorPublicKey, string publishedDocumentJson) =>
        throw new NotSupportedException("Retirement document verification is not implemented.");

    public static Task<bool> FetchAndMatchAsync(
        string didIdentifier, byte[] pinnedOldPublicKey,
        byte[] pinnedSuccessorPublicKey, HttpClient http,
        TimeSpan? maximumDuration = null, CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Retirement document HTTPS verification is not implemented.");

    public static Task<bool> FetchAndMatchWithIsolatedTransportAsync(
        string didIdentifier, byte[] pinnedOldPublicKey,
        byte[] pinnedSuccessorPublicKey, TimeSpan? maximumDuration = null,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException("Retirement document isolated HTTPS verification is not implemented.");
}
