using HeroSSID.DidOperations.Models;

namespace HeroSSID.DidOperations.DidMethod;

/// <summary>
/// Interface for DID method implementations (did:key, did:web, etc.).
/// </summary>
public interface IDidMethod
{
    /// <summary>
    /// Gets the DID method name (e.g., "key", "web").
    /// </summary>
    public string MethodName { get; }

    /// <summary>
    /// Generates a DID identifier from a public key.
    /// </summary>
    /// <param name="publicKey">The public key bytes.</param>
    /// <param name="options">Optional method-specific parameters.</param>
    /// <returns>The complete DID identifier (e.g., "did:key:z6Mk...").</returns>
    public string GenerateDidIdentifier(byte[] publicKey, Dictionary<string, object>? options = null);

    /// <summary>
    /// Creates a DID Document for the given DID identifier.
    /// </summary>
    /// <param name="didIdentifier">The DID identifier.</param>
    /// <param name="publicKey">The public key bytes.</param>
    /// <param name="options">Optional method-specific parameters.</param>
    /// <returns>The W3C-compliant DID Document as JSON string.</returns>
    public string CreateDidDocument(string didIdentifier, byte[] publicKey, Dictionary<string, object>? options = null);

    /// <summary>
    /// Determines if this method can handle the given DID.
    /// </summary>
    /// <param name="did">The DID to check.</param>
    /// <returns>True if this method can handle the DID.</returns>
    public bool CanHandle(string did);

    /// <summary>
    /// Validates if a DID is valid according to this method's rules.
    /// </summary>
    /// <param name="did">The DID to validate.</param>
    /// <returns>True if the DID is valid.</returns>
    public bool IsValid(string did);
}
