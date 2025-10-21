namespace HeroSSID.Core.DidMethod;

/// <summary>
/// Interface for DID method implementations.
/// Supports multiple DID methods (did:key, did:web, etc.) through a common abstraction.
/// </summary>
public interface IDidMethod
{
    /// <summary>
    /// DID method name (e.g., "key", "web")
    /// </summary>
    public string MethodName { get; }

    /// <summary>
    /// Generate DID identifier from a public key.
    /// </summary>
    /// <param name="publicKey">32-byte Ed25519 public key</param>
    /// <param name="options">Optional method-specific parameters (e.g., domain for did:web)</param>
    /// <returns>Full DID identifier (e.g., "did:key:z6Mkf...")</returns>
    /// <exception cref="ArgumentNullException">Thrown if publicKey is null</exception>
    /// <exception cref="ArgumentException">Thrown if publicKey is invalid</exception>
    public string GenerateDidIdentifier(byte[] publicKey, Dictionary<string, object>? options = null);

    /// <summary>
    /// Create a W3C DID Document for the given DID identifier and public key.
    /// </summary>
    /// <param name="didIdentifier">The full DID identifier</param>
    /// <param name="publicKey">32-byte Ed25519 public key</param>
    /// <param name="options">Optional method-specific parameters</param>
    /// <returns>W3C DID Document as JSON string</returns>
    /// <exception cref="ArgumentException">Thrown if parameters are invalid</exception>
    public string CreateDidDocument(string didIdentifier, byte[] publicKey, Dictionary<string, object>? options = null);

    /// <summary>
    /// Check if this method can handle the given DID identifier.
    /// </summary>
    /// <param name="did">DID identifier to check</param>
    /// <returns>True if this method can handle the DID, false otherwise</returns>
    public bool CanHandle(string did);

    /// <summary>
    /// Validate that a DID identifier follows the correct format for this method.
    /// </summary>
    /// <param name="did">DID identifier to validate</param>
    /// <returns>True if valid, false otherwise</returns>
    public bool IsValid(string did);
}
