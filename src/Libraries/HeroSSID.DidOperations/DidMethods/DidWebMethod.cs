using HeroSSID.Core.Interfaces;

namespace HeroSSID.DidOperations.DidMethods;

/// <summary>
/// Placeholder implementation for did:web method.
/// Full implementation planned for Q4 2025.
/// </summary>
public sealed class DidWebMethod : IDidMethod
{
    /// <inheritdoc />
    public string MethodName => "web";

    /// <inheritdoc />
    public string GenerateDidIdentifier(byte[] publicKey, Dictionary<string, object>? options = null)
    {
        // TODO: Q4 2025 implementation
        // Options should include: domain, path
        // Format: did:web:example.com or did:web:example.com:user:alice
        throw new NotImplementedException(
            "did:web support planned for Q4 2025. Use did:key method instead.");
    }

    /// <inheritdoc />
    public string CreateDidDocument(string didIdentifier, byte[] publicKey, Dictionary<string, object>? options = null)
    {
        // TODO: Q4 2025 implementation
        // Should create DID Document for hosting at https://{domain}/.well-known/did.json
        throw new NotImplementedException(
            "did:web support planned for Q4 2025. Use did:key method instead.");
    }

    /// <inheritdoc />
    public bool CanHandle(string did)
    {
        return did?.StartsWith("did:web:", StringComparison.Ordinal) == true;
    }

    /// <inheritdoc />
    public bool IsValid(string did)
    {
        // Basic format validation only (full validation requires resolution)
        if (!CanHandle(did))
        {
            return false;
        }

        // did:web must have at least a domain after the prefix
        // Format: did:web:{domain}
        return did.Length > 8; // "did:web:".Length == 8
    }
}
