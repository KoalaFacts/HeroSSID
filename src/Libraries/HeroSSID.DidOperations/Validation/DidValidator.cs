using HeroSSID.DidOperations.DidMethod;

namespace HeroSSID.DidOperations.Validation;

/// <summary>
/// Validates DID identifiers according to W3C DID Core specification
/// </summary>
/// <remarks>
/// SECURITY: Prevents injection attacks and malformed DID processing by validating
/// DID syntax before database queries or cryptographic operations.
///
/// W3C DID Syntax: did:method:method-specific-id
/// Example: did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
/// </remarks>
public static class DidValidator
{
    /// <summary>
    /// Validates a DID identifier format and method support
    /// </summary>
    /// <param name="didIdentifier">The DID identifier to validate</param>
    /// <param name="methods">Available DID methods to check against</param>
    /// <returns>True if the DID is valid and supported</returns>
    /// <exception cref="ArgumentException">Thrown when DID format is invalid</exception>
    public static void ValidateDidIdentifier(string didIdentifier, IEnumerable<IDidMethod> methods)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(didIdentifier, nameof(didIdentifier));

        // SECURITY: Validate basic DID syntax (did:method:method-specific-id)
        if (!didIdentifier.StartsWith("did:", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                "Invalid DID format: DID must start with 'did:' prefix",
                nameof(didIdentifier));
        }

        // Split into parts: did:method:method-specific-id
        string[] parts = didIdentifier.Split(':', 3);
        if (parts.Length < 3)
        {
            throw new ArgumentException(
                "Invalid DID format: DID must contain method and method-specific-id (did:method:method-specific-id)",
                nameof(didIdentifier));
        }

        string method = parts[1];
        string methodSpecificId = parts[2];

        // Validate method name contains only lowercase letters, digits, or hyphens
        if (string.IsNullOrWhiteSpace(method) || !IsValidMethodName(method))
        {
            throw new ArgumentException(
                $"Invalid DID method name: '{method}'. Method names must contain only lowercase letters, digits, or hyphens",
                nameof(didIdentifier));
        }

        // Validate method-specific-id is not empty
        if (string.IsNullOrWhiteSpace(methodSpecificId))
        {
            throw new ArgumentException(
                "Invalid DID format: method-specific-id cannot be empty",
                nameof(didIdentifier));
        }

        // SECURITY: Check if the method is supported and validate using method-specific rules
        IDidMethod? didMethod = methods.FirstOrDefault(m => m.CanHandle(didIdentifier));
        if (didMethod == null)
        {
            throw new ArgumentException(
                $"Unsupported DID method: '{method}'. Supported methods: {string.Join(", ", methods.Select(m => m.MethodName))}",
                nameof(didIdentifier));
        }

        // Use method-specific validation
        if (!didMethod.IsValid(didIdentifier))
        {
            throw new ArgumentException(
                $"Invalid DID format for method '{method}': DID failed method-specific validation",
                nameof(didIdentifier));
        }
    }

    /// <summary>
    /// Validates DID method name according to W3C DID spec
    /// Method names must be lowercase letters, digits, or hyphens
    /// </summary>
    private static bool IsValidMethodName(string methodName)
    {
        if (string.IsNullOrWhiteSpace(methodName))
        {
            return false;
        }

        foreach (char c in methodName)
        {
            if (!char.IsAsciiLetterLower(c) && !char.IsDigit(c) && c != '-')
            {
                return false;
            }
        }

        return true;
    }
}
