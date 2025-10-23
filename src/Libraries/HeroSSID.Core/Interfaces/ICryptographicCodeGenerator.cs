namespace HeroSSID.Core.Services;

/// <summary>
/// Interface for generating cryptographically secure codes with guaranteed entropy.
/// </summary>
public interface ICryptographicCodeGenerator
{
    /// <summary>
    /// Generates a cryptographically secure pre-authorized code with 256-bit entropy.
    /// </summary>
    /// <returns>Base64url-encoded string (44 characters) with 256 bits of entropy.</returns>
    public string GeneratePreAuthorizedCode();

    /// <summary>
    /// Generates a cryptographically secure nonce with 256-bit entropy for replay protection.
    /// </summary>
    /// <returns>Base64url-encoded string (44 characters) with 256 bits of entropy.</returns>
    public string GenerateNonce();

    /// <summary>
    /// Generates a cryptographically secure state value with 256-bit entropy.
    /// </summary>
    /// <returns>Base64url-encoded string (44 characters) with 256 bits of entropy.</returns>
    public string GenerateState();

    /// <summary>
    /// Generates a 6-digit numeric transaction code for QR security.
    /// </summary>
    /// <returns>6-digit numeric string.</returns>
    public string GenerateTransactionCode();

    /// <summary>
    /// Validates that a code meets minimum entropy requirements.
    /// </summary>
    /// <param name="code">The code to validate.</param>
    /// <returns>True if the code meets 256-bit entropy requirements.</returns>
    public bool ValidateCodeEntropy(string code);
}
