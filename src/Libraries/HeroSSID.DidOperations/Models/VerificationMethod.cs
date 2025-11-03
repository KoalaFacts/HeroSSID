using System.Text.Json.Serialization;

namespace HeroSSID.DidOperations.Models;

/// <summary>
/// W3C DID Core 1.0 Verification Method
/// Used for cryptographic verification operations
/// Reference: https://www.w3.org/TR/did-core/#verification-methods
/// </summary>
public class VerificationMethod
{
    /// <summary>
    /// Unique identifier for this verification method
    /// Format: {did}#{fragment}
    /// </summary>
    [JsonPropertyName("id")]
    public required string Id { get; set; }

    /// <summary>
    /// Type of verification method
    /// For Ed25519: "Ed25519VerificationKey2020"
    /// Reference: https://w3id.org/security/suites/ed25519-2020/v1
    /// </summary>
    [JsonPropertyName("type")]
    public required string Type { get; set; }

    /// <summary>
    /// DID of the controller of this verification method
    /// Usually the same as the DID subject
    /// </summary>
    [JsonPropertyName("controller")]
    public required string Controller { get; set; }

    /// <summary>
    /// Public key encoded with multibase encoding (base58-btc with 'z' prefix)
    /// Per W3C recommendation, this is preferred over publicKeyBase58
    /// </summary>
    [JsonPropertyName("publicKeyMultibase")]
    public string? PublicKeyMultibase { get; set; }

    /// <summary>
    /// DEPRECATED: Use PublicKeyMultibase instead
    /// Kept for backward compatibility only
    /// </summary>
    [JsonPropertyName("publicKeyBase58")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PublicKeyBase58 { get; set; }

    /// <summary>
    /// Public key in JWK format
    /// Alternative to multibase encoding
    /// </summary>
    [JsonPropertyName("publicKeyJwk")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public object? PublicKeyJwk { get; set; }
}
