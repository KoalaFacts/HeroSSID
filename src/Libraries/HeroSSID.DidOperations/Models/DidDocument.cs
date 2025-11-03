using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace HeroSSID.DidOperations.Models;

/// <summary>
/// W3C DID Core 1.0 compliant DID Document
/// Reference: https://www.w3.org/TR/did-core/
/// </summary>
public class DidDocument
{
    /// <summary>
    /// JSON-LD context defining the semantic meaning of the document
    /// Required by W3C DID Core 1.0 specification
    /// </summary>
    [JsonPropertyName("@context")]
    [SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "W3C DID spec requires array for JSON-LD context")]
    public required string[] Context { get; set; }

    /// <summary>
    /// The DID subject identifier
    /// </summary>
    [JsonPropertyName("id")]
    public required string Id { get; set; }

    /// <summary>
    /// Verification methods for cryptographic operations
    /// </summary>
    [JsonPropertyName("verificationMethod")]
    [SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "W3C DID spec uses arrays for verification methods")]
    public VerificationMethod[]? VerificationMethod { get; set; }

    /// <summary>
    /// Authentication verification method references
    /// Used to prove control of the DID
    /// </summary>
    [JsonPropertyName("authentication")]
    [SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "W3C DID spec uses arrays for method references")]
    public string[]? Authentication { get; set; }

    /// <summary>
    /// Assertion method verification references
    /// Used for issuing verifiable credentials
    /// </summary>
    [JsonPropertyName("assertionMethod")]
    [SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "W3C DID spec uses arrays for method references")]
    public string[]? AssertionMethod { get; set; }

    /// <summary>
    /// Key agreement verification method references
    /// Used for establishing secure communication
    /// </summary>
    [JsonPropertyName("keyAgreement")]
    [SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "W3C DID spec uses arrays for method references")]
    public string[]? KeyAgreement { get; set; }

    /// <summary>
    /// Capability invocation verification method references
    /// Used for invoking cryptographic capabilities
    /// </summary>
    [JsonPropertyName("capabilityInvocation")]
    [SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "W3C DID spec uses arrays for method references")]
    public string[]? CapabilityInvocation { get; set; }

    /// <summary>
    /// Capability delegation verification method references
    /// Used for delegating cryptographic capabilities
    /// </summary>
    [JsonPropertyName("capabilityDelegation")]
    [SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "W3C DID spec uses arrays for method references")]
    public string[]? CapabilityDelegation { get; set; }

    /// <summary>
    /// Service endpoints for the DID subject
    /// </summary>
    [JsonPropertyName("service")]
    [SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "W3C DID spec uses arrays for services")]
    public DidService[]? Service { get; set; }
}
