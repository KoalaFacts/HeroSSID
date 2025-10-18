using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;

namespace HeroSSID.Core.Models;

/// <summary>
/// W3C DID Core 1.0 Service Endpoint
/// Describes services associated with the DID subject
/// Reference: https://www.w3.org/TR/did-core/#services
/// </summary>
public class Service
{
    /// <summary>
    /// Unique identifier for this service
    /// Format: {did}#service-{number} or {did}#service-{name}
    /// </summary>
    [JsonPropertyName("id")]
    public required string Id { get; set; }

    /// <summary>
    /// Type of service
    /// Examples: "LinkedDomains", "CredentialRegistry", "DIDCommMessaging"
    /// </summary>
    [JsonPropertyName("type")]
    public required string Type { get; set; }

    /// <summary>
    /// Service endpoint URI or object
    /// Can be a string URI or complex object depending on service type
    /// </summary>
    [JsonPropertyName("serviceEndpoint")]
    public required object ServiceEndpoint { get; set; }

    /// <summary>
    /// Optional: Routing keys for DIDComm messaging
    /// </summary>
    [JsonPropertyName("routingKeys")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "DIDComm spec uses arrays for routing keys")]
    public string[]? RoutingKeys { get; set; }

    /// <summary>
    /// Optional: Accept media types for the service
    /// </summary>
    [JsonPropertyName("accept")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Service spec uses arrays for accept types")]
    public string[]? Accept { get; set; }
}
