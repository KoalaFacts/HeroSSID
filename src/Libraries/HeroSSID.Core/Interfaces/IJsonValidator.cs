namespace HeroSSID.Core.Services;

/// <summary>
/// Interface for validating JSON input to prevent injection attacks.
/// </summary>
public interface IJsonValidator
{
    /// <summary>
    /// Validates that a string contains well-formed JSON and meets size constraints.
    /// </summary>
    /// <param name="json">The JSON string to validate.</param>
    /// <param name="maxSizeBytes">Maximum allowed size in bytes (default: 1 MB).</param>
    /// <returns>Result indicating if the JSON is valid and any error message.</returns>
    public JsonValidationResult ValidateJson(string? json, int maxSizeBytes = 1_048_576);

    /// <summary>
    /// Validates and parses JSON to a specific type.
    /// </summary>
    /// <typeparam name="T">The type to deserialize to.</typeparam>
    /// <param name="json">The JSON string to validate and parse.</param>
    /// <param name="maxSizeBytes">Maximum allowed size in bytes.</param>
    /// <returns>Parsed object or null if validation fails.</returns>
    public JsonParseResult<T> ValidateAndParse<T>(string? json, int maxSizeBytes = 1_048_576) where T : class;
}
