using System.Text.Json;

namespace HeroSSID.Core.Services;

/// <summary>
/// Validates JSON input to prevent injection attacks and ensure well-formed JSON.
/// </summary>
public sealed class JsonValidator : IJsonValidator
{
    private const int MaxJsonSizeBytes = 1_048_576; // 1 MB limit for JSON payloads

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        MaxDepth = 64
    };

    /// <summary>
    /// Validates that a string contains well-formed JSON and meets size constraints.
    /// </summary>
    /// <param name="json">The JSON string to validate.</param>
    /// <param name="maxSizeBytes">Maximum allowed size in bytes (default: 1 MB).</param>
    /// <returns>Result indicating if the JSON is valid and any error message.</returns>
    public JsonValidationResult ValidateJson(string? json, int maxSizeBytes = MaxJsonSizeBytes)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new JsonValidationResult(false, "JSON cannot be null or empty.");
        }

        // Check size limit
        var sizeInBytes = System.Text.Encoding.UTF8.GetByteCount(json);
        if (sizeInBytes > maxSizeBytes)
        {
            return new JsonValidationResult(false, $"JSON exceeds maximum size of {maxSizeBytes} bytes (actual: {sizeInBytes} bytes).");
        }

        // Validate JSON structure
        try
        {
            using var document = JsonDocument.Parse(json);

            // Check nesting depth to prevent DoS attacks
            var maxDepth = GetMaxDepth(document.RootElement);
            if (maxDepth > 64)
            {
                return new JsonValidationResult(false, $"JSON nesting depth exceeds maximum of 64 levels (actual: {maxDepth} levels).");
            }

            return new JsonValidationResult(true, null);
        }
        catch (JsonException ex)
        {
            return new JsonValidationResult(false, $"Invalid JSON: {ex.Message}");
        }
    }

    /// <summary>
    /// Validates and parses JSON to a specific type.
    /// </summary>
    /// <typeparam name="T">The type to deserialize to.</typeparam>
    /// <param name="json">The JSON string to validate and parse.</param>
    /// <param name="maxSizeBytes">Maximum allowed size in bytes.</param>
    /// <returns>Parsed object or null if validation fails.</returns>
    public JsonParseResult<T> ValidateAndParse<T>(string? json, int maxSizeBytes = MaxJsonSizeBytes) where T : class
    {
        var validationResult = ValidateJson(json, maxSizeBytes);
        if (!validationResult.IsValid)
        {
            return new JsonParseResult<T>(null, validationResult.ErrorMessage);
        }

        try
        {
            var parsed = JsonSerializer.Deserialize<T>(json!, SerializerOptions);
            if (parsed is null)
            {
                return new JsonParseResult<T>(null, "Failed to deserialize JSON to expected type.");
            }

            return new JsonParseResult<T>(parsed, null);
        }
        catch (JsonException ex)
        {
            return new JsonParseResult<T>(null, $"Failed to parse JSON: {ex.Message}");
        }
    }

    private static int GetMaxDepth(JsonElement element, int currentDepth = 0)
    {
        var maxDepth = currentDepth;

        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in element.EnumerateObject())
            {
                var depth = GetMaxDepth(property.Value, currentDepth + 1);
                if (depth > maxDepth)
                {
                    maxDepth = depth;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in element.EnumerateArray())
            {
                var depth = GetMaxDepth(item, currentDepth + 1);
                if (depth > maxDepth)
                {
                    maxDepth = depth;
                }
            }
        }

        return maxDepth;
    }
}

/// <summary>
/// Result of JSON validation.
/// </summary>
public sealed record JsonValidationResult(bool IsValid, string? ErrorMessage);

/// <summary>
/// Result of JSON parsing with validation.
/// </summary>
/// <typeparam name="T">The type that was parsed.</typeparam>
public sealed record JsonParseResult<T>(T? Value, string? ErrorMessage) where T : class
{
    public bool IsSuccess => Value is not null && ErrorMessage is null;
}
