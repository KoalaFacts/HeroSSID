using System.Text.Json;
using HeroSSID.Credentials.Utilities;

namespace HeroSSID.Credentials.VerifiablePresentations;

/// <summary>Shared input and time rules for the bounded local presentation profile.</summary>
internal static class PresentationChallengePolicy
{
    internal const int MaximumIdentifierLength = 2048;

    internal static TimeSpan Validate(Guid tenantId, string audience, string issuer, TimeSpan? lifetime)
    {
        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException("A non-empty verifier tenant is required.", nameof(tenantId));
        }

        ValidateIdentifier(audience, nameof(audience));
        ValidateIdentifier(issuer, nameof(issuer));
        var duration = lifetime ?? TimeSpan.FromMinutes(2);
        if (duration < TimeSpan.FromSeconds(1) || duration > InMemoryPresentationChallengeStore.MaximumLifetime)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), "Challenge lifetime must be between one second and five minutes.");
        }

        return duration;
    }

    internal static int TenantCapacity(int capacity, int? tenantCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(capacity);
        var limit = tenantCapacity ?? Math.Min(capacity, 128);
        if (limit < 1 || limit > capacity)
        {
            throw new ArgumentOutOfRangeException(nameof(tenantCapacity), "Tenant capacity must be positive and no larger than global capacity.");
        }

        return limit;
    }

    internal static bool IsValidLookup(Guid tenantId, string audience, string nonce) =>
        tenantId != Guid.Empty && !string.IsNullOrWhiteSpace(audience) &&
        audience.Length <= MaximumIdentifierLength && IsValidNonce(nonce);

    internal static bool IsValidNonce(string nonce)
    {
        if (string.IsNullOrEmpty(nonce) || nonce.Length != 43)
        {
            return false;
        }

        try
        {
            var bytes = Base64UrlEncoder.DecodeBytes(nonce);
            return bytes.Length == 32 && string.Equals(Base64UrlEncoder.Encode(bytes), nonce, StringComparison.Ordinal);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            return false;
        }
    }

    internal static DateTimeOffset Expiry(DateTimeOffset now, TimeSpan duration)
    {
        // PostgreSQL timestamps retain microseconds, not whole seconds. Return exactly what is stored.
        var ticks = now.Add(duration).UtcTicks;
        return new DateTimeOffset(ticks - (ticks % TimeSpan.TicksPerMicrosecond), TimeSpan.Zero);
    }

    internal static decimal NumericDate(DateTimeOffset timestamp) =>
        (timestamp.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / (decimal)TimeSpan.TicksPerSecond;

    internal static bool TryGetNumericDate(JsonElement payload, string name, out decimal value)
    {
        value = 0;
        return payload.TryGetProperty(name, out var element) && element.ValueKind == JsonValueKind.Number &&
            element.TryGetDecimal(out value) && value >= 0 && value < 253402300800m;
    }

    private static void ValidateIdentifier(string value, string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, parameterName);
        if (value.Length > MaximumIdentifierLength)
        {
            throw new ArgumentException("Identifier exceeds the 2048-character limit.", parameterName);
        }
    }
}
