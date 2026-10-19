using System.Net;
using System.Text.Json;

namespace HeroSSID.OpenID4VC.Contract.Tests;

internal static class SetupResponse
{
    internal static async Task<string> ReadRequiredStringAsync(
        HttpResponseMessage response,
        HttpStatusCode expectedStatus,
        string operation,
        string propertyName)
    {
        var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        Assert.True(response.StatusCode == expectedStatus,
            $"{operation}: expected HTTP {(int)expectedStatus} ({expectedStatus}), " +
            $"received HTTP {(int)response.StatusCode} ({response.StatusCode}). Response body: {body}");

        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty(propertyName).GetString()
            ?? throw new InvalidOperationException($"{operation}: '{propertyName}' was null.");
    }
}
