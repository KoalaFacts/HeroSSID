using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>Authenticate setup and happy-path requests without hiding anonymous negative tests.</summary>
internal static class AuthenticatedRequests
{
    internal static async Task<HttpResponseMessage> AuthorizedPostAsJsonAsync<T>(this HttpClient client, string path, T value, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = JsonContent.Create(value) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await GetTokenAsync(client, cancellationToken).ConfigureAwait(false));
        return await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<HttpResponseMessage> AuthorizedGetAsync(this HttpClient client, string path, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await GetTokenAsync(client, cancellationToken).ConfigureAwait(false));
        return await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<string> GetTokenAsync(HttpClient client, CancellationToken cancellationToken)
    {
        using var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials", ["client_id"] = "test_client", ["client_secret"] = "test_secret",
            ["scope"] = "did:manage credential:issue credential:verify"
        });
        using var response = await client.PostAsync(new Uri("/oauth2/token", UriKind.Relative), body, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken).ConfigureAwait(false);
        return json.GetProperty("access_token").GetString() ?? throw new InvalidOperationException("Missing access token.");
    }
}
