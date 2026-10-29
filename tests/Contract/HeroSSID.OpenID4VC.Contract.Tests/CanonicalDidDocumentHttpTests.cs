using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using HeroSSID.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace HeroSSID.OpenID4VC.Contract.Tests;

/// <summary>
/// An explicit, read-only representation for existing did:key records.
/// It is not a remote DID resolver or independent wallet conformance suite.
/// </summary>
public sealed class CanonicalDidDocumentHttpTests(AspireWebApplicationFactory factory) : IClassFixture<AspireWebApplicationFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task CanonicalView_RequiresAuthenticationAndRejectsMismatchedOrDeactivatedDid()
    {
        using var created = await _client.AuthorizedPostAsJsonAsync(
            "/api/v1/dids", new { method = "did:key", keyType = "Ed25519" }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var body = await created.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        string did = body.GetProperty("did").GetString()!;
        string path = "/api/v1/dids/" + Uri.EscapeDataString(did) + "/canonical";

        using var anonymous = await _client.GetAsync(path).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        byte[] originalPublicKey;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeroDbContext>();
            var record = await db.Dids.SingleAsync(item => item.DidIdentifier == did).ConfigureAwait(true);
            originalPublicKey = (byte[])record.PublicKeyEd25519.Clone();
            record.PublicKeyEd25519 = new byte[32];
            await db.SaveChangesAsync().ConfigureAwait(true);
        }

        using var mismatched = await _client.AuthorizedGetAsync(path).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, mismatched.StatusCode);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeroDbContext>();
            var record = await db.Dids.SingleAsync(item => item.DidIdentifier == did).ConfigureAwait(true);
            record.PublicKeyEd25519 = originalPublicKey;
            record.Status = "deactivated";
            await db.SaveChangesAsync().ConfigureAwait(true);
        }

        using var deactivated = await _client.AuthorizedGetAsync(path).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.NotFound, deactivated.StatusCode);
    }

    [Fact]
    public async Task LegacyStoredDid_CanBeReadAsCanonicalEd25519DocumentWithoutRewritingIt()
    {
        using var created = await _client.AuthorizedPostAsJsonAsync(
            "/api/v1/dids", new { method = "did:key", keyType = "Ed25519" }).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var createdBody = await created.Content.ReadFromJsonAsync<JsonElement>().ConfigureAwait(true);
        string did = createdBody.GetProperty("did").GetString()!;
        string legacyMethodId = did + "#keys-1";
        string legacyJson = JsonSerializer.Serialize(new
        {
            id = did,
            verificationMethod = new[] { new { id = legacyMethodId, type = "Ed25519VerificationKey2018" } }
        });

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeroDbContext>();
            var record = await db.Dids.SingleAsync(item => item.DidIdentifier == did).ConfigureAwait(true);
            record.DidDocumentJson = legacyJson;
            await db.SaveChangesAsync().ConfigureAwait(true);
        }

        string path = "/api/v1/dids/" + Uri.EscapeDataString(did);
        using var original = await _client.AuthorizedGetAsync(path).ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, original.StatusCode);
        using var originalJson = JsonDocument.Parse(await original.Content.ReadAsStringAsync().ConfigureAwait(true));
        Assert.Equal(legacyMethodId,
            originalJson.RootElement.GetProperty("verificationMethod")[0].GetProperty("id").GetString());

        // PostgreSQL jsonb normalizes whitespace on write. Compare the exact
        // stored representation before and after the read-only canonical request.
        string storedBefore;
        using (var scopeBefore = factory.Services.CreateScope())
        {
            var dbBefore = scopeBefore.ServiceProvider.GetRequiredService<HeroDbContext>();
            storedBefore = await dbBefore.Dids.AsNoTracking()
                .Where(item => item.DidIdentifier == did)
                .Select(item => item.DidDocumentJson)
                .SingleAsync().ConfigureAwait(true);
        }

        using var canonical = await _client.AuthorizedGetAsync(path + "/canonical").ConfigureAwait(true);
        Assert.Equal(HttpStatusCode.OK, canonical.StatusCode);
        using var canonicalJson = JsonDocument.Parse(await canonical.Content.ReadAsStringAsync().ConfigureAwait(true));
        var document = canonicalJson.RootElement;
        string multibase = did["did:key:".Length..];
        string expectedMethodId = did + "#" + multibase;
        Assert.Equal(did, document.GetProperty("id").GetString());
        Assert.Equal(multibase,
            document.GetProperty("verificationMethod")[0].GetProperty("publicKeyMultibase").GetString());
        Assert.Equal(expectedMethodId,
            document.GetProperty("verificationMethod")[0].GetProperty("id").GetString());
        Assert.Equal(expectedMethodId, document.GetProperty("assertionMethod")[0].GetString());
        Assert.Equal(expectedMethodId, document.GetProperty("authentication")[0].GetString());

        using var scopeAfter = factory.Services.CreateScope();
        var dbAfter = scopeAfter.ServiceProvider.GetRequiredService<HeroDbContext>();
        var persisted = await dbAfter.Dids.AsNoTracking()
            .SingleAsync(item => item.DidIdentifier == did).ConfigureAwait(true);
        Assert.Equal(storedBefore, persisted.DidDocumentJson);
    }
}
