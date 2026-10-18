using System.Text.Json;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Data;
using HeroSSID.Infrastructure.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace HeroSSID.Credentials.Tests;

public sealed class CredentialVerificationJsonKindTests
{
    private const string ValidHeader = "{\"typ\":\"vc+jwt\",\"alg\":\"EdDSA\"}";
    private const string ValidPayload = "{\"iss\":\"did:key:issuer\"}";

    [Theory]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("false")]
    [InlineData("123")]
    [InlineData("\"text\"")]
    [InlineData("[]")]
    public async Task NonObjectHeaderIsMalformedBeforeIssuerLookup(string header)
    {
        await AssertMalformedAsync(header, ValidPayload).ConfigureAwait(true);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("false")]
    [InlineData("123")]
    [InlineData("\"text\"")]
    [InlineData("[]")]
    public async Task NonObjectPayloadIsMalformedBeforeIssuerLookup(string payload)
    {
        await AssertMalformedAsync(ValidHeader, payload).ConfigureAwait(true);
    }

    [Theory]
    [InlineData("typ", "null")]
    [InlineData("typ", "true")]
    [InlineData("typ", "false")]
    [InlineData("typ", "123")]
    [InlineData("typ", "[]")]
    [InlineData("typ", "{}")]
    [InlineData("alg", "null")]
    [InlineData("alg", "true")]
    [InlineData("alg", "false")]
    [InlineData("alg", "123")]
    [InlineData("alg", "[]")]
    [InlineData("alg", "{}")]
    public async Task NonStringHeaderClaimIsMalformedBeforeIssuerLookup(string claim, string value)
    {
        var header = claim == "typ"
            ? $"{{\"typ\":{value},\"alg\":\"EdDSA\"}}"
            : $"{{\"typ\":\"vc+jwt\",\"alg\":{value}}}";
        await AssertMalformedAsync(header, ValidPayload).ConfigureAwait(true);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("false")]
    [InlineData("123")]
    [InlineData("[]")]
    [InlineData("{}")]
    public async Task NonStringIssuerIsMalformedBeforeIssuerLookup(string issuer)
    {
        await AssertMalformedAsync(ValidHeader, $"{{\"iss\":{issuer}}}").ConfigureAwait(true);
    }

    [Theory]
    [InlineData("true")]
    [InlineData("false")]
    [InlineData("\"123\"")]
    [InlineData("[]")]
    [InlineData("{}")]
    public async Task NonNumericExpirationIsMalformedBeforeIssuerLookup(string expiration)
    {
        var payload = $"{{\"iss\":\"did:key:issuer\",\"exp\":{expiration}}}";
        await AssertMalformedAsync(ValidHeader, payload).ConfigureAwait(true);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("true")]
    [InlineData("false")]
    [InlineData("123")]
    [InlineData("\"text\"")]
    [InlineData("[]")]
    public async Task NonObjectCredentialIsMalformedBeforeIssuerLookup(string credential)
    {
        var payload = $"{{\"iss\":\"did:key:issuer\",\"vc\":{credential}}}";
        await AssertMalformedAsync(ValidHeader, payload).ConfigureAwait(true);
    }

    [Theory]
    [InlineData("{\"iss\":\"did:key:issuer\"}")]
    [InlineData("{\"iss\":\"did:key:issuer\",\"exp\":null}")]
    [InlineData("{\"iss\":\"did:key:issuer\",\"vc\":{}}")]
    public async Task ValidOptionalClaimShapesStillReachIssuerLookup(string payload)
    {
        // No provider is configured: valid shapes must reach the real issuer lookup,
        // whose operational failure must not be relabeled as malformed input.
        using var context = new HeroDbContext(new DbContextOptions<HeroDbContext>());
        using var limiter = new InMemoryRateLimiter(TimeSpan.FromMinutes(1), 100);
        var service = new CredentialVerificationService(context, limiter);

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => service.VerifyCredentialAsync(
            new TenantContext(), Token(ValidHeader, payload))).ConfigureAwait(true);
        Assert.Contains("No database provider", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task NumericExpirationPreservesNestedSubjectAfterParsing()
    {
        using var context = new HeroDbContext(new DbContextOptions<HeroDbContext>());
        using var limiter = new InMemoryRateLimiter(TimeSpan.FromMinutes(1), 100);
        var service = new CredentialVerificationService(context, limiter);
        const string payload = "{\"iss\":\"did:key:issuer\",\"exp\":0,\"vc\":{\"credentialSubject\":{\"degree\":{\"name\":\"Bachelor\"}}}}";

        var result = await service.VerifyCredentialAsync(
            new TenantContext(), Token(ValidHeader, payload)).ConfigureAwait(true);

        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.Expired, result.Status);
        Assert.Equal(DateTimeOffset.UnixEpoch, result.ExpiresAt);
        Assert.Equal("did:key:issuer", result.IssuerDid);
        var subject = Assert.IsType<Dictionary<string, object>>(result.CredentialSubject);
        var degree = Assert.IsType<JsonElement>(subject["degree"]);
        Assert.Equal("Bachelor", degree.GetProperty("name").GetString());
    }

    private static async Task AssertMalformedAsync(string header, string payload)
    {
        // No database provider, connection, schema creation or data writes are needed.
        using var context = new HeroDbContext(new DbContextOptions<HeroDbContext>());
        using var limiter = new InMemoryRateLimiter(TimeSpan.FromMinutes(1), 100);
        var service = new CredentialVerificationService(context, limiter);

        var result = await service.VerifyCredentialAsync(
            new TenantContext(), Token(header, payload)).ConfigureAwait(true);

        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.MalformedJwt, result.Status);
        Assert.NotEmpty(result.ValidationErrors);
        Assert.Null(result.IssuerDid);
        Assert.Null(result.ExpiresAt);
        Assert.Null(result.CredentialSubject);
    }

    private static string Token(string header, string payload) =>
        $"{Base64UrlEncoder.Encode(header)}.{Base64UrlEncoder.Encode(payload)}.signature";

    private sealed class TenantContext : ITenantContext
    {
        public Guid GetCurrentTenantId() => Guid.Parse("11111111-1111-1111-1111-111111111111");
    }
}
