#pragma warning disable CA2007, CA2234, CA1062 // Test code uses readable relative HTTP paths and xUnit synchronization.
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Data;
using HeroSSID.Data.Entities;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;

namespace HeroSSID.Api.Tests;

public sealed class AuthenticationPipelineTests
{
    private const string Secret = "HTTP-regression-test-signing-key-with-at-least-32-bytes";
    private static readonly string[] MembershipCredentialTypes = ["VerifiableCredential", "MembershipCredential"];
    private static readonly Guid TenantA = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly Guid TenantB = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");

    [Theory]
    [InlineData("POST", "/api/v1/dids")]
    [InlineData("GET", "/api/v1/dids/did:key:missing")]
    [InlineData("POST", "/api/v1/credentials/issue")]
    [InlineData("POST", "/api/v1/credentials/verify")]
    public async Task ProtectedOperationsRequireBearerAndExactScope(string method, string path)
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(client, method, path)).StatusCode);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token([new("tenant_id", TenantA.ToString())]));
        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(client, method, path)).StatusCode);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token([new("tenant_id", TenantA.ToString()), new("scope", "did:manage-extra credential:issue-extra credential:verify-extra")]));
        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(client, method, path)).StatusCode);
        var requiredScope = path.Contains("dids", StringComparison.Ordinal) ? "did:manage"
            : path.EndsWith("issue", StringComparison.Ordinal) ? "credential:issue" : "credential:verify";
        var wrongScope = requiredScope == "did:manage" ? "credential:issue" : "did:manage";
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token([new("tenant_id", TenantA.ToString()), new("scope", wrongScope)]));
        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(client, method, path)).StatusCode);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token([new("tenant_id", TenantA.ToString()), new("scope", requiredScope)]));
        var expected = method == "GET" ? HttpStatusCode.NotFound : requiredScope == "did:manage" ? HttpStatusCode.Created : HttpStatusCode.BadRequest;
        Assert.Equal(expected, (await SendAsync(client, method, path)).StatusCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-guid")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("duplicate")]
    public async Task InvalidTenantClaimsAreRejectedBeforeOperations(string? tenant)
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        var claims = new List<Claim> { new("scope", "did:manage credential:issue credential:verify") };
        if (tenant == "duplicate")
        {
            claims.Add(new("tenant_id", TenantA.ToString()));
            claims.Add(new("tenant_id", TenantB.ToString()));
        }
        else if (tenant is not null) { claims.Add(new("tenant_id", tenant)); }
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token(claims));
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(client, "POST", "/api/v1/dids")).StatusCode);
        using var scope = factory.Services.CreateScope();
        Assert.Empty(await scope.ServiceProvider.GetRequiredService<HeroDbContext>().Dids.ToListAsync());
    }

    [Theory]
    [InlineData("\"tenant_id\":\"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\",\"tenant_id\":\"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\"")]
    [InlineData("\"tenant_id\":\"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\",\"tenant_id\":\"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\"")]
    [InlineData("\"tenant_id\":\"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\",\"tenant_\\u0069d\":\"bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\"")]
    [InlineData("\"tenant_id\":[\"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\"]")]
    [InlineData("\"tenant_id\":null")]
    [InlineData("\"tenant_id\":42")]
    [InlineData("\"tenant_id\":{}")]
    [InlineData("\"tenant_id\":\"not-a-guid\"")]
    [InlineData("\"tenant_id\":\"unterminated")]
    public async Task RawTenantMembersMustBeOneGuidStringBeforeClaimNormalization(string tenantMembers)
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        // Sign literal JSON so duplicate member names survive token construction.
        var payload = "{\"iss\":\"https://http-test.example\",\"aud\":\"https://http-test.example\",\"nbf\":" + (now - 10) +
            ",\"exp\":" + (now + 600) + ",\"scope\":\"did:manage\"," + tenantMembers + "}";
        var input = Base64UrlEncoder.Encode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}") + "." + Base64UrlEncoder.Encode(payload);
        var token = input + "." + Base64UrlEncoder.Encode(HMACSHA256.HashData(Encoding.UTF8.GetBytes(Secret), Encoding.ASCII.GetBytes(input)));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(client, "POST", "/api/v1/dids")).StatusCode);
        using var scope = factory.Services.CreateScope();
        Assert.Empty(await scope.ServiceProvider.GetRequiredService<HeroDbContext>().Dids.ToListAsync());
    }

    [Theory]
    [InlineData("signature")]
    [InlineData("issuer")]
    [InlineData("audience")]
    [InlineData("expired")]
    [InlineData("HS384")]
    public async Task UnvalidatedBearerCannotOperate(string defect)
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token(
            [new("tenant_id", TenantA.ToString()), new("scope", "did:manage")], defect));
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(client, "POST", "/api/v1/dids")).StatusCode);
    }

    [Fact]
    public async Task TwoTenantsCreateOwnedDidsAndCannotUseEachOthersIssuer()
    {
        await using var factory = new ApiFactory();
        using var a = factory.CreateClient();
        using var b = factory.CreateClient();
        // Exercise both repeated scope claims and a single space-delimited claim.
        a.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token([new("tenant_id", TenantA.ToString()), new("scope", "did:manage"), new("scope", "credential:issue"), new("scope", "credential:verify")]));
        b.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token([new("tenant_id", TenantB.ToString()), new("scope", "did:manage credential:issue credential:verify")]));
        var issuer = await CreateDidAsync(a);
        var holder = await CreateDidAsync(b);
        using (var scope = factory.Services.CreateScope())
        {
            var dids = await scope.ServiceProvider.GetRequiredService<HeroDbContext>().Dids.ToListAsync();
            Assert.Equal(TenantA, Assert.Single(dids, d => d.DidIdentifier == issuer).TenantId);
            Assert.Equal(TenantB, Assert.Single(dids, d => d.DidIdentifier == holder).TenantId);
        }
        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"/api/v1/dids/{issuer}")).StatusCode);
        var request = new { IssuerDid = issuer, HolderDid = holder, CredentialType = "Degree", Claims = new { degree = "BSc" } };
        Assert.Equal(HttpStatusCode.BadRequest, (await b.PostAsJsonAsync("/api/v1/credentials/issue", request)).StatusCode);
        var issued = await a.PostAsJsonAsync("/api/v1/credentials/issue", request);
        Assert.Equal(HttpStatusCode.Created, issued.StatusCode);
        var credential = (await issued.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("credential").GetString();
        var crossTenant = await b.PostAsJsonAsync("/api/v1/credentials/verify", new { Credential = credential });
        Assert.Equal(HttpStatusCode.OK, crossTenant.StatusCode);
        var unavailable = await crossTenant.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(unavailable.GetProperty("isValid").GetBoolean());
        Assert.Equal(JsonValueKind.Null, unavailable.GetProperty("issuerDid").ValueKind);
        Assert.Equal(JsonValueKind.Null, unavailable.GetProperty("holderDid").ValueKind);
        var verified = await a.PostAsJsonAsync("/api/v1/credentials/verify", new { Credential = credential });
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        Assert.True((await verified.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("isValid").GetBoolean());
    }

    [Theory]
    [InlineData(false, HttpStatusCode.BadRequest, false)]
    [InlineData(true, HttpStatusCode.OK, false)]
    [InlineData(true, HttpStatusCode.BadRequest, true)]
    public async Task HttpVerificationSeparatesSignedIssuerStatementFromCredential(
        bool complete, HttpStatusCode expectedStatus, bool malformedUnicode)
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            Token([new("tenant_id", TenantA.ToString()), new("scope", "credential:verify")]));

        using var key = NSec.Cryptography.Key.Create(NSec.Cryptography.SignatureAlgorithm.Ed25519,
            new NSec.Cryptography.KeyCreationParameters
            {
                ExportPolicy = NSec.Cryptography.KeyExportPolicies.AllowPlaintextExport
            });
        const string issuer = "did:example:http-credential-structure-issuer";
        const string holder = "did:example:http-credential-structure-holder";
        var publicKey = key.PublicKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeroDbContext>();
            db.Dids.Add(new DidEntity
            {
                Id = Guid.NewGuid(), TenantId = TenantA, DidIdentifier = issuer,
                PublicKeyEd25519 = publicKey, KeyFingerprint = SHA256.HashData(publicKey),
                PrivateKeyEd25519Encrypted = new byte[64], DidDocumentJson = "{}",
                Status = "active", CreatedAt = DateTimeOffset.UtcNow
            });
            await db.SaveChangesAsync();
        }

        var payload = complete
            ? JsonSerializer.Serialize(new
            {
                iss = issuer, sub = holder, iat = DateTimeOffset.UtcNow.AddMinutes(-1).ToUnixTimeSeconds(),
                vc = new { type = MembershipCredentialTypes, credentialSubject = new { id = holder, role = "Member" } }
            })
            : JsonSerializer.Serialize(new { iss = issuer });
        if (malformedUnicode)
        {
            payload = payload.Replace("\"MembershipCredential\"", "\"\\uD800\"", StringComparison.Ordinal);
            Assert.Contains("\\uD800", payload, StringComparison.Ordinal);
        }

        var privateKey = key.Export(NSec.Cryptography.KeyBlobFormat.RawPrivateKey);
        string credential;
        try
        {
            credential = HeroSSID.Credentials.Utilities.Ed25519JwtSigner.CreateSignedJwt(
                "{\"typ\":\"vc+jwt\",\"alg\":\"EdDSA\"}", payload, privateKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKey);
        }

        using var response = await client.PostAsJsonAsync("/api/v1/credentials/verify", new { credential });
        Assert.Equal(expectedStatus, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        if (complete && !malformedUnicode)
        {
            Assert.True(body.GetProperty("isValid").GetBoolean());
            Assert.Equal(issuer, body.GetProperty("issuerDid").GetString());
            Assert.Equal(holder, body.GetProperty("holderDid").GetString());
        }
        else
        {
            Assert.False(body.TryGetProperty("isValid", out _));
            Assert.False(body.TryGetProperty("holderDid", out _));
            Assert.False(body.TryGetProperty("issuerDid", out _));
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("too-short")]
    [InlineData("your-256-bit-secret-key-change-in-production-min-32-chars")]
    public async Task StartupRejectsUnsafeSigningConfiguration(string? secret)
    {
        await using var factory = new ApiFactory(secret);
        var exception = Assert.Throws<InvalidOperationException>(() => factory.CreateClient());
        Assert.Contains("Jwt:Secret", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OAuthIssuedTokenUsesConfiguredIssuerAudienceAndTenant()
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = KeyDerivation.Pbkdf2("correct", salt, KeyDerivationPrf.HMACSHA256, 100000, 32);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeroDbContext>();
            db.OAuthClients.Add(new OAuthClient { Id = Guid.NewGuid(), ClientId = "issued-client", DisplayName = "HTTP test", TenantId = TenantB, Scopes = "did:manage", ClientSecretHash = Convert.ToBase64String(salt.Concat(hash).ToArray()), IsEnabled = true });
            await db.SaveChangesAsync();
        }
        using var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials", ["client_id"] = "issued-client",
            ["client_secret"] = "correct", ["scope"] = "did:manage"
        });
        var response = await client.PostAsync("/oauth2/token", body);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var accessToken = (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("access_token").GetString();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        var did = await CreateDidAsync(client);
        using var check = factory.Services.CreateScope();
        Assert.Equal(TenantB, (await check.ServiceProvider.GetRequiredService<HeroDbContext>().Dids.SingleAsync(d => d.DidIdentifier == did)).TenantId);
        Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(client, "POST", "/api/v1/credentials/issue")).StatusCode);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    public async Task TokenEndpointRejectsWrongSecretsAndMalformedStoredHashes(int lengthDelta)
    {
        await using var factory = new ApiFactory();
        using var client = factory.CreateClient();
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = KeyDerivation.Pbkdf2("correct", salt, KeyDerivationPrf.HMACSHA256, 100000, 32);
        var stored = salt.Concat(hash).ToArray();
        if (lengthDelta != 0) { Array.Resize(ref stored, stored.Length + lengthDelta); }
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<HeroDbContext>();
            db.OAuthClients.Add(new OAuthClient { Id = Guid.NewGuid(), ClientId = "http-client", DisplayName = "HTTP test", TenantId = TenantA, Scopes = "did:manage", ClientSecretHash = Convert.ToBase64String(stored), IsEnabled = true });
            await db.SaveChangesAsync();
        }
        using var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials", ["client_id"] = "http-client",
            ["client_secret"] = lengthDelta == 0 ? "wrong" : "correct", ["scope"] = "did:manage"
        });
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsync("/oauth2/token", body)).StatusCode);
    }

    private static Task<HttpResponseMessage> SendAsync(HttpClient client, string method, string path) =>
        method == "GET" ? client.GetAsync(path) : client.PostAsJsonAsync(path, new { Method = "did:key", KeyType = "Ed25519" });

    private static async Task<string> CreateDidAsync(HttpClient client)
    {
        var response = await SendAsync(client, "POST", "/api/v1/dids");
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("did").GetString()!;
    }

    private static string Token(IEnumerable<Claim> claims, string? defect = null)
    {
        var now = DateTime.UtcNow;
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            issuer: defect == "issuer" ? "https://wrong.example" : "https://http-test.example",
            audience: defect == "audience" ? "https://wrong.example" : "https://http-test.example",
            claims: claims, notBefore: now.AddHours(-2), expires: defect == "expired" ? now.AddHours(-1) : now.AddHours(1),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(defect == "signature" ? Secret + "wrong" : Secret)), defect == "HS384" ? SecurityAlgorithms.HmacSha384 : SecurityAlgorithms.HmacSha256)));
    }

    private sealed class ApiFactory(string? secret = Secret) : WebApplicationFactory<Program>
    {
        private readonly string _database = Guid.NewGuid().ToString();
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Secret"] = secret, ["Jwt:Issuer"] = "https://http-test.example", ["Jwt:Audience"] = "https://http-test.example",
                ["ConnectionStrings:HeroDb"] = "Host=unused;Database=unused", ["HEROSSID_DB_PASSWORD"] = "unused"
            }));
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<DbContextOptions<HeroDbContext>>();
                services.RemoveAll<IDbContextOptionsConfiguration<HeroDbContext>>();
                services.AddDbContext<HeroDbContext>(options => options.UseInMemoryDatabase(_database));
                services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
            });
        }
    }
}
