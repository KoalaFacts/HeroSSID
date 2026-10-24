using System.Text.Json;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialIssuance;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Utilities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace HeroSSID.Api.Tests;

public sealed class CredentialEndpointTests
{
    private const string Issuer = "did:key:issuer";
    private const string Holder = "did:key:holder";
    private readonly TenantDouble _tenant = new();
    private readonly LookupDouble _lookup = new();
    private readonly IssuanceDouble _issuance = new();
    private readonly VerificationDouble _verification = new();

    [Fact]
    public async Task IssueReturnsCreatedCredentialAndUsesTenantScopedIssuerLookup()
    {
        using var cancellation = new CancellationTokenSource();
        var request = ValidIssueRequest();
        var result = await IssueAsync(request, cancellation.Token).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status201Created, Status(result));
        Assert.Equal("signed.credential.token", Value<IssueCredentialResponse>(result).Credential);
        Assert.Equal((Issuer, _tenant.Id), _lookup.IssuerLookup);
        Assert.Equal(Holder, _lookup.HolderLookup);
        Assert.Equal(_lookup.IssuerId, _issuance.IssuerId);
        Assert.Equal(_lookup.HolderId, _issuance.HolderId);
        Assert.Same(request.Claims, _issuance.Claims);
        Assert.Equal(request.CredentialType, _issuance.CredentialType);
        Assert.Null(_issuance.Expiration);
        Assert.Equal(cancellation.Token, _lookup.IssuerCancellation);
        Assert.Equal(cancellation.Token, _lookup.HolderCancellation);
        Assert.Same(_tenant, _issuance.Tenant);
        Assert.Equal(cancellation.Token, _issuance.Cancellation);
    }

    [Theory]
    [InlineData(null, Holder, "Degree")]
    [InlineData(" ", Holder, "Degree")]
    [InlineData(Issuer, null, "Degree")]
    [InlineData(Issuer, " ", "Degree")]
    [InlineData(Issuer, Holder, null)]
    [InlineData(Issuer, Holder, " ")]
    public async Task IssueRejectsMissingRequiredStrings(string? issuer, string? holder, string? type)
    {
        var request = new IssueCredentialRequest
        {
            IssuerDid = issuer, HolderDid = holder, CredentialType = type,
            Claims = new Dictionary<string, object> { ["degree"] = "Bachelor" }
        };
        AssertProblem(await IssueAsync(request).ConfigureAwait(true), StatusCodes.Status400BadRequest);
        Assert.False(_issuance.Called);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task IssueRejectsMissingOrEmptyClaims(bool empty)
    {
        var request = new IssueCredentialRequest
        {
            IssuerDid = Issuer, HolderDid = Holder, CredentialType = "Degree",
            Claims = empty ? new Dictionary<string, object>() : null
        };
        AssertProblem(await IssueAsync(request).ConfigureAwait(true), StatusCodes.Status400BadRequest);
        Assert.False(_issuance.Called);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task IssueRejectsUnknownDidsWithoutIssuing(bool missingIssuer)
    {
        if (missingIssuer) { _lookup.IssuerId = null; }
        else { _lookup.HolderId = null; }
        AssertProblem(await IssueAsync(ValidIssueRequest()).ConfigureAwait(true), StatusCodes.Status400BadRequest);
        Assert.False(_issuance.Called);
    }

    [Fact]
    public async Task IssueConvertsServiceValidationToProblemDetails()
    {
        _issuance.Failure = new ArgumentException("private validation detail");
        AssertProblem(await IssueAsync(ValidIssueRequest()).ConfigureAwait(true), StatusCodes.Status400BadRequest);
    }

    [Fact]
    public async Task IssueConvertsKnownRateLimitTo429()
    {
        _issuance.Failure = new InvalidOperationException("Rate limit exceeded for credential issuance");
        AssertProblem(await IssueAsync(ValidIssueRequest()).ConfigureAwait(true), StatusCodes.Status429TooManyRequests);
    }

    [Fact]
    public async Task IssueDoesNotMislabelUnexpectedFailureAsRateLimit()
    {
        _issuance.Failure = new InvalidOperationException("sensitive internal detail");
        var result = await IssueAsync(ValidIssueRequest()).ConfigureAwait(true);
        AssertProblem(result, StatusCodes.Status500InternalServerError);
        Assert.DoesNotContain("sensitive", Value<ProblemDetails>(result).Detail ?? string.Empty, StringComparison.Ordinal);
    }

    [Fact]
    public async Task IssuePreservesCancellation()
    {
        _issuance.Failure = new OperationCanceledException();
        await Assert.ThrowsAsync<OperationCanceledException>(() => IssueAsync(ValidIssueRequest())).ConfigureAwait(true);
    }

    [Fact]
    public async Task VerifyReturnsHolderOnlyAfterSuccessForSameToken()
    {
        var token = TokenWithSubject(Holder);
        _verification.Result = VerificationResult(true, VerificationStatus.Valid);
        var result = await VerifyAsync(token).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, Status(result));
        var value = Value<VerifyCredentialResponse>(result);
        Assert.True(value.IsValid);
        Assert.Equal(Issuer, value.IssuerDid);
        Assert.Equal(Holder, value.HolderDid);
        Assert.Equal(token, _verification.Token);
        Assert.Same(_tenant, _verification.Tenant);
    }

    [Fact]
    public async Task VerifyDoesNotDecodeOrExposeUntrustedClaimsOnFailure()
    {
        _verification.Result = VerificationResult(false, VerificationStatus.SignatureInvalid);
        var result = await VerifyAsync("this cannot be decoded").ConfigureAwait(true);
        var value = Value<VerifyCredentialResponse>(result);
        Assert.Equal(StatusCodes.Status200OK, Status(result));
        Assert.False(value.IsValid);
        Assert.Null(value.HolderDid);
        Assert.Null(value.IssuerDid);
    }

    [Theory]
    [InlineData(VerificationStatus.Expired)]
    [InlineData(VerificationStatus.IssuerNotFound)]
    [InlineData(VerificationStatus.Revoked)]
    public async Task VerifyRepresentsNonMalformedFailuresAsInvalid(VerificationStatus status)
    {
        _verification.Result = VerificationResult(false, status);
        var result = await VerifyAsync("untrusted.token.value").ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, Status(result));
        Assert.False(Value<VerifyCredentialResponse>(result).IsValid);
    }

    [Fact]
    public async Task VerifyMapsMalformedJwtTo400()
    {
        _verification.Result = VerificationResult(false, VerificationStatus.MalformedJwt);
        AssertProblem(await VerifyAsync("invalid.jwt.token").ConfigureAwait(true), StatusCodes.Status400BadRequest);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public async Task VerifyRejectsEmptyTokenWithoutCallingService(string? token)
    {
        AssertProblem(await VerifyAsync(token).ConfigureAwait(true), StatusCodes.Status400BadRequest);
        Assert.Null(_verification.Token);
    }

    [Fact]
    public async Task VerifyConvertsServiceValidationTo400()
    {
        _verification.Failure = new ArgumentException("too large");
        AssertProblem(await VerifyAsync("input").ConfigureAwait(true), StatusCodes.Status400BadRequest);
    }

    [Fact]
    public async Task VerifyConvertsKnownRateLimitTo429()
    {
        _verification.Failure = new InvalidOperationException("Rate limit exceeded for credential verification");
        AssertProblem(await VerifyAsync("input").ConfigureAwait(true), StatusCodes.Status429TooManyRequests);
    }

    [Fact]
    public async Task VerifyDoesNotMislabelUnexpectedFailureAsRateLimit()
    {
        _verification.Failure = new InvalidOperationException("sensitive internal detail");
        AssertProblem(await VerifyAsync("input").ConfigureAwait(true), StatusCodes.Status500InternalServerError);
    }

    [Fact]
    public async Task VerifyPreservesCancellation()
    {
        _verification.Failure = new OperationCanceledException();
        await Assert.ThrowsAsync<OperationCanceledException>(() => VerifyAsync("input")).ConfigureAwait(true);
    }

    [Fact]
    public async Task VerifyDoesNotTreatNonStringSubjectAsHolder()
    {
        _verification.Result = VerificationResult(true, VerificationStatus.Valid);
        var token = "header." + Base64UrlEncoder.Encode("{\"sub\":123}") + ".signature";
        var result = await VerifyAsync(token).ConfigureAwait(true);
        Assert.Null(Value<VerifyCredentialResponse>(result).HolderDid);
    }

    [Fact]
    public async Task VerifyForwardsCancellation()
    {
        using var cancellation = new CancellationTokenSource();
        await CredentialEndpoints.VerifyAsync(new VerifyCredentialRequest { Credential = "invalid.jwt.token" },
            _verification, _tenant, NullLogger<Program>.Instance, cancellation.Token).ConfigureAwait(true);
        Assert.Equal(cancellation.Token, _verification.Cancellation);
    }

    [Fact]
    public async Task IssueSerializesCamelCaseCredential()
    {
        var result = await IssueAsync(ValidIssueRequest()).ConfigureAwait(true);
        var json = await SerializeResultAsync(result).ConfigureAwait(true);
        Assert.Equal("signed.credential.token", json.GetProperty("credential").GetString());
        Assert.False(json.TryGetProperty("Credential", out _));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task VerifySerializesCamelCaseAndNullUntrustedIdentities(bool valid)
    {
        _verification.Result = VerificationResult(valid, valid ? VerificationStatus.Valid : VerificationStatus.SignatureInvalid);
        var result = await VerifyAsync(TokenWithSubject(Holder)).ConfigureAwait(true);
        var json = await SerializeResultAsync(result).ConfigureAwait(true);
        Assert.Equal(valid, json.GetProperty("isValid").GetBoolean());
        Assert.Equal(valid ? Issuer : null, json.GetProperty("issuerDid").GetString());
        Assert.Equal(valid ? Holder : null, json.GetProperty("holderDid").GetString());
    }

    private static async Task<JsonElement> SerializeResultAsync(IResult result)
    {
        using var services = new ServiceCollection().AddLogging().BuildServiceProvider();
        using var body = new MemoryStream();
        var context = new DefaultHttpContext { RequestServices = services };
        context.Response.Body = body;
        await result.ExecuteAsync(context).ConfigureAwait(true);
        Assert.StartsWith("application/json", context.Response.ContentType ?? string.Empty, StringComparison.Ordinal);
        body.Position = 0;
        using var json = await JsonDocument.ParseAsync(body).ConfigureAwait(true);
        return json.RootElement.Clone();
    }

    [Fact]
    public async Task RouteMetadataProtectsIssueAndVerificationWithSeparateScopes()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        await using var app = builder.Build();
        app.MapCredentialEndpoints();
        var endpoints = ((IEndpointRouteBuilder)app).DataSources.SelectMany(source => source.Endpoints).OfType<RouteEndpoint>().ToArray();
        var issue = Assert.Single(endpoints, endpoint => endpoint.RoutePattern.RawText == "/api/v1/credentials/issue");
        var verify = Assert.Single(endpoints, endpoint => endpoint.RoutePattern.RawText == "/api/v1/credentials/verify");
        Assert.Contains(issue.Metadata.GetOrderedMetadata<IAuthorizeData>(), auth => auth.Policy == "credential:issue");
        Assert.Null(issue.Metadata.GetMetadata<IAllowAnonymous>());
        Assert.Null(verify.Metadata.GetMetadata<IAllowAnonymous>());
        Assert.Contains(verify.Metadata.GetOrderedMetadata<IAuthorizeData>(), auth => auth.Policy == "credential:verify");
        Assert.Equal("POST", Assert.Single(issue.Metadata.GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
        Assert.Equal("POST", Assert.Single(verify.Metadata.GetMetadata<IHttpMethodMetadata>()!.HttpMethods));
    }

    private Task<IResult> IssueAsync(IssueCredentialRequest request, CancellationToken cancellationToken = default) =>
        CredentialEndpoints.IssueAsync(request, _lookup, _issuance, _tenant, NullLogger<Program>.Instance, cancellationToken);

    private Task<IResult> VerifyAsync(string? token) =>
        CredentialEndpoints.VerifyAsync(new VerifyCredentialRequest { Credential = token }, _verification, _tenant, NullLogger<Program>.Instance, CancellationToken.None);

    private static IssueCredentialRequest ValidIssueRequest() => new()
    {
        IssuerDid = Issuer, HolderDid = Holder, CredentialType = "Degree",
        Claims = new Dictionary<string, object> { ["degree"] = JsonSerializer.Deserialize<JsonElement>("{\"name\":\"Bachelor\"}") }
    };

    private static string TokenWithSubject(string subject) =>
        "header." + Base64UrlEncoder.Encode(JsonSerializer.Serialize(new { sub = subject })) + ".signature";

    private static CredentialVerificationResult VerificationResult(bool valid, VerificationStatus status) => new()
    {
        IsValid = valid, Status = status, ValidationErrors = [], IssuerDid = Issuer
    };

    private static int? Status(IResult result) => Assert.IsAssignableFrom<IStatusCodeHttpResult>(result).StatusCode;
    private static T Value<T>(IResult result) => Assert.IsType<T>(Assert.IsAssignableFrom<IValueHttpResult>(result).Value);
    private static void AssertProblem(IResult result, int status)
    {
        Assert.Equal(status, Status(result));
        Assert.Equal(status, Value<ProblemDetails>(result).Status);
    }

    private sealed class TenantDouble : ITenantContext
    {
        public Guid Id { get; } = Guid.NewGuid();
        public Guid GetCurrentTenantId() => Id;
    }

    private sealed class LookupDouble : ICredentialDidLookup
    {
        public Guid? IssuerId { get; set; } = Guid.NewGuid();
        public Guid? HolderId { get; set; } = Guid.NewGuid();
        public (string Did, Guid Tenant)? IssuerLookup { get; private set; }
        public string? HolderLookup { get; private set; }
        public CancellationToken IssuerCancellation { get; private set; }
        public CancellationToken HolderCancellation { get; private set; }
        public Task<Guid?> FindIssuerAsync(string did, Guid tenantId, CancellationToken cancellationToken)
        {
            IssuerLookup = (did, tenantId);
            IssuerCancellation = cancellationToken;
            return Task.FromResult(IssuerId);
        }
        public Task<Guid?> FindHolderAsync(string did, CancellationToken cancellationToken)
        {
            HolderLookup = did;
            HolderCancellation = cancellationToken;
            return Task.FromResult(HolderId);
        }
    }

    private sealed class IssuanceDouble : ICredentialIssuanceService
    {
        public bool Called { get; private set; }
        public Guid IssuerId { get; private set; }
        public Guid HolderId { get; private set; }
        public Dictionary<string, object>? Claims { get; private set; }
        public string? CredentialType { get; private set; }
        public DateTimeOffset? Expiration { get; private set; }
        public ITenantContext? Tenant { get; private set; }
        public CancellationToken Cancellation { get; private set; }
        public Exception? Failure { get; set; }
        public Task<string> IssueCredentialAsync(ITenantContext tenantContext, Guid issuerDidId, Guid holderDidId, string credentialType, Dictionary<string, object> credentialSubject, DateTimeOffset? expirationDate = null, CancellationToken cancellationToken = default)
        {
            CredentialType = credentialType; Expiration = expirationDate;
            Called = true; IssuerId = issuerDidId; HolderId = holderDidId; Claims = credentialSubject; Tenant = tenantContext; Cancellation = cancellationToken;
            return Failure is null ? Task.FromResult("signed.credential.token") : Task.FromException<string>(Failure);
        }
    }

    private sealed class VerificationDouble : ICredentialVerificationService
    {
        public CredentialVerificationResult Result { get; set; } = VerificationResult(false, VerificationStatus.MalformedJwt);
        public string? Token { get; private set; }
        public CancellationToken Cancellation { get; private set; }
        public ITenantContext? Tenant { get; private set; }
        public Exception? Failure { get; set; }
        public Task<CredentialVerificationResult> VerifyCredentialAsync(ITenantContext tenantContext, string credentialJwt, CancellationToken cancellationToken = default)
        {
            Token = credentialJwt; Tenant = tenantContext; Cancellation = cancellationToken;
            return Failure is null ? Task.FromResult(Result) : Task.FromException<CredentialVerificationResult>(Failure);
        }

        public Task<CredentialVerificationResult> VerifyCredentialFromIssuerAsync(ITenantContext requesterContext, Guid issuerTenantId, string credentialJwt, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("The REST endpoint must use tenant-local verification.");
    }
}
