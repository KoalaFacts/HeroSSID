using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Data;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Opt-in HTTP adapter for a genuine issuer-signed VC Data Model 1.1 jwt_vc_json.
/// The holder need not be enrolled; issuer statements do not prove holder control.
/// </summary>
internal static class JwtVcJsonCredentialIssuanceEndpoint
{
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(15);

    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/jwt-vc-json/issue", IssueAsync)
            .RequireAuthorization(CredentialIssueRequirement.PolicyName)
            .WithName("IssueJwtVcJsonCredential")
            .WithSummary("Issue a short-lived W3C VC1.1 jwt_vc_json with a tenant-owned Ed25519 did:key")
            .Produces<IssueJwtVcJsonCredentialResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status500InternalServerError);
    }

    internal static async Task<IResult> IssueAsync(
        [FromBody] IssueJwtVcJsonCredentialRequest request,
        [FromServices] HeroDbContext dbContext,
        [FromServices] IKeyEncryptionService encryption,
        [FromServices] IRateLimiter rateLimiter,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock,
        [FromServices] ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clock);

        string issuerDid = request.IssuerDid ?? string.Empty;
        string holderDid = request.HolderDid ?? string.Empty;
        string credentialType = request.CredentialType ?? string.Empty;
        Uri? context = request.SubjectContextUri;
        DateTimeOffset validUntil = request.ValidUntil ?? DateTimeOffset.MinValue;

        // Require a globally expanded HTTPS type so a bounded DCQL wallet request
        // cannot silently interpret a context-dependent short term differently.
        if (string.IsNullOrWhiteSpace(issuerDid) || issuerDid.Length > 255 ||
            !issuerDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(holderDid) || holderDid.Length > 255 ||
            !holderDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            credentialType.Length > 128 ||
            credentialType.Any(char.IsWhiteSpace) ||
            !Uri.TryCreate(credentialType, UriKind.Absolute, out var typeIri) ||
            typeIri.Scheme != Uri.UriSchemeHttps ||
            typeIri.Host.Length == 0 || typeIri.UserInfo.Length != 0 ||
            context is null || !context.IsAbsoluteUri ||
            context.Scheme != Uri.UriSchemeHttps ||
            context.Host.Length == 0 || context.UserInfo.Length != 0 ||
            context.Fragment.Length != 0 || context.AbsoluteUri.Length > 2048 ||
            request.CredentialSubject.ValueKind != JsonValueKind.Object ||
            validUntil == DateTimeOffset.MinValue)
        {
            return InvalidRequest();
        }

        try
        {
            Guid tenantId = tenantContext.GetCurrentTenantId();
            if (tenantId == Guid.Empty)
            {
                return Results.NotFound();
            }

            // All issuer formats share the established, per-tenant issuance quota.
            if (!await rateLimiter.TryAcquireAsync(
                tenantId, "CREDENTIAL_ISSUE", cancellationToken).ConfigureAwait(false))
            {
                return Results.Problem(title: "Too Many Requests",
                    detail: "The credential issuance rate limit was exceeded.",
                    statusCode: StatusCodes.Status429TooManyRequests);
            }

            var issuer = await dbContext.Dids.AsNoTracking()
                .Where(did => did.TenantId == tenantId &&
                    did.DidIdentifier == issuerDid && did.Status == "active")
                .Select(did => new { did.PublicKeyEd25519, did.PrivateKeyEd25519Encrypted })
                .FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
            if (issuer is null ||
                !string.Equals(new DidKeyMethod().GenerateDidIdentifier(
                    issuer.PublicKeyEd25519), issuerDid, StringComparison.Ordinal))
            {
                // Unknown, inactive, foreign tenant and mismatched DID keys are indistinguishable.
                return Results.NotFound();
            }

            DateTimeOffset now = clock.GetUtcNow();
            TimeSpan lifetime = validUntil - now;
            if (lifetime <= TimeSpan.Zero || lifetime > MaximumLifetime)
            {
                return InvalidRequest();
            }

            byte[]? seed = null;
            try
            {
                seed = encryption.Decrypt(issuer.PrivateKeyEd25519Encrypted);
                string jwt = JwtVcJsonCredential.Create(issuerDid, holderDid,
                    credentialType, context, request.CredentialSubject, seed,
                    now, validUntil);

                if (clock.GetUtcNow() >= validUntil)
                {
                    return Results.Problem(title: "Credential Issuance Unavailable",
                        detail: "The requested validity expired during signing.",
                        statusCode: StatusCodes.Status503ServiceUnavailable);
                }

                return Results.Json(new IssueJwtVcJsonCredentialResponse(
                    jwt, "SignedButStatusUnchecked"),
                    statusCode: StatusCodes.Status201Created);
            }
            finally
            {
                if (seed is not null)
                {
                    CryptographicOperations.ZeroMemory(seed);
                }
            }
        }
        catch (ArgumentException)
        {
            return InvalidRequest();
        }
#pragma warning disable CA1031 // Never disclose signing keys, issuer rows or user claims from unexpected infrastructure faults.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            logger.LogError(exception, "VC1.1 JWT HTTP issuance failed");
            return Results.Problem(title: "Internal Server Error",
                detail: "An unexpected credential issuance error occurred.",
                statusCode: StatusCodes.Status500InternalServerError);
        }
    }

    private static IResult InvalidRequest() => Results.Problem(
        title: "Invalid Request",
        detail: "An active tenant-owned issuer, external did:key holder, HTTPS credential type and vocabulary, matching subject id and expiry within 15 minutes are required.",
        statusCode: StatusCodes.Status400BadRequest);
}

/// <summary>Issuer claims for a short-lived, full-disclosure VC1.1 JWT.</summary>
public sealed class IssueJwtVcJsonCredentialRequest
{
    public string? IssuerDid { get; init; }
    public string? HolderDid { get; init; }
    public string? CredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public JsonElement CredentialSubject { get; init; }
    public DateTimeOffset? ValidUntil { get; init; }
}

/// <summary>Issuer-signed JWT only: no holder proof, live revocation or business authority.</summary>
public sealed record IssueJwtVcJsonCredentialResponse(string Credential, string Status);
