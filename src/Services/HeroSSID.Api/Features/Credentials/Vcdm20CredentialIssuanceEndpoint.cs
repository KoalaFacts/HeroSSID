using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Data;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Authenticated, tenant-owned issuance of an opt-in, short-lived direct VC2 JWS.
/// This endpoint deliberately does not create a database credential or promise
/// that an unregistered/external holder has proved private-key control.
/// </summary>
internal static class Vcdm20CredentialIssuanceEndpoint
{
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(15);

    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/vcdm20/issue", IssueAsync)
            .RequireAuthorization(CredentialIssueRequirement.PolicyName)
            .WithName("IssueVcdm20Credential")
            .WithSummary("Sign a short-lived direct VC2 JWT using this tenant's active did:key issuer")
            .Produces<IssueVcdm20CredentialResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status500InternalServerError);
    }

    internal static async Task<IResult> IssueAsync(
        [FromBody] IssueVcdm20CredentialRequest request,
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
        if (string.IsNullOrWhiteSpace(issuerDid) ||
            issuerDid.Length > 255 ||
            !issuerDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(holderDid) ||
            holderDid.Length > 255 ||
            !holderDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(credentialType) ||
            credentialType.Length > 128 ||
            context is null || !context.IsAbsoluteUri ||
            context.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(context.UserInfo) ||
            !string.IsNullOrEmpty(context.Fragment) ||
            context.AbsoluteUri.Length > 2048 ||
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

            // Share the existing issuance quota; a new format must not bypass it.
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

            if (issuer is null)
            {
                return Results.NotFound();
            }

            // Never let a historical corrupt or mismatched key sign as a tenant DID.
            if (!string.Equals(new DidKeyMethod().GenerateDidIdentifier(
                issuer.PublicKeyEd25519), issuerDid, StringComparison.Ordinal))
            {
                return Results.NotFound();
            }

            DateTimeOffset now = clock.GetUtcNow();
            TimeSpan lifetime = validUntil - now;
            if (lifetime <= TimeSpan.Zero || lifetime > MaximumLifetime)
            {
                return InvalidRequest();
            }

            byte[]? privateKey = null;
            try
            {
                privateKey = encryption.Decrypt(issuer.PrivateKeyEd25519Encrypted);
                string jwt = Vcdm20JoseCredential.Create(
                    issuerDid, holderDid, credentialType,
                    context, request.CredentialSubject, privateKey, now,
                    validUntil);

                // No stale assertion should be returned after a slow signing operation.
                if (clock.GetUtcNow() >= validUntil)
                {
                    return Results.Problem(title: "Credential Issuance Unavailable",
                        detail: "The requested credential lifetime elapsed during issuance.",
                        statusCode: StatusCodes.Status503ServiceUnavailable);
                }

                return Results.Json(
                    new IssueVcdm20CredentialResponse(jwt, "SignedButStatusUnchecked"),
                    statusCode: StatusCodes.Status201Created);
            }
            finally
            {
                if (privateKey is not null)
                {
                    CryptographicOperations.ZeroMemory(privateKey);
                }
            }
        }
        catch (ArgumentException)
        {
            return InvalidRequest();
        }
#pragma warning disable CA1031 // Unexpected signer/database failures must not disclose keys, claims or tenant records.
        catch (Exception exception) when (exception is not OperationCanceledException)
#pragma warning restore CA1031
        {
            logger.LogError(exception, "Direct VC2 credential issuance failed");
            return Results.Problem(title: "Internal Server Error",
                detail: "An unexpected credential issuance error occurred.",
                statusCode: StatusCodes.Status500InternalServerError);
        }
    }

    private static IResult InvalidRequest() => Results.Problem(
        title: "Invalid Request",
        detail: "An active did:key issuer, valid holder, bounded type and HTTPS context, object subject with matching holder id, and expiry within 15 minutes are required.",
        statusCode: StatusCodes.Status400BadRequest);
}

/// <summary>Claims the authenticated issuer has chosen to sign; holder control is not proven.</summary>
public sealed class IssueVcdm20CredentialRequest
{
    public string? IssuerDid { get; init; }
    public string? HolderDid { get; init; }
    public string? CredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public JsonElement CredentialSubject { get; init; }
    public DateTimeOffset? ValidUntil { get; init; }
}

/// <summary>No stored/revocable status is implied by a successfully signed direct VC2 JWT.</summary>
public sealed record IssueVcdm20CredentialResponse(string Credential, string Status);
