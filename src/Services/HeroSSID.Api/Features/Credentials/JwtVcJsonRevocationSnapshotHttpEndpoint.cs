using System.Security.Cryptography;
using HeroSSID.Api.Authentication;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Data;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.Infrastructure.KeyEncryption;
using HeroSSID.Infrastructure.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Bounded, issuer-owned HTTP signing of a VC1.1 private revocation status export.
/// The issuing tenant remains solely responsible for authoritative completeness
/// and observation time; this endpoint cannot certify either from supplied JWTs.
/// </summary>
internal static class JwtVcJsonRevocationSnapshotHttpEndpoint
{
    private const int MaximumTotalCredentialCharacters = 180_000;
    private const int MaximumCredentialCharacters = 65_536;
    private const string RateLimitOperation = "JWT_VC_JSON_STATUS_EXPORT";

    internal static void Map(IEndpointRouteBuilder credentials)
    {
        credentials.MapPost("/jwt-vc-json/sign-revocation-snapshot", SignAsync)
            .RequireAuthorization(OperationScopes.CredentialRevoke, OperationScopes.DidManage)
            .WithName("SignJwtVcJsonIssuerRevocationSnapshot")
            .WithSummary("Sign a bounded VC1.1 issuer-supplied revocation set using an owned Ed25519 did:key")
            .Produces<SignJwtVcJsonRevocationSnapshotResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);
    }

    internal static async Task<IResult> SignAsync(
        [FromBody] SignJwtVcJsonRevocationSnapshotRequest request,
        [FromServices] HeroDbContext dbContext,
        [FromServices] IKeyEncryptionService encryption,
        [FromServices] IRateLimiter rateLimiter,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(dbContext);
        ArgumentNullException.ThrowIfNull(encryption);
        ArgumentNullException.ThrowIfNull(rateLimiter);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        string issuerDid = request.IssuerDid ?? string.Empty;
        string[]? revoked = request.RevokedCredentials;
        if (issuerDid.Length > 255 || !new DidKeyMethod().IsValid(issuerDid) ||
            request.ObservedAt is not { } observedAt ||
            revoked is null || revoked.Count > JwtVcJsonRevocationSnapshot.MaximumEntries ||
            revoked.Any(static credential =>
                string.IsNullOrWhiteSpace(credential) ||
                credential.Length > MaximumCredentialCharacters) ||
            revoked.Sum(static credential => credential.Length) > MaximumTotalCredentialCharacters)
        {
            return InvalidRequest();
        }

        DateTimeOffset now = clock.GetUtcNow();
        if (observedAt > now || observedAt.ToUnixTimeSeconds() < 0 ||
            now - observedAt >= TimeSpan.FromSeconds(60))
        {
            return InvalidRequest();
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            if (!await rateLimiter.TryAcquireAsync(
                tenantId, RateLimitOperation, cancellationToken).ConfigureAwait(false))
            {
                return Results.Problem(title: "Status Export Capacity Exhausted",
                    detail: "Issuer status export rate limit exceeded.",
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

            try
            {
                if (!string.Equals(
                    new DidKeyMethod().GenerateDidIdentifier(issuer.PublicKeyEd25519),
                    issuerDid, StringComparison.Ordinal))
                {
                    return Results.NotFound();
                }
            }
            catch (ArgumentException)
            {
                // A mismatched persisted public key must not become a valid issuer.
                return Results.NotFound();
            }

            byte[]? seed = null;
            try
            {
                try
                {
                    seed = encryption.Decrypt(issuer.PrivateKeyEd25519Encrypted);
                }
                catch (CryptographicException)
                {
                    return Unavailable();
                }

                try
                {
                    string snapshot = JwtVcJsonRevocationSnapshot.Create(
                        issuerDid, revoked, seed, observedAt, clock);

                    // Return no stale export even if signing and validation
                    // consumed the remainder of its 60-second validity window.
                    if (clock.GetUtcNow().ToUnixTimeSeconds() >=
                        observedAt.ToUnixTimeSeconds() + 60)
                    {
                        return Unavailable();
                    }

                    return Results.Json(
                        new SignJwtVcJsonRevocationSnapshotResponse(snapshot),
                        statusCode: StatusCodes.Status201Created);
                }
                catch (ArgumentException)
                {
                    return InvalidRequest();
                }
                catch (CryptographicException)
                {
                    // Includes a forged, foreign-issuer or malformed revoked JWT.
                    // Never sign a partial list or return any subject claims.
                    return InvalidRequest();
                }
            }
            finally
            {
                if (seed is not null)
                {
                    CryptographicOperations.ZeroMemory(seed);
                }
            }
        }
        catch (NpgsqlException)
        {
            return Unavailable();
        }
        catch (TimeoutException)
        {
            return Unavailable();
        }
    }

    private static IResult InvalidRequest() => Results.Problem(
        title: "Invalid VC1.1 Status Export",
        detail: "An active tenant-owned issuer, a complete bounded set of authentic issuer JWTs and a genuine observation within 60 seconds are required.",
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult Unavailable() => Results.Problem(
        title: "VC1.1 Status Export Unavailable",
        detail: "Issuer signing or status export is unavailable.",
        statusCode: StatusCodes.Status503ServiceUnavailable);
}

/// <summary>
/// Issuer-provided authoritative observation and all revoked VC1.1 JWTs.
/// An empty set is not automatically proven complete or current.
/// </summary>
public sealed class SignJwtVcJsonRevocationSnapshotRequest
{
    public string? IssuerDid { get; init; }
    public DateTimeOffset? ObservedAt { get; init; }
    public IReadOnlyList<string>? RevokedCredentials { get; init; }
}

/// <summary>
/// Private issuer-signed status only; no trusted completeness, live check or business authority.
/// </summary>
public sealed record SignJwtVcJsonRevocationSnapshotResponse(string SnapshotJwt);
