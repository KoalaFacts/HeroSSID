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
            .RequireIssuerSigningGrant()
            .WithName("IssueJwtVcJsonCredential")
            .WithSummary("Issue a short-lived W3C VC1.1 jwt_vc_json with a tenant-owned Ed25519 did:key")
            .Produces<IssueJwtVcJsonCredentialResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status500InternalServerError);

        // Explicit issuer-signed RFC 7519 recipient restriction (private VC-level profile).
        credentials.MapPost("/jwt-vc-json/issue-for-audience", IssueForAudienceAsync)
            .RequireAuthorization(CredentialIssueRequirement.PolicyName)
            .RequireIssuerSigningGrant()
            .WithName("IssueJwtVcJsonCredentialForAudience")
            .WithSummary("Issue a VC1.1 JWT with an explicit HTTPS recipient restriction")
            .Produces<IssueJwtVcJsonCredentialResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status500InternalServerError);
    }

    internal static Task<IResult> IssueAsync(
        [FromBody] IssueJwtVcJsonCredentialRequest request,
        [FromServices] HeroDbContext dbContext,
        [FromServices] IKeyEncryptionService encryption,
        [FromServices] IRateLimiter rateLimiter,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock,
        [FromServices] ILogger<Program> logger,
        CancellationToken cancellationToken)
        => IssueCoreAsync(request, dbContext, encryption, rateLimiter,
            tenantContext, clock, logger, requireAudience: false, cancellationToken: cancellationToken);

    internal static Task<IResult> IssueForAudienceAsync(
        [FromBody] IssueJwtVcJsonCredentialRequest request,
        [FromServices] HeroDbContext dbContext,
        [FromServices] IKeyEncryptionService encryption,
        [FromServices] IRateLimiter rateLimiter,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock,
        [FromServices] ILogger<Program> logger,
        CancellationToken cancellationToken)
        => IssueCoreAsync(request, dbContext, encryption, rateLimiter,
            tenantContext, clock, logger, requireAudience: true, cancellationToken: cancellationToken);

    private static async Task<IResult> IssueCoreAsync(
        [FromBody] IssueJwtVcJsonCredentialRequest request,
        [FromServices] HeroDbContext dbContext,
        [FromServices] IKeyEncryptionService encryption,
        [FromServices] IRateLimiter rateLimiter,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock,
        [FromServices] ILogger<Program> logger,
        bool requireAudience, CancellationToken cancellationToken)
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
            (request.CredentialId is Uri identifier &&
                (!identifier.IsAbsoluteUri ||
                 identifier.Scheme != Uri.UriSchemeHttps ||
                 string.IsNullOrWhiteSpace(identifier.Host) ||
                 identifier.UserInfo.Length != 0 ||
                 identifier.AbsoluteUri.Length > 2048)) ||
            request.CredentialSubject.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array) ||
            validUntil == DateTimeOffset.MinValue ||
            // Exactly one of the single-recipient or multi-recipient forms
            // is permitted on this opt-in route. Legacy routes fail closed.
            (!requireAudience && (request.RecipientAudience is not null ||
                request.RecipientAudiences is not null)) ||
            (requireAudience &&
                ((request.RecipientAudience is null) == (request.RecipientAudiences is null))) ||
            (request.RecipientAudience is not null &&
                !ValidRecipient(request.RecipientAudience)) ||
            (request.RecipientAudiences is not null &&
                !ValidRecipients(request.RecipientAudiences)))
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
                // Preserve existing callers' whole-second HTTP issuance.
                // The explicit opt-in starts at the actual server observation
                // and preserves the caller's exact expiry to 100ns, avoiding
                // the legacy route's up-to-one-second start backdating.
                DateTimeOffset signingStart = request.ExactValidity
                    ? now
                    : DateTimeOffset.FromUnixTimeSeconds(now.ToUnixTimeSeconds());
                string jwt;
                if (requireAudience && request.RecipientAudiences is { } recipients)
                {
                    // The genuine issuer key signs the complete explicitly bounded
                    // recipient set. No legacy or no-audience route may ignore it.
                    jwt = JwtVcJsonCredential.CreateForAudiencesWithMetadata(issuerDid,
                        holderDid, credentialType, context, request.CredentialSubject,
                        seed, signingStart, validUntil, recipients, request.CredentialId,
                        request.IssuerName, request.ExactValidity);
                }
                else if (requireAudience)
                {
                    // The issuer seed remains tenant-owned and is erased below.
                    // A recipient-bound JWT cannot be verified by legacy unpinned routes.
                    jwt = JwtVcJsonCredential.CreateForAudienceWithMetadata(issuerDid,
                        holderDid, credentialType, context, request.CredentialSubject,
                        seed, signingStart, validUntil, request.RecipientAudience!,
                        request.CredentialId, request.IssuerName, request.ExactValidity);
                }
                else if (request.IssuerName is not null)
                {
                    // A descriptive issuer name is signed by the same tenant-owned
                    // Ed25519 key, never an external source of issuer trust.
                    jwt = JwtVcJsonCredential.CreateWithIssuerName(issuerDid,
                        holderDid, credentialType, context, request.CredentialSubject,
                        seed, signingStart, validUntil, request.IssuerName,
                        request.CredentialId, request.ExactValidity);
                }
                else if (request.ExactValidity)
                {
                    jwt = request.CredentialId is Uri exactId
                        ? JwtVcJsonCredential.CreateWithExactValidity(issuerDid,
                            holderDid, credentialType, context, request.CredentialSubject,
                            seed, signingStart, validUntil, exactId)
                        : JwtVcJsonCredential.CreateWithExactValidity(issuerDid,
                            holderDid, credentialType, context, request.CredentialSubject,
                            seed, signingStart, validUntil);
                }
                else
                {
                    jwt = request.CredentialId is Uri credentialId
                        ? JwtVcJsonCredential.Create(issuerDid, holderDid,
                            credentialType, context, request.CredentialSubject, seed,
                            signingStart, validUntil, credentialId)
                        : JwtVcJsonCredential.Create(issuerDid, holderDid,
                            credentialType, context, request.CredentialSubject, seed,
                            signingStart, validUntil);
                }

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

    private static bool ValidRecipient(Uri? uri) =>
        uri is { IsAbsoluteUri: true } &&
        uri.Scheme == Uri.UriSchemeHttps &&
        !string.IsNullOrWhiteSpace(uri.Host) &&
        uri.UserInfo.Length == 0 &&
        uri.Fragment.Length == 0 &&
        uri.AbsoluteUri.Length <= 2048;

    private static bool ValidRecipients(IReadOnlyList<Uri> recipients)
    {
        if (recipients.Count is < 2 or > 8)
        {
            return false;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (Uri? recipient in recipients)
        {
            if (!ValidRecipient(recipient) || !seen.Add(recipient!.AbsoluteUri))
            {
                return false;
            }
        }

        return true;
    }

    private static IResult InvalidRequest() => Results.Problem(
        title: "Invalid Request",
        detail: "An active tenant-owned issuer, external did:key holder, HTTPS credential type and vocabulary, optional bounded HTTPS credential ID, an optional nonblank control-free issuer name of at most 128 characters, one object or one-element object array with absent or matching holder id, and expiry within 15 minutes are required. The opt-in recipient route requires either one HTTPS recipient or an explicit array of two to eight distinct HTTPS recipients, plus optional bounded ID, issuer name and exact-validity options; the legacy route rejects recipient policy.",
        statusCode: StatusCodes.Status400BadRequest);
}

/// <summary>Issuer claims for a short-lived, full-disclosure VC1.1 JWT.</summary>
public sealed class IssueJwtVcJsonCredentialRequest
{
    public string? IssuerDid { get; init; }
    public string? HolderDid { get; init; }
    public string? CredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    /// <summary>Optional issuer-assigned HTTPS credential identifier, signed as JWT jti.</summary>
    public Uri? CredentialId { get; init; }
    /// <summary>
    /// Only the explicit issue-for-audience route signs this private RFC 7519
    /// VC-level recipient restriction. Legacy issuance rejects it.
    /// A signed aud is not standard VC1.1 presentation audience binding.
    /// </summary>
    public Uri? RecipientAudience { get; init; }
    /// <summary>
    /// Exclusive alternative to RecipientAudience, only on issue-for-audience:
    /// two to eight canonical distinct HTTPS recipient URLs. They are signed as
    /// RFC 7519 aud array. Each verifier still pins its own intended URI.
    /// </summary>
    public IReadOnlyList<Uri>? RecipientAudiences { get; init; }
    public JsonElement CredentialSubject { get; init; }
    public DateTimeOffset? ValidUntil { get; init; }
    /// <summary>
    /// Opt in to exact 100ns issuer-signed nbf/iat/exp instead of the
    /// legacy whole-second HTTP validity. Defaults to false.
    /// </summary>
    public bool ExactValidity { get; init; }
    /// <summary>
    /// Optional signed descriptive VC1.1 vc.issuer.name. Never a trust anchor,
    /// proof of legal organisation identity or authorization.
    /// </summary>
    public string? IssuerName { get; init; }
}

/// <summary>Issuer-signed JWT only: no holder proof, live revocation or business authority.</summary>
public sealed record IssueJwtVcJsonCredentialResponse(string Credential, string Status);
