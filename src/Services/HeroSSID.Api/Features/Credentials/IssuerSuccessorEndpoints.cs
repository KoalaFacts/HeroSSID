using System.Security.Cryptography;
using HeroSSID.Api.Authentication;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.Infrastructure.KeyEncryption;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Authenticated, verifier-owned one-time check that two different issuer
/// did:key controllers signed the same successor statement. This does not
/// enroll either key, update issuer trust, recover lost keys or grant authority.
/// </summary>
internal static class IssuerSuccessorEndpoints
{
    // Separate the challenge-store purpose from VC presentation challenges:
    // a proof from either workflow cannot consume the other's nonce.
    private const string PurposePrefix = "issuer-successor:";
    private const int MaximumAttestationLength = 16_384;

    internal static void Map(RouteGroupBuilder credentials)
    {
        credentials.MapPost("/issuer-successor/challenge", Issue)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("IssueIssuerSuccessorChallenge")
            .WithSummary("Issue a verifier-owned one-time challenge for a dual-signed issuer did:key successor proof")
            .Produces<IssueIssuerSuccessorChallengeResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);


        credentials.MapPost("/issuer-successor/signed-challenge", IssueSignedAsync)
            .RequireAuthorization(OperationScopes.CredentialVerify, OperationScopes.DidManage)
            .WithName("IssueSignedIssuerSuccessorChallenge")
            .WithSummary("Issue an authenticated Ed25519 verifier-signed one-use issuer key successor request")
            .Produces<IssueSignedIssuerSuccessorChallengeResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/issuer-successor/verify", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyIssuerSuccessorProof")
            .WithSummary("Verify both issuer keys and atomically consume the verifier-owned successor challenge")
            .Produces<VerifyIssuerSuccessorProofResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);
    }

    /// <summary>
    /// The authenticated verifier chooses the PREVIOUS issuer it independently
    /// trusts. This issues a nonce, not a statement of successor authorization.
    /// </summary>
    internal static IResult Issue(
        [FromBody] IssueIssuerSuccessorChallengeRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (!ValidAudience(request.Audience) ||
            string.IsNullOrWhiteSpace(request.PreviousIssuerDid) ||
            request.PreviousIssuerDid.Length > 255 ||
            !new DidKeyMethod().IsValid(request.PreviousIssuerDid) ||
            request.LifetimeSeconds is < 1 or > 300)
        {
            return InvalidRequest("A canonical HTTPS verifier audience, previous Ed25519 did:key and 1–300 second lifetime are required.");
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            var challenge = challenges.Issue(
                tenantId, StoredAudience(request.Audience!), request.PreviousIssuerDid!,
                TimeSpan.FromSeconds(request.LifetimeSeconds));
            return Results.Json(new IssueIssuerSuccessorChallengeResponse(
                request.Audience!, challenge.Nonce, challenge.TrustedIssuerDid,
                challenge.ExpiresAt), statusCode: StatusCodes.Status201Created);
        }
        catch (ArgumentException)
        {
            return InvalidRequest("The issuer successor challenge is invalid.");
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("challenge limit has been reached", StringComparison.Ordinal))
        {
            return Results.Problem(title: "Challenge Capacity Exhausted",
                detail: "The verifier has reached its retained one-time challenge capacity.",
                statusCode: StatusCodes.Status429TooManyRequests);
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


    /// <summary>
    /// Sign the one-use old-issuer policy with a tenant-owned active verifier
    /// key. This explicitly does not transfer issuer trust or business authority.
    /// </summary>
    internal static async Task<IResult> IssueSignedAsync(
        [FromBody] IssueSignedIssuerSuccessorChallengeRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] HeroDbContext dbContext,
        [FromServices] IKeyEncryptionService encryption,
        [FromServices] TimeProvider clock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(dbContext);
        ArgumentNullException.ThrowIfNull(encryption);
        ArgumentNullException.ThrowIfNull(clock);

        if (!ValidAudience(request.Audience) ||
            string.IsNullOrWhiteSpace(request.VerifierDid) ||
            request.VerifierDid.Length > 255 ||
            !new DidKeyMethod().IsValid(request.VerifierDid) ||
            string.IsNullOrWhiteSpace(request.PreviousIssuerDid) ||
            request.PreviousIssuerDid.Length > 255 ||
            !new DidKeyMethod().IsValid(request.PreviousIssuerDid) ||
            request.LifetimeSeconds is < 1 or > 300)
        {
            return InvalidRequest("An active verifier did:key, pinned previous issuer, exact HTTPS audience and 1–300 second lifetime are required.");
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        byte[]? verifierSeed = null;
        try
        {
            var verifier = await dbContext.Dids.AsNoTracking()
                .Where(did => did.TenantId == tenantId &&
                    did.DidIdentifier == request.VerifierDid && did.Status == "active")
                .Select(did => new { did.PublicKeyEd25519, did.PrivateKeyEd25519Encrypted })
                .FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
            if (verifier is null ||
                !string.Equals(new DidKeyMethod().GenerateDidIdentifier(
                    verifier.PublicKeyEd25519), request.VerifierDid, StringComparison.Ordinal))
            {
                // Never distinguish an unknown DID from a foreign or deactivated one.
                return Results.NotFound();
            }

            verifierSeed = encryption.Decrypt(verifier.PrivateKeyEd25519Encrypted);
            var issued = challenges.Issue(
                tenantId, StoredAudience(request.Audience!), request.PreviousIssuerDid!,
                TimeSpan.FromSeconds(request.LifetimeSeconds));
            // StoredAudience has a private domain-separation prefix. Never sign or
            // publish that internal namespace as a verifier's public HTTPS audience.
            var publicChallenge = new PresentationChallenge
            {
                Audience = request.Audience!,
                Nonce = issued.Nonce,
                TrustedIssuerDid = issued.TrustedIssuerDid,
                ExpiresAt = issued.ExpiresAt
            };
            string signed = IssuerSuccessorVerifierRequest.Create(
                publicChallenge, request.VerifierDid!, verifierSeed, clock);
            return Results.Json(new IssueSignedIssuerSuccessorChallengeResponse(
                signed, request.VerifierDid!, request.Audience!, issued.Nonce,
                issued.TrustedIssuerDid, issued.ExpiresAt),
                statusCode: StatusCodes.Status201Created);
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("challenge limit has been reached", StringComparison.Ordinal))
        {
            return Results.Problem(title: "Challenge Capacity Exhausted",
                detail: "The verifier has reached its retained one-time challenge capacity.",
                statusCode: StatusCodes.Status429TooManyRequests);
        }
        catch (NpgsqlException)
        {
            return Unavailable();
        }
        catch (TimeoutException)
        {
            return Unavailable();
        }
        catch (ArgumentException)
        {
            return Unavailable();
        }
        catch (CryptographicException)
        {
            return Unavailable();
        }
        finally
        {
            if (verifierSeed is not null)
            {
                CryptographicOperations.ZeroMemory(verifierSeed);
            }
        }
    }

    /// <summary>
    /// The previous issuer DID comes from verifier-owned durable state, never
    /// from the supplied signed artifact. Only authentic two-key evidence may
    /// spend the nonce. Returning a proposed successor is NOT trust promotion.
    /// </summary>
    internal static IResult Verify(
        [FromBody] VerifyIssuerSuccessorProofRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        if (string.IsNullOrWhiteSpace(request.Attestation) ||
            request.Attestation.Length > MaximumAttestationLength ||
            !ValidAudience(request.Audience) ||
            string.IsNullOrWhiteSpace(request.Nonce) ||
            request.Nonce.Length != 43)
        {
            return InvalidRequest("A bounded dual-signed attestation, exact HTTPS audience and issued nonce are required.");
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        string storedAudience = StoredAudience(request.Audience!);
        try
        {
            var issued = challenges.Find(tenantId, storedAudience, request.Nonce!);
            if (issued is null ||
                !IssuerKeySuccessorAttestation.TryVerify(
                    request.Attestation!, issued.TrustedIssuerDid, new Uri(request.Audience!),
                    request.Nonce!, clock.GetUtcNow(), out string successorDid) ||
                !challenges.TryConsume(tenantId, storedAudience, request.Nonce!))
            {
                return Results.Ok(new VerifyIssuerSuccessorProofResponse("Invalid", null));
            }

            return Results.Ok(new VerifyIssuerSuccessorProofResponse(
                "ValidKeyContinuity", successorDid));
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

    private static string StoredAudience(string audience) => PurposePrefix + audience;

    private static bool ValidAudience(string? audience) =>
        !string.IsNullOrWhiteSpace(audience) && audience.Length <= 2000 &&
        Uri.TryCreate(audience, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0 &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
        string.Equals(uri.AbsoluteUri, audience, StringComparison.Ordinal);

    private static IResult InvalidRequest(string detail) => Results.Problem(
        title: "Invalid Issuer Successor Request", detail: detail,
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult Unavailable() => Results.Problem(
        title: "Verifier Challenge Store Unavailable",
        detail: "The verifier cannot safely issue or consume a one-time successor challenge.",
        statusCode: StatusCodes.Status503ServiceUnavailable);
}

/// <summary>Verifier policy, not an issuer claim; no key or trust-list mutation.</summary>
public sealed class IssueIssuerSuccessorChallengeRequest
{
    public string? Audience { get; init; }
    public string? PreviousIssuerDid { get; init; }
    public int LifetimeSeconds { get; init; } = 120;
}

/// <summary>The nonce is unsigned; an issuer must pin and authenticate the verifier separately.</summary>
public sealed record IssueIssuerSuccessorChallengeResponse(
    string Audience, string Nonce, string TrustedPreviousIssuerDid, DateTimeOffset ExpiresAt);


/// <summary>Verifier-owned signer and independently trusted previous issuer policy.</summary>
public sealed class IssueSignedIssuerSuccessorChallengeRequest
{
    public string? VerifierDid { get; init; }
    public string? Audience { get; init; }
    public string? PreviousIssuerDid { get; init; }
    public int LifetimeSeconds { get; init; } = 120;
}

/// <summary>A real Ed25519 verifier request; does not prove issuer or business authority.</summary>
public sealed record IssueSignedIssuerSuccessorChallengeResponse(
    string SignedRequestJwt, string VerifierDid, string Audience,
    string Nonce, string TrustedPreviousIssuerDid, DateTimeOffset ExpiresAt);

/// <summary>Complete original dual-signed artifact, without any supplied trusted-issuer override.</summary>
public sealed class VerifyIssuerSuccessorProofRequest
{
    public string? Attestation { get; init; }
    public string? Audience { get; init; }
    public string? Nonce { get; init; }
}

/// <summary>ValidKeyContinuity proves two keys signed, never issuer enrollment or business authority.</summary>
public sealed record VerifyIssuerSuccessorProofResponse(string Status, string? SuccessorIssuerDid);
