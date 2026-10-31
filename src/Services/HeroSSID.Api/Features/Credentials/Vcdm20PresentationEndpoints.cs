using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Data;
using HeroSSID.DidOperations.DidMethods;
using HeroSSID.Credentials.Utilities;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Infrastructure.KeyEncryption;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Authenticated, verifier-owned single-use VC2 presentation boundary.
/// An issuer's signed claim, holder's key proof and issuer status are checked separately.
/// </summary>
internal static class Vcdm20PresentationEndpoints
{
    private const int MaximumPresentationLength = 131_072;
    private const int MaximumSnapshotLength = 65_536;

    internal static void Map(RouteGroupBuilder credentials)
    {
        credentials.MapPost("/vcdm20/signed-presentation-request", IssueSignedAsync)
            .RequireAuthorization("credential:verify", "did:manage")
            .WithName("IssueVcdm20SignedPresentationRequest")
            .WithSummary("Issue and sign a one-use verifier challenge with the tenant's active verifier did:key")
            .Produces<IssueVcdm20SignedPresentationRequestResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/vcdm20/presentation-challenge", Issue)
            .RequireAuthorization("credential:verify")
            .WithName("IssueVcdm20PresentationChallenge")
            .WithSummary("Create a verifier-owned, one-use VC2 challenge for a signed holder request")
            .Produces<IssueVcdm20PresentationChallengeResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/vcdm20/cancel-presentation-challenge", Cancel)
            .RequireAuthorization("credential:verify")
            .WithName("CancelVcdm20PresentationChallenge")
            .WithSummary("Atomically invalidate a pending tenant-owned VC2 verifier challenge")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/vcdm20/verify-presentation", Verify)
            .RequireAuthorization("credential:verify")
            .WithName("VerifyVcdm20Presentation")
            .WithSummary("Check issuer and holder Ed25519 signatures, replay and signed VC2 status")
            .Produces<VerifyVcdm20PresentationResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);
    }

    /// <summary>
    /// A non-.NET verifier may ask HeroSSID to sign its own challenge with an active
    /// verifier DID owned by the authenticated tenant. The holder key remains outside
    /// the API, and the holder must independently pin this verifier DID and audience
    /// and affirmatively consent to every claim before creating a presentation.
    /// This is NOT an OpenID4VP request object or proof of business authorization.
    /// </summary>
    internal static async Task<IResult> IssueSignedAsync(
        [FromBody] IssueVcdm20SignedPresentationRequestRequest request,
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
            string.IsNullOrWhiteSpace(request.TrustedIssuerDid) ||
            request.TrustedIssuerDid.Length > 255 ||
            !new DidKeyMethod().IsValid(request.TrustedIssuerDid) ||
            request.LifetimeSeconds is < 1 or > 300)
        {
            return BadSignedRequest();
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        byte[]? privateKey = null;
        try
        {
            // The untrusted request cannot choose somebody else's verifier key.
            // Require an active DID in the authenticated caller's own tenant.
            var verifier = await dbContext.Dids.AsNoTracking()
                .Where(did => did.TenantId == tenantId &&
                    did.DidIdentifier == request.VerifierDid && did.Status == "active")
                .Select(did => new { did.PublicKeyEd25519, did.PrivateKeyEd25519Encrypted })
                .FirstOrDefaultAsync(cancellationToken).ConfigureAwait(false);
            if (verifier is null ||
                !string.Equals(new DidKeyMethod().GenerateDidIdentifier(
                    verifier.PublicKeyEd25519), request.VerifierDid, StringComparison.Ordinal))
            {
                return Results.NotFound();
            }

            // The retained tenant/issuer policy comes from the verifier, never
            // from the eventual holder proof. Issuing is atomic in the existing
            // PostgreSQL store across HTTP replicas; a signing failure releases
            // no JWT, and the unused nonce expires automatically.
            privateKey = encryption.Decrypt(verifier.PrivateKeyEd25519Encrypted);
            var challenge = challenges.Issue(
                tenantId, request.Audience!, request.TrustedIssuerDid!,
                TimeSpan.FromSeconds(request.LifetimeSeconds));
            string signed = OfflineSignedPresentationRequest.Create(
                challenge, request.VerifierDid!, privateKey, clock);
            return Results.Json(new IssueVcdm20SignedPresentationRequestResponse(
                signed, request.VerifierDid!, challenge.Audience, challenge.Nonce,
                challenge.TrustedIssuerDid, challenge.ExpiresAt),
                statusCode: StatusCodes.Status201Created);
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("challenge limit has been reached", StringComparison.Ordinal))
        {
            return Results.Problem(title: "Challenge Capacity Exhausted",
                detail: "The verifier has reached the retained challenge capacity.",
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
            // Invalid stored public key, decrypted seed or clock-expired signed
            // request must never be returned or mistaken for a holder statement.
            return Unavailable();
        }
        catch (CryptographicException)
        {
            return Unavailable();
        }
        finally
        {
            if (privateKey is not null)
            {
                CryptographicOperations.ZeroMemory(privateKey);
            }
        }
    }

    /// <summary>
    /// The authenticated verifier tenant chooses the issuer it trusts for this request.
    /// It signs the returned challenge with its OWN independent did:key signer before
    /// showing the request to a holder; issuing a nonce does not establish verifier identity.
    /// </summary>
    internal static IResult Issue(
        [FromBody] IssueVcdm20PresentationChallengeRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (!ValidAudience(request.Audience) ||
            string.IsNullOrWhiteSpace(request.TrustedIssuerDid) ||
            request.TrustedIssuerDid.Length > 255 ||
            !new DidKeyMethod().IsValid(request.TrustedIssuerDid) ||
            request.LifetimeSeconds is < 1 or > 300)
        {
            return BadChallenge();
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            var challenge = challenges.Issue(tenantId, request.Audience!,
                request.TrustedIssuerDid!, TimeSpan.FromSeconds(request.LifetimeSeconds));
            return Results.Json(new IssueVcdm20PresentationChallengeResponse(
                challenge.Audience, challenge.Nonce, challenge.TrustedIssuerDid, challenge.ExpiresAt),
                statusCode: StatusCodes.Status201Created);
        }
        catch (ArgumentException)
        {
            return BadChallenge();
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("challenge limit has been reached", StringComparison.Ordinal))
        {
            return Results.Problem(title: "Challenge Capacity Exhausted",
                detail: "The verifier has reached the retained challenge capacity.",
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
    /// A verifier that declines or abandons a request spends its outstanding nonce
    /// without asking a Wallet to sign. Tenant, exact audience and nonce are bound
    /// by the existing cross-replica PostgreSQL atomic consumption operation.
    /// Unknown, cancelled and previously consumed nonces are indistinguishable.
    /// A cancellation cannot retract a disclosure accepted before the operation.
    /// </summary>
    internal static IResult Cancel(
        [FromBody] CancelVcdm20PresentationChallengeRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (!ValidAudience(request.Audience) || !ValidNonce(request.Nonce))
        {
            return Results.Problem(title: "Invalid VC2 Challenge Cancellation",
                detail: "The exact HTTPS verifier audience and canonical 43-character issued nonce are required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            // Both successful cancellation and successful proof verification
            // use this exact tenant/audience/nonce atomic store operation.
            _ = challenges.TryConsume(tenantId, request.Audience!, request.Nonce!);
            return Results.NoContent();
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
    /// The challenge's tenant, audience, nonce and issuer policy come from the verifier
    /// store, never from the holder token. Claims are released only after authentic issuer
    /// AND holder signatures, one-use consumption and an issuer-signed status snapshot.
    /// SignedNotListed is not proof of live non-revocation or business authorization.
    /// </summary>
    internal static IResult Verify(
        [FromBody] VerifyVcdm20PresentationRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        Uri? context = request.SubjectContextUri;
        if (string.IsNullOrWhiteSpace(request.Presentation) ||
            request.Presentation.Length > MaximumPresentationLength ||
            string.IsNullOrWhiteSpace(request.RevocationSnapshot) ||
            request.RevocationSnapshot.Length > MaximumSnapshotLength ||
            !ValidAudience(request.Audience) ||
            string.IsNullOrWhiteSpace(request.Nonce) ||
            request.Nonce.Length != 43 ||
            string.IsNullOrWhiteSpace(request.ExpectedCredentialType) ||
            request.ExpectedCredentialType.Length > 128 ||
            request.ExpectedCredentialType.Any(char.IsWhiteSpace) ||
            context is null || !context.IsAbsoluteUri ||
            !string.Equals(context.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(context.UserInfo) ||
            !string.IsNullOrEmpty(context.Fragment) ||
            context.AbsoluteUri.Length > 2048)
        {
            return Results.Problem(title: "Invalid Presentation Request",
                detail: "A bounded presentation, authentic issuer status, exact issued nonce and pinned HTTPS policy are required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            var status = Vcdm20RevocationSnapshot.CheckPresentation(
                request.Presentation, request.RevocationSnapshot, tenantId, request.Audience!,
                request.Nonce!, request.ExpectedCredentialType!, context,
                challenges, clock, out var subject);
            return Results.Ok(new VerifyVcdm20PresentationResponse(
                status.ToString(),
                status == Vcdm20RevocationCheckResult.SignedNotListed ? subject : null));
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

    private static bool ValidNonce(string? nonce)
    {
        if (nonce is null || nonce.Length != 43)
        {
            return false;
        }

        try
        {
            var bytes = Base64UrlEncoder.DecodeBytes(nonce);
            return bytes.Length == 32 &&
                string.Equals(Base64UrlEncoder.Encode(bytes), nonce, StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool ValidAudience(string? audience) =>
        !string.IsNullOrWhiteSpace(audience) && audience.Length <= 2048 &&
        Uri.TryCreate(audience, UriKind.Absolute, out var uri) &&
        string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) &&
        string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment) &&
        string.Equals(uri.AbsoluteUri, audience, StringComparison.Ordinal);

    private static IResult BadSignedRequest() => Results.Problem(
        title: "Invalid Signed Request",
        detail: "An owned active Ed25519 verifier did:key, exact HTTPS audience, valid trusted issuer did:key and lifetime of 1–300 seconds are required.",
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult BadChallenge() => Results.Problem(
        title: "Invalid Challenge Request",
        detail: "An exact HTTPS verifier audience, valid Ed25519 did:key issuer and lifetime between 1 and 300 seconds are required.",
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult Unavailable() => Results.Problem(
        title: "Verifier Challenge Store Unavailable",
        detail: "The presentation could not be verified using durable challenge state.",
        statusCode: StatusCodes.Status503ServiceUnavailable);
}

/// <summary>A verifier signs only under its own active, tenant-owned did:key.</summary>
public sealed class IssueVcdm20SignedPresentationRequestRequest
{
    public string? VerifierDid { get; init; }
    public string? Audience { get; init; }
    public string? TrustedIssuerDid { get; init; }
    public int LifetimeSeconds { get; init; } = 120;
}

/// <summary>Holder apps must independently pin the verifier DID and audience and obtain consent.</summary>
public sealed record IssueVcdm20SignedPresentationRequestResponse(
    string SignedRequestJwt, string VerifierDid, string Audience, string Nonce,
    string TrustedIssuerDid, DateTimeOffset ExpiresAt);

/// <summary>Only the verifier chooses and retains trusted issuer and challenge audience.</summary>
public sealed class IssueVcdm20PresentationChallengeRequest
{
    public string? Audience { get; init; }
    public string? TrustedIssuerDid { get; init; }
    public int LifetimeSeconds { get; init; } = 120;
}

/// <summary>Verifiers must sign this challenge with an independently held verifier key.</summary>
public sealed record IssueVcdm20PresentationChallengeResponse(
    string Audience, string Nonce, string TrustedIssuerDid, DateTimeOffset ExpiresAt);

/// <summary>Cancel a verifier challenge, not any previously accepted holder disclosure.</summary>
public sealed class CancelVcdm20PresentationChallengeRequest
{
    public string? Audience { get; init; }
    public string? Nonce { get; init; }
}

/// <summary>Caller pins claim vocabulary and type; the server retains issuer policy.</summary>
public sealed class VerifyVcdm20PresentationRequest
{
    public string? Presentation { get; init; }
    public string? RevocationSnapshot { get; init; }
    public string? Audience { get; init; }
    public string? Nonce { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
}

/// <summary>Only SignedNotListed returns verified claims; it never grants authorization.</summary>
public sealed record VerifyVcdm20PresentationResponse(string Status, JsonElement? VerifiedSubject);
