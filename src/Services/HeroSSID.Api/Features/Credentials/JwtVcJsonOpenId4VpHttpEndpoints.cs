using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Api.Authentication;
using HeroSSID.Core.TenantManagement;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;
using HeroSSID.Data;
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
/// Private-policy, authenticated HTTP bridge for the bounded OpenID4VP 1.0
/// jwt_vc_json direct_post SDK. An external application must host the public
/// callback and forward the entire form to this authorized verifier endpoint.
/// Not a public OpenID4VP callback, wallet interop claim, or consent service.
/// </summary>
internal static class JwtVcJsonOpenId4VpHttpEndpoints
{
    private const int MaximumFormLength = 180_000;
    private const int MaximumSnapshotLength = 65_536;
    private const string PublicRequestObjectPath = "/api/v1/credentials/jwt-vc-json/openid4vp/requests/";

    internal static void Map(RouteGroupBuilder credentials)
    {
        credentials.MapGet("/jwt-vc-json/openid4vp/requests/{opaqueReference}", GetHostedRequest)
            .AllowAnonymous()
            .WithName("GetPublishedJwtVcJsonOpenId4VpRequestObject")
            .WithSummary("Fetch a short-lived unchanged Ed25519 signed Request Object by opaque reference");

        credentials.MapPost("/jwt-vc-json/openid4vp/signed-request", IssueSignedAsync)
            .RequireAuthorization(OperationScopes.CredentialVerify, OperationScopes.DidManage)
            .WithName("IssueJwtVcJsonOpenId4VpSignedRequest")
            .WithSummary("Issue a verifier Ed25519-signed bounded OpenID4VP 1.0 jwt_vc_json request")
            .Produces<IssueOpenId4VpSignedRequestResponse>(StatusCodes.Status201Created)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .Produces(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status429TooManyRequests)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/jwt-vc-json/openid4vp/cancel-request", Cancel)
            .RequireAuthorization(OperationScopes.CredentialVerify, OperationScopes.DidManage)
            .WithName("CancelJwtVcJsonOpenId4VpSignedRequest")
            .WithSummary("Atomically invalidate an outstanding verifier-owned OpenID4VP request")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

        credentials.MapPost("/jwt-vc-json/openid4vp/verify-response", Verify)
            .RequireAuthorization(OperationScopes.CredentialVerify)
            .WithName("VerifyJwtVcJsonOpenId4VpDirectPostResponse")
            .WithSummary("Verify forwarded direct_post with issuer and holder Ed25519 signatures and signed status")
            .Produces<VerifyOpenId4VpDirectPostResponse>(StatusCodes.Status200OK)
            .ProducesProblem(StatusCodes.Status400BadRequest)
            .Produces(StatusCodes.Status401Unauthorized)
            .Produces(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status503ServiceUnavailable);
    }

    internal static async Task<IResult> IssueSignedAsync(
        [FromBody] IssueOpenId4VpSignedRequestRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] ITenantContext tenantContext,
        [FromServices] HeroDbContext dbContext,
        [FromServices] IKeyEncryptionService encryption,
        [FromServices] OpenId4VpJwtVcJsonRequestObjectStore requestObjects,
        [FromServices] IConfiguration configuration,
        [FromServices] TimeProvider clock,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(dbContext);
        ArgumentNullException.ThrowIfNull(encryption);
        ArgumentNullException.ThrowIfNull(requestObjects);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNull(clock);

        if (!ValidDid(request.VerifierDid) || !ValidDid(request.TrustedIssuerDid) ||
            !ValidHttps(request.ResponseUri) ||
            !ValidType(request.CredentialType) ||
            !ValidContext(request.SubjectContextUri) ||
            request.LifetimeSeconds is < 1 or > 300)
        {
            return InvalidRequest();
        }

        Uri? requestUriBase = null;
        if (request.PublishRequestUri &&
            (!Uri.TryCreate(configuration["OpenId4Vp:PublicRequestUriBase"],
                UriKind.Absolute, out requestUriBase) ||
            !ValidPublicRequestUriBase(requestUriBase)))
        {
            // Never derive this wallet-facing URL from an attacker-controlled Host header.
            return Unavailable();
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        byte[]? verifierSeed = null;
        string? reservedReference = null;
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
                // Unknown, other-tenant and deactivated verifier signers are indistinguishable.
                return Results.NotFound();
            }

            verifierSeed = encryption.Decrypt(verifier.PrivateKeyEd25519Encrypted);
            // Reserve the single-process host slot BEFORE committing a durable
            // challenge: a full host cannot drain the independent PG quota.
            if (requestUriBase is not null)
            {
                reservedReference = requestObjects.Reserve();
            }

            string clientId = "decentralized_identifier:" + request.VerifierDid;
            var challenge = challenges.Issue(tenantId, clientId,
                request.TrustedIssuerDid!, TimeSpan.FromSeconds(request.LifetimeSeconds));
            string signed = OpenId4VpJwtVcJsonDirectPost.CreateSignedRequest(
                challenge, request.VerifierDid!, verifierSeed, request.ResponseUri!,
                request.CredentialType!, request.SubjectContextUri!, clock);
            string walletInvocation = OpenId4VpJwtVcJsonDirectPost.CreateWalletInvocation(
                signed, request.VerifierDid!, request.ResponseUri!,
                request.CredentialType!, request.SubjectContextUri!, clock);
            string? referenceWalletInvocation = null;
            if (requestUriBase is not null)
            {
                // Create the launch before committing the reservation, so a
                // malformed/expired request cannot leave a published orphan.
                var publishedUri = new Uri(requestUriBase, reservedReference!);
                referenceWalletInvocation = OpenId4VpJwtVcJsonRequestUri.CreateWalletInvocation(
                    signed, publishedUri, request.VerifierDid!, request.ResponseUri!,
                    request.CredentialType!, request.SubjectContextUri!, clock);
                requestObjects.PublishReserved(reservedReference!, tenantId, signed,
                    request.VerifierDid!, request.ResponseUri!, request.CredentialType!,
                    request.SubjectContextUri!);
            }

            return Results.Json(new IssueOpenId4VpSignedRequestResponse(
                signed, clientId, request.VerifierDid!, request.ResponseUri!,
                challenge.Nonce, challenge.TrustedIssuerDid, challenge.ExpiresAt,
                walletInvocation, referenceWalletInvocation),
                statusCode: StatusCodes.Status201Created);
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("challenge limit has been reached", StringComparison.Ordinal))
        {
            return Results.Problem(title: "Challenge Capacity Exhausted",
                detail: "The verifier's retained one-use challenge capacity is exhausted.",
                statusCode: StatusCodes.Status429TooManyRequests);
        }
        catch (InvalidOperationException exception) when (
            exception.Message.Contains("request object capacity", StringComparison.Ordinal))
        {
            return Results.Problem(title: "Request Object Capacity Exhausted",
                detail: "The single-instance request publication capacity is exhausted.",
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
        catch (CryptographicException)
        {
            return Unavailable();
        }
        catch (ArgumentException)
        {
            // A corrupt verifier key or signing failure never becomes an issuer or holder statement.
            return Unavailable();
        }
        finally
        {
            if (reservedReference is not null)
            {
                requestObjects.ReleaseReservation(reservedReference);
            }

            if (verifierSeed is not null)
            {
                CryptographicOperations.ZeroMemory(verifierSeed);
            }
        }
    }

    /// <summary>
    /// Public GET presents no credential/subject claims. The opaque reference is
    /// strong and short-lived, but hosting is VOLATILE and SINGLE-INSTANCE only;
    /// the shared verifier challenge must still be live at retrieval time.
    /// </summary>
    internal static IResult GetHostedRequest(string opaqueReference,
        [FromServices] OpenId4VpJwtVcJsonRequestObjectStore requestObjects,
        HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(requestObjects);
        ArgumentNullException.ThrowIfNull(context);
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.Pragma = "no-cache";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";

        try
        {
            if (!requestObjects.TryGet(opaqueReference, out string signedRequest))
            {
                return Results.NotFound();
            }

            return Results.Bytes(Encoding.ASCII.GetBytes(signedRequest),
                "application/oauth-authz-req+jwt");
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
    /// The authenticated verifier backend cancels an outstanding request when
    /// its transaction ends or the holder declines disclosure. Reuse the exact
    /// PostgreSQL one-time consume gate: cancelling and verifying race atomically.
    /// Do not reveal whether a nonce was unknown, already used or cancelled.
    /// </summary>
    internal static IResult Cancel(
        [FromBody] CancelOpenId4VpSignedRequestRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] OpenId4VpJwtVcJsonRequestObjectStore requestObjects,
        [FromServices] ITenantContext tenantContext)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(requestObjects);
        ArgumentNullException.ThrowIfNull(tenantContext);

        if (!ValidDid(request.VerifierDid) ||
            string.IsNullOrWhiteSpace(request.Nonce) || request.Nonce.Length != 43)
        {
            return Results.Problem(title: "Invalid OpenID4VP Cancellation",
                detail: "A verifier DID and exact 43-character issued nonce are required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            // The retained challenge is bound to tenant, verifier client ID and nonce.
            // Atomic consumption also prevents a future valid holder response.
            string audience = "decentralized_identifier:" + request.VerifierDid;
            _ = challenges.TryConsume(tenantId, audience, request.Nonce);
            // A successfully cancelled (or already-spent) nonce cannot produce
            // a valid holder response. Immediately free its single-process
            // publication slot; otherwise cancelled requests exhaust the host
            // for their full lifetime even though public GET already returns 404.
            requestObjects.RetireConsumedChallenge(tenantId, audience, request.Nonce);
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
    /// The caller forwards a form obtained at its own independently hosted
    /// HTTPS callback. The persisted tenant/client ID/nonce binds the old issuer
    /// policy; the caller pins type/context, never trusting JWT-supplied policy.
    /// Mandatory issuer-signed status prevents misleading 'valid' without status.
    /// </summary>
    internal static IResult Verify(
        [FromBody] VerifyOpenId4VpDirectPostRequest request,
        [FromServices] IPresentationChallengeStore challenges,
        [FromServices] OpenId4VpJwtVcJsonRequestObjectStore requestObjects,
        [FromServices] ITenantContext tenantContext,
        [FromServices] TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(challenges);
        ArgumentNullException.ThrowIfNull(requestObjects);
        ArgumentNullException.ThrowIfNull(tenantContext);
        ArgumentNullException.ThrowIfNull(clock);

        if (!ValidDid(request.VerifierDid) ||
            string.IsNullOrWhiteSpace(request.Nonce) || request.Nonce.Length != 43 ||
            string.IsNullOrWhiteSpace(request.Form) || request.Form.Length > MaximumFormLength ||
            string.IsNullOrWhiteSpace(request.RevocationSnapshot) ||
            request.RevocationSnapshot.Length > MaximumSnapshotLength ||
            !ValidType(request.ExpectedCredentialType) ||
            !ValidContext(request.SubjectContextUri))
        {
            return Results.Problem(title: "Invalid OpenID4VP Response",
                detail: "An exact verifier DID/nonce, bounded direct_post form, signed issuer status and pinned HTTPS vocabulary are required.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        Guid tenantId = tenantContext.GetCurrentTenantId();
        if (tenantId == Guid.Empty)
        {
            return Results.Unauthorized();
        }

        try
        {
            var status = JwtVcJsonDirectPostRevocation.CheckResponseForm(
                request.Form!, request.RevocationSnapshot!, tenantId,
                "decentralized_identifier:" + request.VerifierDid,
                request.Nonce!, request.ExpectedCredentialType!,
                request.SubjectContextUri!, challenges, clock, out JsonElement subject);
            if (status is RevocationSnapshotCheckResult.NotListed or
                RevocationSnapshotCheckResult.Revoked)
            {
                // These decisions follow successful holder/issuer proof and
                // atomic challenge consumption. They must not retain unusable
                // hosted Request Objects until TTL; invalid attempts do not
                // retire a still-live challenge.
                requestObjects.RetireConsumedChallenge(tenantId,
                    "decentralized_identifier:" + request.VerifierDid, request.Nonce!);
            }

            return status switch
            {
                RevocationSnapshotCheckResult.NotListed =>
                    Results.Ok(new VerifyOpenId4VpDirectPostResponse("SignedNotListed", subject)),
                RevocationSnapshotCheckResult.Revoked =>
                    Results.Ok(new VerifyOpenId4VpDirectPostResponse("Revoked", null)),
                _ => Results.Ok(new VerifyOpenId4VpDirectPostResponse("Invalid", null))
            };
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

    private static bool ValidPublicRequestUriBase(Uri? uri) =>
        ValidHttps(uri) && uri!.OriginalString.Length <= 2_000 &&
        uri.AbsolutePath == PublicRequestObjectPath &&
        uri.Query.Length == 0 &&
        uri.OriginalString.EndsWith('/');

    private static bool ValidDid(string? did) =>
        !string.IsNullOrWhiteSpace(did) && did.Length <= 255 &&
        new DidKeyMethod().IsValid(did);

    private static bool ValidHttps(Uri? uri) =>
        uri is { IsAbsoluteUri: true } && uri.OriginalString.Length <= 2048 &&
        uri.Scheme == Uri.UriSchemeHttps && uri.Host.Length != 0 &&
        uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
        string.Equals(uri.AbsoluteUri, uri.OriginalString, StringComparison.Ordinal);

    private static bool ValidContext(Uri? uri) =>
        uri is { IsAbsoluteUri: true } && uri.Scheme == Uri.UriSchemeHttps &&
        uri.Host.Length != 0 && uri.UserInfo.Length == 0 &&
        uri.Fragment.Length == 0 && uri.AbsoluteUri.Length <= 2048;

    private static bool ValidType(string? type) =>
        !string.IsNullOrWhiteSpace(type) && type.Length <= 128 &&
        !type.Any(char.IsWhiteSpace) &&
        Uri.TryCreate(type, UriKind.Absolute, out var iri) &&
        iri.Scheme == Uri.UriSchemeHttps && iri.Host.Length != 0 &&
        iri.UserInfo.Length == 0 &&
        !string.Equals(type,
            "https://www.w3.org/2018/credentials#VerifiableCredential", StringComparison.Ordinal);

    private static IResult InvalidRequest() => Results.Problem(
        title: "Invalid Signed OpenID4VP Request",
        detail: "An active owned Ed25519 verifier DID, independently selected issuer, canonical HTTPS callback/type/context and 1–300 second lifetime are required.",
        statusCode: StatusCodes.Status400BadRequest);

    private static IResult Unavailable() => Results.Problem(
        title: "OpenID4VP Verifier Unavailable",
        detail: "Durable challenge storage or verifier signing is unavailable.",
        statusCode: StatusCodes.Status503ServiceUnavailable);
}

/// <summary>An authenticated tenant signs only using its own active verifier DID.</summary>
public sealed class IssueOpenId4VpSignedRequestRequest
{
    public string? VerifierDid { get; init; }
    public Uri? ResponseUri { get; init; }
    public string? TrustedIssuerDid { get; init; }
    public string? CredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
    public int LifetimeSeconds { get; init; } = 120;
    public bool PublishRequestUri { get; init; }
}

/// <summary>Untrusted holder must independently pin DID, HTTPS callback, type, context and consent.</summary>
public sealed record IssueOpenId4VpSignedRequestResponse(
    string SignedRequestJwt, string ClientId, string VerifierDid, Uri ResponseUri,
    string Nonce, string TrustedIssuerDid, DateTimeOffset ExpiresAt,
    [property: System.Text.Json.Serialization.JsonPropertyName("walletInvocationUri")]
    string WalletInvocation,
    [property: System.Text.Json.Serialization.JsonPropertyName("referenceWalletInvocationUri")]
    string? ReferenceWalletInvocation);

/// <summary>
/// Backend-only cancellation of an outstanding verifier-owned challenge.
/// A holder cannot call this endpoint with a wallet presentation alone.
/// </summary>
public sealed class CancelOpenId4VpSignedRequestRequest
{
    public string? VerifierDid { get; init; }
    public string? Nonce { get; init; }
}

/// <summary>Authorized verifier forwards the entire unmodified direct_post form.</summary>
public sealed class VerifyOpenId4VpDirectPostRequest
{
    public string? VerifierDid { get; init; }
    public string? Nonce { get; init; }
    public string? Form { get; init; }
    public string? RevocationSnapshot { get; init; }
    public string? ExpectedCredentialType { get; init; }
    public Uri? SubjectContextUri { get; init; }
}

/// <summary>No identity/authorization or live status guarantee; only SignedNotListed exposes claims.</summary>
public sealed record VerifyOpenId4VpDirectPostResponse(string Status, JsonElement? VerifiedSubject);
