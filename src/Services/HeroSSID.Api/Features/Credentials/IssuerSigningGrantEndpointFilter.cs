using System.Text.Json;
using HeroSSID.Api.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace HeroSSID.Api.Features.Credentials;

/// <summary>
/// Enforce operator-owned signing-key grants before database lookup, decryption,
/// signing or persistence on every credential-issuance route.
/// </summary>
internal static class IssuerSigningGrantEndpointFilter
{
    internal static RouteHandlerBuilder RequireIssuerSigningGrant(this RouteHandlerBuilder builder) =>
        builder.AddEndpointFilter(async (invocation, next) =>
        {
            if (!Allows(invocation.HttpContext, invocation.Arguments.FirstOrDefault()))
            {
                // Do not reveal whether another client or tenant owns this DID.
                return Results.NotFound();
            }

            return await next(invocation).ConfigureAwait(false);
        });

    internal static bool Allows(HttpContext context, object? request)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!AuthenticatedTenantContext.TryGetTenantId(context.User, out Guid tenant))
        {
            return false;
        }

        (string? issuerDid, string? credentialType,
            IReadOnlyCollection<string>? claimNames, bool intrinsicHolderId) = request switch
        {
            IssueCredentialRequest legacy =>
                (legacy.IssuerDid, legacy.CredentialType, legacy.Claims?.Keys.ToArray(), false),
            IssueJwtVcJsonCredentialRequest vc11 =>
                (vc11.IssuerDid, vc11.CredentialType, SubjectNames(vc11.CredentialSubject), true),
            IssueVcdm20CredentialRequest vc20 =>
                (vc20.IssuerDid, vc20.CredentialType, SubjectNames(vc20.CredentialSubject), true),
            _ => (null, null, null, false)
        };
        var grants = context.RequestServices.GetRequiredService<IssuerSigningGrantRegistry>();
        return grants.IsAllowed(tenant, context.User, issuerDid, credentialType,
            claimNames, intrinsicHolderId);
    }

    private static IReadOnlyCollection<string>? SubjectNames(JsonElement subject) =>
        subject.ValueKind == JsonValueKind.Object
            ? [.. subject.EnumerateObject().Select(static claim => claim.Name)]
            : null;
}
