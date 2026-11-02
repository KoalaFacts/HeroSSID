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

        string? issuerDid = request switch
        {
            IssueCredentialRequest legacy => legacy.IssuerDid,
            IssueJwtVcJsonCredentialRequest vc11 => vc11.IssuerDid,
            IssueVcdm20CredentialRequest vc20 => vc20.IssuerDid,
            _ => null
        };
        var grants = context.RequestServices.GetRequiredService<IssuerSigningGrantRegistry>();
        return grants.IsAllowed(tenant, context.User, issuerDid);
    }
}
