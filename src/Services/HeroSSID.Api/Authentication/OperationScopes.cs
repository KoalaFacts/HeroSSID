namespace HeroSSID.Api.Authentication;

internal static class OperationScopes
{
    internal const string DidManage = "did:manage";
    internal const string CredentialIssue = "credential:issue";
    internal const string CredentialVerify = "credential:verify";
    internal const string CredentialRevoke = "credential:revoke";

    internal static bool HasScope(System.Security.Claims.ClaimsPrincipal user, string requiredScope) =>
        user.FindAll("scope").SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Contains(requiredScope, StringComparer.Ordinal);
}
