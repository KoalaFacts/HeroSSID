using System.CommandLine;
using System.CommandLine.Invocation;
using System.Text.Json;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Original VC1.1 issuer-signed top-level string value under independently
/// enrolled verifier policy. A matching assertion is not business authority.
/// </summary>
internal static partial class CredentialCommands
{
    internal static bool TryVerifyVc11DidKeyPinnedClaim(
        Vc11PinnedVerifyParameters parameters, string? claimName,
        string? claimValue, DateTimeOffset observedAt) =>
        TryVerifyVc11DidKeyPinnedSubject(parameters, observedAt, out JsonElement subject) &&
        MatchesPinnedStringClaim(subject, claimName, claimValue);

    private static Command CreateVc11PinnedClaimCommand()
    {
        var jwtFile = Required("--jwt-file", "Original unchanged issuer-signed VC1.1 JWT");
        var issuer = Required("--trusted-issuer", "Independently enrolled issuer did:key");
        var issuerName = Required("--issuer-name", "Exact independently approved signed issuer name");
        var credentialId = Required("--credential-id", "Independently approved exact signed HTTPS jti");
        var holder = Required("--holder", "Expected subject did:key; not a possession proof");
        var type = Required("--credential-type", "Verifier-approved credential type");
        var context = Required("--context", "Verifier-approved HTTPS subject vocabulary");
        var claimName = Required("--claim-name", "Approved non-reserved top-level string claim name");
        var claimValue = Required("--claim-value", "Required exact signed string value, never printed");
        var command = new Command("verify-vc11-didkey-pinned-claim",
            "Accept one exact signed VC1.1 string assertion only after independent issuer and metadata pins");
        foreach (Option option in new Option[]
        {
            jwtFile, issuer, issuerName, credentialId, holder, type,
            context, claimName, claimValue
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            var policy = new Vc11PinnedVerifyParameters(
                invocation.ParseResult.GetValueForOption(jwtFile),
                invocation.ParseResult.GetValueForOption(issuer),
                invocation.ParseResult.GetValueForOption(issuerName),
                invocation.ParseResult.GetValueForOption(credentialId),
                invocation.ParseResult.GetValueForOption(holder),
                invocation.ParseResult.GetValueForOption(type),
                invocation.ParseResult.GetValueForOption(context));

            if (!TryVerifyVc11DidKeyPinnedClaim(policy,
                invocation.ParseResult.GetValueForOption(claimName),
                invocation.ParseResult.GetValueForOption(claimValue),
                DateTimeOffset.UtcNow))
            {
                Console.Error.WriteLine(
                    "VC1.1 signed claim rejected: original issuer signature, independent pins, exact assertion, validity or file check failed. No claims released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Original issuer-signed VC1.1 JWT, independently pinned issuer/metadata and exact required string assertion verified. " +
                "Holder control, consent, revocation, legal identity and business authorization NOT checked.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
