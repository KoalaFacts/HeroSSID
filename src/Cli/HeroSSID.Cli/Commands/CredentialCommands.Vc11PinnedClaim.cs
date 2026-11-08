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

    // The default System.CommandLine parser expands @response files and prints
    // unrecognized tokens before a command handler executes. For this command
    // that could echo the verifier's expected --claim-value. Validate the full
    // argument shape BEFORE invoking the parser; never report supplied tokens.
    private static readonly string[] PinnedClaimCliOptions =
    [
        "--jwt-file", "--trusted-issuer", "--issuer-name", "--credential-id",
        "--holder", "--credential-type", "--context", "--claim-name",
        "--claim-value"
    ];

    internal static bool CanInvokePinnedClaimWithoutEchoingPolicy(string[] arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        const string operation = "verify-vc11-didkey-pinned-claim";
        if (Array.IndexOf(arguments, operation) < 0)
        {
            // An @response file may expand into the protected operation after
            // this raw-argv preflight. The parser could then echo --claim-value
            // when its expansion or another option fails. Refuse response
            // files before parsing rather than attempting to inspect them.
            // Also reject an unexpected --claim-value on a mistyped command:
            // its token or following value could be echoed as unrecognized.
            foreach (string token in arguments)
            {
                if ((token.Length > 0 && token[0] == '@') ||
                    token.Equals("--claim-value", StringComparison.Ordinal) ||
                    token.StartsWith("--claim-value=", StringComparison.Ordinal))
                {
                    return false;
                }
            }

            // Ordinary unrelated CLI commands retain their original parsing.
            return true;
        }

        if (arguments.Length == 3 &&
            arguments[0] == "credential" && arguments[1] == operation &&
            (arguments[2] == "--help" || arguments[2] == "-h"))
        {
            return true;
        }

        if (arguments.Length < 3 || arguments[0] != "credential" ||
            arguments[1] != operation)
        {
            return false;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        for (int i = 2; i < arguments.Length; i++)
        {
            string token = arguments[i];
            int equals = token.IndexOf('=', StringComparison.Ordinal);
            string option = equals >= 0 ? token[..equals] : token;
            if (Array.IndexOf(PinnedClaimCliOptions, option) < 0 ||
                !seen.Add(option))
            {
                return false;
            }

            string value;
            if (equals >= 0)
            {
                value = token[(equals + 1)..];
            }
            else if (i + 1 < arguments.Length)
            {
                value = arguments[++i];
            }
            else
            {
                return false;
            }

            // @response-file expansion, option-shaped values and control
            // characters could change parsing or expose later policy tokens.
            if (string.IsNullOrEmpty(value) || value[0] == '@' ||
                value[0] == '-' || value.Contains('\r', StringComparison.Ordinal) || value.Contains('\n', StringComparison.Ordinal))
            {
                return false;
            }
        }

        return seen.Count == PinnedClaimCliOptions.Length;
    }

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
