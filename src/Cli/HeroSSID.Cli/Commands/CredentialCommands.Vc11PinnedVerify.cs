using System.CommandLine;
using System.CommandLine.Invocation;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Verifier-operated policy for an unchanged W3C VC1.1 jwt_vc_json credential.
/// Issuer signature validation does not establish holder control or authority.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc11PinnedVerifyParameters(
        string? JwtFile, string? TrustedIssuer, string? IssuerName,
        string? CredentialId, string? HolderDid, string? CredentialType,
        string? Context);

    internal static bool TryVerifyVc11DidKeyPinned(
        Vc11PinnedVerifyParameters parameters, DateTimeOffset observedAt) =>
        TryVerifyVc11DidKeyPinnedSubject(parameters, observedAt, out _);

    // One bounded original file read and one genuine issuer verification shared
    // by the issuer-only and exact-string-claim verifier commands.
    private static bool TryVerifyVc11DidKeyPinnedSubject(
        Vc11PinnedVerifyParameters parameters, DateTimeOffset observedAt,
        out JsonElement verifiedSubject)
    {
        verifiedSubject = default;
        ArgumentNullException.ThrowIfNull(parameters);

        // The operator must supply every exact trust pin independently; none
        // can come from a JWT header, issuer-signed assertion or file contents.
        if (string.IsNullOrWhiteSpace(parameters.JwtFile) ||
            string.IsNullOrWhiteSpace(parameters.TrustedIssuer) ||
            !parameters.TrustedIssuer.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(parameters.IssuerName) ||
            string.IsNullOrWhiteSpace(parameters.HolderDid) ||
            !parameters.HolderDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(parameters.CredentialType) ||
            !TryCanonicalHttpsPin(parameters.CredentialId, out Uri? credentialId) ||
            !TryCanonicalHttpsPin(parameters.Context, out Uri? vocabulary) ||
            vocabulary!.Fragment.Length != 0)
        {
            return false;
        }

        try
        {
            using var stream = new FileStream(parameters.JwtFile,
                FileMode.Open, FileAccess.Read, FileShare.Read, 4096,
                FileOptions.SequentialScan);
            byte[] bytes = new byte[MaximumCredentialFileBytes + 1];
            int length = 0;
            while (length < bytes.Length)
            {
                int count = stream.Read(bytes, length, bytes.Length - length);
                if (count == 0)
                {
                    break;
                }

                length += count;
            }

            if (length == 0 || length > MaximumCredentialFileBytes)
            {
                return false;
            }

            // Authenticate the ORIGINAL compact JWT. Do not deserialize into
            // a new object and mistakenly verify a different representation.
            string originalJwt = new UTF8Encoding(false, true)
                .GetString(bytes, 0, length).TrimEnd('\r', '\n');
            return JwtVcJsonCredential.TryVerifyWithPinnedIssuerNameAndId(
                originalJwt, parameters.TrustedIssuer, parameters.IssuerName,
                parameters.HolderDid, parameters.CredentialType,
                vocabulary, credentialId!, observedAt, out verifiedSubject);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static Command CreateVc11PinnedVerifyCommand()
    {
        var jwtFile = Required("--jwt-file",
            "Path to original unchanged issuer-signed VC1.1 JWT");
        var issuer = Required("--trusted-issuer",
            "Independently enrolled issuer did:key (not learned from JWT)");
        var issuerName = Required("--issuer-name",
            "Exact independently approved signed descriptive issuer name");
        var credentialId = Required("--credential-id",
            "Independently pinned signed HTTPS credential identifier");
        var holder = Required("--holder",
            "Independently expected subject did:key; not proof of key possession");
        var type = Required("--credential-type",
            "Exact verifier-approved credential type");
        var context = Required("--context",
            "Independently approved HTTPS credential subject vocabulary");
        var command = new Command("verify-vc11-didkey-pinned",
            "Check original VC1.1 jwt_vc_json against an explicit did:key, signed issuer name and ID");
        foreach (Option option in new Option[]
        {
            jwtFile, issuer, issuerName, credentialId, holder, type, context
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            var pins = new Vc11PinnedVerifyParameters(
                invocation.ParseResult.GetValueForOption(jwtFile),
                invocation.ParseResult.GetValueForOption(issuer),
                invocation.ParseResult.GetValueForOption(issuerName),
                invocation.ParseResult.GetValueForOption(credentialId),
                invocation.ParseResult.GetValueForOption(holder),
                invocation.ParseResult.GetValueForOption(type),
                invocation.ParseResult.GetValueForOption(context));

            if (!TryVerifyVc11DidKeyPinned(pins, DateTimeOffset.UtcNow))
            {
                Console.Error.WriteLine(
                    "VC1.1 JWT rejected: original issuer signature, signed issuer name/ID, independent pins, validity or file check failed. No claims released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Original VC1.1 issuer signature, independently pinned issuer name/ID, holder DID, type and context verified. " +
                "Holder private-key possession, consent, revocation, real identity and business authorization NOT checked.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
