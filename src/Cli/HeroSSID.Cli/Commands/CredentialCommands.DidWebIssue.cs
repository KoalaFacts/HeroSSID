using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Issuer-operated offline issuance. A raw seed is accepted only from redirected
/// standard input; no private key is accepted via argv, environment or a file.
/// No credential is released until the genuine SDK signer verifies the JWT.
/// </summary>
internal static partial class CredentialCommands
{
    private const int MaximumIssuerSubjectBytes = 16_384;

    internal sealed record Vc2DidWebIssueParameters(
        string? IssuerDid, string? VerificationMethod, string? PublicKeyHex,
        string? IssuerName, string? CredentialId, string? Audience,
        string? HolderDid, string? CredentialType, string? Context,
        string? SubjectFile, string? ValidFrom, string? ValidUntil,
        string? OutputFile);

    internal static bool TryIssueVc2DidWeb(
        Vc2DidWebIssueParameters parameters, Stream seedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(seedInput);

        // Reject malformed local/operator policy before ever touching a key.
        if (string.IsNullOrWhiteSpace(parameters.IssuerDid) ||
            string.IsNullOrWhiteSpace(parameters.VerificationMethod) ||
            string.IsNullOrWhiteSpace(parameters.IssuerName) ||
            string.IsNullOrWhiteSpace(parameters.HolderDid) ||
            string.IsNullOrWhiteSpace(parameters.CredentialType) ||
            string.IsNullOrWhiteSpace(parameters.SubjectFile) ||
            string.IsNullOrWhiteSpace(parameters.OutputFile) ||
            parameters.PublicKeyHex is not { Length: 64 } ||
            !TryCanonicalIssuerHttps(parameters.CredentialId, out Uri? credentialId) ||
            !TryCanonicalIssuerHttps(parameters.Audience, out Uri? audience) ||
            !TryCanonicalIssuerHttps(parameters.Context, out Uri? context) ||
            context!.Fragment.Length != 0 ||
            !DateTimeOffset.TryParseExact(parameters.ValidFrom, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.None,
                out DateTimeOffset validFrom) ||
            !DateTimeOffset.TryParseExact(parameters.ValidUntil, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out DateTimeOffset validUntil) ||
            validFrom.Offset != TimeSpan.Zero ||
            validUntil.Offset != TimeSpan.Zero ||
            validUntil <= validFrom)
        {
            return false;
        }

        byte[] publicKey;
        try
        {
            publicKey = Convert.FromHexString(parameters.PublicKeyHex);
        }
        catch (FormatException)
        {
            return false;
        }

        // No synthetic or untrusted public key can bless a credential:
        // the signing SDK independently verifies the exact JWT with this pin.
        byte[] seed = [];
        bool outputCreated = false;
        bool outputCompleted = false;
        try
        {
            byte[] subjectBytes = new byte[MaximumIssuerSubjectBytes + 1];
            int subjectLength = 0;
            using (var source = new FileStream(parameters.SubjectFile!,
                FileMode.Open, FileAccess.Read, FileShare.Read,
                4096, FileOptions.SequentialScan))
            {
                while (subjectLength < subjectBytes.Length)
                {
                    int read = source.Read(subjectBytes, subjectLength,
                        subjectBytes.Length - subjectLength);
                    if (read == 0)
                    {
                        break;
                    }

                    subjectLength += read;
                }
            }

            if (subjectLength == 0 ||
                subjectLength > MaximumIssuerSubjectBytes)
            {
                return false;
            }

            using var subject = JsonDocument.Parse(
                subjectBytes.AsMemory(0, subjectLength),
                new JsonDocumentOptions { MaxDepth = 16 });

            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (subject.RootElement.ValueKind != JsonValueKind.Object ||
                validFrom > now || validUntil <= now ||
                !TryReadIssuerSeed(seedInput, out seed))
            {
                return false;
            }

            string signedJwt;
            try
            {
                signedJwt = Vcdm20JoseCredential.CreateForPinnedDidWebIssuerAudienceWithId(
                    parameters.IssuerDid, parameters.VerificationMethod, seed,
                    publicKey, parameters.IssuerName, credentialId!, audience!,
                    parameters.HolderDid, parameters.CredentialType, context!,
                    subject.RootElement, validFrom, validUntil);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seed);
                seed = [];
            }

            // CreateNew refuses an existing target or symbolic-link target;
            // Unix create permissions are restricted before the first byte.
            var outputOptions = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None
            };
            if (!OperatingSystem.IsWindows())
            {
                outputOptions.UnixCreateMode =
                    UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            using (var destination = new FileStream(parameters.OutputFile!,
                outputOptions))
            {
                outputCreated = true;
                byte[] jwtBytes = Encoding.ASCII.GetBytes(signedJwt + "\n");
                try
                {
                    destination.Write(jwtBytes);
                    destination.Flush(flushToDisk: true);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(jwtBytes);
                }
            }

            outputCompleted = true;
            return true;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or NotSupportedException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(publicKey);
            if (outputCreated && !outputCompleted)
            {
                try
                {
                    File.Delete(parameters.OutputFile!);
                }
                catch (IOException)
                {
                    // The issuance still failed; never print token material.
                }
                catch (UnauthorizedAccessException)
                {
                    // An owner must remove the incomplete file before retrying.
                }
            }
        }
    }

    private static bool TryReadIssuerSeed(Stream input, out byte[] seed)
    {
        seed = [];
        byte[] characters = new byte[67];
        try
        {
            int length = 0;
            while (length < characters.Length)
            {
                int read = input.Read(characters, length,
                    characters.Length - length);
                if (read == 0)
                {
                    break;
                }

                length += read;
            }

            if (length != 64 &&
                !(length == 65 && characters[64] == (byte)'\n') &&
                !(length == 66 && characters[64] == (byte)'\r' &&
                  characters[65] == (byte)'\n'))
            {
                return false;
            }

            var decoded = new byte[32];
            for (int i = 0; i < decoded.Length; i++)
            {
                int high = HexNibble(characters[2 * i]);
                int low = HexNibble(characters[2 * i + 1]);
                if (high < 0 || low < 0)
                {
                    CryptographicOperations.ZeroMemory(decoded);
                    return false;
                }

                decoded[i] = (byte)((high << 4) | low);
            }

            if (decoded.All(static value => value == 0))
            {
                CryptographicOperations.ZeroMemory(decoded);
                return false;
            }

            seed = decoded;
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(characters);
        }
    }

    private static int HexNibble(byte character) =>
        character is >= (byte)'0' and <= (byte)'9'
            ? character - (byte)'0'
            : character is >= (byte)'A' and <= (byte)'F'
                ? character - (byte)'A' + 10
                : character is >= (byte)'a' and <= (byte)'f'
                    ? character - (byte)'a' + 10
                    : -1;

    private static bool TryCanonicalIssuerHttps(string? text, out Uri? uri)
    {
        uri = null;
        if (string.IsNullOrWhiteSpace(text) || text.Length > 2048 ||
            !Uri.TryCreate(text, UriKind.Absolute, out Uri? parsed) ||
            parsed.Scheme != Uri.UriSchemeHttps ||
            string.IsNullOrWhiteSpace(parsed.Host) ||
            parsed.UserInfo.Length != 0 ||
            !string.Equals(text, parsed.AbsoluteUri, StringComparison.Ordinal))
        {
            return false;
        }

        uri = parsed;
        return true;
    }

    private static Command CreateVc2DidWebIssuerCommand()
    {
        var issuer = Required("--issuer-did", "Issuer-approved did:web identity");
        var method = Required("--verification-method", "Issuer-approved did:web #key-1 or #key-2");
        var publicKey = Required("--public-key-hex", "Issuer's enrolled Ed25519 public key");
        var name = Required("--issuer-name", "Issuer's signed descriptive name");
        var id = Required("--credential-id", "Original signed HTTPS credential ID");
        var audience = Required("--audience", "Intended signed HTTPS recipient");
        var holder = Required("--holder", "Holder did:key subject, not proof of control");
        var credentialType = Required("--credential-type", "Issuer-approved credential type");
        var context = Required("--context", "HTTPS subject vocabulary");
        var subject = Required("--subject-file", "Bounded UTF-8 JSON subject file");
        var from = Required("--valid-from", "UTC round-trip ISO-8601 validity start");
        var until = Required("--valid-until", "UTC round-trip ISO-8601 validity end");
        var output = Required("--output-jwt-file", "New output file, never overwritten");

        var command = new Command("issue-vc2-didweb-recipient",
            "Issue an authentic recipient-bound VC2 JWT using a private seed from redirected stdin");
        foreach (Option option in new Option[]
        {
            issuer, method, publicKey, name, id, audience, holder,
            credentialType, context, subject, from, until, output
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!Console.IsInputRedirected ||
                !TryIssueVc2DidWeb(new Vc2DidWebIssueParameters(
                    invocation.ParseResult.GetValueForOption(issuer),
                    invocation.ParseResult.GetValueForOption(method),
                    invocation.ParseResult.GetValueForOption(publicKey),
                    invocation.ParseResult.GetValueForOption(name),
                    invocation.ParseResult.GetValueForOption(id),
                    invocation.ParseResult.GetValueForOption(audience),
                    invocation.ParseResult.GetValueForOption(holder),
                    invocation.ParseResult.GetValueForOption(credentialType),
                    invocation.ParseResult.GetValueForOption(context),
                    invocation.ParseResult.GetValueForOption(subject),
                    invocation.ParseResult.GetValueForOption(from),
                    invocation.ParseResult.GetValueForOption(until),
                    invocation.ParseResult.GetValueForOption(output)),
                    Console.OpenStandardInput()))
            {
                Console.Error.WriteLine(
                    "Issuance rejected: private-seed pipe, exact signed policy, or output invalid. No claims released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Original issuer-signed VC2 JWT saved; holder control, live status, identity and authorization NOT checked.");
            invocation.ExitCode = 0;
        });
        return command;
    }

    private static Option<string> Required(string name, string description) =>
        new(name, description) { IsRequired = true };
}
