using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Issuer-operated direct VC2 did:key issuance, not a wallet or authority check.
/// The signing seed arrives only on redirected stdin, never in argv or files.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2DidKeyIssueParameters(
        string? IssuerDid, string? HolderDid, string? CredentialType,
        string? Context, string? SubjectFile, string? ValidFrom,
        string? ValidUntil, string? OutputFile);

    internal static bool TryIssueVc2DidKey(
        Vc2DidKeyIssueParameters parameters, Stream seedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(seedInput);

        if (string.IsNullOrWhiteSpace(parameters.IssuerDid) ||
            string.IsNullOrWhiteSpace(parameters.HolderDid) ||
            string.IsNullOrWhiteSpace(parameters.CredentialType) ||
            string.IsNullOrWhiteSpace(parameters.SubjectFile) ||
            string.IsNullOrWhiteSpace(parameters.OutputFile) ||
            !TryCanonicalIssuerHttps(parameters.Context, out Uri? context) ||
            context!.Fragment.Length != 0 ||
            !DateTimeOffset.TryParseExact(parameters.ValidFrom, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out DateTimeOffset validFrom) ||
            !DateTimeOffset.TryParseExact(parameters.ValidUntil, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out DateTimeOffset validUntil) ||
            validFrom.Offset != TimeSpan.Zero ||
            validUntil.Offset != TimeSpan.Zero ||
            validUntil <= validFrom ||
            validUntil - validFrom > TimeSpan.FromHours(24))
        {
            return false;
        }

        byte[] seed = [];
        byte[] subjectBytes = new byte[MaximumIssuerSubjectBytes + 1];
        bool outputCreated = false;
        bool outputCompleted = false;
        try
        {
            int length = 0;
            using (var input = new FileStream(parameters.SubjectFile!,
                FileMode.Open, FileAccess.Read, FileShare.Read,
                4096, FileOptions.SequentialScan))
            {
                while (length < subjectBytes.Length)
                {
                    int read = input.Read(subjectBytes, length, subjectBytes.Length - length);
                    if (read == 0)
                    {
                        break;
                    }

                    length += read;
                }
            }

            if (length == 0 || length > MaximumIssuerSubjectBytes)
            {
                return false;
            }

            using var subject = JsonDocument.Parse(subjectBytes.AsMemory(0, length),
                new JsonDocumentOptions { MaxDepth = 16 });
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (subject.RootElement.ValueKind != JsonValueKind.Object ||
                !HasUniqueIssuerSubjectKeys(subject.RootElement) ||
                validFrom > now || validUntil <= now ||
                !TryReadIssuerSeed(seedInput, out seed))
            {
                return false;
            }

            string jwt;
            try
            {
                // Existing VCDM2 signer proves seed/DID consistency by
                // verifying its own genuine Ed25519 signature before release.
                jwt = Vcdm20JoseCredential.Create(parameters.IssuerDid!,
                    parameters.HolderDid!, parameters.CredentialType!,
                    context!, subject.RootElement, seed, validFrom, validUntil);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seed);
                seed = [];
            }

            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            using (var output = new FileStream(parameters.OutputFile!, options))
            {
                outputCreated = true;
                byte[] jwtBytes = Encoding.ASCII.GetBytes(jwt + "\n");
                try
                {
                    output.Write(jwtBytes);
                    output.Flush(flushToDisk: true);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(jwtBytes);
                }
            }

            outputCompleted = true;
            return true;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            JsonException or ArgumentException or NotSupportedException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(subjectBytes);
            if (outputCreated && !outputCompleted)
            {
                try
                {
                    File.Delete(parameters.OutputFile!);
                }
                catch (IOException)
                {
                    // The operation still fails; never disclose token material.
                }
                catch (UnauthorizedAccessException)
                {
                    // An owner must remove a partial artifact.
                }
            }
        }
    }

    private static bool HasUniqueIssuerSubjectKeys(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in value.EnumerateArray())
            {
                if (!HasUniqueIssuerSubjectKeys(item))
                {
                    return false;
                }
            }

            return true;
        }

        if (value.ValueKind != JsonValueKind.Object)
        {
            return true;
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in value.EnumerateObject())
        {
            if (!names.Add(property.Name) ||
                !HasUniqueIssuerSubjectKeys(property.Value))
            {
                return false;
            }
        }

        return true;
    }

    private static Command CreateVc2DidKeyIssuerCommand()
    {
        var issuer = Required("--issuer-did", "Issuer's own Ed25519 did:key");
        var holder = Required("--holder", "Signed subject did:key; not holder key proof");
        var type = Required("--credential-type", "Issuer-approved VC2 credential type");
        var context = Required("--context", "Canonical HTTPS subject vocabulary URI");
        var subject = Required("--subject-file", "Bounded subject JSON with exact holder id");
        var from = Required("--valid-from", "UTC ISO-8601 round-trip validity start");
        var until = Required("--valid-until", "UTC ISO-8601 round-trip expiry (max 24h)");
        var output = Required("--output-jwt-file", "Create-new credential file; never overwrite");

        var command = new Command("issue-vc2-didkey",
            "Issuer-sign one direct VCDM 2.0 vc+jwt using an Ed25519 seed piped via stdin");
        foreach (Option option in new Option[]
        {
            issuer, holder, type, context, subject, from, until, output
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!Console.IsInputRedirected ||
                !TryIssueVc2DidKey(new Vc2DidKeyIssueParameters(
                    invocation.ParseResult.GetValueForOption(issuer),
                    invocation.ParseResult.GetValueForOption(holder),
                    invocation.ParseResult.GetValueForOption(type),
                    invocation.ParseResult.GetValueForOption(context),
                    invocation.ParseResult.GetValueForOption(subject),
                    invocation.ParseResult.GetValueForOption(from),
                    invocation.ParseResult.GetValueForOption(until),
                    invocation.ParseResult.GetValueForOption(output)),
                    Console.OpenStandardInput()))
            {
                Console.Error.WriteLine(
                    "Direct VC2 issuer issuance rejected: seed, policy, subject or file invalid. No claims released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Direct VC2 issuer-signed JWT saved. Holder control, status, identity and authorization NOT checked.");
            invocation.ExitCode = 0;
        });

        return command;
    }
}
