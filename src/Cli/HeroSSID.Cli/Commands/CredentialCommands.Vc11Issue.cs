using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Offline, issuer-operated genuine VC Data Model 1.1 jwt_vc_json issuance.
/// A wallet never becomes an issuer by presenting a signed credential.
/// </summary>
internal static partial class CredentialCommands
{
    private const int MaximumVc11SubjectFileBytes = 16_384;

    internal sealed record Vc11IssueParameters(
        string? IssuerDid, string? IssuerName, string? CredentialId,
        string? HolderDid, string? CredentialType, string? Context,
        string? SubjectFile, string? ValidFrom, string? ValidUntil,
        string? OutputFile);

    internal static bool TryIssueVc11DidKey(
        Vc11IssueParameters parameters, Stream seedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(seedInput);

        if (string.IsNullOrWhiteSpace(parameters.IssuerDid) ||
            string.IsNullOrWhiteSpace(parameters.HolderDid) ||
            string.IsNullOrWhiteSpace(parameters.CredentialType) ||
            string.IsNullOrWhiteSpace(parameters.SubjectFile) ||
            string.IsNullOrWhiteSpace(parameters.OutputFile) ||
            (parameters.IssuerName is not null &&
                string.IsNullOrWhiteSpace(parameters.IssuerName)) ||
            !TryCanonicalIssuerHttps(parameters.Context, out Uri? context) ||
            context!.Fragment.Length != 0 ||
            (parameters.CredentialId is not null &&
                !TryCanonicalIssuerHttps(parameters.CredentialId, out _)) ||
            !DateTimeOffset.TryParseExact(parameters.ValidFrom, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
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

        Uri? id = null;
        if (parameters.CredentialId is not null &&
            !TryCanonicalIssuerHttps(parameters.CredentialId, out id))
        {
            return false;
        }

        byte[] seed = [];
        byte[] subjectBytes = new byte[MaximumVc11SubjectFileBytes + 1];
        bool outputCreated = false;
        bool outputComplete = false;
        try
        {
            if (File.Exists(parameters.OutputFile))
            {
                return false;
            }

            int length = 0;
            using (var input = new FileStream(parameters.SubjectFile, FileMode.Open,
                FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan))
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

            if (length == 0 || length > MaximumVc11SubjectFileBytes)
            {
                return false;
            }

            using var document = JsonDocument.Parse(subjectBytes.AsMemory(0, length),
                new JsonDocumentOptions { MaxDepth = 16 });
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (document.RootElement.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array) ||
                HasDuplicateVc11Properties(document.RootElement) ||
                validFrom > now || validUntil <= now ||
                !TryReadIssuerSeed(seedInput, out seed))
            {
                return false;
            }

            // The SDK checks real Ed25519 issuer control and normative vc.@context,
            // rejecting an incompatible key or ambiguous subject. The original
            // signed JWT, not a re-encoded claims object, is exported.
            string jwt;
            try
            {
                jwt = parameters.IssuerName is { } name
                    ? JwtVcJsonCredential.CreateWithIssuerName(
                        parameters.IssuerDid, parameters.HolderDid,
                        parameters.CredentialType, context, document.RootElement,
                        seed, validFrom, validUntil, name, id, exactValidity: true)
                    : id is not null
                        ? JwtVcJsonCredential.CreateWithExactValidity(
                            parameters.IssuerDid, parameters.HolderDid,
                            parameters.CredentialType, context, document.RootElement,
                            seed, validFrom, validUntil, id)
                        : JwtVcJsonCredential.CreateWithExactValidity(
                            parameters.IssuerDid, parameters.HolderDid,
                            parameters.CredentialType, context, document.RootElement,
                            seed, validFrom, validUntil);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seed);
                seed = [];
            }

            // Independently check the signed result against the issuer/subject
            // assertions before releasing an output file.
            bool verified;
            now = DateTimeOffset.UtcNow;
            if (parameters.IssuerName is { } expectedName && id is not null)
            {
                verified = JwtVcJsonCredential.TryVerifyWithPinnedIssuerNameAndId(
                    jwt, parameters.IssuerDid, expectedName, parameters.HolderDid,
                    parameters.CredentialType, context, id, now, out _);
            }
            else
            {
                verified = JwtVcJsonCredential.TryVerifyWithIssuerName(
                    jwt, parameters.IssuerDid, parameters.HolderDid,
                    parameters.CredentialType, context, now,
                    out _, out string? verifiedId, out string? verifiedName) &&
                    string.Equals(verifiedId, id?.AbsoluteUri, StringComparison.Ordinal) &&
                    string.Equals(verifiedName, parameters.IssuerName, StringComparison.Ordinal);
            }

            if (!verified)
            {
                return false;
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

            using (var destination = new FileStream(parameters.OutputFile, options))
            {
                outputCreated = true;
                byte[] jwtBytes = Encoding.ASCII.GetBytes(jwt + "\n");
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

            outputComplete = true;
            return true;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or
            ArgumentException or CryptographicException or NotSupportedException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(subjectBytes);
            if (outputCreated && !outputComplete)
            {
                try
                {
                    File.Delete(parameters.OutputFile!);
                }
                catch (IOException)
                {
                    // An incomplete output remains a failed operation.
                }
                catch (UnauthorizedAccessException)
                {
                    // An incomplete output remains a failed operation.
                }
            }
        }
    }

    private static bool HasDuplicateVc11Properties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (!names.Add(property.Name) ||
                    HasDuplicateVc11Properties(property.Value))
                {
                    return true;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in element.EnumerateArray())
            {
                if (HasDuplicateVc11Properties(item))
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static Command CreateVc11IssuerCommand()
    {
        var issuer = Required("--issuer-did", "Issuer's own Ed25519 did:key");
        var name = new Option<string>("--issuer-name",
            "Optional exact descriptive issuer name signed into vc.issuer");
        var id = new Option<string>("--credential-id",
            "Optional canonical HTTPS credential ID signed as jti");
        var holder = Required("--holder", "Credential subject did:key; not holder possession");
        var type = Required("--credential-type", "Issuer-selected credential type");
        var context = Required("--context", "Canonical HTTPS subject vocabulary");
        var subject = Required("--subject-file", "Bounded JSON credential subject file");
        var from = Required("--valid-from", "UTC round-trip ISO 8601 validity start");
        var until = Required("--valid-until", "UTC round-trip ISO 8601 validity end");
        var output = Required("--output-jwt-file", "New output JWT path, never overwritten");
        var command = new Command("issue-vc11-didkey",
            "Sign a genuine VC1.1 jwt_vc_json using a seed from redirected stdin");
        foreach (Option option in new Option[]
        {
            issuer, name, id, holder, type, context, subject, from, until, output
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!Console.IsInputRedirected ||
                !TryIssueVc11DidKey(new Vc11IssueParameters(
                    invocation.ParseResult.GetValueForOption(issuer),
                    invocation.ParseResult.GetValueForOption(name),
                    invocation.ParseResult.GetValueForOption(id),
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
                    "VC1.1 issuance rejected: issuer key, subject, validity, or output invalid. No credential released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Issuer-signed VC1.1 jwt_vc_json saved. Holder key control, consent, revocation, legal identity and authorization NOT checked.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
