using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.Vcdm20;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Issuer-operated, offline export of an independently pinned did:web VC2
/// original-JWT status list. The issuer owns the complete revocation source.
/// A signed non-listing is not live revocation, identity or authorization.
/// </summary>
internal static partial class CredentialCommands
{
    private const int MaximumStatusListFileBytes = 4_194_304;
    private const int MaximumStatusEntries = 256;
    private const int MaximumStatusCredentialLength = 65_536;

    internal sealed record Vc2DidWebStatusIssueParameters(
        string? IssuerDid, string? VerificationMethod, string? PublicKeyHex,
        string? IssuerName, string? RevokedJwtListFile, string? ObservedAt,
        string? OutputFile);

    internal static bool TryIssueVc2DidWebStatus(
        Vc2DidWebStatusIssueParameters parameters, Stream seedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(seedInput);

        // An issuer must supply its own authoritative set. Neither a verifier
        // nor an untrusted JWT supplies policy, status or a replacement key.
        if (string.IsNullOrWhiteSpace(parameters.IssuerDid) ||
            string.IsNullOrWhiteSpace(parameters.VerificationMethod) ||
            string.IsNullOrWhiteSpace(parameters.IssuerName) ||
            string.IsNullOrWhiteSpace(parameters.RevokedJwtListFile) ||
            string.IsNullOrWhiteSpace(parameters.OutputFile) ||
            parameters.PublicKeyHex is not { Length: 64 } ||
            !DateTimeOffset.TryParseExact(parameters.ObservedAt, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out DateTimeOffset observedAt) ||
            observedAt.Offset != TimeSpan.Zero ||
            observedAt < DateTimeOffset.UnixEpoch ||
            observedAt > DateTimeOffset.UtcNow ||
            observedAt.AddSeconds(60) <= DateTimeOffset.UtcNow)
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

        byte[] seed = [];
        byte[] listBytes = [];
        bool outputCreated = false;
        bool outputComplete = false;
        try
        {
            if (File.Exists(parameters.OutputFile) ||
                !TryReadRevocationList(parameters.RevokedJwtListFile,
                    out listBytes, out List<string> revoked) ||
                !TryReadIssuerSeed(seedInput, out seed))
            {
                return false;
            }

            // The SDK authenticates every original listed VC2 JWT under the
            // pinned issuer's Ed25519 key, verifies the signing seed matches,
            // and rejects stale snapshots. It does not verify completeness.
            string snapshot;
            try
            {
                snapshot = Vcdm20PinnedDidWebIssuerStatus.Create(
                    parameters.IssuerDid, parameters.VerificationMethod, seed,
                    publicKey, parameters.IssuerName, revoked, observedAt,
                    TimeProvider.System);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seed);
                seed = [];
            }

            // Never overwrite an existing file or symbolic-link destination.
            // Restrict Unix permissions from the moment the file is created.
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None
            };
            if (!OperatingSystem.IsWindows())
            {
                options.UnixCreateMode =
                    UnixFileMode.UserRead | UnixFileMode.UserWrite;
            }

            using (var destination = new FileStream(parameters.OutputFile, options))
            {
                outputCreated = true;
                byte[] outputBytes = Encoding.ASCII.GetBytes(snapshot + "\n");
                try
                {
                    destination.Write(outputBytes);
                    destination.Flush(flushToDisk: true);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(outputBytes);
                }
            }

            outputComplete = true;
            return true;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or NotSupportedException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(listBytes);
            if (outputCreated && !outputComplete)
            {
                try
                {
                    File.Delete(parameters.OutputFile!);
                }
                catch (IOException)
                {
                    // The caller must remove any incomplete artifact manually.
                }
                catch (UnauthorizedAccessException)
                {
                    // Failure is not success even if cleanup was denied.
                }
            }
        }
    }

    private static bool TryReadRevocationList(
        string path, out byte[] fileBytes, out List<string> revoked)
    {
        fileBytes = new byte[MaximumStatusListFileBytes + 1];
        revoked = [];
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read, 4096, FileOptions.SequentialScan);
        int length = 0;
        while (length < fileBytes.Length)
        {
            int read = input.Read(fileBytes, length, fileBytes.Length - length);
            if (read == 0)
            {
                break;
            }

            length += read;
        }

        if (length > MaximumStatusListFileBytes)
        {
            return false;
        }

        // Compact JWTs are ASCII. Reject BOM, whitespace and malformed
        // encoding rather than silently normalizing a signed original.
        for (int i = 0; i < length; i++)
        {
            if (fileBytes[i] > 0x7f)
            {
                return false;
            }
        }

        string contents = Encoding.ASCII.GetString(fileBytes, 0, length);
        if (contents.Length == 0)
        {
            // Explicit empty authoritative set; completeness is not proven.
            return true;
        }

        string[] lines = contents.Split('\n');
        int count = lines.Length;
        if (lines[count - 1].Length == 0)
        {
            count--;
        }

        if (count > MaximumStatusEntries)
        {
            return false;
        }

        for (int i = 0; i < count; i++)
        {
            string jwt = lines[i];
            if (jwt.EndsWith('\r'))
            {
                jwt = jwt[..^1];
            }

            if (jwt.Length == 0 || jwt.Length > MaximumStatusCredentialLength ||
                jwt.Any(static ch => ch is not (>= 'A' and <= 'Z' or
                    >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '-' or '_')))
            {
                return false;
            }

            revoked.Add(jwt);
        }

        return true;
    }

    private static Command CreateVc2DidWebStatusIssuerCommand()
    {
        var issuer = Required("--issuer-did", "Issuer-owned restricted did:web identity");
        var method = Required("--verification-method", "Enrolled did:web #key-1 or #key-2");
        var key = Required("--public-key-hex", "Issuer's enrolled Ed25519 public key");
        var name = Required("--issuer-name", "Exact issuer-signed descriptive name");
        var revoked = Required("--revoked-jwt-list-file",
            "Authoritative newline-separated unchanged original revoked VC2 JWTs (empty file allowed)");
        var observed = Required("--observed-at",
            "UTC round-trip time observed BEFORE collecting the complete revocation list");
        var output = Required("--output-jwt-file", "New status JWT file; never overwritten");

        var command = new Command("issue-vc2-didweb-status",
            "Sign an issuer-owned 60-second offline did:web VC2 status using an Ed25519 seed from redirected stdin");
        foreach (Option option in new Option[]
        {
            issuer, method, key, name, revoked, observed, output
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!Console.IsInputRedirected ||
                !TryIssueVc2DidWebStatus(new Vc2DidWebStatusIssueParameters(
                    invocation.ParseResult.GetValueForOption(issuer),
                    invocation.ParseResult.GetValueForOption(method),
                    invocation.ParseResult.GetValueForOption(key),
                    invocation.ParseResult.GetValueForOption(name),
                    invocation.ParseResult.GetValueForOption(revoked),
                    invocation.ParseResult.GetValueForOption(observed),
                    invocation.ParseResult.GetValueForOption(output)),
                    Console.OpenStandardInput()))
            {
                Console.Error.WriteLine(
                    "Status export rejected: issuer pin, original JWT list, freshness, signing seed or output invalid. No status artifact released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Issuer-signed 60-second status saved. Non-listing is not live or complete revocation, holder proof, identity or authorization.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
