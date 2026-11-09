using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Offline issuer-owned direct VC2 did:key status publication. The issuer
/// provides its own complete original-JWT revocation set and Ed25519 seed;
/// signed non-listing is never live status, identity or business authority.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2DidKeyStatusIssueParameters(
        string? IssuerDid, string? RevokedJwtListFile,
        string? ObservedAt, string? OutputFile);

    internal static bool TryIssueVc2DidKeyStatus(
        Vc2DidKeyStatusIssueParameters parameters, Stream seedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(seedInput);

        // Policy and the authoritative complete status source come from the
        // issuing organisation, never the Agent holder or a verifier request.
        if (parameters.IssuerDid is not { Length: > 0 and <= 2048 } issuerDid ||
            !issuerDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(parameters.RevokedJwtListFile) ||
            string.IsNullOrWhiteSpace(parameters.OutputFile) ||
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

        byte[] seed = [];
        byte[] manifestBytes = [];
        bool outputCreated = false;
        bool completed = false;
        try
        {
            if (File.Exists(parameters.OutputFile) ||
                !TryReadRevocationList(parameters.RevokedJwtListFile,
                    out manifestBytes, out List<string> revoked) ||
                !TryReadIssuerSeed(seedInput, out seed))
            {
                return false;
            }

            // The existing VC2 SDK checks the authentic original issuer JWT
            // for EVERY listed revocation, enforces the issuer seed/DID match,
            // and signs a separate HeroSSID-private 60-second status.
            string snapshot;
            try
            {
                snapshot = Vcdm20RevocationSnapshot.Create(
                    issuerDid, revoked, seed, observedAt, TimeProvider.System);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seed);
                seed = [];
            }

            // Owner-private from creation, atomic CreateNew rather than
            // truncating an existing output or following an existing symlink.
            using (var destination = NewPrivateFile(parameters.OutputFile!))
            {
                outputCreated = true;
                byte[] bytes = Encoding.ASCII.GetBytes(snapshot + "\n");
                try
                {
                    destination.Write(bytes);
                    destination.Flush(flushToDisk: true);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }

            completed = true;
            return true;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or JsonException or
            FormatException or InvalidOperationException or NotSupportedException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            CryptographicOperations.ZeroMemory(manifestBytes);
            if (outputCreated && !completed)
            {
                TryDeletePartialVerifierFile(parameters.OutputFile!);
            }
        }
    }

    private static Command CreateVc2DidKeyStatusIssueCommand()
    {
        var issuer = Required("--issuer-did",
            "Actual issuer-controlled Ed25519 did:key, not supplied by the Agent");
        var revoked = Required("--revoked-jwt-list-file",
            "Bounded newline-separated exact revoked original direct VC2 JWTs; empty file allowed");
        var observation = Required("--observed-at",
            "UTC round-trip time BEFORE observing complete authoritative revoked list");
        var output = Required("--output-jwt-file",
            "New owner-private signed status JWT file; never overwritten");
        var command = new Command("issue-vc2-didkey-status",
            "Issuer signs 60-second private direct VC2 status with own Ed25519 seed from stdin");
        foreach (Option option in new Option[]
        {
            issuer, revoked, observation, output
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!Console.IsInputRedirected ||
                !TryIssueVc2DidKeyStatus(
                    new Vc2DidKeyStatusIssueParameters(
                        invocation.ParseResult.GetValueForOption(issuer),
                        invocation.ParseResult.GetValueForOption(revoked),
                        invocation.ParseResult.GetValueForOption(observation),
                        invocation.ParseResult.GetValueForOption(output)),
                    Console.OpenStandardInput()))
            {
                Console.Error.WriteLine(
                    "VC2 status export rejected: issuer signing key, original revocation set, freshness or protected output invalid. No status released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Authentic issuer-signed private VC2 status saved. Not-listing does NOT prove complete/live non-revocation, Agent key control, identity or business authorization.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
