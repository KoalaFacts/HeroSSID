using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// One genuine issuer may publish a bounded, private VC1.1 revocation snapshot.
/// An independently pinned relying party authenticates the ORIGINAL credential
/// and the status signed by that SAME issuer. No claim of live non-revocation.
/// </summary>
internal static partial class CredentialCommands
{
    // 256 original 64 KiB compact JWTs plus bounded JSON quoting overhead.
    private const int MaximumVc11StatusManifestBytes = 17_000_000;

    internal sealed record Vc11StatusIssueParameters(
        string? IssuerDid, string? RevokedJwtManifestFile,
        string? OutputSnapshotFile, string? ObservedAt);

    internal sealed record Vc11StatusVerifyParameters(
        Vc11PinnedVerifyParameters Pins, string? SnapshotFile,
        string? MinimumObservedAt);

    internal static bool TryIssueVc11DidKeyStatus(
        Vc11StatusIssueParameters parameters, Stream issuerSeedInput,
        TimeProvider clock)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(issuerSeedInput);
        ArgumentNullException.ThrowIfNull(clock);

        if (string.IsNullOrWhiteSpace(parameters.IssuerDid) ||
            !parameters.IssuerDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(parameters.RevokedJwtManifestFile) ||
            string.IsNullOrWhiteSpace(parameters.OutputSnapshotFile) ||
            !DateTimeOffset.TryParseExact(parameters.ObservedAt, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out DateTimeOffset observedAt) ||
            observedAt.Offset != TimeSpan.Zero)
        {
            return false;
        }

        byte[] seed = [];
        bool created = false;
        bool completed = false;
        try
        {
            if (File.Exists(parameters.OutputSnapshotFile) ||
                !TryReadVc11RevokedManifest(parameters.RevokedJwtManifestFile,
                    out string[] revokedJwt) ||
                !TryReadIssuerSeed(issuerSeedInput, out seed))
            {
                return false;
            }

            // Create authenticates EVERY original revoked JWT with this issuer
            // and checks the real signing seed, observed instant and 60s expiry.
            // The issuer supplies its COMPLETE authoritative revoked set;
            // a verifier cannot prove completeness from a signed export.
            string status = JwtVcJsonRevocationSnapshot.Create(
                parameters.IssuerDid, revokedJwt, seed, observedAt, clock);

            using (var destination = NewPrivateFile(parameters.OutputSnapshotFile))
            {
                created = true;
                byte[] output = Encoding.ASCII.GetBytes(status + "\n");
                try
                {
                    destination.Write(output);
                    destination.Flush(flushToDisk: true);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(output);
                }
            }

            completed = true;
            return true;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or JsonException or
            FormatException or NotSupportedException or InvalidOperationException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            if (created && !completed)
            {
                TryDeletePartialVerifierFile(parameters.OutputSnapshotFile!);
            }
        }
    }

    private static bool TryReadVc11RevokedManifest(
        string path, out string[] revokedJwts)
    {
        revokedJwts = [];
        byte[] buffer = new byte[MaximumVc11StatusManifestBytes + 1];
        try
        {
            using var input = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.SequentialScan);
            int length = 0;
            while (length < buffer.Length)
            {
                int read = input.Read(buffer, length, buffer.Length - length);
                if (read == 0)
                {
                    break;
                }

                length += read;
            }

            if (length == 0 || length > MaximumVc11StatusManifestBytes)
            {
                return false;
            }

            using var document = JsonDocument.Parse(buffer.AsMemory(0, length),
                new JsonDocumentOptions { MaxDepth = 4 });
            JsonElement manifest = document.RootElement;
            if (manifest.ValueKind != JsonValueKind.Array ||
                manifest.GetArrayLength() > JwtVcJsonRevocationSnapshot.MaximumEntries)
            {
                return false;
            }

            var entries = new List<string>(manifest.GetArrayLength());
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonElement element in manifest.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.String ||
                    element.GetString() is not { } original ||
                    original.Length == 0 ||
                    original.Length > MaximumCredentialFileBytes ||
                    !seen.Add(original))
                {
                    return false;
                }

                entries.Add(original);
            }

            revokedJwts = entries.ToArray();
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    internal static bool TryVerifyVc11DidKeyPinnedStatus(
        Vc11StatusVerifyParameters parameters, DateTimeOffset observedAt)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        Vc11PinnedVerifyParameters? pins = parameters.Pins;
        if (pins is null || string.IsNullOrWhiteSpace(pins.JwtFile) ||
            string.IsNullOrWhiteSpace(parameters.SnapshotFile) ||
            string.IsNullOrWhiteSpace(pins.TrustedIssuer) ||
            !pins.TrustedIssuer.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(pins.IssuerName) ||
            string.IsNullOrWhiteSpace(pins.HolderDid) ||
            !pins.HolderDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(pins.CredentialType) ||
            !TryCanonicalHttpsPin(pins.CredentialId, out Uri? id) ||
            !TryCanonicalHttpsPin(pins.Context, out Uri? vocabulary) ||
            vocabulary!.Fragment.Length != 0 ||
            !DateTimeOffset.TryParseExact(parameters.MinimumObservedAt, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out DateTimeOffset minimumObserved) ||
            minimumObserved.Offset != TimeSpan.Zero ||
            minimumObserved < DateTimeOffset.UnixEpoch ||
            minimumObserved > observedAt)
        {
            return false;
        }

        try
        {
            // Read and authenticate EXACTLY ONCE. Reopening an untrusted JWT
            // between credential validation and status digest validation could
            // create a TOCTOU mismatch and improperly clear a different JWT.
            if (!TryReadOriginalStatusJwt(new FileInfo(pins.JwtFile),
                    out string originalCredential) ||
                !TryReadOriginalStatusJwt(new FileInfo(parameters.SnapshotFile),
                    out string originalSnapshot) ||
                !JwtVcJsonCredential.TryVerifyWithPinnedIssuerNameAndId(
                    originalCredential, pins.TrustedIssuer, pins.IssuerName,
                    pins.HolderDid, pins.CredentialType, vocabulary, id!,
                    observedAt, out _))
            {
                return false;
            }

            return JwtVcJsonRevocationSnapshot.CheckWithObservationCutoff(
                originalSnapshot, originalCredential, pins.TrustedIssuer,
                observedAt, minimumObserved) ==
                RevocationSnapshotCheckResult.NotListed;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or JsonException or
            FormatException or InvalidOperationException or NotSupportedException)
        {
            return false;
        }
    }

    private static Command CreateVc11StatusIssueCommand()
    {
        var issuer = Required("--issuer-did", "Actual Ed25519 did:key of the issuing organisation");
        var manifest = Required("--revoked-jwts-manifest-file",
            "Bounded private JSON array of ALL original issuer-revoked VC1.1 JWTs");
        var observation = Required("--observed-at",
            "UTC round-trip timestamp when the complete revoked set was observed");
        var output = Required("--output-snapshot-file",
            "New signed status JWT file (never overwritten, Unix owner only)");
        var command = new Command("issue-vc11-didkey-status",
            "Issuer signs an authentic, 60-second private VC1.1 revocation observation");
        foreach (Option option in new Option[] { issuer, manifest, observation, output })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!Console.IsInputRedirected ||
                !TryIssueVc11DidKeyStatus(new Vc11StatusIssueParameters(
                    invocation.ParseResult.GetValueForOption(issuer),
                    invocation.ParseResult.GetValueForOption(manifest),
                    invocation.ParseResult.GetValueForOption(output),
                    invocation.ParseResult.GetValueForOption(observation)),
                    Console.OpenStandardInput(), TimeProvider.System))
            {
                Console.Error.WriteLine(
                    "VC1.1 status issuance rejected: signer, complete input, observation or private output invalid. No snapshot released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Issuer-signed private VC1.1 status snapshot saved. Complete status and current non-revocation are NOT established.");
            invocation.ExitCode = 0;
        });
        return command;
    }

    private static Command CreateVc11StatusVerifyCommand()
    {
        var jwt = Required("--jwt-file", "Original unchanged VC1.1 issuer-signed JWT");
        var snapshot = Required("--snapshot-file", "Original issuer-signed private status JWT");
        var issuer = Required("--trusted-issuer", "Independently enrolled issuer did:key");
        var name = Required("--issuer-name", "Exact independently approved signed issuer name");
        var id = Required("--credential-id", "Exact independently pinned signed HTTPS credential ID");
        var holder = Required("--holder", "Expected holder did:key; not a control proof");
        var type = Required("--credential-type", "Verifier-approved credential type");
        var context = Required("--context", "Verifier-approved HTTPS vocabulary");
        var cutoff = Required("--minimum-observed-at",
            "Verifier-owned earliest acceptable UTC status observation");
        var command = new Command("verify-vc11-didkey-pinned-status",
            "Verify genuine VC1.1 issuer signature, exact pins, status and incident cutoff");
        foreach (Option option in new Option[]
        {
            jwt, snapshot, issuer, name, id, holder, type, context, cutoff
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            var pins = new Vc11PinnedVerifyParameters(
                invocation.ParseResult.GetValueForOption(jwt),
                invocation.ParseResult.GetValueForOption(issuer),
                invocation.ParseResult.GetValueForOption(name),
                invocation.ParseResult.GetValueForOption(id),
                invocation.ParseResult.GetValueForOption(holder),
                invocation.ParseResult.GetValueForOption(type),
                invocation.ParseResult.GetValueForOption(context));
            if (!TryVerifyVc11DidKeyPinnedStatus(
                new Vc11StatusVerifyParameters(
                    pins, invocation.ParseResult.GetValueForOption(snapshot),
                    invocation.ParseResult.GetValueForOption(cutoff)),
                DateTimeOffset.UtcNow))
            {
                Console.Error.WriteLine(
                    "VC1.1 credential/status rejected: original issuer signature, independent pins, same-issuer status, revocation or observation failed. No claims released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Original VC1.1 issuer signature and same-issuer signed status verified: SignedNotListed. No claims released. " +
                "This is NOT live non-revocation, holder control, consent, legal identity or business authority.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
