using System.CommandLine;
using System.CommandLine.Invocation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Verifier-owned, single-machine offline VC1.1 challenge and presentation session.
/// The private local file is the verifier's durable one-use authorization state,
/// not a hosted OpenID4VP verifier or a distributed challenge store.
/// </summary>
internal static partial class CredentialCommands
{
    private const int MaximumVc11VerifierStateBytes = 16_384;
    private const string Vc11VerifierStateVersion = "herossid-vc11-verifier-session-v1";

    internal sealed record Vc11VerifierRequestParameters(
        string? VerifierDid, string? TenantId, string? Audience,
        string? TrustedIssuerDid, string? CredentialType, string? Context,
        string? RequestJwtFile, string? SessionFile, int LifetimeSeconds);

    internal sealed record Vc11VerifierCheckParameters(
        string? VerifierDid, string? TenantId, string? Audience,
        string? TrustedIssuerDid, string? CredentialType, string? Context,
        string? RequestJwtFile, string? SessionFile, string? PresentationJwtFile);

    private sealed record Vc11VerifierSessionState(
        string Version, string VerifierDid, Guid TenantId, string Audience,
        string TrustedIssuerDid, string CredentialType, string Context,
        string Nonce, DateTimeOffset ExpiresAt, string RequestSha256);

    internal static bool TryCreateVc11VerifierRequest(
        Vc11VerifierRequestParameters parameters, Stream verifierSeedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(verifierSeedInput);

        if (!ValidVerifierPolicy(parameters.VerifierDid, parameters.TenantId,
                parameters.Audience, parameters.TrustedIssuerDid,
                parameters.CredentialType, parameters.Context,
                out Guid tenantId, out _) ||
            string.IsNullOrWhiteSpace(parameters.RequestJwtFile) ||
            string.IsNullOrWhiteSpace(parameters.SessionFile) ||
            string.Equals(Path.GetFullPath(parameters.RequestJwtFile),
                Path.GetFullPath(parameters.SessionFile), StringComparison.Ordinal) ||
            parameters.LifetimeSeconds is < 1 or > 300)
        {
            return false;
        }

        byte[] seed = [];
        bool sessionCreated = false;
        bool requestCreated = false;
        bool completed = false;
        try
        {
            if (File.Exists(parameters.RequestJwtFile) ||
                File.Exists(parameters.SessionFile) ||
                File.Exists(parameters.SessionFile + ".used") ||
                !TryReadIssuerSeed(verifierSeedInput, out seed))
            {
                return false;
            }

            var store = new InMemoryPresentationChallengeStore(TimeProvider.System);
            var challenge = store.Issue(tenantId, parameters.Audience!,
                parameters.TrustedIssuerDid!, TimeSpan.FromSeconds(parameters.LifetimeSeconds));
            string request = OfflineSignedPresentationRequest.Create(
                challenge, parameters.VerifierDid!, seed, TimeProvider.System);
            if (!OfflineSignedPresentationRequest.TryRead(request, parameters.VerifierDid!,
                    parameters.Audience!, TimeProvider.System, out var signedChallenge) ||
                signedChallenge is null ||
                !string.Equals(signedChallenge.TrustedIssuerDid, parameters.TrustedIssuerDid,
                    StringComparison.Ordinal))
            {
                return false;
            }

            var state = new Vc11VerifierSessionState(
                Vc11VerifierStateVersion, parameters.VerifierDid!, tenantId,
                parameters.Audience!, parameters.TrustedIssuerDid!,
                parameters.CredentialType!, parameters.Context!,
                signedChallenge.Nonce, signedChallenge.ExpiresAt,
                Sha256Hex(request));
            byte[] stateBytes = JsonSerializer.SerializeToUtf8Bytes(state);
            if (stateBytes.Length > MaximumVc11VerifierStateBytes)
            {
                return false;
            }

            try
            {
                // Persist verifier-owned, protected replay state FIRST. An
                // interruption must never release a valid untracked request.
                using (var session = NewPrivateFile(parameters.SessionFile!))
                {
                    sessionCreated = true;
                    session.Write(stateBytes);
                    session.Flush(flushToDisk: true);
                }

                using (var destination = NewPrivateFile(parameters.RequestJwtFile!))
                {
                    requestCreated = true;
                    byte[] requestBytes = Encoding.ASCII.GetBytes(request + "\n");
                    try
                    {
                        destination.Write(requestBytes);
                        destination.Flush(flushToDisk: true);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(requestBytes);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(stateBytes);
            }

            completed = true;
            return true;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or
            FormatException or JsonException or InvalidOperationException or
            NotSupportedException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            if (!completed)
            {
                if (requestCreated)
                {
                    TryDeletePartialVerifierFile(parameters.RequestJwtFile!);
                }

                if (sessionCreated)
                {
                    TryDeletePartialVerifierFile(parameters.SessionFile!);
                }
            }
        }
    }

    internal static bool TryVerifyVc11VerifierPresentation(
        Vc11VerifierCheckParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        if (!ValidVerifierPolicy(parameters.VerifierDid, parameters.TenantId,
                parameters.Audience, parameters.TrustedIssuerDid,
                parameters.CredentialType, parameters.Context,
                out Guid tenantId, out Uri? context) ||
            string.IsNullOrWhiteSpace(parameters.RequestJwtFile) ||
            string.IsNullOrWhiteSpace(parameters.SessionFile) ||
            string.IsNullOrWhiteSpace(parameters.PresentationJwtFile))
        {
            return false;
        }

        try
        {
            if (File.Exists(parameters.SessionFile + ".used") ||
                !TryReadPrivateVerifierSession(parameters.SessionFile, out var state) ||
                state is null ||
                !TryReadOriginalCompactJwt(parameters.RequestJwtFile,
                    MaximumVerifierRequestBytes, out string originalRequest) ||
                !TryReadOriginalCompactJwt(parameters.PresentationJwtFile,
                    MaximumVpJwtBytes, out string originalPresentation) ||
                !OfflineSignedPresentationRequest.TryRead(originalRequest,
                    parameters.VerifierDid!, parameters.Audience!,
                    TimeProvider.System, out var signedChallenge) ||
                signedChallenge is null ||
                !MatchesVerifierState(state, parameters, tenantId,
                    signedChallenge, originalRequest))
            {
                return false;
            }

            // This store only reads a verifier-owned protected state file and
            // atomically RENAMES it to .used. Two local CLI processes cannot
            // both consume one state path on the same local filesystem.
            var challenges = new LocalFileVerifierChallengeStore(
                parameters.SessionFile!, state, signedChallenge);
            return JwtVcJsonPresentation.Check(originalPresentation, tenantId,
                parameters.Audience!, signedChallenge.Nonce,
                parameters.CredentialType!, context!, challenges,
                TimeProvider.System, out _) ==
                JwtVcJsonPresentationCheckResult.SignedButStatusUnchecked;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or
            FormatException or JsonException or InvalidOperationException or
            NotSupportedException)
        {
            return false;
        }
    }

    private static bool ValidVerifierPolicy(string? verifierDid, string? tenant,
        string? audience, string? issuerDid, string? type, string? vocabulary,
        out Guid tenantId, out Uri? context)
    {
        context = null;
        tenantId = Guid.Empty;
        return !string.IsNullOrWhiteSpace(verifierDid) &&
            verifierDid.StartsWith("did:key:", StringComparison.Ordinal) &&
            verifierDid.Length <= 2048 &&
            Guid.TryParseExact(tenant, "D", out tenantId) &&
            tenantId != Guid.Empty &&
            !string.IsNullOrWhiteSpace(audience) && audience.Length <= 2048 &&
            !string.IsNullOrWhiteSpace(issuerDid) &&
            issuerDid.StartsWith("did:key:", StringComparison.Ordinal) &&
            issuerDid.Length <= 2048 &&
            !string.IsNullOrWhiteSpace(type) &&
            type.Length <= 128 && !type.Any(char.IsWhiteSpace) &&
            TryCanonicalHttpsPin(vocabulary, out context) &&
            context is not null && context.Fragment.Length == 0;
    }

    private static bool MatchesVerifierState(Vc11VerifierSessionState state,
        Vc11VerifierCheckParameters pins, Guid tenantId,
        PresentationChallenge signedChallenge, string originalRequest) =>
        string.Equals(state.Version, Vc11VerifierStateVersion, StringComparison.Ordinal) &&
        string.Equals(state.VerifierDid, pins.VerifierDid, StringComparison.Ordinal) &&
        state.TenantId == tenantId &&
        string.Equals(state.Audience, pins.Audience, StringComparison.Ordinal) &&
        string.Equals(state.TrustedIssuerDid, pins.TrustedIssuerDid, StringComparison.Ordinal) &&
        string.Equals(state.CredentialType, pins.CredentialType, StringComparison.Ordinal) &&
        string.Equals(state.Context, pins.Context, StringComparison.Ordinal) &&
        string.Equals(state.Nonce, signedChallenge.Nonce, StringComparison.Ordinal) &&
        string.Equals(state.Audience, signedChallenge.Audience, StringComparison.Ordinal) &&
        string.Equals(state.TrustedIssuerDid, signedChallenge.TrustedIssuerDid, StringComparison.Ordinal) &&
        state.ExpiresAt == signedChallenge.ExpiresAt &&
        state.ExpiresAt > DateTimeOffset.UtcNow &&
        string.Equals(state.RequestSha256, Sha256Hex(originalRequest), StringComparison.Ordinal);

    private static string Sha256Hex(string text) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(text)));

    private static FileStream NewPrivateFile(string path)
    {
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

        return new FileStream(path, options);
    }

    private static bool TryReadPrivateVerifierSession(
        string path, out Vc11VerifierSessionState? state)
    {
        state = null;
        if (!OperatingSystem.IsWindows() &&
            (File.GetUnixFileMode(path) &
                (UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                 UnixFileMode.GroupExecute | UnixFileMode.OtherRead |
                 UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
        {
            return false;
        }

        byte[] buffer = new byte[MaximumVc11VerifierStateBytes + 1];
        try
        {
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.Read, 4096, FileOptions.SequentialScan);
            int length = 0;
            while (length < buffer.Length)
            {
                int count = file.Read(buffer, length, buffer.Length - length);
                if (count == 0)
                {
                    break;
                }

                length += count;
            }

            if (length == 0 || length > MaximumVc11VerifierStateBytes)
            {
                return false;
            }

            state = JsonSerializer.Deserialize<Vc11VerifierSessionState>(
                buffer.AsSpan(0, length));
            return state is not null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static void TryDeletePartialVerifierFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // A partial file is not a successful request. Fail closed.
        }
        catch (UnauthorizedAccessException)
        {
            // Operator must recover this failed partial file explicitly.
        }
    }

    /// <summary>
    /// Single-machine-only replay store. Atomic same-directory rename fails
    /// closed if any process has already consumed this verifier-owned nonce.
    /// Do not use NFS, a shared volume, backup restoration or untrusted
    /// directory writers as a substitute for a distributed challenge store.
    /// </summary>
    private sealed class LocalFileVerifierChallengeStore(
        string path, Vc11VerifierSessionState state, PresentationChallenge challenge)
        : IPresentationChallengeStore
    {
        public PresentationChallenge Issue(Guid verifierTenantId, string audience,
            string trustedIssuerDid, TimeSpan? lifetime = null) =>
            throw new NotSupportedException("Issuance belongs to the verifier request command.");

        public PresentationChallenge? Find(Guid verifierTenantId, string audience, string nonce)
        {
            if (File.Exists(path + ".used") || !File.Exists(path) ||
                !TryReadPrivateVerifierSession(path, out var current) ||
                current != state || challenge.ExpiresAt <= DateTimeOffset.UtcNow ||
                verifierTenantId != state.TenantId ||
                !string.Equals(audience, state.Audience, StringComparison.Ordinal) ||
                !string.Equals(nonce, state.Nonce, StringComparison.Ordinal))
            {
                return null;
            }

            return challenge;
        }

        public bool TryConsume(Guid verifierTenantId, string audience, string nonce)
        {
            if (Find(verifierTenantId, audience, nonce) is null)
            {
                return false;
            }

            try
            {
                File.Move(path, path + ".used");
                return true;
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    private static Command CreateVc11VerifierRequestCommand()
    {
        var verifier = Required("--verifier-did", "Verifier's own Ed25519 did:key");
        var tenant = Required("--tenant-id", "Verifier-owned non-empty GUID");
        var audience = Required("--audience", "Exact verifier audience");
        var issuer = Required("--trusted-issuer", "Verifier-approved Ed25519 issuer did:key");
        var type = Required("--credential-type", "Verifier-approved VC1.1 type");
        var context = Required("--context", "Verifier-approved HTTPS vocabulary");
        var request = Required("--output-request-file", "New signed verifier request JWT path");
        var session = Required("--session-file", "New local private challenge JSON path");
        var duration = Required("--lifetime-seconds", "Challenge lifetime in seconds (1 through 300)");
        var command = new Command("request-vc11-didkey",
            "Verifier signs one-use VC1.1 request and saves private offline challenge state");
        foreach (Option option in new Option[]
        {
            verifier, tenant, audience, issuer, type, context, request, session, duration
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            string? lifetimeText = invocation.ParseResult.GetValueForOption(duration);
            if (!int.TryParse(lifetimeText, System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out int seconds) ||
                !Console.IsInputRedirected ||
                !TryCreateVc11VerifierRequest(new Vc11VerifierRequestParameters(
                    invocation.ParseResult.GetValueForOption(verifier),
                    invocation.ParseResult.GetValueForOption(tenant),
                    invocation.ParseResult.GetValueForOption(audience),
                    invocation.ParseResult.GetValueForOption(issuer),
                    invocation.ParseResult.GetValueForOption(type),
                    invocation.ParseResult.GetValueForOption(context),
                    invocation.ParseResult.GetValueForOption(request),
                    invocation.ParseResult.GetValueForOption(session),
                    seconds), Console.OpenStandardInput()))
            {
                Console.Error.WriteLine(
                    "Verifier request rejected: independent pins, actual verifier key, lifetime or private output invalid. No request released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Verifier-signed VC1.1 request and private single-machine challenge saved. Verification requires genuine issuer and holder signatures and atomic one-use consumption.");
            invocation.ExitCode = 0;
        });
        return command;
    }

    private static Command CreateVc11VerifierCheckCommand()
    {
        var verifier = Required("--verifier-did", "Independently enrolled verifier DID");
        var tenant = Required("--tenant-id", "Verifier-owned non-empty GUID");
        var audience = Required("--audience", "Verifier-approved exact audience");
        var issuer = Required("--trusted-issuer", "Independently approved issuer DID");
        var type = Required("--credential-type", "Verifier-approved VC1.1 type");
        var context = Required("--context", "Verifier-approved HTTPS vocabulary");
        var request = Required("--request-jwt-file", "Original verifier-signed request JWT");
        var session = Required("--session-file", "Private verifier-owned unspent challenge JSON");
        var presentation = Required("--presentation-jwt-file", "Original holder-signed VP JWT");
        var command = new Command("verify-vc11-didkey-vp",
            "Verify genuine issuer + holder signatures and consume private single-machine challenge once");
        foreach (Option option in new Option[]
        {
            verifier, tenant, audience, issuer, type, context, request, session, presentation
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!TryVerifyVc11VerifierPresentation(new Vc11VerifierCheckParameters(
                invocation.ParseResult.GetValueForOption(verifier),
                invocation.ParseResult.GetValueForOption(tenant),
                invocation.ParseResult.GetValueForOption(audience),
                invocation.ParseResult.GetValueForOption(issuer),
                invocation.ParseResult.GetValueForOption(type),
                invocation.ParseResult.GetValueForOption(context),
                invocation.ParseResult.GetValueForOption(request),
                invocation.ParseResult.GetValueForOption(session),
                invocation.ParseResult.GetValueForOption(presentation))))
            {
                Console.Error.WriteLine(
                    "Holder VP rejected: issuer/holder signature, verifier-owned challenge, pins, validity, or replay invalid. No claims released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Original issuer signature, holder Ed25519 control and one-use verifier challenge verified. Status, consent, legal identity and business authority NOT checked. No claims released.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
