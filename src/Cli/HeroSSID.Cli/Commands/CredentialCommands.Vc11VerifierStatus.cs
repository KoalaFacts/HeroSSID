using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Credentials.CredentialRevocation;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// One-use locally stored verifier session plus independently supplied original
/// same-issuer signed VC1.1 status. Neither a hosted verifier nor live status.
/// </summary>
internal static partial class CredentialCommands
{
    internal static bool TryVerifyVc11VerifierPresentationWithStatus(
        Vc11VerifierCheckParameters parameters,
        string? snapshotFile, string? minimumObservedAt)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        if (!ValidVerifierPolicy(parameters.VerifierDid, parameters.TenantId,
                parameters.Audience, parameters.TrustedIssuerDid,
                parameters.CredentialType, parameters.Context,
                out Guid tenantId, out Uri? context) ||
            string.IsNullOrWhiteSpace(parameters.RequestJwtFile) ||
            string.IsNullOrWhiteSpace(parameters.SessionFile) ||
            string.IsNullOrWhiteSpace(parameters.PresentationJwtFile) ||
            string.IsNullOrWhiteSpace(snapshotFile) ||
            !DateTimeOffset.TryParseExact(minimumObservedAt, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out DateTimeOffset cutoff) ||
            cutoff.Offset != TimeSpan.Zero ||
            cutoff < DateTimeOffset.UnixEpoch ||
            cutoff > DateTimeOffset.UtcNow)
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
                !TryReadOriginalStatusJwt(new FileInfo(snapshotFile!),
                    out string originalSnapshot) ||
                !OfflineSignedPresentationRequest.TryRead(originalRequest,
                    parameters.VerifierDid!, parameters.Audience!,
                    TimeProvider.System, out var signedChallenge) ||
                signedChallenge is null ||
                !MatchesVerifierState(state, parameters, tenantId,
                    signedChallenge, originalRequest))
            {
                return false;
            }

            var challenges = new LocalFileVerifierChallengeStore(
                parameters.SessionFile!, state, signedChallenge);
            return JwtVcJsonRevocationSnapshot.CheckPresentationWithObservationCutoff(
                originalPresentation, originalSnapshot, tenantId,
                parameters.Audience!, signedChallenge.Nonce,
                parameters.CredentialType!, context!, challenges,
                TimeProvider.System, cutoff, out _) ==
                RevocationSnapshotCheckResult.NotListed;
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

    private static Command CreateVc11VerifierStatusCheckCommand()
    {
        var verifier = Required("--verifier-did", "Independently enrolled verifier DID");
        var tenant = Required("--tenant-id", "Verifier-owned non-empty GUID");
        var audience = Required("--audience", "Verifier-approved exact audience");
        var issuer = Required("--trusted-issuer", "Independently approved issuer did:key");
        var type = Required("--credential-type", "Verifier-approved VC1.1 type");
        var context = Required("--context", "Verifier-approved HTTPS vocabulary");
        var request = Required("--request-jwt-file", "Original verifier-signed request JWT");
        var session = Required("--session-file", "Private verifier-owned unspent challenge");
        var presentation = Required("--presentation-jwt-file", "Original holder-signed VC1.1 VP");
        var snapshot = Required("--snapshot-file", "Separate original issuer-signed private status");
        var cutoff = Required("--minimum-observed-at",
            "Verifier-owned UTC earliest accepted status observation");
        var command = new Command("verify-vc11-didkey-vp-status",
            "One-use genuine issuer/holder VC1.1 VP and issuer status verification");
        foreach (Option option in new Option[]
        {
            verifier, tenant, audience, issuer, type, context, request,
            session, presentation, snapshot, cutoff
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!TryVerifyVc11VerifierPresentationWithStatus(
                new Vc11VerifierCheckParameters(
                    invocation.ParseResult.GetValueForOption(verifier),
                    invocation.ParseResult.GetValueForOption(tenant),
                    invocation.ParseResult.GetValueForOption(audience),
                    invocation.ParseResult.GetValueForOption(issuer),
                    invocation.ParseResult.GetValueForOption(type),
                    invocation.ParseResult.GetValueForOption(context),
                    invocation.ParseResult.GetValueForOption(request),
                    invocation.ParseResult.GetValueForOption(session),
                    invocation.ParseResult.GetValueForOption(presentation)),
                invocation.ParseResult.GetValueForOption(snapshot),
                invocation.ParseResult.GetValueForOption(cutoff)))
            {
                Console.Error.WriteLine(
                    "VC1.1 VP/status rejected: issuer, holder, verifier challenge, one-use state, signed status or observation policy failed. No claims released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Issuer signature, holder Ed25519 control, one-use challenge and same-issuer private status SignedNotListed verified. No claims released. NOT live non-revocation, consent, identity or business authorization.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
