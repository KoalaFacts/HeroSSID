using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// A no-SDK verifier authenticates one unchanged direct VC2 credential and
/// a separately obtained short-lived status statement signed by the SAME
/// independently trusted issuer. No holder key proof or live revocation.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2DidKeyStatusVerifyParameters(
        string? JwtFile, string? SnapshotFile, string? TrustedIssuer,
        string? HolderDid, string? CredentialType, string? Context,
        string? MinimumObservedAt);

    internal static bool TryVerifyVc2DidKeyStatus(
        Vc2DidKeyStatusVerifyParameters parameters, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        // The relying party supplies ALL policy pins independently. A
        // credential, issuer-signed status JWT or holder cannot enroll trust.
        if (string.IsNullOrWhiteSpace(parameters.JwtFile) ||
            string.IsNullOrWhiteSpace(parameters.SnapshotFile) ||
            parameters.TrustedIssuer is not { Length: > 0 and <= 2048 } issuer ||
            !issuer.StartsWith("did:key:", StringComparison.Ordinal) ||
            parameters.HolderDid is not { Length: > 0 and <= 2048 } holder ||
            !holder.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(parameters.CredentialType) ||
            !TryCanonicalHttpsPin(parameters.Context, out Uri? vocabulary) ||
            vocabulary!.Fragment.Length != 0 ||
            !DateTimeOffset.TryParseExact(parameters.MinimumObservedAt, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out DateTimeOffset cutoff) ||
            now.Offset != TimeSpan.Zero ||
            cutoff.Offset != TimeSpan.Zero ||
            cutoff < DateTimeOffset.UnixEpoch ||
            cutoff > now)
        {
            return false;
        }

        try
        {
            // Keep the exact original bytes represented by each JWT and use
            // the SAME credential string for both signature/pin verification
            // and the issuer's exact-original-JWT digest status. Never reopen
            // the credential file between those two checks (TOCTOU).
            if (!TryReadOriginalStatusJwt(new FileInfo(parameters.JwtFile),
                    out string credential) ||
                !TryReadOriginalStatusJwt(new FileInfo(parameters.SnapshotFile),
                    out string snapshot) ||
                !Vcdm20JoseCredential.TryVerify(credential, issuer, holder,
                    parameters.CredentialType!, vocabulary, now, out _))
            {
                return false;
            }

            return Vcdm20RevocationSnapshot.CheckWithObservationCutoff(
                snapshot, credential, issuer, now, cutoff) ==
                Vcdm20RevocationCheckResult.SignedNotListed;
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or JsonException or
            FormatException or InvalidOperationException or NotSupportedException)
        {
            return false;
        }
    }

    private static Command CreateVc2DidKeyStatusVerifyCommand()
    {
        var jwt = Required("--jwt-file", "Unchanged original issuer-signed direct VC2 vc+jwt");
        var snapshot = Required("--snapshot-file",
            "Original separately obtained same-issuer HeroSSID private signed status JWT");
        var issuer = Required("--trusted-issuer",
            "Verifier-enrolled issuer Ed25519 did:key, NEVER from untrusted JWT");
        var holder = Required("--holder",
            "Exact expected VC2 subject DID; NOT proof holder controls its key");
        var type = Required("--credential-type",
            "Exact verifier-approved credential type");
        var context = Required("--context",
            "Independently approved canonical HTTPS subject vocabulary");
        var cutoff = Required("--minimum-observed-at",
            "Verifier-owned earliest acceptable signed issuer status observation, UTC O format");
        var command = new Command("verify-vc2-didkey-status",
            "Offline genuine issuer signature, independent VC2 pins and same-issuer private status");
        foreach (Option option in new Option[]
        {
            jwt, snapshot, issuer, holder, type, context, cutoff
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!TryVerifyVc2DidKeyStatus(new Vc2DidKeyStatusVerifyParameters(
                invocation.ParseResult.GetValueForOption(jwt),
                invocation.ParseResult.GetValueForOption(snapshot),
                invocation.ParseResult.GetValueForOption(issuer),
                invocation.ParseResult.GetValueForOption(holder),
                invocation.ParseResult.GetValueForOption(type),
                invocation.ParseResult.GetValueForOption(context),
                invocation.ParseResult.GetValueForOption(cutoff)),
                DateTimeOffset.UtcNow))
            {
                Console.Error.WriteLine(
                    "Direct VC2 issuer/status rejected: original JWT, independent pins, signature, revocation or observation invalid. No claims released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Original issuer signature, verifier-pinned VC2 fields and same-issuer private status verified: SignedNotListed. No claims released. " +
                "NOT complete/live non-revocation, holder key control, consent, legal identity, Agent authority or business authorization.");
            invocation.ExitCode = 0;
        });

        return command;
    }
}
