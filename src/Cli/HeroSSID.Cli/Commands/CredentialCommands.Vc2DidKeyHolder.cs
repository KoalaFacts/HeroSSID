using System.CommandLine;
using System.CommandLine.Invocation;
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Holder-operated, offline direct VC2 did:key presentation entry point.
/// The wallet keeps and presents the original issuer statement; it cannot
/// change who signed it or grant the receiving application's authority.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2DidKeyHolderParameters(
        string? RequestJwtFile, string? CredentialJwtFile,
        string? TrustedVerifierDid, string? Audience,
        string? TrustedIssuerDid, string? HolderDid,
        string? CredentialType, string? Context,
        string? OutputJwtFile, bool FullDisclosureAcknowledged);

    internal static bool TryPresentVc2DidKey(
        Vc2DidKeyHolderParameters parameters, Stream holderSeedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(holderSeedInput);

        // The invoking holder UI must first display ALL signed claims and
        // independently approve issuer, verifier and audience. This flag is
        // only the caller's assertion, not verified human consent evidence.
        if (!parameters.FullDisclosureAcknowledged ||
            string.IsNullOrWhiteSpace(parameters.RequestJwtFile) ||
            string.IsNullOrWhiteSpace(parameters.CredentialJwtFile) ||
            string.IsNullOrWhiteSpace(parameters.OutputJwtFile) ||
            parameters.TrustedVerifierDid is not { Length: > 0 and <= 2048 } verifierDid ||
            !verifierDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            parameters.TrustedIssuerDid is not { Length: > 0 and <= 2048 } issuerDid ||
            !issuerDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            parameters.HolderDid is not { Length: > 0 and <= 2048 } holderDid ||
            !holderDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            parameters.CredentialType is not { Length: > 0 and <= 128 } type ||
            !TryCanonicalHttpsPin(parameters.Audience, out Uri? audience) ||
            !string.Equals(parameters.Audience, audience!.AbsoluteUri, StringComparison.Ordinal) ||
            !TryCanonicalHttpsPin(parameters.Context, out Uri? context) ||
            context!.Fragment.Length != 0)
        {
            return false;
        }

        byte[] seed = [];
        bool created = false;
        bool completed = false;
        try
        {
            if (File.Exists(parameters.OutputJwtFile) ||
                !TryReadOriginalCompactJwt(parameters.RequestJwtFile,
                    MaximumVerifierRequestBytes, out string originalRequest) ||
                !TryReadOriginalCompactJwt(parameters.CredentialJwtFile,
                    MaximumCredentialFileBytes, out string originalCredential))
            {
                return false;
            }

            // A valid verifier JWS cannot itself enroll its preferred issuer.
            // Check the independently configured issuer before touching seed.
            if (!OfflineSignedPresentationRequest.TryReadPolicyBound(
                    originalRequest, verifierDid, audience!.AbsoluteUri,
                    type, context!, TimeProvider.System, out var challenge) ||
                challenge is null ||
                !string.Equals(challenge.TrustedIssuerDid, issuerDid,
                    StringComparison.Ordinal) ||
                !Vcdm20JoseCredential.TryVerify(
                    originalCredential, issuerDid, holderDid, type, context!,
                    DateTimeOffset.UtcNow, out _) ||
                !TryReadIssuerSeed(holderSeedInput, out seed))
            {
                return false;
            }

            // The SDK checks the genuine original issuer signature again,
            // proves the holder seed controls its own pinned did:key, and signs
            // a SHA-256 of the EXACT verifier JWS into the full-disclosure VP.
            string presentation = Vcdm20JosePresentation.CreateWithSignedRequestBinding(
                originalRequest, verifierDid, audience.AbsoluteUri,
                originalCredential, type, context!, holderDid,
                seed, TimeProvider.System);
            if (presentation.Length == 0 || presentation.Length > MaximumVpJwtBytes)
            {
                return false;
            }

            // Never overwrite any caller's file and never print credential
            // claims or the private seed. On Unix only the owner may read.
            using (var destination = NewPrivateFile(parameters.OutputJwtFile!))
            {
                created = true;
                byte[] bytes = Encoding.ASCII.GetBytes(presentation + "\n");
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
        catch (Exception error) when (
            error is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or FormatException or
            InvalidOperationException or NotSupportedException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            if (created && !completed)
            {
                TryDeletePartialVerifierFile(parameters.OutputJwtFile!);
            }
        }
    }

    private static Command CreateVc2DidKeyHolderCommand()
    {
        var request = Required("--request-jwt-file", "Unchanged verifier-signed policy-bound request JWT");
        var credential = Required("--credential-jwt-file", "Unchanged issuer-signed direct VC2 vc+jwt");
        var verifier = Required("--trusted-verifier", "Independently pinned verifier Ed25519 did:key");
        var audience = Required("--audience", "Independently approved canonical HTTPS verifier recipient");
        var issuer = Required("--trusted-issuer", "Independently pinned issuer Ed25519 did:key");
        var holder = Required("--holder", "Holder did:key controlled by the stdin seed");
        var type = Required("--credential-type", "Exact independently approved VC2 type");
        var context = Required("--context", "Exact approved HTTPS subject vocabulary");
        var output = Required("--output-jwt-file", "Private create-new holder-signed full-disclosure VP JWT");
        var approval = new Option<bool>("--ack-full-disclosure",
            "Caller displayed ALL signed claims and secured disclosure approval; not consent evidence");
        var command = new Command("present-vc2-didkey",
            "Holder signs a genuine request-bound full-disclosure direct VC2 VP with its own Ed25519 seed from redirected stdin");
        foreach (Option option in new Option[]
        {
            request, credential, verifier, audience, issuer, holder,
            type, context, output, approval
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!Console.IsInputRedirected ||
                !TryPresentVc2DidKey(
                    new Vc2DidKeyHolderParameters(
                        invocation.ParseResult.GetValueForOption(request),
                        invocation.ParseResult.GetValueForOption(credential),
                        invocation.ParseResult.GetValueForOption(verifier),
                        invocation.ParseResult.GetValueForOption(audience),
                        invocation.ParseResult.GetValueForOption(issuer),
                        invocation.ParseResult.GetValueForOption(holder),
                        invocation.ParseResult.GetValueForOption(type),
                        invocation.ParseResult.GetValueForOption(context),
                        invocation.ParseResult.GetValueForOption(output),
                        invocation.ParseResult.GetValueForOption(approval)),
                    Console.OpenStandardInput()))
            {
                Console.Error.WriteLine(
                    "Direct VC2 holder presentation rejected: issuer/verifier signature, pinned policy, private holder seed, acknowledgement or protected output invalid. No VP released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Genuine holder-Ed25519 full-disclosure VC2 VP saved. Verifier must independently verify its original request and atomically consume its challenge. No status, consent, identity or authority proof.");
            invocation.ExitCode = 0;
        });

        return command;
    }
}
