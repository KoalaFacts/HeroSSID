using System.CommandLine;
using System.CommandLine.Invocation;
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Holder-operated full-disclosure VC1.1 JWT VP from an authenticated verifier
/// request. Only the holder signs; issuer provenance and independent verifier
/// pins must be checked before disclosure.
/// </summary>
internal static partial class CredentialCommands
{
    private const int MaximumVerifierRequestBytes = 16_384;
    private const int MaximumVpJwtBytes = 131_072;

    internal sealed record Vc11HolderPresentationParameters(
        string? RequestJwtFile, string? CredentialJwtFile,
        string? TrustedVerifierDid, string? Audience,
        string? TrustedIssuerDid, string? IssuerName, string? CredentialId,
        string? HolderDid, string? CredentialType, string? Context,
        string? OutputJwtFile, bool FullDisclosureAcknowledged);

    internal static bool TryPresentVc11DidKey(
        Vc11HolderPresentationParameters parameters, Stream holderSeedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(holderSeedInput);

        // A flag does not prove actual consent: the invoking application must
        // have displayed the COMPLETE original credential to the holder and
        // obtained informed approval before setting it.
        if (!parameters.FullDisclosureAcknowledged ||
            string.IsNullOrWhiteSpace(parameters.RequestJwtFile) ||
            string.IsNullOrWhiteSpace(parameters.CredentialJwtFile) ||
            string.IsNullOrWhiteSpace(parameters.TrustedVerifierDid) ||
            !parameters.TrustedVerifierDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(parameters.Audience) ||
            parameters.Audience.Length > 2048 ||
            string.IsNullOrWhiteSpace(parameters.TrustedIssuerDid) ||
            !parameters.TrustedIssuerDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(parameters.IssuerName) ||
            string.IsNullOrWhiteSpace(parameters.HolderDid) ||
            !parameters.HolderDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(parameters.CredentialType) ||
            string.IsNullOrWhiteSpace(parameters.OutputJwtFile) ||
            !TryCanonicalHttpsPin(parameters.CredentialId, out Uri? credentialId) ||
            !TryCanonicalHttpsPin(parameters.Context, out Uri? context) ||
            context!.Fragment.Length != 0)
        {
            return false;
        }

        byte[] seed = [];
        bool outputCreated = false;
        bool outputCompleted = false;
        try
        {
            if (File.Exists(parameters.OutputJwtFile) ||
                !TryReadOriginalCompactJwt(parameters.RequestJwtFile,
                    MaximumVerifierRequestBytes, out string signedRequest) ||
                !TryReadOriginalCompactJwt(parameters.CredentialJwtFile,
                    MaximumCredentialFileBytes, out string originalCredential))
            {
                return false;
            }

            // Authenticate the verifier's ORIGINAL request with an independently
            // enrolled DID and audience before trusting its issuer policy.
            if (!OfflineSignedPresentationRequest.TryRead(
                    signedRequest, parameters.TrustedVerifierDid,
                    parameters.Audience, TimeProvider.System, out var challenge) ||
                challenge is null ||
                !string.Equals(challenge.TrustedIssuerDid,
                    parameters.TrustedIssuerDid, StringComparison.Ordinal))
            {
                return false;
            }

            // A verifier's request alone cannot enroll an issuer. Verify the
            // genuine ORIGINAL VC1.1 JWT with separate issuer, signed name,
            // signed credential ID, holder, type, context and validity pins.
            if (!JwtVcJsonCredential.TryVerifyWithPinnedIssuerNameAndId(
                    originalCredential, parameters.TrustedIssuerDid,
                    parameters.IssuerName, parameters.HolderDid,
                    parameters.CredentialType, context, credentialId!,
                    DateTimeOffset.UtcNow, out _) ||
                !TryReadIssuerSeed(holderSeedInput, out seed))
            {
                return false;
            }

            // The existing SDK verifies request and issuer a second time,
            // signs a nested vp+jwt with the actual holder's Ed25519 key and
            // rejects a seed that does not control the pinned holder DID.
            string signedPresentation = JwtVcJsonPresentation.Create(
                signedRequest, parameters.TrustedVerifierDid,
                parameters.Audience, originalCredential,
                parameters.CredentialType, context,
                parameters.HolderDid, seed, TimeProvider.System);
            if (signedPresentation.Length == 0 ||
                signedPresentation.Length > MaximumVpJwtBytes)
            {
                return false;
            }

            // Full-disclosure VP contains the credential; create-new and owner
            // permissions prevent accidental overwrite or world-readable output.
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

            using (var output = new FileStream(parameters.OutputJwtFile, options))
            {
                outputCreated = true;
                byte[] encoded = Encoding.ASCII.GetBytes(signedPresentation + "\n");
                try
                {
                    output.Write(encoded);
                    output.Flush(flushToDisk: true);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(encoded);
                }
            }

            outputCompleted = true;
            return true;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or
            FormatException or InvalidOperationException or NotSupportedException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            if (outputCreated && !outputCompleted)
            {
                try
                {
                    File.Delete(parameters.OutputJwtFile!);
                }
                catch (IOException)
                {
                    // Partial output is never reported as a valid presentation.
                }
                catch (UnauthorizedAccessException)
                {
                    // Caller must remove any partial output before retrying.
                }
            }
        }
    }

    private static bool TryReadOriginalCompactJwt(
        string path, int maximumBytes, out string originalJwt)
    {
        originalJwt = string.Empty;
        byte[] bytes = new byte[maximumBytes + 3];
        try
        {
            using var input = new FileStream(path, FileMode.Open,
                FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
            int count = 0;
            while (count < bytes.Length)
            {
                int next = input.Read(bytes, count, bytes.Length - count);
                if (next == 0)
                {
                    break;
                }

                count += next;
            }

            if (count < 1 || count > maximumBytes + 2)
            {
                return false;
            }

            string original = new UTF8Encoding(false, true).GetString(bytes, 0, count);
            if (original.EndsWith("\r\n", StringComparison.Ordinal))
            {
                original = original[..^2];
            }
            else if (original.EndsWith('\n'))
            {
                original = original[..^1];
            }

            if (original.Length == 0 || original.Length > maximumBytes ||
                original.Any(char.IsWhiteSpace))
            {
                return false;
            }

            originalJwt = original;
            return true;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static Command CreateVc11HolderPresentationCommand()
    {
        var request = Required("--request-jwt-file", "Original signed verifier request file");
        var credential = Required("--credential-jwt-file", "Original unchanged VC1.1 JWT");
        var verifier = Required("--trusted-verifier", "Separately pinned verifier did:key");
        var audience = Required("--audience", "Separately approved verifier audience");
        var issuer = Required("--trusted-issuer", "Separately pinned VC1.1 issuer did:key");
        var issuerName = Required("--issuer-name", "Exact approved issuer-signed name");
        var credentialId = Required("--credential-id", "Exact approved issuer-signed HTTPS jti");
        var holder = Required("--holder", "DID controlled by the holder's own seed");
        var type = Required("--credential-type", "Independently approved VC type");
        var context = Required("--context", "Independently approved HTTPS vocabulary");
        var output = Required("--output-jwt-file", "New full-disclosure VP file, never overwritten");
        var acknowledge = new Option<bool>("--ack-full-disclosure",
            "Holder application attests it displayed ALL credential claims and obtained approval; not consent evidence");
        var command = new Command("present-vc11-didkey",
            "Authenticate a signed request and original VC1.1 JWT, then sign full-disclosure VP with holder seed from stdin");

        foreach (Option option in new Option[]
        {
            request, credential, verifier, audience, issuer, issuerName,
            credentialId, holder, type, context, output, acknowledge
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            var policy = new Vc11HolderPresentationParameters(
                invocation.ParseResult.GetValueForOption(request),
                invocation.ParseResult.GetValueForOption(credential),
                invocation.ParseResult.GetValueForOption(verifier),
                invocation.ParseResult.GetValueForOption(audience),
                invocation.ParseResult.GetValueForOption(issuer),
                invocation.ParseResult.GetValueForOption(issuerName),
                invocation.ParseResult.GetValueForOption(credentialId),
                invocation.ParseResult.GetValueForOption(holder),
                invocation.ParseResult.GetValueForOption(type),
                invocation.ParseResult.GetValueForOption(context),
                invocation.ParseResult.GetValueForOption(output),
                invocation.ParseResult.GetValueForOption(acknowledge));

            if (!Console.IsInputRedirected ||
                !TryPresentVc11DidKey(policy, Console.OpenStandardInput()))
            {
                Console.Error.WriteLine(
                    "Holder VC1.1 VP rejected: signed request, independent issuer/verifier pins, actual holder seed, complete-disclosure acknowledgement or output invalid. No VP released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Holder-signed VC1.1 full-disclosure VP saved. Verifier must atomically consume its own challenge. Consent, status, legal identity and business authorization NOT independently established.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
