using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Single-machine verifier-owned direct VC2 did:key request and presentation
/// session. The original issuer statement and separate holder signature are
/// checked under verifier-owned policy and a durable one-use challenge.
/// No live status, identity enrollment, consent or authorization is implied.
/// </summary>
internal static partial class CredentialCommands
{
    internal static bool TryCreateVc2DidKeyVerifierRequest(
        Vc11VerifierRequestParameters parameters, Stream verifierSeedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(verifierSeedInput);

        // A holder must never get to choose the issuer, vocabulary or
        // recipient under which a verifier considers the request authentic.
        // Reuse the proven protected local challenge and signed policy-bound
        // request, not the legacy unbound VC1.1 request form.
        return TryCanonicalHttpsPin(parameters.Audience, out Uri? audience) &&
            string.Equals(parameters.Audience, audience!.AbsoluteUri,
                StringComparison.Ordinal) &&
            ValidVerifierPolicy(parameters.VerifierDid, parameters.TenantId,
                parameters.Audience, parameters.TrustedIssuerDid,
                parameters.CredentialType, parameters.Context, out _, out _) &&
            TryCreateVc11VerifierRequest(parameters, verifierSeedInput,
                policyBound: true);
    }

    internal static bool TryVerifyVc2DidKeyVerifierPresentation(
        Vc11VerifierCheckParameters parameters)
    {
        ArgumentNullException.ThrowIfNull(parameters);

        if (!TryCanonicalHttpsPin(parameters.Audience, out Uri? audience) ||
            !string.Equals(parameters.Audience, audience!.AbsoluteUri,
                StringComparison.Ordinal) ||
            !ValidVerifierPolicy(parameters.VerifierDid, parameters.TenantId,
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
                !OfflineSignedPresentationRequest.TryReadPolicyBound(
                    originalRequest, parameters.VerifierDid!, audience.AbsoluteUri,
                    parameters.CredentialType!, context!, TimeProvider.System,
                    out var challenge) ||
                challenge is null ||
                !MatchesVerifierState(state, parameters, tenantId,
                    challenge, originalRequest))
            {
                return false;
            }

            // The original request digest and nonce come from the verifier's
            // private state, not the incoming holder VP or any issuer claim.
            // The reusable SDK authenticates original issuer and holder
            // Ed25519 signatures, request hash, type/context and expires,
            // then atomically spends exactly one local challenge.
            var store = new LocalFileVerifierChallengeStore(
                parameters.SessionFile!, state, challenge);
            return Vcdm20JosePresentation.CheckWithHolderBoundSignedVerifierRequest(
                originalPresentation, originalRequest, state.RequestSha256,
                parameters.VerifierDid!, tenantId, audience.AbsoluteUri,
                challenge.Nonce, parameters.CredentialType!, context!, store,
                TimeProvider.System, out _) ==
                Vcdm20PresentationCheckResult.SignedButStatusUnchecked;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or FormatException or
            JsonException or InvalidOperationException or NotSupportedException)
        {
            return false;
        }
    }

    private static Command CreateVc2DidKeyVerifierRequestCommand()
    {
        var verifier = Required("--verifier-did", "Verifier-owned genuine Ed25519 did:key");
        var tenant = Required("--tenant-id", "Verifier-owned nonempty tenant GUID");
        var audience = Required("--audience", "Verifier-approved canonical HTTPS recipient");
        var issuer = Required("--trusted-issuer", "Independently approved issuer did:key");
        var type = Required("--credential-type", "Verifier-approved exact direct VC2 type");
        var context = Required("--context", "Verifier-approved HTTPS subject vocabulary");
        var output = Required("--output-request-file", "Create-new genuine verifier request JWT");
        var session = Required("--session-file", "Create-new private single-machine challenge state");
        var lifetime = Required("--lifetime-seconds", "Request lifetime 1 through 300 seconds");
        var command = new Command("request-vc2-didkey",
            "Sign a policy-bound direct VC2 verifier request and retain protected one-use state");
        foreach (Option option in new Option[]
        {
            verifier, tenant, audience, issuer, type, context, output, session, lifetime
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            string? duration = invocation.ParseResult.GetValueForOption(lifetime);
            if (!int.TryParse(duration, NumberStyles.None,
                    CultureInfo.InvariantCulture, out int seconds) ||
                !Console.IsInputRedirected ||
                !TryCreateVc2DidKeyVerifierRequest(
                    new Vc11VerifierRequestParameters(
                        invocation.ParseResult.GetValueForOption(verifier),
                        invocation.ParseResult.GetValueForOption(tenant),
                        invocation.ParseResult.GetValueForOption(audience),
                        invocation.ParseResult.GetValueForOption(issuer),
                        invocation.ParseResult.GetValueForOption(type),
                        invocation.ParseResult.GetValueForOption(context),
                        invocation.ParseResult.GetValueForOption(output),
                        invocation.ParseResult.GetValueForOption(session), seconds),
                    Console.OpenStandardInput()))
            {
                Console.Error.WriteLine(
                    "Direct VC2 verifier request rejected: key, independent policy, lifetime or private output invalid. No request released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Genuine verifier-signed direct VC2 policy request and private single-machine challenge saved. No holder consent or business authority established.");
            invocation.ExitCode = 0;
        });
        return command;
    }

    private static Command CreateVc2DidKeyVerifierCheckCommand()
    {
        var verifier = Required("--verifier-did", "Verifier-owned pinned did:key");
        var tenant = Required("--tenant-id", "Verifier-owned nonempty tenant GUID");
        var audience = Required("--audience", "Exact canonical HTTPS verifier recipient");
        var issuer = Required("--trusted-issuer", "Independently approved issuer did:key");
        var type = Required("--credential-type", "Independently approved direct VC2 type");
        var context = Required("--context", "Independently approved HTTPS subject vocabulary");
        var request = Required("--request-jwt-file", "Exact original signed verifier request JWT");
        var session = Required("--session-file", "Private unspent single-machine verifier state");
        var presentation = Required("--presentation-jwt-file", "Exact original holder-signed VC2 VP");
        var command = new Command("verify-vc2-didkey-vp",
            "Check real issuer and holder signatures and atomically consume one offline verifier challenge");
        foreach (Option option in new Option[]
        {
            verifier, tenant, audience, issuer, type, context,
            request, session, presentation
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!TryVerifyVc2DidKeyVerifierPresentation(
                new Vc11VerifierCheckParameters(
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
                    "Direct VC2 VP rejected: issuer/holder signature, exact verifier request, independent policy or one-use challenge failed. No claims released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Genuine issuer credential, independent holder Ed25519 proof, original verifier request and one-use challenge verified. No claims released. Status UNCHECKED; no consent, identity or business authority.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
