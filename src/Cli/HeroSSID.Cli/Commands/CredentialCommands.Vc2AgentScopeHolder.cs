using System.CommandLine;
using System.CommandLine.Invocation;
using System.Security.Cryptography;
using System.Text;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Holder-operated VC2 Agent scope full-disclosure proof. The Agent holds and
/// presents the original issuer-signed JWT; only its own Ed25519 key signs the
/// VP. Neither signature is legal identity or business authorization.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2AgentScopeHolderParameters(
        string? RequestJwtFile, string? CredentialJwtFile,
        string? TrustedVerifierDid, string? Audience, string? TrustedIssuerDid,
        string? AgentDid, string? Context, string? CredentialId,
        string? Resource, string? Action, string? OutputJwtFile,
        bool FullDisclosureAcknowledged);

    internal static bool TryPresentVc2AgentScope(
        Vc2AgentScopeHolderParameters parameters, Stream agentSeedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(agentSeedInput);

        // The caller, not the request or JWT, independently pins every policy
        // dimension and must have shown the complete original credential to
        // the Agent operator. This flag is NOT proof of human informed consent.
        if (!parameters.FullDisclosureAcknowledged ||
            string.IsNullOrWhiteSpace(parameters.RequestJwtFile) ||
            string.IsNullOrWhiteSpace(parameters.CredentialJwtFile) ||
            string.IsNullOrWhiteSpace(parameters.OutputJwtFile) ||
            parameters.TrustedVerifierDid is not { Length: > 0 and <= 2048 } verifierDid ||
            !verifierDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            parameters.TrustedIssuerDid is not { Length: > 0 and <= 2048 } issuerDid ||
            !issuerDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            parameters.AgentDid is not { Length: > 0 and <= 2048 } agentDid ||
            !agentDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            !TryCanonicalHttpsPin(parameters.Audience, out Uri? audience) ||
            !TryCanonicalHttpsPin(parameters.Context, out Uri? context) ||
            !TryCanonicalHttpsPin(parameters.CredentialId, out Uri? credentialId) ||
            !TryCanonicalHttpsPin(parameters.Resource, out Uri? resource) ||
            !string.IsNullOrEmpty(resource!.Query) ||
            parameters.Action is not { Length: > 0 and <= 64 } action)
        {
            return false;
        }

        byte[] seed = [];
        bool outputCreated = false;
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

            // Authenticate the exact verifier-signed *policy-bound* request
            // against a separately configured verifier DID, audience, type,
            // vocabulary and issuer. The requester cannot enroll its issuer.
            if (!OfflineSignedPresentationRequest.TryReadPolicyBound(
                    originalRequest, verifierDid, audience!.AbsoluteUri,
                    Vcdm20AgentScopeAssertion.CredentialType, context!,
                    TimeProvider.System, out var challenge) ||
                challenge is null ||
                !string.Equals(challenge.TrustedIssuerDid, issuerDid,
                    StringComparison.Ordinal))
            {
                return false;
            }

            // Authentic issuer provenance is separately required before
            // reading the Agent's seed or producing any full-disclosure VP.
            // Exact action, resource, agent DID, signed recipient/ID and
            // <=15-minute signed validity are never copied from the JWT.
            if (!Vcdm20AgentScopeAssertion.TryVerify(
                    originalCredential, issuerDid, agentDid, context!,
                    credentialId!, audience!, resource, action,
                    DateTimeOffset.UtcNow, out _) ||
                !TryReadIssuerSeed(agentSeedInput, out seed))
            {
                return false;
            }

            // The SDK reauthenticates both JWSs, proves the Agent's distinct
            // seed matches the signed holder DID and signs the SHA-256 of the
            // exact original verifier request into the full-disclosure VP.
            string presentation = Vcdm20JosePresentation.CreateForAudienceWithIdAndSignedRequest(
                originalRequest, verifierDid, audience!.AbsoluteUri,
                originalCredential, Vcdm20AgentScopeAssertion.CredentialType,
                context!, credentialId!, audience, agentDid, seed,
                TimeProvider.System);
            if (presentation.Length == 0 || presentation.Length > MaximumVpJwtBytes)
            {
                return false;
            }

            // A new owner-private output is the only result. Never overwrite
            // an existing artifact or print the signed disclosed claims.
            using (var destination = NewPrivateFile(parameters.OutputJwtFile!))
            {
                outputCreated = true;
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
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or FormatException or
            InvalidOperationException or NotSupportedException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            if (outputCreated && !completed)
            {
                TryDeletePartialVerifierFile(parameters.OutputJwtFile!);
            }
        }
    }

    private static Command CreateVc2AgentScopeHolderCommand()
    {
        var request = Required("--request-jwt-file", "Original verifier-signed policy-bound VC2 request");
        var credential = Required("--credential-jwt-file", "Original issuer-signed VC2 Agent scope JWT");
        var verifier = Required("--trusted-verifier", "Independently approved Ed25519 verifier did:key");
        var audience = Required("--audience", "Independently approved canonical HTTPS verifier recipient");
        var issuer = Required("--trusted-issuer", "Independently approved issuer did:key");
        var agent = Required("--agent", "Agent did:key controlled by the redirected holder seed");
        var context = Required("--context", "Independently approved versioned HTTPS Agent scope vocabulary");
        var id = Required("--credential-id", "Exact approved issuer-signed HTTPS credential ID");
        var resource = Required("--resource", "Exact issuer-signed HTTPS resource, no query or fragment");
        var action = Required("--action", "Exact approved literal Agent scope action");
        var output = Required("--output-jwt-file", "New private full-disclosure Agent VP, never overwritten");
        var acknowledgement = new Option<bool>("--ack-full-disclosure",
            "Caller displayed ALL signed credential claims and obtained approval; not independent consent evidence");
        var command = new Command("present-vc2-agent-scope",
            "Agent signs one verifier-request-bound full-disclosure VC2 VP with its OWN Ed25519 seed from stdin");
        foreach (Option option in new Option[]
        {
            request, credential, verifier, audience, issuer, agent, context, id,
            resource, action, output, acknowledgement
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!Console.IsInputRedirected ||
                !TryPresentVc2AgentScope(
                    new Vc2AgentScopeHolderParameters(
                        invocation.ParseResult.GetValueForOption(request),
                        invocation.ParseResult.GetValueForOption(credential),
                        invocation.ParseResult.GetValueForOption(verifier),
                        invocation.ParseResult.GetValueForOption(audience),
                        invocation.ParseResult.GetValueForOption(issuer),
                        invocation.ParseResult.GetValueForOption(agent),
                        invocation.ParseResult.GetValueForOption(context),
                        invocation.ParseResult.GetValueForOption(id),
                        invocation.ParseResult.GetValueForOption(resource),
                        invocation.ParseResult.GetValueForOption(action),
                        invocation.ParseResult.GetValueForOption(output),
                        invocation.ParseResult.GetValueForOption(acknowledgement)),
                    Console.OpenStandardInput()))
            {
                Console.Error.WriteLine(
                    "Agent holder presentation rejected: signed verifier/issuer, independent scope pins, Agent seed, disclosure acknowledgement or private output invalid. No VP released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Agent-signed full-disclosure VC2 VP saved. Verifier must independently validate and consume its own challenge and signed status. No consent proof, legal identity or business authorization established.");
            invocation.ExitCode = 0;
        });

        return command;
    }
}
