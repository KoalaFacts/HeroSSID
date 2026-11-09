using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using HeroSSID.Credentials.Vcdm20;
using HeroSSID.Credentials.VerifiablePresentations;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Single-machine verifier-owned VC2 agent scope signed challenge and status gate.
/// The original issuer signature and agent-holder possession are distinct.
/// No hosted verifier, current/live status or business authorization is implied.
/// </summary>
internal static partial class CredentialCommands
{
    internal sealed record Vc2AgentScopeVerifierRequestParameters(
        string? VerifierDid, string? TenantId, string? Audience,
        string? TrustedIssuerDid, string? Context,
        string? RequestJwtFile, string? SessionFile, int LifetimeSeconds);

    internal static bool TryCreateVc2AgentScopeVerifierRequest(
        Vc2AgentScopeVerifierRequestParameters parameters, Stream verifierSeedInput)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(verifierSeedInput);

        // The verifier, never the Agent or issuer, owns the trusted issuer,
        // exact HTTPS audience, context, signed nonce and private replay state.
        if (!TryCanonicalHttpsPin(parameters.Audience, out Uri? audience) ||
            !ValidVerifierPolicy(parameters.VerifierDid, parameters.TenantId,
                parameters.Audience, parameters.TrustedIssuerDid,
                Vcdm20AgentScopeAssertion.CredentialType, parameters.Context,
                out _, out _) ||
            audience is null)
        {
            return false;
        }

        return TryCreateVc11VerifierRequest(
            new Vc11VerifierRequestParameters(
                parameters.VerifierDid, parameters.TenantId, audience.AbsoluteUri,
                parameters.TrustedIssuerDid,
                Vcdm20AgentScopeAssertion.CredentialType, parameters.Context,
                parameters.RequestJwtFile, parameters.SessionFile,
                parameters.LifetimeSeconds),
            verifierSeedInput, policyBound: true);
    }

    internal static bool TryVerifyVc2AgentScopePresentationWithStatus(
        Vc11VerifierCheckParameters parameters, string? agentDid,
        string? credentialId, string? resource, string? action,
        string? snapshotFile, string? minimumObservedAt)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        if (!string.Equals(parameters.CredentialType,
                Vcdm20AgentScopeAssertion.CredentialType, StringComparison.Ordinal) ||
            !ValidVerifierPolicy(parameters.VerifierDid, parameters.TenantId,
                parameters.Audience, parameters.TrustedIssuerDid,
                parameters.CredentialType, parameters.Context,
                out Guid tenantId, out Uri? context) ||
            !TryCanonicalHttpsPin(parameters.Audience, out Uri? audience) ||
            !string.Equals(parameters.Audience, audience!.AbsoluteUri, StringComparison.Ordinal) ||
            agentDid is not { Length: > 0 and <= 2048 } ||
            !agentDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            !TryCanonicalHttpsPin(credentialId, out Uri? id) ||
            !TryCanonicalHttpsPin(resource, out Uri? resourceUri) ||
            string.IsNullOrEmpty(action) || action.Length > 64 ||
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
                !TryReadOriginalStatusJwt(new FileInfo(snapshotFile),
                    out string originalSnapshot) ||
                !OfflineSignedPresentationRequest.TryReadPolicyBound(
                    originalRequest, parameters.VerifierDid!, audience!.AbsoluteUri,
                    Vcdm20AgentScopeAssertion.CredentialType, context!,
                    TimeProvider.System, out var signedChallenge) ||
                signedChallenge is null ||
                !MatchesVerifierState(state, parameters, tenantId,
                    signedChallenge, originalRequest))
            {
                return false;
            }

            // The immutable verifier-owned digest stored with the private
            // challenge is checked by MatchesVerifierState BEFORE deriving the
            // digest for the SDK verifier. Do not accept an agent-supplied pin.
            var challenges = new LocalFileVerifierChallengeStore(
                parameters.SessionFile!, state, signedChallenge);
            return Vcdm20AgentScopePresentation.CheckWithIssuerStatus(
                originalPresentation, originalRequest, Sha256Hex(originalRequest),
                parameters.VerifierDid!, originalSnapshot, tenantId,
                audience!.AbsoluteUri, signedChallenge.Nonce,
                parameters.TrustedIssuerDid!, agentDid, context!, id!, audience,
                resourceUri!, action, cutoff, challenges, TimeProvider.System,
                out _) == Vcdm20RevocationCheckResult.SignedNotListed;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or
            ArgumentException or CryptographicException or FormatException or
            JsonException or InvalidOperationException or NotSupportedException)
        {
            return false;
        }
    }

    private static Command CreateVc2AgentScopeVerifierRequestCommand()
    {
        var verifier = Required("--verifier-did", "Verifier-owned Ed25519 did:key");
        var tenant = Required("--tenant-id", "Verifier-owned nonempty GUID");
        var audience = Required("--audience", "One verifier-approved canonical HTTPS audience");
        var issuer = Required("--trusted-issuer", "Independently enrolled issuer did:key");
        var context = Required("--context", "Approved versioned HTTPS Agent scope vocabulary");
        var output = Required("--output-request-file", "New genuine signed verifier request JWT");
        var session = Required("--session-file", "New private single-machine one-use state");
        var lifetime = Required("--lifetime-seconds", "Duration 1 through 300 seconds");
        var command = new Command("request-vc2-agent-scope",
            "Verifier signs a policy-bound AgentScopeCredential request and persists a one-use local challenge");
        foreach (Option option in new Option[]
        {
            verifier, tenant, audience, issuer, context, output, session, lifetime
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
                !TryCreateVc2AgentScopeVerifierRequest(
                    new Vc2AgentScopeVerifierRequestParameters(
                        invocation.ParseResult.GetValueForOption(verifier),
                        invocation.ParseResult.GetValueForOption(tenant),
                        invocation.ParseResult.GetValueForOption(audience),
                        invocation.ParseResult.GetValueForOption(issuer),
                        invocation.ParseResult.GetValueForOption(context),
                        invocation.ParseResult.GetValueForOption(output),
                        invocation.ParseResult.GetValueForOption(session), seconds),
                    Console.OpenStandardInput()))
            {
                Console.Error.WriteLine(
                    "VC2 agent verifier request rejected: key, independent pins, lifetime or protected output invalid. No request released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Authentic policy-bound VC2 agent verifier request and private single-machine one-use challenge created. No Agent authority granted.");
            invocation.ExitCode = 0;
        });
        return command;
    }

    private static Command CreateVc2AgentScopeVerifierStatusCommand()
    {
        var verifier = Required("--verifier-did", "Independently pinned verifier DID");
        var tenant = Required("--tenant-id", "Verifier-owned nonempty GUID");
        var audience = Required("--audience", "Exact canonical HTTPS recipient and verifier audience");
        var issuer = Required("--trusted-issuer", "Independently enrolled issuer did:key");
        var agent = Required("--agent", "Exact independently expected Agent did:key");
        var context = Required("--context", "Versioned approved Agent scope HTTPS vocabulary");
        var id = Required("--credential-id", "Exact signed HTTPS credential ID");
        var resource = Required("--resource", "Exact canonical HTTPS resource");
        var action = Required("--action", "One approved literal action");
        var request = Required("--request-jwt-file", "Unchanged verifier-signed policy-bound request");
        var session = Required("--session-file", "Private verifier-owned one-use local challenge");
        var presentation = Required("--presentation-jwt-file", "Unchanged agent-holder-signed VC2 VP");
        var status = Required("--snapshot-file", "Independently obtained same-issuer signed status JWT");
        var cutoff = Required("--minimum-observed-at", "Verifier-selected UTC status observation lower bound");
        var command = new Command("verify-vc2-agent-scope-vp-status",
            "Verify issuer/Agent/verifier Ed25519, exact action scope and one-use status-bound VP");
        foreach (Option option in new Option[]
        {
            verifier, tenant, audience, issuer, agent, context, id, resource,
            action, request, session, presentation, status, cutoff
        })
        {
            command.AddOption(option);
        }

        command.SetHandler((InvocationContext invocation) =>
        {
            if (!TryVerifyVc2AgentScopePresentationWithStatus(
                new Vc11VerifierCheckParameters(
                    invocation.ParseResult.GetValueForOption(verifier),
                    invocation.ParseResult.GetValueForOption(tenant),
                    invocation.ParseResult.GetValueForOption(audience),
                    invocation.ParseResult.GetValueForOption(issuer),
                    Vcdm20AgentScopeAssertion.CredentialType,
                    invocation.ParseResult.GetValueForOption(context),
                    invocation.ParseResult.GetValueForOption(request),
                    invocation.ParseResult.GetValueForOption(session),
                    invocation.ParseResult.GetValueForOption(presentation)),
                invocation.ParseResult.GetValueForOption(agent),
                invocation.ParseResult.GetValueForOption(id),
                invocation.ParseResult.GetValueForOption(resource),
                invocation.ParseResult.GetValueForOption(action),
                invocation.ParseResult.GetValueForOption(status),
                invocation.ParseResult.GetValueForOption(cutoff)))
            {
                Console.Error.WriteLine(
                    "Agent scope VP rejected: signed issuer, Agent key control, verifier challenge, exact action/resource, status observation or replay check failed. No claims released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Original VC2 issuer signature, Agent Ed25519 proof, bound verifier request, one-use nonce and same-issuer SignedNotListed status verified. No claims released. NOT live non-revocation, real identity or business authorization.");
            invocation.ExitCode = 0;
        });
        return command;
    }
}
