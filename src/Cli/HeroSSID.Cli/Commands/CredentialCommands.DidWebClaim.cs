using System.CommandLine;
using System.CommandLine.Invocation;
using System.Text.Json;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Offline issuer-assertion acceptance for one verifier-pinned did:web key,
/// original recipient-bound credential, and exact string claim. A successful
/// signature does not establish holder possession or business authority.
/// </summary>
internal static partial class CredentialCommands
{
    private static Command CreateVc2DidWebRecipientClaimCommand()
    {
        var file = new Option<FileInfo>("--jwt-file",
            "Unchanged direct VCDM 2.0 issuer-signed compact vc+jwt") { IsRequired = true };
        var issuer = new Option<string>("--trusted-issuer",
            "Independently approved did:web issuer") { IsRequired = true };
        var method = new Option<string>("--verification-method",
            "Independently pinned did:web #key-1 or #key-2 method") { IsRequired = true };
        var key = new Option<string>("--public-key-hex",
            "Separately enrolled 32-byte Ed25519 issuer public key (64 hex characters)")
        { IsRequired = true };
        var issuerName = new Option<string>("--issuer-name",
            "Exact separately trusted issuer-signed descriptive name") { IsRequired = true };
        var id = new Option<string>("--credential-id",
            "Exact independently pinned issuer-signed HTTPS credential ID") { IsRequired = true };
        var audience = new Option<string>("--audience",
            "Exact independently pinned signed HTTPS relying-party recipient") { IsRequired = true };
        var holder = new Option<string>("--holder",
            "Expected credential subject DID, not proof of key control") { IsRequired = true };
        var type = new Option<string>("--credential-type",
            "Independently approved exact credential type") { IsRequired = true };
        var vocabulary = new Option<string>("--context",
            "Exact separately approved HTTPS subject vocabulary") { IsRequired = true };
        var claimName = new Option<string>("--claim-name",
            "Exact non-reserved top-level subject string property") { IsRequired = true };
        var claimValue = new Option<string>("--claim-value",
            "Verifier-required exact bounded string claim value") { IsRequired = true };

        var verify = new Command("verify-vc2-didweb-recipient-claim",
            "Check one genuine did:web VC2 issuer assertion, recipient, ID and exact signed string claim");
        verify.AddOption(file);
        verify.AddOption(issuer);
        verify.AddOption(method);
        verify.AddOption(key);
        verify.AddOption(issuerName);
        verify.AddOption(id);
        verify.AddOption(audience);
        verify.AddOption(holder);
        verify.AddOption(type);
        verify.AddOption(vocabulary);
        verify.AddOption(claimName);
        verify.AddOption(claimValue);
        verify.SetHandler((InvocationContext invocation) =>
        {
            // Preserve all existing bounded, strictly UTF-8 JWT file handling,
            // Ed25519 signature verification, and independent did:web pins.
            // Verify recipient and the signed original before claim comparison.
            if (!TryVerifyDidWebIssuerWithSubject(
                    invocation.ParseResult.GetValueForOption(file),
                    invocation.ParseResult.GetValueForOption(issuer),
                    invocation.ParseResult.GetValueForOption(method),
                    invocation.ParseResult.GetValueForOption(key),
                    invocation.ParseResult.GetValueForOption(issuerName),
                    invocation.ParseResult.GetValueForOption(id),
                    invocation.ParseResult.GetValueForOption(holder),
                    invocation.ParseResult.GetValueForOption(type),
                    invocation.ParseResult.GetValueForOption(vocabulary),
                    out JsonElement verifiedSubject, vcdm20: true,
                    audience: invocation.ParseResult.GetValueForOption(audience)) ||
                !MatchesPinnedStringClaim(verifiedSubject,
                    invocation.ParseResult.GetValueForOption(claimName),
                    invocation.ParseResult.GetValueForOption(claimValue)))
            {
                Console.Error.WriteLine(
                    "VC2 did:web recipient-bound issuer claim rejected: signature, original JWT, exact pins, validity, or string value check failed. No claims released.");
                invocation.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Genuine issuer-signed VC2 did:web statement, exact recipient, credential ID and independently required string claim verified. " +
                "Holder key control, consent, revocation, current entitlement, legal identity and business authorization NOT checked.");
            invocation.ExitCode = 0;
        });
        return verify;
    }
}
