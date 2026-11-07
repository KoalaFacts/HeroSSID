using System.CommandLine;
using System.CommandLine.Invocation;
using System.Text;
using HeroSSID.Credentials.JwtVcJson;
using HeroSSID.Credentials.Vcdm20;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Human-invoked, deliberately issuer-only credential checks.
/// No CLI flow may simulate signature verification or issuer issuance.
/// </summary>
internal static class CredentialCommands
{
    private const int MaximumCredentialFileBytes = 65_536;

    public static Command CreateCommand(IServiceProvider serviceProvider)
    {
        var credentials = new Command("credential",
            "Explicitly pinned verifiable credential issuer-signature operations");

        var fileOption = new Option<FileInfo>("--jwt-file",
            "Path to the unchanged issuer-signed compact VC1.1 JWT")
        {
            IsRequired = true
        };
        var issuerOption = new Option<string>("--trusted-issuer",
            "Independently enrolled issuer did:key, never learned from JWT")
        {
            IsRequired = true
        };
        var holderOption = new Option<string>("--holder",
            "Expected credential holder DID, not a key-possession proof")
        {
            IsRequired = true
        };
        var typeOption = new Option<string>("--credential-type",
            "Exact credential type approved by the verifier")
        {
            IsRequired = true
        };
        var contextOption = new Option<string>("--context",
            "Exact preapproved HTTPS subject vocabulary URI")
        {
            IsRequired = true
        };

        var verify = new Command("verify-issuer",
            "Verify issuer Ed25519 signature and VC1.1 fields only; no holder proof or status");
        verify.AddOption(fileOption);
        verify.AddOption(issuerOption);
        verify.AddOption(holderOption);
        verify.AddOption(typeOption);
        verify.AddOption(contextOption);
        verify.SetHandler((InvocationContext context) =>
        {
            FileInfo? file = context.ParseResult.GetValueForOption(fileOption);
            string? issuerDid = context.ParseResult.GetValueForOption(issuerOption);
            string? holderDid = context.ParseResult.GetValueForOption(holderOption);
            string? credentialType = context.ParseResult.GetValueForOption(typeOption);
            string? vocabulary = context.ParseResult.GetValueForOption(contextOption);

            if (!IsIssuerSignatureVerified(file, issuerDid, holderDid,
                    credentialType, vocabulary))
            {
                // Never echo potentially sensitive, untrusted JWT or claims.
                Console.Error.WriteLine(
                    "Issuer credential rejected: signature, pin, format, validity, or file check failed. No claims released.");
                context.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Issuer signature and independently pinned VC1.1 fields verified. " +
                "Holder key control, consent, revocation, legal identity and business authorization NOT checked.");
            context.ExitCode = 0;
        });

        // Historical simulated 'issue' and 'verify' handlers returned success
        // without signing or verifying any credential. They are removed.
        credentials.AddCommand(verify);

        // Do not re-parent System.CommandLine options: each command owns its
        // own independently supplied verifier policy and its own file option.
        var vc2File = new Option<FileInfo>("--jwt-file",
            "Path to the unchanged issuer-signed compact direct VCDM 2.0 JOSE JWT")
        {
            IsRequired = true
        };
        var vc2Issuer = new Option<string>("--trusted-issuer",
            "Independently enrolled issuer did:key, never learned from JWT")
        {
            IsRequired = true
        };
        var vc2Holder = new Option<string>("--holder",
            "Expected credential holder DID; not proof of private-key control")
        {
            IsRequired = true
        };
        var vc2Type = new Option<string>("--credential-type",
            "Exact credential type independently approved by the verifier")
        {
            IsRequired = true
        };
        var vc2Context = new Option<string>("--context",
            "Exact preapproved HTTPS subject vocabulary URI")
        {
            IsRequired = true
        };

        var verifyVc2 = new Command("verify-vc2-issuer",
            "Verify a direct VCDM 2.0 vc+jwt issuer Ed25519 signature and pinned fields only");
        verifyVc2.AddOption(vc2File);
        verifyVc2.AddOption(vc2Issuer);
        verifyVc2.AddOption(vc2Holder);
        verifyVc2.AddOption(vc2Type);
        verifyVc2.AddOption(vc2Context);
        verifyVc2.SetHandler((InvocationContext context) =>
        {
            FileInfo? file = context.ParseResult.GetValueForOption(vc2File);
            string? issuerDid = context.ParseResult.GetValueForOption(vc2Issuer);
            string? holderDid = context.ParseResult.GetValueForOption(vc2Holder);
            string? credentialType = context.ParseResult.GetValueForOption(vc2Type);
            string? vocabulary = context.ParseResult.GetValueForOption(vc2Context);
            if (!IsIssuerSignatureVerified(file, issuerDid, holderDid,
                    credentialType, vocabulary, vcdm20: true))
            {
                Console.Error.WriteLine(
                    "Direct VC2 JOSE issuer credential rejected: signature, pin, format, validity, or file check failed. No claims released.");
                context.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Issuer signature and independently pinned VCDM 2.0 direct JOSE fields verified. " +
                "Holder key control, consent, status, legal identity and business authorization NOT checked.");
            context.ExitCode = 0;
        });
        credentials.AddCommand(verifyVc2);
        return credentials;
    }

    private static bool IsIssuerSignatureVerified(FileInfo? file, string? issuerDid,
        string? holderDid, string? credentialType, string? vocabulary,
        bool vcdm20 = false)
    {
        if (file is null || string.IsNullOrWhiteSpace(issuerDid) ||
            !issuerDid.StartsWith("did:key:", StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(holderDid) ||
            string.IsNullOrWhiteSpace(credentialType) ||
            !Uri.TryCreate(vocabulary, UriKind.Absolute, out Uri? contextUri) ||
            contextUri.Scheme != Uri.UriSchemeHttps ||
            contextUri.UserInfo.Length != 0 || contextUri.Fragment.Length != 0)
        {
            return false;
        }

        try
        {
            // Bound the actual file read, including races with file changes.
            using var input = new FileStream(file.FullName, FileMode.Open,
                FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
            byte[] bytes = new byte[MaximumCredentialFileBytes + 1];
            int length = 0;
            while (length < bytes.Length)
            {
                int read = input.Read(bytes, length, bytes.Length - length);
                if (read == 0)
                {
                    break;
                }

                length += read;
            }

            if (length == 0 || length > MaximumCredentialFileBytes)
            {
                return false;
            }

            string originalJwt = new UTF8Encoding(false, true)
                .GetString(bytes, 0, length).TrimEnd('\r', '\n');
            // The formats are deliberately separate: direct VC2 JOSE must not
            // fall back to VC1.1 nested JWT or a private HeroSSID vc.context.
            return vcdm20
                ? Vcdm20JoseCredential.TryVerify(originalJwt, issuerDid,
                    holderDid, credentialType, contextUri,
                    DateTimeOffset.UtcNow, out _)
                : JwtVcJsonCredential.TryVerify(originalJwt, issuerDid,
                    holderDid, credentialType, contextUri,
                    DateTimeOffset.UtcNow, out _);
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }
}
