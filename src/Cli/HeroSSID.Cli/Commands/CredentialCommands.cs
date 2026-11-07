using System.CommandLine;
using System.CommandLine.Invocation;
using System.Text;
using System.Text.Json;
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

        // This command accepts only the opt-in signed ID + single-recipient
        // profile. An issuer-only VC2, VC1.1 JWT or different audience cannot
        // satisfy the relying party's independently pinned recipient policy.
        var recipientFile = new Option<FileInfo>("--jwt-file",
            "Path to the unchanged recipient-bound issuer-signed VC2 JOSE JWT")
        {
            IsRequired = true
        };
        var recipientIssuer = new Option<string>("--trusted-issuer",
            "Independently approved issuer did:key (not learned from JWT)")
        {
            IsRequired = true
        };
        var recipientHolder = new Option<string>("--holder",
            "Independently expected subject DID, not holder key proof")
        {
            IsRequired = true
        };
        var recipientType = new Option<string>("--credential-type",
            "Independently approved exact credential type")
        {
            IsRequired = true
        };
        var recipientContext = new Option<string>("--context",
            "Independently pinned HTTPS subject vocabulary")
        {
            IsRequired = true
        };
        var recipientId = new Option<string>("--credential-id",
            "Independently pinned exact signed HTTPS credential ID")
        {
            IsRequired = true
        };
        var recipientAudience = new Option<string>("--audience",
            "Independently pinned canonical HTTPS relying-party recipient")
        {
            IsRequired = true
        };

        var verifyVc2Recipient = new Command("verify-vc2-recipient",
            "Verify issuer-signed direct VC2 JWT for one pinned recipient and credential ID");
        verifyVc2Recipient.AddOption(recipientFile);
        verifyVc2Recipient.AddOption(recipientIssuer);
        verifyVc2Recipient.AddOption(recipientHolder);
        verifyVc2Recipient.AddOption(recipientType);
        verifyVc2Recipient.AddOption(recipientContext);
        verifyVc2Recipient.AddOption(recipientId);
        verifyVc2Recipient.AddOption(recipientAudience);
        verifyVc2Recipient.SetHandler((InvocationContext context) =>
        {
            FileInfo? file = context.ParseResult.GetValueForOption(recipientFile);
            string? issuerDid = context.ParseResult.GetValueForOption(recipientIssuer);
            string? holderDid = context.ParseResult.GetValueForOption(recipientHolder);
            string? credentialType = context.ParseResult.GetValueForOption(recipientType);
            string? vocabulary = context.ParseResult.GetValueForOption(recipientContext);
            string? signedId = context.ParseResult.GetValueForOption(recipientId);
            string? recipient = context.ParseResult.GetValueForOption(recipientAudience);
            if (string.IsNullOrEmpty(signedId) || string.IsNullOrEmpty(recipient) ||
                !IsIssuerSignatureVerified(file, issuerDid, holderDid,
                    credentialType, vocabulary, vcdm20: true,
                    credentialId: signedId, audience: recipient))
            {
                Console.Error.WriteLine(
                    "Recipient-bound VC2 credential rejected: signature, exact credential ID, audience, other pins, validity, or file check failed. No claims released.");
                context.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Issuer signature, exact VC2 credential ID and independently pinned recipient verified. " +
                "Holder control, consent, current status, real-world identity and authorization NOT checked.");
            context.ExitCode = 0;
        });
        credentials.AddCommand(verifyVc2Recipient);

        // Exact verifier-owned business data acceptance is distinct from issuer
        // authenticity. This bounded string equality policy cannot be inferred
        // from an untrusted JWT and does not establish holder control or authority.
        var claimFile = new Option<FileInfo>("--jwt-file",
            "Path to the original issuer-signed recipient-bound VC2 JWT")
        {
            IsRequired = true
        };
        var claimIssuer = new Option<string>("--trusted-issuer",
            "Independently enrolled Ed25519 issuer did:key")
        {
            IsRequired = true
        };
        var claimHolder = new Option<string>("--holder",
            "Exact expected credential subject DID (not proof of possession)")
        {
            IsRequired = true
        };
        var claimType = new Option<string>("--credential-type",
            "Verifier-approved exact credential type")
        {
            IsRequired = true
        };
        var claimContext = new Option<string>("--context",
            "Verifier-approved HTTPS subject vocabulary")
        {
            IsRequired = true
        };
        var claimId = new Option<string>("--credential-id",
            "Independently pinned exact signed HTTPS VC ID")
        {
            IsRequired = true
        };
        var claimAudience = new Option<string>("--audience",
            "Independently pinned canonical HTTPS receiving service")
        {
            IsRequired = true
        };
        var claimName = new Option<string>("--claim-name",
            "Exact non-reserved top-level credentialSubject string property")
        {
            IsRequired = true
        };
        var claimValue = new Option<string>("--claim-value",
            "Exact verifier-required value, compared ordinally without disclosure")
        {
            IsRequired = true
        };
        var verifyVc2Claim = new Command("verify-vc2-recipient-claim",
            "Require a signed VC2 recipient, credential ID and exact approved subject string value");
        verifyVc2Claim.AddOption(claimFile);
        verifyVc2Claim.AddOption(claimIssuer);
        verifyVc2Claim.AddOption(claimHolder);
        verifyVc2Claim.AddOption(claimType);
        verifyVc2Claim.AddOption(claimContext);
        verifyVc2Claim.AddOption(claimId);
        verifyVc2Claim.AddOption(claimAudience);
        verifyVc2Claim.AddOption(claimName);
        verifyVc2Claim.AddOption(claimValue);
        verifyVc2Claim.SetHandler((InvocationContext context) =>
        {
            FileInfo? file = context.ParseResult.GetValueForOption(claimFile);
            string? issuerDid = context.ParseResult.GetValueForOption(claimIssuer);
            string? holderDid = context.ParseResult.GetValueForOption(claimHolder);
            string? credentialType = context.ParseResult.GetValueForOption(claimType);
            string? vocabulary = context.ParseResult.GetValueForOption(claimContext);
            string? signedId = context.ParseResult.GetValueForOption(claimId);
            string? recipient = context.ParseResult.GetValueForOption(claimAudience);
            string? requiredName = context.ParseResult.GetValueForOption(claimName);
            string? requiredValue = context.ParseResult.GetValueForOption(claimValue);

            if (!TryVerifyIssuerWithSubject(file, issuerDid, holderDid, credentialType,
                    vocabulary, out JsonElement verifiedSubject, vcdm20: true,
                    credentialId: signedId, audience: recipient) ||
                !MatchesPinnedStringClaim(verifiedSubject, requiredName, requiredValue))
            {
                // Neither success nor failure prints the JWT or any claim value.
                Console.Error.WriteLine(
                    "VC2 recipient-bound signed claim rejected: issuer signature, exact pins, value, validity, or file check failed. No claims released.");
                context.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Original issuer-signed VC2 credential, pinned recipient, exact ID and verifier-required string claim checked. " +
                "Holder key control, consent, revocation, real identity and business authorization NOT checked.");
            context.ExitCode = 0;
        });
        credentials.AddCommand(verifyVc2Claim);
        return credentials;
    }

    private static bool IsIssuerSignatureVerified(FileInfo? file, string? issuerDid,
        string? holderDid, string? credentialType, string? vocabulary,
        bool vcdm20 = false, string? credentialId = null, string? audience = null) =>
        TryVerifyIssuerWithSubject(file, issuerDid, holderDid, credentialType,
            vocabulary, out _, vcdm20, credentialId, audience);

    private static bool TryVerifyIssuerWithSubject(FileInfo? file, string? issuerDid,
        string? holderDid, string? credentialType, string? vocabulary,
        out JsonElement verifiedSubject, bool vcdm20 = false,
        string? credentialId = null, string? audience = null)
    {
        verifiedSubject = default;
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

        // Verify every recipient and credential-ID pin before reading any JWT.
        // A caller cannot turn absent or unsafe recipient policy into a
        // permissive issuer-only check through this overload.
        bool recipientBound = credentialId is not null || audience is not null;
        Uri? expectedId = null;
        Uri? expectedAudience = null;
        if (recipientBound &&
            (!vcdm20 ||
             !TryCanonicalHttpsPin(credentialId, out expectedId) ||
             !TryCanonicalHttpsPin(audience, out expectedAudience)))
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
            if (recipientBound)
            {
                return Vcdm20JoseCredential.TryVerifyForAudienceWithId(
                    originalJwt, issuerDid, holderDid, credentialType,
                    contextUri, expectedId!, expectedAudience!,
                    DateTimeOffset.UtcNow, out verifiedSubject);
            }

            return vcdm20
                ? Vcdm20JoseCredential.TryVerify(originalJwt, issuerDid,
                    holderDid, credentialType, contextUri,
                    DateTimeOffset.UtcNow, out verifiedSubject)
                : JwtVcJsonCredential.TryVerify(originalJwt, issuerDid,
                    holderDid, credentialType, contextUri,
                    DateTimeOffset.UtcNow, out verifiedSubject);
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

    private static bool MatchesPinnedStringClaim(
        JsonElement verifiedSubject, string? name, string? value)
    {
        // A verifier must explicitly choose exactly one simple non-reserved key
        // and a bounded string value. JSON numbers, arrays, objects, nulls and
        // duplicate property names are never silently coerced or accepted.
        if (verifiedSubject.ValueKind != JsonValueKind.Object ||
            string.IsNullOrEmpty(name) || name.Length > 64 ||
            !char.IsAsciiLetter(name[0]) ||
            string.Equals(name, "id", StringComparison.Ordinal) ||
            string.IsNullOrEmpty(value) || value.Length > 256 ||
            !string.Equals(value.Trim(), value, StringComparison.Ordinal) ||
            value.Any(char.IsControl))
        {
            return false;
        }

        for (int i = 1; i < name.Length; i++)
        {
            char character = name[i];
            if (!char.IsAsciiLetterOrDigit(character) &&
                character != '_' && character != '-')
            {
                return false;
            }
        }

        var names = new HashSet<string>(StringComparer.Ordinal);
        bool matched = false;
        foreach (JsonProperty property in verifiedSubject.EnumerateObject())
        {
            if (!names.Add(property.Name))
            {
                return false;
            }

            if (string.Equals(property.Name, name, StringComparison.Ordinal))
            {
                if (property.Value.ValueKind != JsonValueKind.String ||
                    !string.Equals(property.Value.GetString(), value,
                        StringComparison.Ordinal))
                {
                    return false;
                }

                matched = true;
            }
        }

        return matched;
    }

    private static bool TryCanonicalHttpsPin(string? text, out Uri? uri)
    {
        uri = null;
        if (string.IsNullOrEmpty(text) || text.Length > 2_048 ||
            !Uri.TryCreate(text, UriKind.Absolute, out Uri? parsed) ||
            !string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(parsed.Host) ||
            parsed.UserInfo.Length != 0 || parsed.Fragment.Length != 0 ||
            !string.Equals(parsed.AbsoluteUri, text, StringComparison.Ordinal))
        {
            return false;
        }

        uri = parsed;
        return true;
    }
}
