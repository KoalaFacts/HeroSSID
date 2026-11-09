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
internal static partial class CredentialCommands
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

        // Organisation-owned did:web keys require independent enrollment: a
        // signed DID, a JWT kid and a signed display name are NOT trust anchors.
        // The CLI never fetches a DID document or promotes a key on rotation.
        var didWebFile = new Option<FileInfo>("--jwt-file",
            "Original, unchanged Ed25519-signed VC1.1 JWT") { IsRequired = true };
        var didWebIssuer = new Option<string>("--trusted-issuer",
            "Independently approved restricted did:web issuer") { IsRequired = true };
        var didWebMethod = new Option<string>("--verification-method",
            "Independently pinned did:web#key-1 or #key-2 assertion method") { IsRequired = true };
        var didWebPublicKey = new Option<string>("--public-key-hex",
            "Independently enrolled raw 32-byte Ed25519 issuer public key, as 64 hex characters")
        { IsRequired = true };
        var didWebIssuerName = new Option<string>("--issuer-name",
            "Exact independently approved issuer-signed descriptive name") { IsRequired = true };
        var didWebId = new Option<string>("--credential-id",
            "Exact independently pinned HTTPS signed credential ID") { IsRequired = true };
        var didWebHolder = new Option<string>("--holder",
            "Expected credential subject DID, not private-key control") { IsRequired = true };
        var didWebType = new Option<string>("--credential-type",
            "Independently approved exact VC1.1 credential type") { IsRequired = true };
        var didWebContext = new Option<string>("--context",
            "Independently approved HTTPS subject vocabulary") { IsRequired = true };
        var verifyDidWeb = new Command("verify-vc11-didweb-issuer",
            "Verify original VC1.1 did:web issuer Ed25519 signature against exact offline key and metadata pins");
        verifyDidWeb.AddOption(didWebFile);
        verifyDidWeb.AddOption(didWebIssuer);
        verifyDidWeb.AddOption(didWebMethod);
        verifyDidWeb.AddOption(didWebPublicKey);
        verifyDidWeb.AddOption(didWebIssuerName);
        verifyDidWeb.AddOption(didWebId);
        verifyDidWeb.AddOption(didWebHolder);
        verifyDidWeb.AddOption(didWebType);
        verifyDidWeb.AddOption(didWebContext);
        verifyDidWeb.SetHandler((InvocationContext context) =>
        {
            if (!TryVerifyDidWebIssuer(
                context.ParseResult.GetValueForOption(didWebFile),
                context.ParseResult.GetValueForOption(didWebIssuer),
                context.ParseResult.GetValueForOption(didWebMethod),
                context.ParseResult.GetValueForOption(didWebPublicKey),
                context.ParseResult.GetValueForOption(didWebIssuerName),
                context.ParseResult.GetValueForOption(didWebId),
                context.ParseResult.GetValueForOption(didWebHolder),
                context.ParseResult.GetValueForOption(didWebType),
                context.ParseResult.GetValueForOption(didWebContext)))
            {
                Console.Error.WriteLine(
                    "Pinned VC1.1 did:web issuer credential rejected: key, signature, exact metadata pins, validity or file check failed. No claims released.");
                context.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Original VC1.1 did:web issuer signature, exact assertion key, signed issuer name and credential ID verified. " +
                "Domain ownership, holder control, consent, status, legal identity and business authorization NOT checked.");
            context.ExitCode = 0;
        });
        credentials.AddCommand(verifyDidWeb);
        credentials.AddCommand(CreateVc2DidWebCommand());
        credentials.AddCommand(CreateVc2DidWebRecipientClaimCommand());
        credentials.AddCommand(CreateVc2DidWebIssuerCommand());
        credentials.AddCommand(CreateVc2DidWebStatusCommand());
        credentials.AddCommand(CreateVc2DidWebStatusIssuerCommand());
        credentials.AddCommand(CreateVc11IssuerCommand());
        credentials.AddCommand(CreateVc11PinnedVerifyCommand());
        credentials.AddCommand(CreateVc11PinnedClaimCommand());
        credentials.AddCommand(CreateVc11StatusIssueCommand());
        credentials.AddCommand(CreateVc11StatusVerifyCommand());
        credentials.AddCommand(CreateVc11HolderPresentationCommand());
        credentials.AddCommand(CreateVc11VerifierRequestCommand());
        credentials.AddCommand(CreateVc11VerifierCheckCommand());
        credentials.AddCommand(CreateVc11VerifierStatusCheckCommand());
        credentials.AddCommand(CreateVc2AgentScopeCommand());
        credentials.AddCommand(CreateVc2AgentScopeIssueCommand());
        credentials.AddCommand(CreateVc2AgentScopeVerifierRequestCommand());
        credentials.AddCommand(CreateVc2AgentScopeVerifierStatusCommand());
        return credentials;
    }

    private static Command CreateVc2DidWebCommand()
    {
        var file = new Option<FileInfo>("--jwt-file",
            "Original issuer-signed direct VCDM 2.0 vc+jwt") { IsRequired = true };
        var issuer = new Option<string>("--trusted-issuer",
            "Independently enrolled did:web issuer") { IsRequired = true };
        var method = new Option<string>("--verification-method",
            "Exact pre-enrolled #key-1 or #key-2 assertion method") { IsRequired = true };
        var key = new Option<string>("--public-key-hex",
            "Independently pinned raw Ed25519 public key (64 hex characters)") { IsRequired = true };
        var issuerName = new Option<string>("--issuer-name",
            "Exact separately approved signed descriptive issuer name") { IsRequired = true };
        var id = new Option<string>("--credential-id",
            "Exact separately approved signed HTTPS VC2 ID") { IsRequired = true };
        var holder = new Option<string>("--holder",
            "Exact expected credential subject DID, not proof of holder key control") { IsRequired = true };
        var type = new Option<string>("--credential-type",
            "Exact verifier-approved credential type") { IsRequired = true };
        var contextUri = new Option<string>("--context",
            "Exact approved HTTPS subject vocabulary") { IsRequired = true };
        var audience = new Option<string>("--audience",
            "Optional exact independently pinned HTTPS recipient; requires signed aud");
        var verify = new Command("verify-vc2-didweb-issuer",
            "Verify direct VC2 JOSE using separately pinned did:web Ed25519 assertion key");
        verify.AddOption(file);
        verify.AddOption(issuer);
        verify.AddOption(method);
        verify.AddOption(key);
        verify.AddOption(issuerName);
        verify.AddOption(id);
        verify.AddOption(holder);
        verify.AddOption(type);
        verify.AddOption(contextUri);
        verify.AddOption(audience);
        verify.SetHandler((InvocationContext context) =>
        {
            string? pinnedAudience = context.ParseResult.GetValueForOption(audience);
            if (!TryVerifyDidWebIssuer(
                context.ParseResult.GetValueForOption(file),
                context.ParseResult.GetValueForOption(issuer),
                context.ParseResult.GetValueForOption(method),
                context.ParseResult.GetValueForOption(key),
                context.ParseResult.GetValueForOption(issuerName),
                context.ParseResult.GetValueForOption(id),
                context.ParseResult.GetValueForOption(holder),
                context.ParseResult.GetValueForOption(type),
                context.ParseResult.GetValueForOption(contextUri),
                vcdm20: true, audience: pinnedAudience))
            {
                Console.Error.WriteLine(
                    "Direct VC2 did:web credential rejected: issuer signature, key method, signed metadata, validity or file policy failed. No claims released.");
                context.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                pinnedAudience is null
                    ? "Original direct VC2 issuer signature, independently pinned did:web assertion key, name and credential ID verified. " +
                      "DID domain ownership, holder control, consent, revocation, identity, authority and wallet interoperability NOT checked."
                    : "Original direct VC2 issuer signature, independently pinned did:web assertion key, name, ID and exact HTTPS recipient verified. " +
                      "Holder key control, consent, revocation, identity, authority and wallet interoperability NOT checked.");
            context.ExitCode = 0;
        });
        return verify;
    }

    private static bool TryVerifyDidWebIssuer(FileInfo? file, string? issuerDid,
        string? assertionMethod, string? publicKeyHex, string? issuerName,
        string? credentialId, string? holderDid, string? credentialType,
        string? vocabulary, bool vcdm20 = false, string? audience = null)
        => TryVerifyDidWebIssuerWithSubject(file, issuerDid, assertionMethod,
            publicKeyHex, issuerName, credentialId, holderDid, credentialType,
            vocabulary, out _, vcdm20, audience);

    private static bool TryVerifyDidWebIssuerWithSubject(FileInfo? file,
        string? issuerDid, string? assertionMethod, string? publicKeyHex,
        string? issuerName, string? credentialId, string? holderDid,
        string? credentialType, string? vocabulary,
        out JsonElement verifiedSubject, bool vcdm20 = false,
        string? audience = null)
    {
        verifiedSubject = default;
        // Every trust anchor comes from the caller's own independently
        // established policy, never from JWT header or claims. Fail closed
        // before opening a credential file if an essential pin is missing.
        if (file is null || string.IsNullOrWhiteSpace(issuerDid) ||
            string.IsNullOrWhiteSpace(assertionMethod) ||
            string.IsNullOrWhiteSpace(issuerName) ||
            string.IsNullOrWhiteSpace(holderDid) ||
            string.IsNullOrWhiteSpace(credentialType) ||
            publicKeyHex is null || publicKeyHex.Length != 64 ||
            !TryCanonicalHttpsPin(credentialId, out Uri? expectedId) ||
            !Uri.TryCreate(vocabulary, UriKind.Absolute, out Uri? contextUri) ||
            contextUri.Scheme != Uri.UriSchemeHttps ||
            contextUri.UserInfo.Length != 0 || contextUri.Fragment.Length != 0)
        {
            return false;
        }

        Uri? pinnedAudience = null;
        if (audience is not null &&
            (!vcdm20 || !TryCanonicalHttpsPin(audience, out pinnedAudience)))
        {
            return false;
        }

        // Convert.FromHexString is strict; only one exact raw Ed25519 public
        // key is allowed, not a JWK, private seed or multicodec encoding.
        byte[] pinnedKey;
        try
        {
            pinnedKey = Convert.FromHexString(publicKeyHex);
        }
        catch (FormatException)
        {
            return false;
        }

        if (pinnedKey.Length != 32)
        {
            return false;
        }
        try
        {
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
            return vcdm20
                ? pinnedAudience is not null
                    ? Vcdm20JoseCredential.TryVerifyPinnedDidWebIssuerForAudienceWithId(
                        originalJwt, issuerDid, assertionMethod, pinnedKey, issuerName,
                        expectedId!, pinnedAudience, holderDid, credentialType, contextUri,
                        DateTimeOffset.UtcNow, out verifiedSubject)
                    : Vcdm20JoseCredential.TryVerifyPinnedDidWebIssuerNameAndId(
                        originalJwt, issuerDid, assertionMethod, pinnedKey, issuerName,
                        expectedId!, holderDid, credentialType, contextUri,
                        DateTimeOffset.UtcNow, out verifiedSubject)
                : JwtVcJsonPinnedDidWebIssuerVerifier.TryVerifyWithPinnedIssuerNameAndId(
                    originalJwt, issuerDid, assertionMethod, pinnedKey, issuerName,
                    expectedId!, holderDid, credentialType, contextUri,
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
