using System.CommandLine;
using System.CommandLine.Invocation;
using System.Globalization;
using System.Text;
using HeroSSID.Credentials.CredentialVerification;
using HeroSSID.Credentials.Vcdm20;

namespace HeroSSID.Cli.Commands;

/// <summary>
/// Offline, verifier-pinned issuer status over an unchanged original VC2 JWT.
/// An issuer-signed absence from a bounded snapshot is not live non-revocation,
/// holder key control, verified identity, or business authorization.
/// </summary>
internal static partial class CredentialCommands
{
    private static Command CreateVc2DidWebStatusCommand()
    {
        var jwtFile = new Option<FileInfo>("--jwt-file",
            "Path to unchanged, issuer-signed VC2 vc+jwt") { IsRequired = true };
        var snapshotFile = new Option<FileInfo>("--snapshot-file",
            "Path to the matching original issuer-signed status JWT") { IsRequired = true };
        var issuer = new Option<string>("--trusted-issuer",
            "Independently enrolled did:web issuer") { IsRequired = true };
        var method = new Option<string>("--verification-method",
            "Exact independently pinned #key-1 or #key-2 issuer assertion method") { IsRequired = true };
        var publicKey = new Option<string>("--public-key-hex",
            "Independently pinned 32-byte Ed25519 issuer public key, 64 hexadecimal characters")
        { IsRequired = true };
        var issuerName = new Option<string>("--issuer-name",
            "Exact independently approved signed issuer name") { IsRequired = true };
        var credentialId = new Option<string>("--credential-id",
            "Exact approved HTTPS signed VC2 credential ID") { IsRequired = true };
        var audience = new Option<string>("--audience",
            "Exact independently pinned HTTPS relying-party recipient") { IsRequired = true };
        var holder = new Option<string>("--holder",
            "Expected signed subject DID, not holder key control") { IsRequired = true };
        var credentialType = new Option<string>("--credential-type",
            "Exact verifier-approved VC2 credential type") { IsRequired = true };
        var vocabulary = new Option<string>("--context",
            "Exact independently approved HTTPS subject vocabulary URI") { IsRequired = true };
        var minimumObserved = new Option<string>("--minimum-observed-at",
            "Verifier-owned earliest acceptable issuer observation (UTC round-trip timestamp)")
        { IsRequired = true };

        var verify = new Command("verify-vc2-didweb-status",
            "Verify original issuer-signed VC2 JWT and its separate, fresh, issuer-signed status");
        verify.AddOption(jwtFile);
        verify.AddOption(snapshotFile);
        verify.AddOption(issuer);
        verify.AddOption(method);
        verify.AddOption(publicKey);
        verify.AddOption(issuerName);
        verify.AddOption(credentialId);
        verify.AddOption(audience);
        verify.AddOption(holder);
        verify.AddOption(credentialType);
        verify.AddOption(vocabulary);
        verify.AddOption(minimumObserved);
        verify.SetHandler((InvocationContext context) =>
        {
            bool accepted = TryVerifyVc2DidWebStatus(
                context.ParseResult.GetValueForOption(jwtFile),
                context.ParseResult.GetValueForOption(snapshotFile),
                context.ParseResult.GetValueForOption(issuer),
                context.ParseResult.GetValueForOption(method),
                context.ParseResult.GetValueForOption(publicKey),
                context.ParseResult.GetValueForOption(issuerName),
                context.ParseResult.GetValueForOption(credentialId),
                context.ParseResult.GetValueForOption(audience),
                context.ParseResult.GetValueForOption(holder),
                context.ParseResult.GetValueForOption(credentialType),
                context.ParseResult.GetValueForOption(vocabulary),
                context.ParseResult.GetValueForOption(minimumObserved));

            if (!accepted)
            {
                // Do not echo issuer claims, input JWTs, pins or the revocation set.
                Console.Error.WriteLine(
                    "VC2 did:web credential/status rejected: signed provenance, revocation, freshness, policy pins or file check failed. No claims released.");
                context.ExitCode = 1;
                return;
            }

            Console.Out.WriteLine(
                "Original VC2 issuer signature and separately signed, fresh status checked: SignedNotListed. " +
                "No claims released. This does not prove complete or live revocation, holder control, consent, " +
                "legal identity, business authorization or third-party Wallet interoperability.");
            context.ExitCode = 0;
        });
        return verify;
    }

    private static bool TryVerifyVc2DidWebStatus(
        FileInfo? credentialFile, FileInfo? snapshotFile, string? trustedIssuer,
        string? verificationMethod, string? pinnedPublicKeyHex, string? issuerName,
        string? credentialId, string? audience, string? holderDid,
        string? credentialType, string? contextUri, string? minimumObservedText)
    {
        // The verifier's independent policy must be complete before reading
        // either untrusted file. The SDK additionally checks the did:web key.
        if (string.IsNullOrWhiteSpace(trustedIssuer) ||
            string.IsNullOrWhiteSpace(verificationMethod) ||
            string.IsNullOrWhiteSpace(issuerName) ||
            string.IsNullOrWhiteSpace(holderDid) ||
            string.IsNullOrWhiteSpace(credentialType) ||
            pinnedPublicKeyHex is not { Length: 64 } ||
            !TryCanonicalHttpsPin(credentialId, out Uri? expectedId) ||
            !TryCanonicalHttpsPin(audience, out Uri? expectedAudience) ||
            !TryCanonicalHttpsPin(contextUri, out Uri? expectedContext) ||
            !DateTimeOffset.TryParseExact(minimumObservedText, "O",
                CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind,
                out DateTimeOffset minimumObserved) ||
            minimumObserved.Offset != TimeSpan.Zero)
        {
            return false;
        }

        byte[] pinnedPublicKey;
        try
        {
            pinnedPublicKey = Convert.FromHexString(pinnedPublicKeyHex);
        }
        catch (FormatException)
        {
            return false;
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (minimumObserved < DateTimeOffset.UnixEpoch || minimumObserved > now ||
            !TryReadOriginalStatusJwt(credentialFile, out string originalJwt) ||
            !TryReadOriginalStatusJwt(snapshotFile, out string originalSnapshot))
        {
            return false;
        }

        // Never let JWT claims select issuer trust, the receiving application,
        // the observation cutoff, or a replacement issuer verification key.
        return Vcdm20PinnedDidWebIssuerStatus.Check(
            originalSnapshot, originalJwt, trustedIssuer, verificationMethod,
            pinnedPublicKey, issuerName, expectedId!, expectedAudience!, holderDid,
            credentialType, expectedContext!, minimumObserved, now, out _) ==
            Vcdm20RevocationCheckResult.SignedNotListed;
    }

    private static bool TryReadOriginalStatusJwt(FileInfo? file, out string jwt)
    {
        jwt = string.Empty;
        if (file is null)
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

            // Retain original signed bytes, removing only terminal line endings
            // from ordinary text files as in the existing VC2 CLI verifier.
            jwt = new UTF8Encoding(false, true).GetString(bytes, 0, length)
                .TrimEnd('\r', '\n');
            return jwt.Length != 0;
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
