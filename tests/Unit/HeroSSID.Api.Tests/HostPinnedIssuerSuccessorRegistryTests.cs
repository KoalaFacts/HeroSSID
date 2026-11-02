using System.Text.Json;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Data;
using Microsoft.Extensions.Configuration;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

public sealed class HostPinnedIssuerSuccessorRegistryTests
{
    private const string Prefix = "IssuerSuccessorTrust:Policies:0:";
    private const string Audience = "https://verifier.example/host-pinned-successor";
    private static readonly JsonSerializerOptions HttpJson = new(JsonSerializerDefaults.Web);

    [Fact]
    public void ExactOperatorEnrolledPolicyCanOnlyBeReadForItsTenant()
    {
        using var previous = NewKey();
        using var successor = NewKey();
        var values = Entries(DidFromKey(previous), DidFromKey(successor));
        var registry = Registry(values);

        Assert.True(registry.TryGet(HeroDbContext.DefaultTenantId,
            "issuer-migration", out var selected));
        Assert.NotNull(selected);
        Assert.Equal(DidFromKey(previous), selected.TrustedPreviousIssuerDid);
        Assert.Equal(DidFromKey(successor), selected.PreapprovedSuccessorIssuerDid);
        Assert.Equal(Audience, selected.Audience);
        Assert.False(registry.TryGet(Guid.NewGuid(), "issuer-migration", out _));
        Assert.False(registry.TryGet(HeroDbContext.DefaultTenantId, "unknown", out _));
    }

    [Fact]
    public void InvalidUnknownDuplicateOrNestedOperatorPolicyFailsClosed()
    {
        using var previous = NewKey();
        using var successor = NewKey();
        string oldDid = DidFromKey(previous);
        string approvedDid = DidFromKey(successor);

        var unknown = Entries(oldDid, approvedDid);
        unknown[Prefix + "AllowedOverride"] = "true";
        Assert.Throws<InvalidOperationException>(() => Registry(unknown));

        var missing = Entries(oldDid, approvedDid);
        missing.Remove(Prefix + "PreapprovedSuccessorIssuerDid");
        Assert.Throws<InvalidOperationException>(() => Registry(missing));

        var sameKey = Entries(oldDid, oldDid);
        Assert.Throws<InvalidOperationException>(() => Registry(sameKey));

        var invalidDid = Entries(oldDid, "did:key:invalid");
        Assert.Throws<InvalidOperationException>(() => Registry(invalidDid));

        var httpAudience = Entries(oldDid, approvedDid);
        httpAudience[Prefix + "Audience"] = "http://verifier.example/host-pinned-successor";
        Assert.Throws<InvalidOperationException>(() => Registry(httpAudience));

        var nested = Entries(oldDid, approvedDid);
        nested[Prefix + "PreapprovedSuccessorIssuerDid:Injected"] = approvedDid;
        Assert.Throws<InvalidOperationException>(() => Registry(nested));

        var duplicate = Entries(oldDid, approvedDid);
        foreach (var pair in Entries(oldDid, approvedDid))
        {
            duplicate[pair.Key.Replace(":0:", ":1:", StringComparison.Ordinal)] = pair.Value;
        }

        Assert.Throws<InvalidOperationException>(() => Registry(duplicate));

        var scalar = Entries(oldDid, approvedDid);
        scalar["IssuerSuccessorTrust:Policies"] = "ignored";
        Assert.Throws<InvalidOperationException>(() => Registry(scalar));
    }

    [Fact]
    public void HttpRequestCannotSupplyIssuerOrSuccessorTrustOverrides()
    {
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<VerifyHostPinnedIssuerSuccessorProofRequest>(
                """
                {"policyId":"issuer-migration","nonce":"nonce",
                 "attestation":"proof","preapprovedSuccessorIssuerDid":"did:key:attacker"}
                """, HttpJson));
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<IssueHostPinnedIssuerSuccessorChallengeRequest>(
                """
                {"policyId":"issuer-migration","previousIssuerDid":"did:key:attacker"}
                """, HttpJson));
        Assert.Throws<JsonException>(() =>
            JsonSerializer.Deserialize<CancelHostPinnedIssuerSuccessorChallengeRequest>(
                """
                {"policyId":"issuer-migration","nonce":"nonce",
                 "preapprovedSuccessorIssuerDid":"did:key:attacker"}
                """, HttpJson));
    }

    private static HostPinnedIssuerSuccessorRegistry Registry(Dictionary<string, string?> entries) =>
        new(new ConfigurationBuilder().AddInMemoryCollection(entries).Build());

    private static Dictionary<string, string?> Entries(string oldDid, string successorDid) => new()
    {
        [Prefix + "TenantId"] = HeroDbContext.DefaultTenantId.ToString("D"),
        [Prefix + "PolicyId"] = "issuer-migration",
        [Prefix + "Audience"] = Audience,
        [Prefix + "TrustedPreviousIssuerDid"] = oldDid,
        [Prefix + "PreapprovedSuccessorIssuerDid"] = successorDid
    };

    private static Key NewKey() => Key.Create(SignatureAlgorithm.Ed25519,
        new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });

    private static string DidFromKey(Key key)
    {
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(bytes, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes);
    }
}
