using System.Security.Claims;
using HeroSSID.Api.Features.Credentials;
using HeroSSID.Data;
using Microsoft.Extensions.Configuration;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

public sealed class IssuerSigningGrantRegistryTests
{
    private static readonly Guid Tenant = HeroDbContext.DefaultTenantId;
    private static readonly Guid OtherTenant = Guid.Parse("17171717-1717-1717-1717-171717171717");

    [Fact]
    public void UnconfiguredTenantKeepsExistingTenantScopeBehaviour()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519);
        var registry = Registry(new Dictionary<string, string?>());
        Assert.True(registry.IsAllowed(Tenant, Principal("issuing-client"), DidFromKey(key)));
    }

    [Fact]
    public void EnforcedTenantSignsOnlyForExactOperatorGrantedClientAndIssuer()
    {
        using var issuer = Key.Create(SignatureAlgorithm.Ed25519);
        using var otherIssuer = Key.Create(SignatureAlgorithm.Ed25519);
        string did = DidFromKey(issuer);
        var registry = Registry(Entries(did));

        Assert.True(registry.IsAllowed(Tenant, Principal("issuing-client"), did));
        Assert.False(registry.IsAllowed(Tenant, Principal("other-client"), did));
        Assert.False(registry.IsAllowed(Tenant, Principal("issuing-client"), DidFromKey(otherIssuer)));
        Assert.False(registry.IsAllowed(Tenant, Principal("issuing-client"), "did:key:untrusted"));
        // An unrelated tenant remains under its existing tenant-specific policy.
        Assert.True(registry.IsAllowed(OtherTenant, Principal("issuing-client"), did));
    }

    [Fact]
    public void EnforcedTenantRejectsUnauthenticatedAndAmbiguousClientClaims()
    {
        using var issuer = Key.Create(SignatureAlgorithm.Ed25519);
        string did = DidFromKey(issuer);
        var registry = Registry(Entries(did));

        Assert.False(registry.IsAllowed(Tenant, Principal("issuing-client", authenticated: false), did));
        Assert.False(registry.IsAllowed(Tenant, Principal("issuing-client", sub: "other-client"), did));
        Assert.False(registry.IsAllowed(Tenant, Principal("issuing-client", duplicateClient: true), did));
        Assert.False(registry.IsAllowed(Tenant, Principal("issuing-client", duplicateSubject: true), did));
        Assert.False(registry.IsAllowed(Tenant, Principal(null), did));
        Assert.False(registry.IsAllowed(Tenant, Principal("issuing-client"), null));
    }

    [Fact]
    public void EnforcedTenantWithoutGrantDeniesAllIssuers()
    {
        using var issuer = Key.Create(SignatureAlgorithm.Ed25519);
        var entries = Entries(DidFromKey(issuer));
        foreach (string key in entries.Keys.Where(key => key.StartsWith("IssuerSigningGrants:Grants:", StringComparison.Ordinal)).ToArray())
        {
            entries.Remove(key);
        }

        var registry = Registry(entries);
        Assert.False(registry.IsAllowed(Tenant, Principal("issuing-client"), DidFromKey(issuer)));
    }

    [Fact]
    public void ExplicitCredentialTypeGrantsRejectUnapprovedTypesForApprovedSigningKey()
    {
        using var issuer = Key.Create(SignatureAlgorithm.Ed25519);
        string did = DidFromKey(issuer);
        var entries = Entries(did);
        entries["IssuerSigningGrants:Grants:0:CredentialTypes:0"] = "MembershipCredential";
        entries["IssuerSigningGrants:Grants:0:CredentialTypes:1"] =
            "https://issuer.example/credentials#MembershipCredential";
        var registry = Registry(entries);

        Assert.True(registry.IsAllowed(Tenant, Principal("issuing-client"), did, "MembershipCredential"));
        Assert.True(registry.IsAllowed(Tenant, Principal("issuing-client"), did,
            "https://issuer.example/credentials#MembershipCredential"));
        Assert.False(registry.IsAllowed(Tenant, Principal("issuing-client"), did, "AdministratorCredential"));
        Assert.False(registry.IsAllowed(Tenant, Principal("issuing-client"), did, "membershipcredential"));
        Assert.False(registry.IsAllowed(Tenant, Principal("issuing-client"), did, null));
    }

    [Fact]
    public void MalformedCredentialTypeGrantPolicyFailsStartup()
    {
        using var issuer = Key.Create(SignatureAlgorithm.Ed25519);
        string did = DidFromKey(issuer);
        var duplicate = Entries(did);
        duplicate["IssuerSigningGrants:Grants:0:CredentialTypes:0"] = "MembershipCredential";
        duplicate["IssuerSigningGrants:Grants:0:CredentialTypes:1"] = "MembershipCredential";
        Assert.Throws<InvalidOperationException>(() => Registry(duplicate));

        var empty = Entries(did);
        empty["IssuerSigningGrants:Grants:0:CredentialTypes:0"] = "";
        Assert.Throws<InvalidOperationException>(() => Registry(empty));

        var nested = Entries(did);
        nested["IssuerSigningGrants:Grants:0:CredentialTypes:0:Injected"] = "AdministratorCredential";
        Assert.Throws<InvalidOperationException>(() => Registry(nested));

        var tooMany = Entries(did);
        for (int index = 0; index < 17; index++)
        {
            tooMany[$"IssuerSigningGrants:Grants:0:CredentialTypes:{index}"] = $"Type{index}";
        }
        Assert.Throws<InvalidOperationException>(() => Registry(tooMany));
    }

    [Fact]
    public void MalformedSubjectClaimGrantPolicyFailsStartup()
    {
        using var issuer = Key.Create(SignatureAlgorithm.Ed25519);
        string did = DidFromKey(issuer);

        var duplicate = Entries(did);
        duplicate["IssuerSigningGrants:Grants:0:SubjectClaimNames:0"] = "membership";
        duplicate["IssuerSigningGrants:Grants:0:SubjectClaimNames:1"] = "membership";
        Assert.Throws<InvalidOperationException>(() => Registry(duplicate));

        var empty = Entries(did);
        empty["IssuerSigningGrants:Grants:0:SubjectClaimNames:0"] = "";
        Assert.Throws<InvalidOperationException>(() => Registry(empty));

        var nested = Entries(did);
        nested["IssuerSigningGrants:Grants:0:SubjectClaimNames:0:Injected"] = "admin";
        Assert.Throws<InvalidOperationException>(() => Registry(nested));

        var unsafeName = Entries(did);
        unsafeName["IssuerSigningGrants:Grants:0:SubjectClaimNames:0"] = "@context";
        Assert.Throws<InvalidOperationException>(() => Registry(unsafeName));

        var oversized = Entries(did);
        for (int index = 0; index < 33; index++)
        {
            oversized[$"IssuerSigningGrants:Grants:0:SubjectClaimNames:{index}"] =
                $"Claim{index}";
        }
        Assert.Throws<InvalidOperationException>(() => Registry(oversized));
    }

    [Fact]
    public void MalformedOrOrphanedOrDuplicateSecurityPolicyFailsStartup()
    {
        using var issuer = Key.Create(SignatureAlgorithm.Ed25519);
        string did = DidFromKey(issuer);
        var extra = Entries(did);
        extra["IssuerSigningGrants:Grants:0:Unexpected"] = "ignored";
        Assert.Throws<InvalidOperationException>(() => Registry(extra));

        var invalidDid = Entries(did);
        invalidDid["IssuerSigningGrants:Grants:0:IssuerDid"] = "did:key:invalid";
        Assert.Throws<InvalidOperationException>(() => Registry(invalidDid));

        var repeatedTenant = Entries(did);
        repeatedTenant["IssuerSigningGrants:EnforcedTenants:1"] = Tenant.ToString("D");
        Assert.Throws<InvalidOperationException>(() => Registry(repeatedTenant));

        var duplicateGrant = Entries(did);
        foreach (var pair in Entries(did).Where(p => p.Key.StartsWith("IssuerSigningGrants:Grants:0:", StringComparison.Ordinal)))
        {
            duplicateGrant[pair.Key.Replace(":0:", ":1:", StringComparison.Ordinal)] = pair.Value;
        }
        Assert.Throws<InvalidOperationException>(() => Registry(duplicateGrant));

        var orphan = Entries(did);
        orphan["IssuerSigningGrants:EnforcedTenants:0"] = OtherTenant.ToString("D");
        Assert.Throws<InvalidOperationException>(() => Registry(orphan));

        var scalar = Entries(did);
        scalar["IssuerSigningGrants:Grants"] = "ignored";
        Assert.Throws<InvalidOperationException>(() => Registry(scalar));

        var nested = Entries(did);
        nested["IssuerSigningGrants:Grants:0:ClientId:Injected"] = "rogue";
        Assert.Throws<InvalidOperationException>(() => Registry(nested));
    }

    private static Dictionary<string, string?> Entries(string did) => new()
    {
        ["IssuerSigningGrants:EnforcedTenants:0"] = Tenant.ToString("D"),
        ["IssuerSigningGrants:Grants:0:TenantId"] = Tenant.ToString("D"),
        ["IssuerSigningGrants:Grants:0:ClientId"] = "issuing-client",
        ["IssuerSigningGrants:Grants:0:IssuerDid"] = did
    };

    private static IssuerSigningGrantRegistry Registry(Dictionary<string, string?> entries) =>
        new(new ConfigurationBuilder().AddInMemoryCollection(entries).Build());

    private static ClaimsPrincipal Principal(string? clientId, bool authenticated = true,
        string? sub = null, bool duplicateClient = false, bool duplicateSubject = false)
    {
        var claims = new List<Claim> { new("tenant_id", Tenant.ToString("D")) };
        if (clientId is not null)
        {
            claims.Add(new Claim("client_id", clientId));
            claims.Add(new Claim("sub", sub ?? clientId));
            if (duplicateClient)
            {
                claims.Add(new Claim("client_id", clientId));
            }
            if (duplicateSubject)
            {
                claims.Add(new Claim("sub", clientId));
            }
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, authenticated ? "signed-token" : null));
    }

    private static string DidFromKey(Key key)
    {
        var bytes = new byte[34];
        bytes[0] = 0xed;
        bytes[1] = 0x01;
        key.PublicKey.Export(KeyBlobFormat.RawPublicKey).CopyTo(bytes, 2);
        return "did:key:z" + SimpleBase.Base58.Bitcoin.Encode(bytes);
    }
}
