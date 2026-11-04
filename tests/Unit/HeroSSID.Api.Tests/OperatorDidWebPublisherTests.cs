using System.Text;
using HeroSSID.Api.Features.Dids;
using HeroSSID.DidOperations.DidMethods;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using NSec.Cryptography;

namespace HeroSSID.Api.Tests;

public sealed class OperatorDidWebPublisherTests
{
    [Fact]
    public void PublicationDisabledUnlessOperatorEnrollsExactPublicKey()
    {
        var disabled = NewPublisher([]);
        Assert.False(disabled.IsEnabled);
        Assert.Null(disabled.Did);
        Assert.Null(disabled.Document);

        using var key = Key.Create(SignatureAlgorithm.Ed25519);
        byte[] publicKey = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
        var enabled = NewPublisher(Entries(publicKey));
        Assert.True(enabled.IsEnabled);
        Assert.Equal("did:web:issuer.example", enabled.Did);
        Assert.NotNull(enabled.Document);
        Assert.True(DidWebPublishedKeyMatch.MatchesExpectedDocument(
            enabled.Did!, publicKey, enabled.Document));
        Assert.Equal("https://issuer.example/.well-known/did.json",
            DidWebMethod.GetDocumentUri(enabled.Did!).AbsoluteUri);
    }

    [Fact]
    public void MissingUnknownNoncanonicalAndZeroPublicKeyConfigurationsFailClosed()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519);
        var entries = Entries(key.PublicKey.Export(KeyBlobFormat.RawPublicKey));

        var unexpected = new Dictionary<string, string?>(entries)
        {
            ["DidWebPublication:NewTrust"] = "any"
        };
        Assert.Throws<InvalidOperationException>(() => NewPublisher(unexpected));

        var missing = new Dictionary<string, string?>(entries);
        missing.Remove("DidWebPublication:PublicKeyHex");
        Assert.Throws<InvalidOperationException>(() => NewPublisher(missing));

        var badDomain = new Dictionary<string, string?>(entries)
        {
            ["DidWebPublication:Domain"] = "Issuer.Example"
        };
        Assert.Throws<InvalidOperationException>(() => NewPublisher(badDomain));

        var zero = new Dictionary<string, string?>(entries)
        {
            ["DidWebPublication:PublicKeyHex"] = new string('0', 64)
        };
        Assert.Throws<InvalidOperationException>(() => NewPublisher(zero));
    }

    [Fact]
    public async Task HttpsExactHostServesDocumentButWrongHostSchemeOrPortDoesNot()
    {
        using var key = Key.Create(SignatureAlgorithm.Ed25519);
        var enabled = NewPublisher(Entries(key.PublicKey.Export(KeyBlobFormat.RawPublicKey)));

        DefaultHttpContext valid = Context("https", "issuer.example");
        await enabled.Handle(valid).ExecuteAsync(valid).ConfigureAwait(true);
        Assert.Equal(StatusCodes.Status200OK, valid.Response.StatusCode);
        Assert.Equal("application/did+ld+json", valid.Response.ContentType);
        Assert.Equal("no-store", valid.Response.Headers.CacheControl.ToString());
        valid.Response.Body.Position = 0;
        using var reader = new StreamReader(valid.Response.Body, Encoding.UTF8);
        Assert.Equal(enabled.Document, await reader.ReadToEndAsync().ConfigureAwait(true));

        foreach (var pair in new[]
        {
            ("http", "issuer.example"),
            ("https", "other.example"),
            ("https", "issuer.example:8443")
        })
        {
            DefaultHttpContext denied = Context(pair.Item1, pair.Item2);
            await enabled.Handle(denied).ExecuteAsync(denied).ConfigureAwait(true);
            Assert.Equal(StatusCodes.Status404NotFound, denied.Response.StatusCode);
            Assert.Equal(0, denied.Response.Body.Length);
        }
    }

    private static OperatorDidWebPublisher NewPublisher(Dictionary<string, string?> values) =>
        new(new ConfigurationBuilder().AddInMemoryCollection(values).Build());

    private static Dictionary<string, string?> Entries(byte[] publicKey) => new()
    {
        ["DidWebPublication:Domain"] = "issuer.example",
        ["DidWebPublication:PublicKeyHex"] = Convert.ToHexStringLower(publicKey)
    };

    private static DefaultHttpContext Context(string scheme, string host)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = scheme;
        context.Request.Host = new HostString(host);
        context.Response.Body = new MemoryStream();
        return context;
    }
}
