using HeroSSID.DidOperations.DidResolution;

namespace HeroSSID.DidOperations.Tests;

/// <summary>
/// Consumer compile contract: implementations written for the original public
/// resolution interface must remain valid when canonical support is introduced.
/// </summary>
public sealed class LegacyDidResolutionInterfaceTests
{
    [Fact]
    public async Task ExistingCustomResolverRemainsUsableWithoutCanonicalImplementation()
    {
        IDidResolutionService resolver = new LegacyResolver();
        var result = await resolver.ResolveAsync(
            "did:key:legacy", TestContext.Current.CancellationToken).ConfigureAwait(true);

        Assert.True(result.IsSuccess);
        Assert.Equal("did:key:legacy", result.DidIdentifier);
        Assert.Equal("{}", result.DidDocument);
    }

    private sealed class LegacyResolver : IDidResolutionService
    {
        public Task<DidResolutionResult> ResolveAsync(
            string didIdentifier, CancellationToken cancellationToken = default)
            => Task.FromResult(new DidResolutionResult
            {
                DidIdentifier = didIdentifier,
                DidDocument = "{}",
                Metadata = DidResolutionMetadata.CreateSuccess()
            });

        public Task<DidRetrievalResult?> GetByIdAsync(
            Guid id, CancellationToken cancellationToken = default)
            => Task.FromResult<DidRetrievalResult?>(null);

        public Task<bool> ExistsAsync(
            string didIdentifier, CancellationToken cancellationToken = default)
            => Task.FromResult(false);
    }
}
