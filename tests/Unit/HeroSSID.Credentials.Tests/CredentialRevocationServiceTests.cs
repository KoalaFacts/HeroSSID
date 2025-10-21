using HeroSSID.Credentials.CredentialRevocation;
using System;
using System.Threading.Tasks;
using Xunit;

namespace HeroSSID.Credentials.Tests;

/// <summary>
/// TDD tests for ICredentialRevocationService - T044
/// Tests placeholder revocation service (throws NotImplementedException)
/// </summary>
public sealed class CredentialRevocationServiceTests
{
    // T044: Placeholder test - service should throw NotImplementedException
    [Fact]
    public async Task CheckRevocationStatusAsyncThrowsNotImplementedException()
    {
        // Arrange
        var service = new CredentialRevocationService();
        var credentialJwt = "mock.jwt.token";

        // Act & Assert
        await Assert.ThrowsAsync<NotImplementedException>(async () =>
            await service.CheckRevocationStatusAsync(credentialJwt).ConfigureAwait(true)).ConfigureAwait(true);
    }
}
