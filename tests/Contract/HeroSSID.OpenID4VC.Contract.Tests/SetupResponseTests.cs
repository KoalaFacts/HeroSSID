using System.Net;
using System.Text;
using Xunit.Sdk;

namespace HeroSSID.OpenID4VC.Contract.Tests;

public class SetupResponseTests
{
    [Theory]
    [InlineData("Create issuer DID", HttpStatusCode.Created, "did")]
    [InlineData("Create holder DID", HttpStatusCode.Created, "did")]
    [InlineData("Issue setup credential", HttpStatusCode.Created, "credential")]
    [InlineData("Obtain OAuth access token", HttpStatusCode.OK, "access_token")]
    public async Task ReadRequiredStringAsync_ServerError_ReportsOperationStatusAndBodyBeforeParsingJson(
        string operation,
        HttpStatusCode expectedStatus,
        string propertyName)
    {
        const string body = "<html>setup failed: entropy source unavailable</html>";
        using var response = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent(body)
        };

        var exception = await Assert.ThrowsAsync<TrueException>(() =>
            SetupResponse.ReadRequiredStringAsync(response, expectedStatus, operation, propertyName));

        Assert.Contains(operation, exception.Message, StringComparison.Ordinal);
        Assert.Contains($"expected HTTP {(int)expectedStatus} ({expectedStatus})", exception.Message, StringComparison.Ordinal);
        Assert.Contains("received HTTP 500 (InternalServerError)", exception.Message, StringComparison.Ordinal);
        Assert.Contains(body, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ReadRequiredStringAsync_ServerProblemJson_ReportsFailureBeforeReadingMissingDid()
    {
        const string body = "{\"title\":\"Internal Server Error\",\"status\":500,\"detail\":\"An unexpected error occurred while creating the DID\"}";
        using var response = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/problem+json")
        };

        var exception = await Assert.ThrowsAsync<TrueException>(() =>
            SetupResponse.ReadRequiredStringAsync(response, HttpStatusCode.Created, "Create issuer DID", "did"));

        Assert.Contains("Create issuer DID", exception.Message, StringComparison.Ordinal);
        Assert.Contains("expected HTTP 201 (Created)", exception.Message, StringComparison.Ordinal);
        Assert.Contains("received HTTP 500 (InternalServerError)", exception.Message, StringComparison.Ordinal);
        Assert.Contains(body, exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(HttpStatusCode.OK, HttpStatusCode.Created)]
    [InlineData(HttpStatusCode.Created, HttpStatusCode.OK)]
    public async Task ReadRequiredStringAsync_WrongSuccessfulStatus_RejectsResponse(
        HttpStatusCode actualStatus,
        HttpStatusCode expectedStatus)
    {
        const string operation = "Prepare contract test";
        const string body = "{\"value\":\"setup-value\"}";
        using var response = new HttpResponseMessage(actualStatus)
        {
            Content = new StringContent(body)
        };

        var exception = await Assert.ThrowsAsync<TrueException>(() =>
            SetupResponse.ReadRequiredStringAsync(response, expectedStatus, operation, "value"));

        Assert.Contains(operation, exception.Message, StringComparison.Ordinal);
        Assert.Contains($"expected HTTP {(int)expectedStatus} ({expectedStatus})", exception.Message, StringComparison.Ordinal);
        Assert.Contains($"received HTTP {(int)actualStatus} ({actualStatus})", exception.Message, StringComparison.Ordinal);
        Assert.Contains(body, exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Create issuer DID", HttpStatusCode.Created, "did", "did:key:issuer")]
    [InlineData("Create holder DID", HttpStatusCode.Created, "did", "did:key:holder")]
    [InlineData("Issue setup credential", HttpStatusCode.Created, "credential", "header.payload.signature")]
    [InlineData("Obtain OAuth access token", HttpStatusCode.OK, "access_token", "test-access-token")]
    public async Task ReadRequiredStringAsync_ExpectedStatus_ReturnsRequiredValue(
        string operation,
        HttpStatusCode expectedStatus,
        string propertyName,
        string expectedValue)
    {
        using var response = new HttpResponseMessage(expectedStatus)
        {
            Content = new StringContent($"{{\"{propertyName}\":\"{expectedValue}\"}}")
        };

        var value = await SetupResponse.ReadRequiredStringAsync(response, expectedStatus, operation, propertyName);

        Assert.Equal(expectedValue, value);
    }
}
