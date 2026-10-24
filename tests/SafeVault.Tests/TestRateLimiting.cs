using System.Net;
using System.Net.Http.Json;

namespace SafeVault.Tests;

public class TestRateLimiting
{
    [Test]
    public async Task RepeatedLoginAttempts_AreThrottled()
    {
        using var factory = new SafeVaultFactory(authPermitLimit: 3);
        var client = factory.CreateClient();

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++)
        {
            var response = await client.PostAsJsonAsync("/api/auth/login", new { username = "alice", password = "Wr0ng-Password!!" });
            statuses.Add(response.StatusCode);
        }

        Assert.That(statuses, Is.EqualTo(new[]
        {
            HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized,
            HttpStatusCode.TooManyRequests, HttpStatusCode.TooManyRequests,
        }));
    }
}
