using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Tests;

public class TestSqlInjection
{
    private SafeVaultFactory _factory = null!;
    private UserRepository _users = null!;

    [SetUp]
    public async Task SetUp()
    {
        _factory = new SafeVaultFactory();
        _users = _factory.Services.GetRequiredService<UserRepository>();
        (await _factory.RegisterAsync(_factory.CreateClient(), "alice")).EnsureSuccessStatusCode();
    }

    [TearDown]
    public void TearDown() => _factory.Dispose();

    [TestCase("' OR '1'='1")]
    [TestCase("' OR 1=1 --")]
    [TestCase("alice' --")]
    [TestCase("alice'; DROP TABLE Users; --")]
    [TestCase("' UNION SELECT UserID, Username, Email, PasswordHash, Role FROM Users --")]
    public async Task UsernameLookup_TreatsInjectionPayloadAsLiteralData(string payload)
    {
        Assert.That(await _users.FindByUsernameAsync(payload), Is.Null);
        Assert.That(await _users.FindByUsernameAsync("alice"), Is.Not.Null, "Users table must still exist and be intact");
    }

    [TestCase("%")]
    [TestCase("_")]
    [TestCase("' OR 1=1 --")]
    public async Task Search_DoesNotExpandWildcardsOrInjectedConditions(string term) =>
        Assert.That(await _users.SearchAsync(term), Is.Empty);

    [Test]
    public async Task Search_StillFindsLegitimatePartialMatches()
    {
        var found = await _users.SearchAsync("LIC");
        Assert.That(found.Select(u => u.Username), Is.EqualTo(new[] { "alice" }));
    }

    [Test]
    public async Task Login_WithInjectionPayload_IsRejected()
    {
        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/login", new { username = "alice' --", password = "anything" });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

        response = await client.PostAsJsonAsync("/api/auth/login", new { username = "alice", password = "' OR '1'='1" });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Register_WithInjectionPayload_IsRejectedByValidation()
    {
        var response = await _factory.RegisterAsync(_factory.CreateClient(), "x'); DELETE FROM Users; --");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(await _users.CountAsync(), Is.EqualTo(2), "seeded admin + alice");
    }

    [Test]
    public async Task NoteContent_WithSqlPayload_IsStoredVerbatimAndHarmless()
    {
        const string payload = "'); DROP TABLE Notes; --";
        var client = await _factory.CreateUserClientAsync("bob");

        var created = await client.PostAsJsonAsync("/api/notes", new { title = "sql test", content = payload });
        Assert.That(created.StatusCode, Is.EqualTo(HttpStatusCode.Created));

        var notes = await client.GetFromJsonAsync<NoteResponse[]>("/api/notes");
        Assert.That(notes!.Single().Content, Is.EqualTo(payload));
    }

    [Test]
    public async Task AdminSearchEndpoint_WithInjectionPayload_ReturnsNoRows()
    {
        var admin = await _factory.CreateAdminClientAsync();
        var users = await admin.GetFromJsonAsync<UserResponse[]>("/api/admin/users?search=" + Uri.EscapeDataString("' OR '1'='1"));
        Assert.That(users, Is.Empty);
    }
}
