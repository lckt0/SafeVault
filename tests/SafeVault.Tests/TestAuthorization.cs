using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using SafeVault.Models;

namespace SafeVault.Tests;

public class TestAuthorization
{
    private SafeVaultFactory _factory = null!;

    [SetUp]
    public void SetUp() => _factory = new SafeVaultFactory();

    [TearDown]
    public void TearDown() => _factory.Dispose();

    [Test]
    public async Task Login_WithValidCredentials_ReturnsUserToken()
    {
        var client = _factory.CreateClient();
        (await _factory.RegisterAsync(client, "alice")).EnsureSuccessStatusCode();

        var response = await client.PostAsJsonAsync("/api/auth/login", new { username = "alice", password = SafeVaultFactory.DefaultPassword });
        var token = await response.Content.ReadFromJsonAsync<TokenResponse>();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(token!.Role, Is.EqualTo(Roles.User));
        Assert.That(token.AccessToken.Split('.'), Has.Length.EqualTo(3));
    }

    [Test]
    public async Task Login_WrongPasswordAndUnknownUser_GetTheSameGenericError()
    {
        var client = _factory.CreateClient();
        (await _factory.RegisterAsync(client, "alice")).EnsureSuccessStatusCode();

        var wrongPassword = await client.PostAsJsonAsync("/api/auth/login", new { username = "alice", password = "Wr0ng-Password!!" });
        var unknownUser = await client.PostAsJsonAsync("/api/auth/login", new { username = "nobody", password = "Wr0ng-Password!!" });

        Assert.Multiple(async () =>
        {
            Assert.That(wrongPassword.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(unknownUser.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(await wrongPassword.Content.ReadAsStringAsync(), Is.EqualTo(await unknownUser.Content.ReadAsStringAsync()));
        });
    }

    [Test]
    public async Task DuplicateUsername_IsRejectedCaseInsensitively()
    {
        var client = _factory.CreateClient();
        (await _factory.RegisterAsync(client, "alice")).EnsureSuccessStatusCode();
        Assert.That((await _factory.RegisterAsync(client, "ALICE")).StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
    }

    [Test]
    public async Task Register_CannotSelfAssignAdminRole()
    {
        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/register",
            new { username = "mallory", email = "mallory@example.com", password = SafeVaultFactory.DefaultPassword, role = "admin" });
        var user = await response.Content.ReadFromJsonAsync<UserResponse>();

        Assert.That(user!.Role, Is.EqualTo(Roles.User));
    }

    [TestCase("/api/users/me")]
    [TestCase("/api/notes")]
    [TestCase("/api/admin/dashboard")]
    public async Task ProtectedEndpoints_WithoutToken_Return401(string path) =>
        Assert.That((await _factory.CreateClient().GetAsync(path)).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

    [Test]
    public async Task TamperedOrForgedTokens_AreRejected()
    {
        var client = await _factory.CreateUserClientAsync("alice");
        var token = client.DefaultRequestHeaders.Authorization!.Parameter!;
        var parts = token.Split('.');

        // Same header and payload, signature replaced: the signature check must fail.
        var forged = $"{parts[0]}.{parts[1]}.{Convert.ToBase64String(new byte[32]).TrimEnd('=').Replace('+', '-').Replace('/', '_')}";
        // Unsigned "alg":"none" token claiming admin.
        var none = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.";

        foreach (var bad in new[] { forged, none, "not-a-jwt" })
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bad);
            Assert.That((await client.GetAsync("/api/notes")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized), bad);
        }
    }

    [TestCase("/api/admin/dashboard")]
    [TestCase("/api/admin/users?search=a")]
    public async Task RegularUser_IsForbiddenFromAdminEndpoints(string path)
    {
        var client = await _factory.CreateUserClientAsync("alice");
        Assert.That((await client.GetAsync(path)).StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task RegularUser_CannotChangeRoles()
    {
        var client = await _factory.CreateUserClientAsync("alice");
        var response = await client.PutAsJsonAsync("/api/admin/users/alice/role", new { role = "admin" });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task Admin_CanUseDashboardAndPromoteUsers()
    {
        var admin = await _factory.CreateAdminClientAsync();
        (await _factory.CreateUserClientAsync("alice")).Dispose();

        Assert.That((await admin.GetAsync("/api/admin/dashboard")).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var promote = await admin.PutAsJsonAsync("/api/admin/users/alice/role", new { role = "admin" });
        Assert.That(promote.StatusCode, Is.EqualTo(HttpStatusCode.NoContent));

        var invalidRole = await admin.PutAsJsonAsync("/api/admin/users/alice/role", new { role = "root" });
        Assert.That(invalidRole.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));

        // The new role takes effect with the next token.
        var client = _factory.CreateClient();
        var login = await client.PostAsJsonAsync("/api/auth/login", new { username = "alice", password = SafeVaultFactory.DefaultPassword });
        Assert.That((await login.Content.ReadFromJsonAsync<TokenResponse>())!.Role, Is.EqualTo(Roles.Admin));
    }

    [Test]
    public async Task Users_CannotReadOrDeleteOtherUsersNotes_ButAdminsCan()
    {
        var alice = await _factory.CreateUserClientAsync("alice");
        var bob = await _factory.CreateUserClientAsync("bob");
        var admin = await _factory.CreateAdminClientAsync();

        var created = await alice.PostAsJsonAsync("/api/notes", new { title = "private", content = "alice's secret" });
        var note = (await created.Content.ReadFromJsonAsync<NoteResponse>())!;

        Assert.Multiple(async () =>
        {
            Assert.That((await bob.GetAsync($"/api/notes/{note.Id}")).StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            Assert.That((await bob.GetAsync($"/api/notes/{note.Id}/preview")).StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            Assert.That((await bob.DeleteAsync($"/api/notes/{note.Id}")).StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
            Assert.That(await bob.GetFromJsonAsync<NoteResponse[]>("/api/notes"), Is.Empty);
            Assert.That((await alice.GetAsync($"/api/notes/{note.Id}")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That((await admin.GetAsync($"/api/notes/{note.Id}")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });

        Assert.That((await admin.DeleteAsync($"/api/notes/{note.Id}")).StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
    }
}
