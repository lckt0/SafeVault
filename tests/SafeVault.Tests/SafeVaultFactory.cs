using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using SafeVault.Models;

namespace SafeVault.Tests;

/// <summary>Runs the real application pipeline against a throw-away SQLite database.</summary>
public sealed class SafeVaultFactory(int authPermitLimit = 1000) : WebApplicationFactory<Program>
{
    public const string AdminUsername = "admin";
    public const string AdminPassword = "Adm1n-Passw0rd!";
    public const string DefaultPassword = "Corr3ct-Horse-Battery";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"safevault-test-{Guid.NewGuid():N}.db");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ConnectionStrings:SafeVault", $"Data Source={_dbPath}");
        builder.UseSetting("Jwt:Key", "test-signing-key-that-is-at-least-32-bytes-long");
        builder.UseSetting("Seed:AdminUsername", AdminUsername);
        builder.UseSetting("Seed:AdminPassword", AdminPassword);
        builder.UseSetting("RateLimiting:AuthPermitLimit", authPermitLimit.ToString());
    }

    public string ConnectionString => $"Data Source={_dbPath}";

    public async Task<HttpResponseMessage> RegisterAsync(HttpClient client, string username, string password = DefaultPassword) =>
        await client.PostAsJsonAsync("/api/auth/register", new { username, email = $"{username}@example.com", password });

    public async Task<HttpClient> CreateUserClientAsync(string username, string password = DefaultPassword)
    {
        var client = CreateClient();
        (await RegisterAsync(client, username, password)).EnsureSuccessStatusCode();
        return await LoginAsync(client, username, password);
    }

    public async Task<HttpClient> CreateAdminClientAsync() => await LoginAsync(CreateClient(), AdminUsername, AdminPassword);

    private static async Task<HttpClient> LoginAsync(HttpClient client, string username, string password)
    {
        var response = await client.PostAsJsonAsync("/api/auth/login", new { username, password });
        response.EnsureSuccessStatusCode();
        var token = (await response.Content.ReadFromJsonAsync<TokenResponse>())!;
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token.AccessToken);
        return client;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        SqliteConnection.ClearAllPools();
        File.Delete(_dbPath);
    }
}
