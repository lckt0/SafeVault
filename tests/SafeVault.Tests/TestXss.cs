using System.Net;
using System.Net.Http.Json;
using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Tests;

public class TestXss
{
    private const string ScriptPayload = "<script>alert('xss')</script>";
    private SafeVaultFactory _factory = null!;

    [SetUp]
    public void SetUp() => _factory = new SafeVaultFactory();

    [TearDown]
    public void TearDown() => _factory.Dispose();

    [Test]
    public async Task Register_WithScriptInUsernameOrEmail_IsRejected()
    {
        var client = _factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/register",
            new { username = ScriptPayload, email = "\"><img src=x onerror=alert(1)>@x.com", password = SafeVaultFactory.DefaultPassword });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        var problem = await response.Content.ReadFromJsonAsync<ValidationProblem>();
        Assert.That(problem!.Errors.Keys, Is.EquivalentTo(new[] { "username", "email" }));
    }

    [Test]
    public async Task NoteTitle_WithMarkup_IsRejected()
    {
        var client = await _factory.CreateUserClientAsync("alice");
        var response = await client.PostAsJsonAsync("/api/notes", new { title = ScriptPayload, content = "body" });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task HtmlPreview_EncodesStoredScript()
    {
        var client = await _factory.CreateUserClientAsync("alice");
        var created = await client.PostAsJsonAsync("/api/notes", new { title = "Quote's \"test\" & more", content = ScriptPayload });
        var note = (await created.Content.ReadFromJsonAsync<NoteResponse>())!;

        var response = await client.GetAsync($"/api/notes/{note.Id}/preview");
        var html = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.Content.Headers.ContentType!.MediaType, Is.EqualTo("text/html"));
            Assert.That(html, Does.Not.Contain("<script>"));
            Assert.That(html, Does.Contain("&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"));
            Assert.That(html, Does.Contain("Quote&#x27;s &quot;test&quot; &amp; more"));
        });
    }

    [Test]
    public async Task JsonResponses_EscapeHtmlCharacters()
    {
        var client = await _factory.CreateUserClientAsync("alice");
        await client.PostAsJsonAsync("/api/notes", new { title = "payload", content = ScriptPayload });

        var raw = await client.GetStringAsync("/api/notes");
        Assert.That(raw, Does.Not.Contain("<script>"));
        Assert.That((await client.GetFromJsonAsync<NoteResponse[]>("/api/notes"))!.Single().Content, Is.EqualTo(ScriptPayload));
    }

    [Test]
    public async Task Responses_CarrySecurityHeaders()
    {
        var response = await _factory.CreateClient().GetAsync("/");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(response.Headers.GetValues("Content-Security-Policy").Single(), Is.EqualTo(SecurityHeaders.ContentSecurityPolicy));
            Assert.That(response.Headers.GetValues("X-Content-Type-Options").Single(), Is.EqualTo("nosniff"));
            Assert.That(response.Headers.GetValues("X-Frame-Options").Single(), Is.EqualTo("DENY"));
        });
    }

    [Test]
    public async Task FrontEnd_NeverUsesInnerHtml()
    {
        var script = await _factory.CreateClient().GetStringAsync("/app.js");
        Assert.That(script, Does.Not.Contain(".innerHTML").And.Not.Contain("document.write"));
    }

    private sealed record ValidationProblem(Dictionary<string, string[]> Errors);
}
