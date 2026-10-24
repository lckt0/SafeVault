using SafeVault.Security;

namespace SafeVault.Tests;

public class TestInputValidation
{
    [TestCase("alice")]
    [TestCase("bob_smith-01")]
    [TestCase("j.doe")]
    public void ValidUsernames_AreAccepted(string username) =>
        Assert.That(InputValidator.ValidateUsername(username), Is.Null);

    [TestCase(null)]
    [TestCase("")]
    [TestCase("ab")]
    [TestCase("this-username-is-far-too-long-to-be-valid")]
    [TestCase("admin' OR '1'='1")]
    [TestCase("admin'--")]
    [TestCase("x; DROP TABLE Users;")]
    [TestCase("<script>alert(1)</script>")]
    [TestCase("bob smith")]
    [TestCase("ali\u0000ce")]
    public void MaliciousOrMalformedUsernames_AreRejected(string? username) =>
        Assert.That(InputValidator.ValidateUsername(username), Is.Not.Null);

    [TestCase("alice@example.com")]
    [TestCase("first.last+tag@mail.example.org")]
    public void ValidEmails_AreAccepted(string email) =>
        Assert.That(InputValidator.ValidateEmail(email), Is.Null);

    [TestCase(null)]
    [TestCase("not-an-email")]
    [TestCase("a@b")]
    [TestCase("a..b@example.com")]
    [TestCase("\"<script>\"@example.com")]
    [TestCase("user@example.com' OR 1=1 --")]
    [TestCase("Alice <alice@example.com>")]
    public void InvalidEmails_AreRejected(string? email) =>
        Assert.That(InputValidator.ValidateEmail(email), Is.Not.Null);

    [TestCase("short1")]
    [TestCase("onlylettersnodigits")]
    [TestCase("123456789012345")]
    public void WeakPasswords_AreRejected(string password) =>
        Assert.That(InputValidator.ValidatePassword(password), Is.Not.Null);

    [Test]
    public void StrongPassword_IsAccepted() =>
        Assert.That(InputValidator.ValidatePassword("Corr3ct-Horse-Battery"), Is.Null);

    [TestCase("<img src=x onerror=alert(1)>")]
    [TestCase("Hello <b>world</b>")]
    public void NoteTitlesWithMarkup_AreRejected(string title) =>
        Assert.That(InputValidator.ValidateNoteTitle(title), Is.Not.Null);

    [Test]
    public void NoteContent_AllowsMultilineTextButRejectsControlCharacters()
    {
        Assert.Multiple(() =>
        {
            Assert.That(InputValidator.ValidateNoteContent("line 1\nline 2\ttabbed"), Is.Null);
            Assert.That(InputValidator.ValidateNoteContent("bell\u0007"), Is.Not.Null);
            Assert.That(InputValidator.ValidateNoteContent(new string('a', InputValidator.ContentMax + 1)), Is.Not.Null);
        });
    }

    [TestCase("user", true)]
    [TestCase("admin", true)]
    [TestCase("Admin", false)]
    [TestCase("superuser", false)]
    [TestCase(null, false)]
    public void Roles_AreAllowListed(string? role, bool valid) =>
        Assert.That(InputValidator.ValidateRole(role) is null, Is.EqualTo(valid));
}
