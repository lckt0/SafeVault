using SafeVault.Security;

namespace SafeVault.Tests;

public class TestPasswordHashing
{
    private const string Password = "Corr3ct-Horse-Battery";

    [Test]
    public void Hash_IsSaltedAndNeverContainsThePlaintext()
    {
        var first = PasswordHasher.Hash(Password);
        var second = PasswordHasher.Hash(Password);

        Assert.Multiple(() =>
        {
            Assert.That(first, Does.StartWith("PBKDF2-SHA512$210000$"));
            Assert.That(first, Does.Not.Contain(Password));
            Assert.That(first, Is.Not.EqualTo(second), "two hashes of the same password must use different salts");
        });
    }

    [Test]
    public void Verify_AcceptsOnlyTheCorrectPassword()
    {
        var hash = PasswordHasher.Hash(Password);

        Assert.Multiple(() =>
        {
            Assert.That(PasswordHasher.Verify(Password, hash), Is.True);
            Assert.That(PasswordHasher.Verify("corr3ct-horse-battery", hash), Is.False);
            Assert.That(PasswordHasher.Verify("", hash), Is.False);
        });
    }

    [TestCase("")]
    [TestCase("plaintext-password")]
    [TestCase("PBKDF2-SHA512$abc$salt$hash")]
    [TestCase("PBKDF2-SHA512$1000$not base64!$xx")]
    [TestCase("MD5$1$c2FsdA==$aGFzaA==")]
    public void Verify_RejectsMalformedHashes(string stored) =>
        Assert.That(PasswordHasher.Verify(Password, stored), Is.False);
}
