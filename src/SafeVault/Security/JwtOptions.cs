namespace SafeVault.Security;

public sealed class JwtOptions
{
    public string Issuer { get; set; } = "SafeVault";
    public string Audience { get; set; } = "SafeVault";
    public int LifetimeMinutes { get; set; } = 30;

    /// <summary>HMAC-SHA256 signing key, at least 32 bytes. Supplied via configuration (user secrets / environment).</summary>
    public string Key { get; set; } = "";
}
