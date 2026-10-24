namespace SafeVault.Models;

public static class Roles
{
    public const string Admin = "admin";
    public const string User = "user";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal) { Admin, User };
}
