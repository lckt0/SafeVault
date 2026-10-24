using System.Net.Mail;
using System.Text.RegularExpressions;
using SafeVault.Models;

namespace SafeVault.Security;

/// <summary>
/// Allow-list validation for every value that enters the application.
/// Each method returns null when the value is valid, otherwise a user-facing error message.
/// </summary>
public static partial class InputValidator
{
    public const int UsernameMin = 3, UsernameMax = 32;
    public const int EmailMax = 254;
    public const int PasswordMin = 12, PasswordMax = 128;
    public const int TitleMax = 100, ContentMax = 4000;

    [GeneratedRegex("^[A-Za-z0-9_.-]+$")]
    private static partial Regex UsernamePattern();

    [GeneratedRegex(@"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$")]
    private static partial Regex EmailPattern();

    public static string? ValidateUsername(string? username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return "Username is required.";
        if (username.Length is < UsernameMin or > UsernameMax)
            return $"Username must be {UsernameMin}-{UsernameMax} characters.";
        if (!UsernamePattern().IsMatch(username))
            return "Username may only contain letters, digits, '.', '_' and '-'.";
        return null;
    }

    public static string? ValidateEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return "Email is required.";
        if (email.Length > EmailMax || !EmailPattern().IsMatch(email))
            return "Email address is not valid.";
        // MailAddress also rejects structurally broken addresses the regex lets through (e.g. "a..b@x.com").
        if (!MailAddress.TryCreate(email, out var parsed) || parsed.Address != email || email.Contains(".."))
            return "Email address is not valid.";
        return null;
    }

    public static string? ValidatePassword(string? password)
    {
        if (string.IsNullOrEmpty(password))
            return "Password is required.";
        if (password.Length is < PasswordMin or > PasswordMax)
            return $"Password must be {PasswordMin}-{PasswordMax} characters.";
        if (!password.Any(char.IsLetter) || !password.Any(char.IsDigit))
            return "Password must contain at least one letter and one digit.";
        return null;
    }

    public static string? ValidateNoteTitle(string? title)
    {
        if (string.IsNullOrWhiteSpace(title))
            return "Title is required.";
        if (title.Length > TitleMax)
            return $"Title must be at most {TitleMax} characters.";
        if (title.Any(char.IsControl) || ContainsMarkup(title))
            return "Title may not contain markup or control characters.";
        return null;
    }

    public static string? ValidateNoteContent(string? content)
    {
        if (string.IsNullOrWhiteSpace(content))
            return "Content is required.";
        if (content.Length > ContentMax)
            return $"Content must be at most {ContentMax} characters.";
        if (content.Any(c => char.IsControl(c) && c is not ('\n' or '\r' or '\t')))
            return "Content may not contain control characters.";
        return null;
    }

    public static string? ValidateRole(string? role) =>
        role is not null && Roles.All.Contains(role) ? null : "Role must be 'user' or 'admin'.";

    /// <summary>True when the value contains characters that start HTML tags or entities.</summary>
    public static bool ContainsMarkup(string value) => value.IndexOfAny(['<', '>']) >= 0;
}
