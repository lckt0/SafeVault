namespace SafeVault.Endpoints;

/// <summary>Collects validator messages into the dictionary shape expected by Results.ValidationProblem.</summary>
internal sealed class Validation
{
    private readonly Dictionary<string, string[]> _errors = new(StringComparer.Ordinal);

    public Validation Check(string field, string? error)
    {
        if (error is not null)
            _errors[field] = [error];
        return this;
    }

    public bool IsValid => _errors.Count == 0;

    public IResult Problem() => Results.ValidationProblem(_errors);
}
