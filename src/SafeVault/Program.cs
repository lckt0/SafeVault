using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Endpoints;
using SafeVault.Security;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

var jwt = config.GetSection("Jwt").Get<JwtOptions>() ?? new JwtOptions();
if (string.IsNullOrEmpty(jwt.Key))
{
    if (!builder.Environment.IsDevelopment())
        throw new InvalidOperationException("Jwt:Key must be configured (environment variable Jwt__Key or user secrets).");
    // Development only: an ephemeral key, so tokens simply expire when the app restarts.
    jwt.Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
}
if (Encoding.UTF8.GetByteCount(jwt.Key) < 32)
    throw new InvalidOperationException("Jwt:Key must be at least 32 bytes.");

builder.Services.Configure<JwtOptions>(o =>
{
    o.Issuer = jwt.Issuer;
    o.Audience = jwt.Audience;
    o.LifetimeMinutes = jwt.LifetimeMinutes;
    o.Key = jwt.Key;
});

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(new SqliteConnectionFactory(
    config.GetConnectionString("SafeVault") ?? throw new InvalidOperationException("Connection string 'SafeVault' is missing.")));
builder.Services.AddSingleton<UserRepository>();
builder.Services.AddSingleton<NoteRepository>();
builder.Services.AddSingleton<AuthService>();
builder.Services.AddSingleton<TokenService>();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.MapInboundClaims = false;
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwt.Issuer,
            ValidateAudience = true,
            ValidAudience = jwt.Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = TokenService.CreateKey(jwt.Key),
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = TokenService.NameClaim,
            RoleClaimType = TokenService.RoleClaim,
        };
    });
builder.Services.AddAuthorization(Policies.Configure);

builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    var permits = config.GetValue("RateLimiting:AuthPermitLimit", 10);
    var window = TimeSpan.FromSeconds(config.GetValue("RateLimiting:AuthWindowSeconds", 60));
    o.AddPolicy(AuthEndpoints.RateLimitPolicy, context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = permits, Window = window, QueueLimit = 0 }));
});

// ASP.NET Core's default JSON encoder leaves <, > and ' unescaped; the strict encoder emits \u003C etc.,
// so a JSON response can never be interpreted as HTML even if it is rendered in the wrong context.
builder.Services.ConfigureHttpJsonOptions(o => o.SerializerOptions.Encoder = JavaScriptEncoder.Default);
builder.Services.AddProblemDetails();

var app = builder.Build();

await app.Services.GetRequiredService<SqliteConnectionFactory>().EnsureSchemaAsync();
await app.Services.GetRequiredService<AuthService>().EnsureAdminAsync(config["Seed:AdminUsername"], config["Seed:AdminPassword"]);

app.UseExceptionHandler();
if (!app.Environment.IsDevelopment())
    app.UseHsts();
app.UseHttpsRedirection();
app.UseSecurityHeaders();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapAuthEndpoints();
app.MapNoteEndpoints();
app.MapAdminEndpoints();

app.Run();

public partial class Program;
