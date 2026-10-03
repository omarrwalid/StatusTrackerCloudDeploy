using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.RateLimiting;
using ClauseTracker;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseWindowsService(o => o.ServiceName = "ClauseTrackerServer");
builder.WebHost.ConfigureKestrel(k => { k.Limits.MaxRequestBodySize = 64 * 1024; k.AddServerHeader = false; });

// Cloud hosts (Render, Railway, Fly, Azure…) tell us which port to listen on via PORT.
if (Environment.GetEnvironmentVariable("PORT") is { Length: > 0 } port)
    builder.Configuration["Kestrel:Endpoints:Http:Url"] = $"http://0.0.0.0:{port}";

// The host terminates HTTPS and forwards to us; trust its X-Forwarded-* headers so we see the real client IP.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    o.KnownNetworks.Clear(); o.KnownProxies.Clear();
});
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = 429;
    o.AddPolicy("rpc", ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "?",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 240, Window = TimeSpan.FromMinutes(1) }));
});

var app = builder.Build();
app.UseForwardedHeaders();
app.UseRateLimiter();
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["Cache-Control"] = "no-store";
    if (ctx.Request.IsHttps) ctx.Response.Headers["Strict-Transport-Security"] = "max-age=31536000";
    await next();
});

// DATABASE_URL (Render/Railway/Neon style) wins over appsettings.json.
var conn = Environment.GetEnvironmentVariable("DATABASE_URL")
    ?? builder.Configuration.GetConnectionString("Default")
    ?? throw new InvalidOperationException("Set DATABASE_URL or ConnectionStrings:Default.");
Db.Configure(Db.NormalizeConnectionString(conn));

// The database may still be starting — retry for up to ~2 minutes.
for (int attempt = 1; ; attempt++)
{
    try { Db.Init(); app.Logger.LogInformation("Database ready."); break; }
    catch (Exception e) when (attempt < 24)
    {
        app.Logger.LogWarning("Database not ready ({Message}); retry {N}/24", e.Message, attempt);
        Thread.Sleep(5000);
    }
}

const int SessionHours = 12;
static string HashToken(string t) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(t)));

// Sessions live in PostgreSQL, so redeploys/restarts don't log anybody out.
static User? LoadSession(string token)
{
    using var c = Db.Open();
    var r = Db.One(c, @"UPDATE sessions s SET expires_at = now() + interval '12 hours'
        FROM users u WHERE s.token_hash=@h AND s.expires_at > now() AND u.id=s.user_id AND u.active=1
        RETURNING u.id, u.username, u.display_name, u.department, u.role", ("@h", HashToken(token)));
    return r == null ? null : new User((long)r["id"]!, (string)r["username"]!, (string)r["display_name"]!, (string)r["department"]!, (string)r["role"]!);
}

static string CreateSession(User u)
{
    var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    using var c = Db.Open();
    Db.Exec(c, "DELETE FROM sessions WHERE expires_at < now()");
    Db.Exec(c, "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(@h,@u, now() + interval '12 hours')", ("@h", HashToken(token)), ("@u", u.Id));
    return token;
}

static void DeleteSession(string token)
{
    using var c = Db.Open();
    Db.Exec(c, "DELETE FROM sessions WHERE token_hash=@h", ("@h", HashToken(token)));
}

app.MapGet("/api/health", () => Results.Json(new { ok = true, time = DateTime.UtcNow }));

app.MapPost("/api/rpc", async (HttpContext ctx) =>
{
    JsonDocument doc;
    try { doc = await JsonDocument.ParseAsync(ctx.Request.Body); }
    catch { return Results.Json(new { ok = false, error = "طلب غير صالح." }); }

    using (doc)
    {
        var root = doc.RootElement;
        var method = root.TryGetProperty("method", out var m) ? m.GetString() ?? "" : "";
        var args = root.TryGetProperty("args", out var a) ? a : default;

        try
        {
            string? token = null;
            var auth = ctx.Request.Headers.Authorization.ToString();
            if (auth.StartsWith("Bearer ")) token = auth[7..];
            var session = new Session { Ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "?" };
            if (token != null) session.Me = LoadSession(token);
            if (session.Me == null) token = null;

            var result = Api.Handle(method, args, session);

            string? newToken = null;
            if (method == "logout" && token != null) DeleteSession(token);
            else if (session.Me != null && token == null) newToken = CreateSession(session.Me);
            return Results.Json(new { ok = true, result, token = newToken });
        }
        catch (AppError e) { return Results.Json(new { ok = false, error = e.Message }); }
        catch (Exception e)
        {
            app.Logger.LogError(e, "RPC {Method} failed", method);
            return Results.Json(new { ok = false, error = "خطأ في الخادم. حاول مرة أخرى." });
        }
    }
}).RequireRateLimiting("rpc");

app.Run();
