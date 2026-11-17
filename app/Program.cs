using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Unbreakable.Authz;
using Unbreakable.Data;
using Unbreakable.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<UnbreakableContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("Unbreakable")));

// ------------------------------------------------------------------ authenticatie
// Opdracht 4: wie je bent, komt enkel nog uit een access token van Keycloak.
// De header X-User bestaat niet meer.
var oidc = builder.Configuration.GetSection("Oidc");

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Discovery en JWKS haalt de app intern op (http://keycloak:8080, enkel
        // op het Docker-netwerk). De issuer in het token blijft de publieke URL.
        options.MetadataAddress = oidc["MetadataAddress"];
        options.RequireHttpsMetadata = false;
        options.MapInboundClaims = false;   // claims heten zoals in het token (sub, azp, ...)

        options.TokenValidationParameters = new TokenValidationParameters
        {
            // 1. handtekening: met een publieke sleutel van Keycloak (JWKS), enkel RS256
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
            // 2. issuer: uitgegeven door onze realm
            ValidateIssuer = true,
            ValidIssuer = oidc["Issuer"],
            // 3. audience: bedoeld voor deze API
            ValidateAudience = true,
            ValidAudience = oidc["Audience"],
            // 4. geldigheid: exp en nbf, met weinig speling
            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = "preferred_username",
        };

        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                var principal = context.Principal;
                // 5. het is een access token, geen ID token of refresh token
                if (principal?.FindFirstValue("typ") != "Bearer")
                {
                    context.Fail("Geen access token");
                }
                // 6. uitgegeven aan onze SPA
                else if (principal.FindFirstValue("azp") != oidc["ClientId"])
                {
                    context.Fail("Token van een andere client");
                }
                // 7. de claims die we nodig hebben, zijn er
                else if (string.IsNullOrEmpty(principal.FindFirstValue("sub")) ||
                         string.IsNullOrEmpty(principal.FindFirstValue("preferred_username")))
                {
                    context.Fail("sub of preferred_username ontbreekt");
                }
                return Task.CompletedTask;
            },
        };
    });

// Enkel "ingelogd zijn" (authenticatie). Wat je mag, beslist OpenFGA.
builder.Services.AddAuthorization();

var app = builder.Build();

// ------------------------------------------------------------------ databank
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<UnbreakableContext>();

    for (var attempt = 1; attempt <= 30; attempt++)
    {
        try
        {
            context.Database.EnsureCreated();
            break;
        }
        catch (Exception ex) when (attempt < 30)
        {
            app.Logger.LogWarning("Databank nog niet bereikbaar ({Error}), poging {Attempt}", ex.Message, attempt);
            Thread.Sleep(2000);
        }
    }
}

// ------------------------------------------------------------------ PDP
var pdp = await Pdp.ConnectAsync(app.Configuration, app.Logger);

// Geen UseDeveloperExceptionPage meer (stacktraces in productie, opdracht 2)
// en geen CORS meer: de SPA, de API en Keycloak delen dezelfde origin.
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => "ok");

var api = app.MapGroup("/api")
    .RequireAuthorization()
    .AddEndpointFilter(async (context, next) =>
    {
        // Houd het adresboek bij: naam -> sub (zie Models/AppUser.cs).
        var db = context.HttpContext.RequestServices.GetRequiredService<UnbreakableContext>();
        await RememberUserAsync(db, context.HttpContext.User);
        return await next(context);
    });

api.MapGet("/me", (ClaimsPrincipal user) =>
    Results.Ok(new { username = Username(user), sub = Sub(user) }));

// Het adresboek: om een ontvanger te kiezen. Bevat geen berichten.
api.MapGet("/users", async (UnbreakableContext db) =>
    Results.Ok(await db.Users.OrderBy(u => u.Username).Select(u => u.Username).ToListAsync()));

// Inbox: de PDP beslist WELKE berichten (ListObjects can_read). De databank
// levert daarna enkel de inhoud van die id's. "from" is een filter op wat je
// al mag zien, geen autorisatie.
api.MapGet("/messages", (HttpRequest request, ClaimsPrincipal user, UnbreakableContext db) => FailClosed(async () =>
{
    var allowed = await pdp.ListMessagesAsync(Sub(user), Pdp.CanRead);
    var inbox = db.Messages.Where(m => allowed.Contains(m.Id));

    var from = request.Query["from"].ToString();
    if (!string.IsNullOrEmpty(from))
    {
        inbox = inbox.Where(m => m.Sender == from);
    }

    return Results.Ok(await inbox.OrderByDescending(m => m.SentAt).ToListAsync());
}));

// Verzonden: de berichten die je mag verwijderen (ListObjects can_delete).
// Enkel metadata, geen ciphertext of MAC: lezen mag enkel de ontvanger.
api.MapGet("/messages/sent", (ClaimsPrincipal user, UnbreakableContext db) => FailClosed(async () =>
{
    var allowed = await pdp.ListMessagesAsync(Sub(user), Pdp.CanDelete);
    var sent = await db.Messages
        .Where(m => allowed.Contains(m.Id))
        .OrderByDescending(m => m.SentAt)
        .Select(m => new { m.Id, m.Recipient, m.KeyLine, Length = m.Body.Length, m.SentAt })
        .ToListAsync();
    return Results.Ok(sent);
}));

// Export: zelfde vraag aan de PDP als de inbox.
api.MapGet("/messages/export", (ClaimsPrincipal user, UnbreakableContext db) => FailClosed(async () =>
{
    var allowed = await pdp.ListMessagesAsync(Sub(user), Pdp.CanRead);
    var messages = await db.Messages
        .Where(m => allowed.Contains(m.Id))
        .OrderBy(m => m.SentAt)
        .ToListAsync();

    return Results.Text(JsonConvert.SerializeObject(messages, Formatting.Indented), "application/json");
}));

// Eén bericht lezen: eerst de PDP (Check can_read), pas daarna de databank.
// Een onbestaand id heeft geen tuples en geeft dus ook 403: zo verraadt de API
// niet welke id's bestaan.
api.MapGet("/messages/{id:int}", (int id, ClaimsPrincipal user, UnbreakableContext db) => FailClosed(async () =>
{
    if (!await pdp.CheckAsync(Sub(user), Pdp.CanRead, id))
    {
        return Denied(Pdp.CanRead, id);
    }

    var message = await db.Messages.FindAsync(id);
    return message == null ? Results.NotFound() : Results.Ok(message);
}));

api.MapPost("/messages", (Message message, ClaimsPrincipal user, UnbreakableContext db) => FailClosed(async () =>
{
    // De afzender ben jij, volgens het token. Een andere naam meesturen kan niet
    // meer (vroeger: X-User of "sender" in de body vervalsen).
    var me = Username(user);
    if (!string.IsNullOrEmpty(message.Sender) && message.Sender != me)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["sender"] = new[] { "De afzender is altijd de ingelogde gebruiker." },
        });
    }

    message.Sender = me;
    message.Id = 0;
    message.SentAt = DateTime.UtcNow;

    // Formaat van ciphertext, lijnnummer en MAC (opdracht 3).
    var errors = new List<ValidationResult>();
    if (!Validator.TryValidateObject(message, new ValidationContext(message), errors, validateAllProperties: true))
    {
        return Results.ValidationProblem(errors
            .GroupBy(e => e.MemberNames.FirstOrDefault() ?? "")
            .ToDictionary(g => g.Key, g => g.Select(e => e.ErrorMessage ?? "").ToArray()));
    }

    // De ontvanger moet een gekend account zijn: we hebben zijn sub nodig.
    var recipient = await db.Users.FirstOrDefaultAsync(u => u.Username == message.Recipient);
    if (recipient == null)
    {
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["recipient"] = new[] { "Onbekende ontvanger: die persoon heeft nog nooit ingelogd." },
        });
    }

    // Bedrijfsregel (geen autorisatie): een codeboeklijn maar één keer per paar.
    var lineUsed = await db.Messages.AnyAsync(m =>
        m.KeyLine == message.KeyLine &&
        ((m.Sender == message.Sender && m.Recipient == message.Recipient) ||
         (m.Sender == message.Recipient && m.Recipient == message.Sender)));
    if (lineUsed)
    {
        return Results.Conflict(new { error = $"Lijn {message.KeyLine} van het codeboek is al gebruikt. Gebruik een nieuwe lijn." });
    }

    db.Messages.Add(message);
    await db.SaveChangesAsync();

    // De feiten voor de PDP: wie is afzender, wie is ontvanger.
    try
    {
        await pdp.AddMessageAsync(message.Id, Sub(user), recipient.Sub);
    }
    catch
    {
        // Zonder tuples kan niemand het bericht lezen of verwijderen: ruim op.
        db.Messages.Remove(message);
        await db.SaveChangesAsync();
        throw;
    }

    return Results.Created($"/api/messages/{message.Id}", message);
}));

api.MapDelete("/messages/{id:int}", (int id, ClaimsPrincipal user, UnbreakableContext db) => FailClosed(async () =>
{
    if (!await pdp.CheckAsync(Sub(user), Pdp.CanDelete, id))
    {
        return Denied(Pdp.CanDelete, id);
    }

    var message = await db.Messages.FindAsync(id);
    if (message == null)
    {
        return Results.NotFound();
    }

    // Eerst de tuples, dan de rij: loopt het halverwege mis, dan blijft er
    // hoogstens een bericht over dat niemand nog kan openen (veilige kant).
    await pdp.RemoveMessageAsync(id);
    db.Messages.Remove(message);
    await db.SaveChangesAsync();
    return Results.NoContent();
}));

app.Run();

// ------------------------------------------------------------------ hulpfuncties

static string Sub(ClaimsPrincipal user) => user.FindFirstValue("sub");

static string Username(ClaimsPrincipal user) => user.FindFirstValue("preferred_username");

static IResult Denied(string permission, int id) =>
    Results.Problem(statusCode: StatusCodes.Status403Forbidden,
        title: "Geweigerd door de PDP",
        detail: $"OpenFGA: geen {permission} op message:{id}.");

// Fail closed: is de PDP onbereikbaar of geeft hij een fout, dan weigeren we.
async Task<IResult> FailClosed(Func<Task<IResult>> action)
{
    try
    {
        return await action();
    }
    catch (Exception ex) when (ex is OpenFga.Sdk.Exceptions.ApiException or HttpRequestException or TaskCanceledException)
    {
        app.Logger.LogError(ex, "PDP-fout, verzoek geweigerd");
        return Results.Problem(statusCode: StatusCodes.Status503ServiceUnavailable,
            title: "Autorisatie niet beschikbaar",
            detail: "De PDP kon niet beslissen. Het verzoek is geweigerd.");
    }
}

static async Task RememberUserAsync(UnbreakableContext db, ClaimsPrincipal principal)
{
    var sub = Sub(principal);
    var name = Username(principal);
    if (string.IsNullOrEmpty(sub) || string.IsNullOrEmpty(name))
    {
        return;
    }

    var now = DateTime.UtcNow;
    var row = await db.Users.FindAsync(sub);
    if (row != null && row.Username == name && now - row.LastSeen < TimeSpan.FromMinutes(5))
    {
        return;   // niets nieuws, geen schrijfactie
    }

    if (row == null)
    {
        // Staat de naam nog op een oud (verwijderd) account? Dan gaat de naam
        // naar het nieuwe account. Oude berichten blijven aan de oude sub hangen
        // in OpenFGA, dus de nieuwe eigenaar kan ze niet lezen.
        var stale = await db.Users.FirstOrDefaultAsync(u => u.Username == name);
        if (stale != null)
        {
            db.Users.Remove(stale);
        }
        db.Users.Add(new AppUser { Sub = sub, Username = name, LastSeen = now });
    }
    else
    {
        row.Username = name;
        row.LastSeen = now;
    }

    try
    {
        await db.SaveChangesAsync();
    }
    catch (DbUpdateException)
    {
        // Twee gelijktijdige verzoeken van een nieuwe gebruiker: het andere was
        // sneller. Niets aan de hand, maar vergeet de mislukte wijziging.
        db.ChangeTracker.Clear();
    }
}
