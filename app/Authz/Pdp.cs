using OpenFga.Sdk.Client;
using OpenFga.Sdk.Client.Model;
using OpenFga.Sdk.Configuration;

namespace Unbreakable.Authz;

// Opdracht 4: de brug tussen de API (policy enforcement point, PEP) en
// OpenFGA (policy decision point, PDP).
//
// Hier staat GEEN enkele autorisatieregel. Deze klasse stelt enkel vragen
// ("mag user:X can_read op message:Y?") en schrijft feiten weg ("user:X is
// sender van message:Y"). Wat "can_read" en "can_delete" betekenen, staat
// enkel in authz/model.fga.
public class Pdp
{
    // De permissies uit het model. Het zijn namen, geen regels.
    public const string CanRead = "can_read";
    public const string CanDelete = "can_delete";

    private readonly OpenFgaClient _client;

    private Pdp(OpenFgaClient client)
    {
        _client = client;
    }

    public static string UserId(string sub) => $"user:{sub}";
    public static string MessageId(int id) => $"message:{id}";

    // Zoekt de store die fga-init (de PAP) heeft aangemaakt. Geen model-id:
    // OpenFGA gebruikt dan de laatste versie van het model.
    public static async Task<Pdp> ConnectAsync(IConfiguration config, ILogger logger)
    {
        var apiUrl = config["OpenFga:ApiUrl"] ?? throw new InvalidOperationException("OpenFga:ApiUrl ontbreekt");
        var storeName = config["OpenFga:StoreName"] ?? "unbreakable";
        var credentials = new Credentials
        {
            Method = CredentialsMethod.ApiToken,
            Config = new CredentialsConfig { ApiToken = config["OpenFga:ApiKey"] },
        };

        for (var attempt = 1; ; attempt++)
        {
            try
            {
                using var lookup = new OpenFgaClient(new ClientConfiguration { ApiUrl = apiUrl, Credentials = credentials });
                var stores = await lookup.ListStores(new ClientListStoresRequest { Name = storeName });
                var store = stores.Stores?.FirstOrDefault(s => s.Name == storeName)
                    ?? throw new InvalidOperationException($"Store {storeName} bestaat (nog) niet");

                logger.LogInformation("Verbonden met OpenFGA, store {StoreId}", store.Id);
                return new Pdp(new OpenFgaClient(new ClientConfiguration
                {
                    ApiUrl = apiUrl,
                    StoreId = store.Id,
                    Credentials = credentials,
                }));
            }
            catch (Exception ex) when (attempt < 30)
            {
                logger.LogWarning("OpenFGA nog niet klaar ({Error}), poging {Attempt}", ex.Message, attempt);
                await Task.Delay(2000);
            }
        }
    }

    // Check: mag deze gebruiker deze permissie op dit bericht?
    public async Task<bool> CheckAsync(string sub, string permission, int messageId)
    {
        var response = await _client.Check(new ClientCheckRequest
        {
            User = UserId(sub),
            Relation = permission,
            Object = MessageId(messageId),
        });
        return response.Allowed == true;
    }

    // ListObjects: op welke berichten heeft deze gebruiker deze permissie?
    // Zo beslist de PDP ook wat in de inbox en de export komt.
    public async Task<List<int>> ListMessagesAsync(string sub, string permission)
    {
        var response = await _client.ListObjects(new ClientListObjectsRequest
        {
            User = UserId(sub),
            Relation = permission,
            Type = "message",
        });

        var ids = new List<int>();
        foreach (var obj in response.Objects ?? new List<string>())
        {
            if (obj.StartsWith("message:") && int.TryParse(obj["message:".Length..], out var id))
            {
                ids.Add(id);
            }
        }
        return ids;
    }

    // Feiten wegschrijven bij een nieuw bericht: wie is afzender, wie ontvanger.
    // Beide tuples in één write: ofwel staan ze er allebei, ofwel geen van beide.
    public async Task AddMessageAsync(int messageId, string senderSub, string recipientSub)
    {
        await _client.Write(new ClientWriteRequest
        {
            Writes = new List<ClientTupleKey>
            {
                new() { User = UserId(senderSub), Relation = "sender", Object = MessageId(messageId) },
                new() { User = UserId(recipientSub), Relation = "recipient", Object = MessageId(messageId) },
            },
        });
    }

    // Bij verwijderen: alle tuples van het bericht weg. We lezen ze eerst uit
    // OpenFGA, zodat de API zelf niet hoeft te weten wie afzender of ontvanger was.
    public async Task RemoveMessageAsync(int messageId)
    {
        var existing = await _client.Read(new ClientReadRequest { Object = MessageId(messageId) });
        var deletes = (existing.Tuples ?? new List<OpenFga.Sdk.Model.Tuple>())
            .Select(t => new ClientTupleKeyWithoutCondition
            {
                User = t.Key.User,
                Relation = t.Key.Relation,
                Object = t.Key.Object,
            })
            .ToList();

        if (deletes.Count > 0)
        {
            await _client.Write(new ClientWriteRequest { Deletes = deletes });
        }
    }
}
