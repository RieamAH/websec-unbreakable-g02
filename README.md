# Unbreakable

Starter app voor het vak Cyber Security Advanced aan AP Hogeschool.

Unbreakable is een kleine berichtenapp. Je kiest een naam, je stuurt berichten naar anderen en je leest je inbox. De app werkt, maar is nog helemaal niet veilig. Doorheen het semester maken jullie ze beter: een pipeline en een WAF, cryptografie, inloggen, autorisatie en geheimenbeheer.

> **Let op:** deze app bevat bewust zwakke plekken. Gebruik ze enkel in je eigen labomgeving en nooit met echte gegevens.

## Starten

Je hebt enkel Docker nodig, met de compose plugin.

```bash
git clone <jouw repo>
cd <jouw repo>
docker compose up -d --build
```

Surf daarna naar `http://localhost:8080`, of naar poort 8080 van je server. Vul een naam in, bijvoorbeeld **Anna**, **Bram** of **Chris**: die hebben al berichten.

Stoppen doe je met `docker compose down`. Wil je opnieuw beginnen met een lege databank, gebruik dan `docker compose down -v`.

Leeft de app? `curl http://localhost:8080/health` geeft `ok`.

## Opbouw

De app bestaat uit twee delen in één container: een single page app (SPA) die in je browser draait, en een API op de server. De SPA praat met de API in JSON. Open de developer tools van je browser (tabblad Network) om te zien wat er over en weer gaat.

```
docker-compose.yml          de app en een PostgreSQL databank
app/
  Program.cs                de API, en opstarten van de databank
  Models/Message.cs         een bericht
  Data/                     databanktoegang (Entity Framework Core)
  wwwroot/                  de SPA
    index.html
    js/app.js               de schermen
    js/api.js               alle calls naar de API
    lib/                    Bootstrap en jQuery
docs/threat-model.md        basis threat model van de starter app
```

### De API (na opdracht 4)

Elk verzoek naar `/api` heeft een access token van Keycloak nodig (`Authorization: Bearer ...`).
Wat je mag, beslist OpenFGA (model in `authz/model.fga`), niet de code van de API.

| Methode | Pad | Doet | Vraag aan de PDP |
|---|---|---|---|
| GET | `/health` | leeft de app? | - |
| GET | `/api/me` | wie ben ik volgens het token | - |
| GET | `/api/users` | gekende gebruikersnamen (adresboek) | - |
| GET | `/api/messages` | je inbox, optioneel `?from=<naam>` | ListObjects `can_read` |
| GET | `/api/messages/sent` | metadata van je verzonden berichten | ListObjects `can_delete` |
| GET | `/api/messages/export` | je inbox als JSON | ListObjects `can_read` |
| GET | `/api/messages/{id}` | één bericht | Check `can_read` |
| POST | `/api/messages` | bericht versturen | schrijft tuples `sender` + `recipient` |
| DELETE | `/api/messages/{id}` | bericht verwijderen | Check `can_delete` |

### Opdracht 4: identity provider en PDP

```
authz/model.fga         het autorisatiemodel (ReBAC), leesbaar
authz/model.json        hetzelfde model in JSON (voor de API van OpenFGA)
authz/model.fga.yaml    tests van het model (fga model test, ook in de pipeline)
authz/init.sh           PAP: maakt store + model aan bij elke deploy (fga-init)
keycloak/unbreakable-realm.json   realm, client unbreakable-spa (code flow + PKCE)
docs/opdracht4-tests.md           testverzoeken met curl
```

Nieuwe geheimen (GitHub environment `production`): `KC_DB_PASSWORD`, `KC_ADMIN_PASSWORD`,
`FGA_DB_PASSWORD`, `FGA_API_KEY`.

Model aangepast in `model.fga`? Zet het om naar JSON met
`fga model transform --file authz/model.fga > authz/model.json`.

Beheerconsole van Keycloak (niet publiek): `ssh -L 8081:127.0.0.1:8081 g02`,
daarna `http://localhost:8081/auth/admin/`.

## Herkomst

Gebaseerd op [websec-vulnerable-dotnetcore](https://github.com/Splynter-Security/websec-vulnerable-dotnetcore), omgebouwd tot een berichtenapp met een SPA en een API, en bijgewerkt naar .NET 10.
