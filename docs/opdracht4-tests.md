# Opdracht 4 - autorisatie testen

## Voorbereiding

1. Registreer drie accounts via **Inloggen > Register**: `anna`, `bram`, `chris`.
   Elk logt een keer in (dan kent de app hun `sub`).
2. Anna stuurt in de app een bericht naar `bram`. Noteer het id (Network-tab: antwoord op `POST /api/messages`).
3. Haal per persoon een access token: developer tools > Network > een verzoek naar `/api/...` >
   request header `Authorization: Bearer eyJ...`. Een token is 5 minuten geldig.

```bash
D=https://g02.ipv6.thelastgym.be
ID=1                      # id van het bericht Anna -> Bram
ANNA='eyJ...'  BRAM='eyJ...'  CHRIS='eyJ...'
code() { curl -s -o /dev/null -w "%{http_code}\n" "$@"; }
```

Decodeer een token op jwt.io (of `cut -d. -f2 <<<"$BRAM" | base64 -d`) en toon
`iss`, `aud`, `azp`, `typ`, `sub`, `preferred_username`, `exp`.

## 1. Authenticatie: de API gelooft enkel een geldig token

| # | Verzoek | Verwacht |
|---|---|---|
| A1 | `code $D/api/messages` (geen token) | 401 |
| A2 | `code -H "X-User: bram" $D/api/messages/$ID` (de oude manier) | 401 |
| A3 | gewijzigde handtekening: `BAD=$(awk -F. '{print $1"."$2"."substr($3,1,10)"AAAA"substr($3,15)}' <<<"$BRAM"); code -H "Authorization: Bearer $BAD" $D/api/messages` | 401 |
| A4 | verlopen token (na 5 min) | 401 |
| A5 | het **ID token** i.p.v. het access token (aud = unbreakable-spa, typ = ID) | 401 |
| A6 | `curl -H "Authorization: Bearer $BRAM" $D/api/me` | `{"username":"bram","sub":"..."}` |

## 2. Lezen: enkel de ontvanger (Check `can_read`)

| # | Verzoek | Verwacht |
|---|---|---|
| R1 | `code -H "Authorization: Bearer $BRAM"  $D/api/messages/$ID` | 200 (ontvanger) |
| R2 | `code -H "Authorization: Bearer $ANNA"  $D/api/messages/$ID` | 403 (afzender) |
| R3 | `code -H "Authorization: Bearer $CHRIS" $D/api/messages/$ID` | 403 (derde) |
| R4 | `code -H "Authorization: Bearer $CHRIS" $D/api/messages/99999` | 403 (ook onbestaand: geen info-lek) |

## 3. Inbox, filter en export: de PDP kiest de berichten (ListObjects)

| # | Verzoek | Verwacht |
|---|---|---|
| L1 | `curl -H "Authorization: Bearer $BRAM"  $D/api/messages` | bevat bericht `$ID` |
| L2 | `curl -H "Authorization: Bearer $CHRIS" $D/api/messages` | `[]` |
| L3 | `curl -H "Authorization: Bearer $ANNA"  $D/api/messages` | bericht `$ID` staat er niet in |
| L4 | `curl -H "Authorization: Bearer $CHRIS" "$D/api/messages?from=anna"` | `[]` (filter binnen wat je mag zien) |
| L5 | `curl -H "Authorization: Bearer $CHRIS" $D/api/messages/export` | `[]` |
| L6 | `curl -H "Authorization: Bearer $ANNA"  $D/api/messages/sent` | `$ID` met enkel metadata, geen `body`/`mac` |

## 4. Verwijderen: enkel de afzender (Check `can_delete`)

| # | Verzoek | Verwacht |
|---|---|---|
| D1 | `code -X DELETE -H "Authorization: Bearer $BRAM"  $D/api/messages/$ID` | 403 (ontvanger) |
| D2 | `code -X DELETE -H "Authorization: Bearer $CHRIS" $D/api/messages/$ID` | 403 |
| D3 | `code -X DELETE -H "Authorization: Bearer $ANNA"  $D/api/messages/$ID` | 204 |
| D4 | `code -H "Authorization: Bearer $BRAM" $D/api/messages/$ID` | 403 (tuples zijn weg) |

## 5. Spoofing van de afzender

```bash
curl -s -H "Authorization: Bearer $CHRIS" -H 'Content-Type: application/json' \
  -d '{"sender":"directie","recipient":"bram","body":"ABC","keyLine":7,"mac":"'$(printf 'a%.0s' {1..64})'"}' \
  $D/api/messages
```
Verwacht: 400, "De afzender is altijd de ingelogde gebruiker."

## 6. De PDP zelf bekijken (op g02)

```bash
docker compose logs fga-init            # store-id en model-id
docker network ls | grep authz          # bv. websec-unbreakable-g02_authz
docker run --rm --network websec-unbreakable-g02_authz curlimages/curl:8.23.0 -s \
  -H "Authorization: Bearer $FGA_API_KEY" -H 'Content-Type: application/json' \
  -d '{}' http://openfga:8080/stores/<STORE_ID>/read
```
Toont de tuples, bv. `user:<sub-anna> sender message:1` en `user:<sub-bram> recipient message:1`.

## 7. Centraal: een regel wijzigen zonder de API te wijzigen

1. In `authz/model.fga`: `define can_read: recipient or sender`, omzetten naar `model.json`.
2. De modeltest in de pipeline faalt (afzender kan lezen): bewijs dat de regel getest wordt.
3. (Lokaal of op een testbranch) na uitrol geeft R2 nu 200, zonder één regel C# te wijzigen.
4. Terugzetten.

## 8. Fail closed

```bash
docker compose stop openfga
code -H "Authorization: Bearer $BRAM" $D/api/messages/$ID   # 503, nooit 200
docker compose start openfga
```
