#!/bin/sh
# Policy administration point (PAP) van Unbreakable - opdracht 4.
#
# Draait bij elke deploy als eenmalige container (fga-init in docker-compose.yml):
#   1. wacht tot OpenFGA leeft
#   2. zoekt de store "unbreakable", of maakt hem aan
#   3. schrijft het autorisatiemodel uit authz/model.json (= model.fga in JSON)
#
# OpenFGA bewaart elk model als nieuwe, onveranderlijke versie. De app gebruikt
# altijd de laatste versie. Een regel wijzigen = model.fga aanpassen, PR, pipeline:
# geen enkele regel code in de API verandert.
set -eu

FGA="http://openfga:8080"
STORE_NAME="unbreakable"
AUTH="Authorization: Bearer ${FGA_API_KEY}"

i=0
until curl -fsS "$FGA/healthz" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        echo "OpenFGA is niet bereikbaar" >&2
        exit 1
    fi
    sleep 2
done

STORE_ID=$(curl -fsS -H "$AUTH" "$FGA/stores?page_size=100" \
    | tr -d ' \n' \
    | grep -o "\"id\":\"[^\"]*\",\"name\":\"$STORE_NAME\"" \
    | head -n 1 | cut -d '"' -f 4 || true)

if [ -z "$STORE_ID" ]; then
    STORE_ID=$(curl -fsS -H "$AUTH" -H 'Content-Type: application/json' \
        -d "{\"name\":\"$STORE_NAME\"}" "$FGA/stores" \
        | tr -d ' \n' | grep -o '"id":"[^"]*"' | head -n 1 | cut -d '"' -f 4)
    echo "Store $STORE_NAME aangemaakt: $STORE_ID"
fi

MODEL_ID=$(curl -fsS -H "$AUTH" -H 'Content-Type: application/json' \
    --data-binary @/authz/model.json "$FGA/stores/$STORE_ID/authorization-models" \
    | tr -d ' \n' | grep -o '"authorization_model_id":"[^"]*"' | cut -d '"' -f 4)

if [ -z "$MODEL_ID" ]; then
    echo "Het model kon niet worden weggeschreven" >&2
    exit 1
fi

echo "OpenFGA klaar: store=$STORE_ID model=$MODEL_ID"
