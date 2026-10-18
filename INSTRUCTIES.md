# Opdracht 2 — wat zit hierin en wat moet jij nog doen

Deze bestanden zet je in je eigen repo `websec-unbreakable-gNN` (bovenop de starter).

## Bestanden

```
.github/workflows/pipeline.yml   de pipeline: secret scan, SCA, SAST, deploy
.github/scripts/gate.py          faalt op nieuwe kritieke CodeQL-bevindingen
.github/codeql-config.yml        CodeQL-scope (eigen code, libs = SCA)
.gitleaks.toml                   secret-scan config + aanvaarde placeholder-key
.trivyignore                     aanvaarde server-side CVE (Newtonsoft.Json)
.retireignore.json               aanvaarde client-side CVE's (jQuery, Bootstrap)
security/codeql-baseline.json    aanvaarde SAST-bevindingen van de starter
docker-compose.yml               eindtoestand: app+db zonder poorten, WAF ervoor
.env.example                     kopieer naar .env (lokaal) / GitHub Secrets (CI)
docs/threat-model.md             bijgewerkt threat model (DFD + nieuwe dreigingen)
docs/verslag-opdracht-2.md       het verslag
```

## Checklist (alleen jij kan dit — hangt aan jouw machine/repo)

1. **Repo:** maak met *Use this template* `websec-unbreakable-gNN` (publiek). Vul de
   repo-link in het verslag in.
2. **GitHub Secrets** (Settings → Secrets and variables → Actions): `DOMAIN`,
   `LETSENCRYPT_EMAIL`, `DB_PASSWORD`.
3. **Self-hosted runner** op je machine met label `unbreakable` (zie verslag §2).
4. **DNS**: A/AAAA-record naar je machine; test Let's Encrypt eerst met staging.
5. **Eerste run:** check of CodeQL exact `cs/sql-injection@app/Program.cs:89` en
   `js/xss@app/wwwroot/js/app.js:101` meldt; stem `security/codeql-baseline.json` en
   `.trivyignore` af op wat jouw run echt rapporteert.
6. **Bewijs verzamelen** voor het verslag (vervang de «...»-plaatsen):
   - link naar een geslaagde Actions-run;
   - screenshot van een falende run bij een nieuwe secret;
   - `curl` die toont dat 8080 dicht is en HTTPS werkt;
   - de WAF die een aanval blokkeert (403 + log) en wat er gebeurt als je ze anders verpakt;
   - welke AI-agent je voor stap 3 gebruikte.
7. **Branch protection** op `main`: verplichte status checks + review.

## Opgelet, supply chain

Alle GitHub Actions zijn op commit-SHA vastgepind. Trivy draait op v0.75.0 (de versie
v0.69.4 was kwaadaardig, maart 2026). Verander de pins niet zonder reden.
