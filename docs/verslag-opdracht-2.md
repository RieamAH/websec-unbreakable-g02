# Verslag Opdracht 2: pipeline, AI agent en WAF

**Vak:** Cyber Security Advanced — **Naam:** Nezir Kurtesi & Rieam «...»
**Repository:** «https://github.com/<jouw-account>/websec-unbreakable-gNN»
**Succesvolle run (log):** «link naar de geslaagde Actions-run»

> Plaatsen met «...» moet je zelf nog invullen of vervangen door een screenshot:
> die hangen vast aan jouw machine (gNN, IPv6-adres), jouw repo en jouw echte runs.
> De scanresultaten hieronder komen uit een lokale run van exact dezelfde tools op
> de ongewijzigde starter-app; controleer ze tegen je eerste echte pipeline-run.

---

## 1. Opzet

De berichtenapp Unbreakable staat nu online **achter een web application firewall**,
en elke push naar `main` loopt eerst door een **pipeline** die scant op kwetsbaarheden,
kwetsbare bibliotheken en geheimen, en pas daarna uitrolt. De architectuur en het
bijgewerkte threat model staan in `docs/threat-model.md`.

Keten in het kort:

```
push naar main
  → secret scanning (Gitleaks)
  → SCA (Trivy server-side + retire.js client-side)
  → SAST (CodeQL C# + JavaScript) + eigen gate
  → [alles groen] deploy via self-hosted runner → docker compose up achter BunkerWeb
```

## 2. Pipeline

De workflow staat in `.github/workflows/pipeline.yml`. Elke scan vult een DSOMM-activiteit
in die we in opdracht 1 kozen:

| Scan | Tool | Wat | DSOMM-activiteit (niveau uit opdr. 1) |
|---|---|---|---|
| Secret scanning | Gitleaks | sleutels/tokens in de repo | Development and Source Control → *Block pushes containing secrets* (L3) |
| SCA server-side | Trivy (fs) | kwetsbare .NET-packages | Static depth → *Software Composition Analysis (server side)* (L2) |
| SCA client-side | retire.js | kwetsbare jQuery/Bootstrap | Static depth → *Software Composition Analysis (client side)* (L3) |
| SAST | CodeQL (C# + JS) | fouten in eigen code | Static depth → *Static analysis for important server/client side components* (L3) |
| Uitrollen | docker compose (self-hosted) | automatisch online | Deployment → *Automated deployment process* (L1) |
| Actions vastpinnen | SHA-pinning | supply chain pipeline | Build → *Pinning of artifacts* (L2) |

### Wat is een kritieke bevinding? (onze keuze)

- **SAST (CodeQL):** security-severity ≥ 7.0 (High/Critical), of een security-regel met
  niveau *error*. We parsen de SARIF zelf in `.github/scripts/gate.py`, want een melding
  in het Security-tabblad laat de pipeline **niet** falen.
- **SCA (Trivy):** HIGH of CRITICAL **met** beschikbare fix (`--ignore-unfixed`).
- **SCA (retire.js):** severity high of hoger.
- **Secrets:** elke echte secret is kritiek (de pipeline faalt meteen).

### De pipeline beveiligen

De pipeline is zelf een doelwit (zie `tj-actions/changed-files`, maart 2025, en de
kaping van `aquasecurity/trivy-action`, maart 2026, waarbij bijna alle tags herschreven
werden). Daarom:

- **Alle actions vastgepind op een commit-SHA**, niet op een tag die kan verschuiven.
- **Minimale rechten:** `permissions: contents: read` bovenaan; enkel de SAST-jobs krijgen
  `security-events: write`.
- **Trivy v0.75.0** (na het incident; de kwaadaardige build was v0.69.4).
- **Enkel een push naar `main`** rolt uit; pull requests scannen wel, maar deployen nooit.
- **Geheimen in GitHub Secrets** (`DOMAIN`, `LETSENCRYPT_EMAIL`, `DB_PASSWORD`), nooit in de code.

### Aanvaarde bevindingen (baseline op de ongewijzigde app)

De eerste run op de ongewijzigde starter vindt onderstaande. Elk is een **bewuste**
zwakte van de starter; we aanvaarden ze nu met reden en pakken ze aan in een latere
opdracht. De baseline staat in `.gitleaks.toml`, `.trivyignore`, `.retireignore.json`
en `security/codeql-baseline.json`.

| Bevinding | Tool | Ernst | Waarom nu aanvaard | Opgelost in |
|---|---|---|---|---|
| Placeholder-API-key `ubk_live_…` in `appsettings.json` | Gitleaks | — | Nep-placeholder zonder echte waarde; echte secret komt in een secrets manager | O6 |
| `Newtonsoft.Json 12.0.1` (CVE-2024-21907, DoS) | Trivy | High | API serialiseert enkel eigen objecten, geen onvertrouwde JSON van buiten | O2/O3 (of nu bumpen naar 13.0.3) |
| `jQuery 3.3.1` (CVE-2019-11358, -2020-11022/11023) | retire.js | Medium/High | Bewuste lib van de starter; WAF vangt reflected XSS deels af | later |
| `Bootstrap 4.1.3` (CVE-2019-8331) | retire.js | Medium | We gebruiken de kwetsbare data-attributen niet | later |
| SQL-injectie in `/api/messages/search` (`Program.cs:89`) | CodeQL | Critical | Kernzwakte van de starter; echte fix (parameterized query) in secure-coding-opdracht; WAF/CRS dekt tussentijds | O3 |
| Reflected XSS in de zoekbalk (`app.js:101`) | CodeQL | High | Idem; output encoding volgt, WAF dekt tussentijds | O3 |

Een **nieuwe** kritieke bevinding die niet in de baseline staat, laat de pipeline falen.
Dat testten we door bewust een tweede, onbekende secret toe te voegen: de `secrets`-job
faalde zoals verwacht. «voeg hier je screenshot/ runlog van de falende run toe»

### Uitrollen met een self-hosted runner

GitHub-hosted runners raken niet bij een machine met **enkel IPv6**. Daarom draait op de
machine zelf een **self-hosted runner** (label `unbreakable`), die de job uitgaand ophaalt.
In een **publieke** repo mogen fork-PR's die runner niet zomaar gebruiken: dat zou code
execution op onze productiemachine geven (dreiging P2). Daarom draait de deploy-job enkel
op `push` naar `main`, en staat in de repo-instellingen *"Require approval for all outside
collaborators"*.

Installatie op de machine (Settings → Actions → Runners → New self-hosted runner):

```bash
# op de server, als niet-root gebruiker met docker-rechten
mkdir actions-runner && cd actions-runner
curl -o runner.tar.gz -L «url uit de GitHub-wizard»
tar xzf runner.tar.gz
./config.sh --url https://github.com/<account>/websec-unbreakable-gNN --token «token» --labels unbreakable
sudo ./svc.sh install && sudo ./svc.sh start
```

## 3. AI agent

We lieten de code nakijken met de **`code-review-security`** play uit de OWASP Secure Agent
Playbook (CC BY 4.0). De play structureert de review per OWASP-zwakteklasse (injectie,
auth, autorisatie, crypto, datalekken, misconfiguratie). Zie de AI-verantwoording voor
welke agent we gebruikten en hoe.

### Top 5 bevindingen van de agent, naast de SAST

| # | Bevinding (locatie) | Ernst | SAST (CodeQL) | Oordeel |
|---|---|---|---|---|
| A1 | SQL-injectie in `/api/messages/search`, string-concat in `FromSqlRaw` (`Program.cs:86-89`) | Critical | **Ook gevonden** (`cs/sql-injection`) | Terecht; beide eens |
| A2 | **Stored XSS** via niet-geëscapet `subject` in de inbox-tabel en in de berichttitel (`app.js` ~106 en `renderMessage`) | High | **Gemist** door de JS-SAST | Agent vindt extra |
| A3 | **IDOR / ontbrekende autorisatie**: `GET` en `DELETE /api/messages/{id}` doen geen eigenaarscontrole — elk id leesbaar/verwijderbaar (`Program.cs`) | High | **Gemist** (geen auth-model om tegen te toetsen) | Agent vindt extra |
| A4 | **Sender-spoofing / mass assignment**: `POST /messages` neemt een `Sender` uit de body over; identiteit zit enkel in de `X-User`-header | High | **Gemist** | Agent vindt extra |
| A5 | **Te ruime CORS**: `AllowAnyOrigin + AllowAnyHeader + AllowAnyMethod` (`Program.cs:12`) | Medium | Wellicht gemist (CodeQL vlagt CORS vooral in combinatie met credentials) | Agent vindt (allicht) extra |

### Wat vindt de agent extra, wat mist hij, wat klopt niet?

- **Extra t.o.v. de SAST (A2, A3, A4, en allicht A5):** de stored XSS via `subject`, de
  ontbrekende autorisatie (IDOR), de sender-spoofing en de te ruime CORS. Dat zijn **logische**
  fouten over meerdere
  lagen (API → DB → SPA) of het *ontbreken* van een controle. SAST ziet een los patroon
  in één bestand; de agent redeneert over het geheel en ziet dat een eigenaarscontrole
  nergens bestaat. CodeQL's JS-analyse mist A2 omdat de data via de server terugkomt
  (geen zuivere client-side dataflow).
- **Wat de agent mist t.o.v. de scanners:** de **exacte** kwetsbare bibliotheken en CVE's
  (jQuery 3.3.1, Bootstrap 4.1.3, Newtonsoft.Json 12.0.1) en de hardgecodeerde key — die
  som je sneller en vollediger op met SCA (Trivy/retire.js) en secret scanning (Gitleaks).
  De agent noemt "oude libs" wel, maar zonder de volledige, exacte lijst.
- **Wat niet klopte (false positive van de SAST):** CodeQL meldt
  `js/client-side-request-forgery` op `api.js:22` (de fetch-URL bevat een pad). De agent
  beoordeelt dit als **laag/geen echt probleem**: het pad is door de app bepaald, niet door
  een aanvaller naar een externe host te sturen. We nemen het daarom niet als kritiek op.

**Les:** scanners en een AI-agent zijn complementair. SCA en secret scanning zijn sterk in
het **volledig en exact** opsommen van gekende problemen; de agent is sterk in **logica en
context** (autorisatie, spoofing, cross-layer XSS), maar je moet zijn werk controleren — hij
klinkt even zeker bij een fout als bij een terechte bevinding.

## 4. WAF

BunkerWeb (NGINX + ModSecurity + OWASP CRS v4) staat als enige dienst open (poort 80/443) en
proxyt naar de app op poort 8080, die **niet meer publiek** is (geen `ports` in
`docker-compose.yml`, enkel `expose`). HTTPS komt van Let's Encrypt; we testten eerst met
`USE_LETS_ENCRYPT_STAGING=yes` (gedeelde rate limit) en bewaren het certificaat in het
volume `bw-storage`.

Controle dat 8080 dicht is: «`curl http://<IPv6>:8080` → geen verbinding; `https://<domein>`
→ werkt». Voeg hier je screenshot toe.

### Een aanval die de WAF tegenhoudt, en dezelfde aanval anders verpakt

We misbruiken de zoekbalk (de SQL-injectie uit A1) als testgeval.

1. **Rechtstreeks, zonder WAF** (tijdens stap 1-3, poort 8080 open): een klassieke
   injectie in `?q=` gaf een afwijkend resultaat — de zwakte is reëel. «screenshot»
2. **Met de WAF ervoor:** exact dezelfde aanvraag wordt door de CRS geblokkeerd met een
   `403` (anomaly score boven de drempel). «screenshot van de 403 + regel uit de WAF-log»
3. **Anders verpakt:** we probeerden de payload in een andere vorm (andere codering /
   opsplitsing). «beschrijf kort of de CRS dit óók tegenhield of niet, en op welk paranoia
   level». 

**Wat zegt dat over een WAF?** Een WAF werkt met anomaly scoring op gekende patronen. Ze
verhoogt de drempel voor een aanvaller en dekt veel in de breedte, maar is **geen
oplossing**: een voldoende anders verpakte payload, of een logische fout zoals de
ontbrekende autorisatie (A3), raakt er nog door. De echte fixes — parameterized queries
(O3), output encoding (O3), authenticatie (O4) en autorisatie (O5) — blijven nodig. De WAF
is defense-in-depth, geen vervanging voor veilige code.

## 5. Threat model

Het bijgewerkte model staat in `docs/threat-model.md`. Nieuw t.o.v. opdracht 1:

- De **pipeline** en de **WAF** staan op het diagram, met op elke data flow het **protocol**
  (HTTPS, HTTP, SQL/TCP, SSH) en de **authenticatie** (TLS-cert, DB-wachtwoord, SSH-sleutel+MFA,
  GitHub-account, runner-token).
- **Nieuwe dreigingen** die pipeline en WAF zelf meebrengen: gekaapte action/dependency (P1),
  misbruik van de self-hosted runner (P2), gewijzigde workflow via PR (P3), WAF-bypass (P4),
  de WAF als single point (P5), en lekkende pipeline-secrets (P6) — elk met maatregel.
- De opdracht-nummering is rechtgezet volgens de planning (O3 crypto, O4 identity, O5 access,
  O6 secrets).

## 6. AI-verantwoording

Voor deze opdracht gebruikte ik AI op twee manieren, beide gratis en zonder echte geheimen
of persoonsgegevens:

1. **Als hulpmiddel bij het opstellen** van de pipeline, de WAF-configuratie, het bijgewerkte
   threat model en dit verslag. Ik heb elke keuze zelf nagekeken en kan ze verdedigen: de
   DSOMM-mapping tegenover onze keuzes uit opdracht 1, de SHA-pins tegenover de gekende
   supply-chain-incidenten, en de aanvaarde baseline tegenover de functionaliteit van de app.
2. **Als AI-agent voor de code review** (stap 3), met de `code-review-security`-play uit de
   OWASP Secure Agent Playbook. «Vul in welke agent: bv. Claude / GitHub Copilot / Gemini CLI,
   en of je de play in een chat plakte of als skill draaide.» De bevindingen heb ik
   vergeleken met de SAST (zie sectie 3) en niet blind overgenomen: de false positive van
   CodeQL (client-side request forgery) heb ik na controle verworpen.

Er zijn geen echte gegevens of secrets in prompts gebruikt; de enige "sleutel" in de repo is
de bewuste placeholder van de starter.
