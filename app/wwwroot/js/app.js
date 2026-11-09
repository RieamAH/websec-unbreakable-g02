// De schermen van Unbreakable. Navigeren gebeurt met het deel na # in de URL.

import { api, currentUser, setUser } from './api.js';
import { normalize, parseKeyLine, encrypt, decrypt, sign, verify } from './crypto.js';

const app = document.getElementById('app');

function escapeHtml(text) {
    return String(text)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function formatDate(value) {
    return new Date(value).toLocaleString('nl-BE', {
        day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit'
    });
}

function showWho() {
    const user = currentUser();
    document.getElementById('who').innerHTML = user
        ? `Je bent <strong>${escapeHtml(user)}</strong> (<a href="#/">wisselen</a>)`
        : '';
}

// ------------------------------------------------------------------ naam kiezen

function renderLogin() {
    const user = currentUser();
    app.innerHTML = `
        <div class="text-center mb-5">
            <h1 class="display-4">Unbreakable</h1>
            <p class="lead">Berichten die niemand anders kan lezen. Dat is toch de bedoeling.</p>
        </div>
        <div class="row justify-content-center">
            <div class="col-md-5">
                ${user ? `<p>Je gebruikt Unbreakable als <strong>${escapeHtml(user)}</strong>.
                          <a href="#/inbox">Naar je inbox</a></p>
                          <p>Iemand anders? Vul hieronder een andere naam in.</p>` : ''}
                <form id="login">
                    <div class="form-group">
                        <label for="name">Wie ben je?</label>
                        <input id="name" class="form-control" placeholder="bijvoorbeeld Anna"
                               required minlength="2" maxlength="40" />
                    </div>
                    <button type="submit" class="btn btn-primary">Verder</button>
                </form>
            </div>
        </div>`;

    document.getElementById('login').addEventListener('submit', (event) => {
        event.preventDefault();
        setUser(document.getElementById('name').value.trim());
        location.hash = '#/inbox';
    });
}

// ------------------------------------------------------------------ inbox

async function renderInbox(params) {
    const user = currentUser();
    const from = params.get('from') || '';

    const all = await api.inbox();
    const senders = [...new Set(all.map(m => m.sender))].sort();
    const messages = all.filter(m => !from || m.sender === from);

    // Het zoekveld is weg (opdracht 3): de server kan niet zoeken in ciphertext.
    // Daarmee verdwijnt ook de DOM-XSS via ?q= (jQuery .html()).
    app.innerHTML = `
        <h1>Inbox van ${escapeHtml(user)}</h1>
        <p>
            <a href="#/nieuw" class="btn btn-primary">Nieuw bericht</a>
            <button id="export" class="btn btn-outline-secondary">Exporteer als JSON</button>
        </p>
        <form id="filter" class="mb-3">
            <div class="form-row align-items-end">
                <div class="col-auto">
                    <label for="from">Van</label>
                    <select id="from" class="form-control">
                        <option value="">Iedereen</option>
                        ${senders.map(s => `<option value="${escapeHtml(s)}" ${s === from ? 'selected' : ''}>${escapeHtml(s)}</option>`).join('')}
                    </select>
                </div>
                <div class="col-auto">
                    <button type="submit" class="btn btn-secondary">Filter</button>
                </div>
            </div>
        </form>
        <div id="list"></div>`;

    // Alles wat van de server komt, gaat door escapeHtml (geen stored XSS).
    const rows = messages.map(m => `
        <tr>
            <td>${escapeHtml(m.sender)}</td>
            <td><a href="#/bericht/${Number(m.id)}">Versleuteld bericht</a></td>
            <td>Lijn ${Number(m.keyLine)} &middot; ${escapeHtml(String(m.body).length)} tekens</td>
            <td>${formatDate(m.sentAt)}</td>
        </tr>`).join('');

    document.getElementById('list').innerHTML = messages.length
        ? `<table class="table">
               <thead><tr><th>Van</th><th>Bericht</th><th>Codeboek</th><th>Verzonden</th></tr></thead>
               <tbody>${rows}</tbody>
           </table>`
        : '<p class="text-muted">Geen berichten.</p>';

    document.getElementById('filter').addEventListener('submit', (event) => {
        event.preventDefault();
        const next = new URLSearchParams();
        const newFrom = document.getElementById('from').value;
        if (newFrom) next.set('from', newFrom);
        location.hash = '#/inbox' + (next.toString() ? '?' + next.toString() : '');
    });

    document.getElementById('export').addEventListener('click', async () => {
        const data = await api.exportJson();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = 'inbox.json';
        link.click();
        URL.revokeObjectURL(link.href);
    });
}

// ------------------------------------------------------------------ bericht lezen

function showAlert(element, kind, text) {
    element.className = `alert alert-${kind}`;
    element.textContent = text;   // textContent: nooit HTML uit invoer of server
}

async function renderMessage(id) {
    const m = await api.message(id);

    app.innerHTML = `
        <h1>Versleuteld bericht</h1>
        <dl class="row">
            <dt class="col-sm-3">Van</dt><dd class="col-sm-9">${escapeHtml(m.sender)}</dd>
            <dt class="col-sm-3">Aan</dt><dd class="col-sm-9">${escapeHtml(m.recipient)}</dd>
            <dt class="col-sm-3">Verzonden</dt><dd class="col-sm-9">${formatDate(m.sentAt)}</dd>
            <dt class="col-sm-3">Lijn in het codeboek</dt><dd class="col-sm-9">${Number(m.keyLine)}</dd>
            <dt class="col-sm-3">Ciphertext</dt><dd class="col-sm-9"><code id="cipher"></code></dd>
            <dt class="col-sm-3">MAC</dt><dd class="col-sm-9"><code id="mac" class="text-break"></code></dd>
        </dl>
        <div class="row">
            <div class="col-md-8">
                <form id="decrypt" autocomplete="off">
                    <div class="form-group">
                        <label for="key">Sleutel: lijn ${Number(m.keyLine)} uit je codeboek</label>
                        <input id="key" class="form-control text-monospace" required spellcheck="false" />
                    </div>
                    <div class="form-group">
                        <label for="hmac">HMAC-sleutel</label>
                        <input id="hmac" type="password" class="form-control text-monospace" required spellcheck="false" />
                    </div>
                    <button type="submit" class="btn btn-primary">Controleren en ontsleutelen</button>
                </form>
            </div>
        </div>
        <div id="result" class="mt-3"></div>
        <div class="card mb-3 d-none" id="plain-card"><div class="card-body message-body" id="plain"></div></div>
        <p>
            <button id="delete" class="btn btn-outline-danger">Verwijderen</button>
            <a href="#/inbox" class="btn btn-link">Terug naar je inbox</a>
        </p>`;

    document.getElementById('cipher').textContent = m.body;
    document.getElementById('mac').textContent = m.mac;

    document.getElementById('decrypt').addEventListener('submit', async (event) => {
        event.preventDefault();
        const result = document.getElementById('result');
        const plainCard = document.getElementById('plain-card');
        plainCard.classList.add('d-none');

        try {
            // 1. Eerst de MAC controleren. Klopt die niet, dan tonen we NIETS van het bericht.
            const ok = await verify(document.getElementById('hmac').value, m);
            if (!ok) {
                showAlert(result, 'danger',
                    'MAC ongeldig: dit bericht (ciphertext, lijnnummer, afzender of ontvanger) is gewijzigd, ' +
                    'of je HMAC-sleutel is fout. Het bericht wordt niet getoond.');
                return;
            }

            // 2. Pas daarna ontsleutelen.
            const key = parseKeyLine(document.getElementById('key').value);
            const plaintext = decrypt(m.body, key).replaceAll('_', ' ');

            showAlert(result, 'success',
                'MAC geldig: het bericht is niet gewijzigd. ' +
                'Let op: met een verkeerde codeboeklijn krijg je onzin. Een one-time pad kan dat niet opmerken.');
            document.getElementById('plain').textContent = plaintext;
            plainCard.classList.remove('d-none');
        } catch (error) {
            showAlert(result, 'warning', error.message);
        }
    });

    document.getElementById('delete').addEventListener('click', async () => {
        if (confirm('Ben je zeker dat je dit bericht wil verwijderen?')) {
            await api.remove(id);
            location.hash = '#/inbox';
        }
    });
}

// ------------------------------------------------------------------ bericht versturen

async function renderNew() {
    const users = await api.users();

    app.innerHTML = `
        <h1>Nieuw bericht</h1>
        <p class="text-muted">Van: ${escapeHtml(currentUser())}</p>
        <p class="text-muted">Het bericht wordt in je browser versleuteld. De server krijgt enkel de
           ciphertext, het lijnnummer en de MAC, nooit het bericht of de sleutels.</p>
        <div class="row">
            <div class="col-md-8">
                <form id="compose" autocomplete="off">
                    <div class="form-group">
                        <label for="recipient">Aan</label>
                        <input id="recipient" class="form-control" list="known-users"
                               required minlength="2" maxlength="40" />
                        <datalist id="known-users">
                            ${users.map(u => `<option value="${escapeHtml(u)}"></option>`).join('')}
                        </datalist>
                    </div>
                    <div class="form-group">
                        <label for="text">Bericht</label>
                        <input id="text" class="form-control" required maxlength="40" spellcheck="false" />
                        <small class="form-text text-muted">Maximaal 40 tekens: letters, cijfers en spaties.
                            <span id="count">0/40</span></small>
                    </div>
                    <div class="form-row">
                        <div class="form-group col-sm-3">
                            <label for="line">Lijnnummer</label>
                            <input id="line" type="number" min="1" max="9999" class="form-control" required />
                        </div>
                        <div class="form-group col-sm-9">
                            <label for="key">Sleutel: die lijn uit het codeboek</label>
                            <input id="key" class="form-control text-monospace" required spellcheck="false" />
                        </div>
                    </div>
                    <div class="form-group">
                        <label for="hmac">HMAC-sleutel</label>
                        <input id="hmac" type="password" class="form-control text-monospace" required spellcheck="false" />
                    </div>
                    <div id="error"></div>
                    <button type="submit" class="btn btn-primary">Versleutelen en versturen</button>
                    <a href="#/inbox" class="btn btn-link">Annuleren</a>
                </form>
            </div>
        </div>`;

    const text = document.getElementById('text');
    text.addEventListener('input', () => {
        document.getElementById('count').textContent = `${text.value.length}/40`;
    });

    document.getElementById('compose').addEventListener('submit', async (event) => {
        event.preventDefault();
        const error = document.getElementById('error');
        error.className = '';
        error.textContent = '';

        try {
            const plaintext = normalize(text.value);
            const key = parseKeyLine(document.getElementById('key').value);

            const message = {
                sender: currentUser(),
                recipient: document.getElementById('recipient').value.trim(),
                keyLine: Number(document.getElementById('line').value),
                body: encrypt(plaintext, key),
            };
            message.mac = await sign(document.getElementById('hmac').value, message);

            // Enkel dit object gaat naar de server. Kijk in de developer tools (Netwerk).
            await api.send(message);
            location.hash = '#/inbox';
        } catch (e) {
            showAlert(error, 'danger', e.message);
            error.classList.add('mt-2');
        }
    });
}

// ------------------------------------------------------------------ over

function renderAbout() {
    app.innerHTML = `
        <h1>Over Unbreakable</h1>
        <p>Unbreakable is een berichtenapp. Je stuurt een bericht naar iemand, en enkel die persoon kan het lezen.
           Dat is tenminste het doel.</p>
        <p>Deze versie is de starter app van het vak Cyber Security Advanced aan AP Hogeschool.
           Ze werkt, maar is nog helemaal niet veilig. Doorheen het semester maken jullie ze beter.</p>
        <p>De app bestaat uit twee delen: deze single page app in je browser, en een API op de server.
           Bekijk de developer tools van je browser om te zien wat er over en weer gaat.</p>
        <p class="text-danger">Gebruik deze app enkel in je eigen labomgeving en nooit met echte gegevens.</p>`;
}

// ------------------------------------------------------------------ navigatie

async function route() {
    showWho();

    const [path, query] = (location.hash || '#/').slice(1).split('?');
    const params = new URLSearchParams(query || '');

    try {
        if (path === '/' || path === '') {
            return renderLogin();
        }
        if (path === '/over') {
            return renderAbout();
        }
        if (!currentUser()) {
            location.hash = '#/';
            return;
        }
        if (path === '/inbox') {
            return await renderInbox(params);
        }
        if (path === '/nieuw') {
            return await renderNew();
        }
        const match = path.match(/^\/bericht\/(\d+)$/);
        if (match) {
            return await renderMessage(match[1]);
        }
        app.innerHTML = '<p>Deze pagina bestaat niet.</p>';
    } catch (error) {
        app.innerHTML = `<div class="alert alert-danger">Er liep iets mis: ${escapeHtml(error.message)}</div>`;
    }
}

window.addEventListener('hashchange', route);
route();
