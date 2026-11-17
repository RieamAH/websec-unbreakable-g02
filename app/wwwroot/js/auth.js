// Inloggen bij Keycloak met OpenID Connect: authorization code flow + PKCE.
//
// Opdracht 4. Het verloop (zie ook het verslag):
//  1. login(): de browser gaat naar Keycloak met een code_challenge (SHA-256 van
//     een willekeurige code_verifier), een state en een nonce.
//  2. Keycloak logt de gebruiker in en stuurt de browser terug met ?code=...&state=...
//  3. handleRedirect(): we controleren de state en ruilen de code in voor tokens.
//     Daarbij sturen we de code_verifier mee. Wie enkel de code onderschept,
//     heeft de verifier niet en kan er niets mee (dat is PKCE).
//  4. Het access token gaat als "Authorization: Bearer ..." mee naar de API.
//
// De tokens staan ENKEL in het geheugen (een variabele), niet in localStorage:
// een XSS kan ze dan niet zomaar uitlezen na het herladen. Na een herlaadbeurt
// log je opnieuw in; Keycloak onthoudt je sessie, dus dat gaat zonder wachtwoord.

const ISSUER = `${location.origin}/auth/realms/unbreakable`;
const CLIENT_ID = 'unbreakable-spa';
const REDIRECT_URI = `${location.origin}/`;
const PENDING_KEY = 'unbreakable_oidc_pending';   // enkel tijdens de redirect

let discovery = null;
let tokens = null;   // { accessToken, idToken, refreshToken, expiresAt, username }

async function config() {
    if (!discovery) {
        const response = await fetch(`${ISSUER}/.well-known/openid-configuration`);
        if (!response.ok) {
            throw new Error('De identity provider is niet bereikbaar.');
        }
        discovery = await response.json();
        if (discovery.issuer !== ISSUER) {
            throw new Error('Onverwachte issuer in de configuratie van de identity provider.');
        }
    }
    return discovery;
}

// ------------------------------------------------------------------ hulpfuncties

function base64url(bytes) {
    let binary = '';
    for (const b of bytes) {
        binary += String.fromCharCode(b);
    }
    return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function randomString(byteCount = 32) {
    // Cryptografisch veilig, net als bij het codeboek (opdracht 3): geen Math.random.
    return base64url(crypto.getRandomValues(new Uint8Array(byteCount)));
}

async function sha256(text) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
}

function decodePayload(jwt) {
    const part = jwt.split('.')[1].replaceAll('-', '+').replaceAll('_', '/');
    const json = new TextDecoder().decode(Uint8Array.from(atob(part), c => c.charCodeAt(0)));
    return JSON.parse(json);
}

function storeTokens(response) {
    const id = decodePayload(response.id_token || tokens?.idToken);
    tokens = {
        accessToken: response.access_token,
        idToken: response.id_token || tokens?.idToken,
        refreshToken: response.refresh_token,
        expiresAt: Date.now() + response.expires_in * 1000,
        username: id.preferred_username,
    };
}

async function tokenRequest(params) {
    const { token_endpoint } = await config();
    const response = await fetch(token_endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ client_id: CLIENT_ID, ...params }),
    });
    if (!response.ok) {
        throw new Error('Inloggen mislukt: de identity provider weigerde het verzoek.');
    }
    return response.json();
}

// ------------------------------------------------------------------ publiek

export function isLoggedIn() {
    return tokens !== null;
}

export function username() {
    return tokens?.username || null;
}

// Stap 1: naar Keycloak.
export async function login(returnTo = '#/inbox') {
    const { authorization_endpoint } = await config();
    const verifier = randomString(32);
    const state = randomString(16);
    const nonce = randomString(16);

    // Enkel voor de duur van de redirect, in sessionStorage (verdwijnt met de tab).
    sessionStorage.setItem(PENDING_KEY, JSON.stringify({ verifier, state, nonce, returnTo }));

    const url = new URL(authorization_endpoint);
    url.search = new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: 'openid profile',
        state,
        nonce,
        code_challenge: base64url(await sha256(verifier)),
        code_challenge_method: 'S256',
    }).toString();
    location.assign(url.toString());
}

// Stap 3: terug van Keycloak. Geeft true als er net is ingelogd.
export async function handleRedirect() {
    const params = new URLSearchParams(location.search);
    if (!params.has('code') && !params.has('error')) {
        return false;
    }

    const pending = JSON.parse(sessionStorage.getItem(PENDING_KEY) || 'null');
    sessionStorage.removeItem(PENDING_KEY);
    // De code en state niet in de adresbalk of de geschiedenis laten staan.
    history.replaceState(null, '', location.pathname + (pending?.returnTo || '#/inbox'));

    if (params.has('error')) {
        throw new Error(`Inloggen geannuleerd of geweigerd (${params.get('error')}).`);
    }
    // state: hoort dit antwoord bij een login die WIJ gestart zijn? (CSRF op de login)
    if (!pending || params.get('state') !== pending.state) {
        throw new Error('Ongeldige state: deze login werd niet door deze app gestart.');
    }

    const response = await tokenRequest({
        grant_type: 'authorization_code',
        code: params.get('code'),
        redirect_uri: REDIRECT_URI,
        code_verifier: pending.verifier,
    });

    // nonce: het ID token hoort bij DEZE login (geen replay van een oud token).
    // De handtekening van het ID token controleren we hier niet: het komt
    // rechtstreeks van het token endpoint over TLS. De API controleert het
    // access token wel volledig.
    if (decodePayload(response.id_token).nonce !== pending.nonce) {
        throw new Error('Ongeldige nonce in het ID token.');
    }

    storeTokens(response);
    return true;
}

// Een geldig access token voor de API, zo nodig vernieuwd met het refresh token.
export async function accessToken() {
    if (!tokens) {
        return null;
    }
    if (Date.now() > tokens.expiresAt - 30_000) {
        try {
            storeTokens(await tokenRequest({ grant_type: 'refresh_token', refresh_token: tokens.refreshToken }));
        } catch {
            tokens = null;   // sessie verlopen: opnieuw inloggen
            return null;
        }
    }
    return tokens.accessToken;
}

// Uitloggen: tokens weg uit het geheugen EN de sessie bij Keycloak beëindigen.
export async function logout() {
    const { end_session_endpoint } = await config();
    const idToken = tokens?.idToken;
    tokens = null;

    const url = new URL(end_session_endpoint);
    url.search = new URLSearchParams({
        client_id: CLIENT_ID,
        post_logout_redirect_uri: REDIRECT_URI,
        ...(idToken ? { id_token_hint: idToken } : {}),
    }).toString();
    location.assign(url.toString());
}
