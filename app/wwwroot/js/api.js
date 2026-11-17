// Praat met de API. Alles wat de SPA weet, komt van hier.
//
// Opdracht 4: geen X-User meer. Elk verzoek draagt het access token van
// Keycloak; de API haalt daaruit wie je bent.

import { accessToken, login } from './auth.js';

async function call(method, path, body) {
    const token = await accessToken();
    if (!token) {
        await login(location.hash || '#/inbox');
        throw new Error('Je moet eerst inloggen.');
    }

    const headers = { Authorization: `Bearer ${token}` };
    const options = { method, headers };

    if (body !== undefined) {
        headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(body);
    }

    const response = await fetch('/api' + path, options);
    if (response.status === 401) {
        await login(location.hash || '#/inbox');
        throw new Error('Je sessie is verlopen, je wordt opnieuw aangemeld.');
    }
    if (!response.ok) {
        // Toon de reden die de server meegeeft (bv. geweigerd door de PDP, lijn al gebruikt).
        let reason = '';
        try {
            const problem = await response.json();
            reason = problem.error || problem.detail ||
                Object.values(problem.errors || {}).flat().join(' ') || '';
        } catch {
            // geen JSON in het antwoord
        }
        throw new Error(reason || `${method} ${path} gaf ${response.status}`);
    }
    if (response.status === 204) {
        return null;
    }

    const type = response.headers.get('Content-Type') || '';
    return type.includes('application/json') ? response.json() : response.text();
}

export const api = {
    me: () => call('GET', '/me'),
    users: () => call('GET', '/users'),
    inbox: () => call('GET', '/messages'),
    sent: () => call('GET', '/messages/sent'),
    message: (id) => call('GET', '/messages/' + id),
    send: (message) => call('POST', '/messages', message),
    remove: (id) => call('DELETE', '/messages/' + id),
    exportJson: () => call('GET', '/messages/export'),
};
