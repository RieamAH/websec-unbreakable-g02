// Opdracht 3: alle cryptografie gebeurt hier, in de browser.
// De server krijgt enkel de ciphertext, het lijnnummer en de MAC te zien.
// Het bericht, de codeboeklijn en de HMAC-sleutel verlaten de browser nooit.

// Het alfabet van de modulo 37-variant: A=0 .. Z=25, 0=26 .. 9=35, _=36 (spatie).
export const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
const N = ALPHABET.length; // 37

// Zet invoer om naar het alfabet: kleine letters worden hoofdletters, een
// spatie wordt _. Andere tekens (é, ?, !, ...) kunnen we niet versleutelen:
// die weigeren we met een duidelijke fout in plaats van ze stil weg te laten.
export function normalize(text) {
    const result = text.toUpperCase().replaceAll(' ', '_');
    const invalid = [...new Set([...result].filter(c => !ALPHABET.includes(c)))];
    if (invalid.length) {
        throw new Error(`Deze tekens kunnen niet versleuteld worden: ${invalid.join(' ')}. ` +
            'Gebruik enkel letters, cijfers en spaties.');
    }
    return result;
}

// Een codeboeklijn mag je met of zonder lijnnummer plakken ("  49  ABC..." of "ABC...").
export function parseKeyLine(text) {
    const key = text.trim().replace(/^\d+\s+/, '').toUpperCase();
    if (!key) {
        throw new Error('Geef de sleutel (de lijn uit het codeboek) in.');
    }
    if (![...key].every(c => ALPHABET.includes(c))) {
        throw new Error('De sleutel bevat enkel A-Z, 0-9 en _. Kopieer de lijn uit het codeboek.');
    }
    return key;
}

function checkLength(text, key) {
    // One-time pad: de sleutel moet minstens zo lang zijn als het bericht.
    // Een sleutel herhalen zou hergebruik zijn, en dan is de pad te kraken.
    if (text.length > key.length) {
        throw new Error(`Het bericht is ${text.length} tekens, de sleutel maar ${key.length}. ` +
            'Een bericht mag niet langer zijn dan de sleutel.');
    }
}

// C[i] = (P[i] + K[i]) mod 37
export function encrypt(plaintext, key) {
    checkLength(plaintext, key);
    return [...plaintext]
        .map((c, i) => ALPHABET[(ALPHABET.indexOf(c) + ALPHABET.indexOf(key[i])) % N])
        .join('');
}

// P[i] = (C[i] - K[i]) mod 37   (+ N zodat het resultaat nooit negatief is)
export function decrypt(ciphertext, key) {
    checkLength(ciphertext, key);
    return [...ciphertext]
        .map((c, i) => ALPHABET[(ALPHABET.indexOf(c) - ALPHABET.indexOf(key[i]) + N) % N])
        .join('');
}

// ------------------------------------------------------------------ HMAC-SHA256

function subtle() {
    // Web Crypto bestaat enkel in een "secure context": HTTPS of localhost.
    if (!window.crypto || !window.crypto.subtle) {
        throw new Error('Web Crypto is niet beschikbaar. Open de app via HTTPS (of localhost).');
    }
    return window.crypto.subtle;
}

function hexToBytes(hex) {
    const clean = hex.trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(clean)) {
        throw new Error('De HMAC-sleutel is 64 hexadecimale tekens (0-9, a-f).');
    }
    return new Uint8Array(clean.match(/../g).map(b => parseInt(b, 16)));
}

function bytesToHex(buffer) {
    return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function importHmacKey(hexKey) {
    // Niet extractable: de sleutel kan na het importeren niet meer uitgelezen worden.
    return subtle().importKey('raw', hexToBytes(hexKey), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

// Waarover gaat de MAC? Niet enkel over de ciphertext, maar ook over de afzender,
// de ontvanger en het lijnnummer. Zo merkt de ontvanger het ook als iemand in de
// databank het lijnnummer of de afzender aanpast. JSON van een array is een
// eenduidige codering: ["a","bc"] en ["ab","c"] geven een verschillende invoer.
function macInput({ sender, recipient, keyLine, body }) {
    return new TextEncoder().encode(JSON.stringify([sender, recipient, Number(keyLine), body]));
}

export async function sign(hexKey, message) {
    const key = await importHmacKey(hexKey);
    return bytesToHex(await subtle().sign('HMAC', key, macInput(message)));
}

// We laten verify de vergelijking doen in plaats van zelf de hex-strings te
// vergelijken met ===. Een gewone vergelijking stopt bij het eerste verschil;
// aan de tijd die dat duurt kan een aanvaller zien hoeveel bytes al kloppen
// (timing attack). verify vergelijkt in constante tijd.
export async function verify(hexKey, message) {
    if (!/^[0-9a-f]{64}$/.test(message.mac || '')) {
        return false;
    }
    const key = await importHmacKey(hexKey);
    return subtle().verify('HMAC', key, hexToBytes(message.mac), macInput(message));
}
