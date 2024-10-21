import {
    get,
    parseRequestOptionsFromJSON,
} from '/static/js/webauthn-json.browser-ponyfill.js';

async function authenticate() {
    const email = document.getElementById('email').value;
    
    try {
        console.log("Starting authentication");
        const getOptions = await fetch('/authenticate/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({email: email}),
            credentials: 'same-origin'
        }).then(res => {
            if (!res.ok) {
                throw new Error(`HTTP error! status: ${res.status}`);
            }
            return res.json();
        });

        console.log("Get options received:", getOptions);
        let options = parseRequestOptionsFromJSON(getOptions);

        console.log("Parsed options:", options);

        // Convert base64url to ArrayBuffer for challenge and allowCredentials if needed
        options.publicKey.challenge = ensureArrayBuffer(options.publicKey.challenge);
        if (options.publicKey.allowCredentials) {
            options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(cred => {
                cred.id = ensureArrayBuffer(cred.id);
                // Remove transports if it's not present
                if (!cred.transports) {
                    delete cred.transports;
                }
                return cred;
            });
        }

        console.log("Options after conversion:", options);

        let credential = await get(options);
        console.log("Credential retrieved:", credential);

        const result = await fetch('/authenticate/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(credential),
            credentials: 'same-origin'
        }).then(async res => {
            if (!res.ok) {
                const errorText = await res.text();
                throw new Error(`HTTP error! status: ${res.status}, message: ${errorText}`);
            }
            return res.json();
        });

        console.log("Authentication result:", result);
        alert(result.status === 'OK' ? 'Authentication successful!' : 'Authentication failed.');
    } catch (error) {
        console.error('Error during authentication:', error);
        alert('Authentication failed: ' + error.message);
    }
}

function ensureArrayBuffer(input) {
    if (input instanceof ArrayBuffer) {
        return input;
    }
    if (typeof input === 'string') {
        // Convert base64url to ArrayBuffer
        const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
        const padLen = (4 - base64.length % 4) % 4;
        const padded = base64 + '='.repeat(padLen);
        const binary = atob(padded);
        const buffer = new ArrayBuffer(binary.length);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < binary.length; i++) {
            view[i] = binary.charCodeAt(i);
        }
        return buffer;
    }
    throw new Error('Input must be ArrayBuffer or base64url string');
}

document.addEventListener('DOMContentLoaded', (event) => {
    document.getElementById('authenticateButton').addEventListener('click', authenticate);
});
