import {
    create,
    parseCreationOptionsFromJSON,
} from '/static/js/webauthn-json.browser-ponyfill.js';

async function addKey() {
    try {
        console.log("Starting key addition");
        alert("Please ensure your YubiKey or other external security key is connected.");
        
        const createOptions = await fetch('/register/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'same-origin'
        }).then(res => {
            if (!res.ok) {
                return res.json().then(err => { throw new Error(err.error || `HTTP error! status: ${res.status}`); });
            }
            return res.json();
        });

        console.log("Create options received:", createOptions);
        let options = parseCreationOptionsFromJSON(createOptions);

        console.log("Parsed options:", options);

        // Convert base64 to ArrayBuffer for challenge and user.id if needed
        options.publicKey.challenge = ensureArrayBuffer(options.publicKey.challenge);
        options.publicKey.user.id = ensureArrayBuffer(options.publicKey.user.id);
        if (options.publicKey.excludeCredentials) {
            options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(cred => {
                cred.id = ensureArrayBuffer(cred.id);
                // Remove transports if it's not present
                if (!cred.transports) {
                    delete cred.transports;
                }
                return cred;
            });
        }

        console.log("Options after conversion:", options);

        let credential = await create(options);
        console.log("Credential created:", credential);

        const result = await fetch('/register/complete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(credential),
            credentials: 'same-origin'
        }).then(res => {
            if (!res.ok) {
                throw new Error(`HTTP error! status: ${res.status}`);
            }
            return res.json();
        });

        console.log("Key addition result:", result);
        alert(result.status === 'OK' ? 'Key added successfully!' : 'Key addition failed.');
        window.location.href = '/dashboard';
    } catch (error) {
        console.error('Error during key addition:', error);
        alert('Key addition failed: ' + error.message);
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
    document.getElementById('addKeyButton').addEventListener('click', addKey);
});
