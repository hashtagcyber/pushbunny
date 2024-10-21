import {
    get,
    parseRequestOptionsFromJSON,
} from '/static/js/webauthn-json.browser-ponyfill.js';

async function testKeys() {
    try {
        console.log("Starting authentication");
        const getOptions = await fetch('/authenticate/begin', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({}),
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

        options.publicKey.challenge = ensureArrayBuffer(options.publicKey.challenge);
        if (options.publicKey.allowCredentials) {
            options.publicKey.allowCredentials = options.publicKey.allowCredentials.map(cred => {
                cred.id = ensureArrayBuffer(cred.id);
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
        const testResultElement = document.getElementById('testResult');
        if (result.status === 'OK') {
            testResultElement.textContent = `Authentication successful! Key used: ${result.key_name}`;
            testResultElement.style.color = 'green';
        } else {
            testResultElement.textContent = 'Authentication failed.';
            testResultElement.style.color = 'red';
        }
    } catch (error) {
        console.error('Error during authentication:', error);
        const testResultElement = document.getElementById('testResult');
        testResultElement.textContent = 'Authentication failed: ' + error.message;
        testResultElement.style.color = 'red';
    }
}

function ensureArrayBuffer(input) {
    if (input instanceof ArrayBuffer) {
        return input;
    }
    if (typeof input === 'string') {
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
    const testKeysButton = document.getElementById('testKeysButton');
    if (testKeysButton) {
        testKeysButton.addEventListener('click', testKeys);
    }
});
