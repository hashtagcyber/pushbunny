import {
    get,
    parseRequestOptionsFromJSON,
} from '/static/js/webauthn-json.browser-ponyfill.js';

async function generateSshKey() {
    try {
        console.log("Starting SSH key generation");
        const getOptions = await fetch('/request_ssh_key', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
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

        const result = await fetch('/sign_ssh_key', {
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

        console.log("SSH key generation result:", result);
        const sshKeyResultElement = document.getElementById('sshKeyResult');
        if (result.private_key && result.certificate) {
            sshKeyResultElement.innerHTML = `
                <h3>SSH Key Generated Successfully</h3>
                <p>Private Key:</p>
                <pre>${result.private_key}</pre>
                <p>Certificate:</p>
                <pre>${result.certificate}</pre>
                <p>Please save these securely. The private key will not be shown again.</p>
            `;
        } else {
            sshKeyResultElement.textContent = 'SSH key generation failed.';
        }

        if (result.certificate) {
            await verifySshKey(result.certificate);
        }
    } catch (error) {
        console.error('Error during SSH key generation:', error);
        const sshKeyResultElement = document.getElementById('sshKeyResult');
        sshKeyResultElement.textContent = 'SSH key generation failed: ' + error.message;
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

async function verifySshKey(certificate) {
    try {
        console.log("Starting SSH key verification");
        const response = await fetch('/verify_ssh_key', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ certificate: certificate }),
            credentials: 'same-origin'
        });

        const result = await response.json();
        console.log("Verification result:", result);

        if (response.ok) {
            if (result.status === 'OK') {
                alert('Certificate is valid. Details:\n' + result.details);
            } else {
                alert('Certificate verification failed: ' + result.message);
            }
        } else {
            throw new Error(result.error || `HTTP error! status: ${response.status}`);
        }
    } catch (error) {
        console.error('Error during SSH key verification:', error);
        alert('SSH key verification failed: ' + error.message);
    }
}

document.addEventListener('DOMContentLoaded', (event) => {
    const generateSshKeyButton = document.getElementById('generateSshKeyButton');
    if (generateSshKeyButton) {
        generateSshKeyButton.addEventListener('click', generateSshKey);
    }
});
