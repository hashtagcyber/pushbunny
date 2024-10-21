document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.edit-key-name').forEach(button => {
        button.addEventListener('click', function() {
            const keyNameElement = this.closest('.key-name');
            const keyNameTextElement = keyNameElement.querySelector('.key-name-text');
            const currentName = keyNameTextElement.textContent;
            const credentialId = keyNameElement.dataset.credentialId;

            const input = document.createElement('input');
            input.type = 'text';
            input.value = currentName;
            input.className = 'edit-key-name-input';

            const saveButton = document.createElement('button');
            saveButton.textContent = 'Save';
            saveButton.className = 'save-key-name';

            keyNameElement.innerHTML = '';
            keyNameElement.appendChild(input);
            keyNameElement.appendChild(saveButton);

            input.focus();

            saveButton.addEventListener('click', async function() {
                const newName = input.value.trim();
                if (newName && newName !== currentName) {
                    try {
                        const response = await fetch('/edit_key_name', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ credential_id: credentialId, new_name: newName }),
                        });

                        if (response.ok) {
                            keyNameTextElement.textContent = newName;
                        } else {
                            throw new Error('Failed to update key name');
                        }
                    } catch (error) {
                        console.error('Error updating key name:', error);
                        alert('Failed to update key name. Please try again.');
                    }
                }

                keyNameElement.innerHTML = `
                    <span class="key-name-text">${newName || currentName}</span>
                    <button class="edit-key-name">Edit</button>
                `;
            });
        });
    });
});
