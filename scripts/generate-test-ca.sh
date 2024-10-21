#!/bin/bash

# Script to generate a Certificate Authority for signing SSH keys for Pushbunny

# Set variables
CA_NAME="PushbunnySSHCA"
PROJECT_DIR="$(pwd)"  # Assumes the script is run from the project root
CA_DIR="$PROJECT_DIR/.ssh_ca"
CA_KEY="$CA_DIR/${CA_NAME}_ca"
VALIDITY_PERIOD=3650  # 10 years

# Create CA directory if it doesn't exist
mkdir -p "$CA_DIR"

# Generate the CA key
ssh-keygen -t ed25519 -f "$CA_KEY" -C "$CA_NAME" -N ""

# Set appropriate permissions
chmod 700 "$CA_DIR"
chmod 600 "$CA_KEY"
chmod 644 "${CA_KEY}.pub"

echo "Certificate Authority created successfully."
echo "Private key: $CA_KEY"
echo "Public key: ${CA_KEY}.pub"

# Add CA directory to .gitignore if not already present
if ! grep -q "^\.ssh_ca/$" "$PROJECT_DIR/.gitignore"; then
    echo ".ssh_ca/" >> "$PROJECT_DIR/.gitignore"
    echo "Added .ssh_ca/ to .gitignore"
fi

# Function to sign a user's public key
sign_user_key() {
    local user_key="$1"
    local username="$2"
    
    ssh-keygen -s "$CA_KEY" -I "$username" -n "$username" -V "+${VALIDITY_PERIOD}d" "$user_key"
    echo "Signed key for $username: ${user_key}-cert.pub"
}

# Example usage:
# Uncomment and modify the following line to sign a user's public key
# sign_user_key "/path/to/user_public_key.pub" "username"

echo "To sign a user's public key, use:"
echo "./$(basename "$0") sign /path/to/user_public_key.pub username"

# Check if we're signing a key
if [ "$1" = "sign" ] && [ -n "$2" ] && [ -n "$3" ]; then
    sign_user_key "$2" "$3"
fi