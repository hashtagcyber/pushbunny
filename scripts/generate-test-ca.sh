#!/bin/bash

# Script to generate a Certificate Authority for signing SSH keys for Pushbunny

# Set variables
CA_NAME="PushbunnySSHCA"
PROJECT_DIR="$(pwd)"  # Assumes the script is run from the project root
CA_DIR="$PROJECT_DIR/.ssh_ca"
CA_PRIVATE_KEY="$CA_DIR/${CA_NAME}_ca"
CA_PUBLIC_KEY="${CA_PRIVATE_KEY}.pub"
VALIDITY_PERIOD=3650  # 10 years

# Create CA directory if it doesn't exist
mkdir -p "$CA_DIR"

# Generate the CA key pair
ssh-keygen -t ed25519 -f "$CA_PRIVATE_KEY" -C "$CA_NAME" -N ""

# Set appropriate permissions
chmod 700 "$CA_DIR"
chmod 600 "$CA_PRIVATE_KEY"
chmod 644 "$CA_PUBLIC_KEY"

echo "Certificate Authority created successfully."
echo "Private key: $CA_PRIVATE_KEY"
echo "Public key: $CA_PUBLIC_KEY"

# Add CA directory to .gitignore if not already present
if ! grep -q "^\.ssh_ca/$" "$PROJECT_DIR/.gitignore"; then
    echo ".ssh_ca/" >> "$PROJECT_DIR/.gitignore"
    echo "Added .ssh_ca/ to .gitignore"
fi

# Function to sign a user's public key
sign_user_key() {
    local user_key="$1"
    local username="$2"
    
    ssh-keygen -s "$CA_PRIVATE_KEY" -I "$username" -n "$username" -V "+${VALIDITY_PERIOD}d" "$user_key"
    echo "Signed key for $username: ${user_key}-cert.pub"
}

echo "To sign a user's public key, use:"
echo "./$(basename "$0") sign /path/to/user_public_key.pub username"

# Check if we're signing a key
if [ "$1" = "sign" ] && [ -n "$2" ] && [ -n "$3" ]; then
    sign_user_key "$2" "$3"
fi

# Print the paths for use in .env file
echo "Add the following to your .env file:"
echo "SSH_CA_PRIVATE_KEY_PATH=$CA_PRIVATE_KEY"
echo "SSH_CA_PUBLIC_KEY_PATH=$CA_PUBLIC_KEY"
