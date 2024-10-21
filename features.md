# Features
## Objectives
- Provide a platform for enterprise users to register yubikeyauthenticators
- Once registered, the user can use their authenticator to:
    - Generate signed SSH keys that expire within a set time period
    - Generate a JWT for API access
- Provide a CLI for the above functionality
- Administrators should be able to:
    - Configure SAML authentication for google workspace users
    - Configure templates for SSH keys and JWT claims
    - Disable/Enable users
    - Revoke SSH keys and JWTs
- SSH Certificate Authority should be set via a CA bundle file.
    - The CA bundle should be uploaded by the administrator and can be rotated.
    - The CA bundle should be password protected.
    - The CA bundle password should be read from an environment variable.
    - The CA bundle path should be set via an environment variable.

## Requirements
- Docker container for the service
- Build script for the container
- Bootstrap script for generating the CA bundle
- CLI for users to access the service once registered
- README file that explains the setup and configuration
- User documentation

## Technologies
- Use Supabase for authentication, storage, and database
- Use docker to run the service
- Pick a language that has the best support for FIDO2 and WebAuthn