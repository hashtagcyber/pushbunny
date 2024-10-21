# Refactoring Plan for Pushbunny Auth

1. Remove app.py: ✅
   - Ensured all functionality has been moved to appropriate files in the new structure.
   - Deleted app.py.

2. Update imports: ✅
   - Reviewed all Python files and updated imports to reflect the new structure.
   - Ensured all necessary modules are imported in each file.

3. Consolidate authentication logic:
   - Move all authentication-related functions to app/routes/auth.py.
   - Update app/__init__.py to properly initialize authentication.

4. Update static file handling: ✅
   - Ensured all static files (JS, CSS) are properly served from the new structure.
   - Updated references in HTML templates.

5. Review and update templates: ✅
   - Ensured all templates are in the correct location (app/templates/).
   - Updated references to routes and static files in the templates.

6. Implement proper error handling: ✅
   - Created custom exception classes.
   - Implemented a global error handler for consistent error responses.

7. Implement logging: ✅
   - Set up proper logging configuration in app/__init__.py.
   - Replaced print statements with appropriate logging calls.

8. Update configuration handling: ✅
   - Ensured all configuration is properly loaded from environment variables or config files.
   - Moved remaining hardcoded configuration to the config.py file.

9. Review and update JavaScript files: ✅
   - Ensured all JavaScript files are properly linked in the HTML templates.
   - Updated API endpoints in the JavaScript files to match the new route structure.

10. Test the application:
    - Manually test all functionality to ensure it works with the new structure.
    - Write unit tests for critical components. ✅
      - Created basic test structure
      - Implemented initial tests for auth and SSH key functionality
      - TODO: Add more comprehensive tests for all components

11. Update documentation:
    - Update README.md with new setup and running instructions.
    - Document any changes to the project structure or configuration.

12. Clean up:
    - Remove any unused files or code.
    - Ensure consistent code style across all files.

# Refactoring Notes for Pushbunny Auth

- When using datetime functionality, import the datetime class from the datetime module:
  ```python
  from datetime import datetime
  ```
  This allows the use of datetime.now() and other datetime methods.

- In authenticate.js, the main authentication function should be named 'authenticate' instead of 'testKeys' to better reflect its purpose and avoid naming conflicts.

- Ensure that backend routes in auth.py match the endpoints used in frontend JavaScript files. Specifically, add /authenticate/begin and /authenticate/complete routes to handle WebAuthn authentication requests.

- Ensure that button IDs in HTML templates match the IDs used in JavaScript files for event listeners.

- When using ES6 modules, remember to export functions that need to be used in other files or scripts.

- When passing credentials to fido2.server.authenticate_begin(), ensure they are in the correct format:
  ```python
  credentials = [
      PublicKeyCredentialDescriptor(
          type=PublicKeyCredentialType.PUBLIC_KEY,
          id=cred['credential_data'].credential_id
      )
      for cred in user_credentials
  ]
  ```
  This prevents the "missing required positional arguments: 'type' and 'id'" error.

- When serializing data that contains bytes objects (like WebAuthn challenges or credential IDs) to JSON, convert them to base64-encoded strings first:
  ```python
  import base64
  
  # Convert bytes to base64-encoded string
  base64_string = base64.b64encode(bytes_object).decode('ascii')
  ```
  This allows for safe JSON serialization of data containing binary content.

- When accessing attributes of the CredentialRequestOptions object returned by fido2.server.authenticate_begin(), use the public_key attribute:
  ```python
  auth_data, state = current_app.fido_server.authenticate_begin(credentials)
  challenge = auth_data.public_key.challenge
  timeout = auth_data.public_key.timeout
  rp_id = auth_data.public_key.rp_id
  allow_credentials = auth_data.public_key.allow_credentials
  user_verification = auth_data.public_key.user_verification
  ```
  This ensures you're accessing the correct attributes of the PublicKeyCredentialRequestOptions object.

- When handling WebAuthn authentication completion, manually create the necessary objects from the received data:
  ```python
  from fido2.webauthn import AuthenticatorData, CollectedClientData
  from fido2.utils import websafe_decode

  credential_id = websafe_decode(data['rawId'])
  client_data = CollectedClientData(websafe_decode(data['response']['clientDataJSON']))
  auth_data = AuthenticatorData(websafe_decode(data['response']['authenticatorData']))
  signature = websafe_decode(data['response']['signature'])
  ```
  This approach provides more flexibility and control over the authentication process.

- When refactoring Flask applications to use blueprints, replace direct `app` references with `current_app`:  ```python
  from flask import current_app

  # Instead of:
  # app.logger.debug("Some message")
  # Use:
  current_app.logger.debug("Some message")

  # Instead of:
  # app.config['SOME_CONFIG']
  # Use:
  current_app.config['SOME_CONFIG']  ```
  This ensures that the correct application context is used, especially when using blueprints.

- SSH key validation should run regardless of the application's debug mode. Ensure that any debug-specific code or configurations do not interfere with core functionality like SSH key validation.
