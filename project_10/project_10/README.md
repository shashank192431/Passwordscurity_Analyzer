# Password Security Analyzer

A small, dependency-free password security learning tool built with HTML, CSS, JavaScript, and Python.

## Run locally

1. Install Python 3.8 or newer.
2. Open a terminal in this directory and run:

   ```powershell
   python server.py
   ```

3. Visit [http://127.0.0.1:8000](http://127.0.0.1:8000).
4. Stop the server with `Ctrl+C`.

The page and API are served from the Python standard library. No packages need to be installed.

## Features

- **Strength estimate:** Checks length, character variety, familiar patterns, and common-password matches. The bit estimate is a rough illustration, not a guarantee or a substitute for a dedicated password-strength estimator.
- **Actionable suggestions:** Highlights weak spots and suggests stronger habits. The built-in generator uses the browser's cryptographically secure random-number generator to create a fresh 20-character password.
- **Local-first analysis:** Analysis and generation happen in your browser. The password is not sent to a service while you type.
- **Hashing demonstration:** The optional demo sends the entered password to the local Python server, which creates a fresh 16-byte random salt and a 32-byte PBKDF2-HMAC-SHA256 digest using 600,000 iterations. The server does not save the password, salt, or digest.

## Important

Use a made-up password for the hashing demonstration, not a password you use for an account. This is a learning project, not a production authentication service. Real applications should use a password-hashing scheme recommended by current platform guidance (such as Argon2id where available), tune its cost for their deployment, store the salt and hash securely, and use HTTPS.