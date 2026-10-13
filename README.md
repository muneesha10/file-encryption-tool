# Secure File Encryption and Decryption System

A local Flask application for encrypting and decrypting files with AES-256-GCM. Each encrypted file has its own cryptographically random salt and nonce. PBKDF2-HMAC-SHA256 derives the key from the password, and the authenticated file header prevents undetected changes to the format metadata.

## Requirements

- Python 3.10 or newer
- pip
- A modern web browser

## Install and run

Open a terminal in this project folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python app.py
```

If PowerShell blocks virtual-environment activation, run the commands below instead, using the environment's Python directly:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

When Flask starts, open **http://127.0.0.1:5000** in your browser. Stop the server with `Ctrl+C` in the terminal.

## Use

Choose a file and a password of at least 12 characters in the Encrypt section. Save the resulting `.enc` file somewhere separate from the original. To restore it, choose that `.enc` file in the Decrypt section and enter the same password. The original filename is stored inside the authenticated encrypted payload, not in plaintext metadata.

Files are limited to 25 MiB. Passwords are used only for key derivation and are not written to disk or application logs. Download files are placed in a private temporary directory, deleted after download, and expired after one hour when the app next handles a request; the directory is also removed when the app exits.

The application binds to `127.0.0.1` and has Flask debug mode disabled. It is intended for local use and should not be exposed directly to the public internet.

## Run tests

```powershell
python -m unittest -v
```

The tests cover binary file round-trips, incorrect passwords, and unsupported/corrupted encrypted input.