import atexit
import os
import secrets
import shutil
import struct
import tempfile
import threading
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename


MAGIC = b"FENC\x01\r\n\x00"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 600_000
HEADER_SIZE = len(MAGIC) + SALT_SIZE + NONCE_SIZE
TAG_SIZE = 16
MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_ENCRYPTED_SIZE = MAX_FILE_SIZE + 4096
MAX_PASSWORD_BYTES = 1024
OUTPUT_TTL_SECONDS = 60 * 60


def _derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    ).derive(password.encode("utf-8"))


def encrypt_bytes(file_data: bytes, password: str, filename: str) -> bytes:
    """Return a versioned, authenticated encrypted file."""
    if len(file_data) > MAX_FILE_SIZE:
        raise ValueError("The file exceeds the 25 MiB limit.")

    safe_name = secure_filename(filename) or "encrypted-file"
    name_bytes = safe_name.encode("utf-8")
    if len(name_bytes) > 1024:
        raise ValueError("The filename is too long.")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    header = MAGIC + salt + nonce
    plaintext = struct.pack(">H", len(name_bytes)) + name_bytes + file_data
    encrypted = AESGCM(_derive_key(password, salt)).encrypt(nonce, plaintext, header)
    return header + encrypted


def decrypt_bytes(encrypted_data: bytes, password: str) -> tuple[bytes, str]:
    """Authenticate and decrypt a file, returning its content and safe filename."""
    if len(encrypted_data) > MAX_ENCRYPTED_SIZE:
        raise ValueError("The encrypted file exceeds the 25 MiB limit.")
    if len(encrypted_data) < HEADER_SIZE + TAG_SIZE + 2:
        raise ValueError("This file is incomplete or is not a supported encrypted file.")
    if not encrypted_data.startswith(MAGIC):
        raise ValueError("This file is not a supported encrypted file.")

    header = encrypted_data[:HEADER_SIZE]
    salt_start = len(MAGIC)
    salt = encrypted_data[salt_start : salt_start + SALT_SIZE]
    nonce_start = salt_start + SALT_SIZE
    nonce = encrypted_data[nonce_start : nonce_start + NONCE_SIZE]

    try:
        plaintext = AESGCM(_derive_key(password, salt)).decrypt(
            nonce, encrypted_data[HEADER_SIZE:], header
        )
    except InvalidTag as error:
        raise ValueError("Incorrect password or damaged encrypted file.") from error

    if len(plaintext) < 2:
        raise ValueError("The encrypted file does not contain valid file metadata.")
    name_length = struct.unpack(">H", plaintext[:2])[0]
    if name_length == 0 or name_length > 1024 or len(plaintext) < 2 + name_length:
        raise ValueError("The encrypted file does not contain valid file metadata.")

    try:
        original_name = plaintext[2 : 2 + name_length].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("The encrypted file contains invalid filename metadata.") from error

    safe_name = secure_filename(original_name) or "decrypted-file"
    file_data = plaintext[2 + name_length :]
    if len(file_data) > MAX_FILE_SIZE:
        raise ValueError("The decrypted file exceeds the 25 MiB limit.")
    return file_data, safe_name


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=secrets.token_hex(32),
        MAX_CONTENT_LENGTH=26 * 1024 * 1024,
        OUTPUT_DIR=None,
    )
    if test_config:
        app.config.update(test_config)

    output_dir = app.config["OUTPUT_DIR"] or tempfile.mkdtemp(prefix="file-encryption-")
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    app.config["OUTPUT_DIR"] = output_dir
    atexit.register(shutil.rmtree, output_dir, ignore_errors=True)

    pending_downloads: dict[str, tuple[str, str, float]] = {}
    downloads_lock = threading.Lock()

    def cleanup_expired_downloads() -> None:
        cutoff = time.time() - OUTPUT_TTL_SECONDS
        with downloads_lock:
            expired = [token for token, (_, _, created) in pending_downloads.items() if created < cutoff]
            expired_paths = [pending_downloads.pop(token)[0] for token in expired]
        for path in expired_paths:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

    def save_download(data: bytes, filename: str) -> str:
        cleanup_expired_downloads()
        token = secrets.token_urlsafe(32)
        with tempfile.NamedTemporaryFile(dir=output_dir, prefix="download-", delete=False) as output:
            output.write(data)
            output_path = output.name
        with downloads_lock:
            pending_downloads[token] = (output_path, filename, time.time())
        return token

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/")
    def index():
        cleanup_expired_downloads()
        token = request.args.get("download", "")
        with downloads_lock:
            pending = pending_downloads.get(token)
        download_url = url_for("download", token=token) if pending else None
        download_name = pending[1] if pending else None
        return render_template("index.html", download_url=download_url, download_name=download_name)

    @app.post("/encrypt")
    def encrypt():
        uploaded = request.files.get("file")
        password = request.form.get("password", "")
        if uploaded is None or not uploaded.filename:
            flash("Choose a file to encrypt.", "error")
            return redirect(url_for("index"))
        if not password:
            flash("Enter a password for encryption.", "error")
            return redirect(url_for("index"))
        if len(password) < 12:
            flash("Use at least 12 characters for a new encryption password.", "error")
            return redirect(url_for("index"))
        if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
            flash("The password is too long.", "error")
            return redirect(url_for("index"))

        file_data = uploaded.stream.read(MAX_FILE_SIZE + 1)
        if len(file_data) > MAX_FILE_SIZE:
            flash("The file exceeds the 25 MiB limit.", "error")
            return redirect(url_for("index"))
        safe_name = secure_filename(uploaded.filename) or "encrypted-file"
        try:
            encrypted_data = encrypt_bytes(file_data, password, safe_name)
        except ValueError as error:
            flash(str(error), "error")
            return redirect(url_for("index"))

        token = save_download(encrypted_data, f"{safe_name}.enc")
        flash("Encryption complete. Your download is ready.", "success")
        return redirect(url_for("index", download=token))

    @app.post("/decrypt")
    def decrypt():
        uploaded = request.files.get("file")
        password = request.form.get("password", "")
        if uploaded is None or not uploaded.filename:
            flash("Choose an encrypted file to decrypt.", "error")
            return redirect(url_for("index"))
        if not password:
            flash("Enter the password used to encrypt this file.", "error")
            return redirect(url_for("index"))
        if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
            flash("The password is too long.", "error")
            return redirect(url_for("index"))

        encrypted_data = uploaded.stream.read(MAX_ENCRYPTED_SIZE + 1)
        try:
            file_data, original_name = decrypt_bytes(encrypted_data, password)
        except ValueError as error:
            flash(str(error), "error")
            return redirect(url_for("index"))

        token = save_download(file_data, original_name)
        flash("Decryption complete. Your download is ready.", "success")
        return redirect(url_for("index", download=token))

    @app.get("/download/<token>")
    def download(token: str):
        cleanup_expired_downloads()
        with downloads_lock:
            pending = pending_downloads.pop(token, None)
        if pending is None:
            abort(404)

        output_path, filename, _ = pending
        response = send_file(
            output_path,
            as_attachment=True,
            download_name=filename,
            conditional=False,
            max_age=0,
        )

        def remove_download() -> None:
            try:
                os.remove(output_path)
            except FileNotFoundError:
                pass

        response.call_on_close(remove_download)
        return response

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        flash("The upload is too large. Files must be 25 MiB or smaller.", "error")
        return redirect(url_for("index"))

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)