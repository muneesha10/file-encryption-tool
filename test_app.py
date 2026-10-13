import io
import re
import tempfile
import unittest
from pathlib import Path

from app import create_app, decrypt_bytes, encrypt_bytes


class EncryptionTests(unittest.TestCase):
    def test_binary_file_round_trip(self):
        original = bytes(range(256)) * 4
        encrypted = encrypt_bytes(original, "correct horse battery staple", "sample.bin")
        decrypted, filename = decrypt_bytes(encrypted, "correct horse battery staple")

        self.assertEqual(decrypted, original)
        self.assertEqual(filename, "sample.bin")
        self.assertNotIn(original, encrypted)

    def test_wrong_password_is_rejected(self):
        encrypted = encrypt_bytes(b"private", "correct horse battery staple", "note.txt")

        with self.assertRaisesRegex(ValueError, "Incorrect password or damaged"):
            decrypt_bytes(encrypted, "not the right password")

    def test_unsupported_or_corrupted_input_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "not a supported encrypted file"):
            decrypt_bytes(b"not an encrypted file", "a password")

        encrypted = bytearray(encrypt_bytes(b"private", "correct horse battery staple", "note.txt"))
        encrypted[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "Incorrect password or damaged"):
            decrypt_bytes(bytes(encrypted), "correct horse battery staple")


class WebApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING": True, "OUTPUT_DIR": self.temp_dir.name})
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_encrypt_and_download(self):
        response = self.client.post(
            "/encrypt",
            data={
                "password": "correct horse battery staple",
                "file": (io.BytesIO(b"\x00\x01binary\xff"), "sample.bin"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 302)

        page = self.client.get(response.location)
        self.assertIn(b"Encryption complete", page.data)
        match = re.search(rb'href="(/download/[^\"]+)"', page.data)
        self.assertIsNotNone(match)

        download = self.client.get(match.group(1).decode())
        self.assertEqual(download.status_code, 200)
        self.assertIn("sample.bin.enc", download.headers["Content-Disposition"])
        self.assertTrue(download.data.startswith(b"FENC"))
        download.close()

    def test_wrong_password_shows_error(self):
        encrypted = encrypt_bytes(b"private", "correct horse battery staple", "note.txt")
        response = self.client.post(
            "/decrypt",
            data={
                "password": "incorrect password",
                "file": (io.BytesIO(encrypted), "note.txt.enc"),
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertIn(b"Incorrect password or damaged encrypted file", response.data)
        self.assertFalse(list(Path(self.temp_dir.name).iterdir()))


if __name__ == "__main__":
    unittest.main()