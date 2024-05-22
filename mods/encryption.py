import os
import ctypes
from platform import system
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher

class Encryption:
    @staticmethod
    def encrypt(filepath, password, salt, args):
        key = Encryption._derive_key(password, salt)
        for root, dirs, files in os.walk(filepath):
            for name in files:
                filename = os.path.join(root, name)
                Encryption._encrypt_file(filename, key, args)

    @staticmethod
    def _derive_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return kdf.derive(password)

    @staticmethod
    def _encrypt_file(filename, key, args):
        with open(filename, "rb") as f_in, open(filename + ".enc", "wb") as f_out:
            nonce = os.urandom(24)  # XSalsa20 uses a 24-byte nonce
            cipher = Cipher(algorithms.XSalsa20(key, nonce), mode=None).encryptor()
            f_out.write(nonce)  # Save nonce to the beginning of the file
            f_out.write(cipher.update(f_in.read()) + cipher.finalize())
        
        if not args.quiet:
            print(f"Encrypted: {filename}")
        
        os.remove(filename)

    @staticmethod
    def get_system():
        systems = {
            "Windows": "win",
            "Linux": "lin",
            "Darwin": "mac"
        }
        return systems.get(system(), "invalid")

    @staticmethod
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except AttributeError:
            return False

# Example usage:
# Encryption.encrypt('/path/to/files', b'mypassword', b'mysalt', args)
# Note: Ensure `args` has a `quiet` attribute (e.g., args.quiet) as expected by the methods.
