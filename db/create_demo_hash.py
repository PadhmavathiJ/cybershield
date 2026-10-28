import hashlib
import secrets
from getpass import getpass

password = getpass("Choose demo login password: ")
confirmation = getpass("Confirm demo login password: ")

if password != confirmation:
    raise SystemExit("Passwords do not match.")

if len(password) < 10:
    raise SystemExit("Use at least 10 characters.")

salt = secrets.token_hex(16)
iterations = 1_000_000

digest = hashlib.pbkdf2_hmac(
    "sha256",
    password.encode("utf-8"),
    salt.encode("utf-8"),
    iterations,
).hex()

print(f"pbkdf2:sha256:{iterations}${salt}${digest}")