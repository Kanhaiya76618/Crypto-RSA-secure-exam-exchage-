
import argparse
import base64
import getpass
import json
import os
import secrets
import stat
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


ROOT = Path(__file__).resolve().parent
SENDER = ROOT / "sender"
RECIPIENT = ROOT / "recipient"
EXCHANGE = ROOT / "exchange"
RECOVERED = ROOT / "recovered"
TESTS = ROOT / "tests"

for folder in (SENDER, RECIPIENT, EXCHANGE, RECOVERED, TESTS):
    folder.mkdir(parents=True, exist_ok=True)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(data):
    return base64.b64decode(data, validate=True)


def canonical(data):
    """Deterministic JSON bytes for signing and verification."""
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def save_private_key(path, private_key):
    password = getpass.getpass(
        f"Create password for {path.name}: "
    )
    confirm = getpass.getpass("Confirm password: ")

    if not password or password != confirm:
        raise ValueError("Passwords must match and cannot be empty.")

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password.encode("utf-8")
        ),
    )
    path.write_bytes(pem)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def load_private_key(path):
    password = getpass.getpass(
        f"Password for {path.name}: "
    ).encode("utf-8")

    return serialization.load_pem_private_key(
        path.read_bytes(), password=password
    )


def load_public_key(path):
    path = Path(path)
    return serialization.load_pem_public_key(path.read_bytes())

def generate_keys(owner):
    folder = SENDER if owner == "sender" else RECIPIENT
    private_path = folder / "private_key.pem"
    public_path = folder / "public_key.pem"

    if private_path.exists() or public_path.exists():
        raise FileExistsError(
            f"{owner} keys already exist. Refusing to overwrite them."
        )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    save_private_key(private_path, private_key)

    public_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    print(f"{owner.capitalize()} keys generated in {folder}")


def encrypt_file(input_path, output_path):
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.is_file():
        raise FileNotFoundError("Input examination paper not found.")

    if output_path.exists():
        raise FileExistsError("Output package already exists.")

    sender_private = load_private_key(SENDER / "private_key.pem")
    recipient_public = load_public_key(RECIPIENT / "public_key.pem")

    if not isinstance(sender_private, rsa.RSAPrivateKey):
        raise ValueError("Sender key must be an RSA private key.")
    if not isinstance(recipient_public, rsa.RSAPublicKey):
        raise ValueError("Recipient key must be an RSA public key.")

    # A fresh AES-256 key and 96-bit nonce for each encryption.
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)

    metadata = {
        "version": 1,
        "filename": input_path.name,
        "encryption": "AES-256-GCM",
        "key_wrap": "RSA-OAEP-SHA256",
        "signature": "RSA-PSS-SHA256",
    }

    # Authenticate metadata as AES-GCM additional authenticated data.
    aad = canonical(metadata)
    encrypted = AESGCM(aes_key).encrypt(
        nonce, input_path.read_bytes(), aad
    )

    # AESGCM.encrypt returns ciphertext followed by the 16-byte tag.
    ciphertext, tag = encrypted[:-16], encrypted[-16:]

    wrapped_key = recipient_public.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    package = {
        "metadata": metadata,
        "nonce": b64(nonce),
        "encrypted_key": b64(wrapped_key),
        "ciphertext": b64(ciphertext),
        "tag": b64(tag),
    }

    # Sign every package field, including metadata and the GCM tag.
    signature = sender_private.sign(
        canonical(package),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    package["signature"] = b64(signature)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical(package))
    print(f"Encrypted and signed package saved to {output_path}")


def decrypt_file(package_path, output_path, sender_public_path):
    package_path = Path(package_path)
    output_path = Path(output_path)

    if output_path.exists():
        raise FileExistsError(
            "Output already exists. Choose a new output path."
        )

    # Do not release any plaintext until every check succeeds.
    package = json.loads(package_path.read_text(encoding="utf-8"))

    required = {
        "metadata", "nonce", "encrypted_key",
        "ciphertext", "tag", "signature"
    }
    if not isinstance(package, dict) or set(package) != required:
        raise ValueError("Invalid package structure.")

    signature = unb64(package["signature"])
    signed_data = {
        key: value for key, value in package.items()
        if key != "signature"
    }

    sender_public = load_public_key(sender_public_path)
    if not isinstance(sender_public, rsa.RSAPublicKey):
        raise ValueError("Sender verification key must be RSA.")

    # Authenticate the sender and package before attempting decryption.
    sender_public.verify(
        signature,
        canonical(signed_data),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    metadata = package["metadata"]
    if not isinstance(metadata, dict) or set(metadata) != {
        "version", "filename", "encryption", "key_wrap", "signature"
    }:
        raise ValueError("Invalid metadata.")

    if (
        metadata["version"] != 1
        or metadata["encryption"] != "AES-256-GCM"
        or metadata["key_wrap"] != "RSA-OAEP-SHA256"
        or metadata["signature"] != "RSA-PSS-SHA256"
    ):
        raise ValueError("Unsupported package metadata.")

    # Prevent a filename in the package from choosing an arbitrary path.
    filename = metadata["filename"]
    if (
        not isinstance(filename, str)
        or not filename
        or filename in (".", "..")
        or Path(filename).name != filename
        or "/" in filename
        or "\\" in filename
        or "\x00" in filename
    ):
        raise ValueError("Unsafe output filename.")

    nonce = unb64(package["nonce"])
    tag = unb64(package["tag"])
    ciphertext = unb64(package["ciphertext"])
    wrapped_key = unb64(package["encrypted_key"])

    if len(nonce) != 12 or len(tag) != 16:
        raise ValueError("Invalid AES-GCM nonce or tag length.")

    recipient_private = load_private_key(
        RECIPIENT / "private_key.pem"
    )
    if not isinstance(recipient_private, rsa.RSAPrivateKey):
        raise ValueError("Recipient key must be an RSA private key.")

    aes_key = recipient_private.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    if len(aes_key) != 32:
        raise ValueError("Invalid AES-256 session key.")

    # GCM checks authenticity before returning plaintext.
    plaintext = AESGCM(aes_key).decrypt(
        nonce, ciphertext + tag, canonical(metadata)
    )

    # Write only after signature and GCM authentication both succeed.
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("xb") as output:
        output.write(plaintext)

    print(f"Verified and recovered file: {output_path}")


def expect_failure(label, action):
    try:
        action()
    except Exception as exc:
        print(f"PASS - {label}: rejected ({type(exc).__name__})")
        return
    raise AssertionError(f"FAIL - {label}: invalid input was accepted")


def run_tests():
    original = TESTS / "sample_exam.txt"
    original.write_text(
        "Sample examination paper\nQuestion 1: Explain encryption.\n",
        encoding="utf-8",
    )

    first = EXCHANGE / "package_1.json"
    second = EXCHANGE / "package_2.json"

    encrypt_file(original, first)
    encrypt_file(original, second)

    if first.read_bytes() == second.read_bytes():
        raise AssertionError("Two encryptions produced identical packages.")
    print("PASS - Same file produces different packages")

    good_output = RECOVERED / "recovered_exam.txt"
    decrypt_file(first, good_output, SENDER / "public_key.pem")
    assert good_output.read_bytes() == original.read_bytes()
    good_output.unlink()
    print("PASS - Authorized recipient recovers original file")

    original_package = json.loads(first.read_text(encoding="utf-8"))

def tampered_package(field, destination):
    altered = json.loads(json.dumps(original_package))

    if field == "metadata":
        altered["metadata"]["filename"] += ".tampered"
    else:
        altered[field] = altered[field] + " "

    destination.write_bytes(canonical(altered))
    # Alter each of the package's main signed fields independently.
    for field in ("ciphertext", "metadata", "signature"):
        altered_path = TESTS / f"tampered_{field}.json"
        tampered_package(field, altered_path)
        target = RECOVERED / f"must_not_exist_{field}.txt"
        expect_failure(
            f"{field} tampering",
            lambda p=altered_path, t=target: decrypt_file(
                p, t, SENDER / "public_key.pem"
            ),
        )
        assert not target.exists()

    wrong_sender = RECIPIENT / "public_key.pem"
    target = RECOVERED / "wrong_sender.txt"
    expect_failure(
        "Incorrect sender public key",
        lambda: decrypt_file(first, target, wrong_sender),
    )
    assert not target.exists()

    # Build a different recipient key in memory to simulate a wrong key.
    wrong_private = rsa.generate_private_key(
        public_exponent=65537, key_size=3072
    )
    bad_wrapped = wrong_private.public_key().encrypt(
        secrets.token_bytes(32),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    wrong_package = json.loads(json.dumps(original_package))
    wrong_package["encrypted_key"] = b64(bad_wrapped)
    # Re-sign using the legitimate sender key to isolate the OAEP test.
    sender_private = load_private_key(SENDER / "private_key.pem")
    signed_data = {
        key: value for key, value in wrong_package.items()
        if key != "signature"
    }
    wrong_package["signature"] = b64(sender_private.sign(
        canonical(signed_data),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    ))
    wrong_key_path = TESTS / "wrong_recipient_key.json"
    wrong_key_path.write_bytes(canonical(wrong_package))

    expect_failure(
        "Incorrect recipient private key",
        lambda: decrypt_file(
            wrong_key_path, RECOVERED / "wrong_key.txt",
            SENDER / "public_key.pem"
        ),
    )
    assert not (RECOVERED / "wrong_key.txt").exists()

    print("\nAll security tests passed.")


def main():
    parser = argparse.ArgumentParser(
        description="Secure examination-paper exchange"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    key_cmd = sub.add_parser("keygen")
    key_cmd.add_argument("owner", choices=["sender", "recipient"])

    enc_cmd = sub.add_parser("encrypt")
    enc_cmd.add_argument("input")
    enc_cmd.add_argument("output")

    dec_cmd = sub.add_parser("decrypt")
    dec_cmd.add_argument("package")
    dec_cmd.add_argument("output")
    dec_cmd.add_argument(
        "--sender-public",
        default=str(SENDER / "public_key.pem"),
    )

    sub.add_parser("test")

    args = parser.parse_args()

    try:
        if args.command == "keygen":
            generate_keys(args.owner)
        elif args.command == "encrypt":
            encrypt_file(args.input, args.output)
        elif args.command == "decrypt":
            decrypt_file(
                args.package, args.output, args.sender_public
            )
        elif args.command == "test":
            run_tests()
    except Exception as exc:
        print(
            f"ERROR: Operation rejected ({type(exc).__name__}): {exc}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
