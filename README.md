# Secure Exam Exchange

A small command-line tool for encrypting an examination paper for a recipient
and signing the resulting package so the recipient can authenticate its sender.

## How the exchange works

The sender encrypts the paper with a fresh AES key, wraps that AES key for the
recipient, and signs the package. The recipient verifies the sender's signature,
unwraps the AES key with their own private key, and authenticates/decrypts the
paper.

There are two different public-key operations:

| Purpose | Key used | Who keeps the matching private key |
|---|---|---|
| Encrypt/wrap the AES key | Recipient's public key | Recipient |
| Sign/verify the package | Sender's private key to sign; sender's public key to verify | Sender |

Never send a private key or its password to another person. Public keys are
meant to be shared, but verify their fingerprints with the other person over a
trusted, separate channel before using them.

## Requirements

- Python 3
- The `cryptography` Python package

Run commands from the project directory. If using the project's virtual
environment, activate it first (for example, `source .venv/bin/activate`).

## One-time key setup

Each participant needs an RSA key pair for their role:

```bash
python3 secure_exchange.py keygen sender
python3 secure_exchange.py keygen recipient
```

The tool prompts for a password to encrypt each private-key file. Use strong,
unique passwords and store them safely. Key generation refuses to overwrite
existing keys.

Share public keys only:

- Give the sender's `sender/public_key.pem` to the recipient. The recipient
  uses it to verify packages from that sender.
- Give the recipient's `recipient/public_key.pem` to the sender. The sender
  uses it to encrypt packages for that recipient.

Compare a public-key fingerprint with its owner using a trusted, separate
channel. For example, on macOS:

```bash
openssl pkey -pubin -in Sender/friend_sender_public.pem -pubout -outform DER | shasum -a 256
```

Run the same command on the original sender's public key and compare the full
SHA-256 value. Repeat for the recipient public key before the sender encrypts.

The sender's `recipient/public_key.pem` must be the recipient public key that
matches the private key the recipient will use to decrypt. The recipient keeps
their matching private key private. Do not replace or send the recipient's
private key.

For this program's current folder layout, key paths may appear as `Sender/` and
`Recipient/` on a case-insensitive filesystem, or lowercase `sender/` and
`recipient/` on another filesystem.

## Sender: create a package

Before encrypting, confirm that:

1. `sender/private_key.pem` is the sender's signing private key.
2. `recipient/public_key.pem` is the intended recipient's public key.
3. The sender and recipient have independently checked the public-key
   fingerprints.

Then create a package:

```bash
python3 secure_exchange.py encrypt path/to/exam_paper.txt exchange/exam_package.json
```

The sender enters the password for `sender/private_key.pem`. Send the generated
JSON package and the sender's public key to the recipient using an appropriate
secure channel. The public key can be sent separately or its fingerprint can
be verified out of band.

## Recipient: verify and decrypt

Save the package under `exchange/` and the verified sender public key under
`Sender/friend_sender_public.pem` (or another path you specify). Choose a new
output path that does not already exist:

```bash
python3 secure_exchange.py decrypt \
  exchange/exam_package.json \
  Recovered/received_exam.txt \
  --sender-public Sender/friend_sender_public.pem
```

Enter the password for the recipient's `recipient/private_key.pem` when
prompted. Decryption writes the recovered paper only after the package
signature and AES-GCM authentication both succeed. The output path is supplied
by the recipient; the filename in package metadata does not choose an output
directory.

## Package and cryptographic format

Use this exact version-1 JSON shape. All binary values are Base64-encoded:

```json
{
  "metadata": {
    "version": 1,
    "filename": "exam_paper.txt",
    "encryption": "AES-256-GCM",
    "key_wrap": "RSA-OAEP-SHA256",
    "signature": "RSA-PSS-SHA256"
  },
  "nonce": "<Base64: 12 bytes>",
  "encrypted_key": "<Base64: RSA-OAEP-wrapped 32-byte AES key>",
  "ciphertext": "<Base64: encrypted file bytes>",
  "tag": "<Base64: 16 bytes>",
  "signature": "<Base64: RSA-PSS signature>"
}
```

Both people must implement these details identically:

- **File encryption:** AES-256-GCM with a newly generated 32-byte AES key and
  a unique, random 12-byte nonce for every package.
- **Authenticated metadata (AAD):** UTF-8 bytes of the metadata JSON serialized
  with sorted keys, compact separators (`,` and `:`), and ASCII-safe encoding.
  In Python, this is equivalent to
  `json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")`.
- **Key wrapping:** RSA-OAEP with SHA-256, MGF1-SHA-256, and no label, using
  the recipient's public key.
- **Package signature:** RSA-PSS with SHA-256, MGF1-SHA-256, and maximum salt
  length, using the sender's private key.
- **Signed bytes:** Serialize the complete package object *before adding the
  `signature` field* with sorted keys, compact separators, and ASCII-safe
  encoding; sign those UTF-8 bytes. Verification removes `signature` and
  serializes the remaining fields the same way.
- **AES-GCM output:** Store ciphertext and the 16-byte tag separately. They
  must come from the same encryption operation with the same AES key, nonce,
  and AAD.

Do not rename fields, add or remove metadata fields, change algorithms, or
reserialize data differently without updating both implementations. In
particular, a package that merely has the right JSON fields can still fail if
the AAD or signed bytes differ.

## Pre-send / pre-receive checklist

Before sending:

- Confirm the recipient public-key fingerprint with the recipient.
- Confirm the package was encrypted to that exact recipient key.
- Confirm the package was signed by the sender private key matching the
  supplied sender public key.
- Confirm the package follows the schema and algorithm details above.
- Send the encrypted package and sender public key; never send private keys,
  passwords, or plaintext through the package channel.

Before decrypting:

- Confirm the sender public-key fingerprint with the sender.
- Confirm the recipient private key is the pair for the public key the sender
  used to encrypt the package.
- Keep the package unchanged after it was signed.
- Choose a new, non-existing output path.

## Troubleshooting

| Error | What it indicates | What to check |
|---|---|---|
| `Invalid package structure` | Missing, unexpected, or misspelled JSON fields | Use the exact top-level fields shown above. |
| `InvalidSignature` | The signature did not verify for these package bytes and this sender public key | Check that the sender public key matches the signing private key, the package is unmodified, and canonicalization/signature settings match. |
| `Invalid metadata` / `Unsupported package metadata` | Metadata fields or values differ from version 1 | Use exactly the five metadata fields and values shown above. |
| `Invalid AES-GCM nonce or tag length` | Nonce or tag has the wrong decoded byte length | Nonce must be 12 bytes; tag must be 16 bytes. |
| RSA decryption error | The recipient private key could not unwrap the encrypted AES key | Check that the package was encrypted to the public key paired with this recipient private key and that OAEP settings match. |
| `InvalidTag` | AES-GCM could not authenticate the ciphertext and metadata | Check that the AES key, nonce, ciphertext, tag, and exact canonical metadata AAD all belong to the same encryption operation. A valid sender signature does not by itself prove the sender used the same AAD convention as the receiver. |
| Password/decryption error loading private key | The private-key password is incorrect, or the key file is not the expected private key | Use the password for the recipient private key; never send it to the sender. |

The decrypt command validates in order: package structure, sender signature,
metadata, recipient RSA key unwrap, then AES-GCM authentication. A failure at
one step means later steps have not yet been confirmed.

## Tests

The CLI exposes a `test` command:

```bash
python3 secure_exchange.py test
```

It requires free `exchange/package_1.json` and `exchange/package_2.json` paths;
the encryption routine refuses to overwrite existing package files. It also
rewrites `tests/sample_exam.txt` and prompts for the sender private-key
password.

**Current limitation:** the security-test block in `run_tests()` is not
currently reached by this command, so do not treat a successful exit as proof
that all tampering and wrong-key checks ran. Review/fix the test routine before
relying on it as a complete test suite.
