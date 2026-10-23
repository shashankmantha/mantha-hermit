"""minisign-compatible signing and verification (Ed25519, prehashed with BLAKE2b-512).

Files are byte-for-byte the format of https://jedisct1.github.io/minisign/, so either side can use
the `minisign` tool instead:

  public key  line 2 = base64("Ed" + key_id[8] + public_key[32])
  signature   line 2 = base64("ED" + key_id[8] + signature[64])     signature over BLAKE2b-512(file)
              line 3 = "trusted comment: <text>"
              line 4 = base64(signature[64] over signature + text)   (the "global" signature)
  secret key  base64("Ed" + kdf_alg[2] + "B2" + salt[32] + opslimit[8] + memlimit[8]
                     + key_id[8] + secret_key[64] + checksum[32])

Hermit signs with password-free keys itself. Password-protected keys (kdf "Sc", made by
`minisign -G`) are signed by calling the `minisign` tool, which asks for the password.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import shutil
import subprocess
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class SignatureError(Exception):
    pass


def _b64line(lines: list[str], i: int, what: str) -> bytes:
    try:
        return base64.b64decode(lines[i].strip(), validate=True)
    except (IndexError, ValueError) as exc:
        raise SignatureError(f"{what}: not a minisign file (line {i + 1})") from exc


def load_public_key(text: str) -> tuple[bytes, Ed25519PublicKey]:
    """From a .pub file's text, or a bare base64 key string (like `minisign -P`)."""
    lines = [x for x in text.strip().splitlines() if x.strip()]
    raw = _b64line(lines, 1 if len(lines) > 1 else 0, "public key")
    if len(raw) != 42 or raw[:2] != b"Ed":
        raise SignatureError("public key: unsupported format")
    return raw[2:10], Ed25519PublicKey.from_public_bytes(raw[10:])


def generate_keypair(pub_path: Path, sec_path: Path, force: bool = False) -> str:
    """A password-free key pair, the same as `minisign -G -W`: for demos, tests and local use,
    not for the release key. Returns the public key line."""
    for p in (pub_path, sec_path):
        if p.exists() and not force:
            raise SignatureError(f"{p} already exists (use --force to replace it)")
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                              serialization.NoEncryption())
    pk = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_id = secrets.token_bytes(8)
    sk = (b"Ed" + b"\0\0" + b"B2" + b"\0" * 32 + b"\0" * 16 + key_id + seed + pk + b"\0" * 32)
    sec_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(sec_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("untrusted comment: minisign encrypted secret key\n" + base64.b64encode(sk).decode() + "\n")
    os.chmod(sec_path, 0o600)
    kid = key_id[::-1].hex().upper()
    pub_line = base64.b64encode(b"Ed" + key_id + pk).decode()
    pub_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.write_text(f"untrusted comment: minisign public key {kid}\n{pub_line}\n")
    return pub_line


def _load_secret(sec_path: Path) -> tuple[bytes, Ed25519PrivateKey] | None:
    """The key if it isn't password-protected; None if it is (use the minisign tool)."""
    lines = sec_path.read_text().splitlines()
    raw = _b64line(lines, 1, "secret key")
    if len(raw) != 158 or raw[:2] != b"Ed" or raw[4:6] != b"B2":
        raise SignatureError("secret key: unsupported format")
    if raw[2:4] != b"\0\0":
        return None
    key_id, sk, chk = raw[54:62], raw[62:126], raw[126:158]
    if chk != b"\0" * 32 and hashlib.blake2b(raw[:2] + key_id + sk, digest_size=32).digest() != chk:
        raise SignatureError("secret key: checksum mismatch (corrupted file?)")
    return key_id, Ed25519PrivateKey.from_private_bytes(sk[:32])


def is_encrypted(sec_path: Path) -> bool:
    """True if the secret key is password-protected."""
    return _load_secret(sec_path) is None


def generate_protected_keypair(pub_path: Path, sec_path: Path, force: bool = False) -> str:
    """A password-protected key pair, made by the minisign tool (it asks for the password).
    Returns the public key line."""
    exe = shutil.which("minisign")
    if not exe:
        raise SignatureError("the minisign tool is needed for a password-protected key "
                             "(install it, or use --no-password for a test key)")
    for p in (pub_path, sec_path):
        if p.exists() and not force:
            raise SignatureError(f"{p} already exists (use --force to replace it)")
    sec_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run([exe, "-G", "-p", str(pub_path), "-s", str(sec_path)] + (["-f"] if force else []),
                       check=True)
    except subprocess.CalledProcessError as exc:
        raise SignatureError(f"minisign -G failed (exit {exc.returncode})") from None
    os.chmod(sec_path, 0o600)
    return pub_path.read_text().splitlines()[1]


def sign_file(path: Path, sec_path: Path, trusted_comment: str) -> Path:
    if "\n" in trusted_comment or "\r" in trusted_comment:
        raise SignatureError("trusted comment must be one line")
    sig_path = path.with_name(path.name + ".minisig")
    loaded = _load_secret(sec_path)
    if loaded is None:
        exe = shutil.which("minisign")
        if not exe:
            raise SignatureError("this secret key is password-protected; install minisign to sign with it")
        subprocess.run([exe, "-S", "-s", str(sec_path), "-m", str(path), "-x", str(sig_path),
                        "-t", trusted_comment], check=True)
        return sig_path
    key_id, priv = loaded
    with open(path, "rb") as fh:
        digest = hashlib.blake2b(fh.read(), digest_size=64).digest()
    sig = priv.sign(digest)
    global_sig = priv.sign(sig + trusted_comment.encode())
    sig_path.write_text("untrusted comment: signature from hermit (minisign format)\n"
                        + base64.b64encode(b"ED" + key_id + sig).decode() + "\n"
                        + f"trusted comment: {trusted_comment}\n"
                        + base64.b64encode(global_sig).decode() + "\n")
    return sig_path


def verify_file(path: Path, sig_path: Path, public_key_text: str) -> str:
    """Verify a minisign signature. Returns the trusted comment; raises SignatureError."""
    key_id, pk = load_public_key(public_key_text)
    lines = sig_path.read_text().splitlines()
    sig = _b64line(lines, 1, "signature")
    if len(sig) != 74:
        raise SignatureError("signature: unsupported format")
    if sig[2:10] != key_id:
        raise SignatureError("signature was made with a different key")
    if len(lines) < 4 or not lines[2].startswith("trusted comment: "):
        raise SignatureError("signature: missing trusted comment")
    comment = lines[2][len("trusted comment: "):]
    with open(path, "rb") as fh:
        data = fh.read()
    if sig[:2] == b"ED":
        message = hashlib.blake2b(data, digest_size=64).digest()
    elif sig[:2] == b"Ed":
        message = data  # legacy, not prehashed
    else:
        raise SignatureError("signature: unknown algorithm")
    try:
        pk.verify(sig[10:], message)
        pk.verify(_b64line(lines, 3, "signature"), sig[10:] + comment.encode())
    except InvalidSignature as exc:
        raise SignatureError("signature does not match the file (tampered or wrong key)") from exc
    return comment