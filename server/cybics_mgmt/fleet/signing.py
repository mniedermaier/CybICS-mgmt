"""
The fleet's job-signing key (docs/MGMT_DESIGN.md, "Jobs").

The server signs every job with RSA-3072, PKCS#1 v1.5 over SHA-256 of the
job's canonical JSON. A device pins the public key at enrolment and runs only
jobs that verify against it, so neither a man in the middle on a classroom
network nor anybody who can only talk to the device can make it run one.

The key lives in the data volume and is created on first use, not at start:
most installations never create a job. A key that exists but cannot be read
is an error, never silently replaced: every enrolled device has pinned it.
A missing key is created only while no device is enrolled; after that it has
to come back from a backup, or be replaced on purpose (`flask --app
cybics_mgmt new-signing-key`).
"""
import hashlib
import json
import os
import tempfile
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ..db import connect

KEY_FILE = "fleet_signing_key.pem"
KEY_BITS = 3072
PUBLIC_EXPONENT = 65537
JOB_FIELDS = ("action", "device", "id", "params", "seq")

_lock = threading.Lock()


def fingerprint(n, e):
    """What the organiser and the device compare: SHA-256 of "<e>:<n in hex>"."""
    return hashlib.sha256(f"{e}:{n:x}".encode()).hexdigest()


def canonical(job):
    """The bytes a job's signature covers. The client builds the same bytes."""
    return json.dumps({k: job[k] for k in JOB_FIELDS}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


class Signer:
    def __init__(self, private_key):
        self._key = private_key
        numbers = private_key.public_key().public_numbers()
        self.fingerprint = fingerprint(numbers.n, numbers.e)
        # What a device pins at enrolment.
        self.public = {"n": format(numbers.n, "x"), "e": numbers.e, "fingerprint": self.fingerprint}

    def sign(self, job):
        return self._key.sign(canonical(job), padding.PKCS1v15(), hashes.SHA256()).hex()


def _load(pem):
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < KEY_BITS:
        raise RuntimeError("The fleet signing key is not an RSA key of at least 3072 bits.")
    return key


class KeyUnavailable(RuntimeError):
    """The key cannot be read, or is missing while devices have pinned it."""


def load_or_create(data_dir, may_create=lambda: True):
    """
    The key from the data volume, created on first use if may_create() says
    so. Appears atomically with its full content (temporary file, fsync, hard
    link), so two processes starting together end up with the same key.
    """
    path = os.path.join(data_dir, KEY_FILE)
    while True:
        try:
            with open(path, "rb") as f:
                pem = f.read()
        except FileNotFoundError:
            pem = None
        if pem is not None:
            try:
                return _load(pem)
            except (ValueError, RuntimeError) as exc:
                raise KeyUnavailable(f"{path} cannot be read ({exc}). Restore it from a backup; replacing "
                                     "it means re-enrolling every device.") from None
        if not may_create():
            raise KeyUnavailable(f"{path} is missing, but devices have pinned the key it held. Restore it "
                                 "from a backup, or replace it with `flask --app cybics_mgmt new-signing-key` "
                                 "and enrol every device again.")
        key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_BITS)
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        fd, tmp = tempfile.mkstemp(dir=data_dir, prefix=".fleet_signing_key.")
        try:
            with os.fdopen(fd, "wb") as f:   # mkstemp creates the file 0600
                f.write(pem)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.link(tmp, path)
            except FileExistsError:
                continue   # another process won the race: use its key
            return key
        finally:
            os.unlink(tmp)


def _no_devices(app):
    """True while no device could have pinned a key (retired ones refuse jobs anyway)."""
    conn = connect(app.config["DATABASE"])
    try:
        return conn.execute("SELECT 1 FROM devices WHERE retired = 0 LIMIT 1").fetchone() is None
    finally:
        conn.close()


def get_signer(app):
    """
    The app's Signer, or KeyUnavailable. Tests pass a PEM in
    FLEET_SIGNING_KEY instead of generating one each.
    """
    with _lock:
        signer = app.extensions.get("fleet_signer")
        if signer is None:
            pem = app.config.get("FLEET_SIGNING_KEY")
            key = _load(pem) if pem else load_or_create(app.config["DATA_DIR"], lambda: _no_devices(app))
            signer = app.extensions["fleet_signer"] = Signer(key)
        return signer


def replace_key(app):
    """
    A new key in place of the old one, missing or not: every device pinned
    the old one and refuses jobs until it is enrolled again. Returns the new
    Signer.
    """
    path = os.path.join(app.config["DATA_DIR"], KEY_FILE)
    with _lock:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        signer = app.extensions["fleet_signer"] = Signer(load_or_create(app.config["DATA_DIR"]))
        return signer
