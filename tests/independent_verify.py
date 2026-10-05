"""Test-only SSH certificate parser with OpenSSL Ed25519 verification.

This verifier does not call the issuing ssh-keygen command. It deliberately
supports only the narrow Ed25519 user-certificate format used in this lab.
"""

from __future__ import annotations

import base64
import os
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise ValueError("truncated SSH field")
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def string(self) -> bytes:
        size = self.u32()
        return self.take(size)

    def done(self) -> None:
        if self.offset != len(self.data):
            raise ValueError("trailing SSH data")


def _pub_blob(line: str, expected: str) -> bytes:
    fields = line.strip().split()
    if len(fields) < 2 or fields[0] != expected:
        raise ValueError("unexpected SSH key type")
    return base64.b64decode(fields[1], validate=True)


@dataclass(frozen=True)
class VerifiedCert:
    serial: int
    principal: str
    key_id: str
    valid_after: int
    valid_before: int


def verify_user_certificate(cert_line: str, ca_pub_line: str,
                            subject_pub_line: str, expected_principal: str,
                            at_time: int, openssl: str = "openssl") -> VerifiedCert:
    cert = _pub_blob(cert_line, "ssh-ed25519-cert-v01@openssh.com")
    r = _Reader(cert)
    if r.string() != b"ssh-ed25519-cert-v01@openssh.com":
        raise ValueError("bad certificate type")
    r.string()  # nonce
    subject_raw = r.string()
    if len(subject_raw) != 32:
        raise ValueError("bad Ed25519 subject key")
    serial = r.u64()
    if r.u32() != 1:  # SSH_CERT_TYPE_USER
        raise ValueError("host certificate rejected")
    key_id = r.string().decode("utf-8")
    principals_reader = _Reader(r.string())
    principals: list[str] = []
    while principals_reader.offset < len(principals_reader.data):
        principals.append(principals_reader.string().decode("utf-8"))
    principals_reader.done()
    valid_after = r.u64()
    valid_before = r.u64()
    critical = r.string()
    extensions = r.string()
    reserved = r.string()
    signing_ca = r.string()
    signed_data = cert[:r.offset]
    signature_reader = _Reader(r.string())
    if signature_reader.string() != b"ssh-ed25519":
        raise ValueError("unsupported CA signature")
    signature = signature_reader.string()
    signature_reader.done()
    r.done()

    ca_pub = _pub_blob(ca_pub_line, "ssh-ed25519")
    subject_pub = _pub_blob(subject_pub_line, "ssh-ed25519")
    ca = _Reader(ca_pub)
    if ca.string() != b"ssh-ed25519":
        raise ValueError("wrong CA type")
    ca_raw = ca.string()
    ca.done()
    subject = _Reader(subject_pub)
    if subject.string() != b"ssh-ed25519" or subject.string() != subject_raw:
        raise ValueError("subject key mismatch")
    subject.done()
    if signing_ca != ca_pub or len(ca_raw) != 32 or len(signature) != 64:
        raise ValueError("CA mismatch or bad signature")
    if principals != [expected_principal] or not valid_after <= at_time < valid_before:
        raise ValueError("principal or validity mismatch")
    if critical or extensions or reserved:
        raise ValueError("unexpected certificate options")

    spki = bytes.fromhex("302a300506032b6570032100") + ca_raw
    with tempfile.TemporaryDirectory(prefix="ssh-verify-",
                                     dir=os.environ.get("SSH_CERT_TEST_TMPDIR")) as temp:
        root = Path(temp)
        (root / "ca.der").write_bytes(spki)
        (root / "signed.bin").write_bytes(signed_data)
        (root / "sig.bin").write_bytes(signature)
        result = subprocess.run([
            openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(root / "ca.der"),
            "-keyform", "DER", "-sigfile", str(root / "sig.bin"),
            "-in", str(root / "signed.bin"), "-rawin",
        ], capture_output=True, text=True, timeout=15, check=False)
        if result.returncode:
            raise ValueError("Ed25519 signature verification failed")
    return VerifiedCert(serial, expected_principal, key_id, valid_after, valid_before)
