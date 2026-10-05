"""Isolated OpenSSH user-certificate signing adapter."""

from __future__ import annotations

import base64
import subprocess
import tempfile
from pathlib import Path


class OpenSSHSigner:
    def __init__(self, ca_key: str | Path, work_dir: str | Path, ssh_keygen: str = "ssh-keygen"):
        self.ca_key = Path(ca_key).resolve()
        self.work_dir = Path(work_dir).resolve()
        self.ssh_keygen = ssh_keygen
        if not self.ca_key.is_file() or not self.work_dir.is_dir():
            raise ValueError("CA key and existing temporary work directory required")

    def sign(self, public_key_blob: bytes, key_id: str, principal: str,
             serial: int, valid_after: int, valid_before: int) -> str:
        if not (0 < valid_after < valid_before < 2**64):
            raise ValueError("invalid certificate validity")
        with tempfile.TemporaryDirectory(prefix="ssh-issue-", dir=self.work_dir) as tmp:
            pub = Path(tmp) / "subject.pub"
            pub.write_text("ssh-ed25519 " + base64.b64encode(public_key_blob).decode("ascii") + "\n")
            command = [
                self.ssh_keygen, "-q", "-s", str(self.ca_key),
                "-I", key_id, "-n", principal,
                "-V", f"0x{valid_after:x}:0x{valid_before:x}",
                "-z", str(serial), "-O", "clear", str(pub),
            ]
            result = subprocess.run(command, capture_output=True, text=True,
                                    timeout=15, check=False)
            if result.returncode:
                raise RuntimeError("ssh-keygen signing failed: " + result.stderr.strip()[:200])
            certificate = Path(tmp) / "subject-cert.pub"
            line = certificate.read_text().strip()
            if not line.startswith("ssh-ed25519-cert-v01@openssh.com "):
                raise RuntimeError("unexpected certificate type")
            return line + "\n"
