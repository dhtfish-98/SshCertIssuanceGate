from __future__ import annotations

import base64
import os
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from ssh_cert_issuance_gate import IssuanceGate, OpenSSHSigner
from independent_verify import verify_user_certificate


def make_key(root: Path, name: str) -> tuple[Path, str]:
    path = root / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)],
                   capture_output=True, text=True, check=True, timeout=15)
    return path, Path(str(path) + ".pub").read_text()


class GateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ssh-gate-",
                                                dir=os.environ.get("SSH_CERT_TEST_TMPDIR"))
        self.root = Path(self.temp.name)
        self.ca, self.ca_pub = make_key(self.root, "ca")
        _, self.subject_pub = make_key(self.root, "subject")
        _, self.other_pub = make_key(self.root, "other")
        self.now = int(time.time())
        self.clock = lambda: self.now
        self.signer = OpenSSHSigner(self.ca, self.root)
        self.db = self.root / "gate.sqlite"
        self.gate = IssuanceGate(self.db, self.signer, self.clock)
        self.secret = self.gate.register_account("acct-a", ("alice",), 120)
        self.other_secret = self.gate.register_account("acct-b", ("bob",), 90)
        self.request = self.gate.register_request("acct-a", self.secret,
                                                   self.subject_pub, self.now + 300)

    def tearDown(self):
        self.temp.cleanup()

    def issue(self, request=None, key=None, principal="alice", ttl=60,
              account="acct-a", secret=None):
        return self.gate.issue(account, self.secret if secret is None else secret,
                               self.request if request is None else request,
                               self.subject_pub if key is None else key, principal, ttl)

    def test_valid_certificate_is_cryptographically_verified(self):
        result = self.issue()
        self.assertTrue(result.allowed)
        verified = verify_user_certificate(result.certificate, self.ca_pub,
                                           self.subject_pub, "alice", self.now)
        self.assertEqual(verified.serial, result.serial)
        self.assertEqual(verified.key_id, "req-" + self.request)
        self.assertEqual(verified.valid_before - verified.valid_after, 60)
        self.assertEqual(self.gate.audit_for(self.request), ["SIGNED"])

    def test_other_account_and_wrong_secret_denied(self):
        self.assertEqual(self.issue(account="acct-b", secret=self.other_secret).reason,
                         "REQUEST_ACCOUNT_MISMATCH")
        self.assertEqual(self.issue(secret="wrong").reason, "ACCOUNT_DENIED")
        self.assertEqual(self.gate.certificate_count(), 0)

    def test_swapped_public_key_denied(self):
        self.assertEqual(self.issue(key=self.other_pub).reason, "PUBLIC_KEY_MISMATCH")
        self.assertEqual(self.gate.request_status(self.request), "OPEN")

    def test_malformed_public_key_denied(self):
        self.assertEqual(self.issue(key="ssh-rsa invalid").reason, "PUBLIC_KEY_INVALID")
        self.assertEqual(self.gate.certificate_count(), 0)

    def test_unauthorized_principal_denied_and_audited(self):
        self.assertEqual(self.issue(principal="root").reason, "PRINCIPAL_DENIED")
        self.assertEqual(self.gate.audit_for(self.request), ["PRINCIPAL_DENIED"])
        self.assertEqual(self.gate.certificate_count(), 0)

    def test_principal_injection_denied(self):
        self.assertEqual(self.issue(principal="alice,root").reason, "PRINCIPAL_DENIED")

    def test_ttl_ceiling_and_request_window_denied(self):
        self.assertEqual(self.issue(ttl=121).reason, "TTL_DENIED")
        close_request = self.gate.register_request("acct-a", self.secret,
                                                    self.subject_pub, self.now + 20)
        self.assertEqual(self.issue(request=close_request).reason, "REQUEST_WINDOW_EXCEEDED")
        self.assertEqual(self.gate.certificate_count(), 0)

    def test_expired_request_denied(self):
        self.now += 301
        self.assertEqual(self.issue().reason, "REQUEST_EXPIRED")
        self.assertEqual(self.gate.request_status(self.request), "OPEN")

    def test_replay_denied_after_restart(self):
        self.assertTrue(self.issue().allowed)
        restarted = IssuanceGate(self.db, self.signer, self.clock)
        second = restarted.issue("acct-a", self.secret, self.request,
                                 self.subject_pub, "alice", 60)
        self.assertEqual(second.reason, "REQUEST_ALREADY_SIGNED")
        self.assertEqual(restarted.certificate_count(), 1)
        self.assertEqual(restarted.audit_for(self.request),
                         ["SIGNED", "REQUEST_ALREADY_SIGNED"])

    def test_same_request_concurrency_exactly_one_signed(self):
        barrier = threading.Barrier(2)
        output = []

        def attempt():
            barrier.wait()
            output.append(self.issue())

        threads = [threading.Thread(target=attempt), threading.Thread(target=attempt)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=20)
            self.assertFalse(thread.is_alive())
        self.assertEqual(sorted(item.reason for item in output),
                         ["REQUEST_ALREADY_SIGNED", "SIGNED"])
        self.assertEqual(self.gate.certificate_count(), 1)

    def test_expiry_during_signing_denied_without_record(self):
        self.now = int(time.time())
        request = self.gate.register_request("acct-a", self.secret,
                                             self.subject_pub, self.now + 20)

        class SlowSigner:
            def sign(inner, *args):
                certificate = self.signer.sign(*args)
                self.now += 21
                return certificate

        slow_gate = IssuanceGate(self.db, SlowSigner(), self.clock)
        result = slow_gate.issue("acct-a", self.secret, request,
                                 self.subject_pub, "alice", 20)
        self.assertEqual(result.reason, "REQUEST_EXPIRED_DURING_SIGNING")
        self.assertEqual(self.gate.certificate_count(), 0)
        self.assertEqual(self.gate.request_status(request), "OPEN")

    def test_untrusted_ca_or_subject_fails_verification(self):
        result = self.issue()
        _, wrong_ca_pub = make_key(self.root, "wrong-ca")
        with self.assertRaises(ValueError):
            verify_user_certificate(result.certificate, wrong_ca_pub,
                                    self.subject_pub, "alice", self.now)
        with self.assertRaises(ValueError):
            verify_user_certificate(result.certificate, self.ca_pub,
                                    self.other_pub, "alice", self.now)

    def test_wrong_principal_and_expired_certificate_fail_verification(self):
        result = self.issue()
        with self.assertRaises(ValueError):
            verify_user_certificate(result.certificate, self.ca_pub,
                                    self.subject_pub, "root", self.now)
        with self.assertRaises(ValueError):
            verify_user_certificate(result.certificate, self.ca_pub,
                                    self.subject_pub, "alice", self.now + 60)

    def test_modified_certificate_signature_fails(self):
        result = self.issue()
        parts = result.certificate.split()
        blob = bytearray(base64.b64decode(parts[1]))
        blob[-1] ^= 1
        modified = parts[0] + " " + base64.b64encode(blob).decode("ascii")
        with self.assertRaises(ValueError):
            verify_user_certificate(modified, self.ca_pub,
                                    self.subject_pub, "alice", self.now)

    def test_real_host_certificate_is_out_of_scope(self):
        subject = self.root / "host.pub"
        subject.write_text(self.subject_pub)
        subprocess.run(["ssh-keygen", "-q", "-s", str(self.ca), "-h",
                        "-I", "host-test", "-n", "example.test",
                        "-V", f"0x{self.now:x}:0x{self.now + 60:x}",
                        "-O", "clear", str(subject)],
                       capture_output=True, text=True, check=True, timeout=15)
        host_cert = (self.root / "host-cert.pub").read_text()
        with self.assertRaises(ValueError):
            verify_user_certificate(host_cert, self.ca_pub,
                                    self.subject_pub, "example.test", self.now)

    def test_signer_failure_keeps_request_open_and_audited(self):
        class FailedSigner:
            def sign(inner, *args):
                raise RuntimeError("test signer failure")

        broken = IssuanceGate(self.db, FailedSigner(), self.clock)
        result = broken.issue("acct-a", self.secret, self.request,
                              self.subject_pub, "alice", 60)
        self.assertEqual(result.reason, "SIGNER_ERROR")
        self.assertEqual(self.gate.request_status(self.request), "OPEN")
        self.assertEqual(self.gate.certificate_count(), 0)
        self.assertTrue(self.issue().allowed)
        self.assertEqual(self.gate.audit_for(self.request), ["SIGNER_ERROR", "SIGNED"])


if __name__ == "__main__":
    unittest.main()
