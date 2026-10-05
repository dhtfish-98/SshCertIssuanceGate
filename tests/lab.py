"""Self-owned weak-versus-fixed SSH user CA experiment."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
from pathlib import Path

from ssh_cert_issuance_gate import IssuanceGate, OpenSSHSigner
from independent_verify import verify_user_certificate
from weak_baseline import issue_without_principal_policy


def generate(root: Path, name: str) -> tuple[Path, str]:
    key = root / name
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                   capture_output=True, text=True, check=True, timeout=15)
    return key, Path(str(key) + ".pub").read_text()


def run(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    scratch = output / "tmp"
    scratch.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ssh-ca-lab-", dir=scratch) as temp:
        root = Path(temp)
        ca_key, ca_pub = generate(root, "ca")
        _, alice_pub = generate(root, "alice")
        _, swapped_pub = generate(root, "swapped")
        clock_time = int(time.time())
        clock = lambda: clock_time
        signer = OpenSSHSigner(ca_key, root)
        gate = IssuanceGate(root / "state.sqlite", signer, clock)
        alice_secret = gate.register_account("acct-alice", ("alice",), 120)
        bob_secret = gate.register_account("acct-bob", ("bob",), 60)

        unauthorized_request = gate.register_request("acct-alice", alice_secret,
                                                      alice_pub, clock_time + 300)
        weak_cert = issue_without_principal_policy(signer, alice_pub, "root", clock_time)
        weak_verified = verify_user_certificate(weak_cert, ca_pub, alice_pub,
                                                "root", clock_time)
        fixed_unauthorized = gate.issue("acct-alice", alice_secret, unauthorized_request,
                                        alice_pub, "root", 60)
        audit_unauthorized = gate.audit_for(unauthorized_request)

        authorized_request = gate.register_request("acct-alice", alice_secret,
                                                    alice_pub, clock_time + 300)
        cross_account = gate.issue("acct-bob", bob_secret, authorized_request,
                                   alice_pub, "alice", 60)
        bad_secret = gate.issue("acct-alice", "wrong", authorized_request,
                                alice_pub, "alice", 60)
        changed_key = gate.issue("acct-alice", alice_secret, authorized_request,
                                 swapped_pub, "alice", 60)
        excessive_ttl = gate.issue("acct-alice", alice_secret, authorized_request,
                                   alice_pub, "alice", 121)
        authorized = gate.issue("acct-alice", alice_secret, authorized_request,
                                alice_pub, "alice", 60)
        verified = verify_user_certificate(authorized.certificate, ca_pub,
                                           alice_pub, "alice", clock_time)
        open_ssh_view = root / "issued.pub"
        open_ssh_view.write_text(authorized.certificate)
        inspection = subprocess.run(["ssh-keygen", "-L", "-f", str(open_ssh_view)],
                                    capture_output=True, text=True, check=False, timeout=15)
        restarted = IssuanceGate(root / "state.sqlite", signer, clock)
        replay = restarted.issue("acct-alice", alice_secret, authorized_request,
                                 alice_pub, "alice", 60)

        expiry_request = restarted.register_request("acct-alice", alice_secret,
                                                     alice_pub, clock_time + 30)
        clock_time += 31
        expired = restarted.issue("acct-alice", alice_secret, expiry_request,
                                  alice_pub, "alice", 10)
        counts = restarted.certificate_count()
        audit_authorized = restarted.audit_for(authorized_request)
        audit_expired = restarted.audit_for(expiry_request)

        (output / "ca.pub").write_text(ca_pub)
        (output / "subject.pub").write_text(alice_pub)
        (output / "authorized-cert.pub").write_text(authorized.certificate)

    public_names = {"ca.pub", "subject.pub", "authorized-cert.pub", "lab.json"}
    private_marker = b"BEGIN OPENSSH " + b"PRIVATE KEY"
    private_absent = all(p.name in public_names and
                         private_marker not in p.read_bytes()
                         for p in output.rglob("*") if p.is_file())
    checks = {
        "weak_baseline_signed_unauthorized_root": weak_verified.principal == "root",
        "fixed_rejected_unauthorized_root": fixed_unauthorized.reason == "PRINCIPAL_DENIED",
        "fixed_audited_unauthorized_root": audit_unauthorized == ["PRINCIPAL_DENIED"],
        "cross_account_rejected": cross_account.reason == "REQUEST_ACCOUNT_MISMATCH",
        "bad_credential_rejected": bad_secret.reason == "ACCOUNT_DENIED",
        "swapped_public_key_rejected": changed_key.reason == "PUBLIC_KEY_MISMATCH",
        "excessive_ttl_rejected": excessive_ttl.reason == "TTL_DENIED",
        "authorized_signed": authorized.allowed and verified.serial == authorized.serial,
        "authorized_principal_only": verified.principal == "alice",
        "authorized_ttl_60": verified.valid_before - verified.valid_after == 60,
        "openssh_parsed_user_cert": inspection.returncode == 0 and "ssh-ed25519-cert-v01@openssh.com user certificate" in inspection.stdout,
        "replay_rejected_after_restart": replay.reason == "REQUEST_ALREADY_SIGNED",
        "expired_request_rejected": expired.reason == "REQUEST_EXPIRED",
        "only_one_fixed_certificate_record": counts == 1,
        "audit_persisted_after_restart": audit_authorized[-1] == "REQUEST_ALREADY_SIGNED" and audit_expired == ["REQUEST_EXPIRED"],
        "no_private_keys_in_public_evidence": private_absent,
    }
    result = {
        "status": "PASS_LOCAL_ONLY" if all(checks.values()) else "FAIL",
        "checks": checks,
        "decisions": {
            "weak_unauthorized": "SIGNED",
            "fixed_unauthorized": fixed_unauthorized.reason,
            "cross_account": cross_account.reason,
            "bad_credential": bad_secret.reason,
            "swapped_key": changed_key.reason,
            "ttl": excessive_ttl.reason,
            "authorized": authorized.reason,
            "replay": replay.reason,
            "expired": expired.reason,
        },
        "authorized_certificate": {
            "serial": verified.serial,
            "key_id": verified.key_id,
            "principal": verified.principal,
            "valid_after": verified.valid_after,
            "valid_before": verified.valid_before,
        },
        "audit_authorized": audit_authorized,
        "certificate_records": counts,
        "open_ssh_inspection": inspection.stdout,
    }
    (output / "lab.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    report = run(arguments.output)
    print(json.dumps({"status": report["status"], "checks": report["checks"]}, indent=2))
    raise SystemExit(0 if report["status"] == "PASS_LOCAL_ONLY" else 1)
