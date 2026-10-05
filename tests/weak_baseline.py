"""Intentionally unsafe self-owned baseline, excluded from the wheel."""

import base64


def issue_without_principal_policy(signer, subject_pub_line: str,
                                   principal: str, now: int) -> str:
    blob = base64.b64decode(subject_pub_line.split()[1], validate=True)
    return signer.sign(blob, "weak-lab", principal, 9001, now, now + 60)
