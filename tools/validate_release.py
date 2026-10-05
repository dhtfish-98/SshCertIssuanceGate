"""Build-only validation runner for the SshCertIssuanceGate local lab."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1]
BUILD = SOURCE / "Build"
DOCS = SOURCE / "项目文档"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_manifest() -> dict[str, str]:
    result = {}
    for path in sorted(SOURCE.rglob("*")):
        relative = path.relative_to(SOURCE)
        if path.is_file() and relative.parts[0] != ".git" and (
            relative.parts[0] != "Build" or relative == Path("Build/.gitignore")
        ):
            result[str(relative)] = sha(path)
    return result


def invoke(label: str, command: list[str], cwd: Path, env: dict[str, str]) -> str:
    outcome = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                             text=True, check=False, timeout=300)
    log = outcome.stdout + outcome.stderr
    (BUILD / f"{label}.log").write_text(log)
    if outcome.returncode:
        raise RuntimeError(f"{label} failed with exit {outcome.returncode}; see Build log")
    return log


def run_mode(mode: str, project: Path, python: Path, env: dict[str, str]) -> dict:
    run_env = dict(env)
    if mode in ("source", "sdist"):
        run_env["PYTHONPATH"] = str(project / "src")
    else:
        run_env.pop("PYTHONPATH", None)
    tests = project / "tests"
    log = invoke(f"{mode}-tests", [str(python), "-W", "error::ResourceWarning",
                                   "-m", "unittest", "discover", "-s", str(tests), "-v"],
                 project, run_env)
    output = BUILD / mode
    lab_log = invoke(f"{mode}-lab", [str(python), str(tests / "lab.py"), str(output)],
                     project, run_env)
    report = json.loads((output / "lab.json").read_text())
    if report["status"] != "PASS_LOCAL_ONLY" or not all(report["checks"].values()):
        raise RuntimeError(f"{mode} lab did not pass")
    return {
        "unit_tests": int(log.rsplit("Ran ", 1)[1].split(" tests", 1)[0]),
        "unit_log_sha256": sha(BUILD / f"{mode}-tests.log"),
        "lab_log_sha256": sha(BUILD / f"{mode}-lab.log"),
        "lab_sha256": sha(output / "lab.json"),
        "lab_status": report["status"],
        "checks": report["checks"],
        "public_evidence_sha256": {
            filename: sha(output / filename)
            for filename in ("ca.pub", "subject.pub", "authorized-cert.pub")
        },
    }


def main() -> None:
    BUILD.mkdir(exist_ok=True)
    for name in ("dist", "stage", "venv", "consumer", "source", "sdist", "installed", "tmp"):
        path = BUILD / name
        if path.exists():
            shutil.rmtree(path)
        path.mkdir()
    env = dict(os.environ)
    env["TMPDIR"] = str(BUILD / "tmp")
    env["SSH_CERT_TEST_TMPDIR"] = str(BUILD / "tmp")
    env["PIP_CACHE_DIR"] = str(BUILD / "pip-cache")
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    system_python = Path(sys.executable).absolute()
    invoke("build", [str(system_python), "-m", "build", "--no-isolation", "--outdir", str(BUILD / "dist"),
                     str(SOURCE)], SOURCE, env)
    sdist = next((BUILD / "dist").glob("*.tar.gz"))
    wheel = next((BUILD / "dist").glob("*.whl"))
    with tarfile.open(sdist, "r:gz") as archive:
        members = archive.getnames()
        if not all(name.startswith("ssh_cert_issuance_gate-0.1.0/") and
                   ".." not in Path(name).parts and not Path(name).is_absolute()
                   for name in members):
            raise RuntimeError("unexpected sdist root")
        if any(not (member.isfile() or member.isdir()) for member in archive.getmembers()):
            raise RuntimeError("unsupported sdist member type")
        archive.extractall(BUILD / "stage")
    stage = BUILD / "stage/ssh_cert_issuance_gate-0.1.0"
    if not (stage / "项目文档/项目说明.md").is_file():
        raise RuntimeError("project document absent from sdist")
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
    expected_package = {
        "ssh_cert_issuance_gate/__init__.py",
        "ssh_cert_issuance_gate/gate.py",
        "ssh_cert_issuance_gate/signer.py",
    }
    if set(name for name in wheel_names if name.startswith("ssh_cert_issuance_gate/")) != expected_package:
        raise RuntimeError("unexpected wheel package files")
    if any("weak" in name.lower() or "tests/" in name for name in wheel_names):
        raise RuntimeError("weak baseline leaked into wheel")

    invoke("create-venv", [str(system_python), "-m", "venv", str(BUILD / "venv")], BUILD, env)
    installed_python = BUILD / "venv/bin/python"
    invoke("install-wheel", [str(installed_python), "-m", "pip", "install",
                              "--no-deps", "--no-index", str(wheel)], BUILD, env)
    shutil.copytree(SOURCE / "tests", BUILD / "consumer/tests")
    import_path = invoke("installed-import", [str(installed_python), "-c",
                                               "import ssh_cert_issuance_gate as m; print(m.__file__)"],
                         BUILD / "consumer", {k: v for k, v in env.items() if k != "PYTHONPATH"}).strip()
    if not import_path.startswith(str(BUILD / "venv")):
        raise RuntimeError("installed tests imported source tree")

    results = {
        "source": run_mode("source", SOURCE, system_python, env),
        "sdist": run_mode("sdist", stage, system_python, env),
        "installed": run_mode("installed", BUILD / "consumer", installed_python, env),
    }
    private_marker = (b"BEGIN OPENSSH " + b"PRIVATE KEY", b"BEGIN " + b"PRIVATE KEY")
    delivery_files = [p for p in SOURCE.rglob("*") if p.is_file() and (
        p.relative_to(SOURCE).parts[0] not in {"Build", ".git"} or
        p.relative_to(SOURCE) == Path("Build/.gitignore")
    )]
    delivery_files += [p for folder in (BUILD / "source", BUILD / "sdist", BUILD / "installed")
                       for p in folder.rglob("*") if p.is_file()]
    private_absent = all(not any(marker in path.read_bytes() for marker in private_marker)
                         for path in delivery_files)
    temp_empty = not any((BUILD / "tmp").iterdir()) and all(
        not any((BUILD / mode / "tmp").iterdir()) for mode in results)
    checks = {
        "three_modes_pass": all(value["lab_status"] == "PASS_LOCAL_ONLY" and
                                value["unit_tests"] == 16 for value in results.values()),
        "wheel_package_allowlist": True,
        "weak_baseline_not_in_wheel": True,
        "installed_import_from_isolated_venv": True,
        "private_key_marker_absent_in_delivery": private_absent,
        "temporary_key_directories_empty": temp_empty,
        "docs_in_project_docs_dir": DOCS.is_dir(),
    }
    manifest = source_manifest()
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    receipt = {
        "project": "SshCertIssuanceGate",
        "status": "PASS_LOCAL_ONLY" if all(checks.values()) else "FAIL",
        "author": "dhtfish98",
        "upstream_reference": {
            "repo": "smallstep/certificates",
            "commit": "fdeb6fdf53f9ad430c283940eb4c5f1203406fa7",
            "license": "Apache-2.0",
            "relationship": "reference only, no source copied",
        },
        "source": str(SOURCE),
        "docs": str(DOCS),
        "build": str(BUILD),
        "source_manifest_sha256": digest,
        "source_files_sha256": manifest,
        "sdist": {"name": sdist.name, "sha256": sha(sdist), "members": members},
        "wheel": {"name": wheel.name, "sha256": sha(wheel), "members": wheel_names},
        "installed_import_path": import_path,
        "tools": {
            "ssh": invoke("ssh-version", ["ssh", "-V"], BUILD, env).strip(),
            "openssl": invoke("openssl-version", ["openssl", "version"], BUILD, env).strip(),
            "python": invoke("python-version", [str(system_python), "--version"], BUILD, env).strip(),
            "build": invoke("build-version", [str(system_python), "-m", "build", "--version"], BUILD, env).strip(),
        },
        "modes": results,
        "checks": checks,
        "limits": [
            "self-owned synthetic SSH user CA only",
            "no requester private-key possession proof or external identity attestation",
            "no online SSH server authentication test",
            "no inference of CVP acceptance",
        ],
    }
    (BUILD / "validation.json").write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n")
    if receipt["status"] != "PASS_LOCAL_ONLY":
        raise RuntimeError("local validation checks did not all pass")
    print(json.dumps({"status": receipt["status"], "checks": checks,
                      "receipt_sha256": sha(BUILD / "validation.json")}, indent=2))


if __name__ == "__main__":
    main()
