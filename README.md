# SSH Certificate Issuance Gate

An independently written, local SSH **user** certificate CA lab. The account
credential, saved request key, principal allowlist, TTL ceiling, and request
deadline are checked before OpenSSH `ssh-keygen` signs a certificate. Decisions
are recorded in SQLite. This is not an SSH host certificate verifier, an ACME
service, or an X.509 CA.

The package requires a trusted local caller to supply an account credential and
a path to a separately controlled Ed25519 CA private key. It does not establish
a real-world identity, prove possession of the requested SSH private key, expose
a network service, or manage CA key custody. Test keys are generated only in
temporary validation directories under `Build` and are deleted after each run.

`tests/weak_baseline.py` intentionally signs a requested principal without
checking the account allowlist. It is a self-owned comparison fixture and is
excluded from the installed wheel.

The study used a fixed, public snapshot of smallstep/certificates at commit
`fdeb6fdf53f9ad430c283940eb4c5f1203406fa7` as a scope reference. That
commit changes a dependency; this lab does not claim an upstream vulnerability,
copy upstream code, or redistribute the upstream package. Its Apache-2.0 rights
remain with their owners; see the project documentation. OpenSSH and OpenSSL
are invoked as separately installed system tools and are not bundled.

Run `python tools/validate_release.py` from this repository root after
installing the `build` package. It puts every build and test output under
`Build/`. Details and boundaries are in [项目文档/项目说明.md](项目文档/项目说明.md).
Passing this synthetic lab is not a CVP eligibility or approval determination.
