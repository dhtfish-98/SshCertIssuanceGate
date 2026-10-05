"""SQLite-backed authorization checks for a local SSH user CA."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import struct
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .signer import OpenSSHSigner

_PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}\Z")


def _principal(value: str) -> bool:
    return isinstance(value, str) and bool(_PRINCIPAL.fullmatch(value))


def _key_blob(value: str) -> bytes:
    parts = value.strip().split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("only Ed25519 public keys are accepted")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("malformed public key") from exc
    if len(blob) != 51 or blob[:15] != struct.pack(">I", 11) + b"ssh-ed25519":
        raise ValueError("malformed Ed25519 public key")
    if struct.unpack(">I", blob[15:19])[0] != 32:
        raise ValueError("malformed Ed25519 public key")
    return blob


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    request_id: str
    certificate: str | None = None
    serial: int | None = None


class IssuanceGate:
    def __init__(self, database: str | Path, signer: OpenSSHSigner,
                 clock: Callable[[], int] | None = None):
        self.database = str(Path(database).resolve())
        self.signer = signer
        self.clock = clock or (lambda: int(time.time()))
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.database, timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout = 15000")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    @contextmanager
    def _session(self):
        conn = self._connect()
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._session() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS accounts (
                    account_id TEXT PRIMARY KEY,
                    secret_hash TEXT NOT NULL,
                    principals TEXT NOT NULL,
                    max_ttl INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS requests (
                    request_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    expires_at INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('OPEN','SIGNED')),
                    FOREIGN KEY(account_id) REFERENCES accounts(account_id)
                );
                CREATE TABLE IF NOT EXISTS certificates (
                    serial INTEGER PRIMARY KEY,
                    request_id TEXT NOT NULL UNIQUE,
                    principal TEXT NOT NULL,
                    valid_after INTEGER NOT NULL,
                    valid_before INTEGER NOT NULL,
                    certificate TEXT NOT NULL,
                    FOREIGN KEY(request_id) REFERENCES requests(request_id)
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    account_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    at_time INTEGER NOT NULL
                );
            """)

    def register_account(self, account_id: str, principals: tuple[str, ...], max_ttl: int) -> str:
        if not account_id or len(account_id) > 100 or not principals or any(not _principal(p) for p in principals):
            raise ValueError("invalid account or principal allowlist")
        if len(set(principals)) != len(principals) or not isinstance(max_ttl, int) or not 1 <= max_ttl <= 86400:
            raise ValueError("invalid TTL or duplicate principal")
        secret = secrets.token_urlsafe(32)
        secret_hash = hashlib.sha256(secret.encode()).hexdigest()
        with self._session() as conn:
            conn.execute("INSERT INTO accounts VALUES (?, ?, ?, ?)",
                         (account_id, secret_hash, json.dumps(principals), max_ttl))
        return secret

    def _authenticated(self, conn: sqlite3.Connection, account_id: str, secret: str) -> sqlite3.Row | None:
        account = conn.execute("SELECT * FROM accounts WHERE account_id = ?", (account_id,)).fetchone()
        if account is None or not isinstance(secret, str):
            return None
        digest = hashlib.sha256(secret.encode()).hexdigest()
        if not hmac.compare_digest(account["secret_hash"], digest):
            return None
        return account

    def register_request(self, account_id: str, secret: str, public_key: str,
                         expires_at: int) -> str:
        key_blob = _key_blob(public_key)
        now = int(self.clock())
        if not isinstance(expires_at, int) or not now < expires_at <= now + 86400:
            raise ValueError("invalid request expiry")
        with self._session() as conn:
            if self._authenticated(conn, account_id, secret) is None:
                raise ValueError("invalid account credential")
            request_id = uuid.uuid4().hex
            conn.execute("INSERT INTO requests VALUES (?, ?, ?, ?, 'OPEN')",
                         (request_id, account_id, key_blob, expires_at))
        return request_id

    def issue(self, account_id: str, secret: str, request_id: str,
              public_key: str, principal: str, ttl: int) -> Decision:
        now = int(self.clock())
        with self._session() as conn:
            conn.execute("BEGIN IMMEDIATE")

            def denied(reason: str) -> Decision:
                conn.execute("INSERT INTO audit(request_id, account_id, decision, at_time) VALUES (?, ?, ?, ?)",
                             (request_id, account_id, reason, now))
                conn.commit()
                return Decision(False, reason, request_id)

            account = self._authenticated(conn, account_id, secret)
            if account is None:
                return denied("ACCOUNT_DENIED")
            request = conn.execute("SELECT * FROM requests WHERE request_id = ?", (request_id,)).fetchone()
            if request is None or request["account_id"] != account_id:
                return denied("REQUEST_ACCOUNT_MISMATCH")
            if request["status"] != "OPEN":
                return denied("REQUEST_ALREADY_SIGNED")
            if now >= request["expires_at"]:
                return denied("REQUEST_EXPIRED")
            try:
                actual_key = _key_blob(public_key)
            except ValueError:
                return denied("PUBLIC_KEY_INVALID")
            if not hmac.compare_digest(request["public_key"], actual_key):
                return denied("PUBLIC_KEY_MISMATCH")
            if not _principal(principal) or principal not in json.loads(account["principals"]):
                return denied("PRINCIPAL_DENIED")
            if not isinstance(ttl, int) or ttl <= 0 or ttl > account["max_ttl"]:
                return denied("TTL_DENIED")
            valid_before = now + ttl
            if valid_before > request["expires_at"]:
                return denied("REQUEST_WINDOW_EXCEEDED")
            serial = conn.execute("SELECT COALESCE(MAX(serial), 0) + 1 FROM certificates").fetchone()[0]
            try:
                cert = self.signer.sign(actual_key, "req-" + request_id, principal,
                                        serial, now, valid_before)
            except (OSError, RuntimeError, ValueError, TimeoutError):
                return denied("SIGNER_ERROR")
            post_sign = int(self.clock())
            if post_sign >= request["expires_at"] or post_sign >= valid_before:
                return denied("REQUEST_EXPIRED_DURING_SIGNING")
            conn.execute("INSERT INTO certificates VALUES (?, ?, ?, ?, ?, ?)",
                         (serial, request_id, principal, now, valid_before, cert))
            conn.execute("UPDATE requests SET status = 'SIGNED' WHERE request_id = ? AND status = 'OPEN'",
                         (request_id,))
            conn.execute("INSERT INTO audit(request_id, account_id, decision, at_time) VALUES (?, ?, 'SIGNED', ?)",
                         (request_id, account_id, post_sign))
            conn.commit()
            return Decision(True, "SIGNED", request_id, cert, serial)

    def request_status(self, request_id: str) -> str | None:
        with self._session() as conn:
            row = conn.execute("SELECT status FROM requests WHERE request_id = ?", (request_id,)).fetchone()
        return None if row is None else row["status"]

    def audit_for(self, request_id: str) -> list[str]:
        with self._session() as conn:
            rows = conn.execute("SELECT decision FROM audit WHERE request_id = ? ORDER BY id",
                                (request_id,)).fetchall()
        return [row["decision"] for row in rows]

    def certificate_count(self) -> int:
        with self._session() as conn:
            return int(conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0])
