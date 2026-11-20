"""SQLite persistence layer for the federated login simulator.

Design notes
------------
* One database file holds *all* durable state.  Every mutating operation runs
  inside a single ``BEGIN IMMEDIATE`` transaction so that the phase's writes
  (e.g. claim consumption + credential issuance + request receipt) commit or
  roll back together.
* ``claims.claim_id`` is the primary key  -> a claim can be consumed at most
  once, even under concurrent processes.
* ``credentials.state`` transitions ``issued -> consumed`` happen with a
  guarded ``UPDATE ... WHERE state='issued'`` -> a credential can be consumed
  at most once.
* ``receipts.request_id`` is the primary key -> every accepted request leaves
  exactly one durable receipt, written in the same transaction as the effect
  of the request.  Re-issued requests are answered from the receipt without
  re-executing.
* WAL journal + busy timeout so several OS processes can contend on the same
  database file.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS providers (
    provider_id TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    issuer      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'active'   -- active | revoked
);

CREATE TABLE IF NOT EXISTS clients (
    client_id   TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    status      TEXT NOT NULL DEFAULT 'active'   -- active | revoked
);

CREATE TABLE IF NOT EXISTS client_callbacks (
    client_id   TEXT NOT NULL REFERENCES clients(client_id),
    callback    TEXT NOT NULL,
    PRIMARY KEY (client_id, callback)
);

CREATE TABLE IF NOT EXISTS client_scopes (
    client_id   TEXT NOT NULL REFERENCES clients(client_id),
    scope       TEXT NOT NULL,
    PRIMARY KEY (client_id, scope)
);

CREATE TABLE IF NOT EXISTS devices (
    device_id   TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(tenant_id),
    generation  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_subjects (
    tenant_id   TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    sub         TEXT NOT NULL,
    PRIMARY KEY (tenant_id, provider_id, sub)
);

CREATE TABLE IF NOT EXISTS challenges (
    challenge_id      TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    provider_id       TEXT NOT NULL,
    client_id         TEXT NOT NULL,
    device_id         TEXT NOT NULL,
    device_generation INTEGER NOT NULL,
    callback          TEXT NOT NULL,
    scopes_json       TEXT NOT NULL,             -- canonical sorted JSON array
    verifier_sha256   TEXT NOT NULL,
    nonce             TEXT NOT NULL,
    expires_at        INTEGER NOT NULL,
    state             TEXT NOT NULL DEFAULT 'pending',  -- pending | callback_done | redeemed
    created_at        INTEGER NOT NULL
);
-- The same nonce may be reused across clients, but never twice for one client.
CREATE UNIQUE INDEX IF NOT EXISTS ux_challenge_nonce
    ON challenges (tenant_id, client_id, nonce);

CREATE TABLE IF NOT EXISTS claims (
    claim_id     TEXT PRIMARY KEY,               -- consume-once token
    challenge_id TEXT NOT NULL,
    sub          TEXT NOT NULL,
    consumed_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    credential_id      TEXT PRIMARY KEY,
    challenge_id       TEXT NOT NULL REFERENCES challenges(challenge_id),
    claim_id           TEXT NOT NULL UNIQUE,
    tenant_id          TEXT NOT NULL,
    provider_id        TEXT NOT NULL,
    client_id          TEXT NOT NULL,
    device_id          TEXT NOT NULL,
    device_generation  INTEGER NOT NULL,
    sub                TEXT NOT NULL,
    scopes_json        TEXT NOT NULL,
    state              TEXT NOT NULL DEFAULT 'issued',  -- issued | consumed | invalidated
    invalidated_reason TEXT,
    created_at         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL UNIQUE,
    tenant_id     TEXT NOT NULL,
    client_id     TEXT NOT NULL,
    sub           TEXT NOT NULL,
    scopes_json   TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS receipts (
    request_id  TEXT PRIMARY KEY,
    op          TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);
"""


class Store:
    """Thin wrapper around a sqlite3 connection with explicit transactions."""

    def __init__(self, path: str):
        # isolation_level=None -> autocommit; transactions are opened
        # explicitly via tx() so we control exactly where BEGIN/COMMIT happen.
        self.con = sqlite3.connect(path, timeout=30, isolation_level=None)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA busy_timeout=30000")
        self.con.execute("PRAGMA foreign_keys=ON")
        self.con.executescript(SCHEMA)

    @classmethod
    def memory(cls) -> "Store":
        return cls(":memory:")

    def close(self) -> None:
        self.con.close()

    @contextmanager
    def tx(self):
        """One atomic unit of work.  Rolls back on any exception."""
        self.con.execute("BEGIN IMMEDIATE")
        try:
            yield self.con
        except BaseException:
            self.con.rollback()
            raise
        else:
            self.con.commit()

    # -- receipt helpers -------------------------------------------------
    def get_receipt(self, request_id: str):
        row = self.con.execute(
            "SELECT result_json FROM receipts WHERE request_id = ?", (request_id,)
        ).fetchone()
        return json.loads(row["result_json"]) if row else None

    def is_initialized(self) -> bool:
        row = self.con.execute("SELECT COUNT(*) AS n FROM tenants").fetchone()
        return row["n"] > 0
