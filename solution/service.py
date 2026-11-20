"""Business rules of the local federated-login simulator.

Phases
------
challenge : tenant/provider/client/device-generation/callback/scopes/
            sha256(verifier)/expiry are frozen into a challenge row.
callback  : a mock pre-verified claim (bound to the challenge, unique claim
            id) is checked for provider, audience, subject and time; the
            claim is consumed exactly once and a unique redeem credential is
            issued -- claim consumption, credential issuance and the request
            receipt commit in ONE transaction.
redeem    : device generation, callback, client, verifier digest and the
            exact scope set are re-checked against the challenge, and the
            current provider/subject/client state is re-read; the credential
            is consumed exactly once and the session + receipt commit in ONE
            transaction.  A failed redeem consumes nothing.

Invalidation events (provider/client revocation, client scope shrink, device
reset, subject revocation) mark matching *unredeemed* credentials
``invalidated``.  Invalidation is sticky: an invalidated credential can never
be revived, no matter how often confirmation is retried.

Time rule: a challenge or claim is valid while ``now < expires_at``; at the
exact expiry instant it is already expired.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3

from . import errors as E


class RuleViolation(Exception):
    """A business-rule rejection; carries a stable error code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _canon_scopes(scopes) -> str:
    return json.dumps(sorted(set(scopes)))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ok(request_id: str, op: str, **extra):
    result = {"request_id": request_id, "op": op, "status": "ok", "error": None}
    result.update(extra)
    return result


def _err(request_id: str, op: str, code: str):
    return {"request_id": request_id, "op": op, "status": "error", "error": code}


class Service:
    """Executes operations against a Store.  All ids are deterministic:

    challenge_id  = "CH-" + challenge request_id
    credential_id = "CR-" + callback  request_id
    session_id    = "SE-" + redeem    request_id
    """

    def __init__(self, store, crash_hook=None):
        self.store = store
        # Test/crash-injection hook, called at named points inside redeem.
        self.crash_hook = crash_hook or (lambda point: None)

    # ------------------------------------------------------------------
    # setup
    # ------------------------------------------------------------------
    def is_initialized(self) -> bool:
        return self.store.is_initialized()

    def setup(self, setup: dict) -> None:
        with self.store.tx() as con:
            for t in setup.get("tenants", []):
                con.execute("INSERT INTO tenants (tenant_id) VALUES (?)", (t["tenant_id"],))
            for p in setup.get("providers", []):
                con.execute(
                    "INSERT INTO providers (provider_id, tenant_id, issuer, status)"
                    " VALUES (?, ?, ?, 'active')",
                    (p["provider_id"], p["tenant_id"], p["issuer"]),
                )
            for c in setup.get("clients", []):
                con.execute(
                    "INSERT INTO clients (client_id, tenant_id, status) VALUES (?, ?, 'active')",
                    (c["client_id"], c["tenant_id"]),
                )
                for cb in c.get("callbacks", []):
                    con.execute(
                        "INSERT INTO client_callbacks (client_id, callback) VALUES (?, ?)",
                        (c["client_id"], cb),
                    )
                for s in c.get("scopes", []):
                    con.execute(
                        "INSERT INTO client_scopes (client_id, scope) VALUES (?, ?)",
                        (c["client_id"], s),
                    )
            for d in setup.get("devices", []):
                con.execute(
                    "INSERT INTO devices (device_id, tenant_id, generation) VALUES (?, ?, ?)",
                    (d["device_id"], d["tenant_id"], d["generation"]),
                )

    # ------------------------------------------------------------------
    # dispatch + idempotent receipts
    # ------------------------------------------------------------------
    def execute(self, op: dict) -> dict:
        name = op.get("op", "")
        handler = getattr(self, "op_" + name, None)
        rid = op.get("request_id", "")
        if handler is None:
            return _err(rid, name, E.E_UNKNOWN_OP)

        stored = self.store.get_receipt(rid)
        if stored is not None:
            # Same request re-issued: answer from the durable receipt, do not
            # re-execute.  (Only successful operations leave receipts; failed
            # operations are fully rolled back and may be retried.)
            replayed = dict(stored)
            replayed["replayed"] = True
            return replayed

        try:
            return handler(op)
        except RuleViolation as v:
            return _err(rid, name, v.code)
        except sqlite3.IntegrityError:
            # Lost a race against a concurrent writer of the same request.
            stored = self.store.get_receipt(rid)
            if stored is not None:
                replayed = dict(stored)
                replayed["replayed"] = True
                return replayed
            return _err(rid, name, E.E_CONFLICT)

    def _write_receipt(self, con, request_id: str, op: str, result: dict, now: int) -> None:
        con.execute(
            "INSERT INTO receipts (request_id, op, result_json, created_at) VALUES (?, ?, ?, ?)",
            (request_id, op, json.dumps(result, sort_keys=True), now),
        )

    # ------------------------------------------------------------------
    # row helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _one(con, sql, args):
        return con.execute(sql, args).fetchone()

    def _tenant(self, con, tenant_id):
        return self._one(con, "SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,))

    def _provider(self, con, provider_id, tenant_id=None):
        row = self._one(con, "SELECT * FROM providers WHERE provider_id = ?", (provider_id,))
        if row and tenant_id is not None and row["tenant_id"] != tenant_id:
            return None
        return row

    def _client(self, con, client_id, tenant_id=None):
        row = self._one(con, "SELECT * FROM clients WHERE client_id = ?", (client_id,))
        if row and tenant_id is not None and row["tenant_id"] != tenant_id:
            return None
        return row

    def _device(self, con, device_id, tenant_id=None):
        row = self._one(con, "SELECT * FROM devices WHERE device_id = ?", (device_id,))
        if row and tenant_id is not None and row["tenant_id"] != tenant_id:
            return None
        return row

    def _client_scopes(self, con, client_id) -> set:
        rows = con.execute(
            "SELECT scope FROM client_scopes WHERE client_id = ?", (client_id,)
        ).fetchall()
        return {r["scope"] for r in rows}

    def _subject_revoked(self, con, tenant_id, provider_id, sub) -> bool:
        return (
            self._one(
                con,
                "SELECT 1 AS x FROM revoked_subjects WHERE tenant_id=? AND provider_id=? AND sub=?",
                (tenant_id, provider_id, sub),
            )
            is not None
        )

    # ------------------------------------------------------------------
    # phase 1: challenge
    # ------------------------------------------------------------------
    def op_challenge(self, op: dict) -> dict:
        rid, now = op["request_id"], op["now"]
        with self.store.tx() as con:
            if self._tenant(con, op["tenant_id"]) is None:
                raise RuleViolation(E.E_TENANT_UNKNOWN)
            provider = self._provider(con, op["provider_id"], op["tenant_id"])
            if provider is None:
                raise RuleViolation(E.E_PROVIDER_UNKNOWN)
            if provider["status"] != "active":
                raise RuleViolation(E.E_PROVIDER_REVOKED)
            client = self._client(con, op["client_id"], op["tenant_id"])
            if client is None:
                raise RuleViolation(E.E_CLIENT_UNKNOWN)
            if client["status"] != "active":
                raise RuleViolation(E.E_CLIENT_REVOKED)
            if self._device(con, op["device_id"], op["tenant_id"]) is None:
                raise RuleViolation(E.E_DEVICE_UNKNOWN)
            # exact string match against the registered callbacks
            if self._one(
                con,
                "SELECT 1 AS x FROM client_callbacks WHERE client_id = ? AND callback = ?",
                (op["client_id"], op["callback"]),
            ) is None:
                raise RuleViolation(E.E_CALLBACK_NOT_REGISTERED)
            scopes = set(op["scopes"])
            if not scopes or not scopes <= self._client_scopes(con, op["client_id"]):
                raise RuleViolation(E.E_SCOPE_NOT_GRANTED)
            if not op["expires_at"] > now:
                raise RuleViolation(E.E_EXPIRY_PAST)
            if self._one(
                con,
                "SELECT 1 AS x FROM challenges WHERE tenant_id=? AND client_id=? AND nonce=?",
                (op["tenant_id"], op["client_id"], op["nonce"]),
            ) is not None:
                raise RuleViolation(E.E_NONCE_REUSED)

            device = self._device(con, op["device_id"], op["tenant_id"])
            challenge_id = "CH-" + rid
            con.execute(
                "INSERT INTO challenges (challenge_id, tenant_id, provider_id, client_id,"
                " device_id, device_generation, callback, scopes_json, verifier_sha256,"
                " nonce, expires_at, state, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?, 'pending', ?)",
                (
                    challenge_id,
                    op["tenant_id"],
                    op["provider_id"],
                    op["client_id"],
                    op["device_id"],
                    device["generation"],
                    op["callback"],
                    _canon_scopes(op["scopes"]),
                    _sha256(op["verifier"]),
                    op["nonce"],
                    op["expires_at"],
                    now,
                ),
            )
            result = _ok(rid, "challenge", challenge_id=challenge_id)
            self._write_receipt(con, rid, "challenge", result, now)
        return result

    # ------------------------------------------------------------------
    # phase 2: callback (consume claim, issue credential)
    # ------------------------------------------------------------------
    def op_callback(self, op: dict) -> dict:
        rid, now, claim = op["request_id"], op["now"], op["claim"]
        with self.store.tx() as con:
            ch = self._one(
                con, "SELECT * FROM challenges WHERE challenge_id = ?", (op["challenge_id"],)
            )
            if ch is None:
                raise RuleViolation(E.E_CHALLENGE_UNKNOWN)
            if claim["challenge_id"] != ch["challenge_id"]:
                raise RuleViolation(E.E_CHALLENGE_MISMATCH)
            # consume-once: a claim id may never be used twice, whatever the
            # state of the challenge it was originally bound to.
            if self._one(con, "SELECT 1 AS x FROM claims WHERE claim_id = ?", (claim["claim_id"],)) is not None:
                raise RuleViolation(E.E_CLAIM_REPLAYED)
            if ch["state"] != "pending":
                raise RuleViolation(E.E_CHALLENGE_STATE)
            if now >= ch["expires_at"]:
                raise RuleViolation(E.E_CHALLENGE_EXPIRED)
            if claim["iat"] > now or now >= claim["exp"]:
                raise RuleViolation(E.E_CLAIM_TIME)
            device = self._device(con, ch["device_id"], ch["tenant_id"])
            if device["generation"] != ch["device_generation"]:
                raise RuleViolation(E.E_DEVICE_GENERATION)
            provider = self._provider(con, ch["provider_id"], ch["tenant_id"])
            if claim["iss"] != provider["issuer"]:
                raise RuleViolation(E.E_ISSUER_MISMATCH)
            if provider["status"] != "active":
                raise RuleViolation(E.E_PROVIDER_REVOKED)
            if claim["aud"] != ch["client_id"]:
                raise RuleViolation(E.E_AUDIENCE_MISMATCH)
            client = self._client(con, ch["client_id"], ch["tenant_id"])
            if client["status"] != "active":
                raise RuleViolation(E.E_CLIENT_REVOKED)
            if not set(json.loads(ch["scopes_json"])) <= self._client_scopes(con, ch["client_id"]):
                raise RuleViolation(E.E_SCOPE_NOT_GRANTED)
            sub = claim["sub"]
            if not sub:
                raise RuleViolation(E.E_SUBJECT_INVALID)
            if self._subject_revoked(con, ch["tenant_id"], ch["provider_id"], sub):
                raise RuleViolation(E.E_SUBJECT_REVOKED)

            try:
                con.execute(
                    "INSERT INTO claims (claim_id, challenge_id, sub, consumed_at) VALUES (?,?,?,?)",
                    (claim["claim_id"], ch["challenge_id"], sub, now),
                )
            except sqlite3.IntegrityError:
                raise RuleViolation(E.E_CLAIM_REPLAYED) from None

            credential_id = "CR-" + rid
            con.execute(
                "INSERT INTO credentials (credential_id, challenge_id, claim_id, tenant_id,"
                " provider_id, client_id, device_id, device_generation, sub, scopes_json,"
                " state, created_at) VALUES (?,?,?,?,?,?,?,?,?,?, 'issued', ?)",
                (
                    credential_id,
                    ch["challenge_id"],
                    claim["claim_id"],
                    ch["tenant_id"],
                    ch["provider_id"],
                    ch["client_id"],
                    ch["device_id"],
                    ch["device_generation"],
                    sub,
                    ch["scopes_json"],
                    now,
                ),
            )
            con.execute(
                "UPDATE challenges SET state = 'callback_done' WHERE challenge_id = ?",
                (ch["challenge_id"],),
            )
            result = _ok(rid, "callback", credential_id=credential_id)
            self._write_receipt(con, rid, "callback", result, now)
        return result

    # ------------------------------------------------------------------
    # phase 3: redeem (consume credential, create session)
    # ------------------------------------------------------------------
    def op_redeem(self, op: dict) -> dict:
        rid, now = op["request_id"], op["now"]
        with self.store.tx() as con:
            cred = self._one(
                con, "SELECT * FROM credentials WHERE credential_id = ?", (op["credential_id"],)
            )
            if cred is None:
                raise RuleViolation(E.E_CREDENTIAL_UNKNOWN)
            if cred["state"] == "consumed":
                raise RuleViolation(E.E_CREDENTIAL_CONSUMED)
            if cred["state"] == "invalidated":
                # sticky: repeated confirmation can never revive it
                raise RuleViolation(E.E_CREDENTIAL_INVALID)
            ch = self._one(
                con, "SELECT * FROM challenges WHERE challenge_id = ?", (cred["challenge_id"],)
            )
            if now >= ch["expires_at"]:
                raise RuleViolation(E.E_CHALLENGE_EXPIRED)
            device = self._device(con, cred["device_id"], cred["tenant_id"])
            if device["generation"] != cred["device_generation"]:
                raise RuleViolation(E.E_DEVICE_GENERATION)
            if op["callback"] != ch["callback"]:
                raise RuleViolation(E.E_CALLBACK_MISMATCH)
            if op["client_id"] != ch["client_id"]:
                raise RuleViolation(E.E_CLIENT_MISMATCH)
            if _sha256(op["verifier"]) != ch["verifier_sha256"]:
                raise RuleViolation(E.E_VERIFIER_MISMATCH)
            if set(op["scopes"]) != set(json.loads(ch["scopes_json"])):
                raise RuleViolation(E.E_SCOPE_MISMATCH)
            # re-read the *current* state of provider, client and subject
            provider = self._provider(con, cred["provider_id"], cred["tenant_id"])
            if provider["status"] != "active":
                raise RuleViolation(E.E_PROVIDER_REVOKED)
            client = self._client(con, cred["client_id"], cred["tenant_id"])
            if client["status"] != "active":
                raise RuleViolation(E.E_CLIENT_REVOKED)
            if not set(op["scopes"]) <= self._client_scopes(con, cred["client_id"]):
                raise RuleViolation(E.E_SCOPE_SHRUNK)
            if self._subject_revoked(con, cred["tenant_id"], cred["provider_id"], cred["sub"]):
                raise RuleViolation(E.E_SUBJECT_REVOKED)

            cur = con.execute(
                "UPDATE credentials SET state = 'consumed'"
                " WHERE credential_id = ? AND state = 'issued'",
                (cred["credential_id"],),
            )
            if cur.rowcount != 1:
                raise RuleViolation(E.E_CREDENTIAL_CONSUMED)
            session_id = "SE-" + rid
            con.execute(
                "INSERT INTO sessions (session_id, credential_id, tenant_id, client_id,"
                " sub, scopes_json, created_at) VALUES (?,?,?,?,?,?,?)",
                (
                    session_id,
                    cred["credential_id"],
                    cred["tenant_id"],
                    cred["client_id"],
                    cred["sub"],
                    cred["scopes_json"],
                    now,
                ),
            )
            # crash-injection point: session row written but not committed
            self.crash_hook("session_insert")
            con.execute(
                "UPDATE challenges SET state = 'redeemed' WHERE challenge_id = ?",
                (ch["challenge_id"],),
            )
            result = _ok(rid, "redeem", session_id=session_id)
            self._write_receipt(con, rid, "redeem", result, now)
        # crash-injection point: committed but result not returned
        self.crash_hook("commit")
        return result

    # ------------------------------------------------------------------
    # invalidation events
    # ------------------------------------------------------------------
    def _invalidate(self, con, where: str, args: tuple, reason: str) -> int:
        cur = con.execute(
            f"UPDATE credentials SET state = 'invalidated', invalidated_reason = ?"
            f" WHERE state = 'issued' AND {where}",
            (reason, *args),
        )
        return cur.rowcount

    def op_revoke_provider(self, op: dict) -> dict:
        rid, now = op["request_id"], op["now"]
        with self.store.tx() as con:
            con.execute(
                "UPDATE providers SET status = 'revoked' WHERE provider_id = ?",
                (op["provider_id"],),
            )
            n = self._invalidate(con, "provider_id = ?", (op["provider_id"],), "provider_revoked")
            result = _ok(rid, "revoke_provider", invalidated=n)
            self._write_receipt(con, rid, "revoke_provider", result, now)
        return result

    def op_revoke_client(self, op: dict) -> dict:
        rid, now = op["request_id"], op["now"]
        with self.store.tx() as con:
            con.execute(
                "UPDATE clients SET status = 'revoked' WHERE client_id = ?", (op["client_id"],)
            )
            n = self._invalidate(con, "client_id = ?", (op["client_id"],), "client_revoked")
            result = _ok(rid, "revoke_client", invalidated=n)
            self._write_receipt(con, rid, "revoke_client", result, now)
        return result

    def op_revoke_subject(self, op: dict) -> dict:
        rid, now = op["request_id"], op["now"]
        with self.store.tx() as con:
            con.execute(
                "INSERT OR IGNORE INTO revoked_subjects (tenant_id, provider_id, sub)"
                " VALUES (?,?,?)",
                (op["tenant_id"], op["provider_id"], op["sub"]),
            )
            n = self._invalidate(
                con,
                "tenant_id = ? AND provider_id = ? AND sub = ?",
                (op["tenant_id"], op["provider_id"], op["sub"]),
                "subject_revoked",
            )
            result = _ok(rid, "revoke_subject", invalidated=n)
            self._write_receipt(con, rid, "revoke_subject", result, now)
        return result

    def op_shrink_client_scopes(self, op: dict) -> dict:
        rid, now = op["request_id"], op["now"]
        new_scopes = set(op["scopes"])
        with self.store.tx() as con:
            con.execute("DELETE FROM client_scopes WHERE client_id = ?", (op["client_id"],))
            for s in sorted(new_scopes):
                con.execute(
                    "INSERT INTO client_scopes (client_id, scope) VALUES (?, ?)",
                    (op["client_id"], s),
                )
            # invalidate exactly those unredeemed credentials whose scope set
            # no longer fits inside the shrunken grant
            n = 0
            rows = con.execute(
                "SELECT credential_id, scopes_json FROM credentials"
                " WHERE client_id = ? AND state = 'issued'",
                (op["client_id"],),
            ).fetchall()
            for row in rows:
                if not set(json.loads(row["scopes_json"])) <= new_scopes:
                    con.execute(
                        "UPDATE credentials SET state = 'invalidated',"
                        " invalidated_reason = 'scopes_shrunk' WHERE credential_id = ?",
                        (row["credential_id"],),
                    )
                    n += 1
            result = _ok(rid, "shrink_client_scopes", invalidated=n)
            self._write_receipt(con, rid, "shrink_client_scopes", result, now)
        return result

    def op_reset_device(self, op: dict) -> dict:
        rid, now = op["request_id"], op["now"]
        with self.store.tx() as con:
            device = self._device(con, op["device_id"])
            if device is None:
                raise RuleViolation(E.E_DEVICE_UNKNOWN)
            new_gen = device["generation"] + 1
            con.execute(
                "UPDATE devices SET generation = ? WHERE device_id = ?",
                (new_gen, op["device_id"]),
            )
            n = self._invalidate(
                con,
                "device_id = ? AND device_generation != ?",
                (op["device_id"], new_gen),
                "device_reset",
            )
            result = _ok(rid, "reset_device", invalidated=n, generation=new_gen)
            self._write_receipt(con, rid, "reset_device", result, now)
        return result

    # ------------------------------------------------------------------
    # summary
    # ------------------------------------------------------------------
    def summary(self) -> dict:
        con = self.store.con
        sessions = [
            r["session_id"]
            for r in con.execute("SELECT session_id FROM sessions ORDER BY session_id")
        ]
        creds = {"issued": 0, "consumed": 0, "invalidated": 0}
        for r in con.execute("SELECT state, COUNT(*) AS n FROM credentials GROUP BY state"):
            creds[r["state"]] = r["n"]
        claims = con.execute("SELECT COUNT(*) AS n FROM claims").fetchone()["n"]
        challenges = {"pending": 0, "callback_done": 0, "redeemed": 0}
        for r in con.execute("SELECT state, COUNT(*) AS n FROM challenges GROUP BY state"):
            challenges[r["state"]] = r["n"]
        devices = {
            r["device_id"]: r["generation"]
            for r in con.execute("SELECT device_id, generation FROM devices ORDER BY device_id")
        }
        return {
            "sessions_total": len(sessions),
            "sessions": sessions,
            "credentials": creds,
            "claims_consumed": claims,
            "challenges": challenges,
            "devices": devices,
        }
