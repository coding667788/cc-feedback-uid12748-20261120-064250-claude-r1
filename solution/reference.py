"""Independent in-memory reference implementation of the simulator rules.

This module deliberately shares *no code* with solution.service / solution
.store: it keeps plain Python dicts and lists and re-states every rule in its
own terms.  The test-suite runs the same synthetic cases through both
implementations and requires byte-identical results, which guards the SQLite
implementation against rule drift.

Rules restated
--------------
* challenge freezes (tenant, provider, client, device generation, callback,
  scope set, sha256(verifier), expiry).  Nonces are unique per (tenant,
  client) but may repeat across clients.
* callback consumes a claim id at most once (globally), requires the claim to
  be bound to the named challenge, the challenge pending and unexpired
  (now < expires_at), claim times straddling now (iat <= now < exp), the
  device still on the frozen generation, issuer == provider issuer, provider
  active, audience == challenge client, client active, challenge scopes still
  granted, subject non-empty and not revoked; then issues one credential.
* redeem requires the credential issued (not consumed, not invalidated), the
  challenge unexpired, same device generation, same callback, same client,
  same verifier digest, exactly equal scope set, and provider/client/subject
  still valid in their *current* state; then consumes the credential and
  opens a session.  Failure consumes nothing.
* revocation / scope shrink / device reset / subject revocation invalidate
  matching unredeemed credentials permanently.
* successful requests leave a receipt; a repeated request_id is answered from
  the receipt.  Failed requests leave no trace.
"""

from __future__ import annotations

import hashlib

from . import errors as E


class RefViolation(Exception):
    def __init__(self, code):
        self.code = code


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _ok(rid, op, **extra):
    r = {"request_id": rid, "op": op, "status": "ok", "error": None}
    r.update(extra)
    return r


def _err(rid, op, code):
    return {"request_id": rid, "op": op, "status": "error", "error": code}


class ReferenceSim:
    def __init__(self):
        self.tenants = set()
        self.providers = {}          # id -> {tenant_id, issuer, status}
        self.clients = {}            # id -> {tenant_id, status, callbacks:set, scopes:set}
        self.devices = {}            # id -> {tenant_id, generation}
        self.revoked_subjects = set()  # (tenant, provider, sub)
        self.challenges = {}         # id -> dict
        self.used_nonces = set()     # (tenant, client, nonce)
        self.claims = {}             # claim_id -> {challenge_id, sub}
        self.credentials = {}        # id -> dict(state in issued/consumed/invalidated)
        self.sessions = {}           # id -> dict
        self.receipts = {}           # request_id -> result dict

    # ------------------------------------------------------------------
    def is_initialized(self):
        return bool(self.tenants)

    def setup(self, setup):
        for t in setup.get("tenants", []):
            self.tenants.add(t["tenant_id"])
        for p in setup.get("providers", []):
            self.providers[p["provider_id"]] = {
                "tenant_id": p["tenant_id"],
                "issuer": p["issuer"],
                "status": "active",
            }
        for c in setup.get("clients", []):
            self.clients[c["client_id"]] = {
                "tenant_id": c["tenant_id"],
                "status": "active",
                "callbacks": set(c.get("callbacks", [])),
                "scopes": set(c.get("scopes", [])),
            }
        for d in setup.get("devices", []):
            self.devices[d["device_id"]] = {
                "tenant_id": d["tenant_id"],
                "generation": d["generation"],
            }

    # ------------------------------------------------------------------
    def execute(self, op):
        name = op.get("op", "")
        rid = op.get("request_id", "")
        handler = getattr(self, "op_" + name, None)
        if handler is None:
            return _err(rid, name, E.E_UNKNOWN_OP)
        if rid in self.receipts:
            out = dict(self.receipts[rid])
            out["replayed"] = True
            return out
        try:
            result = handler(op)
        except RefViolation as v:
            return _err(rid, name, v.code)
        self.receipts[rid] = result
        return result

    # ------------------------------------------------------------------
    def op_challenge(self, op):
        rid, now = op["request_id"], op["now"]
        if op["tenant_id"] not in self.tenants:
            raise RefViolation(E.E_TENANT_UNKNOWN)
        prov = self.providers.get(op["provider_id"])
        if prov is None or prov["tenant_id"] != op["tenant_id"]:
            raise RefViolation(E.E_PROVIDER_UNKNOWN)
        if prov["status"] != "active":
            raise RefViolation(E.E_PROVIDER_REVOKED)
        client = self.clients.get(op["client_id"])
        if client is None or client["tenant_id"] != op["tenant_id"]:
            raise RefViolation(E.E_CLIENT_UNKNOWN)
        if client["status"] != "active":
            raise RefViolation(E.E_CLIENT_REVOKED)
        dev = self.devices.get(op["device_id"])
        if dev is None or dev["tenant_id"] != op["tenant_id"]:
            raise RefViolation(E.E_DEVICE_UNKNOWN)
        if op["callback"] not in client["callbacks"]:
            raise RefViolation(E.E_CALLBACK_NOT_REGISTERED)
        scopes = set(op["scopes"])
        if not scopes or not scopes <= client["scopes"]:
            raise RefViolation(E.E_SCOPE_NOT_GRANTED)
        if not op["expires_at"] > now:
            raise RefViolation(E.E_EXPIRY_PAST)
        nonce_key = (op["tenant_id"], op["client_id"], op["nonce"])
        if nonce_key in self.used_nonces:
            raise RefViolation(E.E_NONCE_REUSED)
        self.used_nonces.add(nonce_key)
        cid = "CH-" + rid
        self.challenges[cid] = {
            "tenant_id": op["tenant_id"],
            "provider_id": op["provider_id"],
            "client_id": op["client_id"],
            "device_id": op["device_id"],
            "device_generation": dev["generation"],
            "callback": op["callback"],
            "scopes": sorted(scopes),
            "verifier_sha256": _sha256(op["verifier"]),
            "expires_at": op["expires_at"],
            "state": "pending",
        }
        return _ok(rid, "challenge", challenge_id=cid)

    # ------------------------------------------------------------------
    def op_callback(self, op):
        rid, now, claim = op["request_id"], op["now"], op["claim"]
        ch = self.challenges.get(op["challenge_id"])
        if ch is None:
            raise RefViolation(E.E_CHALLENGE_UNKNOWN)
        if claim["challenge_id"] != op["challenge_id"]:
            raise RefViolation(E.E_CHALLENGE_MISMATCH)
        if claim["claim_id"] in self.claims:
            raise RefViolation(E.E_CLAIM_REPLAYED)
        if ch["state"] != "pending":
            raise RefViolation(E.E_CHALLENGE_STATE)
        if now >= ch["expires_at"]:
            raise RefViolation(E.E_CHALLENGE_EXPIRED)
        if claim["iat"] > now or now >= claim["exp"]:
            raise RefViolation(E.E_CLAIM_TIME)
        if self.devices[ch["device_id"]]["generation"] != ch["device_generation"]:
            raise RefViolation(E.E_DEVICE_GENERATION)
        prov = self.providers[ch["provider_id"]]
        if claim["iss"] != prov["issuer"]:
            raise RefViolation(E.E_ISSUER_MISMATCH)
        if prov["status"] != "active":
            raise RefViolation(E.E_PROVIDER_REVOKED)
        if claim["aud"] != ch["client_id"]:
            raise RefViolation(E.E_AUDIENCE_MISMATCH)
        client = self.clients[ch["client_id"]]
        if client["status"] != "active":
            raise RefViolation(E.E_CLIENT_REVOKED)
        if not set(ch["scopes"]) <= client["scopes"]:
            raise RefViolation(E.E_SCOPE_NOT_GRANTED)
        sub = claim["sub"]
        if not sub:
            raise RefViolation(E.E_SUBJECT_INVALID)
        if (ch["tenant_id"], ch["provider_id"], sub) in self.revoked_subjects:
            raise RefViolation(E.E_SUBJECT_REVOKED)

        self.claims[claim["claim_id"]] = {"challenge_id": op["challenge_id"], "sub": sub}
        cred_id = "CR-" + rid
        self.credentials[cred_id] = {
            "challenge_id": op["challenge_id"],
            "claim_id": claim["claim_id"],
            "tenant_id": ch["tenant_id"],
            "provider_id": ch["provider_id"],
            "client_id": ch["client_id"],
            "device_id": ch["device_id"],
            "device_generation": ch["device_generation"],
            "sub": sub,
            "scopes": list(ch["scopes"]),
            "state": "issued",
        }
        ch["state"] = "callback_done"
        return _ok(rid, "callback", credential_id=cred_id)

    # ------------------------------------------------------------------
    def op_redeem(self, op):
        rid, now = op["request_id"], op["now"]
        cred = self.credentials.get(op["credential_id"])
        if cred is None:
            raise RefViolation(E.E_CREDENTIAL_UNKNOWN)
        if cred["state"] == "consumed":
            raise RefViolation(E.E_CREDENTIAL_CONSUMED)
        if cred["state"] == "invalidated":
            raise RefViolation(E.E_CREDENTIAL_INVALID)
        ch = self.challenges[cred["challenge_id"]]
        if now >= ch["expires_at"]:
            raise RefViolation(E.E_CHALLENGE_EXPIRED)
        if self.devices[cred["device_id"]]["generation"] != cred["device_generation"]:
            raise RefViolation(E.E_DEVICE_GENERATION)
        if op["callback"] != ch["callback"]:
            raise RefViolation(E.E_CALLBACK_MISMATCH)
        if op["client_id"] != ch["client_id"]:
            raise RefViolation(E.E_CLIENT_MISMATCH)
        if _sha256(op["verifier"]) != ch["verifier_sha256"]:
            raise RefViolation(E.E_VERIFIER_MISMATCH)
        if set(op["scopes"]) != set(ch["scopes"]):
            raise RefViolation(E.E_SCOPE_MISMATCH)
        if self.providers[cred["provider_id"]]["status"] != "active":
            raise RefViolation(E.E_PROVIDER_REVOKED)
        client = self.clients[cred["client_id"]]
        if client["status"] != "active":
            raise RefViolation(E.E_CLIENT_REVOKED)
        if not set(op["scopes"]) <= client["scopes"]:
            raise RefViolation(E.E_SCOPE_SHRUNK)
        if (cred["tenant_id"], cred["provider_id"], cred["sub"]) in self.revoked_subjects:
            raise RefViolation(E.E_SUBJECT_REVOKED)

        cred["state"] = "consumed"
        sid = "SE-" + rid
        self.sessions[sid] = {"credential_id": op["credential_id"], "sub": cred["sub"]}
        ch["state"] = "redeemed"
        return _ok(rid, "redeem", session_id=sid)

    # ------------------------------------------------------------------
    def _invalidate(self, pred):
        n = 0
        for cred in self.credentials.values():
            if cred["state"] == "issued" and pred(cred):
                cred["state"] = "invalidated"
                n += 1
        return n

    def op_revoke_provider(self, op):
        self.providers[op["provider_id"]]["status"] = "revoked"
        n = self._invalidate(lambda c: c["provider_id"] == op["provider_id"])
        return _ok(op["request_id"], "revoke_provider", invalidated=n)

    def op_revoke_client(self, op):
        self.clients[op["client_id"]]["status"] = "revoked"
        n = self._invalidate(lambda c: c["client_id"] == op["client_id"])
        return _ok(op["request_id"], "revoke_client", invalidated=n)

    def op_revoke_subject(self, op):
        key = (op["tenant_id"], op["provider_id"], op["sub"])
        self.revoked_subjects.add(key)
        n = self._invalidate(
            lambda c: (c["tenant_id"], c["provider_id"], c["sub"]) == key
        )
        return _ok(op["request_id"], "revoke_subject", invalidated=n)

    def op_shrink_client_scopes(self, op):
        new = set(op["scopes"])
        self.clients[op["client_id"]]["scopes"] = set(new)
        n = self._invalidate(
            lambda c: c["client_id"] == op["client_id"]
            and not set(c["scopes"]) <= new
        )
        return _ok(op["request_id"], "shrink_client_scopes", invalidated=n)

    def op_reset_device(self, op):
        dev = self.devices.get(op["device_id"])
        if dev is None:
            raise RefViolation(E.E_DEVICE_UNKNOWN)
        dev["generation"] += 1
        gen = dev["generation"]
        n = self._invalidate(
            lambda c: c["device_id"] == op["device_id"]
            and c["device_generation"] != gen
        )
        return _ok(op["request_id"], "reset_device", invalidated=n, generation=gen)

    # ------------------------------------------------------------------
    def summary(self):
        creds = {"issued": 0, "consumed": 0, "invalidated": 0}
        for c in self.credentials.values():
            creds[c["state"]] += 1
        challenges = {"pending": 0, "callback_done": 0, "redeemed": 0}
        for ch in self.challenges.values():
            challenges[ch["state"]] += 1
        return {
            "sessions_total": len(self.sessions),
            "sessions": sorted(self.sessions),
            "credentials": creds,
            "claims_consumed": len(self.claims),
            "challenges": challenges,
            "devices": {k: self.devices[k]["generation"] for k in sorted(self.devices)},
        }


def run_cases(cases: dict) -> dict:
    """Run a cases.json document through the reference implementation."""
    sim = ReferenceSim()
    if cases.get("setup"):
        sim.setup(cases["setup"])
    results = [sim.execute(op) for op in cases.get("operations", [])]
    return {"results": results, "summary": sim.summary()}
