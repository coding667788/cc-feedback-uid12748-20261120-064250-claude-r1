"""Error codes for the federated login simulator.

Every rule violation surfaces as one of these stable string codes.  They are
part of the public contract of the simulator (documented in README.md) and are
asserted verbatim by the test-suite.
"""

# ---- generic ----
E_UNKNOWN_OP = "E_UNKNOWN_OP"                # unknown operation name
E_CONFLICT = "E_CONFLICT"                    # unexpected storage conflict

# ---- challenge phase ----
E_TENANT_UNKNOWN = "E_TENANT_UNKNOWN"        # tenant does not exist
E_PROVIDER_UNKNOWN = "E_PROVIDER_UNKNOWN"    # provider does not exist (in tenant)
E_PROVIDER_REVOKED = "E_PROVIDER_REVOKED"    # provider exists but is revoked
E_CLIENT_UNKNOWN = "E_CLIENT_UNKNOWN"        # client does not exist (in tenant)
E_CLIENT_REVOKED = "E_CLIENT_REVOKED"        # client exists but is revoked
E_DEVICE_UNKNOWN = "E_DEVICE_UNKNOWN"        # device does not exist (in tenant)
E_CALLBACK_NOT_REGISTERED = "E_CALLBACK_NOT_REGISTERED"  # callback string not registered for client
E_SCOPE_NOT_GRANTED = "E_SCOPE_NOT_GRANTED"  # scopes empty or outside the client's current grant
E_EXPIRY_PAST = "E_EXPIRY_PAST"              # expires_at is not in the future
E_NONCE_REUSED = "E_NONCE_REUSED"            # nonce already used by this (tenant, client)

# ---- callback phase ----
E_CHALLENGE_UNKNOWN = "E_CHALLENGE_UNKNOWN"      # challenge id does not exist
E_CHALLENGE_MISMATCH = "E_CHALLENGE_MISMATCH"    # claim is bound to a different challenge
E_CLAIM_REPLAYED = "E_CLAIM_REPLAYED"            # claim id was already consumed
E_CHALLENGE_STATE = "E_CHALLENGE_STATE"          # challenge no longer pending
E_CHALLENGE_EXPIRED = "E_CHALLENGE_EXPIRED"      # now >= expires_at (exact expiry counts as expired)
E_CLAIM_TIME = "E_CLAIM_TIME"                    # claim iat in the future or claim expired
E_DEVICE_GENERATION = "E_DEVICE_GENERATION"      # device generation moved on (reset)
E_ISSUER_MISMATCH = "E_ISSUER_MISMATCH"          # claim issuer != registered provider issuer
E_AUDIENCE_MISMATCH = "E_AUDIENCE_MISMATCH"      # claim audience != challenge client
E_SUBJECT_INVALID = "E_SUBJECT_INVALID"          # empty / missing subject
E_SUBJECT_REVOKED = "E_SUBJECT_REVOKED"          # subject revoked for (tenant, provider)

# ---- redeem phase ----
E_CREDENTIAL_UNKNOWN = "E_CREDENTIAL_UNKNOWN"    # credential id does not exist
E_CREDENTIAL_CONSUMED = "E_CREDENTIAL_CONSUMED"  # credential already redeemed
E_CREDENTIAL_INVALID = "E_CREDENTIAL_INVALID"    # invalidated by revocation / shrink / reset (sticky)
E_CALLBACK_MISMATCH = "E_CALLBACK_MISMATCH"      # callback differs from the challenge
E_CLIENT_MISMATCH = "E_CLIENT_MISMATCH"          # client differs from the challenge
E_VERIFIER_MISMATCH = "E_VERIFIER_MISMATCH"      # sha256(verifier) differs from the challenge
E_SCOPE_MISMATCH = "E_SCOPE_MISMATCH"            # scopes not exactly equal to the challenge grant
E_SCOPE_SHRUNK = "E_SCOPE_SHRUNK"                # scopes no longer within the client's current grant
