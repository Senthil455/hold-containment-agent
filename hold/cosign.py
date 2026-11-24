"""Two-person co-signature for the human release plane.

Design notes that matter for the safety argument:

* The token is an HMAC over the *exact* payload digest, the requesting
  principal, the action name and the approver. Moving the approval to a
  different lot, a different action, or a different requester invalidates it.
* Tokens are single-use and short-lived (15 minutes by default).
* The approver must differ from the requester.
* The agent's principal does not hold the RELEASE capability at all, so a valid
  co-signature presented *by the agent* is still refused. A stolen token is not
  an escalation path.

In production the HMAC key lives in AWS KMS and the human approves through
AgentCore Identity with their own OIDC session plus a WebAuthn assertion. This
module implements the same protocol with a local key so the demo and the test
suite exercise the real verification path.
"""

from __future__ import annotations

import hmac
import secrets
import threading
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from .util import canonical_json, digest, iso, parse_iso, sha256_hex, utcnow


DEFAULT_TTL_SECONDS = 900


@dataclass(frozen=True, slots=True)
class CosignVerdict:
    ok: bool
    code: str
    reason: str

    def to_json(self) -> dict[str, Any]:
        return {"ok": self.ok, "code": self.code, "reason": self.reason}


def payload_digest(action: str, requester: str, payload: dict[str, Any]) -> str:
    """Digest of exactly what is being approved.

    ``payload`` must contain every semantically relevant argument. The kernel
    builds it from the validated arguments, not from raw model text.
    """
    return sha256_hex(canonical_json({"action": action, "requester": requester, "payload": payload}))


class CosignAuthority:
    def __init__(self, secret: bytes | None = None) -> None:
        self._secret = secret or secrets.token_bytes(32)
        self._used: set[str] = set()
        self._lock = threading.RLock()

    # -- issue (human console / test harness only) ------------------------

    def issue(
        self,
        *,
        action: str,
        requester: str,
        approver: str,
        payload: dict[str, Any],
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> dict[str, Any]:
        if approver == requester:
            raise ValueError("approver must differ from requester")
        now = utcnow()
        token = {
            "v": 1,
            "action": action,
            "requester": requester,
            "approver": approver,
            "payload_hash": payload_digest(action, requester, payload),
            "nonce": secrets.token_hex(16),
            "issued_at": iso(now),
            "expires_at": iso(now + timedelta(seconds=ttl_seconds)),
        }
        token["mac"] = self._mac(token)
        return token

    # -- verify -----------------------------------------------------------

    def _mac(self, token: dict[str, Any]) -> str:
        body = {k: v for k, v in token.items() if k != "mac"}
        return hmac.new(self._secret, canonical_json(body).encode("utf-8"), "sha256").hexdigest()

    def verify(
        self,
        token: Any,
        *,
        action: str,
        requester: str,
        payload: dict[str, Any],
    ) -> CosignVerdict:
        if not isinstance(token, dict):
            return CosignVerdict(False, "COSIGN_MISSING", "No co-signature token supplied.")
        required = {"v", "action", "requester", "approver", "payload_hash", "nonce",
                    "issued_at", "expires_at", "mac"}
        if not required <= set(token):
            return CosignVerdict(False, "COSIGN_MALFORMED", "Token is missing required fields.")
        if not hmac.compare_digest(str(token["mac"]), self._mac(token)):
            return CosignVerdict(False, "COSIGN_BAD_MAC", "Signature does not verify.")
        if token["action"] != action:
            return CosignVerdict(False, "COSIGN_WRONG_ACTION", "Token was issued for a different action.")
        if token["requester"] != requester:
            return CosignVerdict(False, "COSIGN_WRONG_REQUESTER", "Token was issued to a different principal.")
        if token["approver"] == requester:
            return CosignVerdict(False, "COSIGN_SELF_APPROVAL", "Requester cannot approve their own action.")
        expected = payload_digest(action, requester, payload)
        if not hmac.compare_digest(str(token["payload_hash"]), expected):
            return CosignVerdict(
                False,
                "COSIGN_PAYLOAD_MISMATCH",
                "Arguments changed after approval; the signature no longer covers them.",
            )
        try:
            if parse_iso(str(token["expires_at"])) < utcnow():
                return CosignVerdict(False, "COSIGN_EXPIRED", "Approval window has expired.")
        except Exception:
            return CosignVerdict(False, "COSIGN_MALFORMED", "Unreadable expiry.")
        with self._lock:
            if token["nonce"] in self._used:
                return CosignVerdict(False, "COSIGN_REPLAYED", "This approval has already been used.")
        return CosignVerdict(True, "COSIGN_OK", f"Approved by {token['approver']}.")

    def consume(self, token: dict[str, Any]) -> None:
        with self._lock:
            self._used.add(str(token.get("nonce")))

    # -- introspection for the UI ----------------------------------------

    def pending_approvers(self) -> list[str]:
        return ["human:qa-director"]

    def status(self) -> dict[str, Any]:
        return {"used_nonces": len(self._used), "ttl_seconds": DEFAULT_TTL_SECONDS}


__all__ = ["CosignAuthority", "CosignVerdict", "payload_digest", "DEFAULT_TTL_SECONDS"]
