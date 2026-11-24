"""Append-only, hash-chained action ledger.

Every tool request lands here, including the refusals. That is the point: the
interesting audit record is not the action that happened, it is the action that
was attempted and stopped, together with the layer that stopped it.

The chain is a simple SHA-256 linked list over canonical JSON. In production
the same entries are written to a DynamoDB table with deletion protection and a
daily root is sealed to an S3 Object Lock bucket in compliance mode, so a
compromised runtime cannot rewrite history even if it owns the table.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Iterable

from .util import canonical_json, digest, iso, sha256_hex


GENESIS = "0" * 64


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    seq: int
    at: str
    body: dict[str, Any]
    prev_hash: str
    hash: str

    def to_json(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "at": self.at,
            "body": self.body,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
        }


@dataclass(frozen=True, slots=True)
class ChainStatus:
    ok: bool
    length: int
    root: str
    broken_at: int | None = None
    reason: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "length": self.length,
            "root": self.root,
            "broken_at": self.broken_at,
            "reason": self.reason,
        }


class Ledger:
    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []
        self._lock = threading.RLock()
        self._head = GENESIS

    # -- write ------------------------------------------------------------

    def append(self, body: dict[str, Any], *, at: str | None = None) -> LedgerEntry:
        with self._lock:
            seq = len(self._entries) + 1
            body = {
                **body,
                "seq": seq,
                "at": at or iso(),
            }
            prev = self._head
            h = sha256_hex(prev + canonical_json(body))
            entry = LedgerEntry(seq=seq, at=body["at"], body=body, prev_hash=prev, hash=h)
            self._entries.append(entry)
            self._head = h
            return entry

    # -- read -------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def head(self) -> str:
        return self._head

    def entries(self, limit: int | None = None, newest_first: bool = False) -> list[LedgerEntry]:
        with self._lock:
            items = list(self._entries)
        if newest_first:
            items = list(reversed(items))
        if limit is not None:
            items = items[:limit]
        return items

    def entry(self, seq: int) -> LedgerEntry | None:
        with self._lock:
            if 1 <= seq <= len(self._entries):
                return self._entries[seq - 1]
        return None

    def to_json(self, limit: int | None = None, newest_first: bool = True) -> list[dict[str, Any]]:
        return [e.to_json() for e in self.entries(limit, newest_first)]

    # -- verification -----------------------------------------------------

    def verify(self) -> ChainStatus:
        with self._lock:
            entries = list(self._entries)
        prev = GENESIS
        for i, entry in enumerate(entries, start=1):
            recomputed = sha256_hex(prev + canonical_json(entry.body))
            if entry.prev_hash != prev:
                return ChainStatus(False, len(entries), self._head, i, "prev_hash mismatch")
            if entry.hash != recomputed:
                return ChainStatus(False, len(entries), self._head, i, "entry hash mismatch")
            if entry.seq != i or entry.body.get("seq") != i:
                return ChainStatus(False, len(entries), self._head, i, "sequence mismatch")
            prev = entry.hash
        if prev != self._head:
            return ChainStatus(False, len(entries), self._head, None, "head mismatch")
        return ChainStatus(True, len(entries), self._head)

    def root(self) -> str:
        """Chain head, used as the daily seal value."""
        with self._lock:
            return self._head

    # -- test-only tamper -------------------------------------------------

    def _tamper_for_demo(self, seq: int, mutate: dict[str, Any]) -> None:
        """Deliberately corrupt one entry so the UI can prove verification works.

        Guarded by name rather than by a flag so it cannot be reached from the
        agent surface. Never called by the kernel.
        """
        with self._lock:
            idx = seq - 1
            e = self._entries[idx]
            body = {**e.body, **mutate}
            self._entries[idx] = LedgerEntry(e.seq, e.at, body, e.prev_hash, e.hash)


__all__ = ["Ledger", "LedgerEntry", "ChainStatus", "GENESIS"]
