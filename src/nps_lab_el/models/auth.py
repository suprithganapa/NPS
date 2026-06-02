from __future__ import annotations

import time
import uuid
from enum import StrEnum

from pydantic import BaseModel, Field


class AuthorizationState(StrEnum):
    DENIED = "DENIED"
    PENDING = "PENDING"
    AUTHORIZED = "AUTHORIZED"
    EXPIRED = "EXPIRED"


class AuthToken(BaseModel):
    payload: bytes = Field(min_length=16, max_length=16)
    totp_counter: int
    channel_mask: int
    mac: bytes = Field(min_length=16, max_length=16)

    @classmethod
    def total_bits(cls) -> int:
        return 128 + 64 + 8 + 128

    def to_bits(self) -> list[int]:
        bits: list[int] = []
        for byte in self.payload:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        counter_bytes = self.totp_counter.to_bytes(8, "big")
        for byte in counter_bytes:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        for i in range(7, -1, -1):
            bits.append((self.channel_mask >> i) & 1)
        for byte in self.mac:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    @classmethod
    def from_bits(cls, bits: list[int]) -> AuthToken:
        pos = 0
        payload_bytes = bytearray(16)
        for b in range(16):
            val = 0
            for i in range(8):
                val = (val << 1) | bits[pos]
                pos += 1
            payload_bytes[b] = val
        counter = 0
        for _ in range(64):
            counter = (counter << 1) | bits[pos]
            pos += 1
        mask = 0
        for _ in range(8):
            mask = (mask << 1) | bits[pos]
            pos += 1
        mac_bytes = bytearray(16)
        for b in range(16):
            val = 0
            for i in range(8):
                val = (val << 1) | bits[pos]
                pos += 1
            mac_bytes[b] = val
        return cls(
            payload=bytes(payload_bytes),
            totp_counter=counter,
            channel_mask=mask,
            mac=bytes(mac_bytes),
        )


class KnockSession(BaseModel):
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    src_ip: str
    started_at: float = Field(default_factory=time.time)
    symbols: list[int] = Field(default_factory=list)
    iat_observations: list[float] = Field(default_factory=list)
    rs_codeword: bytes | None = None
    state: AuthorizationState
    timeout_seconds: float = 120.0


class CaptureEvent(BaseModel):
    ts: float
    src: str
    dst: str
    icmp_id: int
    icmp_seq: int
    ip_id: int
    ttl: int
    tos: int
    icmp_type: int


class KeyMaterial(BaseModel):
    key_partial: bytes = Field(min_length=28, max_length=28)
    key_fragment: bytes = Field(min_length=4, max_length=4)

    @property
    def key_full(self) -> bytes:
        return self.key_partial + self.key_fragment


class EvalReport(BaseModel):
    ks_d_statistic: float
    ks_p_value: float
    entropy_baseline: float
    entropy_knock: float
    replay_reject_rate: float
    decode_accuracy: float
