# SM3

from __future__ import annotations
from typing import Iterable, Tuple

IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
)

T0 = 0x79CC4519
T1 = 0x7A879D8A

def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

def _ff(x: int, y: int, z: int, j: int) -> int:
    if 0 <= j <= 15:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)

def _gg(x: int, y: int, z: int, j: int) -> int:
    if 0 <= j <= 15:
        return x ^ y ^ z
    return (x & y) | (~x & z)

def _p0(x: int) -> int:
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)

def _p1(x: int) -> int:
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)

def _pad(msg_len_bytes: int) -> bytes:
    bit_len = (msg_len_bytes * 8) & ((1 << 64) - 1)
    pad = b'\x80'
    k = (56 - (msg_len_bytes + 1) % 64) % 64
    pad += b'\x00' * k
    pad += bit_len.to_bytes(8, 'big')
    return pad

def _expand(B: bytes) -> Tuple[list, list]:
    assert len(B) == 64
    W = [0]*68
    Wp = [0]*64
    for i in range(16):
        W[i] = int.from_bytes(B[4*i:4*i+4], 'big')
    for j in range(16, 68):
        x = W[j-16] ^ W[j-9] ^ _rotl(W[j-3], 15)
        W[j] = (_p1(x) ^ _rotl(W[j-13], 7) ^ W[j-6]) & 0xFFFFFFFF
    for j in range(64):
        Wp[j] = (W[j] ^ W[j+4]) & 0xFFFFFFFF
    return W, Wp

def compress(V: Tuple[int, ...], B: bytes) -> Tuple[int, ...]:
    A, Bv, C, D, E, F, G, H = V
    W, Wp = _expand(B)
    for j in range(64):
        Tj = T0 if j <= 15 else T1
        SS1 = _rotl(((_rotl(A, 12) + E + _rotl(Tj, j % 32)) & 0xFFFFFFFF), 7)
        SS2 = SS1 ^ _rotl(A, 12)
        TT1 = (_ff(A, Bv, C, j) + D + SS2 + Wp[j]) & 0xFFFFFFFF
        TT2 = (_gg(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
        D = C
        C = _rotl(Bv, 9)
        Bv = A
        A = TT1
        H = G
        G = _rotl(F, 19)
        F = E
        E = _p0(TT2)
    return (
        A ^ V[0], Bv ^ V[1], C ^ V[2], D ^ V[3],
        E ^ V[4], F ^ V[5], G ^ V[6], H ^ V[7]
    )

class Hasher:
    __slots__ = ("_state", "_buf", "_length")
    def __init__(self, data: bytes | None = None):
        self._state = IV
        self._buf = bytearray()
        self._length = 0
        if data:
            self.update(data)
    def update(self, data: bytes) -> 'Hasher':
        if not data:
            return self
        self._length += len(data)
        self._buf.extend(data)
        while len(self._buf) >= 64:
            block = bytes(self._buf[:64])
            self._buf = self._buf[64:]
            self._state = compress(self._state, block)
        return self
    def copy(self) -> 'Hasher':
        h = Hasher()
        h._state = tuple(self._state)
        h._buf = bytearray(self._buf)
        h._length = self._length
        return h
    def digest(self) -> bytes:
        tmp = self._buf + _pad(self._length)
        st = self._state
        for i in range(0, len(tmp), 64):
            st = compress(st, tmp[i:i+64])
        return b''.join(x.to_bytes(4, 'big') for x in st)
    def hexdigest(self) -> str:
        return self.digest().hex()
    @classmethod
    def from_state(cls, state_words: Iterable[int], total_len_bytes: int, tail: bytes=b"") -> 'Hasher':
        h = Hasher()
        h._state = tuple(int(x) & 0xFFFFFFFF for x in state_words)
        h._buf = bytearray(tail)
        h._length = total_len_bytes
        return h

def sm3(data: bytes) -> bytes:
    return Hasher(data).digest()

def sm3_hex(data: bytes) -> str:
    return sm3(data).hex()