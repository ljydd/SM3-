# Length-Extension Attack demo for SM3 (MD-style strengthening)

from sm3 import Hasher, IV, sm3, sm3_hex
import struct

def md_pad_len(msg_len_bytes: int) -> bytes:
    bit_len = (msg_len_bytes * 8) & ((1 << 64) - 1)
    pad = b'\x80'
    k = (56 - (msg_len_bytes + 1) % 64) % 64
    pad += b'\x00' * k
    pad += bit_len.to_bytes(8, 'big')
    return pad

def digest_to_state(digest: bytes):
    assert len(digest) == 32
    return tuple(int.from_bytes(digest[i:i+4], 'big') for i in range(0, 32, 4))

def forge_extended_hash(orig_digest: bytes, orig_len_bytes: int, suffix: bytes) -> tuple[bytes, bytes]:
    glue = md_pad_len(orig_len_bytes)
    total = orig_len_bytes + len(glue)
    h = Hasher.from_state(digest_to_state(orig_digest), total_len_bytes=total)
    h.update(suffix)
    return h.digest(), glue

def demo():
    secret_prefix = b"SECRET=top:very:confidential"
    public = b"user=alice&coin=100"
    M = secret_prefix + public
    H = sm3(M)
    S = b"&admin=true"
    forged, glue = forge_extended_hash(H, len(M), S)
    honest = sm3(M + glue + S)
    return {
        "orig_digest": H.hex(),
        "suffix": S.decode(),
        "glue_len": len(glue),
        "forged_digest": forged.hex(),
        "honest_digest": honest.hex(),
        "match": forged == honest
    }

if __name__ == "__main__":
    import json
    print(json.dumps(demo(), indent=2))
