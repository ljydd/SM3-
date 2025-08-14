# RFC6962-style Merkle tree (Certificate Transparency) using SM3

from __future__ import annotations
from typing import List, Tuple, Iterable, Optional
from sm3 import sm3

def leaf_hash(data: bytes) -> bytes:
    return sm3(b'\x00' + data)

def node_hash(left: bytes, right: bytes) -> bytes:
    return sm3(b'\x01' + left + right)

class MerkleTree:
    def __init__(self, leaves: Optional[Iterable[bytes]]=None):
        self._leaves: List[bytes] = []
        self._levels: List[List[bytes]] = []
        if leaves is not None:
            self.add_leaves(leaves)
    
    def add_leaves(self, leaves: Iterable[bytes]):
        for d in leaves:
            self._leaves.append(leaf_hash(d))
        self._levels = []
    
    def build(self):
        if not self._leaves:
            self._levels = [[b'']]
            return
        level = list(self._leaves)
        levels = [level]
        while len(level) > 1:
            nxt = []
            for i in range(0, len(level), 2):
                if i+1 < len(level):
                    nxt.append(node_hash(level[i], level[i+1]))
                else:
                    nxt.append(level[i])
            level = nxt
            levels.append(level)
        self._levels = levels
    
    def root(self) -> bytes:
        if not self._levels:
            self.build()
        return self._levels[-1][0] if self._levels[-1] else b''
    
    def inclusion_proof(self, index: int) -> List[bytes]:
        if not self._levels:
            self.build()
        if index < 0 or index >= len(self._leaves):
            raise IndexError("leaf index out of range")
        proof = []
        idx = index
        for level in range(0, len(self._levels)-1):
            cur = self._levels[level]
            sib = idx ^ 1  # sibling index
            if sib < len(cur):
                proof.append(cur[sib])
            idx //= 2
        return proof
    
    @staticmethod
    def _recompute_root_from_proof(leaf: bytes, index: int, proof: List[bytes]) -> bytes:
        h = leaf_hash(leaf)
        idx = index
        for p in proof:
            if idx % 2 == 0:
                h = node_hash(h, p)
            else:
                h = node_hash(p, h)
            idx //= 2
        return h
    
    @staticmethod
    def verify_inclusion(root: bytes, leaf_data: bytes, index: int, proof: List[bytes]) -> bool:
        return MerkleTree._recompute_root_from_proof(leaf_data, index, proof) == root

    def exclusion_proof(self, target: bytes) -> dict:
        raise NotImplementedError("Use ExclusionIndex for exclusion proofs (see class below).")

class ExclusionIndex:
    def __init__(self, data_items: Iterable[bytes]):
        self.data_list = sorted(list(data_items))
        self.tree = MerkleTree(self.data_list)
        self.tree.build()
    
    def root(self) -> bytes:
        return self.tree.root()
    
    def inclusion(self, data: bytes) -> Tuple[int, list]:
        idx = self._index_of(data)
        proof = self.tree.inclusion_proof(idx)
        return idx, proof
    
    def exclusion(self, target: bytes) -> dict:
        import bisect
        i = bisect.bisect_left(self.data_list, target)
        n = len(self.data_list)
        left = i-1 if i > 0 else None
        right = i if i < n else None
        proof = {"target": target.hex(), "root": self.tree.root().hex()}
        if left is not None:
            proof["left"] = {
                "data": self.data_list[left].hex(),
                "index": left,
                "proof": [h.hex() for h in self.tree.inclusion_proof(left)]
            }
        if right is not None:
            proof["right"] = {
                "data": self.data_list[right].hex(),
                "index": right,
                "proof": [h.hex() for h in self.tree.inclusion_proof(right)]
            }
        return proof
    
    def verify_exclusion(self, target: bytes, proof: dict) -> bool:
        root = bytes.fromhex(proof["root"])
        ok_left = ok_right = True
        if "left" in proof:
            left = proof["left"]
            ok_left = MerkleTree.verify_inclusion(root,
                                                  bytes.fromhex(left["data"]),
                                                  left["index"],
                                                  [bytes.fromhex(x) for x in left["proof"]])
            ok_left = ok_left and (bytes.fromhex(left["data"]) < target)
        if "right" in proof:
            right = proof["right"]
            ok_right = MerkleTree.verify_inclusion(root,
                                                   bytes.fromhex(right["data"]),
                                                   right["index"],
                                                   [bytes.fromhex(x) for x in right["proof"]])
            ok_right = ok_right and (target < bytes.fromhex(right["data"]))
        if "left" in proof and "right" in proof:
            return ok_left and ok_right
        return ok_left or ok_right
    
    def _index_of(self, data: bytes) -> int:
        import bisect
        i = bisect.bisect_left(self.data_list, data)
        if i >= len(self.data_list) or self.data_list[i] != data:
            raise ValueError("data not present")
        return i
