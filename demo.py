# demo.py


# 1. 验证 SM3 摘要与标准测试向量是否一致
# 2. 运行长度扩展攻击（Length-Extension Attack）演示
# 3. 构建一个 RFC6962 风格的 Merkle 树，并验证包含性/不包含性证明

from sm3 import sm3_hex
from length_extension import demo as le_demo
from merkle_rfc6962 import ExclusionIndex, MerkleTree

def test_vector():
    """
    测试 SM3 算法的正确性
    使用标准测试向量：SM3("abc") 的期望值为
    66C7F0F462EEEDD9D1F2D46BDC10E4E2
    4167C4875CF2F7A2297DA02B8F4BA8E0（无空格）
    """
    expected = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    got = sm3_hex(b"abc")
    return got == expected, got, expected

def merkle_demo():
    """
    构建一个小规模 RFC6962 Merkle 树（10 个叶子）
    并验证：
      - 某个叶子的存在性证明（inclusion proof）
      - 一个不存在值的不包含性证明（exclusion proof）
    """
    # 构造叶子节点
    items = [f"leaf-{i}".encode() for i in range(10)]
    idx = ExclusionIndex(items) # 创建索引结构
    root = idx.root().hex() # 获取根哈希（十六进制形式）

    # 测试 "leaf-3" 的包含性证明
    i3, proof3 = idx.inclusion(b"leaf-3")
    ok_incl = MerkleTree.verify_inclusion(
        bytes.fromhex(root), b"leaf-3", i3, proof3
    )

    # 测试 "leaf-3.5" 的不包含性证明
    proof_ex = idx.exclusion(b"leaf-3.5")
    ok_ex = idx.verify_exclusion(b"leaf-3.5", proof_ex)

    return {
        "root": root,
        "incl_ok": ok_incl,
        "excl_ok": ok_ex,
        "proof_ex": proof_ex
    }

if __name__ == "__main__":
    # 1. 测试向量验证
    tv_ok, got, exp = test_vector()
    print("SM3 测试向量验证结果:", tv_ok)
    print(" 计算结果:", got)
    print(" 期望结果:", exp)
    print()

    # 2. 长度扩展攻击演示
    print("长度扩展攻击演示:")
    print(le_demo())
    print()

    # 3. Merkle 树演示
    print("Merkle 树演示:")
    print(merkle_demo())
