#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM3初始值
const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 布尔函数
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

// 置换函数
#define P0(x) ((x) ^ ROTL((x), 9) ^ ROTL((x), 17))
#define P1(x) ((x) ^ ROTL((x), 15) ^ ROTL((x), 23))

// 常量Tj
static const uint32_t T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

// 消息填充
void sm3_pad(const uint8_t *msg, size_t len, uint8_t *padded_msg, size_t *padded_len) {
    size_t bit_len = len * 8;
    size_t pad_len = (len % 64 < 56) ? (56 - len % 64) : (120 - len % 64);
    
    memcpy(padded_msg, msg, len);
    padded_msg[len] = 0x80;
    memset(padded_msg + len + 1, 0, pad_len - 1);
    
    for (int i = 0; i < 8; i++) {
        padded_msg[len + pad_len + i] = (bit_len >> (56 - 8 * i)) & 0xFF;
    }
    
    *padded_len = len + pad_len + 8;
}

// 压缩函数
void sm3_compress(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68];
    uint32_t W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    
    // 消息扩展
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3]);
    }
    
    for (int j = 16; j < 68; j++) {
        W[j] = P1(W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15)) ^ ROTL(W[j-13], 7) ^ W[j-6];
    }
    
    for (int j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }
    
    // 压缩
    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];
    
    for (int j = 0; j < 64; j++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        
        if (j < 16) {
            TT1 = FF0(A, B, C) + D + SS2 + W1[j];
            TT2 = GG0(E, F, G) + H + SS1 + W[j];
        } else {
            TT1 = FF1(A, B, C) + D + SS2 + W1[j];
            TT2 = GG1(E, F, G) + H + SS1 + W[j];
        }
        
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
    }
    
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// SM3哈希函数
void sm3_hash(const uint8_t *msg, size_t len, uint8_t digest[32]) {
    uint8_t *padded_msg = (uint8_t *)malloc(64 * ((len + 72) / 64));
    size_t padded_len;
    uint32_t state[8];
    
    sm3_pad(msg, len, padded_msg, &padded_len);
    
    memcpy(state, IV, sizeof(IV));
    
    for (size_t i = 0; i < padded_len; i += 64) {
        sm3_compress(state, padded_msg + i);
    }
    
    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = state[i] & 0xFF;
    }

    free(padded_msg);
}

// 从哈希值恢复内部状态
void hash_to_state(const uint8_t hash[32], uint32_t state[8]) {
    for (int i = 0; i < 8; i++) {
        state[i] = (hash[i*4]<<24) | (hash[i*4+1]<<16) |
                  (hash[i*4+2]<<8) | hash[i*4+3];
    }
}

// 长度扩展攻击核心函数
void length_extension_attack(
    const uint8_t original_hash[32],
    size_t orig_len,
    const uint8_t *append_data,
    size_t append_len,
    uint8_t forged_hash[32]
) {
    uint32_t state[8];
    hash_to_state(original_hash, state);

    // 原消息做完 padding 后一定在块边界上
    size_t orig_pad_len = (orig_len % 64 < 56) ? (56 - orig_len % 64) : (120 - orig_len % 64);

    // 新消息（padding 之前）的总长度：|M'| = |M| + |pad(M)| + |append|
    size_t new_pre_len = orig_len + orig_pad_len + 8 + append_len;

    // 现在只构造：append || pad_for_M'
    size_t tail_pad_len = (new_pre_len % 64 < 56) ? (56 - new_pre_len % 64) : (120 - new_pre_len % 64);
    size_t ext_len = append_len + tail_pad_len + 8;

    uint8_t *buf = (uint8_t *)malloc(ext_len);
    if (!buf) { perror("malloc"); exit(EXIT_FAILURE); }

    // 先放入 append
    memcpy(buf, append_data, append_len);

    // 然后是对整条新消息 M' 的最终 padding
    buf[append_len] = 0x80;
    memset(buf + append_len + 1, 0, tail_pad_len - 1);

    uint64_t new_bit_len = (uint64_t)new_pre_len * 8ULL;
    for (int i = 0; i < 8; i++) {
        buf[append_len + tail_pad_len + i] = (new_bit_len >> (56 - 8*i)) & 0xFF;
    }

    // 用已知的内部状态继续压缩
    for (size_t i = 0; i < ext_len; i += 64) {
        sm3_compress(state, buf + i);
    }

    // 输出伪造哈希
    for (int i = 0; i < 8; i++) {
        forged_hash[i*4+0] = (state[i] >> 24) & 0xFF;
        forged_hash[i*4+1] = (state[i] >> 16) & 0xFF;
        forged_hash[i*4+2] = (state[i] >>  8) & 0xFF;
        forged_hash[i*4+3] =  state[i]        & 0xFF;
    }

    free(buf);
}

int main() {
    const char *secret = "Hello world";
    size_t secret_len = strlen(secret);
    uint8_t original_hash[32];
    sm3_hash((uint8_t*)secret, secret_len, original_hash);

    printf("原始消息: \"%s\"\n", secret);
    printf("原始哈希: ");
    for (int i = 0; i < 32; i++) printf("%02x", original_hash[i]);
    printf("\n");

    // 攻击者伪造 Hash(secret || Pad || "append")
    const char *append = "yyyyy";
    uint8_t forged_hash[32];
    length_extension_attack(
        original_hash,
        secret_len,
        (uint8_t*)append,
        strlen(append),
        forged_hash
    );

    printf("伪造哈希: ");
    for (int i = 0; i < 32; i++) printf("%02x", forged_hash[i]);
    printf("\n");

    // 直接计算真实 Hash(secret || Pad || "append")
    size_t pad_len = (secret_len % 64 < 56) ? 
                   (56 - secret_len % 64) : 
                   (120 - secret_len % 64);
    uint8_t *combined = (uint8_t *)malloc(secret_len + pad_len + 8 + strlen(append));
    memcpy(combined, secret, secret_len);
    combined[secret_len] = 0x80;
    memset(combined + secret_len + 1, 0, pad_len - 1);
    uint64_t bit_len = secret_len * 8;
    for (int i = 0; i < 8; i++) {
        combined[secret_len + pad_len + i] = (bit_len >> (56 - 8 * i)) & 0xFF;
    }
    memcpy(combined + secret_len + pad_len + 8, append, strlen(append));
    
    uint8_t true_hash[32];
    sm3_hash(combined, secret_len + pad_len + 8 + strlen(append), true_hash);
    free(combined);

    printf("真实哈希: ");
    for (int i = 0; i < 32; i++) printf("%02x", true_hash[i]);
    printf("\n");

    // 验证攻击是否成功
    if (memcmp(forged_hash, true_hash, 32) == 0) {
        printf("\n>>> 攻击成功！SM3易受长度扩展攻击。\n");
    } else {
        printf("\n攻击失败！请检查填充和状态恢复逻辑。\n");
    }

    return 0;
}