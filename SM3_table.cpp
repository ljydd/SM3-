#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <immintrin.h>  // 用于SIMD指令
#include <tmmintrin.h>  // SSSE3
#include <smmintrin.h>  // SSE4.1

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// 跨平台的64位字节交换函数
static uint64_t byteswap64(uint64_t x) {
    return ((x & 0xFF00000000000000ULL) >> 56) |
           ((x & 0x00FF000000000000ULL) >> 40) |
           ((x & 0x0000FF0000000000ULL) >> 24) |
           ((x & 0x000000FF00000000ULL) >> 8)  |
           ((x & 0x00000000FF000000ULL) << 8)  |
           ((x & 0x0000000000FF0000ULL) << 24) |
           ((x & 0x000000000000FF00ULL) << 40) |
           ((x & 0x00000000000000FFULL) << 56);
}

// 预计算P1函数的结果
uint32_t P1_table[256];
void init_P1_table() {
    for(int i=0; i<256; i++) {
        P1_table[i] = (i ^ ((i << 9) | (i >> 23)) ^ ((i << 17) | (i >> 15)));
    }
}

// 使用查表法优化的P1函数
#define P1_OPT(x) (P1_table[(x) & 0xFF] ^ \
                  ROTL(P1_table[(x >> 8) & 0xFF], 8) ^ \
                  ROTL(P1_table[(x >> 16) & 0xFF], 16) ^ \
                  ROTL(P1_table[(x >> 24) & 0xFF], 24))

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

// 优化的消息填充
void sm3_pad_opt(const uint8_t *msg, size_t len, uint8_t *padded_msg, size_t *padded_len) {
    size_t bit_len = len * 8;
    size_t pad_len = (len % 64 < 56) ? (56 - len % 64) : (120 - len % 64);
    
    memcpy(padded_msg, msg, len);
    padded_msg[len] = 0x80;
    
    // 使用memset优化
    if (pad_len > 1) {
        memset(padded_msg + len + 1, 0, pad_len - 1);
    }
    
    // 使用64位写入优化
    uint64_t len_be = byteswap64(bit_len);
    memcpy(padded_msg + len + pad_len, &len_be, 8);
    
    *padded_len = len + pad_len + 8;
}

// 使用SIMD优化的压缩函数
void sm3_compress_opt(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[68];
    uint32_t W1[64];
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    
    // 使用SIMD加速消息扩展
    __m128i *block128 = (__m128i*)block;
    for (int i = 0; i < 4; i++) {
        __m128i word = _mm_loadu_si128(block128 + i);
        word = _mm_shuffle_epi8(word, _mm_set_epi8(12,13,14,15, 8,9,10,11, 4,5,6,7, 0,1,2,3));
        _mm_storeu_si128((__m128i*)(W + i*4), word);
    }
    
    // 使用查表法优化的消息扩展
    for (int j = 16; j < 68; j++) {
        W[j] = P1_OPT(W[j-16] ^ W[j-9] ^ ROTL(W[j-3], 15)) ^ ROTL(W[j-13], 7) ^ W[j-6];
    }
    
    for (int j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j+4];
    }
    
    // 压缩函数 - 部分循环展开
    A = state[0]; B = state[1]; C = state[2]; D = state[3];
    E = state[4]; F = state[5]; G = state[6]; H = state[7];
    
    for (int j = 0; j < 64; j += 4) {
        // 第j轮
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = (j < 16 ? FF0(A,B,C) : FF1(A,B,C)) + D + SS2 + W1[j];
        TT2 = (j < 16 ? GG0(E,F,G) : GG1(E,F,G)) + H + SS1 + W[j];
        D = C; C = ROTL(B, 9); B = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
        
        // 第j+1轮
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j+1], j+1)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = (j+1 < 16 ? FF0(A,B,C) : FF1(A,B,C)) + D + SS2 + W1[j+1];
        TT2 = (j+1 < 16 ? GG0(E,F,G) : GG1(E,F,G)) + H + SS1 + W[j+1];
        D = C; C = ROTL(B, 9); B = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
        
        // 第j+2轮
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j+2], j+2)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = (j+2 < 16 ? FF0(A,B,C) : FF1(A,B,C)) + D + SS2 + W1[j+2];
        TT2 = (j+2 < 16 ? GG0(E,F,G) : GG1(E,F,G)) + H + SS1 + W[j+2];
        D = C; C = ROTL(B, 9); B = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
        
        // 第j+3轮
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j+3], j+3)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = (j+3 < 16 ? FF0(A,B,C) : FF1(A,B,C)) + D + SS2 + W1[j+3];
        TT2 = (j+3 < 16 ? GG0(E,F,G) : GG1(E,F,G)) + H + SS1 + W[j+3];
        D = C; C = ROTL(B, 9); B = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
    }
    
    state[0] ^= A; state[1] ^= B; state[2] ^= C; state[3] ^= D;
    state[4] ^= E; state[5] ^= F; state[6] ^= G; state[7] ^= H;
}

// 优化的SM3哈希函数
void sm3_hash_opt(const uint8_t *msg, size_t len, uint8_t digest[32]) {
    uint8_t *padded_msg =(uint8_t *) malloc(len + 72); // 最大填充大小
    size_t padded_len;
    uint32_t state[8];
    
    init_P1_table();
    sm3_pad_opt(msg, len, padded_msg, &padded_len);
    
    memcpy(state, IV, sizeof(IV));
    
    for (size_t i = 0; i < padded_len; i += 64) {
        sm3_compress_opt(state, padded_msg + i);
    }
    
    // 使用SIMD加速结果存储
    __m128i *state128 = (__m128i*)state;
    __m128i shuffle = _mm_set_epi8(3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12);
    
    for (int i = 0; i < 2; i++) {
        __m128i word = _mm_loadu_si128(state128 + i);
        word = _mm_shuffle_epi8(word, shuffle);
        _mm_storeu_si128((__m128i*)(digest + i*16), word);
    }
    
    free(padded_msg);
}

int main() {
    const char *msg = "Hello,world!";
    uint8_t digest_opt[32];
    
    // 优化版本
    sm3_hash_opt((const uint8_t *)msg, strlen(msg), digest_opt);
    printf("Optimized SM3 hash of \"%s\":\n", msg);
    for (int i = 0; i < 32; i++) printf("%02x", digest_opt[i]);
    printf("\n");
    
    return 0;
}