#ifndef SEPAR_COMMON_H
#define SEPAR_COMMON_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#endif

#define WORDS 65536u
#define LANE_EDGES 256u
#define BYTE_EDGES 65536u
#define PROBE_COUNT 7u
#define DIFF_COUNT 6u

typedef struct {
    uint16_t state[8];
    uint16_t lfsr;
} SeparCtx;

typedef struct {
    uint64_t score;
    uint16_t k0;
    uint16_t k1;
} PairScore;

typedef struct {
    uint32_t key;
    uint32_t count;
} EdgeCount;

static const uint8_t S1[16] = {
    1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4
};
static const uint8_t S2[16] = {
    6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8
};
static const uint8_t S3[16] = {
    12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13, 15, 4
};
static const uint8_t S4[16] = {
    13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14
};
static const uint8_t IS1[16] = {
    4, 0, 3, 5, 15, 6, 8, 11, 7, 9, 13, 2, 10, 12, 14, 1
};
static const uint8_t IS2[16] = {
    12, 8, 7, 13, 3, 14, 0, 9, 15, 6, 1, 11, 10, 5, 4, 2
};
static const uint8_t IS3[16] = {
    4, 3, 1, 5, 15, 6, 2, 8, 7, 9, 12, 10, 0, 13, 11, 14
};
static const uint8_t IS4[16] = {
    4, 11, 2, 5, 13, 6, 8, 3, 7, 14, 12, 1, 9, 0, 15, 10
};

static const uint16_t DEFAULT_KEY[16] = {
    0xE8B9, 0xB733, 0xDA5D, 0x96D7, 0x02DD, 0x3972, 0xE953, 0x07FD,
    0x50C5, 0x12DB, 0xF44A, 0x233E, 0x8D1E, 0x9DF5, 0xFC7D, 0x6371
};

static const uint16_t PROBES[PROBE_COUNT] = {
    0x0000, 0x0001, 0x0002, 0x0004, 0x0008, 0x000F, 0x0010
};

static _Noreturn void die(const char *message)
{
    fprintf(stderr, "error: %s\n", message);
    exit(EXIT_FAILURE);
}

static inline uint64_t now_ns(void)
{
#if defined(_WIN32)
    static LARGE_INTEGER frequency;
    LARGE_INTEGER counter;
    if (frequency.QuadPart == 0) {
        if (!QueryPerformanceFrequency(&frequency))
            return GetTickCount64() * 1000000ULL;
    }
    if (!QueryPerformanceCounter(&counter))
        return GetTickCount64() * 1000000ULL;
    {
        uint64_t count = (uint64_t)counter.QuadPart;
        uint64_t freq = (uint64_t)frequency.QuadPart;
        uint64_t seconds = count / freq;
        uint64_t remainder = count % freq;
        return seconds * 1000000000ULL +
               (remainder * 1000000000ULL) / freq;
    }
#else
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
        die("clock_gettime failed");
    return (uint64_t)value.tv_sec * 1000000000ULL +
           (uint64_t)value.tv_nsec;
#endif
}

static inline unsigned detected_threads(void)
{
#if defined(_WIN32)
    DWORD n = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    return n == 0 ? 1u : (unsigned)n;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n < 1 ? 1u : (unsigned)n;
#endif
}

static inline uint16_t rotl16(uint16_t x, unsigned amount)
{
    amount &= 15u;
    if (amount == 0u) return x;
    return (uint16_t)((uint16_t)(x << amount) |
                      (uint16_t)(x >> (16u - amount)));
}

static inline uint16_t rotr16(uint16_t x, unsigned amount)
{
    amount &= 15u;
    if (amount == 0u) return x;
    return (uint16_t)((uint16_t)(x >> amount) |
                      (uint16_t)(x << (16u - amount)));
}

static inline uint16_t sbox_layer(uint16_t x)
{
    return (uint16_t)(((uint16_t)S1[(x >> 12) & 15u] << 12) |
                      ((uint16_t)S2[(x >> 8) & 15u] << 8) |
                      ((uint16_t)S3[(x >> 4) & 15u] << 4) |
                      (uint16_t)S4[x & 15u]);
}

static inline uint16_t isbox_layer(uint16_t x)
{
    return (uint16_t)(((uint16_t)IS1[(x >> 12) & 15u] << 12) |
                      ((uint16_t)IS2[(x >> 8) & 15u] << 8) |
                      ((uint16_t)IS3[(x >> 4) & 15u] << 4) |
                      (uint16_t)IS4[x & 15u]);
}

static inline uint16_t separ_linear(uint16_t x)
{
    uint8_t a = (uint8_t)(x >> 12);
    uint8_t b = (uint8_t)((x >> 8) & 15u);
    uint8_t c = (uint8_t)((x >> 4) & 15u);
    uint8_t d = (uint8_t)(x & 15u);
    uint16_t y;
    a ^= c;
    b ^= d;
    c ^= b;
    d ^= a;
    y = (uint16_t)(((uint16_t)a << 12) | ((uint16_t)b << 8) |
                   ((uint16_t)c << 4) | (uint16_t)d);
    return (uint16_t)(y ^ rotl16(y, 12) ^ rotl16(y, 8));
}

static inline uint16_t separ_linear_inverse(uint16_t x)
{
    uint8_t a, b, c, d;
    x = (uint16_t)(x ^ rotr16(x, 12) ^ rotr16(x, 8));
    a = (uint8_t)(x >> 12);
    b = (uint8_t)((x >> 8) & 15u);
    c = (uint8_t)((x >> 4) & 15u);
    d = (uint8_t)(x & 15u);
    d ^= a;
    c ^= b;
    b ^= d;
    a ^= c;
    return (uint16_t)(((uint16_t)a << 12) | ((uint16_t)b << 8) |
                      ((uint16_t)c << 4) | (uint16_t)d);
}

static inline void derive_key23(uint16_t k0, uint16_t k1, uint8_t stage,
                                uint16_t *key2, uint16_t *key3)
{
    uint16_t x2 = rotl16(k0, 6);
    uint16_t x3 = rotl16(k1, 10);
    uint8_t b2 = (uint8_t)((x2 >> 6) & 15u);
    uint8_t b3 = (uint8_t)((x3 >> 6) & 15u);
    x2 |= (uint16_t)((uint16_t)S1[b2] << 6);
    x3 |= (uint16_t)((uint16_t)S1[b3] << 6);
    x2 ^= (uint16_t)(stage + 2u);
    x3 ^= (uint16_t)(stage + 3u);
    *key2 = x2;
    *key3 = x3;
}

static inline uint16_t enc_block(uint16_t input, uint16_t k0, uint16_t k1,
                                 uint8_t stage)
{
    uint16_t key2, key3, x;
    derive_key23(k0, k1, stage, &key2, &key3);
    x = (uint16_t)(input ^ k0);
    x = separ_linear(sbox_layer(x));
    x ^= k1;
    x = separ_linear(sbox_layer(x));
    x ^= key2;
    x = separ_linear(sbox_layer(x));
    x ^= key3;
    x = separ_linear(sbox_layer(x));
    x ^= (uint16_t)(k0 ^ k1);
    x = sbox_layer(x);
    x ^= (uint16_t)(key2 ^ key3);
    return x;
}

static inline uint16_t dec_block(uint16_t input, uint16_t k0, uint16_t k1,
                                 uint8_t stage)
{
    uint16_t key2, key3, x;
    derive_key23(k0, k1, stage, &key2, &key3);
    x = (uint16_t)(input ^ key2 ^ key3);
    x = isbox_layer(x);
    x ^= (uint16_t)(k0 ^ k1);
    x = isbox_layer(separ_linear_inverse(x));
    x ^= key3;
    x = isbox_layer(separ_linear_inverse(x));
    x ^= key2;
    x = isbox_layer(separ_linear_inverse(x));
    x ^= k1;
    x = isbox_layer(separ_linear_inverse(x));
    x ^= k0;
    return x;
}

static inline void initial_state(const uint16_t key[16], const uint16_t iv[8],
                                 SeparCtx *ctx)
{
    uint16_t ct = 0;
    memcpy(ctx->state, iv, sizeof(ctx->state));
    for (unsigned round = 0; round < 4u; ++round) {
        uint16_t v12 = enc_block((uint16_t)(ctx->state[0] + ctx->state[2] + ctx->state[4] + ctx->state[6]), key[0], key[1], 1);
        uint16_t v23 = enc_block((uint16_t)(v12 + ctx->state[1]), key[2], key[3], 2);
        uint16_t v34 = enc_block((uint16_t)(v23 + ctx->state[2]), key[4], key[5], 3);
        uint16_t v45 = enc_block((uint16_t)(v34 + ctx->state[3]), key[6], key[7], 4);
        uint16_t v56 = enc_block((uint16_t)(v45 + ctx->state[4]), key[8], key[9], 5);
        uint16_t v67 = enc_block((uint16_t)(v56 + ctx->state[5]), key[10], key[11], 6);
        uint16_t v78 = enc_block((uint16_t)(v67 + ctx->state[6]), key[12], key[13], 7);
        ct = enc_block((uint16_t)(v78 + ctx->state[7]), key[14], key[15], 8);
        ctx->state[0] = (uint16_t)(ctx->state[0] + ct);
        ctx->state[1] = (uint16_t)(ctx->state[1] + v12);
        ctx->state[2] = (uint16_t)(ctx->state[2] + v23);
        ctx->state[3] = (uint16_t)(ctx->state[3] + v34);
        ctx->state[4] = (uint16_t)(ctx->state[4] + v45);
        ctx->state[5] = (uint16_t)(ctx->state[5] + v56);
        ctx->state[6] = (uint16_t)(ctx->state[6] + v67);
        ctx->state[7] = (uint16_t)(ctx->state[7] + v78);
    }
    ctx->lfsr = (uint16_t)(ct | 0x0100u);
}

static inline uint16_t encrypt_word(uint16_t pt, SeparCtx *ctx,
                                    const uint16_t key[16])
{
    uint16_t v12 = enc_block((uint16_t)(pt + ctx->state[0]), key[0], key[1], 1);
    uint16_t v23 = enc_block((uint16_t)(v12 + ctx->state[1]), key[2], key[3], 2);
    uint16_t v34 = enc_block((uint16_t)(v23 + ctx->state[2]), key[4], key[5], 3);
    uint16_t v45 = enc_block((uint16_t)(v34 + ctx->state[3]), key[6], key[7], 4);
    uint16_t v56 = enc_block((uint16_t)(v45 + ctx->state[4]), key[8], key[9], 5);
    uint16_t v67 = enc_block((uint16_t)(v56 + ctx->state[5]), key[10], key[11], 6);
    uint16_t v78 = enc_block((uint16_t)(v67 + ctx->state[6]), key[12], key[13], 7);
    uint16_t ct = enc_block((uint16_t)(v78 + ctx->state[7]), key[14], key[15], 8);
    ctx->state[1] = (uint16_t)(ctx->state[1] + v12 + v56 + ctx->state[5]);
    ctx->state[2] = (uint16_t)(ctx->state[2] + v23 + v34 + ctx->state[3] + ctx->state[0]);
    ctx->state[3] = (uint16_t)(ctx->state[3] + v12 + v45 + ctx->state[7]);
    ctx->state[4] = (uint16_t)(ctx->state[4] + v23);
    ctx->state[5] = (uint16_t)(ctx->state[5] + v12 + v45 + ctx->state[6]);
    ctx->state[6] = (uint16_t)(ctx->state[6] + v23 + v67);
    ctx->state[7] = (uint16_t)(ctx->state[7] + v45);
    ctx->state[0] = (uint16_t)(ctx->state[0] + v34 + v23 + ctx->state[4] + v78);
    ctx->lfsr = (uint16_t)((ctx->lfsr >> 1) ^
                 ((uint16_t)(-(int)(ctx->lfsr & 1u)) & 0xCA44u));
    ctx->state[4] = (uint16_t)(ctx->state[4] + ctx->lfsr);
    return ct;
}

static inline void lane_permutation(uint16_t nu, uint8_t out[16])
{
    uint8_t beta0 = (uint8_t)(nu & 15u);
    uint8_t beta1 = (uint8_t)((nu >> 4) & 15u);
    uint8_t beta2 = (uint8_t)((nu >> 8) & 15u);
    uint8_t beta3 = (uint8_t)((nu >> 12) & 15u);
    for (uint8_t b = 0; b < 16u; ++b) {
        uint8_t v = S2[b ^ beta0];
        v = S2[v ^ beta1];
        v = S2[v ^ beta2];
        v = S2[v ^ beta3];
        out[b] = (uint8_t)(S2[v ^ beta0 ^ beta1] ^ beta2 ^ beta3);
    }
}

static inline uint16_t lane_tuple_from_pair(uint16_t k0, uint16_t k1)
{
    uint16_t key2, key3;
    uint16_t beta0 = (uint16_t)((k0 >> 8) & 15u);
    uint16_t beta1 = (uint16_t)((k1 >> 8) & 15u);
    derive_key23(k0, k1, 8, &key2, &key3);
    return (uint16_t)(beta0 | (uint16_t)(beta1 << 4) |
                      (uint16_t)(((key2 >> 8) & 15u) << 8) |
                      (uint16_t)(((key3 >> 8) & 15u) << 12));
}

static inline size_t collect_word_candidates(uint8_t beta_direct,
                                             uint8_t beta_derived,
                                             int first_word,
                                             uint16_t values[WORDS])
{
    size_t count = 0;
    for (uint32_t x = 0; x < WORDS; ++x) {
        uint16_t key2, key3;
        uint16_t derived;
        derive_key23(first_word ? (uint16_t)x : 0,
                     first_word ? 0 : (uint16_t)x, 8, &key2, &key3);
        derived = first_word ? key2 : key3;
        if (((x >> 8) & 15u) != beta_direct) continue;
        if ((((uint32_t)derived >> 8) & 15u) != beta_derived) continue;
        values[count++] = (uint16_t)x;
    }
    return count;
}

static inline uint32_t edge_multiplicity(const EdgeCount *edges, size_t count,
                                         uint32_t key)
{
    size_t low = 0, high = count;
    while (low < high) {
        size_t middle = low + (high - low) / 2u;
        if (edges[middle].key < key) low = middle + 1u;
        else high = middle;
    }
    return low < count && edges[low].key == key ? edges[low].count : 0u;
}

static inline int uint32_compare(const void *left, const void *right)
{
    uint32_t a = *(const uint32_t *)left;
    uint32_t b = *(const uint32_t *)right;
    return a < b ? -1 : a > b ? 1 : 0;
}

static inline int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static inline int parse_hex_words(const char *text, uint16_t *words,
                                  size_t count)
{
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) text += 2;
    if (strlen(text) != count * 4u) return -1;
    for (size_t i = 0; i < count; ++i) {
        unsigned value = 0;
        for (size_t j = 0; j < 4u; ++j) {
            int digit = hex_value(text[i * 4u + j]);
            if (digit < 0) return -1;
            value = (value << 4) | (unsigned)digit;
        }
        words[i] = (uint16_t)value;
    }
    return 0;
}

static inline unsigned parse_unsigned_arg(const char *name, const char *text,
                                          unsigned minimum,
                                          unsigned maximum)
{
    char *end = NULL;
    unsigned long value;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < minimum ||
        value > maximum) {
        fprintf(stderr, "error: %s must be in [%u,%u]\n",
                name, minimum, maximum);
        exit(EXIT_FAILURE);
    }
    return (unsigned)value;
}

static inline uint64_t parse_u64_arg(const char *name, const char *text)
{
    char *end = NULL;
    uint64_t value;
    errno = 0;
#if defined(_MSC_VER)
    value = _strtoui64(text, &end, 0);
#else
    value = strtoull(text, &end, 0);
#endif
    if (errno != 0 || end == text || *end != '\0') {
        fprintf(stderr, "error: invalid %s\n", name);
        exit(EXIT_FAILURE);
    }
    return value;
}

#if defined(_WIN32)
typedef HANDLE ThreadHandle;
typedef DWORD(WINAPI *ThreadProc)(LPVOID);
#define THREAD_FUNCTION(name) static DWORD WINAPI name(LPVOID opaque)
#define THREAD_FINISH return 0
static inline int start_thread(ThreadHandle *handle, ThreadProc proc, void *arg)
{
    *handle = CreateThread(NULL, 0, proc, arg, 0, NULL);
    return *handle == NULL ? -1 : 0;
}
static inline int join_thread(ThreadHandle handle)
{
    DWORD status = WaitForSingleObject(handle, INFINITE);
    CloseHandle(handle);
    return status == WAIT_OBJECT_0 ? 0 : -1;
}
#else
typedef pthread_t ThreadHandle;
typedef void *(*ThreadProc)(void *);
#define THREAD_FUNCTION(name) static void *name(void *opaque)
#define THREAD_FINISH return NULL
static inline int start_thread(ThreadHandle *handle, ThreadProc proc, void *arg)
{
    return pthread_create(handle, NULL, proc, arg);
}
static inline int join_thread(ThreadHandle handle)
{
    return pthread_join(handle, NULL);
}
#endif

static inline void run_threads(ThreadHandle *handles, unsigned count,
                               ThreadProc proc, void *workers,
                               size_t worker_size)
{
    unsigned started = 0;
    for (; started < count; ++started) {
        void *worker = (unsigned char *)workers +
                       (size_t)started * worker_size;
        if (start_thread(&handles[started], proc, worker) != 0) break;
    }
    if (started != count) {
        for (unsigned i = 0; i < started; ++i)
            (void)join_thread(handles[i]);
        die("thread creation failed");
    }
    for (unsigned i = 0; i < count; ++i)
        if (join_thread(handles[i]) != 0) die("thread join failed");
}

static inline int separ_cipher_self_test(void)
{
    static const uint16_t expected_stream[PROBE_COUNT] = {
        0xEFC8u, 0x5074u, 0xAEE5u, 0x6EC6u, 0xD241u, 0xE0C1u, 0xD7C1u
    };
    static const uint16_t table10_plaintext[8] = {
        0x156Fu, 0x19E1u, 0x8FE6u, 0x2975u,
        0x19A3u, 0x52C4u, 0x5731u, 0x536Au
    };
    static const uint16_t table10_ciphertext[8] = {
        0x41E1u, 0x5D76u, 0x9296u, 0x4947u,
        0x46F6u, 0x38CEu, 0x27FBu, 0x07E9u
    };
    int failed = 0;

    printf("[self-test] checking main.c known-answer vector ... ");
    fflush(stdout);
    {
        static const uint16_t zero_iv[8] = {0};
        SeparCtx ctx;
        initial_state(DEFAULT_KEY, zero_iv, &ctx);
        for (unsigned i = 0; i < PROBE_COUNT; ++i) {
            if (encrypt_word(PROBES[i], &ctx, DEFAULT_KEY) !=
                expected_stream[i]) {
                failed = 1;
                break;
            }
        }
    }
    printf("%s\n", failed ? "FAIL" : "ok");
    if (failed) return 1;

    printf("[self-test] checking published Table 10 vector ... ");
    fflush(stdout);
    {
        static const uint16_t zero_iv[8] = {0};
        SeparCtx ctx;
        initial_state(DEFAULT_KEY, zero_iv, &ctx);
        for (unsigned i = 0; i < 8u; ++i) {
            if (encrypt_word(table10_plaintext[i], &ctx, DEFAULT_KEY) !=
                table10_ciphertext[i]) {
                failed = 1;
                break;
            }
        }
    }
    printf("%s\n", failed ? "FAIL" : "ok");
    if (failed) return 1;

    printf("[self-test] checking ENC_Block/DEC_Block inverses ... ");
    fflush(stdout);
    for (uint32_t x = 0; x < WORDS; ++x) {
        uint16_t y = enc_block((uint16_t)x, DEFAULT_KEY[14],
                               DEFAULT_KEY[15], 8);
        if (dec_block(y, DEFAULT_KEY[14], DEFAULT_KEY[15], 8) !=
            (uint16_t)x) {
            failed = 1;
            break;
        }
    }
    printf("%s\n", failed ? "FAIL" : "ok");
    if (failed) return 1;

    printf("[self-test] checking autonomous-lane formula ... ");
    fflush(stdout);
    {
        uint16_t true_nu = lane_tuple_from_pair(DEFAULT_KEY[14],
                                                DEFAULT_KEY[15]);
        uint8_t permutation[16];
        lane_permutation(true_nu, permutation);
        for (uint32_t x = 0; x < WORDS; ++x) {
            uint16_t y = enc_block((uint16_t)x, DEFAULT_KEY[14],
                                   DEFAULT_KEY[15], 8);
            if (((y >> 8) & 15u) != permutation[(x >> 8) & 15u]) {
                failed = 1;
                break;
            }
        }
    }
    printf("%s\n", failed ? "FAIL" : "ok");
    return failed;
}

#endif
