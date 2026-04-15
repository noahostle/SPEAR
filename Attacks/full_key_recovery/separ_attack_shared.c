#include "separ_attack_shared.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static const uint8_t S1[16] = {1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4};
static const uint8_t S2[16] = {6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8};
static const uint8_t S3[16] = {12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13, 15, 4};
static const uint8_t S4[16] = {13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14};
static const uint8_t IS1[16] = {4, 0, 3, 5, 15, 6, 8, 11, 7, 9, 13, 2, 10, 12, 14, 1};
static const uint8_t IS2[16] = {12, 8, 7, 13, 3, 14, 0, 9, 15, 6, 1, 11, 10, 5, 4, 2};
static const uint8_t IS3[16] = {4, 3, 1, 5, 15, 6, 2, 8, 7, 9, 12, 10, 0, 13, 11, 14};
static const uint8_t IS4[16] = {4, 11, 2, 5, 13, 6, 8, 3, 7, 14, 12, 1, 9, 0, 15, 10};

uint8_t separ_sbox2(uint8_t x)
{
    return S2[x & 0xFu];
}

void fatal(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    exit(1);
}

uint64_t now_ms(void)
{
    return (uint64_t)GetTickCount64();
}

int pair_equal(KeyPair a, KeyPair b)
{
    return a.k0 == b.k0 && a.k1 == b.k1;
}

int pair_cmp(KeyPair a, KeyPair b)
{
    if (a.k0 != b.k0) return (a.k0 < b.k0) ? -1 : 1;
    if (a.k1 != b.k1) return (a.k1 < b.k1) ? -1 : 1;
    return 0;
}

static uint16_t rotl16(uint16_t x, unsigned y)
{
    y &= 15u;
    if (y == 0u) return x;
    return (uint16_t)((x << y) | (x >> (16u - y)));
}

static uint16_t rotr16(uint16_t x, unsigned y)
{
    y &= 15u;
    if (y == 0u) return x;
    return (uint16_t)((x >> y) | (x << (16u - y)));
}

static uint16_t do_sbox(uint16_t x)
{
    return (uint16_t)((S1[(x >> 12) & 0xF] << 12) |
                      (S2[(x >> 8) & 0xF] << 8) |
                      (S3[(x >> 4) & 0xF] << 4) |
                      S4[x & 0xF]);
}

static uint16_t do_isbox(uint16_t x)
{
    return (uint16_t)((IS1[(x >> 12) & 0xF] << 12) |
                      (IS2[(x >> 8) & 0xF] << 8) |
                      (IS3[(x >> 4) & 0xF] << 4) |
                      IS4[x & 0xF]);
}

static uint16_t sep_rotl16(uint16_t x)
{
    uint8_t a = (uint8_t)(x >> 12);
    uint8_t b = (uint8_t)((x >> 8) & 0xF);
    uint8_t c = (uint8_t)((x >> 4) & 0xF);
    uint8_t d = (uint8_t)(x & 0xF);
    a ^= c;
    b ^= d;
    c ^= b;
    d ^= a;
    x = (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
    return (uint16_t)(x ^ rotl16(x, 12) ^ rotl16(x, 8));
}

static uint16_t sep_inrotl16(uint16_t x)
{
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;
    x = (uint16_t)(x ^ rotr16(x, 12) ^ rotr16(x, 8));
    a = (uint8_t)(x >> 12);
    b = (uint8_t)((x >> 8) & 0xF);
    c = (uint8_t)((x >> 4) & 0xF);
    d = (uint8_t)(x & 0xF);
    d ^= a;
    c ^= b;
    b ^= d;
    a ^= c;
    return (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
}

void derive_key23(uint16_t k0, uint16_t k1, uint8_t stage, uint16_t *key2, uint16_t *key3)
{
    uint16_t t2 = rotl16(k0, 6);
    uint16_t t3 = rotl16(k1, 10);
    t2 |= (uint16_t)(S1[(t2 >> 6) & 0xF] << 6);
    t3 |= (uint16_t)(S1[(t3 >> 6) & 0xF] << 6);
    t2 ^= (uint16_t)(stage + 2u);
    t3 ^= (uint16_t)(stage + 3u);
    *key2 = t2;
    *key3 = t3;
}

uint16_t enc_block(uint16_t pt, KeyPair pair, uint8_t stage)
{
    uint16_t key2;
    uint16_t key3;
    uint16_t t;
    derive_key23(pair.k0, pair.k1, stage, &key2, &key3);
    t = (uint16_t)(pt ^ pair.k0);
    t = do_sbox(t);
    t = sep_rotl16(t);
    t ^= pair.k1;
    t = do_sbox(t);
    t = sep_rotl16(t);
    t ^= key2;
    t = do_sbox(t);
    t = sep_rotl16(t);
    t ^= key3;
    t = do_sbox(t);
    t = sep_rotl16(t);
    t ^= (uint16_t)(pair.k0 ^ pair.k1);
    t = do_sbox(t);
    t ^= (uint16_t)(key2 ^ key3);
    return t;
}

uint16_t dec_block(uint16_t ct, KeyPair pair, uint8_t stage)
{
    uint16_t key2;
    uint16_t key3;
    uint16_t t;
    derive_key23(pair.k0, pair.k1, stage, &key2, &key3);
    t = (uint16_t)(ct ^ key2 ^ key3);
    t = do_isbox(t);
    t ^= (uint16_t)(pair.k0 ^ pair.k1);
    t = sep_inrotl16(t);
    t = do_isbox(t);
    t ^= key3;
    t = sep_inrotl16(t);
    t = do_isbox(t);
    t ^= key2;
    t = sep_inrotl16(t);
    t = do_isbox(t);
    t ^= pair.k1;
    t = sep_inrotl16(t);
    t = do_isbox(t);
    t ^= pair.k0;
    return t;
}

KeyPair stage_pair_from_key(const uint16_t key_words[16], uint8_t stage)
{
    KeyPair pair;
    pair.k0 = key_words[(stage - 1u) * 2u];
    pair.k1 = key_words[(stage - 1u) * 2u + 1u];
    return pair;
}

static uint16_t lfsr_step(uint16_t lfsr)
{
    return (uint16_t)((lfsr >> 1) ^ ((uint16_t)(-(int)(lfsr & 1u)) & 0xCA44u));
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

int parse_hex_words(const char *text, uint16_t *out_words, size_t word_count)
{
    const char *p = text;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    if (strlen(p) != word_count * 4u) return -1;
    for (size_t i = 0; i < word_count; i++) {
        int a = hex_value(p[i * 4u + 0u]);
        int b = hex_value(p[i * 4u + 1u]);
        int c = hex_value(p[i * 4u + 2u]);
        int d = hex_value(p[i * 4u + 3u]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        out_words[i] = (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
    }
    return 0;
}

uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

void separ_initial_ctx(const uint16_t key_words[16], const uint16_t iv_words[8], SeparCtx *ctx)
{
    uint16_t ct = 0u;
    memcpy(ctx->state, iv_words, sizeof(ctx->state));
    for (int i = 0; i < 4; i++) {
        uint16_t v12 = enc_block((uint16_t)(ctx->state[0] + ctx->state[2] + ctx->state[4] + ctx->state[6]), stage_pair_from_key(key_words, 1), 1);
        uint16_t v23 = enc_block((uint16_t)(v12 + ctx->state[1]), stage_pair_from_key(key_words, 2), 2);
        uint16_t v34 = enc_block((uint16_t)(v23 + ctx->state[2]), stage_pair_from_key(key_words, 3), 3);
        uint16_t v45 = enc_block((uint16_t)(v34 + ctx->state[3]), stage_pair_from_key(key_words, 4), 4);
        uint16_t v56 = enc_block((uint16_t)(v45 + ctx->state[4]), stage_pair_from_key(key_words, 5), 5);
        uint16_t v67 = enc_block((uint16_t)(v56 + ctx->state[5]), stage_pair_from_key(key_words, 6), 6);
        uint16_t v78 = enc_block((uint16_t)(v67 + ctx->state[6]), stage_pair_from_key(key_words, 7), 7);
        ct = enc_block((uint16_t)(v78 + ctx->state[7]), stage_pair_from_key(key_words, 8), 8);
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

uint16_t separ_encrypt_word_record(uint16_t pt, SeparCtx *ctx, const uint16_t key_words[16], RoundRow *row)
{
    uint16_t before[8];
    uint16_t v12;
    uint16_t v23;
    uint16_t v34;
    uint16_t v45;
    uint16_t v56;
    uint16_t v67;
    uint16_t v78;
    uint16_t ct;
    memcpy(before, ctx->state, sizeof(before));
    v12 = enc_block((uint16_t)(pt + ctx->state[0]), stage_pair_from_key(key_words, 1), 1);
    v23 = enc_block((uint16_t)(v12 + ctx->state[1]), stage_pair_from_key(key_words, 2), 2);
    v34 = enc_block((uint16_t)(v23 + ctx->state[2]), stage_pair_from_key(key_words, 3), 3);
    v45 = enc_block((uint16_t)(v34 + ctx->state[3]), stage_pair_from_key(key_words, 4), 4);
    v56 = enc_block((uint16_t)(v45 + ctx->state[4]), stage_pair_from_key(key_words, 5), 5);
    v67 = enc_block((uint16_t)(v56 + ctx->state[5]), stage_pair_from_key(key_words, 6), 6);
    v78 = enc_block((uint16_t)(v67 + ctx->state[6]), stage_pair_from_key(key_words, 7), 7);
    ct = enc_block((uint16_t)(v78 + ctx->state[7]), stage_pair_from_key(key_words, 8), 8);

    ctx->state[1] = (uint16_t)(ctx->state[1] + v12 + v56 + ctx->state[5]);
    ctx->state[2] = (uint16_t)(ctx->state[2] + v23 + v34 + ctx->state[3] + ctx->state[0]);
    ctx->state[3] = (uint16_t)(ctx->state[3] + v12 + v45 + ctx->state[7]);
    ctx->state[4] = (uint16_t)(ctx->state[4] + v23);
    ctx->state[5] = (uint16_t)(ctx->state[5] + v12 + v45 + ctx->state[6]);
    ctx->state[6] = (uint16_t)(ctx->state[6] + v23 + v67);
    ctx->state[7] = (uint16_t)(ctx->state[7] + v45);
    ctx->state[0] = (uint16_t)(ctx->state[0] + v34 + v23 + ctx->state[4] + v78);
    ctx->lfsr = lfsr_step(ctx->lfsr);
    ctx->state[4] = (uint16_t)(ctx->state[4] + ctx->lfsr);

    row->pt = pt;
    row->ct = ct;
    row->s1 = before[0];
    row->s2 = before[1];
    row->s3 = before[2];
    row->s4 = before[3];
    row->s5 = before[4];
    row->s6 = before[5];
    row->s7 = before[6];
    row->s8 = before[7];
    row->s6n = ctx->state[5];
    row->s7n = ctx->state[6];
    row->s8n = ctx->state[7];
    row->v12 = v12;
    row->v23 = v23;
    row->v45 = v45;
    row->v56 = v56;
    row->v67 = v67;
    row->v78 = v78;
    row->delta2 = (uint16_t)(v12 + v56 + before[5]);
    row->delta4 = (uint16_t)(v12 + ctx->state[7]);
    return ct;
}

uint16_t separ_encrypt_word_simple(uint16_t pt, const SeparCtx *base, const uint16_t key_words[16])
{
    SeparCtx tmp = *base;
    RoundRow row;
    return separ_encrypt_word_record(pt, &tmp, key_words, &row);
}

void ctx_after_prefix(const uint16_t key_words[16], const uint16_t iv_words[8], const uint16_t *prefix_words, size_t prefix_len, SeparCtx *out)
{
    separ_initial_ctx(key_words, iv_words, out);
    for (size_t i = 0; i < prefix_len; i++) {
        RoundRow row;
        (void)separ_encrypt_word_record(prefix_words[i], out, key_words, &row);
    }
}

void next_word_table_from_ctx(const SeparCtx *ctx, const uint16_t key_words[16], uint16_t *table)
{
    for (uint32_t pt = 0u; pt < 0x10000u; pt++) {
        table[pt] = separ_encrypt_word_simple((uint16_t)pt, ctx, key_words);
    }
}

static void invert_table_u16(const uint16_t *table, uint16_t *inv)
{
    for (uint32_t x = 0u; x < 0x10000u; x++) {
        inv[table[x]] = (uint16_t)x;
    }
}

FullContext build_full_context(const uint16_t key_words[16], const uint16_t iv_words[8], const uint16_t *prefix_words, size_t prefix_len)
{
    FullContext out;
    out.table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    out.inv_table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    if (out.table == NULL || out.inv_table == NULL) fatal("context table allocation failed");
    ctx_after_prefix(key_words, iv_words, prefix_words, prefix_len, &out.ctx);
    next_word_table_from_ctx(&out.ctx, key_words, out.table);
    invert_table_u16(out.table, out.inv_table);
    return out;
}

void free_full_context(FullContext *ctx)
{
    if (ctx->table != NULL) free(ctx->table);
    if (ctx->inv_table != NULL) free(ctx->inv_table);
    ctx->table = NULL;
    ctx->inv_table = NULL;
}

unsigned detect_workers(void)
{
    DWORD count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    return count == 0u ? 1u : (unsigned)count;
}

void format_iv_hex(const uint16_t iv_words[8], char out[33])
{
    for (size_t i = 0u; i < 8u; i++) {
        snprintf(out + (i * 4u), 5u, "%04X", iv_words[i]);
    }
    out[32] = '\0';
}

