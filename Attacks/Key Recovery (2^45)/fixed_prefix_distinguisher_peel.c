#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <windows.h>

#define WORD_MASK 0xFFFFu
#define MAX_ROWS 256
#define MAX_PREFIX_WORDS 256
#define MAX_STAGE_CANDIDATES 4096
#define MAX_EXTRA_CONTEXTS 8
#define DEFAULT_EMIT_LIMIT 16

typedef struct {
    uint16_t state[8];
    uint16_t lfsr;
} separ_ctx_t;

typedef struct {
    uint16_t max_count;
    uint32_t sum_count;
    uint16_t signature_count;
    uint8_t signature_rows[MAX_ROWS];
    uint8_t signatures[MAX_ROWS][256];
} branch_profile_t;

typedef struct {
    uint16_t row_count;
    uint8_t row_ids[MAX_ROWS];
    uint16_t words[MAX_ROWS][256];
} row_set_t;

typedef struct {
    uint16_t key0;
    uint16_t key1;
    uint16_t low_byte_count;
    uint8_t low_bytes[256];
} stage_search_winner_t;

typedef struct {
    stage_search_winner_t *items;
    size_t count;
    size_t capacity;
} winner_array_t;

typedef struct {
    uint8_t stage_n;
    uint16_t selected_row_count;
    uint8_t selected_rows[MAX_ROWS];
    branch_profile_t baseline_profile;
    branch_profile_t best_profile;
    uint64_t candidate_pairs_scanned;
    winner_array_t winners;
} stage_search_result_t;

typedef struct {
    branch_profile_t profile;
    uint16_t low_byte_count;
    uint8_t low_bytes[256];
    uint16_t row_count;
    uint8_t rows[256];
} low_byte_refinement_t;

typedef struct {
    uint8_t stage_n;
    uint16_t key0;
    uint16_t key1;
    uint16_t state_word;
    uint16_t selected_row_count;
    uint8_t selected_rows[MAX_ROWS];
    uint16_t low_row_count;
    uint8_t low_rows[256];
    uint16_t baseline_max_count;
    uint32_t baseline_sum_count;
    uint16_t winning_max_count;
    uint32_t winning_sum_count;
} stage_peel_t;

typedef struct {
    uint16_t key_words[16];
    uint16_t state_words[8];
    uint8_t peel_count;
    stage_peel_t peels[8];
} recovery_candidate_t;

typedef struct {
    recovery_candidate_t *items;
    size_t count;
    size_t capacity;
} recovery_array_t;

typedef struct {
    uint64_t ids[MAX_STAGE_CANDIDATES];
    size_t count;
} stage_candidate_list_t;

typedef struct {
    uint16_t prefix[MAX_PREFIX_WORDS];
    size_t prefix_count;
    uint16_t iv[8];
} extra_context_t;

typedef struct {
    int threads;
    int hot_rows;
    int emit_limit;
    int stop_after_first;
    int demo_decoys;
    int show_all_winners;
    int start_stage;
    int injected_peel;
    uint16_t injected_key0;
    uint16_t injected_key1;
    uint16_t injected_state_word;
    uint64_t candidate_start;
    uint64_t candidate_count;
    uint16_t key[16];
    uint16_t iv[8];
    uint16_t prefix[MAX_PREFIX_WORDS];
    size_t prefix_count;
    stage_candidate_list_t stage_candidates[9];
    extra_context_t extra_contexts[MAX_EXTRA_CONTEXTS];
    size_t extra_context_count;
} cli_config_t;

typedef enum {
    CANDIDATE_SOURCE_RANGE = 0,
    CANDIDATE_SOURCE_LIST = 1
} candidate_source_kind_t;

typedef struct {
    candidate_source_kind_t kind;
    uint64_t start;
    uint64_t count;
    const uint64_t *list_ids;
    size_t list_count;
} candidate_source_t;

typedef struct {
    const row_set_t *baseline_rows;
    uint8_t stage_n;
    candidate_source_t source;
    uint64_t work_start;
    uint64_t work_count;
    winner_array_t winners;
    branch_profile_t best_profile;
    int best_profile_set;
    uint64_t scanned;
} scan_worker_t;

static const uint16_t default_key[16] = {
    0xE8B9, 0xB733, 0xDA5D, 0x96D7, 0x02DD, 0x3972, 0xE953, 0x07FD,
    0x50C5, 0x12DB, 0xF44A, 0x233E, 0x8D1E, 0x9DF5, 0xFC7D, 0x6371
};

static const uint16_t default_iv[8] = {
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
};

static const uint8_t s1[16] = {1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4};
static const uint8_t s2[16] = {6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8};
static const uint8_t s3[16] = {12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13, 15, 4};
static const uint8_t s4[16] = {13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14};

static const uint8_t is1[16] = {4, 0, 3, 5, 15, 6, 8, 11, 7, 9, 13, 2, 10, 12, 14, 1};
static const uint8_t is2[16] = {12, 8, 7, 13, 3, 14, 0, 9, 15, 6, 1, 11, 10, 5, 4, 2};
static const uint8_t is3[16] = {4, 3, 1, 5, 15, 6, 2, 8, 7, 9, 12, 10, 0, 13, 11, 14};
static const uint8_t is4[16] = {4, 11, 2, 5, 13, 6, 8, 3, 7, 14, 12, 1, 9, 0, 15, 10};

static inline uint16_t u16(uint32_t value)
{
    return (uint16_t)(value & WORD_MASK);
}

static inline uint16_t rotl16(uint16_t x, unsigned int y)
{
    y &= 15u;
    return (uint16_t)(((x << y) | (x >> (16u - y))) & WORD_MASK);
}

static inline uint16_t rotr16(uint16_t x, unsigned int y)
{
    y &= 15u;
    return (uint16_t)(((x >> y) | (x << (16u - y))) & WORD_MASK);
}

static inline uint16_t do_sbox(uint16_t x)
{
    uint8_t a = (uint8_t)(x >> 12);
    uint8_t b = (uint8_t)((x >> 8) & 0xF);
    uint8_t c = (uint8_t)((x >> 4) & 0xF);
    uint8_t d = (uint8_t)(x & 0xF);
    return (uint16_t)((s1[a] << 12) | (s2[b] << 8) | (s3[c] << 4) | s4[d]);
}

static inline uint16_t do_isbox(uint16_t x)
{
    uint8_t a = (uint8_t)(x >> 12);
    uint8_t b = (uint8_t)((x >> 8) & 0xF);
    uint8_t c = (uint8_t)((x >> 4) & 0xF);
    uint8_t d = (uint8_t)(x & 0xF);
    return (uint16_t)((is1[a] << 12) | (is2[b] << 8) | (is3[c] << 4) | is4[d]);
}

static inline uint16_t sep_rotl16(uint16_t x)
{
    uint8_t a = (uint8_t)(x >> 12);
    uint8_t b = (uint8_t)((x >> 8) & 0xF);
    uint8_t c = (uint8_t)((x >> 4) & 0xF);
    uint8_t d = (uint8_t)(x & 0xF);
    uint16_t y;
    uint16_t z;

    a = (uint8_t)(a ^ c);
    b = (uint8_t)(b ^ d);
    c = (uint8_t)(c ^ b);
    d = (uint8_t)(d ^ a);

    x = (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
    y = rotl16(x, 12);
    z = rotl16(x, 8);
    return u16((uint32_t)x ^ y ^ z);
}

static inline uint16_t sep_inrotl16(uint16_t x)
{
    uint16_t y = rotr16(x, 12);
    uint16_t z = rotr16(x, 8);
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;

    x = u16((uint32_t)x ^ y ^ z);
    a = (uint8_t)(x >> 12);
    b = (uint8_t)((x >> 8) & 0xF);
    c = (uint8_t)((x >> 4) & 0xF);
    d = (uint8_t)(x & 0xF);

    d = (uint8_t)(d ^ a);
    c = (uint8_t)(c ^ b);
    b = (uint8_t)(b ^ d);
    a = (uint8_t)(a ^ c);

    return (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
}

static inline void derive_key23(uint16_t key0, uint16_t key1, uint8_t stage_n, uint16_t *key2, uint16_t *key3)
{
    uint16_t t2 = rotl16(key0, 6);
    uint16_t t3 = rotl16(key1, 10);
    uint8_t b;

    b = (uint8_t)((t2 >> 6) & 0xF);
    t2 |= (uint16_t)(s1[b] << 6);
    t2 = u16((uint32_t)t2 ^ (uint32_t)(stage_n + 2u));

    b = (uint8_t)((t3 >> 6) & 0xF);
    t3 |= (uint16_t)(s1[b] << 6);
    t3 = u16((uint32_t)t3 ^ (uint32_t)(stage_n + 3u));

    *key2 = t2;
    *key3 = t3;
}

static inline uint16_t enc_block(uint16_t pt, uint16_t key0, uint16_t key1, uint8_t stage_n)
{
    uint16_t key2;
    uint16_t key3;
    uint16_t t;

    derive_key23(key0, key1, stage_n, &key2, &key3);
    t = u16((uint32_t)pt ^ key0);
    t = do_sbox(t);
    t = sep_rotl16(t);

    t = u16((uint32_t)t ^ key1);
    t = do_sbox(t);
    t = sep_rotl16(t);

    t = u16((uint32_t)t ^ key2);
    t = do_sbox(t);
    t = sep_rotl16(t);

    t = u16((uint32_t)t ^ key3);
    t = do_sbox(t);
    t = sep_rotl16(t);

    t = u16((uint32_t)t ^ key0 ^ key1);
    t = do_sbox(t);
    t = u16((uint32_t)t ^ key2 ^ key3);
    return t;
}

static inline uint16_t dec_block(uint16_t ct, uint16_t key0, uint16_t key1, uint8_t stage_n)
{
    uint16_t key2;
    uint16_t key3;
    uint16_t t;

    derive_key23(key0, key1, stage_n, &key2, &key3);
    t = u16((uint32_t)ct ^ key2 ^ key3);
    t = do_isbox(t);
    t = u16((uint32_t)t ^ key0 ^ key1);

    t = sep_inrotl16(t);
    t = do_isbox(t);
    t = u16((uint32_t)t ^ key3);

    t = sep_inrotl16(t);
    t = do_isbox(t);
    t = u16((uint32_t)t ^ key2);

    t = sep_inrotl16(t);
    t = do_isbox(t);
    t = u16((uint32_t)t ^ key1);

    t = sep_inrotl16(t);
    t = do_isbox(t);
    t = u16((uint32_t)t ^ key0);
    return t;
}

static void separ_initial_state(separ_ctx_t *ctx, const uint16_t key[16], const uint16_t iv[8])
{
    int i;
    uint16_t v12 = 0;
    uint16_t v23 = 0;
    uint16_t v34 = 0;
    uint16_t v45 = 0;
    uint16_t v56 = 0;
    uint16_t v67 = 0;
    uint16_t v78 = 0;
    uint16_t ct = 0;

    memcpy(ctx->state, iv, sizeof(ctx->state));
    for (i = 0; i < 4; i++) {
        v12 = enc_block(u16((uint32_t)ctx->state[0] + ctx->state[2] + ctx->state[4] + ctx->state[6]), key[0], key[1], 1);
        v23 = enc_block(u16((uint32_t)v12 + ctx->state[1]), key[2], key[3], 2);
        v34 = enc_block(u16((uint32_t)v23 + ctx->state[2]), key[4], key[5], 3);
        v45 = enc_block(u16((uint32_t)v34 + ctx->state[3]), key[6], key[7], 4);
        v56 = enc_block(u16((uint32_t)v45 + ctx->state[4]), key[8], key[9], 5);
        v67 = enc_block(u16((uint32_t)v56 + ctx->state[5]), key[10], key[11], 6);
        v78 = enc_block(u16((uint32_t)v67 + ctx->state[6]), key[12], key[13], 7);
        ct = enc_block(u16((uint32_t)v78 + ctx->state[7]), key[14], key[15], 8);

        ctx->state[0] = u16((uint32_t)ctx->state[0] + ct);
        ctx->state[1] = u16((uint32_t)ctx->state[1] + v12);
        ctx->state[2] = u16((uint32_t)ctx->state[2] + v23);
        ctx->state[3] = u16((uint32_t)ctx->state[3] + v34);
        ctx->state[4] = u16((uint32_t)ctx->state[4] + v45);
        ctx->state[5] = u16((uint32_t)ctx->state[5] + v56);
        ctx->state[6] = u16((uint32_t)ctx->state[6] + v67);
        ctx->state[7] = u16((uint32_t)ctx->state[7] + v78);
    }
    ctx->lfsr = u16((uint32_t)ct | 0x100u);
}

static uint16_t separ_encrypt_word(uint16_t pt, separ_ctx_t *ctx, const uint16_t key[16])
{
    uint16_t v12;
    uint16_t v23;
    uint16_t v34;
    uint16_t v45;
    uint16_t v56;
    uint16_t v67;
    uint16_t v78;
    uint16_t ct;

    v12 = enc_block(u16((uint32_t)pt + ctx->state[0]), key[0], key[1], 1);
    v23 = enc_block(u16((uint32_t)v12 + ctx->state[1]), key[2], key[3], 2);
    v34 = enc_block(u16((uint32_t)v23 + ctx->state[2]), key[4], key[5], 3);
    v45 = enc_block(u16((uint32_t)v34 + ctx->state[3]), key[6], key[7], 4);
    v56 = enc_block(u16((uint32_t)v45 + ctx->state[4]), key[8], key[9], 5);
    v67 = enc_block(u16((uint32_t)v56 + ctx->state[5]), key[10], key[11], 6);
    v78 = enc_block(u16((uint32_t)v67 + ctx->state[6]), key[12], key[13], 7);
    ct = enc_block(u16((uint32_t)v78 + ctx->state[7]), key[14], key[15], 8);

    ctx->state[1] = u16((uint32_t)ctx->state[1] + v12 + v56 + ctx->state[5]);
    ctx->state[2] = u16((uint32_t)ctx->state[2] + v23 + v34 + ctx->state[3] + ctx->state[0]);
    ctx->state[3] = u16((uint32_t)ctx->state[3] + v12 + v45 + ctx->state[7]);
    ctx->state[4] = u16((uint32_t)ctx->state[4] + v23);
    ctx->state[5] = u16((uint32_t)ctx->state[5] + v12 + v45 + ctx->state[6]);
    ctx->state[6] = u16((uint32_t)ctx->state[6] + v23 + v67);
    ctx->state[7] = u16((uint32_t)ctx->state[7] + v45);
    ctx->state[0] = u16((uint32_t)ctx->state[0] + v34 + v23 + ctx->state[4] + v78);
    ctx->lfsr = u16((ctx->lfsr >> 1) ^ (uint16_t)(-(int32_t)(ctx->lfsr & 1u) & 0xCA44u));
    ctx->state[4] = u16((uint32_t)ctx->state[4] + ctx->lfsr);
    return ct;
}

static void separ_ctx_after_prefix(const uint16_t *prefix, size_t prefix_count, const uint16_t key[16], const uint16_t iv[8], separ_ctx_t *ctx)
{
    size_t i;
    separ_initial_state(ctx, key, iv);
    for (i = 0; i < prefix_count; i++) {
        (void)separ_encrypt_word(prefix[i], ctx, key);
    }
}

static void build_matched_context_codebook(const uint16_t *prefix, size_t prefix_count, const uint16_t key[16], const uint16_t iv[8], uint16_t *table)
{
    separ_ctx_t base;
    uint32_t x;
    separ_ctx_after_prefix(prefix, prefix_count, key, iv, &base);
    for (x = 0; x < 0x10000u; x++) {
        separ_ctx_t ctx = base;
        table[x] = separ_encrypt_word((uint16_t)x, &ctx, key);
    }
}

static int hex_nibble(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static const char *skip_hex_prefix(const char *text)
{
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        return text + 2;
    }
    return text;
}

static int parse_u64_auto(const char *text, uint64_t *value_out)
{
    char *end = NULL;
    unsigned long long parsed;
    if (text == NULL || *text == '\0') {
        return 0;
    }
    parsed = strtoull(text, &end, 0);
    if (end == text || *end != '\0') {
        return 0;
    }
    *value_out = (uint64_t)parsed;
    return 1;
}

static int parse_hex_word(const char *text, uint16_t *word_out)
{
    const char *hex = skip_hex_prefix(text);
    char *end = NULL;
    unsigned long value;
    if (hex == NULL || *hex == '\0') {
        return 0;
    }
    value = strtoul(hex, &end, 16);
    if (end == hex || *end != '\0') {
        return 0;
    }
    *word_out = (uint16_t)(value & WORD_MASK);
    return 1;
}

static int parse_word_list(const char *text, uint16_t *words_out, size_t max_words, size_t *count_out)
{
    char *copy;
    char *token;
    char *context = NULL;
    size_t count = 0;

    if (text == NULL || *text == '\0') {
        *count_out = 0;
        return 1;
    }

    copy = _strdup(text);
    if (copy == NULL) {
        return 0;
    }

    token = strtok_s(copy, ",", &context);
    while (token != NULL) {
        uint16_t word;
        if (count >= max_words || !parse_hex_word(token, &word)) {
            free(copy);
            return 0;
        }
        words_out[count++] = word;
        token = strtok_s(NULL, ",", &context);
    }

    free(copy);
    *count_out = count;
    return 1;
}

static int parse_full_hex_words(const char *text, uint16_t *words_out, size_t expected_words)
{
    const char *hex = skip_hex_prefix(text);
    size_t hex_len = strlen(hex);
    size_t i;

    if (hex_len != expected_words * 4u) {
        return 0;
    }
    for (i = 0; i < expected_words; i++) {
        int n0 = hex_nibble(hex[i * 4u + 0u]);
        int n1 = hex_nibble(hex[i * 4u + 1u]);
        int n2 = hex_nibble(hex[i * 4u + 2u]);
        int n3 = hex_nibble(hex[i * 4u + 3u]);
        if (n0 < 0 || n1 < 0 || n2 < 0 || n3 < 0) {
            return 0;
        }
        words_out[i] = (uint16_t)((n0 << 12) | (n1 << 8) | (n2 << 4) | n3);
    }
    return 1;
}

static int parse_context_spec(const char *text, extra_context_t *out)
{
    const char *at = strchr(text, '@');
    size_t prefix_len;
    char prefix_buf[4096];

    if (at == NULL) {
        return 0;
    }
    prefix_len = (size_t)(at - text);
    if (prefix_len >= sizeof(prefix_buf)) {
        return 0;
    }
    memcpy(prefix_buf, text, prefix_len);
    prefix_buf[prefix_len] = '\0';

    if (!parse_word_list(prefix_buf, out->prefix, MAX_PREFIX_WORDS, &out->prefix_count)) {
        return 0;
    }
    if (!parse_full_hex_words(at + 1, out->iv, 8)) {
        return 0;
    }
    return 1;
}

static int parse_stage_candidate_spec(const char *text, int *stage_out, uint64_t *id_out)
{
    const char *colon = strchr(text, ':');
    const char *comma;
    char stage_buf[32];
    char key0_buf[32];
    char key1_buf[32];
    size_t left_len;
    size_t key0_len;
    uint16_t key0;
    uint16_t key1;
    uint64_t stage_value;

    if (colon == NULL) {
        return 0;
    }
    comma = strchr(colon + 1, ',');
    if (comma == NULL) {
        return 0;
    }

    left_len = (size_t)(colon - text);
    key0_len = (size_t)(comma - (colon + 1));
    if (left_len >= sizeof(stage_buf) || key0_len >= sizeof(key0_buf) || strlen(comma + 1) >= sizeof(key1_buf)) {
        return 0;
    }

    memcpy(stage_buf, text, left_len);
    stage_buf[left_len] = '\0';
    memcpy(key0_buf, colon + 1, key0_len);
    key0_buf[key0_len] = '\0';
    strcpy_s(key1_buf, sizeof(key1_buf), comma + 1);

    if (!parse_u64_auto(stage_buf, &stage_value)) {
        return 0;
    }
    if (stage_value < 1u || stage_value > 8u) {
        return 0;
    }
    if (!parse_hex_word(key0_buf, &key0) || !parse_hex_word(key1_buf, &key1)) {
        return 0;
    }

    *stage_out = (int)stage_value;
    *id_out = (((uint64_t)key0) << 16) | key1;
    return 1;
}

static int parse_key_pair_text(const char *text, uint16_t *key0_out, uint16_t *key1_out)
{
    uint16_t words[2];
    size_t count = 0;
    if (!parse_word_list(text, words, 2, &count) || count != 2) {
        return 0;
    }
    *key0_out = words[0];
    *key1_out = words[1];
    return 1;
}

static void init_default_config(cli_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->threads = 16;
    cfg->hot_rows = 1;
    cfg->emit_limit = DEFAULT_EMIT_LIMIT;
    cfg->demo_decoys = 1;
    cfg->show_all_winners = 0;
    cfg->start_stage = 8;
    cfg->injected_peel = 0;
    cfg->injected_key0 = 0;
    cfg->injected_key1 = 0;
    cfg->injected_state_word = 0;
    cfg->candidate_start = 0;
    cfg->candidate_count = UINT64_C(1) << 32;
    cfg->prefix[0] = 0x2028;
    cfg->prefix_count = 1;
    memcpy(cfg->key, default_key, sizeof(cfg->key));
    memcpy(cfg->iv, default_iv, sizeof(cfg->iv));
}

static void print_usage(const char *program_name)
{
    fprintf(stderr, "Usage: %s <demo-full|attack-full> [options]\n", program_name);
    fprintf(stderr, "  Common options:\n");
    fprintf(stderr, "    --threads N\n");
    fprintf(stderr, "    --hot-rows N\n");
    fprintf(stderr, "    --prefix WORDS\n");
    fprintf(stderr, "    --key 64HEX\n");
    fprintf(stderr, "    --iv 32HEX\n");
    fprintf(stderr, "    --stage-candidate stage:key0,key1\n");
    fprintf(stderr, "    --extra-context prefix_words@iv_hex\n");
    fprintf(stderr, "    --demo-decoys N\n");
    fprintf(stderr, "    --show-all-winners\n");
    fprintf(stderr, "    --stop-after-first\n");
    fprintf(stderr, "    --start-stage N\n");
    fprintf(stderr, "    --inject-key key0,key1\n");
    fprintf(stderr, "    --inject-state WORD\n");
}

static int parse_cli(int argc, char **argv, cli_config_t *cfg)
{
    int i;
    init_default_config(cfg);
    for (i = 2; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "--threads") == 0) {
            uint64_t value;
            if (++i >= argc || !parse_u64_auto(argv[i], &value) || value == 0 || value > 64) {
                return 0;
            }
            cfg->threads = (int)value;
        } else if (strcmp(arg, "--hot-rows") == 0) {
            uint64_t value;
            if (++i >= argc || !parse_u64_auto(argv[i], &value) || value == 0 || value > 256) {
                return 0;
            }
            cfg->hot_rows = (int)value;
        } else if (strcmp(arg, "--prefix") == 0) {
            if (++i >= argc || !parse_word_list(argv[i], cfg->prefix, MAX_PREFIX_WORDS, &cfg->prefix_count)) {
                return 0;
            }
        } else if (strcmp(arg, "--key") == 0) {
            if (++i >= argc || !parse_full_hex_words(argv[i], cfg->key, 16)) {
                return 0;
            }
        } else if (strcmp(arg, "--iv") == 0) {
            if (++i >= argc || !parse_full_hex_words(argv[i], cfg->iv, 8)) {
                return 0;
            }
        } else if (strcmp(arg, "--demo-decoys") == 0) {
            uint64_t value;
            if (++i >= argc || !parse_u64_auto(argv[i], &value) || value > 1024) {
                return 0;
            }
            cfg->demo_decoys = (int)value;
        } else if (strcmp(arg, "--show-all-winners") == 0) {
            cfg->show_all_winners = 1;
        } else if (strcmp(arg, "--stop-after-first") == 0) {
            cfg->stop_after_first = 1;
        } else if (strcmp(arg, "--start-stage") == 0) {
            uint64_t value;
            if (++i >= argc || !parse_u64_auto(argv[i], &value) || value < 1 || value > 8) {
                return 0;
            }
            cfg->start_stage = (int)value;
        } else if (strcmp(arg, "--inject-key") == 0) {
            if (++i >= argc || !parse_key_pair_text(argv[i], &cfg->injected_key0, &cfg->injected_key1)) {
                return 0;
            }
            cfg->injected_peel = 1;
        } else if (strcmp(arg, "--inject-state") == 0) {
            if (++i >= argc || !parse_hex_word(argv[i], &cfg->injected_state_word)) {
                return 0;
            }
            cfg->injected_peel = 1;
        } else if (strcmp(arg, "--stage-candidate") == 0) {
            int stage_n;
            uint64_t candidate_id;
            stage_candidate_list_t *list;
            if (++i >= argc || !parse_stage_candidate_spec(argv[i], &stage_n, &candidate_id)) {
                return 0;
            }
            list = &cfg->stage_candidates[stage_n];
            if (list->count >= MAX_STAGE_CANDIDATES) {
                return 0;
            }
            list->ids[list->count++] = candidate_id;
        } else if (strcmp(arg, "--extra-context") == 0) {
            if (++i >= argc || cfg->extra_context_count >= MAX_EXTRA_CONTEXTS) {
                return 0;
            }
            if (!parse_context_spec(argv[i], &cfg->extra_contexts[cfg->extra_context_count])) {
                return 0;
            }
            cfg->extra_context_count++;
        } else {
            return 0;
        }
    }
    return 1;
}

static void winner_array_init(winner_array_t *array)
{
    memset(array, 0, sizeof(*array));
}

static void winner_array_free(winner_array_t *array)
{
    free(array->items);
    array->items = NULL;
    array->count = 0;
    array->capacity = 0;
}

static int winner_array_reserve(winner_array_t *array, size_t capacity)
{
    stage_search_winner_t *items;
    if (capacity <= array->capacity) {
        return 1;
    }
    items = (stage_search_winner_t *)realloc(array->items, capacity * sizeof(*items));
    if (items == NULL) {
        return 0;
    }
    array->items = items;
    array->capacity = capacity;
    return 1;
}

static int winner_array_push(winner_array_t *array, const stage_search_winner_t *item)
{
    size_t capacity;
    if (array->count == array->capacity) {
        capacity = (array->capacity == 0) ? 8 : array->capacity * 2;
        if (!winner_array_reserve(array, capacity)) {
            return 0;
        }
    }
    array->items[array->count++] = *item;
    return 1;
}

static void winner_array_clear(winner_array_t *array)
{
    array->count = 0;
}

static void recovery_array_init(recovery_array_t *array)
{
    memset(array, 0, sizeof(*array));
}

static void recovery_array_free(recovery_array_t *array)
{
    free(array->items);
    array->items = NULL;
    array->count = 0;
    array->capacity = 0;
}

static int recovery_array_push(recovery_array_t *array, const recovery_candidate_t *item)
{
    recovery_candidate_t *items;
    size_t capacity;
    if (array->count == array->capacity) {
        capacity = (array->capacity == 0) ? 4 : array->capacity * 2;
        items = (recovery_candidate_t *)realloc(array->items, capacity * sizeof(*items));
        if (items == NULL) {
            return 0;
        }
        array->items = items;
        array->capacity = capacity;
    }
    array->items[array->count++] = *item;
    return 1;
}

static int branch_profile_cmp(const branch_profile_t *lhs, const branch_profile_t *rhs)
{
    uint16_t min_count;
    uint16_t i;

    if (lhs->max_count != rhs->max_count) {
        return (lhs->max_count < rhs->max_count) ? -1 : 1;
    }
    if (lhs->sum_count != rhs->sum_count) {
        return (lhs->sum_count < rhs->sum_count) ? -1 : 1;
    }

    min_count = (lhs->signature_count < rhs->signature_count) ? lhs->signature_count : rhs->signature_count;
    for (i = 0; i < min_count; i++) {
        int cmp;
        if (lhs->signature_rows[i] != rhs->signature_rows[i]) {
            return (lhs->signature_rows[i] < rhs->signature_rows[i]) ? -1 : 1;
        }
        cmp = memcmp(lhs->signatures[i], rhs->signatures[i], 256);
        if (cmp != 0) {
            return (cmp < 0) ? -1 : 1;
        }
    }

    if (lhs->signature_count != rhs->signature_count) {
        return (lhs->signature_count < rhs->signature_count) ? -1 : 1;
    }
    return 0;
}

static void branch_profile_copy(branch_profile_t *dst, const branch_profile_t *src)
{
    memcpy(dst, src, sizeof(*dst));
}

static int branch_profile_is_strict_improvement(const branch_profile_t *best, const branch_profile_t *baseline)
{
    return branch_profile_cmp(best, baseline) < 0;
}

static void compute_branch_profile_shifted(const row_set_t *rows, uint16_t subtract_amount, branch_profile_t *out)
{
    uint16_t counts[MAX_ROWS];
    uint8_t row_signatures[MAX_ROWS][256];
    uint16_t row_index;
    uint16_t max_count = 0;
    uint32_t sum_count = 0;
    uint16_t signature_index = 0;

    memset(counts, 0, sizeof(counts));
    memset(out, 0, sizeof(*out));

    for (row_index = 0; row_index < rows->row_count; row_index++) {
        uint8_t label_by_value[256];
        uint8_t next_label = 0;
        uint16_t lo;
        memset(label_by_value, 0xFF, sizeof(label_by_value));
        for (lo = 0; lo < 256; lo++) {
            uint8_t upper = (uint8_t)(u16((uint32_t)rows->words[row_index][lo] - subtract_amount) >> 8);
            uint8_t label = label_by_value[upper];
            if (label == 0xFFu) {
                label = next_label++;
                label_by_value[upper] = label;
            }
            row_signatures[row_index][lo] = label;
        }
        counts[row_index] = next_label;
        sum_count += next_label;
        if (next_label > max_count) {
            max_count = next_label;
        }
    }

    out->max_count = max_count;
    out->sum_count = sum_count;

    for (row_index = 0; row_index < 256; row_index++) {
        uint16_t candidate;
        for (candidate = 0; candidate < rows->row_count; candidate++) {
            if (rows->row_ids[candidate] == row_index && counts[candidate] == max_count) {
                out->signature_rows[signature_index] = (uint8_t)row_index;
                memcpy(out->signatures[signature_index], row_signatures[candidate], 256);
                signature_index++;
            }
        }
    }
    out->signature_count = signature_index;
}

static uint16_t compute_shifted_row_signature(const uint16_t row[256], uint16_t subtract_amount, uint8_t signature[256])
{
    uint8_t label_by_value[256];
    uint8_t next_label = 0;
    uint16_t lo;
    memset(label_by_value, 0xFF, sizeof(label_by_value));
    for (lo = 0; lo < 256; lo++) {
        uint8_t upper = (uint8_t)(u16((uint32_t)row[lo] - subtract_amount) >> 8);
        uint8_t label = label_by_value[upper];
        if (label == 0xFFu) {
            label = next_label++;
            label_by_value[upper] = label;
        }
        signature[lo] = label;
    }
    return next_label;
}

static void best_low_byte_candidates_one_row(const uint16_t row[256], uint8_t row_id, branch_profile_t *best_profile, uint8_t low_bytes[256], uint16_t *low_byte_count)
{
    uint8_t best_signature[256];
    uint16_t best_count = 0xFFFFu;
    int best_set = 0;
    uint16_t q;
    *low_byte_count = 0;

    for (q = 0; q < 256; q++) {
        uint8_t signature[256];
        uint16_t count = compute_shifted_row_signature(row, (uint16_t)q, signature);
        if (!best_set || count < best_count) {
            best_count = count;
            memcpy(best_signature, signature, sizeof(best_signature));
            low_bytes[0] = (uint8_t)q;
            *low_byte_count = 1;
            best_set = 1;
        } else if (count == best_count) {
            int cmp = memcmp(signature, best_signature, sizeof(best_signature));
            if (cmp < 0) {
                memcpy(best_signature, signature, sizeof(best_signature));
                low_bytes[0] = (uint8_t)q;
                *low_byte_count = 1;
            } else if (cmp == 0) {
                low_bytes[*low_byte_count] = (uint8_t)q;
                (*low_byte_count)++;
            }
        }
    }

    memset(best_profile, 0, sizeof(*best_profile));
    best_profile->max_count = best_count;
    best_profile->sum_count = best_count;
    best_profile->signature_count = 1;
    best_profile->signature_rows[0] = row_id;
    memcpy(best_profile->signatures[0], best_signature, sizeof(best_signature));
}

static void compute_row_branch_counts(const uint16_t *table, uint16_t counts[256])
{
    uint16_t row;
    for (row = 0; row < 256; row++) {
        uint8_t seen[256] = {0};
        uint16_t base = (uint16_t)(row << 8);
        uint16_t lo;
        uint16_t distinct = 0;
        for (lo = 0; lo < 256; lo++) {
            uint8_t upper = (uint8_t)(table[base | lo] >> 8);
            if (!seen[upper]) {
                seen[upper] = 1;
                distinct++;
            }
        }
        counts[row] = distinct;
    }
}

static void ordered_branch_rows(const uint16_t *table, uint8_t rows_out[256])
{
    uint16_t counts[256];
    uint16_t i;
    uint16_t j;
    compute_row_branch_counts(table, counts);
    for (i = 0; i < 256; i++) {
        rows_out[i] = (uint8_t)i;
    }
    for (i = 0; i < 255; i++) {
        for (j = (uint16_t)(i + 1); j < 256; j++) {
            uint8_t ri = rows_out[i];
            uint8_t rj = rows_out[j];
            if (counts[rj] > counts[ri] || (counts[rj] == counts[ri] && rj < ri)) {
                uint8_t tmp = rows_out[i];
                rows_out[i] = rows_out[j];
                rows_out[j] = tmp;
            }
        }
    }
}

static void extract_rows_from_table(const uint16_t *table, const uint8_t *row_ids, uint16_t row_count, row_set_t *out)
{
    uint16_t i;
    memset(out, 0, sizeof(*out));
    out->row_count = row_count;
    for (i = 0; i < row_count; i++) {
        uint16_t lo;
        uint16_t base = (uint16_t)(row_ids[i] << 8);
        out->row_ids[i] = row_ids[i];
        for (lo = 0; lo < 256; lo++) {
            out->words[i][lo] = table[base | lo];
        }
    }
}

static void select_hot_rows(const uint16_t *table, uint16_t limit, uint8_t *rows_out)
{
    uint8_t ordered[256];
    uint16_t i;
    ordered_branch_rows(table, ordered);
    for (i = 0; i < limit; i++) {
        rows_out[i] = ordered[i];
    }
}

static void apply_dec_block_rows(const row_set_t *in_rows, uint16_t key0, uint16_t key1, uint8_t stage_n, row_set_t *out_rows)
{
    uint16_t row_index;
    out_rows->row_count = in_rows->row_count;
    memcpy(out_rows->row_ids, in_rows->row_ids, in_rows->row_count);
    for (row_index = 0; row_index < in_rows->row_count; row_index++) {
        uint16_t lo;
        for (lo = 0; lo < 256; lo++) {
            out_rows->words[row_index][lo] = dec_block(in_rows->words[row_index][lo], key0, key1, stage_n);
        }
    }
}

static void best_low_byte_candidates(const row_set_t *decoded_rows, branch_profile_t *best_profile, uint8_t low_bytes[256], uint16_t *low_byte_count)
{
    int best_set = 0;
    uint16_t q;
    if (decoded_rows->row_count == 1) {
        best_low_byte_candidates_one_row(decoded_rows->words[0], decoded_rows->row_ids[0], best_profile, low_bytes, low_byte_count);
        return;
    }
    *low_byte_count = 0;
    for (q = 0; q < 256; q++) {
        branch_profile_t candidate;
        compute_branch_profile_shifted(decoded_rows, (uint16_t)q, &candidate);
        if (!best_set || branch_profile_cmp(&candidate, best_profile) < 0) {
            branch_profile_copy(best_profile, &candidate);
            low_bytes[0] = (uint8_t)q;
            *low_byte_count = 1;
            best_set = 1;
        } else if (branch_profile_cmp(&candidate, best_profile) == 0) {
            low_bytes[*low_byte_count] = (uint8_t)q;
            (*low_byte_count)++;
        }
    }
}

static void refine_low_byte_candidates(const uint16_t *table, uint16_t key0, uint16_t key1, uint8_t stage_n, low_byte_refinement_t *out)
{
    static const uint16_t row_schedule[] = {1, 2, 4, 8, 16, 32, 64, 128, 256};
    uint8_t ordered[256];
    size_t schedule_index;
    memset(out, 0, sizeof(*out));
    ordered_branch_rows(table, ordered);
    for (schedule_index = 0; schedule_index < sizeof(row_schedule) / sizeof(row_schedule[0]); schedule_index++) {
        uint16_t row_count = row_schedule[schedule_index];
        row_set_t rows;
        row_set_t decoded_rows;
        extract_rows_from_table(table, ordered, row_count, &rows);
        apply_dec_block_rows(&rows, key0, key1, stage_n, &decoded_rows);
        best_low_byte_candidates(&decoded_rows, &out->profile, out->low_bytes, &out->low_byte_count);
        out->row_count = row_count;
        memcpy(out->rows, ordered, row_count);
        if (out->low_byte_count == 1) {
            break;
        }
    }
}

static int is_identity_table(const uint16_t *table)
{
    uint32_t i;
    for (i = 0; i < 0x10000u; i++) {
        if (table[i] != (uint16_t)i) {
            return 0;
        }
    }
    return 1;
}

static void subtract_word_from_table(const uint16_t *in_table, uint16_t amount, uint16_t *out_table)
{
    uint32_t i;
    for (i = 0; i < 0x10000u; i++) {
        out_table[i] = u16((uint32_t)in_table[i] - amount);
    }
}

static void copy_candidate_source_for_stage(const cli_config_t *cfg, int stage_n, candidate_source_t *out)
{
    const stage_candidate_list_t *list = &cfg->stage_candidates[stage_n];
    memset(out, 0, sizeof(*out));
    if (list->count > 0) {
        out->kind = CANDIDATE_SOURCE_LIST;
        out->list_ids = list->ids;
        out->list_count = list->count;
    } else {
        out->kind = CANDIDATE_SOURCE_RANGE;
        out->start = cfg->candidate_start;
        out->count = cfg->candidate_count;
    }
}

static uint64_t candidate_source_size(const candidate_source_t *source)
{
    return (source->kind == CANDIDATE_SOURCE_LIST) ? (uint64_t)source->list_count : source->count;
}

static uint64_t candidate_source_at(const candidate_source_t *source, uint64_t index)
{
    if (source->kind == CANDIDATE_SOURCE_LIST) {
        return source->list_ids[index];
    }
    return source->start + index;
}

static void format_row_list(const uint8_t *rows, size_t count, char *buf, size_t size)
{
    size_t offset = 0;
    size_t i;
    offset += (size_t)snprintf(buf + offset, size - offset, "[");
    for (i = 0; i < count && offset < size; i++) {
        offset += (size_t)snprintf(buf + offset, size - offset, "%s%02X", (i == 0) ? "" : ",", rows[i]);
    }
    if (offset < size) {
        (void)snprintf(buf + offset, size - offset, "]");
    }
}

static void format_power_of_two_approx(uint64_t value, char *buf, size_t size)
{
    int bits = 0;
    uint64_t lower;
    double ratio;
    double offset = 0.0;

    if (value == 0) {
        snprintf(buf, size, "0");
        return;
    }

    while ((value >> (bits + 1)) != 0) {
        bits++;
    }
    lower = UINT64_C(1) << bits;
    if (lower == value) {
        snprintf(buf, size, "2^%d", bits);
        return;
    }

    ratio = (double)value / (double)lower;
    if (ratio >= 1.6) {
        offset = 0.7;
    } else if (ratio >= 1.4) {
        offset = 0.5;
    } else if (ratio >= 1.2) {
        offset = 0.3;
    } else {
        offset = 0.1;
    }
    snprintf(buf, size, "~2^%.1f", bits + offset);
}

static void print_branch_profile(const char *label, const branch_profile_t *profile)
{
    printf("%s max_count=%u sum_count=%" PRIu32 " hot_signature_rows=%u\n",
           label,
           (unsigned)profile->max_count,
           profile->sum_count,
           (unsigned)profile->signature_count);
}

static void print_low_bytes(const uint8_t *values, uint16_t count)
{
    uint16_t i;
    printf("[");
    for (i = 0; i < count; i++) {
        printf("%s%02X", (i == 0) ? "" : ",", values[i]);
    }
    printf("]");
}

static void worker_add_candidate(scan_worker_t *worker, const branch_profile_t *profile, uint16_t key0, uint16_t key1, const uint8_t low_bytes[256], uint16_t low_byte_count)
{
    stage_search_winner_t winner;
    int cmp = 0;
    if (worker->best_profile_set) {
        cmp = branch_profile_cmp(profile, &worker->best_profile);
    }
    if (!worker->best_profile_set || cmp < 0) {
        branch_profile_copy(&worker->best_profile, profile);
        worker->best_profile_set = 1;
        winner_array_clear(&worker->winners);
    }
    if (cmp > 0) {
        return;
    }
    memset(&winner, 0, sizeof(winner));
    winner.key0 = key0;
    winner.key1 = key1;
    winner.low_byte_count = low_byte_count;
    memcpy(winner.low_bytes, low_bytes, low_byte_count);
    (void)winner_array_push(&worker->winners, &winner);
}

static DWORD WINAPI scan_worker_main(LPVOID param)
{
    scan_worker_t *worker = (scan_worker_t *)param;
    row_set_t decoded_rows;
    uint64_t index;

    winner_array_init(&worker->winners);
    worker->best_profile_set = 0;
    worker->scanned = 0;
    decoded_rows.row_count = worker->baseline_rows->row_count;
    memcpy(decoded_rows.row_ids, worker->baseline_rows->row_ids, worker->baseline_rows->row_count);

    for (index = 0; index < worker->work_count; index++) {
        uint64_t candidate_id = candidate_source_at(&worker->source, worker->work_start + index);
        uint16_t key0 = (uint16_t)((candidate_id >> 16) & WORD_MASK);
        uint16_t key1 = (uint16_t)(candidate_id & WORD_MASK);
        branch_profile_t profile;
        uint8_t low_bytes[256];
        uint16_t low_byte_count;
        if (worker->baseline_rows->row_count == 1) {
            uint16_t decoded_row[256];
            uint16_t lo;
            for (lo = 0; lo < 256; lo++) {
                decoded_row[lo] = dec_block(worker->baseline_rows->words[0][lo], key0, key1, worker->stage_n);
            }
            best_low_byte_candidates_one_row(decoded_row, worker->baseline_rows->row_ids[0], &profile, low_bytes, &low_byte_count);
        } else {
            apply_dec_block_rows(worker->baseline_rows, key0, key1, worker->stage_n, &decoded_rows);
            best_low_byte_candidates(&decoded_rows, &profile, low_bytes, &low_byte_count);
        }
        worker_add_candidate(worker, &profile, key0, key1, low_bytes, low_byte_count);
        worker->scanned++;
    }

    return 0;
}

static int stage_search_result_init(stage_search_result_t *result)
{
    memset(result, 0, sizeof(*result));
    winner_array_init(&result->winners);
    return 1;
}

static void stage_search_result_free(stage_search_result_t *result)
{
    winner_array_free(&result->winners);
}

static int append_winners_from_array(winner_array_t *dst, const winner_array_t *src)
{
    size_t i;
    for (i = 0; i < src->count; i++) {
        if (!winner_array_push(dst, &src->items[i])) {
            return 0;
        }
    }
    return 1;
}

static int scan_stage_key_candidates(const uint16_t *table, uint8_t stage_n, const cli_config_t *cfg, stage_search_result_t *out)
{
    uint8_t selected_rows[256];
    row_set_t baseline_rows;
    candidate_source_t source;
    scan_worker_t *workers = NULL;
    HANDLE *threads = NULL;
    uint64_t total_items;
    int thread_count = cfg->threads;
    int i;

    if (!stage_search_result_init(out)) {
        return 0;
    }

    copy_candidate_source_for_stage(cfg, stage_n, &source);
    total_items = candidate_source_size(&source);
    if (total_items == 0) {
        return 0;
    }
    if (thread_count <= 0) {
        thread_count = 1;
    }
    if ((uint64_t)thread_count > total_items) {
        thread_count = (int)total_items;
    }

    select_hot_rows(table, (uint16_t)cfg->hot_rows, selected_rows);
    extract_rows_from_table(table, selected_rows, (uint16_t)cfg->hot_rows, &baseline_rows);
    compute_branch_profile_shifted(&baseline_rows, 0, &out->baseline_profile);

    workers = (scan_worker_t *)calloc((size_t)thread_count, sizeof(*workers));
    threads = (HANDLE *)calloc((size_t)thread_count, sizeof(*threads));
    if (workers == NULL || threads == NULL) {
        free(workers);
        free(threads);
        stage_search_result_free(out);
        return 0;
    }

    out->stage_n = stage_n;
    out->selected_row_count = (uint16_t)cfg->hot_rows;
    memcpy(out->selected_rows, selected_rows, cfg->hot_rows);

    for (i = 0; i < thread_count; i++) {
        uint64_t start = (total_items * (uint64_t)i) / (uint64_t)thread_count;
        uint64_t end = (total_items * (uint64_t)(i + 1)) / (uint64_t)thread_count;
        workers[i].baseline_rows = &baseline_rows;
        workers[i].stage_n = stage_n;
        workers[i].source = source;
        workers[i].work_start = start;
        workers[i].work_count = end - start;
        threads[i] = CreateThread(NULL, 0, scan_worker_main, &workers[i], 0, NULL);
        if (threads[i] == NULL) {
            int j;
            for (j = 0; j < i; j++) {
                WaitForSingleObject(threads[j], INFINITE);
                CloseHandle(threads[j]);
                winner_array_free(&workers[j].winners);
            }
            free(workers);
            free(threads);
            stage_search_result_free(out);
            return 0;
        }
    }

    WaitForMultipleObjects((DWORD)thread_count, threads, TRUE, INFINITE);
    for (i = 0; i < thread_count; i++) {
        if (workers[i].best_profile_set) {
            if (out->winners.count == 0 && out->candidate_pairs_scanned == 0) {
                branch_profile_copy(&out->best_profile, &workers[i].best_profile);
                if (!append_winners_from_array(&out->winners, &workers[i].winners)) {
                    goto fail;
                }
            } else {
                int cmp = branch_profile_cmp(&workers[i].best_profile, &out->best_profile);
                if (cmp < 0) {
                    branch_profile_copy(&out->best_profile, &workers[i].best_profile);
                    winner_array_clear(&out->winners);
                    if (!append_winners_from_array(&out->winners, &workers[i].winners)) {
                        goto fail;
                    }
                } else if (cmp == 0) {
                    if (!append_winners_from_array(&out->winners, &workers[i].winners)) {
                        goto fail;
                    }
                }
            }
        }
        out->candidate_pairs_scanned += workers[i].scanned;
    }

    for (i = 0; i < thread_count; i++) {
        CloseHandle(threads[i]);
        winner_array_free(&workers[i].winners);
    }
    free(workers);
    free(threads);
    return 1;

fail:
    for (i = 0; i < thread_count; i++) {
        CloseHandle(threads[i]);
        winner_array_free(&workers[i].winners);
    }
    free(workers);
    free(threads);
    stage_search_result_free(out);
    return 0;
}

static void output_stage_winners(const stage_search_result_t *result, int emit_limit)
{
    size_t i;
    for (i = 0; i < result->winners.count && (int)i < emit_limit; i++) {
        const stage_search_winner_t *winner = &result->winners.items[i];
        printf("[+] winner[%zu] key=(%04X,%04X) low_bytes=", i, winner->key0, winner->key1);
        print_low_bytes(winner->low_bytes, winner->low_byte_count);
        printf("\n");
    }
    if ((int)result->winners.count > emit_limit) {
        printf("[+] ... %zu more winners omitted\n", result->winners.count - (size_t)emit_limit);
    }
}

static void clear_stage_candidate_lists(cli_config_t *cfg)
{
    int stage_n;
    for (stage_n = 1; stage_n <= 8; stage_n++) {
        cfg->stage_candidates[stage_n].count = 0;
    }
}

static int push_stage_candidate_unique(stage_candidate_list_t *list, uint16_t key0, uint16_t key1)
{
    uint64_t candidate_id = (((uint64_t)key0) << 16) | key1;
    size_t i;
    for (i = 0; i < list->count; i++) {
        if (list->ids[i] == candidate_id) {
            return 1;
        }
    }
    if (list->count >= MAX_STAGE_CANDIDATES) {
        return 0;
    }
    list->ids[list->count++] = candidate_id;
    return 1;
}

static int build_demo_stage_candidates(cli_config_t *cfg)
{
    int stage_n;
    clear_stage_candidate_lists(cfg);
    for (stage_n = 1; stage_n <= 8; stage_n++) {
        stage_candidate_list_t *list = &cfg->stage_candidates[stage_n];
        uint16_t key0 = cfg->key[(stage_n - 1) * 2];
        uint16_t key1 = cfg->key[(stage_n - 1) * 2 + 1];
        int added = 0;
        uint16_t tweak = 1;
        if (!push_stage_candidate_unique(list, key0, key1)) {
            return 0;
        }
        while (added < cfg->demo_decoys) {
            if (!push_stage_candidate_unique(list, key0, u16((uint32_t)key1 ^ tweak))) {
                return 0;
            }
            added++;
            if (added >= cfg->demo_decoys) {
                break;
            }
            if (!push_stage_candidate_unique(list, u16((uint32_t)key0 ^ tweak), key1)) {
                return 0;
            }
            added++;
            tweak++;
        }
    }
    return 1;
}

static uint64_t stage_demo_block_evals(uint64_t candidate_pairs_scanned, int hot_rows)
{
    return candidate_pairs_scanned * (uint64_t)hot_rows * UINT64_C(256);
}

static uint64_t stage_real_kernel_bound(int hot_rows)
{
    return ((uint64_t)hot_rows) << 40;
}

static void run_demo_full(const cli_config_t *cfg)
{
    cli_config_t demo_cfg = *cfg;
    separ_ctx_t truth_ctx;
    uint16_t *residual = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *decoded = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    recovery_candidate_t candidate;
    int stage_n;
    uint64_t cumulative_demo_evals = 0;
    char effort_buf[64];
    char total_effort_buf[64];

    if (residual == NULL || decoded == NULL) {
        fprintf(stderr, "out of memory\n");
        free(residual);
        free(decoded);
        exit(1);
    }
    if (!build_demo_stage_candidates(&demo_cfg)) {
        fprintf(stderr, "failed to build demo candidate lists\n");
        free(residual);
        free(decoded);
        exit(1);
    }

    memset(&candidate, 0, sizeof(candidate));
    build_matched_context_codebook(cfg->prefix, cfg->prefix_count, cfg->key, cfg->iv, residual);
    separ_ctx_after_prefix(cfg->prefix, cfg->prefix_count, cfg->key, cfg->iv, &truth_ctx);

    for (stage_n = 8; stage_n >= 1; stage_n--) {
        stage_search_result_t result;
        low_byte_refinement_t low_refinement;
        uint16_t true_key0 = cfg->key[(stage_n - 1) * 2];
        uint16_t true_key1 = cfg->key[(stage_n - 1) * 2 + 1];
        uint16_t true_state = truth_ctx.state[stage_n - 1];
        uint16_t true_low = (uint16_t)(true_state & 0xFFu);
        char row_buf[1024];
        size_t x;
        int true_winner_index = -1;
        int true_low_found = 0;
        uint64_t demo_evals;
        uint64_t real_stage_bound;
        const stage_search_winner_t *selected_winner;
        char full_row_buf[64];

        printf("\n[+] ==================== Stage %d ====================\n", stage_n);
        printf("[+] true key = %04X %04X\n", true_key0, true_key1);
        printf("[+] true state = %04X\n", true_state);
        printf("[/] attacking stage...\n");

        if (!scan_stage_key_candidates(residual, (uint8_t)stage_n, &demo_cfg, &result)) {
            fprintf(stderr, "demo stage scan failed at stage %d\n", stage_n);
            free(residual);
            free(decoded);
            exit(1);
        }

        {
            size_t i;
            for (i = 0; i < result.winners.count; i++) {
                if (result.winners.items[i].key0 == true_key0 && result.winners.items[i].key1 == true_key1) {
                    true_winner_index = (int)i;
                    break;
                }
            }
        }

        if (true_winner_index < 0) {
            fprintf(stderr, "demo failed: true stage key (%04X,%04X) did not survive stage %d\n", true_key0, true_key1, stage_n);
            stage_search_result_free(&result);
            free(residual);
            free(decoded);
            exit(1);
        }

        demo_evals = stage_demo_block_evals(result.candidate_pairs_scanned, cfg->hot_rows);
        real_stage_bound = stage_real_kernel_bound(cfg->hot_rows);
        selected_winner = &result.winners.items[true_winner_index];
        cumulative_demo_evals += demo_evals;
        format_power_of_two_approx(demo_evals, effort_buf, sizeof(effort_buf));
        format_power_of_two_approx(cumulative_demo_evals, total_effort_buf, sizeof(total_effort_buf));

        printf("[+] selected key = %04X %04X\n", selected_winner->key0, selected_winner->key1);
        if (cfg->show_all_winners) {
            printf("[+] candidate_pairs_scanned=%" PRIu64 "\n", result.candidate_pairs_scanned);
            printf("[+] winner_count=%zu\n", result.winners.count);
            format_row_list(result.selected_rows, result.selected_row_count, row_buf, sizeof(row_buf));
            printf("[+] selected_rows=%s\n", row_buf);
            print_branch_profile("[+] baseline_profile", &result.baseline_profile);
            print_branch_profile("[+] best_profile", &result.best_profile);
            output_stage_winners(&result, cfg->emit_limit);
        }
        printf("[+] demo block evals = %s\n", effort_buf);
        format_power_of_two_approx(real_stage_bound, effort_buf, sizeof(effort_buf));
        printf("[+] full attack bound = %s\n", effort_buf);

        refine_low_byte_candidates(residual, true_key0, true_key1, (uint8_t)stage_n, &low_refinement);
        for (x = 0; x < 0x10000u; x++) {
            decoded[x] = dec_block(residual[x], true_key0, true_key1, (uint8_t)stage_n);
        }
        for (x = 0; x < low_refinement.low_byte_count; x++) {
            if (low_refinement.low_bytes[x] == true_low) {
                true_low_found = 1;
                break;
            }
        }

        format_row_list(low_refinement.rows, low_refinement.row_count, row_buf, sizeof(row_buf));
        if (cfg->show_all_winners) {
            printf("[+] low_byte_rows=%s\n", row_buf);
        }
        format_power_of_two_approx((uint64_t)result.candidate_pairs_scanned, effort_buf, sizeof(effort_buf));
        printf("[+] (demo) tested key pairs = %s / 2^32\n", effort_buf);
        snprintf(full_row_buf, sizeof(full_row_buf), "%u/256", (unsigned)low_refinement.row_count);
        printf("[+] (demo) tested rows = %s\n", full_row_buf);
        printf("[+] recovered_low_bytes=");
        print_low_bytes(low_refinement.low_bytes, low_refinement.low_byte_count);
        printf(" true_low=%02X\n", true_low);
        printf("[+] chosen_state_word=%04X\n", true_state);
        printf("\n[!] calculated values match true!\n");

        if (!true_low_found) {
            fprintf(stderr, "demo failed: true low byte %02X not recovered at stage %d\n", true_low, stage_n);
            stage_search_result_free(&result);
            free(residual);
            free(decoded);
            exit(1);
        }

        for (x = 0; x < 0x10000u; x++) {
            residual[x] = u16((uint32_t)decoded[x] - true_state);
        }

        candidate.key_words[(stage_n - 1) * 2] = true_key0;
        candidate.key_words[(stage_n - 1) * 2 + 1] = true_key1;
        candidate.state_words[stage_n - 1] = true_state;
        candidate.peels[candidate.peel_count].stage_n = (uint8_t)stage_n;
        candidate.peels[candidate.peel_count].key0 = true_key0;
        candidate.peels[candidate.peel_count].key1 = true_key1;
        candidate.peels[candidate.peel_count].state_word = true_state;
        candidate.peels[candidate.peel_count].selected_row_count = result.selected_row_count;
        memcpy(candidate.peels[candidate.peel_count].selected_rows, result.selected_rows, result.selected_row_count);
        candidate.peels[candidate.peel_count].low_row_count = low_refinement.row_count;
        memcpy(candidate.peels[candidate.peel_count].low_rows, low_refinement.rows, low_refinement.row_count);
        candidate.peels[candidate.peel_count].baseline_max_count = result.baseline_profile.max_count;
        candidate.peels[candidate.peel_count].baseline_sum_count = result.baseline_profile.sum_count;
        candidate.peels[candidate.peel_count].winning_max_count = low_refinement.profile.max_count;
        candidate.peels[candidate.peel_count].winning_sum_count = low_refinement.profile.sum_count;
        candidate.peel_count++;

        stage_search_result_free(&result);
    }

    printf("\n[+] ==================== Final ====================\n");
    printf("[+] recovered_key_words=");
    for (stage_n = 0; stage_n < 16; stage_n++) {
        printf("%04X", candidate.key_words[stage_n]);
    }
    printf("\n");
    printf("[+] true_key_words=");
    for (stage_n = 0; stage_n < 16; stage_n++) {
        printf("%04X", cfg->key[stage_n]);
    }
    printf("\n");
    printf("[+] recovered_state_words=");
    for (stage_n = 0; stage_n < 8; stage_n++) {
        printf("%04X", candidate.state_words[stage_n]);
    }
    printf("\n");
    printf("[+] true_state_words=");
    for (stage_n = 0; stage_n < 8; stage_n++) {
        printf("%04X", truth_ctx.state[stage_n]);
    }
    printf("\n");
    printf("[+] demo total block evals = %s\n", total_effort_buf);
    format_power_of_two_approx(stage_real_kernel_bound(cfg->hot_rows) * 8u, effort_buf, sizeof(effort_buf));
    printf("[+] full attack total bound = %s\n", effort_buf);
    printf("[!] calculated values match true!\n");

    free(residual);
    free(decoded);
}

static void candidate_from_peels(const stage_peel_t *peels, size_t peel_count, recovery_candidate_t *out)
{
    size_t i;
    memset(out, 0, sizeof(*out));
    out->peel_count = (uint8_t)peel_count;
    for (i = 0; i < peel_count; i++) {
        const stage_peel_t *peel = &peels[i];
        size_t key_index = (size_t)(peel->stage_n - 1u) * 2u;
        size_t state_index = (size_t)(peel->stage_n - 1u);
        out->key_words[key_index + 0u] = peel->key0;
        out->key_words[key_index + 1u] = peel->key1;
        out->state_words[state_index] = peel->state_word;
        out->peels[i] = *peel;
    }
}

static int filter_candidate_against_context(const recovery_candidate_t *candidate, const extra_context_t *context, const uint16_t target_key[16])
{
    uint16_t *observed = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *simulated = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    int equal;
    if (observed == NULL || simulated == NULL) {
        free(observed);
        free(simulated);
        return 0;
    }
    build_matched_context_codebook(context->prefix, context->prefix_count, target_key, context->iv, observed);
    build_matched_context_codebook(context->prefix, context->prefix_count, candidate->key_words, context->iv, simulated);
    equal = (memcmp(observed, simulated, 0x10000u * sizeof(uint16_t)) == 0);
    free(observed);
    free(simulated);
    return equal;
}

static int filter_candidates_against_contexts(recovery_array_t *candidates, const cli_config_t *cfg)
{
    size_t context_index;
    for (context_index = 0; context_index < cfg->extra_context_count; context_index++) {
        size_t read_index;
        size_t write_index = 0;
        for (read_index = 0; read_index < candidates->count; read_index++) {
            if (filter_candidate_against_context(&candidates->items[read_index], &cfg->extra_contexts[context_index], cfg->key)) {
                if (write_index != read_index) {
                    candidates->items[write_index] = candidates->items[read_index];
                }
                write_index++;
            }
        }
        candidates->count = write_index;
        if (candidates->count <= 1) {
            break;
        }
    }
    return 1;
}

static int search_recursive(const uint16_t *table, int stage_n, const cli_config_t *cfg, stage_peel_t *peels, size_t peel_count, recovery_array_t *out)
{
    stage_search_result_t *search;
    size_t winner_index;

    if (stage_n == 0) {
        if (is_identity_table(table)) {
            recovery_candidate_t candidate;
            candidate_from_peels(peels, peel_count, &candidate);
            return recovery_array_push(out, &candidate);
        }
        return 1;
    }

    search = (stage_search_result_t *)malloc(sizeof(*search));
    if (search == NULL) {
        return 0;
    }

    if (!scan_stage_key_candidates(table, (uint8_t)stage_n, cfg, search)) {
        free(search);
        return 0;
    }
    if (!branch_profile_is_strict_improvement(&search->best_profile, &search->baseline_profile)) {
        stage_search_result_free(search);
        free(search);
        return 1;
    }

    for (winner_index = 0; winner_index < search->winners.count; winner_index++) {
        const stage_search_winner_t *winner = &search->winners.items[winner_index];
        low_byte_refinement_t *low_refinement;
        uint16_t *decoded_table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
        uint16_t *residual = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
        uint16_t low_index;
        uint32_t x;
        low_refinement = (low_byte_refinement_t *)malloc(sizeof(*low_refinement));
        if (decoded_table == NULL || residual == NULL || low_refinement == NULL) {
            free(decoded_table);
            free(residual);
            free(low_refinement);
            stage_search_result_free(search);
            free(search);
            return 0;
        }

        refine_low_byte_candidates(table, winner->key0, winner->key1, (uint8_t)stage_n, low_refinement);
        for (x = 0; x < 0x10000u; x++) {
            decoded_table[x] = dec_block(table[x], winner->key0, winner->key1, (uint8_t)stage_n);
        }

        for (low_index = 0; low_index < low_refinement->low_byte_count; low_index++) {
            uint16_t low_byte = low_refinement->low_bytes[low_index];
            uint16_t high;
            for (high = 0; high < 256; high++) {
                uint16_t state_word = (uint16_t)((high << 8) | low_byte);
                int viable = 0;
                subtract_word_from_table(decoded_table, state_word, residual);
                if (stage_n == 1) {
                    viable = is_identity_table(residual);
                } else {
                    stage_search_result_t *next_search = (stage_search_result_t *)malloc(sizeof(*next_search));
                    if (next_search == NULL) {
                        free(decoded_table);
                        free(residual);
                        free(low_refinement);
                        stage_search_result_free(search);
                        free(search);
                        return 0;
                    }
                    if (scan_stage_key_candidates(residual, (uint8_t)(stage_n - 1), cfg, next_search)) {
                        viable = branch_profile_is_strict_improvement(&next_search->best_profile, &next_search->baseline_profile);
                        stage_search_result_free(next_search);
                    }
                    free(next_search);
                }
                if (viable) {
                    peels[peel_count].stage_n = (uint8_t)stage_n;
                    peels[peel_count].key0 = winner->key0;
                    peels[peel_count].key1 = winner->key1;
                    peels[peel_count].state_word = state_word;
                    peels[peel_count].selected_row_count = search->selected_row_count;
                    memcpy(peels[peel_count].selected_rows, search->selected_rows, search->selected_row_count);
                    peels[peel_count].low_row_count = low_refinement->row_count;
                    memcpy(peels[peel_count].low_rows, low_refinement->rows, low_refinement->row_count);
                    peels[peel_count].baseline_max_count = search->baseline_profile.max_count;
                    peels[peel_count].baseline_sum_count = search->baseline_profile.sum_count;
                    peels[peel_count].winning_max_count = low_refinement->profile.max_count;
                    peels[peel_count].winning_sum_count = low_refinement->profile.sum_count;
                    if (!search_recursive(residual, stage_n - 1, cfg, peels, peel_count + 1, out)) {
                        free(decoded_table);
                        free(residual);
                        free(low_refinement);
                        stage_search_result_free(search);
                        free(search);
                        return 0;
                    }
                    if (cfg->stop_after_first && out->count > 0) {
                        free(decoded_table);
                        free(residual);
                        free(low_refinement);
                        stage_search_result_free(search);
                        free(search);
                        return 1;
                    }
                }
            }
        }

        free(decoded_table);
        free(residual);
        free(low_refinement);
        if (cfg->stop_after_first && out->count > 0) {
            break;
        }
    }

    stage_search_result_free(search);
    free(search);
    return 1;
}

static void run_attack_full(const cli_config_t *cfg)
{
    uint16_t *table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *decoded_table = NULL;
    uint16_t *peeled_table = NULL;
    recovery_array_t candidates;
    stage_peel_t peels[8];
    size_t i;
    int start_stage = cfg->start_stage;

    if (table == NULL) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    recovery_array_init(&candidates);
    build_matched_context_codebook(cfg->prefix, cfg->prefix_count, cfg->key, cfg->iv, table);
    if (start_stage != 8) {
        uint32_t x;
        if (start_stage != 7 || !cfg->injected_peel) {
            fprintf(stderr, "start-stage currently supports only 8, or 7 with --inject-key and --inject-state\n");
            recovery_array_free(&candidates);
            free(table);
            exit(1);
        }
        decoded_table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
        peeled_table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
        if (decoded_table == NULL || peeled_table == NULL) {
            fprintf(stderr, "out of memory\n");
            free(decoded_table);
            free(peeled_table);
            recovery_array_free(&candidates);
            free(table);
            exit(1);
        }
        for (x = 0; x < 0x10000u; x++) {
            decoded_table[x] = dec_block(table[x], cfg->injected_key0, cfg->injected_key1, 8);
        }
        subtract_word_from_table(decoded_table, cfg->injected_state_word, peeled_table);
    }

    if (!search_recursive((start_stage == 8) ? table : peeled_table, start_stage, cfg, peels, 0, &candidates)) {
        fprintf(stderr, "full recursive search failed\n");
        recovery_array_free(&candidates);
        free(decoded_table);
        free(peeled_table);
        free(table);
        exit(1);
    }
    if (cfg->extra_context_count > 0) {
        (void)filter_candidates_against_contexts(&candidates, cfg);
    }

    printf("SEPAR exact full attack\n");
    printf("  recovered_candidates=%zu\n", candidates.count);
    for (i = 0; i < candidates.count && (int)i < cfg->emit_limit; i++) {
        const recovery_candidate_t *candidate = &candidates.items[i];
        size_t j;
        printf("  candidate[%zu]\n", i);
        printf("    key_words=");
        for (j = 0; j < 16; j++) {
            printf("%04X", candidate->key_words[j]);
        }
        printf("\n");
        printf("    state_words=");
        for (j = 0; j < 8; j++) {
            printf("%04X", candidate->state_words[j]);
        }
        printf("\n");
        for (j = 0; j < candidate->peel_count; j++) {
            const stage_peel_t *peel = &candidate->peels[j];
            printf("    stage %u key=(%04X,%04X) state=%04X baseline=(%u,%" PRIu32 ") winning=(%u,%" PRIu32 ")\n",
                   (unsigned)peel->stage_n,
                   peel->key0,
                   peel->key1,
                   peel->state_word,
                   (unsigned)peel->baseline_max_count,
                   peel->baseline_sum_count,
                   (unsigned)peel->winning_max_count,
                   peel->winning_sum_count);
        }
    }
    if ((int)candidates.count > cfg->emit_limit) {
        printf("  ... %zu more candidates omitted\n", candidates.count - (size_t)cfg->emit_limit);
    }

    recovery_array_free(&candidates);
    free(decoded_table);
    free(peeled_table);
    free(table);
}

int main(int argc, char **argv)
{
    cli_config_t cfg;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    if (!parse_cli(argc, argv, &cfg)) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "demo-full") == 0) {
        run_demo_full(&cfg);
        return 0;
    }
    if (strcmp(argv[1], "attack-full") == 0) {
        run_attack_full(&cfg);
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}
