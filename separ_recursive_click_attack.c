#include <ctype.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

#ifndef ROTL16
#define ROTL16(x, y) (uint16_t)((((uint16_t)(x)) << ((y) & 15)) | (((uint16_t)(x)) >> (16 - ((y) & 15))))
#define ROTR16(x, y) (uint16_t)((((uint16_t)(x)) >> ((y) & 15)) | (((uint16_t)(x)) << (16 - ((y) & 15))))
#endif

#define TABLE_SIZE 65536u
#define STATE_COUNT 8u
#define MAX_PREFIX_WORDS 32u
#define MAX_TOP_RESULTS 16u

typedef struct {
    uint16_t k0;
    uint16_t k1;
} KeyPair;

typedef struct {
    uint16_t state[STATE_COUNT];
    uint16_t lfsr;
} SeparCtx;

typedef struct {
    uint64_t score;
    KeyPair pair;
} KeyScore;

typedef struct {
    uint32_t total_support;
    uint8_t support_rows[4];
    uint8_t low;
} LowScore;

typedef struct {
    uint64_t score;
    uint8_t low;
    uint8_t high;
    KeyPair pair;
} ClickScore;

typedef struct {
    uint16_t key[16];
    uint16_t iv[8];
    uint16_t prefix[MAX_PREFIX_WORDS];
    size_t prefix_len;
    unsigned threads;
    size_t candidate_count;
    size_t h_count;
    size_t low_top_count;
    size_t top_count;
    int full_search;
    int inject_true;
    int validate;
    uint64_t seed;
} Options;

typedef struct {
    KeyScore *items;
    size_t count;
    size_t cap;
} KeyTopList;

typedef struct {
    LowScore *items;
    size_t count;
    size_t cap;
} LowTopList;

typedef struct {
    ClickScore *items;
    size_t count;
    size_t cap;
} ClickTopList;

typedef struct {
    const uint16_t *source_table;
    uint8_t stage;
    const uint16_t *diffs;
    size_t diff_count;
    const KeyPair *candidate_pairs;
    uint64_t total_candidates;
    int exhaustive;
    atomic_ullong progress;
    atomic_int finished_workers;
    size_t worker_count;
    size_t topn;
    KeyTopList *worker_results;
    uint64_t candidate_chunk;
} KeySearchPlan;

typedef struct {
    HANDLE handle;
    KeySearchPlan *plan;
    size_t worker_index;
    uint64_t start;
    uint64_t end;
} KeyWorker;

typedef struct {
    KeyPair *pairs;
    size_t count;
} CandidateSet;

typedef struct {
    uint8_t *values;
    size_t count;
} HighCandidateSet;

typedef struct {
    KeyPair recovered_keys[9];
    uint16_t recovered_states[9];
    int key_known[9];
    int state_known[9];
} AttackResult;

static const uint16_t default_key[16] = {
    0xE8B9, 0xB733, 0xDA5D, 0x96D7, 0x02DD, 0x3972, 0xE953, 0x07FD,
    0x50C5, 0x12DB, 0xF44A, 0x233E, 0x8D1E, 0x9DF5, 0xFC7D, 0x6371,
};

static const uint16_t default_iv[8] = {
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

static const uint8_t S1[16] = {1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4};
static const uint8_t S2[16] = {6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8};
static const uint8_t S3[16] = {12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13, 15, 4};
static const uint8_t S4[16] = {13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14};

static const uint8_t IS1[16] = {4, 0, 3, 5, 15, 6, 8, 11, 7, 9, 13, 2, 10, 12, 14, 1};
static const uint8_t IS2[16] = {12, 8, 7, 13, 3, 14, 0, 9, 15, 6, 1, 11, 10, 5, 4, 2};
static const uint8_t IS3[16] = {4, 3, 1, 5, 15, 6, 2, 8, 7, 9, 12, 10, 0, 13, 11, 14};
static const uint8_t IS4[16] = {4, 11, 2, 5, 13, 6, 8, 3, 7, 14, 12, 1, 9, 0, 15, 10};

static const uint16_t default_diffs[] = {0x0001, 0x0002, 0x0004, 0x0008, 0x000F, 0x0010};
static const uint8_t support_rows[] = {0x00, 0x40, 0x80, 0xC0};

static inline uint16_t do_sbox(uint16_t x)
{
    uint8_t a = (uint8_t)(x >> 12);
    uint8_t b = (uint8_t)((x >> 8) & 0xF);
    uint8_t c = (uint8_t)((x >> 4) & 0xF);
    uint8_t d = (uint8_t)(x & 0xF);
    return (uint16_t)((S1[a] << 12) | (S2[b] << 8) | (S3[c] << 4) | S4[d]);
}

static inline uint16_t do_isbox(uint16_t x)
{
    uint8_t a = (uint8_t)(x >> 12);
    uint8_t b = (uint8_t)((x >> 8) & 0xF);
    uint8_t c = (uint8_t)((x >> 4) & 0xF);
    uint8_t d = (uint8_t)(x & 0xF);
    return (uint16_t)((IS1[a] << 12) | (IS2[b] << 8) | (IS3[c] << 4) | IS4[d]);
}

static inline uint16_t sep_rotl16(uint16_t x)
{
    uint8_t a = (uint8_t)(x >> 12);
    uint8_t b = (uint8_t)((x >> 8) & 0xF);
    uint8_t c = (uint8_t)((x >> 4) & 0xF);
    uint8_t d = (uint8_t)(x & 0xF);
    uint16_t y;
    uint16_t z;

    a ^= c;
    b ^= d;
    c ^= b;
    d ^= a;

    x = (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
    y = ROTL16(x, 12);
    z = ROTL16(x, 8);
    return (uint16_t)(x ^ y ^ z);
}

static inline uint16_t sep_inrotl16(uint16_t x)
{
    uint16_t y = ROTR16(x, 12);
    uint16_t z = ROTR16(x, 8);
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;

    x ^= y ^ z;
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

static inline void derive_key23(uint16_t key0, uint16_t key1, uint8_t stage, uint16_t *key2, uint16_t *key3)
{
    uint16_t k2 = ROTL16(key0, 6);
    uint16_t k3 = ROTL16(key1, 10);
    uint8_t b;

    b = (uint8_t)((k2 >> 6) & 0xF);
    k2 |= (uint16_t)(S1[b] << 6);
    k2 ^= (uint16_t)(stage + 2);

    b = (uint8_t)((k3 >> 6) & 0xF);
    k3 |= (uint16_t)(S1[b] << 6);
    k3 ^= (uint16_t)(stage + 3);

    *key2 = k2;
    *key3 = k3;
}

static inline uint16_t enc_block(uint16_t pt, KeyPair pair, uint8_t stage)
{
    uint16_t t;
    uint16_t key2;
    uint16_t key3;

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

static inline uint16_t dec_block(uint16_t ct, KeyPair pair, uint8_t stage)
{
    uint16_t t;
    uint16_t key2;
    uint16_t key3;

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

static inline KeyPair stage_pair_from_full_key(const uint16_t full_key[16], uint8_t stage)
{
    KeyPair pair;
    pair.k0 = full_key[(stage - 1u) * 2u];
    pair.k1 = full_key[(stage - 1u) * 2u + 1u];
    return pair;
}

static inline int pair_equal(KeyPair lhs, KeyPair rhs)
{
    return lhs.k0 == rhs.k0 && lhs.k1 == rhs.k1;
}

static inline int is_default_key(const uint16_t key[16])
{
    return memcmp(key, default_key, sizeof(default_key)) == 0;
}

static inline int is_default_iv(const uint16_t iv[8])
{
    return memcmp(iv, default_iv, sizeof(default_iv)) == 0;
}

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static unsigned default_thread_count(void)
{
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    if (info.dwNumberOfProcessors == 0) {
        return 4u;
    }
    return info.dwNumberOfProcessors;
}

static int cmp_keyscore(const KeyScore *lhs, const KeyScore *rhs)
{
    if (lhs->score != rhs->score) {
        return (lhs->score > rhs->score) ? -1 : 1;
    }
    if (lhs->pair.k0 != rhs->pair.k0) {
        return (lhs->pair.k0 < rhs->pair.k0) ? -1 : 1;
    }
    if (lhs->pair.k1 != rhs->pair.k1) {
        return (lhs->pair.k1 < rhs->pair.k1) ? -1 : 1;
    }
    return 0;
}

static int cmp_lowscore(const LowScore *lhs, const LowScore *rhs)
{
    size_t i;
    if (lhs->total_support != rhs->total_support) {
        return (lhs->total_support < rhs->total_support) ? -1 : 1;
    }
    for (i = 0; i < 4; i++) {
        if (lhs->support_rows[i] != rhs->support_rows[i]) {
            return (lhs->support_rows[i] < rhs->support_rows[i]) ? -1 : 1;
        }
    }
    if (lhs->low != rhs->low) {
        return (lhs->low < rhs->low) ? -1 : 1;
    }
    return 0;
}

static int cmp_clickscore(const ClickScore *lhs, const ClickScore *rhs)
{
    if (lhs->score != rhs->score) {
        return (lhs->score > rhs->score) ? -1 : 1;
    }
    if (lhs->low != rhs->low) {
        return (lhs->low < rhs->low) ? -1 : 1;
    }
    if (lhs->high != rhs->high) {
        return (lhs->high < rhs->high) ? -1 : 1;
    }
    if (lhs->pair.k0 != rhs->pair.k0) {
        return (lhs->pair.k0 < rhs->pair.k0) ? -1 : 1;
    }
    if (lhs->pair.k1 != rhs->pair.k1) {
        return (lhs->pair.k1 < rhs->pair.k1) ? -1 : 1;
    }
    return 0;
}

static void init_key_toplist(KeyTopList *list, size_t cap)
{
    list->items = (KeyScore *)calloc(cap, sizeof(KeyScore));
    list->count = 0;
    list->cap = cap;
}

static void init_low_toplist(LowTopList *list, size_t cap)
{
    list->items = (LowScore *)calloc(cap, sizeof(LowScore));
    list->count = 0;
    list->cap = cap;
}

static void init_click_toplist(ClickTopList *list, size_t cap)
{
    list->items = (ClickScore *)calloc(cap, sizeof(ClickScore));
    list->count = 0;
    list->cap = cap;
}

static void free_key_toplist(KeyTopList *list)
{
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static void free_low_toplist(LowTopList *list)
{
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static void free_click_toplist(ClickTopList *list)
{
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static void insert_key_top(KeyTopList *list, KeyScore candidate)
{
    size_t pos;
    if (list->cap == 0) {
        return;
    }
    if (list->count == 0) {
        list->items[0] = candidate;
        list->count = 1;
        return;
    }
    pos = 0;
    while (pos < list->count && cmp_keyscore(&candidate, &list->items[pos]) > 0) {
        pos++;
    }
    if (list->count < list->cap) {
        size_t move = list->count - pos;
        if (move > 0) {
            memmove(&list->items[pos + 1], &list->items[pos], move * sizeof(KeyScore));
        }
        list->items[pos] = candidate;
        list->count++;
        return;
    }
    if (pos >= list->cap) {
        return;
    }
    memmove(&list->items[pos + 1], &list->items[pos], (list->cap - pos - 1) * sizeof(KeyScore));
    list->items[pos] = candidate;
}

static void insert_low_top(LowTopList *list, LowScore candidate)
{
    size_t pos;
    if (list->cap == 0) {
        return;
    }
    if (list->count == 0) {
        list->items[0] = candidate;
        list->count = 1;
        return;
    }
    pos = 0;
    while (pos < list->count && cmp_lowscore(&candidate, &list->items[pos]) > 0) {
        pos++;
    }
    if (list->count < list->cap) {
        size_t move = list->count - pos;
        if (move > 0) {
            memmove(&list->items[pos + 1], &list->items[pos], move * sizeof(LowScore));
        }
        list->items[pos] = candidate;
        list->count++;
        return;
    }
    if (pos >= list->cap) {
        return;
    }
    memmove(&list->items[pos + 1], &list->items[pos], (list->cap - pos - 1) * sizeof(LowScore));
    list->items[pos] = candidate;
}

static void insert_click_top(ClickTopList *list, ClickScore candidate)
{
    size_t pos;
    if (list->cap == 0) {
        return;
    }
    if (list->count == 0) {
        list->items[0] = candidate;
        list->count = 1;
        return;
    }
    pos = 0;
    while (pos < list->count && cmp_clickscore(&candidate, &list->items[pos]) > 0) {
        pos++;
    }
    if (list->count < list->cap) {
        size_t move = list->count - pos;
        if (move > 0) {
            memmove(&list->items[pos + 1], &list->items[pos], move * sizeof(ClickScore));
        }
        list->items[pos] = candidate;
        list->count++;
        return;
    }
    if (pos >= list->cap) {
        return;
    }
    memmove(&list->items[pos + 1], &list->items[pos], (list->cap - pos - 1) * sizeof(ClickScore));
    list->items[pos] = candidate;
}

static void print_usage(const char *program)
{
    printf("Usage: %s [options]\n", program);
    printf("  --prefix HEX[,HEX...]     chosen plaintext prefix for the matched context (default 2028)\n");
    printf("  --key HEX64               full 256-bit key as 64 hex chars\n");
    printf("  --iv HEX32                IV as 32 hex chars\n");
    printf("  --threads N               worker threads for key scans (default: CPU count)\n");
    printf("  --candidate-count N       stage-key shortlist size in validation mode (default 12)\n");
    printf("  --h-count N               high-byte shortlist size per stage (default 8)\n");
    printf("  --low-top N               number of low-byte candidates kept before the click step (default 16)\n");
    printf("  --top N                   number of top scorers to print (default 5)\n");
    printf("  --seed N                  seed for deterministic shortlist generation\n");
    printf("  --full-search             scan the full 2^32 stage-key space instead of a shortlist\n");
    printf("  --no-inject-true          do not inject the true stage keys/high bytes into shortlist mode\n");
    printf("  --skip-validation         skip the built-in primitive validation checks\n");
    printf("  --help                    show this message\n");
}

static int hex_nibble(char c)
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

static int parse_fixed_hex_words(const char *text, uint16_t *words, size_t expected_words)
{
    const char *hex = skip_hex_prefix(text);
    size_t hex_len = strlen(hex);
    size_t i;

    if (hex_len != expected_words * 4u) {
        return 0;
    }
    for (i = 0; i < expected_words; i++) {
        int n0 = hex_nibble(hex[i * 4u]);
        int n1 = hex_nibble(hex[i * 4u + 1u]);
        int n2 = hex_nibble(hex[i * 4u + 2u]);
        int n3 = hex_nibble(hex[i * 4u + 3u]);
        if (n0 < 0 || n1 < 0 || n2 < 0 || n3 < 0) {
            return 0;
        }
        words[i] = (uint16_t)((n0 << 12) | (n1 << 8) | (n2 << 4) | n3);
    }
    return 1;
}

static int parse_prefix_words(const char *text, uint16_t *words, size_t *word_count)
{
    char *copy = _strdup(text);
    char *token;
    char *next = NULL;
    size_t count = 0;
    if (copy == NULL) {
        return 0;
    }
    token = strtok_s(copy, ",", &next);
    while (token != NULL) {
        const char *hex = skip_hex_prefix(token);
        size_t len = strlen(hex);
        int n0;
        int n1;
        int n2;
        int n3;
        if (count >= MAX_PREFIX_WORDS || len != 4u) {
            free(copy);
            return 0;
        }
        n0 = hex_nibble(hex[0]);
        n1 = hex_nibble(hex[1]);
        n2 = hex_nibble(hex[2]);
        n3 = hex_nibble(hex[3]);
        if (n0 < 0 || n1 < 0 || n2 < 0 || n3 < 0) {
            free(copy);
            return 0;
        }
        words[count++] = (uint16_t)((n0 << 12) | (n1 << 8) | (n2 << 4) | n3);
        token = strtok_s(NULL, ",", &next);
    }
    free(copy);
    if (count == 0) {
        return 0;
    }
    *word_count = count;
    return 1;
}

static void print_pair(KeyPair pair)
{
    printf("(%04X, %04X)", pair.k0, pair.k1);
}

static void init_options(Options *opts)
{
    memset(opts, 0, sizeof(*opts));
    memcpy(opts->key, default_key, sizeof(default_key));
    memcpy(opts->iv, default_iv, sizeof(default_iv));
    opts->prefix[0] = 0x2028;
    opts->prefix_len = 1;
    opts->threads = default_thread_count();
    opts->candidate_count = 12u;
    opts->h_count = 8u;
    opts->low_top_count = 16u;
    opts->top_count = 5u;
    opts->full_search = 0;
    opts->inject_true = 1;
    opts->validate = 1;
    opts->seed = 0x53455041ULL;
}

static int parse_args(int argc, char **argv, Options *opts)
{
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--prefix") == 0 && i + 1 < argc) {
            if (!parse_prefix_words(argv[++i], opts->prefix, &opts->prefix_len)) {
                fprintf(stderr, "failed to parse --prefix\n");
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            if (!parse_fixed_hex_words(argv[++i], opts->key, 16u)) {
                fprintf(stderr, "failed to parse --key\n");
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--iv") == 0 && i + 1 < argc) {
            if (!parse_fixed_hex_words(argv[++i], opts->iv, 8u)) {
                fprintf(stderr, "failed to parse --iv\n");
                return -1;
            }
            continue;
        }
        if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            opts->threads = (unsigned)strtoul(argv[++i], NULL, 10);
            if (opts->threads == 0u) {
                opts->threads = 1u;
            }
            continue;
        }
        if (strcmp(argv[i], "--candidate-count") == 0 && i + 1 < argc) {
            opts->candidate_count = (size_t)strtoull(argv[++i], NULL, 10);
            continue;
        }
        if (strcmp(argv[i], "--h-count") == 0 && i + 1 < argc) {
            opts->h_count = (size_t)strtoull(argv[++i], NULL, 10);
            continue;
        }
        if (strcmp(argv[i], "--low-top") == 0 && i + 1 < argc) {
            opts->low_top_count = (size_t)strtoull(argv[++i], NULL, 10);
            continue;
        }
        if (strcmp(argv[i], "--top") == 0 && i + 1 < argc) {
            opts->top_count = (size_t)strtoull(argv[++i], NULL, 10);
            if (opts->top_count == 0u) {
                opts->top_count = 1u;
            }
            if (opts->top_count > MAX_TOP_RESULTS) {
                opts->top_count = MAX_TOP_RESULTS;
            }
            continue;
        }
        if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            opts->seed = _strtoui64(argv[++i], NULL, 0);
            continue;
        }
        if (strcmp(argv[i], "--full-search") == 0) {
            opts->full_search = 1;
            continue;
        }
        if (strcmp(argv[i], "--no-inject-true") == 0) {
            opts->inject_true = 0;
            continue;
        }
        if (strcmp(argv[i], "--skip-validation") == 0) {
            opts->validate = 0;
            continue;
        }
        fprintf(stderr, "unknown argument: %s\n", argv[i]);
        return -1;
    }
    if (opts->candidate_count == 0u && !opts->full_search) {
        opts->candidate_count = 1u;
    }
    if (opts->h_count == 0u) {
        opts->h_count = 1u;
    }
    if (opts->low_top_count == 0u) {
        opts->low_top_count = 1u;
    }
    return 1;
}

static void separ_initial_state(SeparCtx *ctx, const uint16_t key[16], const uint16_t iv[8])
{
    int round;
    uint16_t v12 = 0;
    uint16_t v23 = 0;
    uint16_t v34 = 0;
    uint16_t v45 = 0;
    uint16_t v56 = 0;
    uint16_t v67 = 0;
    uint16_t v78 = 0;
    uint16_t ct = 0;

    memcpy(ctx->state, iv, sizeof(uint16_t) * STATE_COUNT);

    for (round = 0; round < 4; round++) {
        v12 = enc_block((uint16_t)(ctx->state[0] + ctx->state[2] + ctx->state[4] + ctx->state[6]), stage_pair_from_full_key(key, 1), 1);
        v23 = enc_block((uint16_t)(v12 + ctx->state[1]), stage_pair_from_full_key(key, 2), 2);
        v34 = enc_block((uint16_t)(v23 + ctx->state[2]), stage_pair_from_full_key(key, 3), 3);
        v45 = enc_block((uint16_t)(v34 + ctx->state[3]), stage_pair_from_full_key(key, 4), 4);
        v56 = enc_block((uint16_t)(v45 + ctx->state[4]), stage_pair_from_full_key(key, 5), 5);
        v67 = enc_block((uint16_t)(v56 + ctx->state[5]), stage_pair_from_full_key(key, 6), 6);
        v78 = enc_block((uint16_t)(v67 + ctx->state[6]), stage_pair_from_full_key(key, 7), 7);
        ct = enc_block((uint16_t)(v78 + ctx->state[7]), stage_pair_from_full_key(key, 8), 8);

        ctx->state[0] = (uint16_t)(ctx->state[0] + ct);
        ctx->state[1] = (uint16_t)(ctx->state[1] + v12);
        ctx->state[2] = (uint16_t)(ctx->state[2] + v23);
        ctx->state[3] = (uint16_t)(ctx->state[3] + v34);
        ctx->state[4] = (uint16_t)(ctx->state[4] + v45);
        ctx->state[5] = (uint16_t)(ctx->state[5] + v56);
        ctx->state[6] = (uint16_t)(ctx->state[6] + v67);
        ctx->state[7] = (uint16_t)(ctx->state[7] + v78);
    }
    ctx->lfsr = (uint16_t)(ct | 0x100u);
}

static uint16_t separ_encrypt_word(uint16_t pt, SeparCtx *ctx, const uint16_t key[16])
{
    uint16_t v12;
    uint16_t v23;
    uint16_t v34;
    uint16_t v45;
    uint16_t v56;
    uint16_t v67;
    uint16_t v78;
    uint16_t ct;

    v12 = enc_block((uint16_t)(pt + ctx->state[0]), stage_pair_from_full_key(key, 1), 1);
    v23 = enc_block((uint16_t)(v12 + ctx->state[1]), stage_pair_from_full_key(key, 2), 2);
    v34 = enc_block((uint16_t)(v23 + ctx->state[2]), stage_pair_from_full_key(key, 3), 3);
    v45 = enc_block((uint16_t)(v34 + ctx->state[3]), stage_pair_from_full_key(key, 4), 4);
    v56 = enc_block((uint16_t)(v45 + ctx->state[4]), stage_pair_from_full_key(key, 5), 5);
    v67 = enc_block((uint16_t)(v56 + ctx->state[5]), stage_pair_from_full_key(key, 6), 6);
    v78 = enc_block((uint16_t)(v67 + ctx->state[6]), stage_pair_from_full_key(key, 7), 7);
    ct = enc_block((uint16_t)(v78 + ctx->state[7]), stage_pair_from_full_key(key, 8), 8);

    ctx->state[1] = (uint16_t)(ctx->state[1] + v12 + v56 + ctx->state[5]);
    ctx->state[2] = (uint16_t)(ctx->state[2] + v23 + v34 + ctx->state[3] + ctx->state[0]);
    ctx->state[3] = (uint16_t)(ctx->state[3] + v12 + v45 + ctx->state[7]);
    ctx->state[4] = (uint16_t)(ctx->state[4] + v23);
    ctx->state[5] = (uint16_t)(ctx->state[5] + v12 + v45 + ctx->state[6]);
    ctx->state[6] = (uint16_t)(ctx->state[6] + v23 + v67);
    ctx->state[7] = (uint16_t)(ctx->state[7] + v45);
    ctx->state[0] = (uint16_t)(ctx->state[0] + v34 + v23 + ctx->state[4] + v78);

    ctx->lfsr = (uint16_t)((ctx->lfsr >> 1) ^ ((uint16_t)(-(int32_t)(ctx->lfsr & 1u)) & 0xCA44u));
    ctx->state[4] = (uint16_t)(ctx->state[4] + ctx->lfsr);
    return ct;
}

static void separ_ctx_after_prefix(SeparCtx *ctx, const uint16_t key[16], const uint16_t iv[8], const uint16_t *prefix, size_t prefix_len)
{
    size_t i;
    separ_initial_state(ctx, key, iv);
    for (i = 0; i < prefix_len; i++) {
        (void)separ_encrypt_word(prefix[i], ctx, key);
    }
}

static void build_next_word_codebook(uint16_t *table, const SeparCtx *ctx, const uint16_t key[16], int show_progress)
{
    uint32_t x;
    for (x = 0; x < TABLE_SIZE; x++) {
        uint16_t v12;
        uint16_t v23;
        uint16_t v34;
        uint16_t v45;
        uint16_t v56;
        uint16_t v67;
        uint16_t v78;
        v12 = enc_block((uint16_t)(x + ctx->state[0]), stage_pair_from_full_key(key, 1), 1);
        v23 = enc_block((uint16_t)(v12 + ctx->state[1]), stage_pair_from_full_key(key, 2), 2);
        v34 = enc_block((uint16_t)(v23 + ctx->state[2]), stage_pair_from_full_key(key, 3), 3);
        v45 = enc_block((uint16_t)(v34 + ctx->state[3]), stage_pair_from_full_key(key, 4), 4);
        v56 = enc_block((uint16_t)(v45 + ctx->state[4]), stage_pair_from_full_key(key, 5), 5);
        v67 = enc_block((uint16_t)(v56 + ctx->state[5]), stage_pair_from_full_key(key, 6), 6);
        v78 = enc_block((uint16_t)(v67 + ctx->state[6]), stage_pair_from_full_key(key, 7), 7);
        table[x] = enc_block((uint16_t)(v78 + ctx->state[7]), stage_pair_from_full_key(key, 8), 8);
        if (show_progress && (x & 0x01FFu) == 0u) {
            printf("\r[codebook] %" PRIu32 "/65536", x);
            fflush(stdout);
        }
    }
    if (show_progress) {
        printf("\r[codebook] 65536/65536\n");
    }
}

static void build_true_reduced_tables(uint16_t **tables, const uint16_t key[16], const SeparCtx *ctx)
{
    uint8_t stage;
    build_next_word_codebook(tables[8], ctx, key, 0);
    for (stage = 8; stage >= 1; stage--) {
        uint32_t x;
        KeyPair pair = stage_pair_from_full_key(key, stage);
        for (x = 0; x < TABLE_SIZE; x++) {
            tables[stage - 1][x] = (uint16_t)(dec_block(tables[stage][x], pair, stage) - ctx->state[stage - 1u]);
        }
        if (stage == 1u) {
            break;
        }
    }
}

static void print_truth(const uint16_t key[16], const SeparCtx *ctx)
{
    uint8_t stage;
    printf("True stage keys and current matched-context states:\n");
    for (stage = 1; stage <= 8; stage++) {
        KeyPair pair = stage_pair_from_full_key(key, stage);
        printf("  K%u = ", stage);
        print_pair(pair);
        printf("   s%u = %04X (low=%02X high=%02X)\n",
               stage,
               ctx->state[stage - 1u],
               (unsigned)(ctx->state[stage - 1u] & 0x00FFu),
               (unsigned)(ctx->state[stage - 1u] >> 8));
    }
    printf("\n");
}

static uint64_t additive_score_table(const uint16_t *table,
                                     const uint16_t *diffs,
                                     size_t diff_count,
                                     uint32_t *counts,
                                     uint16_t *touched,
                                     uint16_t *best_outs,
                                     uint32_t *best_counts)
{
    uint64_t score = 0;
    size_t touched_count = 0;
    size_t diff_idx;
    uint32_t x;

    for (diff_idx = 0; diff_idx < diff_count; diff_idx++) {
        uint16_t delta = diffs[diff_idx];
        uint32_t best_count = 0;
        uint16_t best_out = 0;
        size_t i;

        for (i = 0; i < touched_count; i++) {
            counts[touched[i]] = 0;
        }
        touched_count = 0;

        for (x = 0; x < TABLE_SIZE; x++) {
            uint16_t out = (uint16_t)(table[(x + delta) & 0xFFFFu] - table[x]);
            uint32_t new_count = counts[out] + 1u;
            if (counts[out] == 0u) {
                touched[touched_count++] = out;
            }
            counts[out] = new_count;
            if (new_count > best_count || (new_count == best_count && out < best_out)) {
                best_count = new_count;
                best_out = out;
            }
        }
        if (best_outs != NULL) {
            best_outs[diff_idx] = best_out;
        }
        if (best_counts != NULL) {
            best_counts[diff_idx] = best_count;
        }
        score += best_count;
    }
    for (size_t i = 0; i < touched_count; i++) {
        counts[touched[i]] = 0;
    }
    return score;
}

static uint64_t additive_score_after_key(const uint16_t *source_table,
                                         KeyPair pair,
                                         uint8_t stage,
                                         const uint16_t *diffs,
                                         size_t diff_count,
                                         uint16_t *scratch,
                                         uint32_t *counts,
                                         uint16_t *touched)
{
    uint32_t x;
    for (x = 0; x < TABLE_SIZE; x++) {
        scratch[x] = dec_block(source_table[x], pair, stage);
    }
    return additive_score_table(scratch, diffs, diff_count, counts, touched, NULL, NULL);
}

static uint64_t additive_score_after_key_detailed(const uint16_t *source_table,
                                                  KeyPair pair,
                                                  uint8_t stage,
                                                  const uint16_t *diffs,
                                                  size_t diff_count,
                                                  uint16_t *scratch,
                                                  uint32_t *counts,
                                                  uint16_t *touched,
                                                  uint16_t *best_outs,
                                                  uint32_t *best_counts)
{
    uint32_t x;
    for (x = 0; x < TABLE_SIZE; x++) {
        scratch[x] = dec_block(source_table[x], pair, stage);
    }
    return additive_score_table(scratch, diffs, diff_count, counts, touched, best_outs, best_counts);
}

static KeyPair pair_from_index(uint64_t index)
{
    KeyPair pair;
    uint32_t value = (uint32_t)index;
    pair.k0 = (uint16_t)(value >> 16);
    pair.k1 = (uint16_t)(value & 0xFFFFu);
    return pair;
}

static DWORD WINAPI key_search_worker(LPVOID param)
{
    KeyWorker *worker = (KeyWorker *)param;
    KeySearchPlan *plan = worker->plan;
    KeyTopList *local = &plan->worker_results[worker->worker_index];
    uint16_t *scratch = (uint16_t *)malloc(TABLE_SIZE * sizeof(uint16_t));
    uint16_t *touched = (uint16_t *)malloc(TABLE_SIZE * sizeof(uint16_t));
    uint32_t *counts = (uint32_t *)calloc(TABLE_SIZE, sizeof(uint32_t));
    uint64_t idx;
    uint64_t pending = 0;

    if (scratch == NULL || touched == NULL || counts == NULL) {
        fprintf(stderr, "worker allocation failed\n");
        free(scratch);
        free(touched);
        free(counts);
        atomic_fetch_add_explicit(&plan->finished_workers, 1, memory_order_relaxed);
        return 0;
    }

    for (idx = worker->start; idx < worker->end; idx++) {
        KeyPair pair = plan->exhaustive ? pair_from_index(idx) : plan->candidate_pairs[idx];
        KeyScore result;
        result.pair = pair;
        result.score = additive_score_after_key(plan->source_table,
                                                pair,
                                                plan->stage,
                                                plan->diffs,
                                                plan->diff_count,
                                                scratch,
                                                counts,
                                                touched);
        insert_key_top(local, result);
        pending++;
        if (pending >= plan->candidate_chunk) {
            atomic_fetch_add_explicit(&plan->progress, pending, memory_order_relaxed);
            pending = 0;
        }
    }
    if (pending != 0) {
        atomic_fetch_add_explicit(&plan->progress, pending, memory_order_relaxed);
    }

    free(scratch);
    free(touched);
    free(counts);
    atomic_fetch_add_explicit(&plan->finished_workers, 1, memory_order_relaxed);
    return 0;
}

static void merge_key_toplists(KeyTopList *dst, const KeyTopList *src)
{
    size_t i;
    for (i = 0; i < src->count; i++) {
        insert_key_top(dst, src->items[i]);
    }
}

static void print_progress_bar(const char *label, uint64_t done, uint64_t total)
{
    printf("\r[%s] %" PRIu64 "/%" PRIu64, label, done, total);
    fflush(stdout);
}

static void run_key_search(const uint16_t *table,
                           uint8_t stage,
                           const uint16_t *diffs,
                           size_t diff_count,
                           const CandidateSet *candidates,
                           int exhaustive,
                           unsigned threads,
                           size_t topn,
                           const char *label,
                           int show_progress,
                           KeyTopList *result)
{
    KeySearchPlan plan;
    KeyWorker *workers;
    HANDLE *handles;
    size_t worker_count;
    uint64_t total_candidates = exhaustive ? (1ULL << 32) : (uint64_t)candidates->count;
    size_t i;

    memset(&plan, 0, sizeof(plan));
    plan.source_table = table;
    plan.stage = stage;
    plan.diffs = diffs;
    plan.diff_count = diff_count;
    plan.candidate_pairs = exhaustive ? NULL : candidates->pairs;
    plan.total_candidates = total_candidates;
    plan.exhaustive = exhaustive;
    atomic_init(&plan.progress, 0);
    atomic_init(&plan.finished_workers, 0);
    plan.topn = topn;
    plan.candidate_chunk = exhaustive ? 64u : 1u;

    worker_count = threads == 0u ? 1u : threads;
    if (worker_count > total_candidates) {
        worker_count = (size_t)total_candidates;
    }
    if (worker_count == 0u) {
        worker_count = 1u;
    }
    plan.worker_count = worker_count;
    plan.worker_results = (KeyTopList *)calloc(worker_count, sizeof(KeyTopList));
    workers = (KeyWorker *)calloc(worker_count, sizeof(KeyWorker));
    handles = (HANDLE *)calloc(worker_count, sizeof(HANDLE));
    if (plan.worker_results == NULL || workers == NULL || handles == NULL) {
        fprintf(stderr, "search allocation failed\n");
        exit(1);
    }

    for (i = 0; i < worker_count; i++) {
        uint64_t start = (total_candidates * i) / worker_count;
        uint64_t end = (total_candidates * (i + 1u)) / worker_count;
        init_key_toplist(&plan.worker_results[i], topn);
        workers[i].plan = &plan;
        workers[i].worker_index = i;
        workers[i].start = start;
        workers[i].end = end;
        handles[i] = CreateThread(NULL, 0, key_search_worker, &workers[i], 0, NULL);
        if (handles[i] == NULL) {
            fprintf(stderr, "failed to create worker thread\n");
            exit(1);
        }
    }

    if (show_progress) {
        while ((size_t)atomic_load_explicit(&plan.finished_workers, memory_order_relaxed) < worker_count) {
            uint64_t done = atomic_load_explicit(&plan.progress, memory_order_relaxed);
            print_progress_bar(label, done, total_candidates);
            Sleep(100);
        }
    }

    WaitForMultipleObjects((DWORD)worker_count, handles, TRUE, INFINITE);
    if (show_progress) {
        uint64_t done = atomic_load_explicit(&plan.progress, memory_order_relaxed);
        print_progress_bar(label, done, total_candidates);
        printf("\n");
    }

    init_key_toplist(result, topn);
    for (i = 0; i < worker_count; i++) {
        CloseHandle(handles[i]);
        merge_key_toplists(result, &plan.worker_results[i]);
        free_key_toplist(&plan.worker_results[i]);
    }

    free(plan.worker_results);
    free(handles);
    free(workers);
}

static void print_key_search_results(const char *title,
                                     const KeyTopList *results,
                                     const uint16_t *table,
                                     uint8_t stage,
                                     const uint16_t *diffs,
                                     size_t diff_count,
                                     KeyPair true_pair,
                                     size_t limit)
{
    size_t i;
    uint16_t *scratch = (uint16_t *)malloc(TABLE_SIZE * sizeof(uint16_t));
    uint16_t *touched = (uint16_t *)malloc(TABLE_SIZE * sizeof(uint16_t));
    uint32_t *counts = (uint32_t *)calloc(TABLE_SIZE, sizeof(uint32_t));
    uint16_t *best_outs = (uint16_t *)calloc(diff_count, sizeof(uint16_t));
    uint32_t *best_counts = (uint32_t *)calloc(diff_count, sizeof(uint32_t));
    if (scratch == NULL || touched == NULL || counts == NULL || best_outs == NULL || best_counts == NULL) {
        fprintf(stderr, "print_key_search_results allocation failed\n");
        exit(1);
    }

    printf("%s\n", title);
    for (i = 0; i < results->count && i < limit; i++) {
        uint64_t score = additive_score_after_key_detailed(table,
                                                           results->items[i].pair,
                                                           stage,
                                                           diffs,
                                                           diff_count,
                                                           scratch,
                                                           counts,
                                                           touched,
                                                           best_outs,
                                                           best_counts);
        size_t d;
        printf("  #%zu ", i + 1u);
        print_pair(results->items[i].pair);
        printf(" score=%" PRIu64, score);
        if (pair_equal(results->items[i].pair, true_pair)) {
            printf("  <-- true");
        }
        printf("\n");
        for (d = 0; d < diff_count; d++) {
            printf("      add in=%04X best out=%04X count=%" PRIu32 " prob=%.8f\n",
                   diffs[d],
                   best_outs[d],
                   best_counts[d],
                   best_counts[d] / 65536.0);
        }
    }
    printf("\n");

    free(scratch);
    free(touched);
    free(counts);
    free(best_outs);
    free(best_counts);
}

static void peel_table_with_key(uint16_t *dst, const uint16_t *src, KeyPair pair, uint8_t stage)
{
    uint32_t x;
    for (x = 0; x < TABLE_SIZE; x++) {
        dst[x] = dec_block(src[x], pair, stage);
    }
}

static void subtract_translation(uint16_t *dst, const uint16_t *src, uint16_t value)
{
    uint32_t x;
    for (x = 0; x < TABLE_SIZE; x++) {
        dst[x] = (uint16_t)(src[x] - value);
    }
}

static void scan_low_candidates(const uint16_t *peeled_table, size_t topn, LowTopList *results)
{
    uint16_t seen[256];
    uint16_t epoch = 1u;
    uint8_t row_idx;
    uint16_t low;
    init_low_toplist(results, topn);

    memset(seen, 0, sizeof(seen));
    for (low = 0; low < 256u; low++) {
        LowScore candidate;
        candidate.total_support = 0;
        candidate.low = (uint8_t)low;

        for (row_idx = 0; row_idx < 4u; row_idx++) {
            uint16_t count = 0;
            uint16_t lo;
            uint16_t mark = epoch++;
            uint32_t base = ((uint32_t)support_rows[row_idx]) << 8;
            for (lo = 0; lo < 256u; lo++) {
                uint8_t upper = (uint8_t)(((uint16_t)(peeled_table[base | lo] - low)) >> 8);
                if (seen[upper] != mark) {
                    seen[upper] = mark;
                    count++;
                }
            }
            candidate.support_rows[row_idx] = (uint8_t)count;
            candidate.total_support += count;
        }
        insert_low_top(results, candidate);
    }
}

static void print_low_candidates(const LowTopList *results, uint8_t true_low)
{
    size_t i;
    printf("  Top low-byte candidates by carry/support score:\n");
    for (i = 0; i < results->count; i++) {
        const LowScore *item = &results->items[i];
        printf("    #%zu low=%02X total_support=%" PRIu32 " rows=(%u,%u,%u,%u)",
               i + 1u,
               item->low,
               item->total_support,
               item->support_rows[0],
               item->support_rows[1],
               item->support_rows[2],
               item->support_rows[3]);
        if (item->low == true_low) {
            printf("  <-- true");
        }
        printf("\n");
    }
    printf("\n");
}

static CandidateSet build_key_candidates(KeyPair true_pair, size_t count, int inject_true, uint64_t *seed)
{
    CandidateSet set;
    size_t target = count == 0u ? 1u : count;
    size_t index = 0;
    set.pairs = (KeyPair *)calloc(target, sizeof(KeyPair));
    set.count = 0;
    if (set.pairs == NULL) {
        fprintf(stderr, "candidate allocation failed\n");
        exit(1);
    }

    if (inject_true && index < target) {
        set.pairs[index++] = true_pair;
    }
    if (index < target) {
        KeyPair near_pair = true_pair;
        near_pair.k1 ^= 0x0001u;
        if (!pair_equal(near_pair, true_pair)) {
            set.pairs[index++] = near_pair;
        }
    }
    if (index < target) {
        set.pairs[index++] = (KeyPair){0x1111u, 0x2222u};
    }
    if (index < target) {
        set.pairs[index++] = (KeyPair){0x0000u, 0x0000u};
    }
    if (index < target) {
        set.pairs[index++] = (KeyPair){0xBEEFu, 0x1234u};
    }

    while (index < target) {
        KeyPair pair;
        int duplicate = 0;
        size_t j;
        uint64_t r = splitmix64(seed);
        pair.k0 = (uint16_t)(r >> 48);
        pair.k1 = (uint16_t)(r >> 16);
        for (j = 0; j < index; j++) {
            if (pair_equal(pair, set.pairs[j])) {
                duplicate = 1;
                break;
            }
        }
        if (!duplicate) {
            set.pairs[index++] = pair;
        }
    }
    set.count = target;
    return set;
}

static HighCandidateSet build_high_candidates(uint8_t true_high, size_t count, int inject_true, uint64_t *seed)
{
    HighCandidateSet set;
    size_t target = count == 0u ? 1u : count;
    size_t index = 0;
    set.values = (uint8_t *)calloc(target, sizeof(uint8_t));
    set.count = 0;
    if (set.values == NULL) {
        fprintf(stderr, "high-candidate allocation failed\n");
        exit(1);
    }

    #define ADD_HIGH_CANDIDATE(value_expr)                                                     \
        do {                                                                                   \
            uint8_t candidate_value = (uint8_t)(value_expr);                                   \
            size_t candidate_index;                                                            \
            int duplicate = 0;                                                                 \
            for (candidate_index = 0; candidate_index < index; candidate_index++) {            \
                if (set.values[candidate_index] == candidate_value) {                          \
                    duplicate = 1;                                                             \
                    break;                                                                     \
                }                                                                              \
            }                                                                                  \
            if (!duplicate && index < target) {                                                \
                set.values[index++] = candidate_value;                                         \
            }                                                                                  \
        } while (0)

    if (inject_true) {
        ADD_HIGH_CANDIDATE(true_high);
    }
    ADD_HIGH_CANDIDATE((uint8_t)(true_high ^ 0x01u));
    ADD_HIGH_CANDIDATE((uint8_t)(true_high ^ 0x20u));
    ADD_HIGH_CANDIDATE((uint8_t)(true_high + 1u));
    ADD_HIGH_CANDIDATE((uint8_t)(true_high - 1u));
    ADD_HIGH_CANDIDATE(0x00u);
    ADD_HIGH_CANDIDATE(0xFFu);
    ADD_HIGH_CANDIDATE(0x30u);
    #undef ADD_HIGH_CANDIDATE

    while (index < target) {
        uint8_t value = (uint8_t)(splitmix64(seed) & 0xFFu);
        size_t j;
        int duplicate = 0;
        for (j = 0; j < index; j++) {
            if (set.values[j] == value) {
                duplicate = 1;
                break;
            }
        }
        if (!duplicate) {
            set.values[index++] = value;
        }
    }
    set.count = target;
    return set;
}

static void free_candidates(CandidateSet *set)
{
    free(set->pairs);
    set->pairs = NULL;
    set->count = 0;
}

static void free_high_candidates(HighCandidateSet *set)
{
    free(set->values);
    set->values = NULL;
    set->count = 0;
}

static size_t key_rank_in_results(const KeyTopList *results, KeyPair target)
{
    size_t i;
    for (i = 0; i < results->count; i++) {
        if (pair_equal(results->items[i].pair, target)) {
            return i + 1u;
        }
    }
    return 0u;
}

static int validate_roundtrip(const uint16_t key[16], const uint16_t iv[8])
{
    SeparCtx ctx_enc;
    SeparCtx ctx_dec;
    uint32_t i;
    separ_initial_state(&ctx_enc, key, iv);
    separ_initial_state(&ctx_dec, key, iv);
    for (i = 0; i < 64u; i++) {
        uint16_t pt = (uint16_t)(i * 997u + 0x1234u);
        uint16_t ct = separ_encrypt_word(pt, &ctx_enc, key);
        uint16_t back;
        uint16_t v78;
        uint16_t v67;
        uint16_t v56;
        uint16_t v45;
        uint16_t v34;
        uint16_t v23;
        uint16_t v12;
        v78 = (uint16_t)(dec_block(ct, stage_pair_from_full_key(key, 8), 8) - ctx_dec.state[7]);
        v67 = (uint16_t)(dec_block(v78, stage_pair_from_full_key(key, 7), 7) - ctx_dec.state[6]);
        v56 = (uint16_t)(dec_block(v67, stage_pair_from_full_key(key, 6), 6) - ctx_dec.state[5]);
        v45 = (uint16_t)(dec_block(v56, stage_pair_from_full_key(key, 5), 5) - ctx_dec.state[4]);
        v34 = (uint16_t)(dec_block(v45, stage_pair_from_full_key(key, 4), 4) - ctx_dec.state[3]);
        v23 = (uint16_t)(dec_block(v34, stage_pair_from_full_key(key, 3), 3) - ctx_dec.state[2]);
        v12 = (uint16_t)(dec_block(v23, stage_pair_from_full_key(key, 2), 2) - ctx_dec.state[1]);
        back = (uint16_t)(dec_block(v12, stage_pair_from_full_key(key, 1), 1) - ctx_dec.state[0]);
        if (back != pt) {
            return 0;
        }
        ctx_dec.state[1] = (uint16_t)(ctx_dec.state[1] + v12 + v56 + ctx_dec.state[5]);
        ctx_dec.state[2] = (uint16_t)(ctx_dec.state[2] + v23 + v34 + ctx_dec.state[3] + ctx_dec.state[0]);
        ctx_dec.state[3] = (uint16_t)(ctx_dec.state[3] + v12 + v45 + ctx_dec.state[7]);
        ctx_dec.state[4] = (uint16_t)(ctx_dec.state[4] + v23);
        ctx_dec.state[5] = (uint16_t)(ctx_dec.state[5] + v12 + v45 + ctx_dec.state[6]);
        ctx_dec.state[6] = (uint16_t)(ctx_dec.state[6] + v23 + v67);
        ctx_dec.state[7] = (uint16_t)(ctx_dec.state[7] + v45);
        ctx_dec.state[0] = (uint16_t)(ctx_dec.state[0] + v34 + v23 + ctx_dec.state[4] + v78);
        ctx_dec.lfsr = (uint16_t)((ctx_dec.lfsr >> 1) ^ ((uint16_t)(-(int32_t)(ctx_dec.lfsr & 1u)) & 0xCA44u));
        ctx_dec.state[4] = (uint16_t)(ctx_dec.state[4] + ctx_dec.lfsr);
    }
    return 1;
}

static int validate_reference_k8(void)
{
    SeparCtx ctx;
    uint16_t *table = (uint16_t *)malloc(TABLE_SIZE * sizeof(uint16_t));
    CandidateSet candidates;
    KeyTopList results;
    KeyPair true_k8 = {default_key[14], default_key[15]};
    uint64_t seed = 0;
    size_t rank;

    if (table == NULL) {
        return 0;
    }
    separ_ctx_after_prefix(&ctx, default_key, default_iv, (const uint16_t[]){0x2028u}, 1u);
    build_next_word_codebook(table, &ctx, default_key, 0);

    candidates = build_key_candidates(true_k8, 5u, 1, &seed);
    candidates.pairs[1] = (KeyPair){0x1111u, 0x2222u};
    candidates.pairs[2] = (KeyPair){0x0000u, 0x0000u};
    candidates.pairs[3] = (KeyPair){0xBEEFu, 0x1234u};
    candidates.pairs[4] = (KeyPair){0xFC7Du, 0x6370u};

    run_key_search(table,
                   8u,
                   default_diffs,
                   sizeof(default_diffs) / sizeof(default_diffs[0]),
                   &candidates,
                   0,
                   1u,
                   5u,
                   "ref-k8",
                   0,
                   &results);
    rank = key_rank_in_results(&results, true_k8);
    if (rank == 0u || results.items[0].score != 2292u || !pair_equal(results.items[0].pair, true_k8)) {
        uint16_t sample_after[8];
        uint32_t idx;
        printf("    observed state =");
        for (idx = 0; idx < 8u; idx++) {
            printf(" %04X", ctx.state[idx]);
        }
        printf("\n    observed codebook0..7 =");
        for (idx = 0; idx < 8u; idx++) {
            printf(" %04X", table[idx]);
            sample_after[idx] = dec_block(table[idx], true_k8, 8u);
        }
        printf("\n    observed afterk80..7 =");
        for (idx = 0; idx < 8u; idx++) {
            printf(" %04X", sample_after[idx]);
        }
        printf("\n");
        printf("    observed top K8 = ");
        if (results.count > 0) {
            print_pair(results.items[0].pair);
            printf(" score=%" PRIu64 "\n", results.items[0].score);
        } else {
            printf("(none)\n");
        }
        free(table);
        free_key_toplist(&results);
        free_candidates(&candidates);
        return 0;
    }
    free(table);
    free_key_toplist(&results);
    free_candidates(&candidates);
    return 1;
}

static int validate_reference_click(void)
{
    SeparCtx ctx;
    uint16_t *table = (uint16_t *)malloc(TABLE_SIZE * sizeof(uint16_t));
    uint16_t *after_k8 = (uint16_t *)malloc(TABLE_SIZE * sizeof(uint16_t));
    uint16_t *aligned = (uint16_t *)malloc(TABLE_SIZE * sizeof(uint16_t));
    CandidateSet k7_candidates;
    KeyTopList results;
    KeyPair true_k7 = {default_key[12], default_key[13]};
    KeyPair true_k8 = {default_key[14], default_key[15]};
    uint8_t h_candidates[] = {0x10u, 0x0Fu, 0x11u, 0x00u, 0xFFu, 0x30u};
    uint16_t low;
    size_t h_idx;
    uint64_t best_score = 0;
    uint8_t best_h = 0;
    KeyPair best_pair = {0, 0};

    if (table == NULL || after_k8 == NULL || aligned == NULL) {
        free(table);
        free(after_k8);
        free(aligned);
        return 0;
    }

    separ_ctx_after_prefix(&ctx, default_key, default_iv, (const uint16_t[]){0x2028u}, 1u);
    build_next_word_codebook(table, &ctx, default_key, 0);
    peel_table_with_key(after_k8, table, true_k8, 8u);
    low = (uint16_t)(ctx.state[7] & 0x00FFu);

    k7_candidates = build_key_candidates(true_k7, 5u, 1, &(uint64_t){1u});
    k7_candidates.pairs[1] = (KeyPair){0x1111u, 0x2222u};
    k7_candidates.pairs[2] = (KeyPair){0x0000u, 0x0000u};
    k7_candidates.pairs[3] = (KeyPair){0xBEEFu, 0x1234u};
    k7_candidates.pairs[4] = (KeyPair){0x8D1Eu, 0x9DF4u};

    for (h_idx = 0; h_idx < sizeof(h_candidates) / sizeof(h_candidates[0]); h_idx++) {
        uint32_t x;
        uint16_t translation = (uint16_t)(low + ((uint16_t)h_candidates[h_idx] << 8));
        for (x = 0; x < TABLE_SIZE; x++) {
            aligned[x] = (uint16_t)(after_k8[x] - translation);
        }
        run_key_search(aligned,
                       7u,
                       default_diffs,
                       sizeof(default_diffs) / sizeof(default_diffs[0]),
                       &k7_candidates,
                       0,
                       1u,
                       1u,
                       "ref-click",
                       0,
                       &results);
        if (results.count > 0 && (results.items[0].score > best_score ||
                                  (results.items[0].score == best_score && h_candidates[h_idx] < best_h))) {
            best_score = results.items[0].score;
            best_h = h_candidates[h_idx];
            best_pair = results.items[0].pair;
        }
        free_key_toplist(&results);
    }

    free_candidates(&k7_candidates);
    free(table);
    free(after_k8);
    free(aligned);
    if (!(best_score == 3303u && best_h == 0x10u && pair_equal(best_pair, true_k7))) {
        printf("    observed best h=%02X best K7=", best_h);
        print_pair(best_pair);
        printf(" score=%" PRIu64 "\n", best_score);
        return 0;
    }
    return 1;
}

static int run_validation_checks(const Options *opts)
{
    int ok = 1;
    printf("Validation checks:\n");
    printf("  local roundtrip: ");
    if (validate_roundtrip(opts->key, opts->iv)) {
        printf("PASS\n");
    } else {
        printf("FAIL\n");
        ok = 0;
    }

    if (is_default_key(opts->key) && is_default_iv(opts->iv) &&
        opts->prefix_len == 1u && opts->prefix[0] == 0x2028u) {
        printf("  reference K8 differential score (expect true top at 2292): ");
        if (validate_reference_k8()) {
            printf("PASS\n");
        } else {
            printf("FAIL\n");
            ok = 0;
        }
        printf("  reference stage-7 click score (expect h=10, K7 true, score 3303): ");
        if (validate_reference_click()) {
            printf("PASS\n");
        } else {
            printf("FAIL\n");
            ok = 0;
        }
    } else {
        printf("  reference default-key checks: skipped (custom key/IV/prefix)\n");
    }
    printf("\n");
    return ok;
}

static void compare_table_alignment(const char *label, const uint16_t *lhs, const uint16_t *rhs)
{
    if (memcmp(lhs, rhs, TABLE_SIZE * sizeof(uint16_t)) == 0) {
        printf("  %s: exact table alignment PASS\n", label);
    } else {
        uint32_t idx;
        for (idx = 0; idx < TABLE_SIZE; idx++) {
            if (lhs[idx] != rhs[idx]) {
                printf("  %s: exact table alignment FAIL at x=%04X recovered=%04X true=%04X\n",
                       label, idx, lhs[idx], rhs[idx]);
                break;
            }
        }
    }
}

static void print_stage_separator(uint8_t stage)
{
    printf("============================================================\n");
    printf("Stage %u\n", stage);
    printf("============================================================\n");
}

static void run_recursive_attack(const Options *opts)
{
    SeparCtx ctx;
    uint16_t *current_table = (uint16_t *)malloc(TABLE_SIZE * sizeof(uint16_t));
    uint16_t *work_table = (uint16_t *)malloc(TABLE_SIZE * sizeof(uint16_t));
    uint16_t *aligned_table = (uint16_t *)malloc(TABLE_SIZE * sizeof(uint16_t));
    uint16_t **true_tables = NULL;
    CandidateSet stage_candidates[9];
    AttackResult recovered;
    KeyPair current_key = {0, 0};
    uint64_t seed = opts->seed;
    uint8_t stage;
    int current_key_is_known = 0;

    if (current_table == NULL || work_table == NULL || aligned_table == NULL) {
        fprintf(stderr, "table allocation failed\n");
        exit(1);
    }

    memset(&recovered, 0, sizeof(recovered));
    memset(stage_candidates, 0, sizeof(stage_candidates));

    separ_ctx_after_prefix(&ctx, opts->key, opts->iv, opts->prefix, opts->prefix_len);
    build_next_word_codebook(current_table, &ctx, opts->key, 1);
    print_truth(opts->key, &ctx);

    true_tables = (uint16_t **)calloc(9u, sizeof(uint16_t *));
    if (true_tables == NULL) {
        fprintf(stderr, "true table allocation failed\n");
        exit(1);
    }
    for (stage = 0; stage <= 8; stage++) {
        true_tables[stage] = (uint16_t *)malloc(TABLE_SIZE * sizeof(uint16_t));
        if (true_tables[stage] == NULL) {
            fprintf(stderr, "true table allocation failed\n");
            exit(1);
        }
    }
    build_true_reduced_tables(true_tables, opts->key, &ctx);

    if (!opts->full_search) {
        for (stage = 1; stage <= 8; stage++) {
            stage_candidates[stage] = build_key_candidates(stage_pair_from_full_key(opts->key, stage),
                                                           opts->candidate_count,
                                                           opts->inject_true,
                                                           &seed);
        }
    }

    for (stage = 8; stage >= 1; stage--) {
        KeyPair true_pair = stage_pair_from_full_key(opts->key, stage);
        KeyTopList stage_results;
        LowTopList low_results;
        uint8_t true_low = (uint8_t)(ctx.state[stage - 1u] & 0x00FFu);
        uint8_t true_high = (uint8_t)(ctx.state[stage - 1u] >> 8);
        uint16_t best_state = 0;

        print_stage_separator(stage);
        printf("Working on the outer remaining stage K%u / s%u.\n", stage, stage);

        if (!current_key_is_known) {
            printf("  Scanning K%u by matched-context additive differentials.\n", stage);
            run_key_search(current_table,
                           stage,
                           default_diffs,
                           sizeof(default_diffs) / sizeof(default_diffs[0]),
                           &stage_candidates[stage],
                           opts->full_search,
                           opts->threads,
                           opts->top_count,
                           "stage-key",
                           1,
                           &stage_results);
            print_key_search_results("  Top stage-key scorers:",
                                     &stage_results,
                                     current_table,
                                     stage,
                                     default_diffs,
                                     sizeof(default_diffs) / sizeof(default_diffs[0]),
                                     true_pair,
                                     opts->top_count);
            current_key = stage_results.items[0].pair;
            recovered.recovered_keys[stage] = current_key;
            recovered.key_known[stage] = 1;
            printf("  Selected K%u = ", stage);
            print_pair(current_key);
            if (pair_equal(current_key, true_pair)) {
                printf("  [true]\n\n");
            } else {
                printf("  [mismatch vs true ");
                print_pair(true_pair);
                printf("]\n\n");
            }
            free_key_toplist(&stage_results);
        } else {
            recovered.recovered_keys[stage] = current_key;
            recovered.key_known[stage] = 1;
            printf("  Using K%u from the previous click step: ", stage);
            print_pair(current_key);
            if (pair_equal(current_key, true_pair)) {
                printf("  [true]\n\n");
            } else {
                printf("  [mismatch vs true ");
                print_pair(true_pair);
                printf("]\n\n");
            }
        }

        printf("  Peeling K%u to expose the translated reduced cascade.\n", stage);
        peel_table_with_key(work_table, current_table, current_key, stage);

        if (stage == 1u) {
            uint16_t s1 = (uint16_t)(work_table[0] - 0u);
            uint32_t x;
            int ok = 1;
            for (x = 0; x < TABLE_SIZE; x++) {
                if ((uint16_t)(work_table[x] - x) != s1) {
                    ok = 0;
                    break;
                }
            }
            recovered.recovered_states[1] = s1;
            recovered.state_known[1] = 1;
            printf("  Recovering s1 directly from constancy of DEC_Block_1(F1(x)) - x.\n");
            printf("  Recovered s1 = %04X", s1);
            if (s1 == ctx.state[0]) {
                printf("  [true]\n");
            } else {
                printf("  [mismatch vs true %04X]\n", ctx.state[0]);
            }
            printf("  Constancy check: %s\n\n", ok ? "PASS" : "FAIL");
            compare_table_alignment("Final F0 (identity)", work_table, true_tables[0]);
            break;
        }

        printf("  Recovering the low byte of s%u using the carry/support primitive.\n", stage);
        scan_low_candidates(work_table, opts->low_top_count, &low_results);
        print_low_candidates(&low_results, true_low);

        printf("  Guessing h%u and K%u, then looking for the next differential peel to click.\n",
               stage,
               stage - 1u);
        {
            HighCandidateSet highs = build_high_candidates(true_high, opts->h_count, opts->inject_true, &seed);
            ClickTopList click_results;
            size_t low_idx;
            size_t high_idx;
            size_t combo_index = 0;
            size_t combo_total = low_results.count * highs.count;
            init_click_toplist(&click_results, opts->top_count);

            for (low_idx = 0; low_idx < low_results.count; low_idx++) {
                for (high_idx = 0; high_idx < highs.count; high_idx++) {
                    uint16_t translation = (uint16_t)(low_results.items[low_idx].low | ((uint16_t)highs.values[high_idx] << 8));
                    KeyTopList next_results;
                    uint32_t x;
                    combo_index++;
                    printf("\r  [click combos] %zu/%zu", combo_index, combo_total);
                    fflush(stdout);
                    for (x = 0; x < TABLE_SIZE; x++) {
                        aligned_table[x] = (uint16_t)(work_table[x] - translation);
                    }
                    run_key_search(aligned_table,
                                   (uint8_t)(stage - 1u),
                                   default_diffs,
                                   sizeof(default_diffs) / sizeof(default_diffs[0]),
                                   &stage_candidates[stage - 1u],
                                   opts->full_search,
                                   opts->threads,
                                   1u,
                                   "click-inner",
                                   0,
                                   &next_results);
                    if (next_results.count > 0) {
                        ClickScore row;
                        row.score = next_results.items[0].score;
                        row.low = low_results.items[low_idx].low;
                        row.high = highs.values[high_idx];
                        row.pair = next_results.items[0].pair;
                        insert_click_top(&click_results, row);
                    }
                    free_key_toplist(&next_results);
                }
            }
            printf("\r  [click combos] %zu/%zu\n\n", combo_total, combo_total);

            printf("  Top click restorations for stage %u -> stage %u:\n", stage, stage - 1u);
            for (low_idx = 0; low_idx < click_results.count; low_idx++) {
                ClickScore row = click_results.items[low_idx];
                KeyPair true_next = stage_pair_from_full_key(opts->key, (uint8_t)(stage - 1u));
                printf("    #%zu low=%02X high=%02X next_key=", low_idx + 1u, row.low, row.high);
                print_pair(row.pair);
                printf(" score=%" PRIu64, row.score);
                if (row.low == true_low && row.high == true_high) {
                    printf("  [true state bytes]");
                }
                if (pair_equal(row.pair, true_next)) {
                    printf("  [true K%u]", stage - 1u);
                }
                printf("\n");
            }
            printf("\n");

            if (click_results.count == 0u) {
                fprintf(stderr, "no click results produced\n");
                exit(1);
            }

            best_state = (uint16_t)(click_results.items[0].low | ((uint16_t)click_results.items[0].high << 8));
            recovered.recovered_states[stage] = best_state;
            recovered.state_known[stage] = 1;
            recovered.recovered_keys[stage - 1u] = click_results.items[0].pair;
            recovered.key_known[stage - 1u] = 1;
            current_key = click_results.items[0].pair;
            current_key_is_known = 1;

            printf("  Selected s%u = %04X", stage, best_state);
            if (best_state == ctx.state[stage - 1u]) {
                printf("  [true]\n");
            } else {
                printf("  [mismatch vs true %04X]\n", ctx.state[stage - 1u]);
            }
            printf("  Selected K%u = ", stage - 1u);
            print_pair(current_key);
            if (pair_equal(current_key, stage_pair_from_full_key(opts->key, (uint8_t)(stage - 1u)))) {
                printf("  [true]\n\n");
            } else {
                printf("  [mismatch vs true ");
                print_pair(stage_pair_from_full_key(opts->key, (uint8_t)(stage - 1u)));
                printf("]\n\n");
            }

            subtract_translation(current_table, work_table, best_state);
            compare_table_alignment("Reduced cascade after peel", current_table, true_tables[stage - 1u]);

            free_click_toplist(&click_results);
            free_high_candidates(&highs);
        }

        free_low_toplist(&low_results);
    }

    printf("\nRecovered values summary:\n");
    for (stage = 1; stage <= 8; stage++) {
        printf("  K%u = ", stage);
        if (recovered.key_known[stage]) {
            print_pair(recovered.recovered_keys[stage]);
        } else {
            printf("(unknown)");
        }
        printf("   true=");
        print_pair(stage_pair_from_full_key(opts->key, stage));
        if (recovered.key_known[stage] && pair_equal(recovered.recovered_keys[stage], stage_pair_from_full_key(opts->key, stage))) {
            printf("  [OK]");
        } else if (recovered.key_known[stage]) {
            printf("  [mismatch]");
        }
        printf("\n");
        printf("  s%u = ", stage);
        if (recovered.state_known[stage]) {
            printf("%04X", recovered.recovered_states[stage]);
        } else {
            printf("(unknown)");
        }
        printf("   true=%04X", ctx.state[stage - 1u]);
        if (recovered.state_known[stage] && recovered.recovered_states[stage] == ctx.state[stage - 1u]) {
            printf("  [OK]");
        } else if (recovered.state_known[stage]) {
            printf("  [mismatch]");
        }
        printf("\n");
    }
    printf("\n");

    for (stage = 0; stage <= 8; stage++) {
        free(true_tables[stage]);
    }
    free(true_tables);
    for (stage = 1; stage <= 8; stage++) {
        if (!opts->full_search) {
            free_candidates(&stage_candidates[stage]);
        }
    }
    free(current_table);
    free(work_table);
    free(aligned_table);
}

int main(int argc, char **argv)
{
    Options opts;
    int parse_rc;
    init_options(&opts);
    parse_rc = parse_args(argc, argv, &opts);
    if (parse_rc <= 0) {
        return (parse_rc == 0) ? 0 : 1;
    }

    printf("SEPAR recursive context-matching + differential click harness\n");
    printf("  prefix   = ");
    for (size_t i = 0; i < opts.prefix_len; i++) {
        printf("%s%04X", i == 0 ? "" : ",", opts.prefix[i]);
    }
    printf("\n");
    printf("  threads  = %u\n", opts.threads);
    printf("  shortlist= %s", opts.full_search ? "full 2^32 stage-key search" : "validation shortlist");
    if (!opts.full_search) {
        printf(" (candidate-count=%zu, h-count=%zu, low-top=%zu)", opts.candidate_count, opts.h_count, opts.low_top_count);
    }
    printf("\n\n");

    if (opts.validate) {
        if (!run_validation_checks(&opts)) {
            fprintf(stderr, "validation failed; aborting attack run\n");
            return 1;
        }
    }

    run_recursive_attack(&opts);
    return 0;
}
