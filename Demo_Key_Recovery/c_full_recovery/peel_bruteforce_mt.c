#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#include <intrin.h>
#define POPCNT64(x) __popcnt64(x)
#else
#define POPCNT64(x) __builtin_popcountll((unsigned long long)(x))
#endif

#ifndef ROTL16
#define ROTL16(x, y) (uint16_t)((((uint16_t)(x)) << ((y) & 15)) | (((uint16_t)(x)) >> (16 - ((y) & 15))))
#define ROTR16(x, y) (uint16_t)((((uint16_t)(x)) >> ((y) & 15)) | (((uint16_t)(x)) << (16 - ((y) & 15))))
#endif

#define MASK16 0xFFFFu
#define CODEBOOK_WORDS 65536u
#define DEFAULT_KEEP_TOP 16u
#define DEFAULT_PROGRESS_MS 1000u
#define MAX_STAGE 8

typedef struct {
    uint16_t state_1;
    uint16_t state_2;
    uint16_t state_3;
    uint16_t state_4;
    uint16_t state_5;
    uint16_t state_6;
    uint16_t state_7;
    uint16_t state_8;
    uint16_t lfsr;
} SeparCtx;

typedef struct {
    uint32_t score;
    uint32_t index;
    uint8_t best_low;
} CandidateRow;

typedef struct {
    uint16_t *codebook;
    uint64_t score;
    uint32_t keys[9];
    uint16_t states[9];
    uint8_t has_key[9];
    uint8_t has_state[9];
    CandidateRow *prefetch_rows;
    uint32_t prefetch_count;
    int prefetched_stage;
} BeamPath;

typedef struct {
    BeamPath *path;
    uint64_t score;
} PathRow;

typedef struct {
    uint32_t score;
    uint8_t best_low;
    uint8_t state_high;
} StateHighRow;

typedef struct {
    int coarse_highs;
    int coarse_low_step;
    uint32_t coarse_keep;
    int strong_highs;
    int strong_low_step;
    uint32_t strong_keep;
    uint32_t threads;
    uint32_t progress_ms;
    uint32_t beam;
    uint32_t key_beam;
    uint32_t low_profile[9];
    uint32_t high_profile[9];
    uint32_t *candidate_indices[9];
    uint32_t candidate_counts[9];
} RecoverConfig;

typedef struct {
    uint16_t *codebook;
    uint16_t *sample_values;
    int stage_num;
    int sample_highs;
    int low_count;
    uint32_t keep_top;
    uint32_t watch_index;
    int watch_enabled;
    volatile LONG64 *progress_counter;
    CandidateRow *out_rows;
    uint32_t *out_count;
    int *watch_found;
    CandidateRow *watch_row;
} ScanJob;

typedef struct {
    ScanJob *job;
    uint64_t begin;
    uint64_t end;
} ThreadCtx;

typedef struct {
    uint32_t *indices;
    uint32_t count;
    uint16_t *codebook;
    int stage_num;
    int sample_highs;
    int low_count;
    uint16_t *sample_values;
    volatile LONG64 *progress_counter;
    CandidateRow *rows;
    int *watch_found;
    CandidateRow *watch_row;
    uint32_t watch_index;
    int watch_enabled;
} RefineJob;

static const uint16_t DEFAULT_KEY[16] = {
    0xE8B9, 0xB733, 0xDA5D, 0x96D7, 0x02DD, 0x3972, 0xE953, 0x07FD,
    0x50C5, 0x12DB, 0xF44A, 0x233E, 0x8D1E, 0x9DF5, 0xFC7D, 0x6371
};

static const uint16_t DEFAULT_IV[8] = {
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
};

static const uint8_t Separ_sbox1[16] = {1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4};
static const uint8_t Separ_sbox2[16] = {6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8};
static const uint8_t Separ_sbox3[16] = {12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13, 15, 4};
static const uint8_t Separ_sbox4[16] = {13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14};

static const uint8_t Separ_isbox1[16] = {4, 0, 3, 5, 15, 6, 8, 11, 7, 9, 13, 2, 10, 12, 14, 1};
static const uint8_t Separ_isbox2[16] = {12, 8, 7, 13, 3, 14, 0, 9, 15, 6, 1, 11, 10, 5, 4, 2};
static const uint8_t Separ_isbox3[16] = {4, 3, 1, 5, 15, 6, 2, 8, 7, 9, 12, 10, 0, 13, 11, 14};
static const uint8_t Separ_isbox4[16] = {4, 11, 2, 5, 13, 6, 8, 3, 7, 14, 12, 1, 9, 0, 15, 10};

static void print_usage(const char *program) {
    fprintf(stderr,
        "Usage:\n"
        "  %s build-codebook --out FILE [--key-hex 64hex] [--iv-hex 32hex]\n"
        "  %s score-key --codebook FILE --stage N --keypair HEX8 [--sample-highs N] [--low-step N]\n"
        "  %s scan-stage --codebook FILE --stage N [--start-index N] [--count N] [--sample-highs N] [--low-step N]\n"
        "                [--keep-top N] [--threads N] [--progress-ms N] [--out FILE] [--watch-key HEX8]\n"
        "  %s refine-stage --codebook FILE --stage N --in FILE [--sample-highs N] [--low-step N]\n"
        "                  [--threads N] [--progress-ms N] [--out FILE] [--watch-key HEX8]\n"
        "  %s recover-key --codebook FILE [--beam N] [--key-beam N] [--stop-stage N]\n"
        "                 [--coarse-highs N] [--coarse-low-step N] [--coarse-keep N]\n"
        "                 [--strong-highs N] [--strong-low-step N] [--strong-keep N]\n"
        "                 [--low-profile a,b,c,d,e,f,g,h] [--high-profile a,b,c,d,e,f,g,h]\n"
        "                 [--candidate-file stage:path] [--save-dir DIR] [--threads N] [--progress-ms N]\n",
        program, program, program, program, program);
}

static void die(const char *message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}

static inline uint64_t now_ticks(void) {
    return GetTickCount64();
}

static double seconds_since(uint64_t start_ticks) {
    return (double)(now_ticks() - start_ticks) / 1000.0;
}

static int parse_u64(const char *s, uint64_t *out) {
    char *end = NULL;
    unsigned long long value = _strtoui64(s, &end, 0);
    if (s == end || *end != '\0') {
        return 0;
    }
    *out = (uint64_t)value;
    return 1;
}

static int parse_u32(const char *s, uint32_t *out) {
    uint64_t value = 0;
    if (!parse_u64(s, &value) || value > 0xFFFFFFFFull) {
        return 0;
    }
    *out = (uint32_t)value;
    return 1;
}

static int parse_int(const char *s, int *out) {
    char *end = NULL;
    long value = strtol(s, &end, 0);
    if (s == end || *end != '\0') {
        return 0;
    }
    *out = (int)value;
    return 1;
}

static int hex_nibble(char c) {
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

static const char *skip_hex_prefix(const char *s) {
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        return s + 2;
    }
    return s;
}

static int parse_fixed_hex_words(const char *input, uint16_t *words, size_t word_count) {
    const char *s = skip_hex_prefix(input);
    size_t needed = word_count * 4;
    size_t length = strlen(s);
    size_t i;
    if (length != needed) {
        return 0;
    }
    for (i = 0; i < word_count; i++) {
        int n0 = hex_nibble(s[i * 4 + 0]);
        int n1 = hex_nibble(s[i * 4 + 1]);
        int n2 = hex_nibble(s[i * 4 + 2]);
        int n3 = hex_nibble(s[i * 4 + 3]);
        if (n0 < 0 || n1 < 0 || n2 < 0 || n3 < 0) {
            return 0;
        }
        words[i] = (uint16_t)((n0 << 12) | (n1 << 8) | (n2 << 4) | n3);
    }
    return 1;
}

static int parse_hex8_keypair(const char *input, uint32_t *out_index) {
    const char *s = skip_hex_prefix(input);
    size_t length = strlen(s);
    size_t i;
    uint32_t value = 0;
    if (length != 8) {
        return 0;
    }
    for (i = 0; i < 8; i++) {
        int n = hex_nibble(s[i]);
        if (n < 0) {
            return 0;
        }
        value = (value << 4) | (uint32_t)n;
    }
    *out_index = value;
    return 1;
}

static inline uint16_t do_sbox(uint16_t x) {
    uint8_t a = Separ_sbox1[(x >> 12) & 0xF];
    uint8_t b = Separ_sbox2[(x >> 8) & 0xF];
    uint8_t c = Separ_sbox3[(x >> 4) & 0xF];
    uint8_t d = Separ_sbox4[x & 0xF];
    return (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
}

static inline uint16_t do_isbox(uint16_t x) {
    uint8_t a = Separ_isbox1[(x >> 12) & 0xF];
    uint8_t b = Separ_isbox2[(x >> 8) & 0xF];
    uint8_t c = Separ_isbox3[(x >> 4) & 0xF];
    uint8_t d = Separ_isbox4[x & 0xF];
    return (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
}

static inline uint16_t Sep_ROTL16(uint16_t x) {
    uint8_t a = (x >> 12) & 0xF;
    uint8_t b = (x >> 8) & 0xF;
    uint8_t c = (x >> 4) & 0xF;
    uint8_t d = x & 0xF;
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

static inline uint16_t Sep_inROTL16(uint16_t x) {
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;
    uint16_t y = ROTR16(x, 12);
    uint16_t z = ROTR16(x, 8);
    x = (uint16_t)(x ^ y ^ z);
    a = (x >> 12) & 0xF;
    b = (x >> 8) & 0xF;
    c = (x >> 4) & 0xF;
    d = x & 0xF;
    d ^= a;
    c ^= b;
    b ^= d;
    a ^= c;
    return (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
}

static inline uint16_t derive_key2(uint16_t k0, uint8_t n) {
    uint16_t key2 = ROTL16(k0, 6);
    uint16_t b = (key2 >> 6) & 0xF;
    b = Separ_sbox1[b];
    key2 |= (uint16_t)(b << 6);
    key2 ^= (uint16_t)(n + 2);
    return key2;
}

static inline uint16_t derive_key3(uint16_t k1, uint8_t n) {
    uint16_t key3 = ROTL16(k1, 10);
    uint16_t b = (key3 >> 6) & 0xF;
    b = Separ_sbox1[b];
    key3 |= (uint16_t)(b << 6);
    key3 ^= (uint16_t)(n + 3);
    return key3;
}

static inline uint16_t ENC_Block(uint16_t pt, const uint16_t *key, uint8_t n) {
    uint16_t k0 = key[0];
    uint16_t k1 = key[1];
    uint16_t k2 = derive_key2(k0, n);
    uint16_t k3 = derive_key3(k1, n);
    uint16_t t = (uint16_t)(pt ^ k0);
    t = do_sbox(t);
    t = Sep_ROTL16(t);
    t ^= k1;
    t = do_sbox(t);
    t = Sep_ROTL16(t);
    t ^= k2;
    t = do_sbox(t);
    t = Sep_ROTL16(t);
    t ^= k3;
    t = do_sbox(t);
    t = Sep_ROTL16(t);
    t ^= (uint16_t)(k1 ^ k0);
    t = do_sbox(t);
    t ^= (uint16_t)(k2 ^ k3);
    return t;
}

static inline uint16_t DEC_Block(uint16_t ct, const uint16_t *key, uint8_t n) {
    uint16_t k0 = key[0];
    uint16_t k1 = key[1];
    uint16_t k2 = derive_key2(k0, n);
    uint16_t k3 = derive_key3(k1, n);
    uint16_t t = (uint16_t)(ct ^ k3 ^ k2);
    t = do_isbox(t);
    t ^= (uint16_t)(k0 ^ k1);
    t = Sep_inROTL16(t);
    t = do_isbox(t);
    t ^= k3;
    t = Sep_inROTL16(t);
    t = do_isbox(t);
    t ^= k2;
    t = Sep_inROTL16(t);
    t = do_isbox(t);
    t ^= k1;
    t = Sep_inROTL16(t);
    t = do_isbox(t);
    t ^= k0;
    return t;
}

static void Separ_Initial_State(SeparCtx *c, const uint16_t key[16], const uint16_t iv[8]) {
    int i;
    uint16_t v12 = 0;
    uint16_t v23 = 0;
    uint16_t v34 = 0;
    uint16_t v45 = 0;
    uint16_t v56 = 0;
    uint16_t v67 = 0;
    uint16_t v78 = 0;
    uint16_t ct = 0;

    c->state_1 = iv[0];
    c->state_2 = iv[1];
    c->state_3 = iv[2];
    c->state_4 = iv[3];
    c->state_5 = iv[4];
    c->state_6 = iv[5];
    c->state_7 = iv[6];
    c->state_8 = iv[7];

    for (i = 0; i < 4; i++) {
        v12 = ENC_Block((uint16_t)(c->state_1 + c->state_3 + c->state_5 + c->state_7), &key[0], 1);
        v23 = ENC_Block((uint16_t)(v12 + c->state_2), &key[2], 2);
        v34 = ENC_Block((uint16_t)(v23 + c->state_3), &key[4], 3);
        v45 = ENC_Block((uint16_t)(v34 + c->state_4), &key[6], 4);
        v56 = ENC_Block((uint16_t)(v45 + c->state_5), &key[8], 5);
        v67 = ENC_Block((uint16_t)(v56 + c->state_6), &key[10], 6);
        v78 = ENC_Block((uint16_t)(v67 + c->state_7), &key[12], 7);
        ct = ENC_Block((uint16_t)(v78 + c->state_8), &key[14], 8);

        c->state_1 = (uint16_t)(c->state_1 + ct);
        c->state_2 = (uint16_t)(c->state_2 + v12);
        c->state_3 = (uint16_t)(c->state_3 + v23);
        c->state_4 = (uint16_t)(c->state_4 + v34);
        c->state_5 = (uint16_t)(c->state_5 + v45);
        c->state_6 = (uint16_t)(c->state_6 + v56);
        c->state_7 = (uint16_t)(c->state_7 + v67);
        c->state_8 = (uint16_t)(c->state_8 + v78);
    }

    c->lfsr = (uint16_t)(ct | 0x100);
}

static uint16_t Separ_Encryption(uint16_t pt, SeparCtx *c, const uint16_t key[16]) {
    uint16_t v12;
    uint16_t v23;
    uint16_t v34;
    uint16_t v45;
    uint16_t v56;
    uint16_t v67;
    uint16_t v78;
    uint16_t ct;

    v12 = ENC_Block((uint16_t)(pt + c->state_1), &key[0], 1);
    v23 = ENC_Block((uint16_t)(v12 + c->state_2), &key[2], 2);
    v34 = ENC_Block((uint16_t)(v23 + c->state_3), &key[4], 3);
    v45 = ENC_Block((uint16_t)(v34 + c->state_4), &key[6], 4);
    v56 = ENC_Block((uint16_t)(v45 + c->state_5), &key[8], 5);
    v67 = ENC_Block((uint16_t)(v56 + c->state_6), &key[10], 6);
    v78 = ENC_Block((uint16_t)(v67 + c->state_7), &key[12], 7);
    ct = ENC_Block((uint16_t)(v78 + c->state_8), &key[14], 8);

    c->state_2 = (uint16_t)(c->state_2 + v12 + v56 + c->state_6);
    c->state_3 = (uint16_t)(c->state_3 + v23 + v34 + c->state_4 + c->state_1);
    c->state_4 = (uint16_t)(c->state_4 + v12 + v45 + c->state_8);
    c->state_5 = (uint16_t)(c->state_5 + v23);
    c->state_6 = (uint16_t)(c->state_6 + v12 + v45 + c->state_7);
    c->state_7 = (uint16_t)(c->state_7 + v23 + v67);
    c->state_8 = (uint16_t)(c->state_8 + v45);
    c->state_1 = (uint16_t)(c->state_1 + v34 + v23 + c->state_5 + v78);
    c->lfsr = (uint16_t)((c->lfsr >> 1) ^ (uint16_t)(-(int)(c->lfsr & 1u) & 0xCA44u));
    c->state_5 = (uint16_t)(c->state_5 + c->lfsr);
    return ct;
}

static int sample_high_values(int sample_highs, uint8_t *out) {
    int i;
    int step;
    if (sample_highs <= 0 || 256 % sample_highs != 0) {
        return 0;
    }
    step = 256 / sample_highs;
    for (i = 0; i < sample_highs; i++) {
        out[i] = (uint8_t)(i * step);
    }
    return 1;
}

static int sample_low_values(int low_step, uint8_t *out, int *out_count) {
    int i;
    int count = 0;
    if (low_step <= 0 || 256 % low_step != 0) {
        return 0;
    }
    for (i = 0; i < 256; i += low_step) {
        out[count++] = (uint8_t)i;
    }
    *out_count = count;
    return 1;
}

static uint16_t *build_sample_values(int sample_highs, int low_step, int *out_low_count) {
    uint8_t highs[256];
    uint8_t lows[256];
    int low_count = 0;
    int total = 0;
    int i;
    int j;
    uint16_t *values = NULL;

    if (!sample_high_values(sample_highs, highs)) {
        return NULL;
    }
    if (!sample_low_values(low_step, lows, &low_count)) {
        return NULL;
    }

    total = sample_highs * low_count;
    values = (uint16_t *)malloc((size_t)total * sizeof(uint16_t));
    if (values == NULL) {
        return NULL;
    }
    for (i = 0; i < sample_highs; i++) {
        for (j = 0; j < low_count; j++) {
            values[i * low_count + j] = (uint16_t)((highs[i] << 8) | lows[j]);
        }
    }
    *out_low_count = low_count;
    return values;
}

static uint16_t *load_codebook(const char *path) {
    FILE *f = fopen(path, "rb");
    uint16_t *codebook;
    size_t read_count;
    if (f == NULL) {
        fprintf(stderr, "failed to open codebook: %s\n", path);
        return NULL;
    }
    codebook = (uint16_t *)malloc(CODEBOOK_WORDS * sizeof(uint16_t));
    if (codebook == NULL) {
        fclose(f);
        die("out of memory");
    }
    read_count = fread(codebook, sizeof(uint16_t), CODEBOOK_WORDS, f);
    fclose(f);
    if (read_count != CODEBOOK_WORDS) {
        free(codebook);
        fprintf(stderr, "expected %u codebook words, got %zu\n", CODEBOOK_WORDS, read_count);
        return NULL;
    }
    return codebook;
}

static int save_codebook(const char *path, const uint16_t *codebook) {
    FILE *f = fopen(path, "wb");
    size_t write_count;
    if (f == NULL) {
        fprintf(stderr, "failed to open output file: %s\n", path);
        return 0;
    }
    write_count = fwrite(codebook, sizeof(uint16_t), CODEBOOK_WORDS, f);
    fclose(f);
    if (write_count != CODEBOOK_WORDS) {
        fprintf(stderr, "short write while saving codebook: %s\n", path);
        return 0;
    }
    return 1;
}

static uint16_t *build_first_block_codebook(const uint16_t key[16], const uint16_t iv[8]) {
    uint16_t *codebook = (uint16_t *)malloc(CODEBOOK_WORDS * sizeof(uint16_t));
    SeparCtx base;
    uint32_t pt;
    if (codebook == NULL) {
        die("out of memory");
    }
    Separ_Initial_State(&base, key, iv);
    for (pt = 0; pt < CODEBOOK_WORDS; pt++) {
        SeparCtx ctx = base;
        codebook[pt] = Separ_Encryption((uint16_t)pt, &ctx, key);
    }
    return codebook;
}

static inline int row_better(CandidateRow a, CandidateRow b) {
    if (a.score != b.score) {
        return a.score < b.score;
    }
    return a.index < b.index;
}

static inline int row_worse(CandidateRow a, CandidateRow b) {
    if (a.score != b.score) {
        return a.score > b.score;
    }
    return a.index > b.index;
}

static void heap_swap(CandidateRow *a, CandidateRow *b) {
    CandidateRow tmp = *a;
    *a = *b;
    *b = tmp;
}

static void max_heap_sift_up(CandidateRow *heap, uint32_t index) {
    while (index > 0) {
        uint32_t parent = (index - 1u) / 2u;
        if (!row_worse(heap[index], heap[parent])) {
            break;
        }
        heap_swap(&heap[index], &heap[parent]);
        index = parent;
    }
}

static void max_heap_sift_down(CandidateRow *heap, uint32_t count, uint32_t index) {
    for (;;) {
        uint32_t left = index * 2u + 1u;
        uint32_t right = left + 1u;
        uint32_t worst = index;
        if (left < count && row_worse(heap[left], heap[worst])) {
            worst = left;
        }
        if (right < count && row_worse(heap[right], heap[worst])) {
            worst = right;
        }
        if (worst == index) {
            break;
        }
        heap_swap(&heap[index], &heap[worst]);
        index = worst;
    }
}

static void max_heap_push_keep_top(CandidateRow *heap, uint32_t *count, uint32_t capacity, CandidateRow row) {
    if (*count < capacity) {
        heap[*count] = row;
        max_heap_sift_up(heap, *count);
        *count += 1u;
        return;
    }
    if (capacity == 0) {
        return;
    }
    if (row_better(row, heap[0])) {
        heap[0] = row;
        max_heap_sift_down(heap, *count, 0);
    }
}

static int cmp_row_asc(const void *a, const void *b) {
    const CandidateRow *ra = (const CandidateRow *)a;
    const CandidateRow *rb = (const CandidateRow *)b;
    if (ra->score < rb->score) {
        return -1;
    }
    if (ra->score > rb->score) {
        return 1;
    }
    if (ra->index < rb->index) {
        return -1;
    }
    if (ra->index > rb->index) {
        return 1;
    }
    return 0;
}

static uint32_t sampled_best_score_for_index(
    const uint16_t *codebook,
    const uint16_t *sample_values,
    int stage_num,
    int sample_highs,
    int low_count,
    uint32_t index,
    uint8_t *decoded_highs,
    uint8_t *decoded_lows,
    uint8_t *out_best_low
) {
    uint16_t keypair[2];
    int total_samples = sample_highs * low_count;
    int s;
    uint32_t best_score = UINT32_MAX;
    uint8_t best_low = 0;

    keypair[0] = (uint16_t)(index >> 16);
    keypair[1] = (uint16_t)index;
    for (s = 0; s < total_samples; s++) {
        uint16_t decoded = DEC_Block(codebook[sample_values[s]], keypair, (uint8_t)stage_num);
        decoded_highs[s] = (uint8_t)(decoded >> 8);
        decoded_lows[s] = (uint8_t)(decoded & 0xFF);
    }

    for (s = 0; s < 256; s++) {
        int group;
        uint32_t total = 0;
        uint8_t low_guess = (uint8_t)s;
        for (group = 0; group < sample_highs; group++) {
            uint64_t bits0 = 0;
            uint64_t bits1 = 0;
            uint64_t bits2 = 0;
            uint64_t bits3 = 0;
            int base = group * low_count;
            int j;
            for (j = 0; j < low_count; j++) {
                int pos = base + j;
                uint8_t out_high = (uint8_t)(decoded_highs[pos] - (decoded_lows[pos] < low_guess ? 1u : 0u));
                switch (out_high >> 6) {
                    case 0: bits0 |= 1ull << (out_high & 63); break;
                    case 1: bits1 |= 1ull << (out_high & 63); break;
                    case 2: bits2 |= 1ull << (out_high & 63); break;
                    default: bits3 |= 1ull << (out_high & 63); break;
                }
            }
            total += (uint32_t)POPCNT64(bits0);
            total += (uint32_t)POPCNT64(bits1);
            total += (uint32_t)POPCNT64(bits2);
            total += (uint32_t)POPCNT64(bits3);
        }
        if (total < best_score) {
            best_score = total;
            best_low = low_guess;
        }
    }

    *out_best_low = best_low;
    return best_score;
}

static DWORD WINAPI scan_thread_main(LPVOID param) {
    ThreadCtx *ctx = (ThreadCtx *)param;
    ScanJob *job = ctx->job;
    uint32_t local_count = 0;
    CandidateRow *heap = NULL;
    uint64_t index;
    int total_samples = job->sample_highs * job->low_count;
    uint8_t *decoded_highs = NULL;
    uint8_t *decoded_lows = NULL;
    LONG64 local_progress = 0;

    heap = (CandidateRow *)malloc((size_t)job->keep_top * sizeof(CandidateRow));
    decoded_highs = (uint8_t *)malloc((size_t)total_samples);
    decoded_lows = (uint8_t *)malloc((size_t)total_samples);
    if (heap == NULL || decoded_highs == NULL || decoded_lows == NULL) {
        free(heap);
        free(decoded_highs);
        free(decoded_lows);
        return 1;
    }

    for (index = ctx->begin; index < ctx->end; index++) {
        CandidateRow row;
        row.index = (uint32_t)index;
        row.score = sampled_best_score_for_index(
            job->codebook,
            job->sample_values,
            job->stage_num,
            job->sample_highs,
            job->low_count,
            row.index,
            decoded_highs,
            decoded_lows,
            &row.best_low
        );
        max_heap_push_keep_top(heap, &local_count, job->keep_top, row);
        if (job->watch_enabled && row.index == job->watch_index) {
            *job->watch_found = 1;
            *job->watch_row = row;
        }
        local_progress += 1;
        if ((local_progress & 0x0FFF) == 0) {
            InterlockedAdd64(job->progress_counter, local_progress);
            local_progress = 0;
        }
    }

    if (local_progress != 0) {
        InterlockedAdd64(job->progress_counter, local_progress);
    }

    qsort(heap, local_count, sizeof(CandidateRow), cmp_row_asc);
    memcpy(job->out_rows, heap, (size_t)local_count * sizeof(CandidateRow));
    *job->out_count = local_count;

    free(heap);
    free(decoded_highs);
    free(decoded_lows);
    return 0;
}

static DWORD WINAPI refine_thread_main(LPVOID param) {
    ThreadCtx *ctx = (ThreadCtx *)param;
    RefineJob *job = (RefineJob *)ctx->job;
    uint64_t i;
    int total_samples = job->sample_highs * job->low_count;
    uint8_t *decoded_highs = (uint8_t *)malloc((size_t)total_samples);
    uint8_t *decoded_lows = (uint8_t *)malloc((size_t)total_samples);
    LONG64 local_progress = 0;

    if (decoded_highs == NULL || decoded_lows == NULL) {
        free(decoded_highs);
        free(decoded_lows);
        return 1;
    }

    for (i = ctx->begin; i < ctx->end; i++) {
        CandidateRow row;
        row.index = job->indices[i];
        row.score = sampled_best_score_for_index(
            job->codebook,
            job->sample_values,
            job->stage_num,
            job->sample_highs,
            job->low_count,
            row.index,
            decoded_highs,
            decoded_lows,
            &row.best_low
        );
        job->rows[i] = row;
        if (job->watch_enabled && row.index == job->watch_index) {
            *job->watch_found = 1;
            *job->watch_row = row;
        }
        local_progress += 1;
        if ((local_progress & 0x3FF) == 0) {
            InterlockedAdd64(job->progress_counter, local_progress);
            local_progress = 0;
        }
    }

    if (local_progress != 0) {
        InterlockedAdd64(job->progress_counter, local_progress);
    }

    free(decoded_highs);
    free(decoded_lows);
    return 0;
}

static uint32_t detect_threads(void) {
    SYSTEM_INFO info;
    GetSystemInfo(&info);
    if (info.dwNumberOfProcessors == 0) {
        return 1;
    }
    return info.dwNumberOfProcessors;
}

static void print_stage_banner(
    const char *label,
    int stage_num,
    int sample_highs,
    int low_step,
    uint64_t start_index,
    uint64_t count,
    uint32_t threads,
    uint32_t keep_top
) {
    fprintf(stdout,
        "%s: stage=%d  sample_highs=%d  low_step=%d  start=0x%08" PRIX64 "  count=%" PRIu64
        "  threads=%u  keep_top=%u\n",
        label,
        stage_num,
        sample_highs,
        low_step,
        start_index,
        count,
        threads,
        keep_top);
    fflush(stdout);
}

static void print_rows(const CandidateRow *rows, uint32_t count, uint32_t top) {
    uint32_t i;
    if (top > count) {
        top = count;
    }
    for (i = 0; i < top; i++) {
        uint16_t k0 = (uint16_t)(rows[i].index >> 16);
        uint16_t k1 = (uint16_t)rows[i].index;
        fprintf(stdout,
            "  #%u  score=%u  idx=0x%08" PRIX32 "  low=0x%02X  key=%04X%04X\n",
            i + 1,
            rows[i].score,
            rows[i].index,
            rows[i].best_low,
            k0,
            k1);
    }
}

static void save_rows_tsv(const char *path, const CandidateRow *rows, uint32_t count) {
    FILE *f = fopen(path, "wb");
    uint32_t i;
    if (f == NULL) {
        fprintf(stderr, "failed to open output file: %s\n", path);
        exit(1);
    }
    fprintf(f, "# score\tindex\tbest_low\tkeypair\n");
    for (i = 0; i < count; i++) {
        fprintf(
            f,
            "%u\t0x%08" PRIX32 "\t0x%02X\t%04X%04X\n",
            rows[i].score,
            rows[i].index,
            rows[i].best_low,
            (uint16_t)(rows[i].index >> 16),
            (uint16_t)rows[i].index
        );
    }
    fclose(f);
}

static uint32_t *load_indices_from_tsv(const char *path, uint32_t *out_count) {
    FILE *f = fopen(path, "rb");
    char line[256];
    uint32_t capacity = 256;
    uint32_t count = 0;
    uint32_t *indices = NULL;
    if (f == NULL) {
        fprintf(stderr, "failed to open input file: %s\n", path);
        return NULL;
    }
    indices = (uint32_t *)malloc((size_t)capacity * sizeof(uint32_t));
    if (indices == NULL) {
        fclose(f);
        die("out of memory");
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        uint32_t score = 0;
        uint32_t index = 0;
        uint32_t best_low = 0;
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        if (sscanf(line, "%u\t0x%x\t0x%x", &score, &index, &best_low) != 3) {
            fprintf(stderr, "failed to parse line in %s: %s\n", path, line);
            free(indices);
            fclose(f);
            return NULL;
        }
        if (count == capacity) {
            uint32_t new_capacity = capacity * 2u;
            uint32_t *tmp = (uint32_t *)realloc(indices, (size_t)new_capacity * sizeof(uint32_t));
            if (tmp == NULL) {
                free(indices);
                fclose(f);
                die("out of memory");
            }
            indices = tmp;
            capacity = new_capacity;
        }
        indices[count++] = index;
    }
    fclose(f);
    *out_count = count;
    return indices;
}

static int parse_profile_csv(const char *text, uint32_t out_profile[9]) {
    char buffer[256];
    char *token;
    char *context = NULL;
    int stage = 1;
    size_t length = strlen(text);
    if (length >= sizeof(buffer)) {
        return 0;
    }
    memcpy(buffer, text, length + 1);
    token = strtok_s(buffer, ",", &context);
    while (token != NULL && stage <= 8) {
        uint32_t value = 0;
        if (!parse_u32(token, &value)) {
            return 0;
        }
        out_profile[stage++] = value;
        token = strtok_s(NULL, ",", &context);
    }
    return stage == 9 && token == NULL;
}

static int parse_stage_file_arg(const char *text, int *out_stage, const char **out_path) {
    const char *colon = strchr(text, ':');
    int stage = 0;
    if (colon == NULL) {
        return 0;
    }
    {
        char stage_buf[16];
        size_t len = (size_t)(colon - text);
        if (len == 0 || len >= sizeof(stage_buf)) {
            return 0;
        }
        memcpy(stage_buf, text, len);
        stage_buf[len] = '\0';
        if (!parse_int(stage_buf, &stage)) {
            return 0;
        }
    }
    if (stage < 1 || stage > 8 || colon[1] == '\0') {
        return 0;
    }
    *out_stage = stage;
    *out_path = colon + 1;
    return 1;
}

static CandidateRow *copy_candidate_rows(const CandidateRow *rows, uint32_t count) {
    CandidateRow *copy = NULL;
    if (count == 0) {
        return NULL;
    }
    copy = (CandidateRow *)malloc((size_t)count * sizeof(CandidateRow));
    if (copy == NULL) {
        die("out of memory");
    }
    memcpy(copy, rows, (size_t)count * sizeof(CandidateRow));
    return copy;
}

static void free_beam_path(BeamPath *path) {
    if (path->codebook != NULL) {
        free(path->codebook);
        path->codebook = NULL;
    }
    if (path->prefetch_rows != NULL) {
        free(path->prefetch_rows);
        path->prefetch_rows = NULL;
    }
    path->prefetch_count = 0;
    path->prefetched_stage = 0;
}

static int cmp_path_row(const void *a, const void *b) {
    const PathRow *ra = (const PathRow *)a;
    const PathRow *rb = (const PathRow *)b;
    if (ra->score < rb->score) {
        return -1;
    }
    if (ra->score > rb->score) {
        return 1;
    }
    return 0;
}

static uint16_t *decode_codebook_for_index(const uint16_t *codebook, int stage_num, uint32_t index) {
    uint16_t keypair[2];
    uint16_t *decoded = (uint16_t *)malloc(CODEBOOK_WORDS * sizeof(uint16_t));
    uint32_t i;
    if (decoded == NULL) {
        die("out of memory");
    }
    keypair[0] = (uint16_t)(index >> 16);
    keypair[1] = (uint16_t)index;
    for (i = 0; i < CODEBOOK_WORDS; i++) {
        decoded[i] = DEC_Block(codebook[i], keypair, (uint8_t)stage_num);
    }
    return decoded;
}

static uint16_t *peel_codebook_from_decoded(const uint16_t *decoded, uint16_t state_word) {
    uint16_t *peeled = (uint16_t *)malloc(CODEBOOK_WORDS * sizeof(uint16_t));
    uint32_t i;
    if (peeled == NULL) {
        die("out of memory");
    }
    for (i = 0; i < CODEBOOK_WORDS; i++) {
        peeled[i] = (uint16_t)(decoded[i] - state_word);
    }
    return peeled;
}

static uint32_t best_low_plateau_for_index(
    const uint16_t *codebook,
    const uint16_t *sample_values,
    int stage_num,
    int sample_highs,
    int low_count,
    uint32_t index,
    uint32_t max_width,
    uint8_t *out_lows,
    uint32_t *out_low_count
) {
    int total_samples = sample_highs * low_count;
    uint8_t *decoded_highs = (uint8_t *)malloc((size_t)total_samples);
    uint8_t *decoded_lows = (uint8_t *)malloc((size_t)total_samples);
    uint32_t best_score;
    uint8_t best_low;
    uint32_t count = 0;
    int low;
    if (decoded_highs == NULL || decoded_lows == NULL) {
        die("out of memory");
    }
    best_score = sampled_best_score_for_index(
        codebook,
        sample_values,
        stage_num,
        sample_highs,
        low_count,
        index,
        decoded_highs,
        decoded_lows,
        &best_low
    );
    for (low = 0; low < 256; low++) {
        int group;
        uint32_t total = 0;
        for (group = 0; group < sample_highs; group++) {
            uint64_t bits0 = 0;
            uint64_t bits1 = 0;
            uint64_t bits2 = 0;
            uint64_t bits3 = 0;
            int base = group * low_count;
            int j;
            for (j = 0; j < low_count; j++) {
                int pos = base + j;
                uint8_t out_high = (uint8_t)(decoded_highs[pos] - (decoded_lows[pos] < (uint8_t)low ? 1u : 0u));
                switch (out_high >> 6) {
                    case 0: bits0 |= 1ull << (out_high & 63); break;
                    case 1: bits1 |= 1ull << (out_high & 63); break;
                    case 2: bits2 |= 1ull << (out_high & 63); break;
                    default: bits3 |= 1ull << (out_high & 63); break;
                }
            }
            total += (uint32_t)POPCNT64(bits0);
            total += (uint32_t)POPCNT64(bits1);
            total += (uint32_t)POPCNT64(bits2);
            total += (uint32_t)POPCNT64(bits3);
        }
        if (total == best_score) {
            if (count < max_width) {
                out_lows[count] = (uint8_t)low;
            }
            count += 1;
        }
    }
    if (count > max_width) {
        count = max_width;
    }
    *out_low_count = count;
    if (count == 0) {
        out_lows[0] = best_low;
        *out_low_count = 1;
    }
    free(decoded_highs);
    free(decoded_lows);
    return best_score;
}

static uint16_t *precompute_dec_table_for_index(int stage_num, uint32_t index) {
    uint16_t keypair[2];
    uint16_t *table = (uint16_t *)malloc(CODEBOOK_WORDS * sizeof(uint16_t));
    uint32_t i;
    if (table == NULL) {
        die("out of memory");
    }
    keypair[0] = (uint16_t)(index >> 16);
    keypair[1] = (uint16_t)index;
    for (i = 0; i < CODEBOOK_WORDS; i++) {
        table[i] = DEC_Block((uint16_t)i, keypair, (uint8_t)stage_num);
    }
    return table;
}

static uint32_t best_score_from_sample_arrays(
    const uint8_t *sample_highs_buf,
    const uint8_t *sample_lows_buf,
    int sample_high_count,
    int low_count,
    uint8_t *out_best_low
) {
    uint32_t best_score = UINT32_MAX;
    uint8_t best_low = 0;
    int low;
    for (low = 0; low < 256; low++) {
        int group;
        uint32_t total = 0;
        for (group = 0; group < sample_high_count; group++) {
            uint64_t bits0 = 0;
            uint64_t bits1 = 0;
            uint64_t bits2 = 0;
            uint64_t bits3 = 0;
            int base = group * low_count;
            int j;
            for (j = 0; j < low_count; j++) {
                int pos = base + j;
                uint8_t out_high = (uint8_t)(sample_highs_buf[pos] - (sample_lows_buf[pos] < (uint8_t)low ? 1u : 0u));
                switch (out_high >> 6) {
                    case 0: bits0 |= 1ull << (out_high & 63); break;
                    case 1: bits1 |= 1ull << (out_high & 63); break;
                    case 2: bits2 |= 1ull << (out_high & 63); break;
                    default: bits3 |= 1ull << (out_high & 63); break;
                }
            }
            total += (uint32_t)POPCNT64(bits0);
            total += (uint32_t)POPCNT64(bits1);
            total += (uint32_t)POPCNT64(bits2);
            total += (uint32_t)POPCNT64(bits3);
        }
        if (total < best_score) {
            best_score = total;
            best_low = (uint8_t)low;
        }
    }
    *out_best_low = best_low;
    return best_score;
}

static uint32_t best_score_after_peel_for_index(
    const uint16_t *decoded_codebook,
    uint16_t state_word,
    int stage_num,
    uint32_t index,
    const uint16_t *sample_values,
    int sample_high_count,
    int low_count,
    uint8_t *out_best_low
) {
    uint16_t keypair[2];
    int total_samples = sample_high_count * low_count;
    uint8_t *buf_high = (uint8_t *)malloc((size_t)total_samples);
    uint8_t *buf_low = (uint8_t *)malloc((size_t)total_samples);
    int s;
    uint32_t score;
    if (buf_high == NULL || buf_low == NULL) {
        die("out of memory");
    }
    keypair[0] = (uint16_t)(index >> 16);
    keypair[1] = (uint16_t)index;
    for (s = 0; s < total_samples; s++) {
        uint16_t peeled = (uint16_t)(decoded_codebook[sample_values[s]] - state_word);
        uint16_t residual = DEC_Block(peeled, keypair, (uint8_t)stage_num);
        buf_high[s] = (uint8_t)(residual >> 8);
        buf_low[s] = (uint8_t)residual;
    }
    score = best_score_from_sample_arrays(buf_high, buf_low, sample_high_count, low_count, out_best_low);
    free(buf_high);
    free(buf_low);
    return score;
}

static int cmp_state_high_row(const void *a, const void *b) {
    const StateHighRow *ra = (const StateHighRow *)a;
    const StateHighRow *rb = (const StateHighRow *)b;
    if (ra->score < rb->score) {
        return -1;
    }
    if (ra->score > rb->score) {
        return 1;
    }
    if (ra->best_low < rb->best_low) {
        return -1;
    }
    if (ra->best_low > rb->best_low) {
        return 1;
    }
    if (ra->state_high < rb->state_high) {
        return -1;
    }
    if (ra->state_high > rb->state_high) {
        return 1;
    }
    return 0;
}

static void rank_state_high_candidates_for_table(
    const uint16_t *decoded_codebook,
    uint8_t peeled_state_low,
    const uint16_t *next_stage_table,
    const uint16_t *sample_values,
    int sample_high_count,
    int low_count,
    StateHighRow out_rows[256]
) {
    int total_samples = sample_high_count * low_count;
    uint8_t *buf_high = (uint8_t *)malloc((size_t)total_samples);
    uint8_t *buf_low = (uint8_t *)malloc((size_t)total_samples);
    int state_high;
    if (buf_high == NULL || buf_low == NULL) {
        die("out of memory");
    }
    for (state_high = 0; state_high < 256; state_high++) {
        uint16_t state_word = (uint16_t)((state_high << 8) | peeled_state_low);
        int s;
        for (s = 0; s < total_samples; s++) {
            uint16_t peeled = (uint16_t)(decoded_codebook[sample_values[s]] - state_word);
            uint16_t residual = next_stage_table[peeled];
            buf_high[s] = (uint8_t)(residual >> 8);
            buf_low[s] = (uint8_t)residual;
        }
        out_rows[state_high].score = best_score_from_sample_arrays(buf_high, buf_low, sample_high_count, low_count, &out_rows[state_high].best_low);
        out_rows[state_high].state_high = (uint8_t)state_high;
    }
    qsort(out_rows, 256, sizeof(StateHighRow), cmp_state_high_row);
    free(buf_high);
    free(buf_low);
}

static void maybe_save_rows(const char *save_dir, int stage, uint32_t path_index, const char *kind, const CandidateRow *rows, uint32_t count) {
    char file_path[MAX_PATH];
    if (save_dir == NULL) {
        return;
    }
    CreateDirectoryA(save_dir, NULL);
    snprintf(file_path, sizeof(file_path), "%s\\stage%d_path%u_%s.tsv", save_dir, stage, path_index, kind);
    save_rows_tsv(file_path, rows, count);
}

static uint32_t run_scan_stage(
    uint16_t *codebook,
    int stage_num,
    uint64_t start_index,
    uint64_t count,
    int sample_highs,
    int low_step,
    uint32_t keep_top,
    uint32_t threads,
    uint32_t progress_ms,
    int watch_enabled,
    uint32_t watch_index,
    CandidateRow **out_rows,
    int *out_watch_found,
    CandidateRow *out_watch_row,
    double *out_seconds
) {
    HANDLE *thread_handles = NULL;
    ThreadCtx *thread_ctxs = NULL;
    ScanJob *jobs = NULL;
    LONG64 progress_counter = 0;
    uint16_t *sample_values = NULL;
    int low_count = 0;
    uint32_t i;
    uint64_t assigned = 0;
    uint64_t begin_ticks = now_ticks();
    CandidateRow *merged = NULL;
    uint32_t merged_count = 0;

    if (keep_top == 0) {
        die("keep_top must be positive");
    }
    if (threads == 0) {
        threads = 1;
    }
    sample_values = build_sample_values(sample_highs, low_step, &low_count);
    if (sample_values == NULL) {
        die("invalid sample_highs or low_step");
    }

    thread_handles = (HANDLE *)malloc((size_t)threads * sizeof(HANDLE));
    thread_ctxs = (ThreadCtx *)calloc(threads, sizeof(ThreadCtx));
    jobs = (ScanJob *)calloc(threads, sizeof(ScanJob));
    merged = (CandidateRow *)malloc((size_t)threads * (size_t)keep_top * sizeof(CandidateRow));
    if (thread_handles == NULL || thread_ctxs == NULL || jobs == NULL || merged == NULL) {
        die("out of memory");
    }

    for (i = 0; i < threads; i++) {
        uint64_t remaining = count - assigned;
        uint64_t share = remaining / (threads - i);
        int *watch_found = (int *)calloc(1, sizeof(int));
        CandidateRow *watch_row = (CandidateRow *)calloc(1, sizeof(CandidateRow));
        uint32_t *row_count = (uint32_t *)calloc(1, sizeof(uint32_t));
        CandidateRow *rows = (CandidateRow *)calloc(keep_top, sizeof(CandidateRow));
        if (watch_found == NULL || watch_row == NULL || row_count == NULL || rows == NULL) {
            die("out of memory");
        }
        jobs[i].codebook = codebook;
        jobs[i].sample_values = sample_values;
        jobs[i].stage_num = stage_num;
        jobs[i].sample_highs = sample_highs;
        jobs[i].low_count = low_count;
        jobs[i].keep_top = keep_top;
        jobs[i].watch_index = watch_index;
        jobs[i].watch_enabled = watch_enabled;
        jobs[i].progress_counter = &progress_counter;
        jobs[i].out_rows = rows;
        jobs[i].out_count = row_count;
        jobs[i].watch_found = watch_found;
        jobs[i].watch_row = watch_row;

        thread_ctxs[i].job = &jobs[i];
        thread_ctxs[i].begin = start_index + assigned;
        thread_ctxs[i].end = thread_ctxs[i].begin + share;
        assigned += share;

        thread_handles[i] = CreateThread(NULL, 0, scan_thread_main, &thread_ctxs[i], 0, NULL);
        if (thread_handles[i] == NULL) {
            die("failed to create worker thread");
        }
    }

    while (WaitForMultipleObjects(threads, thread_handles, TRUE, progress_ms) == WAIT_TIMEOUT) {
        LONG64 done = InterlockedAdd64(&progress_counter, 0);
        double elapsed = seconds_since(begin_ticks);
        double rate = elapsed > 0.0 ? (double)done / elapsed : 0.0;
        double fraction = count > 0 ? (double)done / (double)count : 1.0;
        double eta = rate > 0.0 ? ((double)(count - (uint64_t)done) / rate) : 0.0;
        fprintf(stdout,
            "progress: %" PRIu64 "/%" PRIu64 "  %.2f%%  rate=%.0f cand/s  elapsed=%.1fs  eta=%.1fs\n",
            (uint64_t)done,
            count,
            fraction * 100.0,
            rate,
            elapsed,
            eta);
        fflush(stdout);
    }

    for (i = 0; i < threads; i++) {
        DWORD exit_code = 0;
        GetExitCodeThread(thread_handles[i], &exit_code);
        CloseHandle(thread_handles[i]);
        if (exit_code != 0) {
            die("worker thread failed");
        }
        memcpy(merged + merged_count, jobs[i].out_rows, (size_t)(*jobs[i].out_count) * sizeof(CandidateRow));
        merged_count += *jobs[i].out_count;
        if (jobs[i].watch_enabled && *jobs[i].watch_found) {
            *out_watch_found = 1;
            *out_watch_row = *jobs[i].watch_row;
        }
        free(jobs[i].out_rows);
        free(jobs[i].out_count);
        free(jobs[i].watch_found);
        free(jobs[i].watch_row);
    }

    qsort(merged, merged_count, sizeof(CandidateRow), cmp_row_asc);
    if (merged_count > keep_top) {
        merged_count = keep_top;
    }
    *out_rows = (CandidateRow *)malloc((size_t)merged_count * sizeof(CandidateRow));
    if (*out_rows == NULL) {
        die("out of memory");
    }
    memcpy(*out_rows, merged, (size_t)merged_count * sizeof(CandidateRow));
    *out_seconds = seconds_since(begin_ticks);

    free(sample_values);
    free(thread_handles);
    free(thread_ctxs);
    free(jobs);
    free(merged);
    return merged_count;
}

static uint32_t run_refine_stage(
    uint16_t *codebook,
    int stage_num,
    const uint32_t *indices,
    uint32_t index_count,
    int sample_highs,
    int low_step,
    uint32_t threads,
    uint32_t progress_ms,
    int watch_enabled,
    uint32_t watch_index,
    CandidateRow **out_rows,
    int *out_watch_found,
    CandidateRow *out_watch_row,
    double *out_seconds
) {
    HANDLE *thread_handles = NULL;
    ThreadCtx *thread_ctxs = NULL;
    RefineJob *jobs = NULL;
    LONG64 progress_counter = 0;
    uint16_t *sample_values = NULL;
    CandidateRow *rows = NULL;
    int low_count = 0;
    uint64_t begin_ticks = now_ticks();
    uint32_t i;
    uint64_t assigned = 0;

    if (threads == 0) {
        threads = 1;
    }
    sample_values = build_sample_values(sample_highs, low_step, &low_count);
    if (sample_values == NULL) {
        die("invalid sample_highs or low_step");
    }
    thread_handles = (HANDLE *)malloc((size_t)threads * sizeof(HANDLE));
    thread_ctxs = (ThreadCtx *)calloc(threads, sizeof(ThreadCtx));
    jobs = (RefineJob *)calloc(threads, sizeof(RefineJob));
    rows = (CandidateRow *)calloc(index_count, sizeof(CandidateRow));
    if (thread_handles == NULL || thread_ctxs == NULL || jobs == NULL || rows == NULL) {
        die("out of memory");
    }

    for (i = 0; i < threads; i++) {
        uint64_t remaining = index_count - assigned;
        uint64_t share = remaining / (threads - i);
        int *watch_found = (int *)calloc(1, sizeof(int));
        CandidateRow *watch_row = (CandidateRow *)calloc(1, sizeof(CandidateRow));
        if (watch_found == NULL || watch_row == NULL) {
            die("out of memory");
        }
        jobs[i].indices = (uint32_t *)indices;
        jobs[i].count = index_count;
        jobs[i].codebook = codebook;
        jobs[i].stage_num = stage_num;
        jobs[i].sample_highs = sample_highs;
        jobs[i].low_count = low_count;
        jobs[i].sample_values = sample_values;
        jobs[i].progress_counter = &progress_counter;
        jobs[i].rows = rows;
        jobs[i].watch_found = watch_found;
        jobs[i].watch_row = watch_row;
        jobs[i].watch_index = watch_index;
        jobs[i].watch_enabled = watch_enabled;

        thread_ctxs[i].job = (ScanJob *)&jobs[i];
        thread_ctxs[i].begin = assigned;
        thread_ctxs[i].end = assigned + share;
        assigned += share;
        thread_handles[i] = CreateThread(NULL, 0, refine_thread_main, &thread_ctxs[i], 0, NULL);
        if (thread_handles[i] == NULL) {
            die("failed to create worker thread");
        }
    }

    while (WaitForMultipleObjects(threads, thread_handles, TRUE, progress_ms) == WAIT_TIMEOUT) {
        LONG64 done = InterlockedAdd64(&progress_counter, 0);
        double elapsed = seconds_since(begin_ticks);
        double rate = elapsed > 0.0 ? (double)done / elapsed : 0.0;
        double fraction = index_count > 0 ? (double)done / (double)index_count : 1.0;
        double eta = rate > 0.0 ? ((double)(index_count - (uint32_t)done) / rate) : 0.0;
        fprintf(stdout,
            "progress: %" PRIu64 "/%" PRIu32 "  %.2f%%  rate=%.0f cand/s  elapsed=%.1fs  eta=%.1fs\n",
            (uint64_t)done,
            index_count,
            fraction * 100.0,
            rate,
            elapsed,
            eta);
        fflush(stdout);
    }

    for (i = 0; i < threads; i++) {
        DWORD exit_code = 0;
        GetExitCodeThread(thread_handles[i], &exit_code);
        CloseHandle(thread_handles[i]);
        if (exit_code != 0) {
            die("worker thread failed");
        }
        if (jobs[i].watch_enabled && *jobs[i].watch_found) {
            *out_watch_found = 1;
            *out_watch_row = *jobs[i].watch_row;
        }
        free(jobs[i].watch_found);
        free(jobs[i].watch_row);
    }

    qsort(rows, index_count, sizeof(CandidateRow), cmp_row_asc);
    *out_rows = rows;
    *out_seconds = seconds_since(begin_ticks);

    free(sample_values);
    free(thread_handles);
    free(thread_ctxs);
    free(jobs);
    return index_count;
}

static CandidateRow *narrow_stage_candidates(
    uint16_t *codebook,
    int stage_num,
    const RecoverConfig *cfg,
    const uint32_t *candidate_indices,
    uint32_t candidate_count,
    uint32_t path_index,
    const char *save_dir,
    uint32_t *out_count
) {
    CandidateRow *coarse_rows = NULL;
    CandidateRow *strong_rows = NULL;
    CandidateRow *final_rows = NULL;
    CandidateRow dummy_watch_row;
    int dummy_watch_found = 0;
    double seconds = 0.0;
    uint32_t coarse_count = 0;
    uint32_t strong_count = 0;
    uint32_t i;

    if (candidate_indices != NULL && candidate_count > 0) {
        run_refine_stage(
            codebook,
            stage_num,
            candidate_indices,
            candidate_count,
            cfg->coarse_highs,
            cfg->coarse_low_step,
            cfg->threads,
            cfg->progress_ms,
            0,
            0,
            &coarse_rows,
            &dummy_watch_found,
            &dummy_watch_row,
            &seconds
        );
        coarse_count = candidate_count;
        if (coarse_count > cfg->coarse_keep) {
            coarse_count = cfg->coarse_keep;
        }
        maybe_save_rows(save_dir, stage_num, path_index, "coarse", coarse_rows, coarse_count);
    } else {
        coarse_count = run_scan_stage(
            codebook,
            stage_num,
            0,
            1ull << 32,
            cfg->coarse_highs,
            cfg->coarse_low_step,
            cfg->coarse_keep,
            cfg->threads,
            cfg->progress_ms,
            0,
            0,
            &coarse_rows,
            &dummy_watch_found,
            &dummy_watch_row,
            &seconds
        );
        maybe_save_rows(save_dir, stage_num, path_index, "coarse", coarse_rows, coarse_count);
    }

    if (coarse_count == 0) {
        free(coarse_rows);
        *out_count = 0;
        return NULL;
    }

    {
        uint32_t *coarse_indices = (uint32_t *)malloc((size_t)coarse_count * sizeof(uint32_t));
        if (coarse_indices == NULL) {
            die("out of memory");
        }
        for (i = 0; i < coarse_count; i++) {
            coarse_indices[i] = coarse_rows[i].index;
        }
        run_refine_stage(
            codebook,
            stage_num,
            coarse_indices,
            coarse_count,
            cfg->strong_highs,
            cfg->strong_low_step,
            cfg->threads,
            cfg->progress_ms,
            0,
            0,
            &strong_rows,
            &dummy_watch_found,
            &dummy_watch_row,
            &seconds
        );
        free(coarse_indices);
    }
    strong_count = coarse_count;
    if (strong_count > cfg->strong_keep) {
        strong_count = cfg->strong_keep;
    }
    maybe_save_rows(save_dir, stage_num, path_index, "strong", strong_rows, strong_count);

    final_rows = copy_candidate_rows(strong_rows, strong_count);
    free(coarse_rows);
    free(strong_rows);
    *out_count = strong_count;
    return final_rows;
}

static void cmd_build_codebook(int argc, char **argv) {
    const char *out_path = NULL;
    uint16_t key[16];
    uint16_t iv[8];
    int i;
    uint16_t *codebook;

    memcpy(key, DEFAULT_KEY, sizeof(key));
    memcpy(iv, DEFAULT_IV, sizeof(iv));

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (strcmp(argv[i], "--key-hex") == 0 && i + 1 < argc) {
            if (!parse_fixed_hex_words(argv[++i], key, 16)) {
                die("invalid --key-hex");
            }
        } else if (strcmp(argv[i], "--iv-hex") == 0 && i + 1 < argc) {
            if (!parse_fixed_hex_words(argv[++i], iv, 8)) {
                die("invalid --iv-hex");
            }
        } else {
            print_usage(argv[0]);
            exit(1);
        }
    }

    if (out_path == NULL) {
        die("build-codebook requires --out");
    }

    fprintf(stdout, "building first-block codebook\n");
    codebook = build_first_block_codebook(key, iv);
    if (!save_codebook(out_path, codebook)) {
        free(codebook);
        exit(1);
    }
    fprintf(stdout, "saved codebook to %s\n", out_path);
    free(codebook);
}

static void cmd_score_key(int argc, char **argv) {
    const char *codebook_path = NULL;
    int stage_num = 0;
    uint32_t key_index = 0;
    int sample_highs = 8;
    int low_step = 8;
    uint16_t *codebook = NULL;
    uint16_t *sample_values = NULL;
    int low_count = 0;
    uint8_t best_low = 0;
    uint32_t score;
    uint8_t *decoded_highs = NULL;
    uint8_t *decoded_lows = NULL;
    int i;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--codebook") == 0 && i + 1 < argc) {
            codebook_path = argv[++i];
        } else if (strcmp(argv[i], "--stage") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &stage_num)) {
                die("invalid --stage");
            }
        } else if (strcmp(argv[i], "--keypair") == 0 && i + 1 < argc) {
            if (!parse_hex8_keypair(argv[++i], &key_index)) {
                die("invalid --keypair");
            }
        } else if (strcmp(argv[i], "--sample-highs") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &sample_highs)) {
                die("invalid --sample-highs");
            }
        } else if (strcmp(argv[i], "--low-step") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &low_step)) {
                die("invalid --low-step");
            }
        } else {
            print_usage(argv[0]);
            exit(1);
        }
    }

    if (codebook_path == NULL || stage_num < 1 || stage_num > MAX_STAGE) {
        die("score-key requires --codebook and --stage 1..8");
    }

    codebook = load_codebook(codebook_path);
    if (codebook == NULL) {
        exit(1);
    }
    sample_values = build_sample_values(sample_highs, low_step, &low_count);
    if (sample_values == NULL) {
        die("invalid sample settings");
    }
    decoded_highs = (uint8_t *)malloc((size_t)(sample_highs * low_count));
    decoded_lows = (uint8_t *)malloc((size_t)(sample_highs * low_count));
    if (decoded_highs == NULL || decoded_lows == NULL) {
        die("out of memory");
    }
    score = sampled_best_score_for_index(
        codebook,
        sample_values,
        stage_num,
        sample_highs,
        low_count,
        key_index,
        decoded_highs,
        decoded_lows,
        &best_low
    );
    fprintf(stdout,
        "stage=%d  key=0x%08" PRIX32 " (%04X%04X)  score=%u  best_low=0x%02X\n",
        stage_num,
        key_index,
        (uint16_t)(key_index >> 16),
        (uint16_t)key_index,
        score,
        best_low);

    free(decoded_highs);
    free(decoded_lows);
    free(sample_values);
    free(codebook);
}

static void cmd_scan_stage(int argc, char **argv) {
    const char *codebook_path = NULL;
    const char *out_path = NULL;
    uint16_t *codebook = NULL;
    int stage_num = 0;
    uint64_t start_index = 0;
    uint64_t count = (1ull << 32);
    int sample_highs = 4;
    int low_step = 16;
    uint32_t keep_top = DEFAULT_KEEP_TOP;
    uint32_t threads = detect_threads();
    uint32_t progress_ms = DEFAULT_PROGRESS_MS;
    uint32_t watch_index = 0;
    int watch_enabled = 0;
    CandidateRow *rows = NULL;
    CandidateRow watch_row;
    int watch_found = 0;
    uint32_t row_count = 0;
    double seconds = 0.0;
    int i;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--codebook") == 0 && i + 1 < argc) {
            codebook_path = argv[++i];
        } else if (strcmp(argv[i], "--stage") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &stage_num)) {
                die("invalid --stage");
            }
        } else if (strcmp(argv[i], "--start-index") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &start_index)) {
                die("invalid --start-index");
            }
        } else if (strcmp(argv[i], "--count") == 0 && i + 1 < argc) {
            if (!parse_u64(argv[++i], &count)) {
                die("invalid --count");
            }
        } else if (strcmp(argv[i], "--sample-highs") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &sample_highs)) {
                die("invalid --sample-highs");
            }
        } else if (strcmp(argv[i], "--low-step") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &low_step)) {
                die("invalid --low-step");
            }
        } else if (strcmp(argv[i], "--keep-top") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &keep_top)) {
                die("invalid --keep-top");
            }
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &threads)) {
                die("invalid --threads");
            }
        } else if (strcmp(argv[i], "--progress-ms") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &progress_ms)) {
                die("invalid --progress-ms");
            }
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (strcmp(argv[i], "--watch-key") == 0 && i + 1 < argc) {
            if (!parse_hex8_keypair(argv[++i], &watch_index)) {
                die("invalid --watch-key");
            }
            watch_enabled = 1;
        } else {
            print_usage(argv[0]);
            exit(1);
        }
    }

    if (codebook_path == NULL || stage_num < 1 || stage_num > MAX_STAGE) {
        die("scan-stage requires --codebook and --stage 1..8");
    }
    if (count == 0) {
        die("--count must be positive");
    }
    if (start_index >= (1ull << 32)) {
        die("--start-index must be below 2^32");
    }
    if (start_index + count > (1ull << 32)) {
        count = (1ull << 32) - start_index;
    }

    codebook = load_codebook(codebook_path);
    if (codebook == NULL) {
        exit(1);
    }

    print_stage_banner("scan-stage", stage_num, sample_highs, low_step, start_index, count, threads, keep_top);
    row_count = run_scan_stage(
        codebook,
        stage_num,
        start_index,
        count,
        sample_highs,
        low_step,
        keep_top,
        threads,
        progress_ms,
        watch_enabled,
        watch_index,
        &rows,
        &watch_found,
        &watch_row,
        &seconds
    );
    fprintf(stdout, "finished in %.3f seconds\n", seconds);
    print_rows(rows, row_count, row_count);
    if (watch_enabled) {
        if (watch_found) {
            fprintf(stdout,
                "watch-key matched: score=%u  idx=0x%08" PRIX32 "  low=0x%02X\n",
                watch_row.score,
                watch_row.index,
                watch_row.best_low);
        } else {
            fprintf(stdout, "watch-key was outside the scanned range or not processed\n");
        }
    }
    if (out_path != NULL) {
        save_rows_tsv(out_path, rows, row_count);
        fprintf(stdout, "saved survivors to %s\n", out_path);
    }

    free(rows);
    free(codebook);
}

static void cmd_refine_stage(int argc, char **argv) {
    const char *codebook_path = NULL;
    const char *in_path = NULL;
    const char *out_path = NULL;
    uint16_t *codebook = NULL;
    uint32_t *indices = NULL;
    uint32_t index_count = 0;
    int stage_num = 0;
    int sample_highs = 8;
    int low_step = 8;
    uint32_t threads = detect_threads();
    uint32_t progress_ms = DEFAULT_PROGRESS_MS;
    uint32_t watch_index = 0;
    int watch_enabled = 0;
    CandidateRow *rows = NULL;
    CandidateRow watch_row;
    int watch_found = 0;
    double seconds = 0.0;
    int i;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--codebook") == 0 && i + 1 < argc) {
            codebook_path = argv[++i];
        } else if (strcmp(argv[i], "--stage") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &stage_num)) {
                die("invalid --stage");
            }
        } else if (strcmp(argv[i], "--in") == 0 && i + 1 < argc) {
            in_path = argv[++i];
        } else if (strcmp(argv[i], "--sample-highs") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &sample_highs)) {
                die("invalid --sample-highs");
            }
        } else if (strcmp(argv[i], "--low-step") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &low_step)) {
                die("invalid --low-step");
            }
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &threads)) {
                die("invalid --threads");
            }
        } else if (strcmp(argv[i], "--progress-ms") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &progress_ms)) {
                die("invalid --progress-ms");
            }
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        } else if (strcmp(argv[i], "--watch-key") == 0 && i + 1 < argc) {
            if (!parse_hex8_keypair(argv[++i], &watch_index)) {
                die("invalid --watch-key");
            }
            watch_enabled = 1;
        } else {
            print_usage(argv[0]);
            exit(1);
        }
    }

    if (codebook_path == NULL || in_path == NULL || stage_num < 1 || stage_num > MAX_STAGE) {
        die("refine-stage requires --codebook, --stage 1..8, and --in");
    }

    indices = load_indices_from_tsv(in_path, &index_count);
    if (indices == NULL) {
        exit(1);
    }
    codebook = load_codebook(codebook_path);
    if (codebook == NULL) {
        free(indices);
        exit(1);
    }

    print_stage_banner("refine-stage", stage_num, sample_highs, low_step, 0, index_count, threads, index_count);
    run_refine_stage(
        codebook,
        stage_num,
        indices,
        index_count,
        sample_highs,
        low_step,
        threads,
        progress_ms,
        watch_enabled,
        watch_index,
        &rows,
        &watch_found,
        &watch_row,
        &seconds
    );
    fprintf(stdout, "finished in %.3f seconds\n", seconds);
    print_rows(rows, index_count, index_count);
    if (watch_enabled) {
        if (watch_found) {
            fprintf(stdout,
                "watch-key matched: score=%u  idx=0x%08" PRIX32 "  low=0x%02X\n",
                watch_row.score,
                watch_row.index,
                watch_row.best_low);
        } else {
            fprintf(stdout, "watch-key was not present in the input survivor file\n");
        }
    }
    if (out_path != NULL) {
        save_rows_tsv(out_path, rows, index_count);
        fprintf(stdout, "saved refined survivors to %s\n", out_path);
    }

    free(rows);
    free(indices);
    free(codebook);
}

static BeamPath *alloc_child_path(const BeamPath *parent) {
    BeamPath *child = (BeamPath *)calloc(1, sizeof(BeamPath));
    if (child == NULL) {
        die("out of memory");
    }
    if (parent != NULL) {
        child->score = parent->score;
        memcpy(child->keys, parent->keys, sizeof(child->keys));
        memcpy(child->states, parent->states, sizeof(child->states));
        memcpy(child->has_key, parent->has_key, sizeof(child->has_key));
        memcpy(child->has_state, parent->has_state, sizeof(child->has_state));
    }
    return child;
}

static void print_path_summary(const BeamPath *path) {
    int stage;
    fprintf(stdout, "score=%" PRIu64 "  keys:", path->score);
    for (stage = 8; stage >= 1; stage--) {
        if (path->has_key[stage]) {
            fprintf(stdout, " s%d:%08" PRIX32, stage, path->keys[stage]);
        }
    }
    fprintf(stdout, "  states:");
    for (stage = 8; stage >= 1; stage--) {
        if (path->has_state[stage]) {
            fprintf(stdout, " s%d:%04X", stage, path->states[stage]);
        }
    }
    fprintf(stdout, "\n");
}

static void free_path_rows(PathRow *rows, uint32_t count) {
    uint32_t i;
    if (rows == NULL) {
        return;
    }
    for (i = 0; i < count; i++) {
        if (rows[i].path != NULL) {
            free_beam_path(rows[i].path);
            free(rows[i].path);
        }
    }
    free(rows);
}

static void cmd_recover_key(int argc, char **argv) {
    const char *codebook_path = NULL;
    const char *save_dir = NULL;
    uint16_t *initial_codebook = NULL;
    RecoverConfig cfg;
    BeamPath **paths = NULL;
    uint32_t path_count = 0;
    int stop_stage = 1;
    int stage;
    int i;

    memset(&cfg, 0, sizeof(cfg));
    cfg.coarse_highs = 4;
    cfg.coarse_low_step = 16;
    cfg.coarse_keep = 16;
    cfg.strong_highs = 8;
    cfg.strong_low_step = 8;
    cfg.strong_keep = 8;
    cfg.threads = detect_threads();
    cfg.progress_ms = DEFAULT_PROGRESS_MS;
    cfg.beam = 16;
    cfg.key_beam = 3;
    cfg.low_profile[1] = 8;
    cfg.low_profile[2] = 17;
    cfg.low_profile[3] = 13;
    cfg.low_profile[4] = 3;
    cfg.low_profile[5] = 2;
    cfg.low_profile[6] = 4;
    cfg.low_profile[7] = 1;
    cfg.low_profile[8] = 1;
    cfg.high_profile[1] = 1;
    cfg.high_profile[2] = 1;
    cfg.high_profile[3] = 1;
    cfg.high_profile[4] = 1;
    cfg.high_profile[5] = 1;
    cfg.high_profile[6] = 1;
    cfg.high_profile[7] = 1;
    cfg.high_profile[8] = 8;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--codebook") == 0 && i + 1 < argc) {
            codebook_path = argv[++i];
        } else if (strcmp(argv[i], "--beam") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &cfg.beam)) {
                die("invalid --beam");
            }
        } else if (strcmp(argv[i], "--key-beam") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &cfg.key_beam)) {
                die("invalid --key-beam");
            }
        } else if (strcmp(argv[i], "--stop-stage") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &stop_stage)) {
                die("invalid --stop-stage");
            }
        } else if (strcmp(argv[i], "--coarse-highs") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &cfg.coarse_highs)) {
                die("invalid --coarse-highs");
            }
        } else if (strcmp(argv[i], "--coarse-low-step") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &cfg.coarse_low_step)) {
                die("invalid --coarse-low-step");
            }
        } else if (strcmp(argv[i], "--coarse-keep") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &cfg.coarse_keep)) {
                die("invalid --coarse-keep");
            }
        } else if (strcmp(argv[i], "--strong-highs") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &cfg.strong_highs)) {
                die("invalid --strong-highs");
            }
        } else if (strcmp(argv[i], "--strong-low-step") == 0 && i + 1 < argc) {
            if (!parse_int(argv[++i], &cfg.strong_low_step)) {
                die("invalid --strong-low-step");
            }
        } else if (strcmp(argv[i], "--strong-keep") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &cfg.strong_keep)) {
                die("invalid --strong-keep");
            }
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &cfg.threads)) {
                die("invalid --threads");
            }
        } else if (strcmp(argv[i], "--progress-ms") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &cfg.progress_ms)) {
                die("invalid --progress-ms");
            }
        } else if (strcmp(argv[i], "--low-profile") == 0 && i + 1 < argc) {
            if (!parse_profile_csv(argv[++i], cfg.low_profile)) {
                die("invalid --low-profile");
            }
        } else if (strcmp(argv[i], "--high-profile") == 0 && i + 1 < argc) {
            if (!parse_profile_csv(argv[++i], cfg.high_profile)) {
                die("invalid --high-profile");
            }
        } else if (strcmp(argv[i], "--candidate-file") == 0 && i + 1 < argc) {
            int arg_stage = 0;
            const char *file_path = NULL;
            if (!parse_stage_file_arg(argv[++i], &arg_stage, &file_path)) {
                die("invalid --candidate-file, expected stage:path");
            }
            cfg.candidate_indices[arg_stage] = load_indices_from_tsv(file_path, &cfg.candidate_counts[arg_stage]);
            if (cfg.candidate_indices[arg_stage] == NULL) {
                die("failed to load candidate file");
            }
        } else if (strcmp(argv[i], "--save-dir") == 0 && i + 1 < argc) {
            save_dir = argv[++i];
        } else {
            print_usage(argv[0]);
            exit(1);
        }
    }

    if (codebook_path == NULL) {
        die("recover-key requires --codebook");
    }
    if (stop_stage < 1 || stop_stage > 8) {
        die("--stop-stage must be in 1..8");
    }

    initial_codebook = load_codebook(codebook_path);
    if (initial_codebook == NULL) {
        exit(1);
    }
    paths = (BeamPath **)calloc(cfg.beam, sizeof(BeamPath *));
    if (paths == NULL) {
        die("out of memory");
    }
    paths[0] = alloc_child_path(NULL);
    paths[0]->codebook = initial_codebook;
    path_count = 1;

    for (stage = 8; stage >= stop_stage; stage--) {
        PathRow *stage_rows = NULL;
        uint32_t stage_row_count = 0;
        uint32_t stage_row_capacity = 0;
        uint32_t p;
        fprintf(stdout, "recover-key: stage %d  active_paths=%u\n", stage, path_count);
        fflush(stdout);

        for (p = 0; p < path_count; p++) {
            BeamPath *path = paths[p];
            CandidateRow *cur_candidates = NULL;
            uint32_t cur_count = 0;
            uint32_t key_limit;

            if (path->prefetched_stage == stage && path->prefetch_rows != NULL) {
                cur_candidates = copy_candidate_rows(path->prefetch_rows, path->prefetch_count);
                cur_count = path->prefetch_count;
            } else {
                cur_candidates = narrow_stage_candidates(
                    path->codebook,
                    stage,
                    &cfg,
                    cfg.candidate_indices[stage],
                    cfg.candidate_counts[stage],
                    p,
                    save_dir,
                    &cur_count
                );
            }
            if (cur_candidates == NULL || cur_count == 0) {
                free(cur_candidates);
                continue;
            }

            key_limit = cur_count;
            if (key_limit > cfg.key_beam) {
                key_limit = cfg.key_beam;
            }

            for (i = 0; i < (int)key_limit; i++) {
                CandidateRow cur = cur_candidates[i];
                int low_count = 0;
                uint8_t low_guesses[256];
                uint16_t *branch_sample_values = NULL;
                int branch_low_count = 0;
                uint16_t *decoded = NULL;
                branch_sample_values = build_sample_values(cfg.strong_highs, cfg.strong_low_step, &branch_low_count);
                if (branch_sample_values == NULL) {
                    die("invalid strong sample settings");
                }
                best_low_plateau_for_index(
                    path->codebook,
                    branch_sample_values,
                    stage,
                    cfg.strong_highs,
                    branch_low_count,
                    cur.index,
                    cfg.low_profile[stage] > 0 ? cfg.low_profile[stage] : 1,
                    low_guesses,
                    (uint32_t *)&low_count
                );
                decoded = decode_codebook_for_index(path->codebook, stage, cur.index);

                if (stage == stop_stage) {
                    int low_i;
                    for (low_i = 0; low_i < low_count; low_i++) {
                        BeamPath *child = alloc_child_path(path);
                        PathRow row;
                        child->score += cur.score;
                        child->keys[stage] = cur.index;
                        child->has_key[stage] = 1;
                        child->states[stage] = low_guesses[low_i];
                        child->has_state[stage] = 1;
                        row.path = child;
                        row.score = child->score;
                        if (stage_row_count == stage_row_capacity) {
                            uint32_t new_cap = stage_row_capacity == 0 ? 32 : stage_row_capacity * 2;
                            PathRow *tmp = (PathRow *)realloc(stage_rows, (size_t)new_cap * sizeof(PathRow));
                            if (tmp == NULL) {
                                die("out of memory");
                            }
                            stage_rows = tmp;
                            stage_row_capacity = new_cap;
                        }
                        stage_rows[stage_row_count++] = row;
                    }
                } else {
                    PathRow *branch_rows = NULL;
                    uint32_t branch_count = 0;
                    uint32_t branch_cap = 0;
                    int low_i;
                    if (cfg.candidate_counts[stage - 1] > 0) {
                        uint32_t next_i;
                        for (next_i = 0; next_i < cfg.candidate_counts[stage - 1]; next_i++) {
                            uint32_t next_index = cfg.candidate_indices[stage - 1][next_i];
                            uint16_t *next_table = precompute_dec_table_for_index(stage - 1, next_index);
                            for (low_i = 0; low_i < low_count; low_i++) {
                                StateHighRow high_rows[256];
                                uint32_t keep_high = cfg.high_profile[stage] > 0 ? cfg.high_profile[stage] : 1;
                                uint32_t h;
                                rank_state_high_candidates_for_table(
                                    decoded,
                                    low_guesses[low_i],
                                    next_table,
                                    branch_sample_values,
                                    cfg.strong_highs,
                                    branch_low_count,
                                    high_rows
                                );
                                if (keep_high > 256) {
                                    keep_high = 256;
                                }
                                for (h = 0; h < keep_high; h++) {
                                    uint16_t state_word = (uint16_t)((high_rows[h].state_high << 8) | low_guesses[low_i]);
                                    uint8_t next_best_low = 0;
                                    uint32_t next_self_score = best_score_after_peel_for_index(
                                        decoded,
                                        state_word,
                                        stage - 1,
                                        next_index,
                                        branch_sample_values,
                                        cfg.strong_highs,
                                        branch_low_count,
                                        &next_best_low
                                    );
                                    BeamPath *child = alloc_child_path(path);
                                    PathRow row;
                                    child->score += cur.score + high_rows[h].score + next_self_score;
                                    child->keys[stage] = cur.index;
                                    child->has_key[stage] = 1;
                                    child->states[stage] = state_word;
                                    child->has_state[stage] = 1;
                                    child->codebook = peel_codebook_from_decoded(decoded, state_word);
                                    row.path = child;
                                    row.score = child->score;
                                    if (branch_count == branch_cap) {
                                        uint32_t new_cap = branch_cap == 0 ? 64 : branch_cap * 2;
                                        PathRow *tmp = (PathRow *)realloc(branch_rows, (size_t)new_cap * sizeof(PathRow));
                                        if (tmp == NULL) {
                                            die("out of memory");
                                        }
                                        branch_rows = tmp;
                                        branch_cap = new_cap;
                                    }
                                    branch_rows[branch_count++] = row;
                                }
                            }
                            free(next_table);
                        }
                    } else {
                        for (low_i = 0; low_i < low_count; low_i++) {
                            uint32_t state_high;
                            for (state_high = 0; state_high < 256; state_high++) {
                                uint16_t state_word = (uint16_t)((state_high << 8) | low_guesses[low_i]);
                                uint16_t *peeled = peel_codebook_from_decoded(decoded, state_word);
                                uint32_t next_count = 0;
                                CandidateRow *next_candidates = narrow_stage_candidates(
                                    peeled,
                                    stage - 1,
                                    &cfg,
                                    cfg.candidate_indices[stage - 1],
                                    cfg.candidate_counts[stage - 1],
                                    0,
                                    NULL,
                                    &next_count
                                );
                                if (next_candidates != NULL && next_count > 0) {
                                    BeamPath *child = alloc_child_path(path);
                                    PathRow row;
                                    child->score += cur.score + next_candidates[0].score;
                                    child->keys[stage] = cur.index;
                                    child->has_key[stage] = 1;
                                    child->states[stage] = state_word;
                                    child->has_state[stage] = 1;
                                    child->codebook = peeled;
                                    child->prefetch_rows = next_candidates;
                                    child->prefetch_count = next_count;
                                    child->prefetched_stage = stage - 1;
                                    row.path = child;
                                    row.score = child->score;
                                    if (branch_count == branch_cap) {
                                        uint32_t new_cap = branch_cap == 0 ? 64 : branch_cap * 2;
                                        PathRow *tmp = (PathRow *)realloc(branch_rows, (size_t)new_cap * sizeof(PathRow));
                                        if (tmp == NULL) {
                                            die("out of memory");
                                        }
                                        branch_rows = tmp;
                                        branch_cap = new_cap;
                                    }
                                    branch_rows[branch_count++] = row;
                                } else {
                                    free(peeled);
                                    free(next_candidates);
                                }
                            }
                        }
                    }
                    if (branch_count > 0) {
                        uint32_t keep = cfg.beam;
                        uint32_t b;
                        qsort(branch_rows, branch_count, sizeof(PathRow), cmp_path_row);
                        for (b = 0; b < branch_count && b < keep; b++) {
                            if (stage_row_count == stage_row_capacity) {
                                uint32_t new_cap = stage_row_capacity == 0 ? 32 : stage_row_capacity * 2;
                                PathRow *tmp = (PathRow *)realloc(stage_rows, (size_t)new_cap * sizeof(PathRow));
                                if (tmp == NULL) {
                                    die("out of memory");
                                }
                                stage_rows = tmp;
                                stage_row_capacity = new_cap;
                            }
                            stage_rows[stage_row_count++] = branch_rows[b];
                            branch_rows[b].path = NULL;
                        }
                    }
                    free_path_rows(branch_rows, branch_count);
                }

                free(decoded);
                free(branch_sample_values);
            }

            free(cur_candidates);
        }

        for (p = 0; p < path_count; p++) {
            free_beam_path(paths[p]);
            free(paths[p]);
        }
        if (stage_row_count == 0) {
            free(stage_rows);
            fprintf(stdout, "recover-key: no surviving paths at stage %d\n", stage);
            break;
        }
        qsort(stage_rows, stage_row_count, sizeof(PathRow), cmp_path_row);
        if (stage_row_count > cfg.beam) {
            uint32_t drop;
            for (drop = cfg.beam; drop < stage_row_count; drop++) {
                if (stage_rows[drop].path != NULL) {
                    free_beam_path(stage_rows[drop].path);
                    free(stage_rows[drop].path);
                    stage_rows[drop].path = NULL;
                }
            }
            stage_row_count = cfg.beam;
        }
        path_count = stage_row_count;
        for (p = 0; p < path_count; p++) {
            paths[p] = stage_rows[p].path;
        }
        free(stage_rows);

        fprintf(stdout, "after stage %d:\n", stage);
        for (p = 0; p < path_count && p < 5; p++) {
            fprintf(stdout, "  #%u ", p + 1);
            print_path_summary(paths[p]);
        }
        fflush(stdout);
    }

    fprintf(stdout, "recover-key final paths:\n");
    for (i = 0; i < (int)path_count; i++) {
        fprintf(stdout, "  #%d ", i + 1);
        print_path_summary(paths[i]);
    }

    for (i = 0; i < (int)path_count; i++) {
        free_beam_path(paths[i]);
        free(paths[i]);
    }
    free(paths);
    for (stage = 1; stage <= 8; stage++) {
        free(cfg.candidate_indices[stage]);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "build-codebook") == 0) {
        cmd_build_codebook(argc, argv);
        return 0;
    }
    if (strcmp(argv[1], "score-key") == 0) {
        cmd_score_key(argc, argv);
        return 0;
    }
    if (strcmp(argv[1], "scan-stage") == 0) {
        cmd_scan_stage(argc, argv);
        return 0;
    }
    if (strcmp(argv[1], "refine-stage") == 0) {
        cmd_refine_stage(argc, argv);
        return 0;
    }
    if (strcmp(argv[1], "recover-key") == 0) {
        cmd_recover_key(argc, argv);
        return 0;
    }
    print_usage(argv[0]);
    return 1;
}
