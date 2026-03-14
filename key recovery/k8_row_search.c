#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#define MASK16 0xFFFFu
#define ALPHA_COUNT 8

static const uint16_t ALPHAS[ALPHA_COUNT] = {1, 2, 3, 4, 5, 6, 7, 8};

#ifndef ROTL16
#define ROTL16(x, y) (uint16_t)((((uint16_t)(x)) << ((y) & 15)) | (((uint16_t)(x)) >> (16 - ((y) & 15))))
#define ROTR16(x, y) (uint16_t)((((uint16_t)(x)) >> ((y) & 15)) | (((uint16_t)(x)) << (16 - ((y) & 15))))
#endif

static const uint8_t SBOX1[16] = {1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4};
static const uint8_t SBOX2[16] = {6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8};
static const uint8_t SBOX3[16] = {12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13, 15, 4};
static const uint8_t SBOX4[16] = {13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14};

static const uint8_t ISBOX1[16] = {4, 0, 3, 5, 15, 6, 8, 11, 7, 9, 13, 2, 10, 12, 14, 1};
static const uint8_t ISBOX2[16] = {12, 8, 7, 13, 3, 14, 0, 9, 15, 6, 1, 11, 10, 5, 4, 2};
static const uint8_t ISBOX3[16] = {4, 3, 1, 5, 15, 6, 2, 8, 7, 9, 12, 10, 0, 13, 11, 14};
static const uint8_t ISBOX4[16] = {4, 11, 2, 5, 13, 6, 8, 3, 7, 14, 12, 1, 9, 0, 15, 10};

typedef struct {
    uint32_t count;
    uint16_t *inputs;
    uint16_t *outputs;
    int32_t input_pos[65536];
    uint16_t *pair_left[ALPHA_COUNT];
    uint16_t *pair_right[ALPHA_COUNT];
    uint32_t pair_count[ALPHA_COUNT];
} AttackData;

typedef struct {
    uint16_t *decoded;
    uint16_t *hist;
} Scratch;

typedef struct {
    uint16_t best_k0;
    uint16_t best_k1;
    uint32_t best_score;
} SearchResult;

static inline uint16_t do_isbox(uint16_t x) {
    uint8_t a = ISBOX1[(x >> 12) & 0xF];
    uint8_t b = ISBOX2[(x >> 8) & 0xF];
    uint8_t c = ISBOX3[(x >> 4) & 0xF];
    uint8_t d = ISBOX4[x & 0xF];
    return (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
}

static inline uint16_t sep_inrotl16(uint16_t x) {
    uint16_t y = ROTR16(x, 12);
    uint16_t z = ROTR16(x, 8);
    uint8_t a, b, c, d;

    x ^= y ^ z;
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

static inline uint16_t dec_block(uint16_t ct, uint16_t key0, uint16_t key1, uint8_t n) {
    uint16_t key2, key3, t;
    uint8_t b;

    key2 = ROTL16(key0, 6);
    b = (key2 >> 6) & 0xF;
    b = SBOX1[b];
    key2 |= (uint16_t)(b << 6);
    key2 ^= (uint16_t)(n + 2);

    key3 = ROTL16(key1, 10);
    b = (key3 >> 6) & 0xF;
    b = SBOX1[b];
    key3 |= (uint16_t)(b << 6);
    key3 ^= (uint16_t)(n + 3);

    t = ct ^ key3 ^ key2;
    t = do_isbox(t);
    t ^= (uint16_t)(key0 ^ key1);

    t = sep_inrotl16(t);
    t = do_isbox(t);
    t ^= key3;

    t = sep_inrotl16(t);
    t = do_isbox(t);
    t ^= key2;

    t = sep_inrotl16(t);
    t = do_isbox(t);
    t ^= key1;

    t = sep_inrotl16(t);
    t = do_isbox(t);
    t ^= key0;
    return t;
}

static int load_dataset(const char *path, AttackData *data) {
    FILE *fp = fopen(path, "rb");
    uint32_t count;
    uint32_t i, alpha_idx;

    if (fp == NULL) {
        fprintf(stderr, "failed to open %s\n", path);
        return 0;
    }
    if (fread(&count, sizeof(count), 1, fp) != 1) {
        fclose(fp);
        return 0;
    }

    memset(data, 0, sizeof(*data));
    data->count = count;
    data->inputs = (uint16_t *)malloc(sizeof(uint16_t) * count);
    data->outputs = (uint16_t *)malloc(sizeof(uint16_t) * count);
    if (data->inputs == NULL || data->outputs == NULL) {
        fclose(fp);
        return 0;
    }
    if (fread(data->inputs, sizeof(uint16_t), count, fp) != count ||
        fread(data->outputs, sizeof(uint16_t), count, fp) != count) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    for (i = 0; i < 65536; i++) {
        data->input_pos[i] = -1;
    }
    for (i = 0; i < count; i++) {
        data->input_pos[data->inputs[i]] = (int32_t)i;
    }

    for (alpha_idx = 0; alpha_idx < ALPHA_COUNT; alpha_idx++) {
        uint16_t alpha = ALPHAS[alpha_idx];
        uint32_t pairs = 0;
        for (i = 0; i < count; i++) {
            if (data->input_pos[(data->inputs[i] + alpha) & MASK16] >= 0) {
                pairs++;
            }
        }
        data->pair_left[alpha_idx] = (uint16_t *)malloc(sizeof(uint16_t) * pairs);
        data->pair_right[alpha_idx] = (uint16_t *)malloc(sizeof(uint16_t) * pairs);
        data->pair_count[alpha_idx] = pairs;
        if (data->pair_left[alpha_idx] == NULL || data->pair_right[alpha_idx] == NULL) {
            return 0;
        }
        pairs = 0;
        for (i = 0; i < count; i++) {
            int32_t j = data->input_pos[(data->inputs[i] + alpha) & MASK16];
            if (j >= 0) {
                data->pair_left[alpha_idx][pairs] = (uint16_t)i;
                data->pair_right[alpha_idx][pairs] = (uint16_t)j;
                pairs++;
            }
        }
    }
    return 1;
}

static void free_dataset(AttackData *data) {
    uint32_t alpha_idx;
    for (alpha_idx = 0; alpha_idx < ALPHA_COUNT; alpha_idx++) {
        free(data->pair_left[alpha_idx]);
        free(data->pair_right[alpha_idx]);
    }
    free(data->inputs);
    free(data->outputs);
}

static int init_scratch(const AttackData *data, Scratch *scratch) {
    scratch->decoded = (uint16_t *)malloc(sizeof(uint16_t) * data->count);
    scratch->hist = (uint16_t *)malloc(sizeof(uint16_t) * 65536);
    return scratch->decoded != NULL && scratch->hist != NULL;
}

static void free_scratch(Scratch *scratch) {
    free(scratch->decoded);
    free(scratch->hist);
}

static uint32_t score_candidate_single(
    const AttackData *data,
    Scratch *scratch,
    uint8_t stage,
    uint16_t shift,
    uint16_t key0,
    uint16_t key1)
{
    uint32_t alpha_idx;
    uint32_t total = 0;
    uint32_t i;

    for (i = 0; i < data->count; i++) {
        scratch->decoded[i] = dec_block((uint16_t)(data->outputs[i] - shift), key0, key1, stage);
    }

    for (alpha_idx = 0; alpha_idx < ALPHA_COUNT; alpha_idx++) {
        uint32_t best = 0;
        uint32_t pairs = data->pair_count[alpha_idx];
        memset(scratch->hist, 0, sizeof(uint16_t) * 65536);
        for (i = 0; i < pairs; i++) {
            uint16_t left = data->pair_left[alpha_idx][i];
            uint16_t right = data->pair_right[alpha_idx][i];
            uint16_t diff = (uint16_t)(scratch->decoded[right] - scratch->decoded[left]);
            uint16_t next = (uint16_t)(scratch->hist[diff] + 1);
            scratch->hist[diff] = next;
            if (next > best) {
                best = next;
            }
        }
        total += best;
    }
    return total;
}

static uint32_t score_candidate_multi(
    const AttackData *datasets,
    Scratch *scratch_sets,
    uint32_t dataset_count,
    uint8_t stage,
    uint16_t shift,
    uint16_t key0,
    uint16_t key1)
{
    uint32_t total = 0;
    uint32_t i;
    for (i = 0; i < dataset_count; i++) {
        total += score_candidate_single(&datasets[i], &scratch_sets[i], stage, shift, key0, key1);
    }
    return total;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s <stage> <shift> <k1_start> <k1_end> <dataset1.bin> [dataset2.bin ...]\n", argv0);
}

int main(int argc, char **argv) {
    uint8_t stage;
    uint16_t shift;
    uint32_t k1_start;
    uint32_t k1_end;
    uint32_t dataset_count;
    AttackData *datasets;
    SearchResult global_best = {0, 0, 0};
    uint32_t dataset_idx;
    int had_error = 0;

    if (argc < 6) {
        usage(argv[0]);
        return 1;
    }

    stage = (uint8_t)strtoul(argv[1], NULL, 0);
    shift = (uint16_t)strtoul(argv[2], NULL, 0);
    k1_start = (uint32_t)strtoul(argv[3], NULL, 0);
    k1_end = (uint32_t)strtoul(argv[4], NULL, 0);
    dataset_count = (uint32_t)(argc - 5);
    if (k1_end < k1_start || k1_end > 65536u) {
        fprintf(stderr, "invalid k1 range\n");
        return 1;
    }

    datasets = (AttackData *)calloc(dataset_count, sizeof(AttackData));
    if (datasets == NULL) {
        return 1;
    }
    for (dataset_idx = 0; dataset_idx < dataset_count; dataset_idx++) {
        if (!load_dataset(argv[5 + dataset_idx], &datasets[dataset_idx])) {
            fprintf(stderr, "failed to load dataset %s\n", argv[5 + dataset_idx]);
            return 1;
        }
    }

#pragma omp parallel shared(had_error)
    {
        uint32_t k1;
        SearchResult local_best = {0, 0, 0};
        Scratch *scratch_sets = (Scratch *)calloc(dataset_count, sizeof(Scratch));
        int scratch_ok = 1;
        for (dataset_idx = 0; dataset_idx < dataset_count; dataset_idx++) {
            if (!init_scratch(&datasets[dataset_idx], &scratch_sets[dataset_idx])) {
                scratch_ok = 0;
            }
        }
        if (!scratch_ok) {
            had_error = 1;
        } else {
#pragma omp for schedule(dynamic)
            for (k1 = k1_start; k1 < k1_end; k1++) {
                uint32_t k0;
                for (k0 = 0; k0 < 65536u; k0++) {
                    uint32_t score = score_candidate_multi(
                        datasets,
                        scratch_sets,
                        dataset_count,
                        stage,
                        shift,
                        (uint16_t)k0,
                        (uint16_t)k1);
                    if (score > local_best.best_score) {
                        local_best.best_score = score;
                        local_best.best_k0 = (uint16_t)k0;
                        local_best.best_k1 = (uint16_t)k1;
                    }
                }
            }

#pragma omp critical
            {
                if (local_best.best_score > global_best.best_score) {
                    global_best = local_best;
                }
            }
        }

        for (dataset_idx = 0; dataset_idx < dataset_count; dataset_idx++) {
            free_scratch(&scratch_sets[dataset_idx]);
        }
        free(scratch_sets);
    }

    if (had_error) {
        fprintf(stderr, "failed to allocate scratch buffers\n");
        for (dataset_idx = 0; dataset_idx < dataset_count; dataset_idx++) {
            free_dataset(&datasets[dataset_idx]);
        }
        free(datasets);
        return 2;
    }

    printf("%u %u %u\n", global_best.best_k0, global_best.best_k1, global_best.best_score);

    for (dataset_idx = 0; dataset_idx < dataset_count; dataset_idx++) {
        free_dataset(&datasets[dataset_idx]);
    }
    free(datasets);
    return 0;
}
