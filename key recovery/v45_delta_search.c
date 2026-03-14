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

typedef struct {
    uint32_t count;
    uint16_t *inputs;
    uint16_t *outputs;
    int32_t input_pos[65536];
    uint16_t *pair_left[ALPHA_COUNT];
    uint16_t *pair_right[ALPHA_COUNT];
    uint32_t pair_count[ALPHA_COUNT];
} Codebook;

typedef struct {
    uint16_t *hist;
    int32_t inverse_outputs[65536];
} Scratch;

static int load_codebook(const char *path, Codebook *book) {
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

    memset(book, 0, sizeof(*book));
    book->count = count;
    book->inputs = (uint16_t *)malloc(sizeof(uint16_t) * count);
    book->outputs = (uint16_t *)malloc(sizeof(uint16_t) * count);
    if (book->inputs == NULL || book->outputs == NULL) {
        fclose(fp);
        return 0;
    }
    if (fread(book->inputs, sizeof(uint16_t), count, fp) != count ||
        fread(book->outputs, sizeof(uint16_t), count, fp) != count) {
        fclose(fp);
        return 0;
    }
    fclose(fp);

    for (i = 0; i < 65536; i++) {
        book->input_pos[i] = -1;
    }
    for (i = 0; i < count; i++) {
        book->input_pos[book->inputs[i]] = (int32_t)i;
    }

    for (alpha_idx = 0; alpha_idx < ALPHA_COUNT; alpha_idx++) {
        uint16_t alpha = ALPHAS[alpha_idx];
        uint32_t pairs = 0;
        for (i = 0; i < count; i++) {
            if (book->input_pos[(book->inputs[i] + alpha) & MASK16] >= 0) {
                pairs++;
            }
        }
        book->pair_left[alpha_idx] = (uint16_t *)malloc(sizeof(uint16_t) * pairs);
        book->pair_right[alpha_idx] = (uint16_t *)malloc(sizeof(uint16_t) * pairs);
        book->pair_count[alpha_idx] = pairs;
        if (book->pair_left[alpha_idx] == NULL || book->pair_right[alpha_idx] == NULL) {
            return 0;
        }
        pairs = 0;
        for (i = 0; i < count; i++) {
            int32_t j = book->input_pos[(book->inputs[i] + alpha) & MASK16];
            if (j >= 0) {
                book->pair_left[alpha_idx][pairs] = (uint16_t)i;
                book->pair_right[alpha_idx][pairs] = (uint16_t)j;
                pairs++;
            }
        }
    }
    return 1;
}

static void free_codebook(Codebook *book) {
    uint32_t alpha_idx;
    for (alpha_idx = 0; alpha_idx < ALPHA_COUNT; alpha_idx++) {
        free(book->pair_left[alpha_idx]);
        free(book->pair_right[alpha_idx]);
    }
    free(book->inputs);
    free(book->outputs);
}

static int init_scratch(Scratch *scratch) {
    uint32_t i;
    scratch->hist = (uint16_t *)malloc(sizeof(uint16_t) * 65536);
    if (scratch->hist == NULL) {
        return 0;
    }
    for (i = 0; i < 65536; i++) {
        scratch->inverse_outputs[i] = -1;
    }
    return 1;
}

static void free_scratch(Scratch *scratch) {
    free(scratch->hist);
}

static void build_inverse_outputs(const Codebook *book, Scratch *scratch) {
    uint32_t i;
    for (i = 0; i < 65536; i++) {
        scratch->inverse_outputs[i] = -1;
    }
    for (i = 0; i < book->count; i++) {
        scratch->inverse_outputs[book->outputs[i]] = (int32_t)book->inputs[i];
    }
}

static uint32_t score_delta(
    const Codebook *left_book,
    const Codebook *right_book,
    Scratch *scratch,
    uint16_t delta)
{
    uint32_t alpha_idx;
    uint32_t total = 0;

    (void)right_book;
    for (alpha_idx = 0; alpha_idx < ALPHA_COUNT; alpha_idx++) {
        uint32_t best = 0;
        uint32_t pair_idx;
        memset(scratch->hist, 0, sizeof(uint16_t) * 65536);
        for (pair_idx = 0; pair_idx < left_book->pair_count[alpha_idx]; pair_idx++) {
            uint16_t left_index = left_book->pair_left[alpha_idx][pair_idx];
            uint16_t right_index = left_book->pair_right[alpha_idx][pair_idx];
            uint16_t y0 = (uint16_t)(left_book->outputs[left_index] - delta);
            uint16_t y1 = (uint16_t)(left_book->outputs[right_index] - delta);
            int32_t q0 = scratch->inverse_outputs[y0];
            int32_t q1 = scratch->inverse_outputs[y1];
            if (q0 >= 0 && q1 >= 0) {
                uint16_t diff = (uint16_t)(q1 - q0);
                uint16_t next = (uint16_t)(scratch->hist[diff] + 1);
                scratch->hist[diff] = next;
                if (next > best) {
                    best = next;
                }
            }
        }
        total += best;
    }
    return total;
}

static void usage(const char *argv0) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s <left_codebook.bin> <right_codebook.bin>\n", argv0);
}

int main(int argc, char **argv) {
    Codebook left_book;
    Codebook right_book;
    uint16_t global_best_delta = 0;
    uint32_t global_best_score = 0;
    int had_error = 0;

    if (argc != 3) {
        usage(argv[0]);
        return 1;
    }
    if (!load_codebook(argv[1], &left_book) || !load_codebook(argv[2], &right_book)) {
        fprintf(stderr, "failed to load codebooks\n");
        return 1;
    }

#pragma omp parallel shared(global_best_delta, global_best_score, had_error)
    {
        Scratch scratch;
        uint32_t delta;
        uint16_t local_best_delta = 0;
        uint32_t local_best_score = 0;
        if (!init_scratch(&scratch)) {
            had_error = 1;
        } else {
            build_inverse_outputs(&right_book, &scratch);
#pragma omp for schedule(dynamic)
            for (delta = 0; delta < 65536u; delta++) {
                uint32_t score = score_delta(&left_book, &right_book, &scratch, (uint16_t)delta);
                if (score > local_best_score) {
                    local_best_score = score;
                    local_best_delta = (uint16_t)delta;
                }
            }
#pragma omp critical
            {
                if (local_best_score > global_best_score) {
                    global_best_score = local_best_score;
                    global_best_delta = local_best_delta;
                }
            }
            free_scratch(&scratch);
        }
    }

    if (had_error) {
        fprintf(stderr, "failed to allocate scratch buffers\n");
        free_codebook(&left_book);
        free_codebook(&right_book);
        return 2;
    }

    printf("%u %u\n", global_best_delta, global_best_score);
    free_codebook(&left_book);
    free_codebook(&right_book);
    return 0;
}
