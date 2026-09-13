/*
 * Exact-filtered ranked inward key recovery for the implemented SEPAR cipher.
 *
 * This is phase two of the PoC.  separ_prefix_attack orders K8 candidates;
 * pass one with --known-k8.  Scores only order finite candidate sets.  A
 * bounded miss is reported as INCONCLUSIVE.  Zero for every tier budget is
 * the exhaustive traversal described in the paper (normally impractical).
 *
 * --oracle-key is used solely by the local chosen-plaintext oracle and, when
 * --audit is present, to print truth ranks.  Acceptance never compares keys:
 * the first key consistent with the finite public transcript is returned.
 */
#include "separ_common.h"

typedef struct {
    uint16_t k0;
    uint16_t k1;
} KeyPair;

#define MAX_CONTEXTS 16u
#define DEFAULT_CONTEXTS 8u

static const uint16_t RANK_DIFFS[] = {
    0x0001u, 0x0002u, 0x0004u, 0x0008u, 0x000fu, 0x0010u
};

static const uint16_t VALIDATION_MASKS[2][8] = {
    {0x0001u,0x0100u,0x1000u,0x8000u,0x55AAu,0xA55Au,0x3C6Eu,0xC3E1u},
    {0xFFFFu,0x0F0Fu,0xF0F0u,0x3333u,0xCCCCu,0x9696u,0x6969u,0x5A5Au}
};
typedef struct {
    uint32_t m4[256];
    uint32_t *m8;
    EdgeCount *full;
    size_t full_count;
} EdgeProfile;

typedef struct {
    uint16_t iv[8];
    uint16_t true_state[8]; /* audit only */
    uint16_t *pivot;
    EdgeProfile edge;
} AttackContext;

typedef struct {
    uint64_t score;
    uint16_t nu;
} NuScore;

typedef struct {
    uint64_t s8;
    uint64_t s16;
    uint8_t value;
} ShiftScore;

typedef struct {
    uint32_t support;
    unsigned bounds[4];
    uint8_t value;
    uint8_t admissible;
} ByteScore;
typedef struct {
    uint32_t support;
    unsigned bounds[4];
    uint16_t state_word;
} StateScore;


typedef struct {
    uint16_t forward_high[256];
    uint16_t inverse_high[256];
    uint16_t forward_middle[16];
    uint16_t inverse_middle[16];
    uint32_t forward_high_total[256];
} TranslationBounds;

typedef struct {
    uint16_t k0;
    uint16_t k1;
    uint64_t s8;
    uint64_t s16;
} RankedPair;

typedef struct {
    unsigned threads;
    unsigned contexts;
    unsigned lane_tiers;
    unsigned pair_tiers;
    unsigned state_tiers;
    uint64_t seed;
    int audit;
    uint16_t oracle_key[16];
    KeyPair known_k8;
    int have_known_k8;
} AttackOptions;

typedef struct {
    const SeparCtx *initial;
    const uint16_t *key;
    uint16_t *table;
    uint32_t begin;
    uint32_t end;
} CodebookWorker;

typedef struct {
    const AttackContext *contexts;
    const uint8_t *active;
    unsigned context_count;
    NuScore *scores;
    uint32_t begin;
    uint32_t end;
} NuWorker;

typedef struct {
    const AttackContext *contexts;
    const uint8_t *active;
    unsigned context_count;
    uint8_t stage;
    const uint16_t *k0_values;
    const uint16_t *k1_values;
    size_t k1_count;
    PairScore *scores;
    uint64_t begin;
    uint64_t end;
} PairWorker;

typedef struct {
    const uint16_t *pivot;
    StateScore *rows;
    KeyPair pair;
    uint8_t stage;
    unsigned begin_h;
    unsigned end_h;
    size_t count;
    int allocation_failed;
} StateWorker;

typedef struct {
    const AttackOptions *opt;
    AttackContext ctx[MAX_CONTEXTS];
    uint8_t active_context[MAX_CONTEXTS];
    unsigned active_count;
    KeyPair pairs[9];
    uint16_t state[MAX_CONTEXTS][8];
    uint8_t low_known[MAX_CONTEXTS][8];
    uint8_t truth_context[MAX_CONTEXTS]; /* audit guard only */
    uint16_t *verification_tables[MAX_CONTEXTS];
    uint64_t nodes;
    uint16_t validation_transcripts[2][64];
    uint64_t leaves;
    uint64_t start_ns;
} Search;

static void inward_usage(const char *program)
{
    printf("usage: %s --known-k8 HEX8 [options]\n", program);
    puts("  --oracle-key HEX64  local oracle secret (default: published key)");
    puts("  --known-k8 HEX8     candidate supplied by the outer bootstrap");
    puts("  --threads N         worker threads, 1..256");
    puts("  --contexts N        deterministic reset codebooks, 1..16 (default 8)");
    puts("  --seed N            deterministic IV-family seed (default 1)");
    puts("  --lane-tiers N      S4 score tiers per stage; 0 means exhaustive");
    puts("  --pair-tiers N      S8 score tiers per lane; 0 means exhaustive");
    puts("  --state-tiers N    joint exact-admissible state-word tiers; 0 means exhaustive");
    puts("  --audit             print truth ranks; never used for selection");
    puts("  --complete          set all three tier budgets to zero");
    puts("  --self-test         cipher, pivot, carry-bound, and factor tests");
    puts("\nA bounded failure is INCONCLUSIVE, never a recovery claim.");
    puts("Acceptance returns the first transcript-consistent representative;");
    puts("numeric equality to the oracle key is reported only by --audit.");
}

static AttackOptions inward_options(int argc, char **argv, int *self_test)
{
    AttackOptions opt;
    int complete = 0;
    memset(&opt, 0, sizeof(opt));
    memcpy(opt.oracle_key, DEFAULT_KEY, sizeof(DEFAULT_KEY));
    opt.threads = detected_threads();
    if (opt.threads > 16u) opt.threads = 16u;
    opt.contexts = DEFAULT_CONTEXTS;
    opt.lane_tiers = 1u;
    opt.pair_tiers = 1u;
    opt.state_tiers = 1u;
    opt.seed = 1u;
    *self_test = 0;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            inward_usage(argv[0]);
            exit(EXIT_SUCCESS);
        } else if (strcmp(argv[i], "--oracle-key") == 0 && i + 1 < argc) {
            if (parse_hex_words(argv[++i], opt.oracle_key, 16u) != 0)
                die("invalid --oracle-key");
        } else if (strcmp(argv[i], "--known-k8") == 0 && i + 1 < argc) {
            uint16_t words[2];
            if (parse_hex_words(argv[++i], words, 2u) != 0)
                die("invalid --known-k8");
            opt.known_k8.k0 = words[0];
            opt.known_k8.k1 = words[1];
            opt.have_known_k8 = 1;
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            opt.threads = parse_unsigned_arg("--threads", argv[++i], 1u, 256u);
        } else if (strcmp(argv[i], "--contexts") == 0 && i + 1 < argc) {
            opt.contexts = parse_unsigned_arg("--contexts", argv[++i], 1u, MAX_CONTEXTS);
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            opt.seed = parse_u64_arg("--seed", argv[++i]);
        } else if (strcmp(argv[i], "--lane-tiers") == 0 && i + 1 < argc) {
            opt.lane_tiers = parse_unsigned_arg("--lane-tiers", argv[++i], 0u, UINT_MAX);
        } else if (strcmp(argv[i], "--pair-tiers") == 0 && i + 1 < argc) {
            opt.pair_tiers = parse_unsigned_arg("--pair-tiers", argv[++i], 0u, UINT_MAX);
        } else if (strcmp(argv[i], "--state-tiers") == 0 && i + 1 < argc) {
            opt.state_tiers = parse_unsigned_arg("--state-tiers", argv[++i], 0u, UINT_MAX);
        } else if (strcmp(argv[i], "--audit") == 0) {
            opt.audit = 1;
        } else if (strcmp(argv[i], "--complete") == 0) {
            complete = 1;
        } else if (strcmp(argv[i], "--self-test") == 0) {
            *self_test = 1;
        } else {
            inward_usage(argv[0]);
            die("unknown or incomplete option");
        }
    }
    if (complete)
        opt.lane_tiers = opt.pair_tiers = opt.state_tiers = 0u;
    if (!*self_test && !opt.have_known_k8)
        die("--known-k8 is required (run separ_prefix_attack first)");
    return opt;
}

static int exhaustive_mode(const AttackOptions *opt)
{
    return opt->lane_tiers == 0u && opt->pair_tiers == 0u &&
           opt->state_tiers == 0u;
}

static uint64_t inward_splitmix64(uint64_t *state)
{
    uint64_t z = (*state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static void deterministic_iv(uint64_t seed, unsigned index, uint16_t iv[8])
{
    uint64_t state = seed;
    for (unsigned skip = 1u; skip < index; ++skip)
        for (unsigned i = 0; i < 8u; ++i) (void)inward_splitmix64(&state);
    for (unsigned i = 0; i < 8u; ++i)
        iv[i] = (uint16_t)inward_splitmix64(&state);
}

THREAD_FUNCTION(codebook_worker_main)
{
    CodebookWorker *worker = (CodebookWorker *)opaque;
    for (uint32_t x = worker->begin; x < worker->end; ++x) {
        SeparCtx local = *worker->initial;
        worker->table[x] = encrypt_word((uint16_t)x, &local, worker->key);
    }
    THREAD_FINISH;
}

static uint16_t *oracle_reset_codebook(const AttackOptions *opt,
                                       const uint16_t iv[8], SeparCtx *initial)
{
    uint16_t *table = (uint16_t *)malloc(WORDS * sizeof(*table));
    ThreadHandle *handles = (ThreadHandle *)calloc(opt->threads, sizeof(*handles));
    CodebookWorker *workers = (CodebookWorker *)calloc(opt->threads, sizeof(*workers));
    if (table == NULL || handles == NULL || workers == NULL)
        die("codebook allocation failed");
    initial_state(opt->oracle_key, iv, initial);
    for (unsigned t = 0; t < opt->threads; ++t) {
        workers[t].initial = initial;
        workers[t].key = opt->oracle_key;
        workers[t].table = table;
        workers[t].begin = (uint32_t)(((uint64_t)WORDS * t) / opt->threads);
        workers[t].end = (uint32_t)(((uint64_t)WORDS * (t + 1u)) / opt->threads);
    }
    run_threads(handles, opt->threads, codebook_worker_main, workers, sizeof(*workers));
    free(workers);
    free(handles);
    return table;
}

static void edge_profile_clear(EdgeProfile *profile)
{
    free(profile->m8);
    free(profile->full);
    memset(profile, 0, sizeof(*profile));
}

static void build_small_edges(const uint16_t *table, EdgeProfile *profile)
{
    edge_profile_clear(profile);
    profile->m8 = (uint32_t *)calloc(BYTE_EDGES, sizeof(*profile->m8));
    if (profile->m8 == NULL) die("edge-matrix allocation failed");
    for (size_t di = 0; di < sizeof(RANK_DIFFS) / sizeof(RANK_DIFFS[0]); ++di) {
        uint16_t d = RANK_DIFFS[di];
        for (uint32_t x = 0; x < WORDS; ++x) {
            uint8_t a8 = (uint8_t)(table[x] >> 8);
            uint8_t b8 = (uint8_t)(table[(uint16_t)(x + d)] >> 8);
            profile->m8[((uint32_t)a8 << 8) | b8]++;
            profile->m4[((uint32_t)(a8 & 15u) << 4) | (b8 & 15u)]++;
        }
    }
}

static void ensure_full_edges(const uint16_t *table, EdgeProfile *profile)
{
    size_t raw_count = (size_t)WORDS *
        (sizeof(RANK_DIFFS) / sizeof(RANK_DIFFS[0]));
    uint32_t *raw;
    size_t count = 0;
    if (profile->full != NULL) return;
    raw = (uint32_t *)malloc(raw_count * sizeof(*raw));
    profile->full = (EdgeCount *)malloc(raw_count * sizeof(*profile->full));
    if (raw == NULL || profile->full == NULL) die("full-edge allocation failed");
    for (size_t di = 0; di < sizeof(RANK_DIFFS) / sizeof(RANK_DIFFS[0]); ++di) {
        uint16_t d = RANK_DIFFS[di];
        for (uint32_t x = 0; x < WORDS; ++x)
            raw[count++] = ((uint32_t)table[x] << 16) |
                           table[(uint16_t)(x + d)];
    }
    qsort(raw, count, sizeof(*raw), uint32_compare);
    profile->full_count = 0;
    for (size_t i = 0; i < count;) {
        size_t j = i + 1u;
        while (j < count && raw[j] == raw[i]) ++j;
        profile->full[profile->full_count].key = raw[i];
        profile->full[profile->full_count].count = (uint32_t)(j - i);
        profile->full_count++;
        i = j;
    }
    free(raw);
}

static uint64_t s4_score(const uint32_t m4[256], uint16_t nu, uint8_t lambda)
{
    uint8_t q[16];
    uint64_t score = 0;
    lane_permutation(nu, q);
    for (unsigned x = 0; x < 16u; ++x) {
        uint8_t a = (uint8_t)((q[x] + lambda) & 15u);
        uint8_t b = (uint8_t)((q[(x + 1u) & 15u] + lambda) & 15u);
        score += m4[((uint32_t)a << 4) | b];
    }
    return score;
}

static uint64_t s8_score(const uint32_t *m8, const uint8_t q[256], uint8_t shift)
{
    uint64_t score = 0;
    for (unsigned x = 0; x < 256u; ++x) {
        uint8_t a = (uint8_t)(q[x] + shift);
        uint8_t b = (uint8_t)(q[(x + 1u) & 255u] + shift);
        score += m8[((uint32_t)a << 8) | b];
    }
    return score;
}

static void quotient_u8(KeyPair pair, uint8_t stage, uint8_t q[256])
{
    for (unsigned x = 0; x < 256u; ++x)
        q[x] = (uint8_t)(enc_block((uint16_t)(x << 8), pair.k0,
                                   pair.k1, stage) >> 8);
}

static uint64_t s16_score(const uint16_t *table, EdgeProfile *profile,
                          KeyPair pair, uint8_t stage, uint8_t shift)
{
    uint16_t translation = (uint16_t)((uint16_t)shift << 8);
    uint16_t first, previous;
    uint64_t score = 0;
    ensure_full_edges(table, profile);
    first = (uint16_t)(enc_block(0u, pair.k0, pair.k1, stage) + translation);
    previous = first;
    for (uint32_t x = 1u; x < WORDS; ++x) {
        uint16_t next = (uint16_t)(enc_block((uint16_t)x, pair.k0,
                                            pair.k1, stage) + translation);
        score += edge_multiplicity(profile->full, profile->full_count,
                                   ((uint32_t)previous << 16) | next);
        previous = next;
    }
    score += edge_multiplicity(profile->full, profile->full_count,
                               ((uint32_t)previous << 16) | first);
    return score;
}
static int nu_cmp(const void *left, const void *right)
{
    const NuScore *a = (const NuScore *)left;
    const NuScore *b = (const NuScore *)right;
    if (a->score != b->score) return a->score > b->score ? -1 : 1;
    return a->nu < b->nu ? -1 : a->nu > b->nu;
}

static int pair_cmp_rank(const void *left, const void *right)
{
    const PairScore *a = (const PairScore *)left;
    const PairScore *b = (const PairScore *)right;
    if (a->score != b->score) return a->score > b->score ? -1 : 1;
    if (a->k0 != b->k0) return a->k0 < b->k0 ? -1 : 1;
    return a->k1 < b->k1 ? -1 : a->k1 > b->k1;
}

static int ranked_pair_cmp(const void *left, const void *right)
{
    const RankedPair *a = (const RankedPair *)left;
    const RankedPair *b = (const RankedPair *)right;
    if (a->s16 != b->s16) return a->s16 > b->s16 ? -1 : 1;
    if (a->s8 != b->s8) return a->s8 > b->s8 ? -1 : 1;
    if (a->k0 != b->k0) return a->k0 < b->k0 ? -1 : 1;
    return a->k1 < b->k1 ? -1 : a->k1 > b->k1;
}



static int byte_cmp(const void *left, const void *right)
{
    const ByteScore *a = (const ByteScore *)left;
    const ByteScore *b = (const ByteScore *)right;
    if (a->admissible != b->admissible)
        return a->admissible ? -1 : 1;
    if (a->support != b->support) return a->support < b->support ? -1 : 1;
    return a->value < b->value ? -1 : a->value > b->value;
}

static int state_cmp(const void *left, const void *right)
{
    const StateScore *a = (const StateScore *)left;
    const StateScore *b = (const StateScore *)right;
    if (a->support != b->support) return a->support < b->support ? -1 : 1;
    return a->state_word < b->state_word ? -1 : a->state_word > b->state_word;
}

THREAD_FUNCTION(nu_worker_main)
{
    NuWorker *worker = (NuWorker *)opaque;
    for (uint32_t nu = worker->begin; nu < worker->end; ++nu) {
        uint64_t total = 0;
        for (unsigned c = 0; c < worker->context_count; ++c) {
            if (!worker->active[c]) continue;
            uint64_t best = 0;
            for (unsigned lambda = 0; lambda < 16u; ++lambda) {
                uint64_t score = s4_score(worker->contexts[c].edge.m4,
                                          (uint16_t)nu, (uint8_t)lambda);
                if (lambda == 0u || score > best) best = score;
            }
            total += best;
        }
        worker->scores[nu].nu = (uint16_t)nu;
        worker->scores[nu].score = total;
    }
    THREAD_FINISH;
}


THREAD_FUNCTION(pair_worker_main)
{
    PairWorker *worker = (PairWorker *)opaque;
    for (uint64_t index = worker->begin; index < worker->end; ++index) {
        size_t i0 = (size_t)(index / worker->k1_count);
        size_t i1 = (size_t)(index % worker->k1_count);
        KeyPair pair = {worker->k0_values[i0], worker->k1_values[i1]};
        uint8_t q[256];
        uint64_t total = 0;
        quotient_u8(pair, worker->stage, q);
        for (unsigned c = 0; c < worker->context_count; ++c) {
            if (!worker->active[c]) continue;
            uint64_t best = 0;
            int have = 0;
            for (unsigned h = 0; h < 256u; ++h) {
                uint64_t score = s8_score(worker->contexts[c].edge.m8, q,
                                          (uint8_t)h);
                if (!have || score > best) {
                    best = score;
                    have = 1;
                }
            }
            total += best;
        }
        worker->scores[index].score = total;
        worker->scores[index].k0 = pair.k0;
        worker->scores[index].k1 = pair.k1;
    }
    THREAD_FINISH;
}

static void add_support_range(int difference[257], unsigned modulus,
                              int first, int last)
{
    if (first > last || last < 0 || first >= (int)modulus) return;
    if (first < 0) first = 0;
    if (last >= (int)modulus) last = (int)modulus - 1;
    difference[first]++;
    difference[last + 1]--;
}

/*
 * For every byte b, compute the four exact quotient-support maxima of
 * x -> table[x]-b.  Each fixed output quotient q contributes before a
 * threshold, after a threshold, or both; inverse supports are updated by
 * moving one boundary column at a time.  The total cost is O(2^16).
 */
static void all_translation_bounds(const uint16_t *table,
                                   TranslationBounds *result)
{
    uint16_t *inverse = (uint16_t *)malloc(WORDS * sizeof(*inverse));
    if (inverse == NULL) die("translation-bound inverse allocation failed");
    memset(result, 0, sizeof(*result));
    for (uint32_t x = 0; x < WORDS; ++x) inverse[table[x]] = (uint16_t)x;

    for (unsigned row = 0; row < 256u; ++row) {
        int minimum[256], maximum[256], difference[257] = {0};
        int support = 0;
        for (unsigned q = 0; q < 256u; ++q) {
            minimum[q] = 256;
            maximum[q] = -1;
        }
        for (unsigned low = 0; low < 256u; ++low) {
            uint16_t y = table[(row << 8) | low];
            unsigned q = y >> 8;
            int l = (int)(y & 255u);
            if (l < minimum[q]) minimum[q] = l;
            if (l > maximum[q]) maximum[q] = l;
        }
        for (unsigned q = 0; q < 256u; ++q) {
            int left_last = maximum[q];
            int right_first = minimum[(q + 1u) & 255u] + 1;
            if (left_last + 1 >= right_first) {
                add_support_range(difference, 256u, 0, 255);
            } else {
                add_support_range(difference, 256u, 0, left_last);
                add_support_range(difference, 256u, right_first, 255);
            }
        }
        for (unsigned b = 0; b < 256u; ++b) {
            support += difference[b];
            result->forward_high_total[b] += (uint32_t)support;
            if ((unsigned)support > result->forward_high[b])
                result->forward_high[b] = (uint16_t)support;
        }
    }

    for (unsigned row = 0; row < 256u; ++row) {
        int minimum[256], maximum[256], difference[257] = {0};
        int support = 0;
        for (unsigned q = 0; q < 256u; ++q) {
            minimum[q] = 16;
            maximum[q] = -1;
        }
        for (unsigned top = 0; top < 16u; ++top) {
            for (unsigned low = 0; low < 16u; ++low) {
                unsigned x = (top << 12) | (row << 4) | low;
                uint16_t y = table[x];
                unsigned q = (y >> 4) & 255u;
                int l = (int)(y & 15u);
                if (l < minimum[q]) minimum[q] = l;
                if (l > maximum[q]) maximum[q] = l;
            }
        }
        for (unsigned q = 0; q < 256u; ++q) {
            int left_last = maximum[q];
            int right_first = minimum[(q + 1u) & 255u] + 1;
            if (left_last + 1 >= right_first) {
                add_support_range(difference, 16u, 0, 15);
            } else {
                add_support_range(difference, 16u, 0, left_last);
                add_support_range(difference, 16u, right_first, 15);
            }
        }
        for (unsigned residue = 0; residue < 16u; ++residue) {
            support += difference[residue];
            if ((unsigned)support > result->forward_middle[residue])
                result->forward_middle[residue] = (uint16_t)support;
        }
    }

    for (unsigned row = 0; row < 256u; ++row) {
        uint16_t multiplicity[256] = {0};
        unsigned support = 0;
        for (unsigned low = 0; low < 256u; ++low) {
            unsigned q = inverse[(row << 8) | low] >> 8;
            if (multiplicity[q]++ == 0u) support++;
        }
        if (support > result->inverse_high[0])
            result->inverse_high[0] = (uint16_t)support;
        for (unsigned b = 1; b < 256u; ++b) {
            unsigned removed = inverse[(row << 8) | (b - 1u)] >> 8;
            unsigned added = inverse[(((row + 1u) & 255u) << 8) |
                                     (b - 1u)] >> 8;
            if (--multiplicity[removed] == 0u) support--;
            if (multiplicity[added]++ == 0u) support++;
            if (support > result->inverse_high[b])
                result->inverse_high[b] = (uint16_t)support;
        }
    }

    for (unsigned row = 0; row < 256u; ++row) {
        uint16_t multiplicity[256] = {0};
        unsigned support = 0;
        for (unsigned top = 0; top < 16u; ++top) {
            for (unsigned low = 0; low < 16u; ++low) {
                unsigned x = (top << 12) | (row << 4) | low;
                unsigned q = (inverse[x] >> 4) & 255u;
                if (multiplicity[q]++ == 0u) support++;
            }
        }
        if (support > result->inverse_middle[0])
            result->inverse_middle[0] = (uint16_t)support;
        for (unsigned residue = 1; residue < 16u; ++residue) {
            for (unsigned top = 0; top < 16u; ++top) {
                unsigned x0 = (top << 12) | (row << 4) | (residue - 1u);
                unsigned x1 = (top << 12) |
                              (((row + 1u) & 255u) << 4) |
                              (residue - 1u);
                unsigned removed = (inverse[x0] >> 4) & 255u;
                unsigned added = (inverse[x1] >> 4) & 255u;
                if (--multiplicity[removed] == 0u) support--;
                if (multiplicity[added]++ == 0u) support++;
            }
            if (support > result->inverse_middle[residue])
                result->inverse_middle[residue] = (uint16_t)support;
        }
    }
    free(inverse);
}

static void bounds_for_byte(const TranslationBounds *all, uint8_t byte,
                            unsigned bounds[4])
{
    unsigned residue = byte & 15u;
    bounds[0] = all->forward_high[byte];
    bounds[1] = all->forward_middle[residue];
    bounds[2] = all->inverse_high[byte];
    bounds[3] = all->inverse_middle[residue];
}

static void byte_order(const uint16_t *table, unsigned rounds,
                       ByteScore rows[256])
{
    TranslationBounds all;
    unsigned limit = rounds >= 8u ? 256u : (1u << rounds);
    all_translation_bounds(table, &all);
    for (unsigned b = 0; b < 256u; ++b) {
        rows[b].value = (uint8_t)b;
        rows[b].support = all.forward_high_total[b];
        bounds_for_byte(&all, (uint8_t)b, rows[b].bounds);
        rows[b].admissible = (uint8_t)(
            rows[b].bounds[0] <= limit && rows[b].bounds[1] <= limit &&
            rows[b].bounds[2] <= limit && rows[b].bounds[3] <= limit);
    }
    qsort(rows, 256u, sizeof(rows[0]), byte_cmp);
}

static unsigned quotient_max_support(const uint16_t *table, int middle)
{
    uint16_t stamp[256] = {0};
    unsigned maximum = 0;
    for (unsigned q = 0; q < 256u; ++q) {
        unsigned count = 0;
        uint16_t epoch = (uint16_t)(q + 1u);
        if (!middle) {
            for (unsigned lo = 0; lo < 256u; ++lo) {
                unsigned out = table[(q << 8) | lo] >> 8;
                if (stamp[out] != epoch) {
                    stamp[out] = epoch;
                    count++;
                }
            }
        } else {
            for (unsigned top = 0; top < 16u; ++top) {
                for (unsigned low = 0; low < 16u; ++low) {
                    unsigned x = (top << 12) | (q << 4) | low;
                    unsigned out = (table[x] >> 4) & 255u;
                    if (stamp[out] != epoch) {
                        stamp[out] = epoch;
                        count++;
                    }
                }
            }
        }
        if (count > maximum) maximum = count;
    }
    return maximum;
}

static int carry_admissible(const uint16_t *table, unsigned rounds,
                            unsigned bounds[4])
{
    uint16_t *inverse = (uint16_t *)malloc(WORDS * sizeof(*inverse));
    unsigned limit = rounds >= 8u ? 256u : (1u << rounds);
    if (inverse == NULL) die("inverse-table allocation failed");
    for (uint32_t x = 0; x < WORDS; ++x) inverse[table[x]] = (uint16_t)x;
    bounds[0] = quotient_max_support(table, 0);
    bounds[1] = quotient_max_support(table, 1);
    bounds[2] = quotient_max_support(inverse, 0);
    bounds[3] = quotient_max_support(inverse, 1);
    free(inverse);
    return bounds[0] <= limit && bounds[1] <= limit &&
           bounds[2] <= limit && bounds[3] <= limit;
}

static void subtract_byte(const uint16_t *source, uint8_t byte, uint16_t *dest)
{
    for (uint32_t x = 0; x < WORDS; ++x)
        dest[x] = (uint16_t)(source[x] - byte);
}

static void inverse_shifted(const uint16_t *source, KeyPair pair, uint8_t stage,
                            uint8_t shift, uint16_t *dest)
{
    uint16_t translation = (uint16_t)((uint16_t)shift << 8);
    for (uint32_t x = 0; x < WORDS; ++x)
        dest[x] = dec_block((uint16_t)(source[x] - translation),
                            pair.k0, pair.k1, stage);
}

static uint16_t true_nu_for_stage(const Search *search, uint8_t stage)
{
    return lane_tuple_from_pair(search->opt->oracle_key[(stage - 1u) * 2u],
                                search->opt->oracle_key[(stage - 1u) * 2u + 1u]);
}

static int branch_is_true_through(const Search *search, uint8_t low_stage)
{
    if (!search->opt->audit) return 0;
    for (unsigned c = 0; c < search->opt->contexts; ++c)
        if (search->active_context[c] && !search->truth_context[c]) return 0;
    for (uint8_t stage = low_stage; stage <= 8u; ++stage) {
        KeyPair truth = {
            search->opt->oracle_key[(stage - 1u) * 2u],
            search->opt->oracle_key[(stage - 1u) * 2u + 1u]
        };
        if (search->pairs[stage].k0 != truth.k0 ||
            search->pairs[stage].k1 != truth.k1) return 0;
    }
    return 1;
}

static void rebuild_edges(Search *search)
{
    for (unsigned c = 0; c < search->opt->contexts; ++c)
        if (search->active_context[c])
            build_small_edges(search->ctx[c].pivot, &search->ctx[c].edge);
}

static NuScore *rank_nus(Search *search, uint8_t stage)
{
    NuScore *rows = (NuScore *)malloc(WORDS * sizeof(*rows));
    ThreadHandle *handles =
        (ThreadHandle *)calloc(search->opt->threads, sizeof(*handles));
    NuWorker *workers =
        (NuWorker *)calloc(search->opt->threads, sizeof(*workers));
    if (rows == NULL || handles == NULL || workers == NULL)
        die("lane-rank allocation failed");
    for (unsigned t = 0; t < search->opt->threads; ++t) {
        workers[t].contexts = search->ctx;
        workers[t].context_count = search->opt->contexts;
        workers[t].scores = rows;
        workers[t].active = search->active_context;
        workers[t].begin =
            (uint32_t)(((uint64_t)WORDS * t) / search->opt->threads);
        workers[t].end =
            (uint32_t)(((uint64_t)WORDS * (t + 1u)) / search->opt->threads);
    }
    run_threads(handles, search->opt->threads, nu_worker_main,
                workers, sizeof(*workers));
    qsort(rows, WORDS, sizeof(*rows), nu_cmp);
    if (search->opt->audit &&
        branch_is_true_through(search, (uint8_t)(stage + 1u))) {
        uint16_t truth = true_nu_for_stage(search, stage);
        size_t greater = 0, tied = 0, better_tiers = 0;
        uint64_t truth_score = 0;
        uint64_t previous = UINT64_MAX;
        for (size_t i = 0; i < WORDS; ++i)
            if (rows[i].nu == truth) truth_score = rows[i].score;
        for (size_t i = 0; i < WORDS; ++i) {
            if (rows[i].score > truth_score) {
                greater++;
                if (rows[i].score != previous) {
                    better_tiers++;
                    previous = rows[i].score;
                }
            }
            if (rows[i].score == truth_score) tied++;
        }
        printf("AUDIT stage=%u S4_true_nu=%04X rank=%zu tier_rank=%zu "
               "tied=%zu score=%" PRIu64 "\n",
               stage, truth, greater + 1u, better_tiers + 1u, tied,
               truth_score);
    }
    free(workers);
    free(handles);
    return rows;
}

static PairScore *rank_pairs_in_nu(Search *search, uint8_t stage, uint16_t nu,
                                   size_t *out_count)
{
    uint16_t *k0_values = (uint16_t *)malloc(WORDS * sizeof(*k0_values));
    uint16_t *k1_values = (uint16_t *)malloc(WORDS * sizeof(*k1_values));
    size_t k0_count, k1_count, count;
    PairScore *rows;
    ThreadHandle *handles;
    PairWorker *workers;
    if (k0_values == NULL || k1_values == NULL) die("fibre allocation failed");
    k0_count = collect_word_candidates((uint8_t)(nu & 15u),
                                       (uint8_t)((nu >> 8) & 15u),
                                       1, k0_values);
    k1_count = collect_word_candidates((uint8_t)((nu >> 4) & 15u),
                                       (uint8_t)((nu >> 12) & 15u),
                                       0, k1_values);
    count = k0_count * k1_count;
    rows = (PairScore *)malloc(count * sizeof(*rows));
    handles = (ThreadHandle *)calloc(search->opt->threads, sizeof(*handles));
    workers = (PairWorker *)calloc(search->opt->threads, sizeof(*workers));
    if (rows == NULL || handles == NULL || workers == NULL)
        die("pair-rank allocation failed");
    for (unsigned t = 0; t < search->opt->threads; ++t) {
        workers[t].contexts = search->ctx;
        workers[t].context_count = search->opt->contexts;
        workers[t].active = search->active_context;
        workers[t].stage = stage;
        workers[t].k0_values = k0_values;
        workers[t].k1_values = k1_values;
        workers[t].k1_count = k1_count;
        workers[t].scores = rows;
        workers[t].begin = ((uint64_t)count * t) / search->opt->threads;
        workers[t].end = ((uint64_t)count * (t + 1u)) / search->opt->threads;
    }
    run_threads(handles, search->opt->threads, pair_worker_main,
                workers, sizeof(*workers));
    qsort(rows, count, sizeof(*rows), pair_cmp_rank);
    if (search->opt->audit &&
        branch_is_true_through(search, (uint8_t)(stage + 1u)) &&
        nu == true_nu_for_stage(search, stage)) {
        uint16_t tk0 = search->opt->oracle_key[(stage - 1u) * 2u];
        uint16_t tk1 = search->opt->oracle_key[(stage - 1u) * 2u + 1u];
        size_t greater = 0, tied = 0, better_tiers = 0;
        uint64_t truth_score = 0;
        uint64_t previous = UINT64_MAX;
        for (size_t i = 0; i < count; ++i)
            if (rows[i].k0 == tk0 && rows[i].k1 == tk1)
                truth_score = rows[i].score;
        for (size_t i = 0; i < count; ++i) {
            if (rows[i].score > truth_score) {
                greater++;
                if (rows[i].score != previous) {
                    better_tiers++;
                    previous = rows[i].score;
                }
            }
            if (rows[i].score == truth_score) tied++;
        }
        printf("AUDIT stage=%u S8_true_pair=%04X%04X rank=%zu "
               "tier_rank=%zu tied=%zu fibre=%zu score=%" PRIu64 "\n",
               stage, tk0, tk1, greater + 1u, better_tiers + 1u,
               tied, count, truth_score);
    }
    free(workers);
    free(handles);
    free(k1_values);
    free(k0_values);
    *out_count = count;
    return rows;
}

static uint64_t refine_pair_s16(Search *search, uint8_t stage, KeyPair pair)
{
    uint8_t q[256];
    uint64_t aggregate = 0;
    quotient_u8(pair, stage, q);
    for (unsigned c = 0; c < search->opt->contexts; ++c) {
        if (!search->active_context[c]) continue;
        ShiftScore shifts[256];
        uint64_t best_s8 = 0, best_s16 = 0;
        int have_s8 = 0, have_s16 = 0;
        for (unsigned h = 0; h < 256u; ++h) {
            uint64_t score = s8_score(search->ctx[c].edge.m8, q, (uint8_t)h);
            shifts[h].value = (uint8_t)h;
            shifts[h].s8 = score;
            shifts[h].s16 = 0;
            if (!have_s8 || score > best_s8) {
                best_s8 = score;
                have_s8 = 1;
            }
        }
        for (unsigned i = 0; i < 256u; ++i) {
            if (shifts[i].s8 != best_s8) continue;
            shifts[i].s16 = s16_score(search->ctx[c].pivot,
                                      &search->ctx[c].edge, pair, stage,
                                      shifts[i].value);
            if (!have_s16 || shifts[i].s16 > best_s16) {
                best_s16 = shifts[i].s16;
                have_s16 = 1;
            }
        }
        aggregate += best_s16;
    }
    return aggregate;
}

THREAD_FUNCTION(state_worker_main)
{
    StateWorker *worker = (StateWorker *)opaque;
    StateScore *out = worker->rows + (size_t)worker->begin_h * 256u;
    uint16_t *peeled = (uint16_t *)malloc(WORDS * sizeof(*peeled));
    unsigned limit = 1u << (worker->stage - 1u);
    size_t count = 0;
    if (peeled == NULL) {
        worker->allocation_failed = 1;
    } else {
        for (unsigned h = worker->begin_h; h < worker->end_h; ++h) {
            TranslationBounds all;
            inverse_shifted(worker->pivot, worker->pair, worker->stage,
                            (uint8_t)h, peeled);
            all_translation_bounds(peeled, &all);
            for (unsigned b = 0; b < 256u; ++b) {
                unsigned bounds[4];
                bounds_for_byte(&all, (uint8_t)b, bounds);
                if (bounds[0] > limit || bounds[1] > limit ||
                    bounds[2] > limit || bounds[3] > limit) continue;
                out[count].support = all.forward_high_total[b];
                memcpy(out[count].bounds, bounds, sizeof(bounds));
                out[count].state_word = (uint16_t)((h << 8) | b);
                count++;
            }
        }
        free(peeled);
    }
    worker->count = count;
    THREAD_FINISH;
}

static StateScore *state_order(const uint16_t *pivot, KeyPair pair,
                               uint8_t stage, unsigned thread_count,
                               size_t *out_count)
{
    StateScore *rows = (StateScore *)malloc(WORDS * sizeof(*rows));
    ThreadHandle *handles;
    StateWorker *workers;
    size_t count = 0;
    if (thread_count == 0u) thread_count = 1u;
    if (thread_count > 256u) thread_count = 256u;
    handles = (ThreadHandle *)calloc(thread_count, sizeof(*handles));
    workers = (StateWorker *)calloc(thread_count, sizeof(*workers));
    if (rows == NULL || handles == NULL || workers == NULL)
        die("state-order allocation failed");
    for (unsigned t = 0; t < thread_count; ++t) {
        workers[t].pivot = pivot;
        workers[t].rows = rows;
        workers[t].pair = pair;
        workers[t].stage = stage;
        workers[t].begin_h = (unsigned)(((uint64_t)256u * t) / thread_count);
        workers[t].end_h =
            (unsigned)(((uint64_t)256u * (t + 1u)) / thread_count);
    }
    run_threads(handles, thread_count, state_worker_main,
                workers, sizeof(*workers));
    for (unsigned t = 0; t < thread_count; ++t)
        if (workers[t].allocation_failed)
            die("state-order worker allocation failed");
    for (unsigned t = 0; t < thread_count; ++t) {
        size_t source = (size_t)workers[t].begin_h * 256u;
        size_t n = workers[t].count;
        if (n != 0u && count != source)
            memmove(rows + count, rows + source, n * sizeof(*rows));
        count += n;
    }
    free(workers);
    free(handles);
    qsort(rows, count, sizeof(*rows), state_cmp);
    *out_count = count;
    return rows;
}
static int stage1_factor_for_h(const uint16_t *pivot, KeyPair pair,
                               uint8_t h, uint16_t *out_s1)
{
    uint16_t translation = (uint16_t)((uint16_t)h << 8);
    uint16_t s1 = dec_block((uint16_t)(pivot[0] - translation),
                            pair.k0, pair.k1, 1u);
    for (uint32_t x = 1u; x < WORDS; ++x) {
        uint16_t value = dec_block((uint16_t)(pivot[x] - translation),
                                   pair.k0, pair.k1, 1u);
        if ((uint16_t)(value - (uint16_t)x) != s1) return 0;
    }
    *out_s1 = s1;
    return 1;
}

static int exact_stage1_factor(const uint16_t *pivot, KeyPair pair,
                               uint8_t *out_h2, uint16_t *out_s1)
{
    for (unsigned h = 0; h < 256u; ++h) {
        uint16_t s1;
        if (stage1_factor_for_h(pivot, pair, (uint8_t)h, &s1)) {
            *out_h2 = (uint8_t)h;
            *out_s1 = s1;
            return 1;
        }
    }
    return 0;
}

static uint16_t validation_plaintext(unsigned transcript, unsigned i)
{
    return (uint16_t)(
        (i * 0x9E37u + 0xB7E1u + transcript * 0x6D2Bu) ^
        (i << (transcript + 1u)));
}

static void collect_validation_transcripts(Search *search)
{
    for (unsigned transcript = 0; transcript < 2u; ++transcript) {
        uint16_t iv[8];
        SeparCtx oracle;
        for (unsigned i = 0; i < 8u; ++i)
            iv[i] = (uint16_t)(
                search->ctx[0].iv[i] ^ VALIDATION_MASKS[transcript][i]);
        initial_state(search->opt->oracle_key, iv, &oracle);
        for (unsigned i = 0; i < 64u; ++i)
            search->validation_transcripts[transcript][i] = encrypt_word(
                validation_plaintext(transcript, i), &oracle,
                search->opt->oracle_key);
    }
}
static int verify_recovered(Search *search)
{
    uint16_t candidate[16];
    for (unsigned stage = 1; stage <= 8u; ++stage) {
        candidate[(stage - 1u) * 2u] = search->pairs[stage].k0;
        candidate[(stage - 1u) * 2u + 1u] = search->pairs[stage].k1;
    }

    /* The recovered state is checked against the specified four-round IV map. */
    for (unsigned c = 0; c < search->opt->contexts; ++c) {
        SeparCtx initialized;
        if (!search->active_context[c]) continue;
        initial_state(candidate, search->ctx[c].iv, &initialized);
        if (memcmp(initialized.state, search->state[c],
                   sizeof(initialized.state)) != 0) return 0;
    }

    /* Every queried recovery codebook, retained from the online phase. */
    for (unsigned c = 0; c < search->opt->contexts; ++c) {
        SeparCtx candidate_initial;
        if (search->verification_tables[c] == NULL) return 0;
        initial_state(candidate, search->ctx[c].iv, &candidate_initial);
        for (uint32_t x = 0; x < WORDS; ++x) {
            SeparCtx local = candidate_initial;
            if (encrypt_word((uint16_t)x, &local, candidate) !=
                search->verification_tables[c][x]) return 0;
        }
    }

    /* Two additional IVs, each one stateful 64-word transcript. */
    for (unsigned transcript = 0; transcript < 2u; ++transcript) {
        uint16_t iv[8];
        SeparCtx candidate_ctx;
        for (unsigned i = 0; i < 8u; ++i)
            iv[i] = (uint16_t)(
                search->ctx[0].iv[i] ^ VALIDATION_MASKS[transcript][i]);
        initial_state(candidate, iv, &candidate_ctx);
        for (unsigned i = 0; i < 64u; ++i) {
            uint16_t pt = validation_plaintext(transcript, i);
            if (encrypt_word(pt, &candidate_ctx, candidate) !=
                search->validation_transcripts[transcript][i])
                return 0;
        }
    }

    printf("VERIFICATION=PASS codebooks=%ux65536 held_out=2x64 "
           "reconstructed_initialization_contexts=%u retired_contexts=%u\n",
           search->opt->contexts, search->active_count,
           search->opt->contexts - search->active_count);
    printf("RECOVERED_KEY=");
    for (unsigned i = 0; i < 16u; ++i) printf("%04X", candidate[i]);
    putchar('\n');
    if (search->opt->audit)
        printf("AUDIT_EXACT_KEY=%s\n",
               memcmp(candidate, search->opt->oracle_key,
                      sizeof(candidate)) == 0 ? "PASS" : "FAIL");
    return 1;
}

static int recover_stage(Search *search, uint8_t stage);

static int try_stage1_context(Search *search, KeyPair pair,
                              unsigned context)
{
    if (context == search->opt->contexts) {
        search->pairs[1] = pair;
        search->leaves++;
        if (verify_recovered(search)) return 1;
        return 0;
    }
    if (!search->active_context[context])
        return try_stage1_context(search, pair, context + 1u);
    for (unsigned h = 0; h < 256u; ++h) {
        uint16_t s1;
        uint16_t old_s1, old_s2;
        if (!stage1_factor_for_h(search->ctx[context].pivot, pair,
                                 (uint8_t)h, &s1)) continue;
        old_s1 = search->state[context][0];
        old_s2 = search->state[context][1];
        search->state[context][0] = s1;
        search->state[context][1] =
            (uint16_t)(search->low_known[context][1] |
                       ((uint16_t)h << 8));
        if (try_stage1_context(search, pair, context + 1u)) return 1;
        search->state[context][0] = old_s1;
        search->state[context][1] = old_s2;
    }
    return 0;
}

static int try_stage1_pair(Search *search, KeyPair pair)
{
    return try_stage1_context(search, pair, 0u);
}

static int advance_candidate_context(Search *search, uint8_t stage,
                                     KeyPair pair, unsigned context);

static void audit_state_rank(Search *search, uint8_t stage, unsigned context,
                             const StateScore *states, size_t count)
{
    uint16_t truth;
    uint32_t score = 0, previous = UINT32_MAX;
    size_t greater = 0, tied = 0, better_tiers = 0;
    int retained = 0;
    if (!search->opt->audit || !branch_is_true_through(search, stage)) return;
    truth = (uint16_t)(
        ((search->ctx[context].true_state[stage] >> 8) << 8) |
        (search->ctx[context].true_state[stage - 1u] & 255u));
    for (size_t i = 0; i < count; ++i) {
        if (states[i].state_word == truth) {
            score = states[i].support;
            retained = 1;
            break;
        }
    }
    if (!retained) {
        printf("AUDIT stage=%u context=%u state_true=%04X retained=0\n",
               stage, context + 1u, truth);
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        if (states[i].support < score) {
            greater++;
            if (states[i].support != previous) {
                better_tiers++;
                previous = states[i].support;
            }
        }
        if (states[i].support == score) tied++;
    }
    printf("AUDIT stage=%u context=%u state_true=%04X rank=%zu "
           "tier_rank=%zu tied=%zu retained=%zu support=%u\n",
           stage, context + 1u, truth, greater + 1u,
           better_tiers + 1u, tied, count, score);
}

static int advance_candidate_context(Search *search, uint8_t stage,
                                     KeyPair pair, unsigned context)
{
    const AttackOptions *opt = search->opt;
    StateScore *states;
    size_t count;
    unsigned tier = 0;
    if (context == opt->contexts)
        return recover_stage(search, (uint8_t)(stage - 1u));

    if (!search->active_context[context])
        return advance_candidate_context(search, stage, pair, context + 1u);
    states = state_order(search->ctx[context].pivot, pair, stage,
                         opt->threads, &count);
    audit_state_rank(search, stage, context, states, count);
    if (count != 0u && opt->state_tiers != 0u &&
        search->active_count > 1u) {
        size_t first_end = 1u;
        int result;
        while (first_end < count &&
               states[first_end].support == states[0].support) first_end++;
        if (first_end > 1u) {
            if (opt->audit)
                printf("CONTEXT_RETIRED stage=%u context=%u first_tier=%zu "
                       "admissible=%zu active_before=%u\n",
                       stage, context + 1u, first_end, count,
                       search->active_count);
            if (opt->audit && branch_is_true_through(search, stage))
                printf("AUDIT retirement stage=%u context=%u "
                       "first_tier=%zu\n", stage, context + 1u, first_end);
            search->active_context[context] = 0u;
            search->active_count--;
            result = advance_candidate_context(search, stage, pair,
                                               context + 1u);
            search->active_count++;
            search->active_context[context] = 1u;
            free(states);
            return result;
        }
    }
    for (size_t i = 0; i < count;) {
        size_t end = i + 1u;
        while (end < count && states[end].support == states[i].support) end++;
        tier++;
        if (opt->state_tiers != 0u && tier > opt->state_tiers) break;
        for (size_t j = i; j < end; ++j) {
            uint8_t h = (uint8_t)(states[j].state_word >> 8);
            uint8_t b = (uint8_t)states[j].state_word;
            uint16_t *peeled = (uint16_t *)malloc(WORDS * sizeof(*peeled));
            uint16_t *next = (uint16_t *)malloc(WORDS * sizeof(*next));
            uint16_t old_state = search->state[context][stage];
            uint8_t old_low = search->low_known[context][stage - 1u];
            uint8_t old_truth = search->truth_context[context];
            uint16_t *old_pivot;
            if (peeled == NULL || next == NULL)
                die("joint-state pivot allocation failed");
            inverse_shifted(search->ctx[context].pivot, pair, stage, h, peeled);
            subtract_byte(peeled, b, next);
            free(peeled);

            search->nodes++;
            search->state[context][stage] =
                (uint16_t)(search->low_known[context][stage] |
                           ((uint16_t)h << 8));
            search->low_known[context][stage - 1u] = b;
            if (opt->audit)
                search->truth_context[context] = (uint8_t)(
                    old_truth &&
                    h == (uint8_t)(search->ctx[context].true_state[stage] >> 8) &&
                    b == (uint8_t)search->ctx[context].true_state[stage - 1u]);
            old_pivot = search->ctx[context].pivot;
            search->ctx[context].pivot = next;
            if (advance_candidate_context(search, stage, pair, context + 1u)) {
                free(old_pivot);
                free(states);
                return 1;
            }
            search->ctx[context].pivot = old_pivot;
            search->state[context][stage] = old_state;
            search->low_known[context][stage - 1u] = old_low;
            search->truth_context[context] = old_truth;
            free(next);
        }
        i = end;
    }
    free(states);
    return 0;
}
static int try_ranked_pair(Search *search, uint8_t stage, RankedPair row)
{
    KeyPair pair = {row.k0, row.k1};
    KeyPair saved = search->pairs[stage];
    search->pairs[stage] = pair;
    if (stage == 1u) {
        if (try_stage1_pair(search, pair)) return 1;
    } else if (advance_candidate_context(search, stage, pair, 0u)) {
        return 1;
    }
    search->pairs[stage] = saved;
    return 0;
}

static int recover_stage(Search *search, uint8_t stage)
{
    NuScore *nus;
    unsigned lane_tier = 0;
    uint64_t phase_start;
    if (stage == 0u) return 0;
    phase_start = now_ns();
    rebuild_edges(search);
    nus = rank_nus(search, stage);
    printf("STAGE=%u phase=S4 elapsed=%.3f\n", stage,
           (double)(now_ns() - phase_start) / 1e9);

    for (size_t ni = 0; ni < WORDS;) {
        size_t nend = ni + 1u;
        while (nend < WORDS && nus[nend].score == nus[ni].score) nend++;
        lane_tier++;
        if (search->opt->lane_tiers != 0u &&
            lane_tier > search->opt->lane_tiers) break;

        for (size_t n = ni; n < nend; ++n) {
            size_t pair_count;
            PairScore *pairs;
            unsigned pair_tier = 0;
            phase_start = now_ns();
            pairs = rank_pairs_in_nu(search, stage, nus[n].nu, &pair_count);
            printf("STAGE=%u phase=S8 nu=%04X fibre=%zu elapsed=%.3f\n",
                   stage, nus[n].nu, pair_count,
                   (double)(now_ns() - phase_start) / 1e9);

            for (size_t pi = 0; pi < pair_count;) {
                size_t pend = pi + 1u;
                RankedPair *refined;
                while (pend < pair_count &&
                       pairs[pend].score == pairs[pi].score) pend++;
                pair_tier++;
                if (search->opt->pair_tiers != 0u &&
                    pair_tier > search->opt->pair_tiers) break;

                refined = (RankedPair *)malloc(
                    (pend - pi) * sizeof(*refined));
                if (refined == NULL) die("S16 refinement allocation failed");
                for (size_t j = pi; j < pend; ++j) {
                    KeyPair pair = {pairs[j].k0, pairs[j].k1};
                    refined[j - pi].k0 = pair.k0;
                    refined[j - pi].k1 = pair.k1;
                    refined[j - pi].s8 = pairs[j].score;
                    refined[j - pi].s16 =
                        refine_pair_s16(search, stage, pair);
                }
                qsort(refined, pend - pi, sizeof(*refined), ranked_pair_cmp);
                for (size_t j = 0; j < pend - pi; ++j) {
                    if (try_ranked_pair(search, stage, refined[j])) {
                        free(refined);
                        free(pairs);
                        free(nus);
                        return 1;
                    }
                    rebuild_edges(search);
                }
                free(refined);
                pi = pend;
            }
            free(pairs);
        }
        ni = nend;
    }
    free(nus);
    return 0;
}

static void audit_outer_byte_rank(Search *search, unsigned context,
                                  const ByteScore bytes[256])
{
    uint8_t truth = (uint8_t)search->ctx[context].true_state[7];
    uint32_t score = 0, previous = UINT32_MAX;
    size_t greater = 0, tied = 0, better_tiers = 0, retained = 0;
    if (!branch_is_true_through(search, 8u)) return;
    for (unsigned i = 0; i < 256u; ++i)
        if (bytes[i].admissible && bytes[i].value == truth)
            score = bytes[i].support;
    for (unsigned i = 0; i < 256u; ++i) {
        if (!bytes[i].admissible) continue;
        retained++;
        if (bytes[i].support < score) {
            greater++;
            if (bytes[i].support != previous) {
                better_tiers++;
                previous = bytes[i].support;
            }
        }
        if (bytes[i].support == score) tied++;
    }
    printf("AUDIT stage=8 context=%u byte_true=%02X rank=%zu "
           "tier_rank=%zu tied=%zu retained=%zu support=%u\n",
           context + 1u, truth, greater + 1u, better_tiers + 1u,
           tied, retained, score);
}

static int peel_k8_context(Search *search, unsigned context)
{
    KeyPair pair = search->pairs[8];
    uint16_t *peeled;
    ByteScore bytes[256];
    unsigned tier = 0;
    if (context == search->opt->contexts) return recover_stage(search, 7u);

    if (!search->active_context[context])
        return peel_k8_context(search, context + 1u);
    peeled = (uint16_t *)malloc(WORDS * sizeof(*peeled));
    if (peeled == NULL) die("K8 peel allocation failed");
    inverse_shifted(search->ctx[context].pivot, pair, 8u, 0u, peeled);
    byte_order(peeled, 7u, bytes);
    audit_outer_byte_rank(search, context, bytes);

    if (bytes[0].admissible && search->opt->state_tiers != 0u &&
        search->active_count > 1u) {
        size_t first_end = 1u;
        int result;
        while (first_end < 256u && bytes[first_end].admissible &&
               bytes[first_end].support == bytes[0].support) first_end++;
        if (first_end > 1u) {
            if (search->opt->audit)
                printf("CONTEXT_RETIRED stage=8 context=%u first_tier=%zu "
                       "active_before=%u\n", context + 1u, first_end,
                       search->active_count);
            if (search->opt->audit && branch_is_true_through(search, 8u))
                printf("AUDIT retirement stage=8 context=%u "
                       "first_tier=%zu\n", context + 1u, first_end);
            search->active_context[context] = 0u;
            search->active_count--;
            result = peel_k8_context(search, context + 1u);
            search->active_count++;
            search->active_context[context] = 1u;
            free(peeled);
            return result;
        }
    }
    for (unsigned i = 0; i < 256u; ++i) {
        uint16_t *next;
        if (!bytes[i].admissible) break;
        if (i == 0u || bytes[i].support != bytes[i - 1u].support) {
            tier++;
            if (search->opt->state_tiers != 0u &&
                tier > search->opt->state_tiers) break;
        }
        next = (uint16_t *)malloc(WORDS * sizeof(*next));
        if (next == NULL) die("K8 pivot allocation failed");
        subtract_byte(peeled, bytes[i].value, next);
        {
            uint16_t *old = search->ctx[context].pivot;
            uint8_t old_low = search->low_known[context][7];
            uint8_t old_truth = search->truth_context[context];
            search->ctx[context].pivot = next;
            search->low_known[context][7] = bytes[i].value;
            if (search->opt->audit)
                search->truth_context[context] = (uint8_t)(
                    old_truth && bytes[i].value ==
                    (uint8_t)search->ctx[context].true_state[7]);
            if (peel_k8_context(search, context + 1u)) {
                free(old);
                free(peeled);
                return 1;
            }
            search->ctx[context].pivot = old;
            search->low_known[context][7] = old_low;
            search->truth_context[context] = old_truth;
        }
        free(next);
    }
    free(peeled);
    return 0;
}

static int inward_self_test(const AttackOptions *opt)
{
    uint16_t iv[8];
    SeparCtx initialized;
    uint16_t *root, *current, *next;
    unsigned bounds[4];
    int status = separ_cipher_self_test();
    if (status != 0) return status;
    deterministic_iv(1u, 1u, iv);
    if (iv[0] != 0x5CC1u || iv[1] != 0xEC67u ||
        iv[7] != 0x8575u) {
        fprintf(stderr, "[self-test] deterministic IV family mismatch\n");
        return 1;
    }

    root = oracle_reset_codebook(opt, iv, &initialized);
    current = root;
    for (int stage = 8; stage >= 2; --stage) {
        KeyPair pair = {
            opt->oracle_key[(stage - 1) * 2],
            opt->oracle_key[(stage - 1) * 2 + 1]
        };
        uint8_t hnext = stage == 8 ? 0u :
            (uint8_t)(initialized.state[stage] >> 8);
        uint8_t b = (uint8_t)initialized.state[stage - 1];
        uint16_t truth = (uint16_t)(((uint16_t)hnext << 8) | b);
        uint16_t *w = (uint16_t *)malloc(WORDS * sizeof(*w));
        TranslationBounds fast_all;
        StateScore *ordered;
        size_t ordered_count;
        unsigned fast_bounds[4];
        unsigned limit = 1u << (stage - 1);
        int found = 0;
        next = (uint16_t *)malloc(WORDS * sizeof(*next));
        if (w == NULL || next == NULL) die("self-test allocation failed");

        ordered = state_order(current, pair, (uint8_t)stage, opt->threads,
                              &ordered_count);
        if (stage == 8 && opt->threads != 1u) {
            StateScore *serial;
            size_t serial_count;
            int same;
            serial = state_order(current, pair, (uint8_t)stage, 1u,
                                 &serial_count);
            same = serial_count == ordered_count;
            for (size_t i = 0; same && i < ordered_count; ++i)
                same = serial[i].support == ordered[i].support &&
                       serial[i].state_word == ordered[i].state_word &&
                       memcmp(serial[i].bounds, ordered[i].bounds,
                              sizeof(serial[i].bounds)) == 0;
            free(serial);
            if (!same) {
                fprintf(stderr,
                        "[self-test] serial/threaded state order mismatch\n");
                free(ordered);
                free(w); free(next); free(root);
                return 1;
            }
        }
        for (size_t i = 0; i < ordered_count; ++i)
            if (ordered[i].state_word == truth) found = 1;
        free(ordered);
        if (!found) {
            fprintf(stderr,
                    "[self-test] true joint state rejected at stage %d\n",
                    stage);
            if (current != root) free(current);
            free(w); free(next); free(root);
            return 1;
        }

        inverse_shifted(current, pair, (uint8_t)stage, hnext, w);
        all_translation_bounds(w, &fast_all);
        if (stage == 8) {
            for (unsigned candidate = 0; candidate < 256u; ++candidate) {
                unsigned slow_bounds[4], candidate_fast[4];
                int slow_ok, fast_ok;
                bounds_for_byte(&fast_all, (uint8_t)candidate, candidate_fast);
                subtract_byte(w, (uint8_t)candidate, next);
                slow_ok = carry_admissible(next, 7u, slow_bounds);
                fast_ok = candidate_fast[0] <= 128u &&
                          candidate_fast[1] <= 128u &&
                          candidate_fast[2] <= 128u &&
                          candidate_fast[3] <= 128u;
                if (slow_ok != fast_ok ||
                    memcmp(slow_bounds, candidate_fast,
                           sizeof(slow_bounds)) != 0) {
                    fprintf(stderr,
                            "[self-test] optimized/slow bound mismatch b=%02X\n",
                            candidate);
                    if (current != root) free(current);
                    free(w); free(next); free(root);
                    return 1;
                }
            }
        }
        bounds_for_byte(&fast_all, b, fast_bounds);
        subtract_byte(w, b, next);
        free(w);
        if (!carry_admissible(next, (unsigned)(stage - 1), bounds) ||
            memcmp(bounds, fast_bounds, sizeof(bounds)) != 0 ||
            fast_bounds[0] > limit || fast_bounds[1] > limit ||
            fast_bounds[2] > limit || fast_bounds[3] > limit) {
            fprintf(stderr,
                    "[self-test] true carry bound rejected at stage %d\n",
                    stage);
            if (current != root) free(current);
            free(next); free(root);
            return 1;
        }
        if (current != root) free(current);
        current = next;
    }
    {
        KeyPair pair = {opt->oracle_key[0], opt->oracle_key[1]};
        uint8_t h2;
        uint16_t s1;
        if (!exact_stage1_factor(current, pair, &h2, &s1) ||
            h2 != (uint8_t)(initialized.state[1] >> 8) ||
            s1 != initialized.state[0]) {
            fprintf(stderr, "[self-test] exact stage-1 factor failed\n");
            free(current);
            free(root);
            return 1;
        }
    }
    printf("[self-test] serial/threaded joint-state order equivalence ... ok\n");
    printf("[self-test] all-translation/slow equivalence and "
           "joint-state retention ... ok\n");
    printf("[self-test] pivot induction, four carry bounds, and "
           "exact factor ... ok\n");
    free(current);
    free(root);
    return 0;
}

int main(int argc, char **argv)
{
    int self_test;
    int found;
    AttackOptions opt = inward_options(argc, argv, &self_test);
    Search search;
    if (self_test)
        return inward_self_test(&opt) ? EXIT_FAILURE : EXIT_SUCCESS;

    memset(&search, 0, sizeof(search));
    search.opt = &opt;
    search.active_count = opt.contexts;
    memset(search.active_context, 1, opt.contexts);
    search.pairs[8] = opt.known_k8;
    search.start_ns = now_ns();
    printf("SEPAR ranked inward recovery\n");
    printf("K8_SOURCE=external candidate=%04X%04X contexts=%u threads=%u "
           "seed=%" PRIu64 "\n", opt.known_k8.k0, opt.known_k8.k1,
           opt.contexts, opt.threads, opt.seed);
    printf("BUDGETS lane=%u pair=%u state=%u (0=exhaustive)\n",
           opt.lane_tiers, opt.pair_tiers, opt.state_tiers);

    for (unsigned c = 0; c < opt.contexts; ++c) {
        SeparCtx initial;
        deterministic_iv(opt.seed, c + 1u, search.ctx[c].iv);
        search.ctx[c].pivot =
            oracle_reset_codebook(&opt, search.ctx[c].iv, &initial);
        search.truth_context[c] = 1u;
        memcpy(search.ctx[c].true_state, initial.state,
               sizeof(initial.state));
        search.verification_tables[c] =
            (uint16_t *)malloc(WORDS * sizeof(*search.verification_tables[c]));
        if (search.verification_tables[c] == NULL)
            die("verification table allocation failed");
        memcpy(search.verification_tables[c], search.ctx[c].pivot,
               WORDS * sizeof(*search.verification_tables[c]));
    }
    collect_validation_transcripts(&search);
    printf("ORACLE codebook_contexts=%u codebook_reset_messages=%u "
           "codebook_word_encryptions=%u held_out_reset_messages=2 "
           "held_out_word_encryptions=128 total_reset_messages=%u "
           "total_word_encryptions=%u\n",
           opt.contexts, opt.contexts * WORDS, opt.contexts * WORDS,
           opt.contexts * WORDS + 2u, opt.contexts * WORDS + 128u);

    found = peel_k8_context(&search, 0u);
    if (!found) {
        const char *reason = exhaustive_mode(&opt) ?
            "candidate-space-exhausted" : "rank-budget-exhausted";
        printf("RESULT=INCONCLUSIVE reason=%s nodes=%" PRIu64
               " leaves=%" PRIu64 " elapsed=%.3f\n", reason,
               search.nodes, search.leaves,
               (double)(now_ns() - search.start_ns) / 1e9);
    }
    else
        printf("RESULT=SUCCESS nodes=%" PRIu64 " leaves=%" PRIu64
               " elapsed=%.3f\n", search.nodes, search.leaves,
               (double)(now_ns() - search.start_ns) / 1e9);

    for (unsigned c = 0; c < opt.contexts; ++c) {
        edge_profile_clear(&search.ctx[c].edge);
        free(search.ctx[c].pivot);
        free(search.verification_tables[c]);
    }
    return found ? EXIT_SUCCESS : 2;
}
