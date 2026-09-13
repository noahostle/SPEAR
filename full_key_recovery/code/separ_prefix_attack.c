/*
 * Deterministic fixed-IV exhaustive-prefix bootstrap for SEPAR K8.
 *
 * Build on POSIX: cc -O3 -std=c11 -pthread separ_prefix_attack.c -o separ_prefix_attack
 * Build on Windows (MSVC): cl /O2 /std:c11 separ_prefix_attack.c
 */

#include "separ_common.h"

typedef struct {
    uint64_t score;
    uint16_t nu;
} LaneScore;

typedef struct {
    uint32_t begin;
    uint32_t end;
    const SeparCtx *initial;
    const uint16_t *key;
    uint64_t lane_edges[LANE_EDGES];
    uint64_t *byte_edges;
    uint32_t *full_edges;
    size_t full_edge_count;
} QueryWorker;

typedef struct {
    uint32_t begin;
    uint32_t end;
    const uint64_t *lane_edges;
    LaneScore *scores;
} LaneWorker;

typedef struct {
    uint64_t begin;
    uint64_t end;
    const uint64_t *byte_edges;
    const uint16_t *k0_values;
    const uint16_t *k1_values;
    size_t k1_count;
    PairScore *scores;
} LiftWorker;

typedef struct {
    size_t begin;
    size_t end;
    const EdgeCount *edge_counts;
    size_t edge_count;
    const PairScore *high_scores;
    PairScore *full_scores;
} FullLiftWorker;

typedef struct {
    unsigned threads;
    unsigned top;
    unsigned lane_rank;
    int emit_fallback;
    int self_test;
    uint16_t key[16];
    uint16_t iv[8];
} Options;

static const uint16_t DEFAULT_IV[8] = {0};

THREAD_FUNCTION(query_worker_main)
{
    QueryWorker *worker = (QueryWorker *)opaque;
    for (uint32_t prefix = worker->begin; prefix < worker->end; ++prefix) {
        SeparCtx after_prefix = *worker->initial;
        uint16_t outputs[PROBE_COUNT];
        encrypt_word((uint16_t)prefix, &after_prefix, worker->key);
        for (unsigned qi = 0; qi < PROBE_COUNT; ++qi) {
            SeparCtx second = after_prefix;
            outputs[qi] = encrypt_word(PROBES[qi], &second, worker->key);
        }
        for (unsigned di = 1; di < PROBE_COUNT; ++di) {
            uint8_t a8 = (uint8_t)(outputs[0] >> 8);
            uint8_t b8 = (uint8_t)(outputs[di] >> 8);
            uint8_t a4 = (uint8_t)(a8 & 15u);
            uint8_t b4 = (uint8_t)(b8 & 15u);
            worker->lane_edges[((unsigned)a4 << 4) | b4]++;
            worker->byte_edges[((unsigned)a8 << 8) | b8]++;
            worker->full_edges[worker->full_edge_count++] =
                ((uint32_t)outputs[0] << 16) | outputs[di];
        }
    }
    THREAD_FINISH;
}

THREAD_FUNCTION(lane_worker_main)
{
    LaneWorker *worker = (LaneWorker *)opaque;
    for (uint32_t value = worker->begin; value < worker->end; ++value) {
        uint8_t permutation[16];
        uint64_t score = 0;
        lane_permutation((uint16_t)value, permutation);
        for (unsigned b = 0; b < 16u; ++b) {
            uint8_t from = permutation[b];
            uint8_t to = permutation[(b + 1u) & 15u];
            score += worker->lane_edges[((unsigned)from << 4) | to];
        }
        worker->scores[value].score = score;
        worker->scores[value].nu = (uint16_t)value;
    }
    THREAD_FINISH;
}

THREAD_FUNCTION(lift_worker_main)
{
    LiftWorker *worker = (LiftWorker *)opaque;
    for (uint64_t index = worker->begin; index < worker->end; ++index) {
        size_t i0 = (size_t)(index / worker->k1_count);
        size_t i1 = (size_t)(index % worker->k1_count);
        uint16_t k0 = worker->k0_values[i0];
        uint16_t k1 = worker->k1_values[i1];
        uint8_t quotient[256];
        uint64_t score = 0;
        for (unsigned h = 0; h < 256u; ++h) {
            quotient[h] = (uint8_t)(enc_block((uint16_t)(h << 8), k0, k1, 8) >> 8);
        }
        for (unsigned h = 0; h < 256u; ++h) {
            uint8_t from = quotient[h];
            uint8_t to = quotient[(h + 1u) & 255u];
            score += worker->byte_edges[((unsigned)from << 8) | to];
        }
        worker->scores[index].score = score;
        worker->scores[index].k0 = k0;
        worker->scores[index].k1 = k1;
    }
    THREAD_FINISH;
}

THREAD_FUNCTION(full_lift_worker_main)
{
    FullLiftWorker *worker = (FullLiftWorker *)opaque;
    for (size_t index = worker->begin; index < worker->end; ++index) {
        uint16_t k0 = worker->high_scores[index].k0;
        uint16_t k1 = worker->high_scores[index].k1;
        uint16_t first = enc_block(0, k0, k1, 8);
        uint16_t previous = first;
        uint64_t score = 0;
        for (uint32_t x = 0; x < WORDS - 1u; ++x) {
            uint16_t next = enc_block((uint16_t)(x + 1u), k0, k1, 8);
            uint32_t edge = ((uint32_t)previous << 16) | next;
            score += edge_multiplicity(worker->edge_counts, worker->edge_count, edge);
            previous = next;
        }
        score += edge_multiplicity(worker->edge_counts, worker->edge_count,
                                   ((uint32_t)previous << 16) | first);
        worker->full_scores[index].score = score;
        worker->full_scores[index].k0 = k0;
        worker->full_scores[index].k1 = k1;
    }
    THREAD_FINISH;
}

static int lane_score_compare(const void *left, const void *right)
{
    const LaneScore *a = (const LaneScore *)left;
    const LaneScore *b = (const LaneScore *)right;
    if (a->score != b->score) return a->score > b->score ? -1 : 1;
    if (a->nu != b->nu) return a->nu < b->nu ? -1 : 1;
    return 0;
}

static int pair_score_compare(const void *left, const void *right)
{
    const PairScore *a = (const PairScore *)left;
    const PairScore *b = (const PairScore *)right;
    if (a->score != b->score) return a->score > b->score ? -1 : 1;
    if (a->k0 != b->k0) return a->k0 < b->k0 ? -1 : 1;
    if (a->k1 != b->k1) return a->k1 < b->k1 ? -1 : 1;
    return 0;
}

static void print_usage(const char *program)
{
    printf("usage: %s [--threads N] [--top N] [--lane-rank N]\n", program);
    printf("          [--emit-fallback]\n");
    printf("          [--key HEX64] [--iv HEX32]\n");
    printf("       %s --self-test\n", program);
    printf("\n");
    printf("  --threads N    worker count, 1..256\n");
    printf("  --top N        diagnostic rows printed, 1..65536\n");
    printf("  --lane-rank N  lift exactly the Nth score-ordered S4 lane (1..65536);\n");
    printf("                 this is the exact escalation path after the maxima fail\n");
    printf("  --emit-fallback  emit every remaining raw key in the selected S4 fibres\n");
    printf("                   for exhaustive continuation after the fast candidate\n");
    printf("\n  By default every global S4 maximizer is lifted.  --lane-rank makes\n");
    printf("  the remaining lanes individually enumerable without a maximality premise.\n");
}

static Options parse_options(int argc, char **argv)
{
    Options options;
    options.threads = detected_threads();
    options.top = 5;
    options.lane_rank = 0;
    options.emit_fallback = 0;
    options.self_test = 0;
    memcpy(options.key, DEFAULT_KEY, sizeof(options.key));
    memcpy(options.iv, DEFAULT_IV, sizeof(options.iv));
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            options.threads = parse_unsigned_arg("--threads", argv[++i],
                                                 1u, 256u);
        } else if (strcmp(argv[i], "--top") == 0 && i + 1 < argc) {
            options.top = parse_unsigned_arg("--top", argv[++i],
                                             1u, WORDS);
        } else if (strcmp(argv[i], "--lane-rank") == 0 && i + 1 < argc) {
            options.lane_rank = parse_unsigned_arg("--lane-rank", argv[++i],
                                                   1u, WORDS);
        } else if (strcmp(argv[i], "--emit-fallback") == 0) {
            options.emit_fallback = 1;
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            if (parse_hex_words(argv[++i], options.key, 16) != 0) die("key must contain exactly 64 hexadecimal characters");
        } else if (strcmp(argv[i], "--iv") == 0 && i + 1 < argc) {
            if (parse_hex_words(argv[++i], options.iv, 8) != 0) die("IV must contain exactly 32 hexadecimal characters");
        } else if (strcmp(argv[i], "--self-test") == 0) {
            options.self_test = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        } else {
            print_usage(argv[0]);
            die("unknown or incomplete option");
        }
    }
    return options;
}

static int u64_compare(const void *left, const void *right)
{
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return a < b ? -1 : a > b ? 1 : 0;
}

static int self_test_lane_injectivity(void)
{
    uint64_t *permutations = (uint64_t *)malloc(WORDS * sizeof(*permutations));
    if (permutations == NULL) die("self-test allocation failed");
    for (uint32_t nu = 0; nu < WORDS; ++nu) {
        uint8_t permutation[16];
        uint64_t packed = 0;
        lane_permutation((uint16_t)nu, permutation);
        for (unsigned b = 0; b < 16u; ++b) packed |= (uint64_t)permutation[b] << (4u * b);
        permutations[nu] = packed;
    }
    qsort(permutations, WORDS, sizeof(*permutations), u64_compare);
    for (uint32_t i = 1; i < WORDS; ++i) {
        if (permutations[i - 1u] == permutations[i]) {
            free(permutations);
            return 1;
        }
    }
    free(permutations);
    return 0;
}

static size_t find_lane_rank(const LaneScore *scores, uint16_t nu)
{
    for (size_t i = 0; i < WORDS; ++i) if (scores[i].nu == nu) return i + 1u;
    return 0;
}

static size_t find_pair_rank(const PairScore *scores, size_t count, uint16_t k0, uint16_t k1)
{
    for (size_t i = 0; i < count; ++i) {
        if (scores[i].k0 == k0 && scores[i].k1 == k1) return i + 1u;
    }
    return 0;
}

int main(int argc, char **argv)
{
    Options options = parse_options(argc, argv);
    if (options.self_test) {
        int status = separ_cipher_self_test();
        if (status == 0) {
            printf("[self-test] completing injectivity check ... ");
            fflush(stdout);
            status = self_test_lane_injectivity();
            printf("%s\n", status ? "FAIL" : "ok");
        }
        return status ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    SeparCtx initial;
    QueryWorker *query_workers;
    LaneWorker *lane_workers;
    ThreadHandle *handles;
    LaneScore *lane_scores;
    uint64_t lane_edges[LANE_EDGES] = {0};
    uint64_t *byte_edges;
    uint32_t *raw_full_edges;
    EdgeCount *full_edge_counts;
    size_t raw_full_edge_count = 0;
    size_t full_edge_count = 0;
    size_t lane_global_max_count = 0;
    size_t selected_lane_start = 0;
    size_t selected_lane_count = 0;
    uint16_t true_nu;
    uint64_t attack_start = now_ns();
    uint64_t phase_start;

    initial_state(options.key, options.iv, &initial);
    true_nu = lane_tuple_from_pair(options.key[14], options.key[15]);
    printf("SEPAR deterministic exhaustive-prefix K8 bootstrap\n");
    printf("threads=%u prefixes=65536 probes={0,1,2,4,8,15,16}\n", options.threads);
    printf("oracle_messages=458752 logical_word_encryptions=917504 optimized_word_encryptions=524288\n");
    printf("audit_true_K8=(%04X,%04X) audit_true_nu=%04X\n",
           options.key[14], options.key[15], true_nu);

    handles = (ThreadHandle *)calloc(options.threads, sizeof(*handles));
    query_workers = (QueryWorker *)calloc(options.threads, sizeof(*query_workers));
    lane_workers = (LaneWorker *)calloc(options.threads, sizeof(*lane_workers));
    lane_scores = (LaneScore *)malloc(WORDS * sizeof(*lane_scores));
    byte_edges = (uint64_t *)calloc(BYTE_EDGES, sizeof(*byte_edges));
    raw_full_edges = (uint32_t *)malloc((size_t)WORDS * DIFF_COUNT * sizeof(*raw_full_edges));
    full_edge_counts = (EdgeCount *)malloc((size_t)WORDS * DIFF_COUNT * sizeof(*full_edge_counts));
    if (handles == NULL || query_workers == NULL || lane_workers == NULL ||
        lane_scores == NULL || byte_edges == NULL || raw_full_edges == NULL ||
        full_edge_counts == NULL) die("allocation failed");

    phase_start = now_ns();
    for (unsigned t = 0; t < options.threads; ++t) {
        query_workers[t].begin = (uint32_t)(((uint64_t)WORDS * t) / options.threads);
        query_workers[t].end = (uint32_t)(((uint64_t)WORDS * (t + 1u)) / options.threads);
        query_workers[t].initial = &initial;
        query_workers[t].key = options.key;
        query_workers[t].byte_edges = (uint64_t *)calloc(BYTE_EDGES, sizeof(uint64_t));
        query_workers[t].full_edges = (uint32_t *)malloc(
            (size_t)(query_workers[t].end - query_workers[t].begin) * DIFF_COUNT * sizeof(uint32_t));
        if (query_workers[t].byte_edges == NULL || query_workers[t].full_edges == NULL) {
            die("query-worker edge allocation failed");
        }
    }
    run_threads(handles, options.threads, query_worker_main, query_workers, sizeof(*query_workers));
    for (unsigned t = 0; t < options.threads; ++t) {
        for (unsigned e = 0; e < LANE_EDGES; ++e) lane_edges[e] += query_workers[t].lane_edges[e];
        for (unsigned e = 0; e < BYTE_EDGES; ++e) byte_edges[e] += query_workers[t].byte_edges[e];
        memcpy(raw_full_edges + raw_full_edge_count, query_workers[t].full_edges,
               query_workers[t].full_edge_count * sizeof(uint32_t));
        raw_full_edge_count += query_workers[t].full_edge_count;
        free(query_workers[t].full_edges);
        free(query_workers[t].byte_edges);
    }
    qsort(raw_full_edges, raw_full_edge_count, sizeof(*raw_full_edges), uint32_compare);
    for (size_t i = 0; i < raw_full_edge_count;) {
        size_t j = i + 1u;
        while (j < raw_full_edge_count && raw_full_edges[j] == raw_full_edges[i]) ++j;
        full_edge_counts[full_edge_count].key = raw_full_edges[i];
        full_edge_counts[full_edge_count].count = (uint32_t)(j - i);
        ++full_edge_count;
        i = j;
    }
    printf("phase=query+aggregate elapsed=%.3f s edges=%u\n",
           (double)(now_ns() - phase_start) / 1e9, WORDS * DIFF_COUNT);

    phase_start = now_ns();
    for (unsigned t = 0; t < options.threads; ++t) {
        lane_workers[t].begin = (uint32_t)(((uint64_t)WORDS * t) / options.threads);
        lane_workers[t].end = (uint32_t)(((uint64_t)WORDS * (t + 1u)) / options.threads);
        lane_workers[t].lane_edges = lane_edges;
        lane_workers[t].scores = lane_scores;
    }
    run_threads(handles, options.threads, lane_worker_main, lane_workers, sizeof(*lane_workers));
    qsort(lane_scores, WORDS, sizeof(*lane_scores), lane_score_compare);
    lane_global_max_count = 1u;
    while (lane_global_max_count < WORDS &&
           lane_scores[lane_global_max_count].score == lane_scores[0].score) {
        ++lane_global_max_count;
    }
    if (options.lane_rank != 0u) {
        selected_lane_start = (size_t)options.lane_rank - 1u;
        selected_lane_count = 1u;
    } else {
        selected_lane_start = 0u;
        selected_lane_count = lane_global_max_count;
    }
    {
        size_t rank = find_lane_rank(lane_scores, true_nu);
        uint64_t true_score = rank == 0 ? 0 : lane_scores[rank - 1u].score;
        uint64_t greater = 0;
        uint64_t equal = 0;
        for (size_t i = 0; i < WORDS; ++i) {
            if (lane_scores[i].score > true_score) ++greater;
            if (lane_scores[i].score == true_score) ++equal;
        }
        printf("phase=lane-enumeration elapsed=%.3f s candidates=65536 "
               "global_maximizers=%zu\n",
               (double)(now_ns() - phase_start) / 1e9,
               lane_global_max_count);
        printf("selected_lane_start_rank=%zu selected_lane_count=%zu\n",
               selected_lane_start + 1u, selected_lane_count);
        printf("true_lane_rank=%zu true_lane_score=%" PRIu64 " greater=%" PRIu64 " tied=%" PRIu64 "\n",
               rank, true_score, greater, equal);
        for (unsigned i = 0; i < options.top; ++i) {
            printf("lane[%u] nu=%04X score=%" PRIu64 "%s\n", i + 1u,
                   lane_scores[i].nu, lane_scores[i].score,
                   lane_scores[i].nu == true_nu ? " true" : "");
        }
    }

    {
        uint16_t *k0_values = (uint16_t *)malloc(WORDS * sizeof(uint16_t));
        uint16_t *k1_values = (uint16_t *)malloc(WORDS * sizeof(uint16_t));
        uint64_t pair_count = 0u;
        PairScore *pair_scores;
        LiftWorker *lift_workers;
        FullLiftWorker *full_lift_workers;
        if (k0_values == NULL || k1_values == NULL) die("lift-list allocation failed");
        for (size_t lane_offset = 0; lane_offset < selected_lane_count;
             ++lane_offset) {
            size_t lane_index = selected_lane_start + lane_offset;
            uint16_t nu = lane_scores[lane_index].nu;
            size_t k0_count = collect_word_candidates(
                (uint8_t)(nu & 15u), (uint8_t)((nu >> 8) & 15u),
                1, k0_values);
            size_t k1_count = collect_word_candidates(
                (uint8_t)((nu >> 4) & 15u),
                (uint8_t)((nu >> 12) & 15u), 0, k1_values);
            uint64_t lane_pair_count =
                (uint64_t)k0_count * (uint64_t)k1_count;
            if (UINT64_MAX - pair_count < lane_pair_count) {
                die("lift candidate count overflow");
            }
            pair_count += lane_pair_count;
            if (selected_lane_count == 1u) {
                printf("lift_lane=%04X k0_candidates=%zu k1_candidates=%zu "
                       "pair_candidates=%" PRIu64 "\n",
                       nu, k0_count, k1_count, lane_pair_count);
            }
        }
        if (pair_count == 0 || pair_count > SIZE_MAX / sizeof(PairScore)) die("invalid lift candidate count");
        pair_scores = (PairScore *)malloc((size_t)pair_count * sizeof(*pair_scores));
        lift_workers = (LiftWorker *)calloc(options.threads, sizeof(*lift_workers));
        full_lift_workers = (FullLiftWorker *)calloc(options.threads, sizeof(*full_lift_workers));
        if (pair_scores == NULL || lift_workers == NULL || full_lift_workers == NULL) {
            die("lift-score allocation failed");
        }
        if (selected_lane_count != 1u) {
            printf("lift_lanes=%zu first_lane=%04X pair_candidates=%" PRIu64 "\n",
                   selected_lane_count, lane_scores[selected_lane_start].nu,
                   pair_count);
        }
        phase_start = now_ns();
        {
            uint64_t pair_offset = 0u;
            for (size_t lane_offset = 0; lane_offset < selected_lane_count;
                 ++lane_offset) {
                size_t lane_index = selected_lane_start + lane_offset;
                uint16_t nu = lane_scores[lane_index].nu;
                size_t k0_count = collect_word_candidates(
                    (uint8_t)(nu & 15u),
                    (uint8_t)((nu >> 8) & 15u), 1, k0_values);
                size_t k1_count = collect_word_candidates(
                    (uint8_t)((nu >> 4) & 15u),
                    (uint8_t)((nu >> 12) & 15u), 0, k1_values);
                uint64_t lane_pair_count =
                    (uint64_t)k0_count * (uint64_t)k1_count;
                for (unsigned t = 0; t < options.threads; ++t) {
                    lift_workers[t].begin =
                        (lane_pair_count * t) / options.threads;
                    lift_workers[t].end =
                        (lane_pair_count * (t + 1u)) / options.threads;
                    lift_workers[t].byte_edges = byte_edges;
                    lift_workers[t].k0_values = k0_values;
                    lift_workers[t].k1_values = k1_values;
                    lift_workers[t].k1_count = k1_count;
                    lift_workers[t].scores = pair_scores + (size_t)pair_offset;
                }
                run_threads(handles, options.threads, lift_worker_main,
                            lift_workers, sizeof(*lift_workers));
                pair_offset += lane_pair_count;
            }
            if (pair_offset != pair_count) die("lift candidate count changed");
        }
        qsort(pair_scores, (size_t)pair_count, sizeof(*pair_scores), pair_score_compare);
        {
            size_t true_rank = find_pair_rank(pair_scores, (size_t)pair_count,
                                              options.key[14], options.key[15]);
            printf("phase=high-byte-lift elapsed=%.3f s\n",
                   (double)(now_ns() - phase_start) / 1e9);
            if (true_rank == 0) {
                printf("true_K8_lift_rank=absent "
                       "(true key is outside the selected S4 lane tier)\n");
            } else {
                uint64_t true_score = pair_scores[true_rank - 1u].score;
                size_t greater = 0;
                size_t tied = 0;
                for (size_t i = 0; i < (size_t)pair_count; ++i) {
                    if (pair_scores[i].score > true_score) ++greater;
                    if (pair_scores[i].score == true_score) ++tied;
                }
                printf("true_K8_lift_rank=%zu true_K8_lift_score=%" PRIu64 " greater=%zu tied=%zu\n",
                       true_rank, true_score, greater, tied);
            }
            for (unsigned i = 0; i < options.top && i < pair_count; ++i) {
                printf("K8-high[%u]=(%04X,%04X) score=%" PRIu64 "%s\n", i + 1u,
                       pair_scores[i].k0, pair_scores[i].k1, pair_scores[i].score,
                       pair_scores[i].k0 == options.key[14] && pair_scores[i].k1 == options.key[15]
                           ? " true" : "");
            }
        }
        {
            size_t global_max_count = 1u;
            size_t full_count;
            while (global_max_count < (size_t)pair_count &&
                   pair_scores[global_max_count].score == pair_scores[0].score) {
                ++global_max_count;
            }
            full_count = global_max_count;
            PairScore *full_scores =
                (PairScore *)malloc(full_count * sizeof(*full_scores));
            if (full_scores == NULL) die("full-lift allocation failed");
            phase_start = now_ns();
            for (unsigned t = 0; t < options.threads; ++t) {
                full_lift_workers[t].begin =
                    (size_t)(((uint64_t)full_count * t) / options.threads);
                full_lift_workers[t].end =
                    (size_t)(((uint64_t)full_count * (t + 1u)) /
                             options.threads);
                full_lift_workers[t].edge_counts = full_edge_counts;
                full_lift_workers[t].edge_count = full_edge_count;
                full_lift_workers[t].high_scores = pair_scores;
                full_lift_workers[t].full_scores = full_scores;
            }
            run_threads(handles, options.threads, full_lift_worker_main,
                        full_lift_workers, sizeof(*full_lift_workers));
            qsort(full_scores, full_count, sizeof(*full_scores),
                  pair_score_compare);
            {
                size_t full_global_max_count = 1u;
                size_t true_rank = find_pair_rank(full_scores, full_count,
                                                  options.key[14], options.key[15]);
                while (full_global_max_count < full_count &&
                       full_scores[full_global_max_count].score == full_scores[0].score) {
                    ++full_global_max_count;
                }
                printf("phase=full-block-lift elapsed=%.3f s high_global_maximizers=%zu full_candidates=%zu full_global_maximizers=%zu unique_observed_edges=%zu\n",
                       (double)(now_ns() - phase_start) / 1e9,
                       global_max_count, full_count,
                       full_global_max_count, full_edge_count);
                if (true_rank == 0)
                    printf("true_K8_full_rank=absent-from-high-maxima\n");
                else printf("true_K8_full_rank=%zu true_K8_full_score=%" PRIu64 "\n",
                            true_rank, full_scores[true_rank - 1u].score);
                for (unsigned i = 0; i < options.top && i < full_count; ++i) {
                    printf("K8-full[%u]=(%04X,%04X) score=%" PRIu64 "%s\n", i + 1u,
                           full_scores[i].k0, full_scores[i].k1, full_scores[i].score,
                           full_scores[i].k0 == options.key[14] && full_scores[i].k1 == options.key[15]
                               ? " true" : "");
                }
                for (size_t i = 0; i < full_global_max_count; ++i) {
                    printf("candidate_K8=(%04X,%04X) score=%" PRIu64 "\n",
                           full_scores[i].k0, full_scores[i].k1, full_scores[i].score);
                }
                if (options.emit_fallback) {
                    size_t emitted = 0u;
                    for (size_t i = full_global_max_count; i < full_count; ++i) {
                        printf("fallback_K8=(%04X,%04X) tier=S16 score=%" PRIu64 "\n",
                               full_scores[i].k0, full_scores[i].k1,
                               full_scores[i].score);
                        ++emitted;
                    }
                    for (size_t i = full_count; i < (size_t)pair_count; ++i) {
                        printf("fallback_K8=(%04X,%04X) tier=S8 score=%" PRIu64 "\n",
                               pair_scores[i].k0, pair_scores[i].k1,
                               pair_scores[i].score);
                        ++emitted;
                    }
                    printf("fallback_candidates=%zu retained_fibre_candidates=%" PRIu64 "\n",
                           emitted, pair_count);
                }
                printf("recovered_K8=(%04X,%04X) audit=%s\n",
                       full_scores[0].k0, full_scores[0].k1,
                       full_scores[0].k0 == options.key[14] && full_scores[0].k1 == options.key[15]
                           ? "match" : "mismatch");
            }
            free(full_scores);
        }
        free(full_lift_workers);
        free(lift_workers);
        free(pair_scores);
        free(k1_values);
        free(k0_values);
    }

    printf("total_elapsed=%.3f s\n", (double)(now_ns() - attack_start) / 1e9);
    free(full_edge_counts);
    free(raw_full_edges);
    free(byte_edges);
    free(lane_scores);
    free(lane_workers);
    free(query_workers);
    free(handles);
    return EXIT_SUCCESS;
}
