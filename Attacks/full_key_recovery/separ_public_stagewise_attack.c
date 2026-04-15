#define main separ_public_full_hybrid_attack_main
#include "quotient/separ_public_full_hybrid_attack.c"
#undef main

typedef struct {
    KeyPair pair;
    uint32_t hits;
    uint16_t sample_iv[8];
} StagePairHit;

typedef struct {
    StagePairHit *rows;
    size_t count;
    size_t cap;
} StagePairHitVec;

typedef struct {
    SeparCtx ctx;
    uint16_t *table;
} StagewiseTableContext;

typedef struct {
    const Options *opt;
    const KeyPair *known_pairs;
    uint8_t target_stage;
    uint32_t start_trial;
    uint32_t end_trial;
    atomic_ullong *progress;
    StagePairHitVec hits;
} StagewiseCollectWorker;

typedef struct {
    const Options *opt;
    const KeyPair *known_pairs;
    uint32_t start_trial;
    uint32_t end_trial;
    atomic_ullong *progress;
    atomic_int *found;
    int have_result;
    InwardProbeResult result;
} Stage2Worker;

static int stage_pair_hit_cmp(const void *lhs, const void *rhs)
{
    const StagePairHit *a = (const StagePairHit *)lhs;
    const StagePairHit *b = (const StagePairHit *)rhs;
    if (a->hits != b->hits) return (a->hits < b->hits) ? 1 : -1;
    return pair_cmp(a->pair, b->pair);
}

static StagewiseTableContext build_stagewise_table_context(const uint16_t key_words[16],
                                                           const uint16_t iv_words[8])
{
    StagewiseTableContext out;
    out.table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    if (out.table == NULL) fatal("stagewise table allocation failed");
    ctx_after_prefix(key_words, iv_words, NULL, 0u, &out.ctx);
    next_word_table_from_ctx(&out.ctx, key_words, out.table);
    return out;
}

static void free_stagewise_table_context(StagewiseTableContext *ctx)
{
    if (ctx->table != NULL) free(ctx->table);
    ctx->table = NULL;
}

static void stage_pair_hit_add_count(StagePairHitVec *vec, KeyPair pair, const uint16_t iv_words[8], uint32_t count)
{
    for (size_t i = 0u; i < vec->count; i++) {
        if (pair_equal(vec->rows[i].pair, pair)) {
            vec->rows[i].hits += count;
            return;
        }
    }
    if (vec->count == vec->cap) {
        size_t new_cap = (vec->cap == 0u) ? 16u : (vec->cap * 2u);
        StagePairHit *grown = (StagePairHit *)realloc(vec->rows, new_cap * sizeof(StagePairHit));
        if (grown == NULL) fatal("stage-pair-hit realloc failed");
        vec->rows = grown;
        vec->cap = new_cap;
    }
    vec->rows[vec->count].pair = pair;
    vec->rows[vec->count].hits = count;
    memcpy(vec->rows[vec->count].sample_iv, iv_words, 8u * sizeof(uint16_t));
    vec->count++;
}

static void stage_pair_hit_add(StagePairHitVec *vec, KeyPair pair, const uint16_t iv_words[8])
{
    for (size_t i = 0u; i < vec->count; i++) {
        if (pair_equal(vec->rows[i].pair, pair)) {
            vec->rows[i].hits++;
            return;
        }
    }
    if (vec->count == vec->cap) {
        size_t new_cap = (vec->cap == 0u) ? 16u : (vec->cap * 2u);
        StagePairHit *grown = (StagePairHit *)realloc(vec->rows, new_cap * sizeof(StagePairHit));
        if (grown == NULL) fatal("stage-pair-hit realloc failed");
        vec->rows = grown;
        vec->cap = new_cap;
    }
    vec->rows[vec->count].pair = pair;
    vec->rows[vec->count].hits = 1u;
    memcpy(vec->rows[vec->count].sample_iv, iv_words, 8u * sizeof(uint16_t));
    vec->count++;
}

static void dedupe_min_rows(const OuterStageCandidate *rows,
                            size_t row_count,
                            StagePairHitVec *hits,
                            const uint16_t iv_words[8])
{
    for (size_t i = 0u; i < row_count; i++) {
        int seen = 0;
        for (size_t j = 0u; j < i; j++) {
            if (pair_equal(rows[i].pair, rows[j].pair)) {
                seen = 1;
                break;
            }
        }
        if (!seen) stage_pair_hit_add(hits, rows[i].pair, iv_words);
    }
}

static int attacked_position_scan_exact_collect_min_rows(const uint16_t *current_outputs,
                                                         uint8_t stage,
                                                         OuterStageCandidate **out_rows,
                                                         size_t *out_count)
{
    LowScore lows[256];
    uint32_t best_low_support;
    size_t low_count = 0u;
    OuterStageCandidate *rows = NULL;
    size_t row_count = 0u;
    size_t row_cap = 0u;
    exact_low_byte_scan_u16(current_outputs, lows);
    best_low_support = lows[0].total_support;
    while (low_count < 256u && lows[low_count].total_support == best_low_support) low_count++;
    for (size_t li = 0u; li < low_count; li++) {
        uint16_t *corrected = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
        uint64_t *cycles;
        size_t cycle_count = 0u;
        uint32_t cycle_score = 0u;
        if (corrected == NULL) fatal("stage %u corrected-table allocation failed", (unsigned)stage);
        subtract_translation_table(current_outputs, lows[li].low, corrected);
        cycles = exact_max_projected_cycles(corrected, stage, DEFAULT_DIFFS, sizeof(DEFAULT_DIFFS) / sizeof(DEFAULT_DIFFS[0]), &cycle_count, &cycle_score);
        for (size_t ci = 0u; ci < cycle_count; ci++) {
            for (uint8_t rot = 0u; rot < 16u; rot++) {
                uint8_t order[256];
                uint64_t rotated = rotate_cycle_left_packed(cycles[ci], rot);
                if (!reconstruct_order_from_outputs_u16(corrected, rotated, DEFAULT_DIFFS, sizeof(DEFAULT_DIFFS) / sizeof(DEFAULT_DIFFS[0]), order)) continue;
                translated_exact_candidates_for_cycle(current_outputs, stage, lows[li].low, rotated, order, cycle_score, &rows, &row_count, &row_cap);
            }
        }
        free(cycles);
        free(corrected);
    }
    if (row_count == 0u) {
        *out_rows = NULL;
        *out_count = 0u;
        return 0;
    }
    qsort(rows, row_count, sizeof(OuterStageCandidate), outer_stage_candidate_cmp);
    {
        uint32_t min_verifier = rows[0].verifier_score;
        size_t keep = 0u;
        for (size_t i = 0u; i < row_count; i++) {
            if (rows[i].verifier_score != min_verifier) break;
            keep++;
        }
        *out_rows = rows;
        *out_count = keep;
        return 1;
    }
}

static int recover_known_pair_state_fast(const uint16_t *current_outputs,
                                         uint8_t stage,
                                         KeyPair known_pair,
                                         OuterStageCandidate *out_best)
{
    LowScore lows[256];
    uint32_t best_low_support;
    size_t low_count = 0u;
    uint16_t *reduced = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    OuterStageCandidate best = {{0u, 0u}, 0u, UINT32_MAX, 0u};
    int have = 0;
    if (reduced == NULL) fatal("known-pair reduced allocation failed");
    exact_low_byte_scan_u16(current_outputs, lows);
    best_low_support = lows[0].total_support;
    while (low_count < 256u && lows[low_count].total_support == best_low_support) low_count++;
    for (size_t li = 0u; li < low_count; li++) {
        uint16_t low = lows[li].low;
        for (uint32_t hi = 0u; hi < 256u; hi++) {
            OuterStageCandidate cand;
            cand.pair = known_pair;
            cand.state_word = (uint16_t)(low | (hi << 8));
            subtract_translation_table(current_outputs, cand.state_word, reduced);
            cand.verifier_score = support_collapse_score_after_peel_u16(reduced, known_pair, stage, OUTER_BOOTSTRAP_ROWS, 4u);
            cand.cycle_score = 0u;
            if (!have || outer_stage_candidate_cmp(&cand, &best) < 0) {
                best = cand;
                have = 1;
            }
        }
    }
    free(reduced);
    if (!have) return 0;
    *out_best = best;
    return 1;
}

static int prepare_current_for_target_stage(const uint16_t key_words[16],
                                            const uint16_t iv_words[8],
                                            const KeyPair known_pairs[9],
                                            uint8_t target_stage,
                                            StagewiseTableContext *out_ctx,
                                            uint16_t *current)
{
    uint16_t reduced[0x10000u];
    *out_ctx = build_stagewise_table_context(key_words, iv_words);
    peel_current_forward_stage_table_u16(out_ctx->table, known_pairs[8], 8u, current);
    for (int stage = 7; stage > (int)target_stage; stage--) {
        OuterStageCandidate best;
        if (!recover_known_pair_state_fast(current, (uint8_t)stage, known_pairs[stage], &best)) {
            free_stagewise_table_context(out_ctx);
            return 0;
        }
        subtract_translation_table(current, best.state_word, reduced);
        peel_current_forward_stage_table_u16(reduced, best.pair, (uint8_t)stage, current);
    }
    return 1;
}

static int try_stage2_finish_on_iv(const uint16_t key_words[16],
                                   const uint16_t iv_words[8],
                                   const KeyPair known_pairs[9],
                                   InwardProbeResult *out)
{
    StagewiseTableContext ctx;
    uint16_t current[0x10000u];
    OuterStageCandidate *rows = NULL;
    size_t row_count = 0u;
    KeyPair k1_pair = {0u, 0u};
    uint16_t s1 = 0u;
    uint16_t s2 = 0u;
    size_t solution_count = 0u;

    memset(out, 0, sizeof(*out));
    memcpy(out->iv_words, iv_words, 8u * sizeof(uint16_t));
    memcpy(out->pairs, known_pairs, 9u * sizeof(KeyPair));
    if (!prepare_current_for_target_stage(key_words, iv_words, known_pairs, 2u, &ctx, current)) return 0;
    if (!attacked_position_scan_exact_collect_min_rows(current, 2u, &rows, &row_count)) {
        free_stagewise_table_context(&ctx);
        return 0;
    }
    for (size_t i = 0u; i < row_count; i++) {
        out->pairs[2] = rows[i].pair;
        out->states[3] = rows[i].state_word;
        if (!stage1_finish_from_stage2_current(current, rows[i].pair, rows[i].state_word, &k1_pair, &s1, &s2, &solution_count)) continue;
        out->pairs[1] = k1_pair;
        out->states[1] = s1;
        out->states[2] = s2;
        out->s1 = s1;
        out->s2 = s2;
        out->stage1_solution_count = solution_count;
        if (verify_full_key_candidate_on_iv(out->pairs, iv_words, ctx.table)) {
            free(rows);
            free_stagewise_table_context(&ctx);
            out->success = 1;
            out->deepest_stage = 1u;
            return 1;
        }
    }
    free(rows);
    free_stagewise_table_context(&ctx);
    return 0;
}

static int fill_outer_states_on_success_iv(const uint16_t key_words[16],
                                           const uint16_t iv_words[8],
                                           InwardProbeResult *out)
{
    StagewiseTableContext ctx;
    uint16_t current[0x10000u];
    uint16_t reduced[0x10000u];
    ctx = build_stagewise_table_context(key_words, iv_words);
    peel_current_forward_stage_table_u16(ctx.table, out->pairs[8], 8u, current);
    for (int stage = 7; stage >= 2; stage--) {
        OuterStageCandidate best;
        if (!recover_known_pair_state_fast(current, (uint8_t)stage, out->pairs[stage], &best)) {
            free_stagewise_table_context(&ctx);
            return 0;
        }
        out->states[stage + 1u] = best.state_word;
        subtract_translation_table(current, best.state_word, reduced);
        if (stage > 2) peel_current_forward_stage_table_u16(reduced, best.pair, (uint8_t)stage, current);
    }
    free_stagewise_table_context(&ctx);
    return 1;
}

static void derive_stage_rng_seed(const Options *opt, uint8_t target_stage, uint64_t *rng)
{
    *rng = opt->search_seed ^ (0x9E3779B97F4A7C15ULL * (uint64_t)target_stage) ^ 0xA24BAED4963EE407ULL;
}

static void generate_stage_iv_words(const Options *opt,
                                    uint8_t target_stage,
                                    uint32_t trial_index,
                                    uint16_t iv_words[8])
{
    uint64_t rng;
    derive_stage_rng_seed(opt, target_stage, &rng);
    rng ^= 0xD1B54A32D192ED03ULL * (uint64_t)trial_index;
    for (size_t i = 0u; i < 8u; i++) iv_words[i] = (uint16_t)(splitmix64(&rng) & 0xFFFFu);
}

static DWORD WINAPI stagewise_collect_worker_proc(LPVOID param)
{
    StagewiseCollectWorker *worker = (StagewiseCollectWorker *)param;
    uint64_t local_progress = 0u;
    worker->hits.rows = NULL;
    worker->hits.count = 0u;
    worker->hits.cap = 0u;
        for (uint32_t trial = worker->start_trial; trial < worker->end_trial; trial++) {
            uint16_t iv_words[8];
            StagewiseTableContext ctx;
            uint16_t current[0x10000u];
            OuterStageCandidate *rows = NULL;
            size_t row_count = 0u;
            generate_stage_iv_words(worker->opt, worker->target_stage, trial, iv_words);
            if (!prepare_current_for_target_stage(worker->opt->key_words, iv_words, worker->known_pairs, worker->target_stage, &ctx, current)) {
            local_progress++;
            if ((local_progress & 31u) == 0u) {
                atomic_fetch_add(worker->progress, local_progress);
                local_progress = 0u;
            }
            continue;
        }
        if (attacked_position_scan_exact_collect_min_rows(current, worker->target_stage, &rows, &row_count)) {
            dedupe_min_rows(rows, row_count, &worker->hits, iv_words);
            free(rows);
        }
        free_stagewise_table_context(&ctx);
        local_progress++;
        if ((local_progress & 31u) == 0u) {
            atomic_fetch_add(worker->progress, local_progress);
            local_progress = 0u;
        }
    }
    if (local_progress != 0u) atomic_fetch_add(worker->progress, local_progress);
    return 0;
}

static DWORD WINAPI stage2_worker_proc(LPVOID param)
{
    Stage2Worker *worker = (Stage2Worker *)param;
    uint64_t local_progress = 0u;
    worker->have_result = 0;
    for (uint32_t trial = worker->start_trial; trial < worker->end_trial; trial++) {
        uint16_t iv_words[8];
        if (atomic_load(worker->found)) break;
        generate_stage_iv_words(worker->opt, 2u, trial, iv_words);
        if (try_stage2_finish_on_iv(worker->opt->key_words, iv_words, worker->known_pairs, &worker->result)) {
            int expected = 0;
            worker->have_result = 1;
            if (atomic_compare_exchange_strong(worker->found, &expected, 1)) {
                local_progress++;
                if (local_progress != 0u) atomic_fetch_add(worker->progress, local_progress);
                return 0;
            }
        }
        local_progress++;
        if ((local_progress & 31u) == 0u) {
            atomic_fetch_add(worker->progress, local_progress);
            local_progress = 0u;
        }
    }
    if (local_progress != 0u) atomic_fetch_add(worker->progress, local_progress);
    return 0;
}

static int collect_stagewise_hits(const Options *opt,
                                  const KeyPair known_pairs[9],
                                  uint8_t target_stage,
                                  StagePairHitVec *hits)
{
    hits->rows = NULL;
    hits->count = 0u;
    hits->cap = 0u;
    if (g_debug_output || opt->workers <= 1u || opt->inward_trials <= 1u) {
        for (uint32_t trial = 1u; trial <= opt->inward_trials; trial++) {
            uint16_t iv_words[8];
            StagewiseTableContext ctx;
            uint16_t current[0x10000u];
            OuterStageCandidate *rows = NULL;
            size_t row_count = 0u;
            generate_stage_iv_words(opt, target_stage, trial, iv_words);
            if (!g_debug_output) {
                char phase[16];
                snprintf(phase, sizeof(phase), "stage%u-iv", (unsigned)target_stage);
                display_set_phase_progress(phase, trial, opt->inward_trials);
            }
            if (!prepare_current_for_target_stage(opt->key_words, iv_words, known_pairs, target_stage, &ctx, current)) continue;
            if (!attacked_position_scan_exact_collect_min_rows(current, target_stage, &rows, &row_count)) {
                free_stagewise_table_context(&ctx);
                continue;
            }
            dedupe_min_rows(rows, row_count, hits, iv_words);
            free(rows);
            free_stagewise_table_context(&ctx);
        }
    } else {
        unsigned workers = opt->workers;
        HANDLE *handles;
        StagewiseCollectWorker *worker;
        atomic_ullong progress;
        get_rep_table(target_stage, 1);
        if (workers == 0u) workers = 1u;
        if (workers > opt->inward_trials) workers = opt->inward_trials;
        handles = (HANDLE *)calloc(workers, sizeof(HANDLE));
        worker = (StagewiseCollectWorker *)calloc(workers, sizeof(StagewiseCollectWorker));
        if (handles == NULL || worker == NULL) fatal("stagewise collect allocation failed");
        atomic_init(&progress, 0u);
        {
            uint32_t chunk = opt->inward_trials / workers;
            for (unsigned i = 0u; i < workers; i++) {
                uint32_t begin = chunk * i + 1u;
                uint32_t end = (i + 1u == workers) ? (opt->inward_trials + 1u) : (chunk * (i + 1u) + 1u);
                worker[i].opt = opt;
                worker[i].known_pairs = known_pairs;
                worker[i].target_stage = target_stage;
                worker[i].start_trial = begin;
                worker[i].end_trial = end;
                worker[i].progress = &progress;
                handles[i] = CreateThread(NULL, 0, stagewise_collect_worker_proc, &worker[i], 0, NULL);
                if (handles[i] == NULL) fatal("stagewise collect CreateThread failed");
            }
        }
        for (;;) {
            DWORD wait = WaitForMultipleObjects(workers, handles, TRUE, 250u);
            uint64_t done = atomic_load(&progress);
            char phase[16];
            snprintf(phase, sizeof(phase), "stage%u-iv", (unsigned)target_stage);
            display_set_phase_progress(phase, done, opt->inward_trials);
            if (wait == WAIT_OBJECT_0) break;
            if (wait != WAIT_TIMEOUT) fatal("stagewise collect WaitForMultipleObjects failed");
        }
        WaitForMultipleObjects(workers, handles, TRUE, INFINITE);
        for (unsigned i = 0u; i < workers; i++) {
            for (size_t j = 0u; j < worker[i].hits.count; j++) {
                stage_pair_hit_add_count(hits,
                                         worker[i].hits.rows[j].pair,
                                         worker[i].hits.rows[j].sample_iv,
                                         worker[i].hits.rows[j].hits);
            }
            free(worker[i].hits.rows);
            CloseHandle(handles[i]);
        }
        free(worker);
        free(handles);
    }
    qsort(hits->rows, hits->count, sizeof(StagePairHit), stage_pair_hit_cmp);
    return hits->count != 0u;
}

static int stagewise_search_recursive(const Options *opt,
                                      KeyPair known_pairs[9],
                                      uint8_t target_stage,
                                      InwardProbeResult *out)
{
    StagePairHitVec hits;
    if (target_stage == 2u) {
        if (g_debug_output || opt->workers <= 1u || opt->inward_trials <= 1u) {
            for (uint32_t trial = 1u; trial <= opt->inward_trials; trial++) {
                uint16_t iv_words[8];
                generate_stage_iv_words(opt, 2u, trial, iv_words);
                if (!g_debug_output) {
                    display_set_phase_progress("stage2-iv", trial, opt->inward_trials);
                }
                if (try_stage2_finish_on_iv(opt->key_words, iv_words, known_pairs, out)) return 1;
            }
            return 0;
        } else {
            unsigned workers = opt->workers;
            HANDLE *handles;
            Stage2Worker *worker;
            atomic_ullong progress;
            atomic_int found;
            get_rep_table(2u, 1);
            if (workers == 0u) workers = 1u;
            if (workers > opt->inward_trials) workers = opt->inward_trials;
            handles = (HANDLE *)calloc(workers, sizeof(HANDLE));
            worker = (Stage2Worker *)calloc(workers, sizeof(Stage2Worker));
            if (handles == NULL || worker == NULL) fatal("stage2 worker allocation failed");
            atomic_init(&progress, 0u);
            atomic_init(&found, 0);
            {
                uint32_t chunk = opt->inward_trials / workers;
                for (unsigned i = 0u; i < workers; i++) {
                    uint32_t begin = chunk * i + 1u;
                    uint32_t end = (i + 1u == workers) ? (opt->inward_trials + 1u) : (chunk * (i + 1u) + 1u);
                    worker[i].opt = opt;
                    worker[i].known_pairs = known_pairs;
                    worker[i].start_trial = begin;
                    worker[i].end_trial = end;
                    worker[i].progress = &progress;
                    worker[i].found = &found;
                    handles[i] = CreateThread(NULL, 0, stage2_worker_proc, &worker[i], 0, NULL);
                    if (handles[i] == NULL) fatal("stage2 CreateThread failed");
                }
            }
            for (;;) {
                DWORD wait = WaitForMultipleObjects(workers, handles, TRUE, 250u);
                uint64_t done = atomic_load(&progress);
                display_set_phase_progress("stage2-iv", done, opt->inward_trials);
                if (wait == WAIT_OBJECT_0) break;
                if (wait != WAIT_TIMEOUT) fatal("stage2 WaitForMultipleObjects failed");
            }
            WaitForMultipleObjects(workers, handles, TRUE, INFINITE);
            for (unsigned i = 0u; i < workers; i++) {
                if (worker[i].have_result && atomic_load(&found)) {
                    *out = worker[i].result;
                    for (unsigned j = 0u; j < workers; j++) CloseHandle(handles[j]);
                    free(worker);
                    free(handles);
                    return 1;
                }
            }
            for (unsigned i = 0u; i < workers; i++) CloseHandle(handles[i]);
            free(worker);
            free(handles);
            return 0;
        }
    }
    if (!collect_stagewise_hits(opt, known_pairs, target_stage, &hits)) return 0;
    ts_printf("stagewise stage %u distinct candidate pairs=%zu", (unsigned)target_stage, hits.count);
    for (size_t i = 0u; i < hits.count; i++) {
        KeyPair saved = known_pairs[target_stage];
        known_pairs[target_stage] = hits.rows[i].pair;
        if (!g_debug_output) {
            display_commit_stage(target_stage, hits.rows[i].pair, 0u);
        }
        ts_printf("stagewise stage %u try %zu/%zu pair=(%04X,%04X) hits=%u",
                  (unsigned)target_stage, i + 1u, hits.count,
                  hits.rows[i].pair.k0, hits.rows[i].pair.k1, hits.rows[i].hits);
        if (stagewise_search_recursive(opt, known_pairs, (uint8_t)(target_stage - 1u), out)) {
            free(hits.rows);
            return 1;
        }
        known_pairs[target_stage] = saved;
    }
    free(hits.rows);
    return 0;
}

int main(int argc, char **argv)
{
    Options opt;
    WeakIVCandidate *beam = NULL;
    size_t beam_count = 0u;
    KeyPair recovered_k8 = {0u, 0u};
    KeyPair pairs[9] = {{0}};
    InwardProbeResult result;

    memset(&opt, 0, sizeof(opt));
    memcpy(opt.key_words, DEFAULT_KEY, sizeof(DEFAULT_KEY));
    memcpy(opt.iv_words, DEFAULT_IV, sizeof(DEFAULT_IV));
    opt.debug_output = 0;
    opt.workers = 16u;
    opt.search_trials = 512u;
    opt.search_beam = 32u;
    opt.search_seed = 1u;
    opt.inward_trials = 64u;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--search-trials") == 0 && i + 1 < argc) opt.search_trials = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--search-beam") == 0 && i + 1 < argc) opt.search_beam = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--search-seed") == 0 && i + 1 < argc) opt.search_seed = _strtoui64(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--inward-trials") == 0 && i + 1 < argc) opt.inward_trials = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--oracle-key") == 0 && i + 1 < argc) {
            if (parse_hex_words(argv[++i], opt.key_words, 16u) != 0) fatal("invalid full key");
        } else if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) {
            opt.workers = (unsigned)strtoul(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--verbose") == 0) {
            opt.debug_output = 1;
        } else {
            fatal("usage: %s [--search-trials N] [--search-beam N] [--search-seed N] [--inward-trials N] [--workers N] [--oracle-key HEX64] [--verbose]", argv[0]);
        }
    }
    if (opt.search_trials == 0u) opt.search_trials = 1u;
    if (opt.search_beam == 0u) opt.search_beam = 1u;
    if (opt.inward_trials == 0u) opt.inward_trials = 1u;
    g_outer_workers = opt.workers;
    display_init(opt.debug_output);
    beam = (WeakIVCandidate *)calloc(opt.search_beam, sizeof(WeakIVCandidate));
    if (beam == NULL) fatal("weak beam allocation failed");
    search_weak_ivs(&opt, beam, &beam_count);
    if (!recover_k8_hybrid_from_beam(&opt, beam, beam_count, &recovered_k8)) fatal("failed to recover K8");
    if (!opt.debug_output && opt.workers > 1u) {
        g_outer_workers = 1u;
    }
    memset(pairs, 0, sizeof(pairs));
    pairs[8] = recovered_k8;
    if (!g_debug_output) display_set_k8(recovered_k8);
    if (!stagewise_search_recursive(&opt, pairs, 7u, &result)) fatal("stagewise inward search failed");
    if (!fill_outer_states_on_success_iv(opt.key_words, result.iv_words, &result)) {
        fatal("successful key recovered but failed to reconstruct IV-local outer states");
    }
    if (!g_debug_output) {
        display_commit_stage(7u, result.pairs[7], result.states[8]);
        display_commit_stage(6u, result.pairs[6], result.states[7]);
        display_commit_stage(5u, result.pairs[5], result.states[6]);
        display_commit_stage(4u, result.pairs[4], result.states[5]);
        display_commit_stage(3u, result.pairs[3], result.states[4]);
        display_commit_stage(2u, result.pairs[2], result.states[3]);
        display_commit_stage1(result.pairs[1], result.states[2], result.states[1]);
        display_mark_done();
        display_render();
        display_finish();
        putchar('\n');
    }
    print_full_recovery_summary(&result);
    free(beam);
    return 0;
}
