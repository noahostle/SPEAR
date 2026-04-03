#define main fixed_prefix_attack_main
#include "fixed_prefix_distinguisher_peel.c"
#undef main

#include <errno.h>

#define CERT_BRANCH_SCAN_CAP (UINT64_C(1) << 18)

typedef struct {
    int sep_rotl16_collapse_ok;
    int byte_triangularity_ok;
    int matched_context_inverse_ok;
    int truth_path_normalization_ok;
    int second_context_filter_ok;
} self_check_report_t;

typedef struct {
    uint8_t stage_n;
    uint16_t key0;
    uint16_t key1;
    uint16_t state_word;
    uint16_t low_byte_count;
    uint8_t low_bytes[256];
    uint16_t row_count;
    uint8_t rows[256];
} truth_stage_lowbyte_t;

typedef struct {
    uint8_t stage_n;
    uint8_t low_byte;
    uint8_t true_high;
    uint16_t viable_high_count;
    uint8_t viable_highs[256];
} branch_probe_summary_t;

static uint16_t separ_decrypt_word(uint16_t ct, separ_ctx_t *ctx, const uint16_t key[16])
{
    uint16_t v12;
    uint16_t v23;
    uint16_t v34;
    uint16_t v45;
    uint16_t v56;
    uint16_t v67;
    uint16_t v78;
    uint16_t pt;

    v78 = u16((uint32_t)dec_block(ct, key[14], key[15], 8) - ctx->state[7]);
    v67 = u16((uint32_t)dec_block(v78, key[12], key[13], 7) - ctx->state[6]);
    v56 = u16((uint32_t)dec_block(v67, key[10], key[11], 6) - ctx->state[5]);
    v45 = u16((uint32_t)dec_block(v56, key[8], key[9], 5) - ctx->state[4]);
    v34 = u16((uint32_t)dec_block(v45, key[6], key[7], 4) - ctx->state[3]);
    v23 = u16((uint32_t)dec_block(v34, key[4], key[5], 3) - ctx->state[2]);
    v12 = u16((uint32_t)dec_block(v23, key[2], key[3], 2) - ctx->state[1]);
    pt = u16((uint32_t)dec_block(v12, key[0], key[1], 1) - ctx->state[0]);

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
    return pt;
}

static uint16_t sep_rotl16_closed_form(uint16_t x)
{
    uint8_t a = (uint8_t)(x >> 12);
    uint8_t b = (uint8_t)((x >> 8) & 0x0Fu);
    uint8_t c = (uint8_t)((x >> 4) & 0x0Fu);
    uint8_t d = (uint8_t)(x & 0x0Fu);
    return (uint16_t)(((b ^ c) << 12) | (b << 8) | (a << 4) | (a ^ d));
}

static uint64_t fnv1a64_update(uint64_t hash, const void *data, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)data;
    size_t i;
    for (i = 0; i < size; i++) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t branch_profile_digest(const branch_profile_t *profile)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    hash = fnv1a64_update(hash, &profile->max_count, sizeof(profile->max_count));
    hash = fnv1a64_update(hash, &profile->sum_count, sizeof(profile->sum_count));
    hash = fnv1a64_update(hash, &profile->signature_count, sizeof(profile->signature_count));
    hash = fnv1a64_update(hash, profile->signature_rows, profile->signature_count);
    hash = fnv1a64_update(hash, profile->signatures, (size_t)profile->signature_count * 256u);
    return hash;
}

static void json_print_bool(int value)
{
    printf("%s", value ? "true" : "false");
}

static void json_print_hex_word(uint16_t value)
{
    printf("\"%04X\"", value);
}

static void json_print_byte_array(const uint8_t *values, size_t count)
{
    size_t i;
    printf("[");
    for (i = 0; i < count; i++) {
        if (i != 0) {
            printf(",");
        }
        printf("\"%02X\"", values[i]);
    }
    printf("]");
}

static void json_print_row_array(const uint8_t *values, size_t count)
{
    size_t i;
    printf("[");
    for (i = 0; i < count; i++) {
        if (i != 0) {
            printf(",");
        }
        printf("%u", (unsigned)values[i]);
    }
    printf("]");
}

static void json_print_candidate_source(const cli_config_t *cfg, int stage_n)
{
    candidate_source_t source;
    copy_candidate_source_for_stage(cfg, stage_n, &source);
    printf("\"candidate_source\":{");
    if (source.kind == CANDIDATE_SOURCE_LIST) {
        printf("\"kind\":\"list\",\"count\":%zu", source.list_count);
    } else {
        printf("\"kind\":\"range\",\"start\":\"0x%08" PRIX64 "\",\"count\":\"0x%08" PRIX64 "\"", source.start, source.count);
    }
    printf("}");
}

static void json_print_branch_profile(const char *name, const branch_profile_t *profile)
{
    printf("\"%s\":{", name);
    printf("\"max_count\":%u,", (unsigned)profile->max_count);
    printf("\"sum_count\":%" PRIu32 ",", profile->sum_count);
    printf("\"signature_count\":%u,", (unsigned)profile->signature_count);
    printf("\"signature_digest\":\"0x%016" PRIX64 "\"", branch_profile_digest(profile));
    printf("}");
}

static void push_default_branch_probe_candidates(cli_config_t *cfg, int stage_n)
{
    uint16_t key0 = cfg->key[(stage_n - 1) * 2];
    uint16_t key1 = cfg->key[(stage_n - 1) * 2 + 1];
    clear_stage_candidate_lists(cfg);
    (void)push_stage_candidate_unique(&cfg->stage_candidates[stage_n], key0, key1);
    (void)push_stage_candidate_unique(&cfg->stage_candidates[stage_n], key0, u16((uint32_t)key1 ^ 0x0001u));
    (void)push_stage_candidate_unique(&cfg->stage_candidates[stage_n], 0x0000u, 0x0000u);
}

static int build_truth_stage_table(const cli_config_t *cfg, int stage_n, uint16_t *table, separ_ctx_t *truth_ctx)
{
    separ_ctx_t ctx;
    uint16_t *scratch = NULL;
    int stage;

    if (stage_n < 1 || stage_n > 8) {
        return 0;
    }

    build_matched_context_codebook(cfg->prefix, cfg->prefix_count, cfg->key, cfg->iv, table);
    separ_ctx_after_prefix(cfg->prefix, cfg->prefix_count, cfg->key, cfg->iv, &ctx);
    if (truth_ctx != NULL) {
        *truth_ctx = ctx;
    }

    if (stage_n == 8 && !cfg->injected_peel) {
        return 1;
    }

    scratch = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    if (scratch == NULL) {
        return 0;
    }

    if (cfg->injected_peel && stage_n == cfg->start_stage && stage_n == 7) {
        uint32_t x;
        for (x = 0; x < 0x10000u; x++) {
            scratch[x] = dec_block(table[x], cfg->injected_key0, cfg->injected_key1, 8);
        }
        subtract_word_from_table(scratch, cfg->injected_state_word, table);
        free(scratch);
        return 1;
    }

    for (stage = 8; stage > stage_n; stage--) {
        uint16_t key0 = cfg->key[(stage - 1) * 2];
        uint16_t key1 = cfg->key[(stage - 1) * 2 + 1];
        uint32_t x;
        for (x = 0; x < 0x10000u; x++) {
            scratch[x] = dec_block(table[x], key0, key1, (uint8_t)stage);
        }
        subtract_word_from_table(scratch, ctx.state[stage - 1], table);
    }

    free(scratch);
    return 1;
}

static int collect_truth_stage_lowbytes(const cli_config_t *cfg, truth_stage_lowbyte_t out_rows[8])
{
    separ_ctx_t truth_ctx;
    uint16_t *residual = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *decoded = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    int stage_n;

    if (residual == NULL || decoded == NULL) {
        free(residual);
        free(decoded);
        return 0;
    }

    build_matched_context_codebook(cfg->prefix, cfg->prefix_count, cfg->key, cfg->iv, residual);
    separ_ctx_after_prefix(cfg->prefix, cfg->prefix_count, cfg->key, cfg->iv, &truth_ctx);

    for (stage_n = 8; stage_n >= 1; stage_n--) {
        low_byte_refinement_t low_refinement;
        uint16_t key0 = cfg->key[(stage_n - 1) * 2];
        uint16_t key1 = cfg->key[(stage_n - 1) * 2 + 1];
        uint32_t x;

        memset(&low_refinement, 0, sizeof(low_refinement));
        refine_low_byte_candidates(residual, key0, key1, (uint8_t)stage_n, &low_refinement);

        out_rows[stage_n - 1].stage_n = (uint8_t)stage_n;
        out_rows[stage_n - 1].key0 = key0;
        out_rows[stage_n - 1].key1 = key1;
        out_rows[stage_n - 1].state_word = truth_ctx.state[stage_n - 1];
        out_rows[stage_n - 1].low_byte_count = low_refinement.low_byte_count;
        memcpy(out_rows[stage_n - 1].low_bytes, low_refinement.low_bytes, low_refinement.low_byte_count);
        out_rows[stage_n - 1].row_count = low_refinement.row_count;
        memcpy(out_rows[stage_n - 1].rows, low_refinement.rows, low_refinement.row_count);

        for (x = 0; x < 0x10000u; x++) {
            decoded[x] = dec_block(residual[x], key0, key1, (uint8_t)stage_n);
        }
        subtract_word_from_table(decoded, truth_ctx.state[stage_n - 1], residual);
    }

    free(residual);
    free(decoded);
    return 1;
}

static int check_sep_rotl16_collapse(void)
{
    uint32_t x;
    for (x = 0; x < 0x10000u; x++) {
        if (sep_rotl16((uint16_t)x) != sep_rotl16_closed_form((uint16_t)x)) {
            return 0;
        }
    }
    return 1;
}

static int check_byte_triangularity(const uint16_t key[16])
{
    int stage_n;
    for (stage_n = 1; stage_n <= 8; stage_n++) {
        uint16_t key0 = key[(stage_n - 1) * 2];
        uint16_t key1 = key[(stage_n - 1) * 2 + 1];
        uint16_t hi;
        for (hi = 0; hi < 256; hi++) {
            uint16_t lo;
            uint8_t enc_upper = (uint8_t)(enc_block((uint16_t)(hi << 8), key0, key1, (uint8_t)stage_n) >> 8);
            uint8_t dec_upper = (uint8_t)(dec_block((uint16_t)(hi << 8), key0, key1, (uint8_t)stage_n) >> 8);
            for (lo = 1; lo < 256; lo++) {
                if ((uint8_t)(enc_block((uint16_t)((hi << 8) | lo), key0, key1, (uint8_t)stage_n) >> 8) != enc_upper) {
                    return 0;
                }
                if ((uint8_t)(dec_block((uint16_t)((hi << 8) | lo), key0, key1, (uint8_t)stage_n) >> 8) != dec_upper) {
                    return 0;
                }
            }
        }
    }
    return 1;
}

static int check_matched_context_inverse(const cli_config_t *cfg)
{
    separ_ctx_t enc_ctx;
    separ_ctx_t dec_ctx;
    separ_ctx_t base_enc_ctx;
    separ_ctx_t base_dec_ctx;
    uint16_t *codebook = NULL;
    uint16_t *cipher_prefix = NULL;
    size_t i;
    uint32_t x;

    codebook = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    cipher_prefix = (uint16_t *)calloc(cfg->prefix_count == 0 ? 1u : cfg->prefix_count, sizeof(uint16_t));
    if (codebook == NULL || cipher_prefix == NULL) {
        free(codebook);
        free(cipher_prefix);
        return 0;
    }

    build_matched_context_codebook(cfg->prefix, cfg->prefix_count, cfg->key, cfg->iv, codebook);
    separ_initial_state(&enc_ctx, cfg->key, cfg->iv);
    separ_initial_state(&dec_ctx, cfg->key, cfg->iv);
    for (i = 0; i < cfg->prefix_count; i++) {
        cipher_prefix[i] = separ_encrypt_word(cfg->prefix[i], &enc_ctx, cfg->key);
        if (separ_decrypt_word(cipher_prefix[i], &dec_ctx, cfg->key) != cfg->prefix[i]) {
            free(codebook);
            free(cipher_prefix);
            return 0;
        }
    }

    if (memcmp(enc_ctx.state, dec_ctx.state, sizeof(enc_ctx.state)) != 0 || enc_ctx.lfsr != dec_ctx.lfsr) {
        free(codebook);
        free(cipher_prefix);
        return 0;
    }

    base_enc_ctx = enc_ctx;
    base_dec_ctx = dec_ctx;
    for (x = 0; x < 0x10000u; x++) {
        uint16_t ct;
        uint16_t pt;
        enc_ctx = base_enc_ctx;
        dec_ctx = base_dec_ctx;
        ct = separ_encrypt_word((uint16_t)x, &enc_ctx, cfg->key);
        if (ct != codebook[x]) {
            free(codebook);
            free(cipher_prefix);
            return 0;
        }
        pt = separ_decrypt_word(ct, &dec_ctx, cfg->key);
        if (pt != (uint16_t)x) {
            free(codebook);
            free(cipher_prefix);
            return 0;
        }
        if (memcmp(enc_ctx.state, dec_ctx.state, sizeof(enc_ctx.state)) != 0 || enc_ctx.lfsr != dec_ctx.lfsr) {
            free(codebook);
            free(cipher_prefix);
            return 0;
        }
    }

    free(codebook);
    free(cipher_prefix);
    return 1;
}

static int check_truth_path_normalization(const cli_config_t *cfg)
{
    separ_ctx_t truth_ctx;
    uint16_t *residual = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *decoded = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    int stage_n;

    if (residual == NULL || decoded == NULL) {
        free(residual);
        free(decoded);
        return 0;
    }

    build_matched_context_codebook(cfg->prefix, cfg->prefix_count, cfg->key, cfg->iv, residual);
    separ_ctx_after_prefix(cfg->prefix, cfg->prefix_count, cfg->key, cfg->iv, &truth_ctx);
    for (stage_n = 8; stage_n >= 1; stage_n--) {
        uint16_t key0 = cfg->key[(stage_n - 1) * 2];
        uint16_t key1 = cfg->key[(stage_n - 1) * 2 + 1];
        uint32_t x;
        for (x = 0; x < 0x10000u; x++) {
            decoded[x] = dec_block(residual[x], key0, key1, (uint8_t)stage_n);
        }
        subtract_word_from_table(decoded, truth_ctx.state[stage_n - 1], residual);
    }

    stage_n = is_identity_table(residual);
    free(residual);
    free(decoded);
    return stage_n;
}

static int check_second_context_filter(const cli_config_t *cfg)
{
    recovery_candidate_t true_candidate;
    recovery_candidate_t wrong_candidate;
    extra_context_t context;

    memset(&true_candidate, 0, sizeof(true_candidate));
    memset(&wrong_candidate, 0, sizeof(wrong_candidate));
    memset(&context, 0, sizeof(context));

    memcpy(true_candidate.key_words, cfg->key, sizeof(true_candidate.key_words));
    memcpy(wrong_candidate.key_words, cfg->key, sizeof(wrong_candidate.key_words));
    wrong_candidate.key_words[15] ^= 0x0001u;

    context.prefix_count = 2;
    context.prefix[0] = 0x1111u;
    context.prefix[1] = 0xA55Au;
    context.iv[0] = 0x0123u;
    context.iv[1] = 0x4567u;
    context.iv[2] = 0x89ABu;
    context.iv[3] = 0xCDEFu;
    context.iv[4] = 0x1357u;
    context.iv[5] = 0x2468u;
    context.iv[6] = 0xDEADu;
    context.iv[7] = 0xBEEFu;

    return filter_candidate_against_context(&true_candidate, &context, cfg->key) &&
           !filter_candidate_against_context(&wrong_candidate, &context, cfg->key);
}

static void run_self_checks(const cli_config_t *cfg)
{
    self_check_report_t report;
    int overall;

    report.sep_rotl16_collapse_ok = check_sep_rotl16_collapse();
    report.byte_triangularity_ok = check_byte_triangularity(cfg->key);
    report.matched_context_inverse_ok = check_matched_context_inverse(cfg);
    report.truth_path_normalization_ok = check_truth_path_normalization(cfg);
    report.second_context_filter_ok = check_second_context_filter(cfg);

    overall = report.sep_rotl16_collapse_ok &&
              report.byte_triangularity_ok &&
              report.matched_context_inverse_ok &&
              report.truth_path_normalization_ok &&
              report.second_context_filter_ok;

    printf("{");
    printf("\"mode\":\"self-checks\",");
    printf("\"sep_rotl16_collapse_ok\":");
    json_print_bool(report.sep_rotl16_collapse_ok);
    printf(",");
    printf("\"byte_triangularity_ok\":");
    json_print_bool(report.byte_triangularity_ok);
    printf(",");
    printf("\"matched_context_inverse_ok\":");
    json_print_bool(report.matched_context_inverse_ok);
    printf(",");
    printf("\"truth_path_normalization_ok\":");
    json_print_bool(report.truth_path_normalization_ok);
    printf(",");
    printf("\"second_context_filter_ok\":");
    json_print_bool(report.second_context_filter_ok);
    printf(",");
    printf("\"overall_pass\":");
    json_print_bool(overall);
    printf("}\n");
}

static void run_stage_kernel_census(const cli_config_t *cfg)
{
    separ_ctx_t truth_ctx;
    stage_search_result_t result;
    uint16_t *table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    int stage_n = cfg->start_stage;
    size_t i;

    if (table == NULL) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    if (!build_truth_stage_table(cfg, stage_n, table, &truth_ctx)) {
        fprintf(stderr, "failed to build stage table for stage %d\n", stage_n);
        free(table);
        exit(1);
    }
    if (!scan_stage_key_candidates(table, (uint8_t)stage_n, cfg, &result)) {
        fprintf(stderr, "stage scan failed\n");
        free(table);
        exit(1);
    }

    printf("{");
    printf("\"mode\":\"stage-kernel-census\",");
    printf("\"stage\":%d,", stage_n);
    json_print_candidate_source(cfg, stage_n);
    printf(",");
    printf("\"hot_rows\":%d,", cfg->hot_rows);
    printf("\"candidate_pairs_scanned\":%" PRIu64 ",", result.candidate_pairs_scanned);
    printf("\"subset_block_evals\":%" PRIu64 ",", stage_demo_block_evals(result.candidate_pairs_scanned, cfg->hot_rows));
    printf("\"full_stage_block_evals\":%" PRIu64 ",", stage_real_kernel_bound(cfg->hot_rows));
    printf("\"true_key\":[");
    json_print_hex_word(cfg->key[(stage_n - 1) * 2]);
    printf(",");
    json_print_hex_word(cfg->key[(stage_n - 1) * 2 + 1]);
    printf("],");
    printf("\"true_state\":");
    json_print_hex_word(truth_ctx.state[stage_n - 1]);
    printf(",");
    printf("\"selected_rows\":");
    json_print_row_array(result.selected_rows, result.selected_row_count);
    printf(",");
    json_print_branch_profile("baseline_profile", &result.baseline_profile);
    printf(",");
    json_print_branch_profile("best_profile", &result.best_profile);
    printf(",");
    printf("\"strict_improvement\":");
    json_print_bool(branch_profile_is_strict_improvement(&result.best_profile, &result.baseline_profile));
    printf(",");
    printf("\"winner_count\":%zu,", result.winners.count);
    printf("\"winners\":[");
    for (i = 0; i < result.winners.count; i++) {
        const stage_search_winner_t *winner = &result.winners.items[i];
        if (i != 0) {
            printf(",");
        }
        printf("{\"key0\":");
        json_print_hex_word(winner->key0);
        printf(",\"key1\":");
        json_print_hex_word(winner->key1);
        printf(",\"low_byte_count\":%u,\"low_bytes\":", (unsigned)winner->low_byte_count);
        json_print_byte_array(winner->low_bytes, winner->low_byte_count);
        printf("}");
    }
    printf("]");
    printf("}\n");

    stage_search_result_free(&result);
    free(table);
}

static void run_lowbyte_certify(const cli_config_t *cfg)
{
    separ_ctx_t truth_ctx;
    low_byte_refinement_t low_refinement;
    uint16_t *table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    int stage_n = cfg->start_stage;
    uint16_t key0 = cfg->key[(stage_n - 1) * 2];
    uint16_t key1 = cfg->key[(stage_n - 1) * 2 + 1];
    uint16_t true_low;
    size_t i;
    int true_low_present = 0;

    if (table == NULL) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    if (!build_truth_stage_table(cfg, stage_n, table, &truth_ctx)) {
        fprintf(stderr, "failed to build stage table for stage %d\n", stage_n);
        free(table);
        exit(1);
    }

    memset(&low_refinement, 0, sizeof(low_refinement));
    refine_low_byte_candidates(table, key0, key1, (uint8_t)stage_n, &low_refinement);
    true_low = (uint16_t)(truth_ctx.state[stage_n - 1] & 0x00FFu);
    for (i = 0; i < low_refinement.low_byte_count; i++) {
        if (low_refinement.low_bytes[i] == true_low) {
            true_low_present = 1;
            break;
        }
    }

    printf("{");
    printf("\"mode\":\"lowbyte-certify\",");
    printf("\"stage\":%d,", stage_n);
    printf("\"true_key\":[");
    json_print_hex_word(key0);
    printf(",");
    json_print_hex_word(key1);
    printf("],");
    printf("\"true_state\":");
    json_print_hex_word(truth_ctx.state[stage_n - 1]);
    printf(",");
    printf("\"true_low\":\"%02X\",", (unsigned)true_low);
    printf("\"row_count\":%u,", (unsigned)low_refinement.row_count);
    printf("\"rows\":");
    json_print_row_array(low_refinement.rows, low_refinement.row_count);
    printf(",");
    printf("\"low_byte_count\":%u,", (unsigned)low_refinement.low_byte_count);
    printf("\"low_bytes\":");
    json_print_byte_array(low_refinement.low_bytes, low_refinement.low_byte_count);
    printf(",");
    json_print_branch_profile("profile", &low_refinement.profile);
    printf(",");
    printf("\"true_low_present\":");
    json_print_bool(true_low_present);
    printf("}\n");

    free(table);
}

static int branch_scan_bounded_for_stage(const cli_config_t *cfg, int stage_n)
{
    candidate_source_t source;
    copy_candidate_source_for_stage(cfg, stage_n, &source);
    if (source.kind == CANDIDATE_SOURCE_LIST) {
        return 1;
    }
    return source.count <= CERT_BRANCH_SCAN_CAP;
}

static void run_branch_certify(const cli_config_t *cfg)
{
    separ_ctx_t truth_ctx;
    low_byte_refinement_t low_refinement;
    uint16_t *table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *decoded = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *after_low = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *residual = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    int stage_n = cfg->start_stage;
    uint16_t key0;
    uint16_t key1;
    size_t low_index;
    uint32_t x;

    if (stage_n <= 1) {
        fprintf(stderr, "branch-certify requires --start-stage >= 2\n");
        exit(1);
    }
    if (!branch_scan_bounded_for_stage(cfg, stage_n - 1)) {
        fprintf(stderr, "branch-certify refuses an unbounded stage-%d scan; use --stage-candidate or --candidate-count <= 0x%llX\n",
                stage_n - 1, (unsigned long long)CERT_BRANCH_SCAN_CAP);
        exit(1);
    }
    if (table == NULL || decoded == NULL || after_low == NULL || residual == NULL) {
        fprintf(stderr, "out of memory\n");
        free(table);
        free(decoded);
        free(after_low);
        free(residual);
        exit(1);
    }
    if (!build_truth_stage_table(cfg, stage_n, table, &truth_ctx)) {
        fprintf(stderr, "failed to build stage table for stage %d\n", stage_n);
        free(table);
        free(decoded);
        free(after_low);
        free(residual);
        exit(1);
    }

    key0 = cfg->key[(stage_n - 1) * 2];
    key1 = cfg->key[(stage_n - 1) * 2 + 1];
    memset(&low_refinement, 0, sizeof(low_refinement));
    refine_low_byte_candidates(table, key0, key1, (uint8_t)stage_n, &low_refinement);
    for (x = 0; x < 0x10000u; x++) {
        decoded[x] = dec_block(table[x], key0, key1, (uint8_t)stage_n);
    }

    printf("{");
    printf("\"mode\":\"branch-certify\",");
    printf("\"stage\":%d,", stage_n);
    printf("\"true_key\":[");
    json_print_hex_word(key0);
    printf(",");
    json_print_hex_word(key1);
    printf("],");
    printf("\"true_state\":");
    json_print_hex_word(truth_ctx.state[stage_n - 1]);
    printf(",");
    printf("\"true_low\":\"%02X\",", (unsigned)(truth_ctx.state[stage_n - 1] & 0xFFu));
    printf("\"true_high\":\"%02X\",", (unsigned)(truth_ctx.state[stage_n - 1] >> 8));
    json_print_candidate_source(cfg, stage_n - 1);
    printf(",");
    printf("\"low_candidates\":[");
    for (low_index = 0; low_index < low_refinement.low_byte_count; low_index++) {
        uint8_t low_byte = low_refinement.low_bytes[low_index];
        uint16_t viable_count = 0;
        uint8_t viable_highs[256];
        uint16_t high;
        if (low_index != 0) {
            printf(",");
        }
        subtract_word_from_table(decoded, low_byte, after_low);
        for (high = 0; high < 256u; high++) {
            stage_search_result_t next_search;
            subtract_word_from_table(after_low, (uint16_t)(high << 8), residual);
            if (!scan_stage_key_candidates(residual, (uint8_t)(stage_n - 1), cfg, &next_search)) {
                fprintf(stderr, "branch-certify next-stage scan failed\n");
                free(table);
                free(decoded);
                free(after_low);
                free(residual);
                exit(1);
            }
            if (branch_profile_is_strict_improvement(&next_search.best_profile, &next_search.baseline_profile)) {
                viable_highs[viable_count++] = (uint8_t)high;
            }
            stage_search_result_free(&next_search);
        }
        printf("{\"low_byte\":\"%02X\",\"viable_high_count\":%u,\"viable_highs\":", (unsigned)low_byte, (unsigned)viable_count);
        json_print_byte_array(viable_highs, viable_count);
        printf("}");
    }
    printf("]");
    printf("}\n");

    free(table);
    free(decoded);
    free(after_low);
    free(residual);
}

static void csv_write_header(FILE *fp, const char *line)
{
    fprintf(fp, "%s\n", line);
}

static int write_self_checks_csv(const self_check_report_t *report)
{
    FILE *fp = fopen("certifier_self_checks.csv", "w");
    if (fp == NULL) {
        return 0;
    }
    csv_write_header(fp, "check,pass");
    fprintf(fp, "sep_rotl16_collapse,%d\n", report->sep_rotl16_collapse_ok);
    fprintf(fp, "byte_triangularity,%d\n", report->byte_triangularity_ok);
    fprintf(fp, "matched_context_inverse,%d\n", report->matched_context_inverse_ok);
    fprintf(fp, "truth_path_normalization,%d\n", report->truth_path_normalization_ok);
    fprintf(fp, "second_context_filter,%d\n", report->second_context_filter_ok);
    fclose(fp);
    return 1;
}

static int write_truth_lowbyte_csv(const truth_stage_lowbyte_t rows[8])
{
    FILE *fp = fopen("certifier_truth_lowbyte_rows.csv", "w");
    int stage_n;
    if (fp == NULL) {
        return 0;
    }
    csv_write_header(fp, "stage,key0,key1,state_word,low_byte_count,low_bytes,row_count,rows");
    for (stage_n = 8; stage_n >= 1; stage_n--) {
        const truth_stage_lowbyte_t *row = &rows[stage_n - 1];
        size_t i;
        fprintf(fp, "%d,%04X,%04X,%04X,%u,\"", stage_n, row->key0, row->key1, row->state_word, (unsigned)row->low_byte_count);
        for (i = 0; i < row->low_byte_count; i++) {
            fprintf(fp, "%s%02X", i == 0 ? "" : " ", row->low_bytes[i]);
        }
        fprintf(fp, "\",%u,\"", (unsigned)row->row_count);
        for (i = 0; i < row->row_count; i++) {
            fprintf(fp, "%s%u", i == 0 ? "" : " ", (unsigned)row->rows[i]);
        }
        fprintf(fp, "\"\n");
    }
    fclose(fp);
    return 1;
}

static int write_stage_window_csv(const stage_search_result_t *result, uint64_t subset_evals, uint64_t full_evals)
{
    FILE *fp = fopen("certifier_stage8_window.csv", "w");
    size_t i;
    if (fp == NULL) {
        return 0;
    }
    csv_write_header(fp, "candidate_pairs_scanned,subset_block_evals,full_stage_block_evals,winner_index,key0,key1,low_byte_count,low_bytes");
    for (i = 0; i < result->winners.count; i++) {
        const stage_search_winner_t *winner = &result->winners.items[i];
        size_t j;
        fprintf(fp, "%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%zu,%04X,%04X,%u,\"",
                result->candidate_pairs_scanned, subset_evals, full_evals, i, winner->key0, winner->key1, (unsigned)winner->low_byte_count);
        for (j = 0; j < winner->low_byte_count; j++) {
            fprintf(fp, "%s%02X", j == 0 ? "" : " ", winner->low_bytes[j]);
        }
        fprintf(fp, "\"\n");
    }
    fclose(fp);
    return 1;
}

static int write_branch_probe_csv(const branch_probe_summary_t *summary)
{
    FILE *fp = fopen("certifier_branch_probe.csv", "w");
    size_t i;
    if (fp == NULL) {
        return 0;
    }
    csv_write_header(fp, "stage,low_byte,true_high,viable_high_count,viable_highs");
    fprintf(fp, "%u,%02X,%02X,%u,\"",
            (unsigned)summary->stage_n,
            (unsigned)summary->low_byte,
            (unsigned)summary->true_high,
            (unsigned)summary->viable_high_count);
    for (i = 0; i < summary->viable_high_count; i++) {
        fprintf(fp, "%s%02X", i == 0 ? "" : " ", summary->viable_highs[i]);
    }
    fprintf(fp, "\"\n");
    fclose(fp);
    return 1;
}

static void run_paper_export(const cli_config_t *cfg)
{
    self_check_report_t report;
    truth_stage_lowbyte_t lowbyte_rows[8];
    cli_config_t census_cfg = *cfg;
    cli_config_t branch_cfg = *cfg;
    stage_search_result_t census_result;
    branch_probe_summary_t branch_summary;
    separ_ctx_t truth_ctx;
    uint16_t *table = NULL;
    uint16_t *decoded = NULL;
    uint16_t *after_low = NULL;
    uint16_t *residual = NULL;
    low_byte_refinement_t low_refinement;
    uint32_t x;
    uint16_t high;
    int stage_n;
    FILE *macro_fp;

    report.sep_rotl16_collapse_ok = check_sep_rotl16_collapse();
    report.byte_triangularity_ok = check_byte_triangularity(cfg->key);
    report.matched_context_inverse_ok = check_matched_context_inverse(cfg);
    report.truth_path_normalization_ok = check_truth_path_normalization(cfg);
    report.second_context_filter_ok = check_second_context_filter(cfg);
    if (!write_self_checks_csv(&report)) {
        fprintf(stderr, "failed to write certifier_self_checks.csv\n");
        exit(1);
    }

    if (!collect_truth_stage_lowbytes(cfg, lowbyte_rows) || !write_truth_lowbyte_csv(lowbyte_rows)) {
        fprintf(stderr, "failed to export truth-path low-byte rows\n");
        exit(1);
    }

    init_default_config(&census_cfg);
    memcpy(census_cfg.key, cfg->key, sizeof(census_cfg.key));
    memcpy(census_cfg.iv, cfg->iv, sizeof(census_cfg.iv));
    memcpy(census_cfg.prefix, cfg->prefix, sizeof(uint16_t) * cfg->prefix_count);
    census_cfg.prefix_count = cfg->prefix_count;
    census_cfg.hot_rows = 1;
    census_cfg.start_stage = 8;
    census_cfg.candidate_start = ((((uint64_t)cfg->key[14]) << 16) | cfg->key[15]) & ~UINT64_C(0xFF);
    census_cfg.candidate_count = UINT64_C(0x100);

    table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    decoded = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    after_low = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    residual = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    if (table == NULL || decoded == NULL || after_low == NULL || residual == NULL) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }
    if (!build_truth_stage_table(&census_cfg, 8, table, &truth_ctx)) {
        fprintf(stderr, "failed to build stage-8 table for paper export\n");
        exit(1);
    }
    if (!scan_stage_key_candidates(table, 8, &census_cfg, &census_result)) {
        fprintf(stderr, "failed to build stage-8 census for paper export\n");
        exit(1);
    }
    if (!write_stage_window_csv(&census_result,
                                stage_demo_block_evals(census_result.candidate_pairs_scanned, census_cfg.hot_rows),
                                stage_real_kernel_bound(census_cfg.hot_rows))) {
        fprintf(stderr, "failed to write certifier_stage8_window.csv\n");
        exit(1);
    }

    init_default_config(&branch_cfg);
    memcpy(branch_cfg.key, cfg->key, sizeof(branch_cfg.key));
    memcpy(branch_cfg.iv, cfg->iv, sizeof(branch_cfg.iv));
    memcpy(branch_cfg.prefix, cfg->prefix, sizeof(uint16_t) * cfg->prefix_count);
    branch_cfg.prefix_count = cfg->prefix_count;
    branch_cfg.start_stage = 8;
    branch_cfg.hot_rows = 1;
    push_default_branch_probe_candidates(&branch_cfg, 7);

    build_truth_stage_table(&branch_cfg, 8, table, &truth_ctx);
    memset(&low_refinement, 0, sizeof(low_refinement));
    refine_low_byte_candidates(table, branch_cfg.key[14], branch_cfg.key[15], 8, &low_refinement);
    for (x = 0; x < 0x10000u; x++) {
        decoded[x] = dec_block(table[x], branch_cfg.key[14], branch_cfg.key[15], 8);
    }
    subtract_word_from_table(decoded, low_refinement.low_bytes[0], after_low);
    memset(&branch_summary, 0, sizeof(branch_summary));
    branch_summary.stage_n = 8;
    branch_summary.low_byte = low_refinement.low_bytes[0];
    branch_summary.true_high = (uint8_t)(truth_ctx.state[7] >> 8);
    for (high = 0; high < 256u; high++) {
        stage_search_result_t next_search;
        subtract_word_from_table(after_low, (uint16_t)(high << 8), residual);
        if (!scan_stage_key_candidates(residual, 7, &branch_cfg, &next_search)) {
            fprintf(stderr, "failed to build bounded branch probe\n");
            exit(1);
        }
        if (branch_profile_is_strict_improvement(&next_search.best_profile, &next_search.baseline_profile)) {
            branch_summary.viable_highs[branch_summary.viable_high_count++] = (uint8_t)high;
        }
        stage_search_result_free(&next_search);
    }
    if (!write_branch_probe_csv(&branch_summary)) {
        fprintf(stderr, "failed to write certifier_branch_probe.csv\n");
        exit(1);
    }

    macro_fp = fopen("certifier_macros.tex", "w");
    if (macro_fp == NULL) {
        fprintf(stderr, "failed to write certifier_macros.tex\n");
        exit(1);
    }
    fprintf(macro_fp, "%% Auto-generated by separ_proof_certifier paper-export.\n");
    fprintf(macro_fp, "\\renewcommand{\\StageKernelBound}{2^{40}}\n");
    fprintf(macro_fp, "\\renewcommand{\\FullTargetBound}{2^{45}}\n");
    fprintf(macro_fp, "\\renewcommand{\\RecursiveStatusText}{open under bounded certification}\n");
    fprintf(macro_fp, "\\renewcommand{\\BoundedBranchViableHighCount}{%u}\n", (unsigned)branch_summary.viable_high_count);
    fprintf(macro_fp, "\\renewcommand{\\BoundedBranchTrueHigh}{%02X}\n", (unsigned)branch_summary.true_high);
    fprintf(macro_fp, "\\renewcommand{\\StageWindowWinnerCount}{%zu}\n", census_result.winners.count);
    fclose(macro_fp);

    printf("%% Auto-generated by separ_proof_certifier paper-export.\n");
    printf("%% CSV sidecars: certifier_self_checks.csv, certifier_truth_lowbyte_rows.csv,\n");
    printf("%% certifier_stage8_window.csv, certifier_branch_probe.csv.\n");
    printf("\\begin{table}[t]\n");
    printf("\\centering\n");
    printf("\\caption{Native exact self-checks used by the proof certifier.}\n");
    printf("\\begin{tabular}{|l|l|}\n");
    printf("\\hline\n");
    printf("Check & Result \\\\\n");
    printf("\\hline\n");
    printf("$\\mathrm{Sep\\_ROTL16}$ closed form & %s \\\\\n", report.sep_rotl16_collapse_ok ? "PASS" : "FAIL");
    printf("Byte-triangularity regression & %s \\\\\n", report.byte_triangularity_ok ? "PASS" : "FAIL");
    printf("Matched-context inverse oracle & %s \\\\\n", report.matched_context_inverse_ok ? "PASS" : "FAIL");
    printf("Truth-path normalization & %s \\\\\n", report.truth_path_normalization_ok ? "PASS" : "FAIL");
    printf("Second-context filter & %s \\\\\n", report.second_context_filter_ok ? "PASS" : "FAIL");
    printf("\\hline\n");
    printf("\\end{tabular}\n");
    printf("\\end{table}\n\n");

    printf("\\begin{table}[t]\n");
    printf("\\centering\n");
    printf("\\caption{Exact low-byte refinement along the true residual path for the built-in key, IV, and prefix.}\n");
    printf("\\begin{tabular}{|r|r|r|r|l|}\n");
    printf("\\hline\n");
    printf("Stage & State & $|L_i|$ & Rows & Low bytes \\\\\n");
    printf("\\hline\n");
    for (stage_n = 8; stage_n >= 1; stage_n--) {
        const truth_stage_lowbyte_t *row = &lowbyte_rows[stage_n - 1];
        size_t i;
        printf("%u & %04X & %u & %u & ", (unsigned)row->stage_n, row->state_word, (unsigned)row->low_byte_count, (unsigned)row->row_count);
        for (i = 0; i < row->low_byte_count; i++) {
            printf("%s%02X", i == 0 ? "" : " ", row->low_bytes[i]);
        }
        printf(" \\\\\n");
    }
    printf("\\hline\n");
    printf("\\end{tabular}\n");
    printf("\\end{table}\n\n");

    printf("\\begin{table}[t]\n");
    printf("\\centering\n");
    printf("\\caption{Bounded exact proof probes generated by the certifier.}\n");
    printf("\\begin{tabular}{|l|l|l|l|}\n");
    printf("\\hline\n");
    printf("Probe & Candidate source & Exact work & Result \\\\\n");
    printf("\\hline\n");
    printf("Stage-8 window census & 256 key pairs around $K_8$ & $2^{16}$ block evals & %zu winners \\\\\n",
           census_result.winners.count);
    printf("Bounded branch probe & $|\\mathcal{K}_7|=3$ & 256 high-byte scans & %u viable highs \\\\\n",
           (unsigned)branch_summary.viable_high_count);
    printf("Full-stage theorem & exhaustive key space & $\\StageKernelBound$ & exact \\\\\n");
    printf("Full recursive theorem & target schedule & $\\FullTargetBound$ & \\RecursiveStatusText \\\\\n");
    printf("\\hline\n");
    printf("\\end{tabular}\n");
    printf("\\end{table}\n");

    stage_search_result_free(&census_result);
    free(table);
    free(decoded);
    free(after_low);
    free(residual);
}

static void cert_print_usage(const char *program_name)
{
    fprintf(stderr, "Usage: %s <self-checks|stage-kernel-census|lowbyte-certify|branch-certify|paper-export> [options]\n", program_name);
    fprintf(stderr, "  Common options:\n");
    fprintf(stderr, "    --threads N\n");
    fprintf(stderr, "    --hot-rows N\n");
    fprintf(stderr, "    --prefix WORDS\n");
    fprintf(stderr, "    --key 64HEX\n");
    fprintf(stderr, "    --iv 32HEX\n");
    fprintf(stderr, "    --start-stage N\n");
    fprintf(stderr, "    --inject-key key0,key1\n");
    fprintf(stderr, "    --inject-state WORD\n");
    fprintf(stderr, "    --stage-candidate stage:key0,key1\n");
    fprintf(stderr, "    --candidate-start VALUE\n");
    fprintf(stderr, "    --candidate-count VALUE\n");
    fprintf(stderr, "    --extra-context prefix_words@iv_hex\n");
}

static int cert_parse_cli(int argc, char **argv, cli_config_t *cfg)
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
        } else if (strcmp(arg, "--candidate-start") == 0) {
            uint64_t value;
            if (++i >= argc || !parse_u64_auto(argv[i], &value)) {
                return 0;
            }
            cfg->candidate_start = value;
        } else if (strcmp(arg, "--candidate-count") == 0) {
            uint64_t value;
            if (++i >= argc || !parse_u64_auto(argv[i], &value) || value == 0) {
                return 0;
            }
            cfg->candidate_count = value;
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

int main(int argc, char **argv)
{
    cli_config_t cfg;

    if (argc < 2) {
        cert_print_usage(argv[0]);
        return 1;
    }
    if (!cert_parse_cli(argc, argv, &cfg)) {
        cert_print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "self-checks") == 0) {
        run_self_checks(&cfg);
        return 0;
    }
    if (strcmp(argv[1], "stage-kernel-census") == 0) {
        run_stage_kernel_census(&cfg);
        return 0;
    }
    if (strcmp(argv[1], "lowbyte-certify") == 0) {
        run_lowbyte_certify(&cfg);
        return 0;
    }
    if (strcmp(argv[1], "branch-certify") == 0) {
        run_branch_certify(&cfg);
        return 0;
    }
    if (strcmp(argv[1], "paper-export") == 0) {
        run_paper_export(&cfg);
        return 0;
    }

    cert_print_usage(argv[0]);
    return 1;
}
