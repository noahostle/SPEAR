static uint16_t E[8][65536], current_iv[8], current_shift8;
static const uint16_t *current_y;
static uint16_t candidate_key[16], recursive_known[16];
static void keep_master(const uint16_t pair[4], const uint16_t state[3], void *unused) {
    (void)state; (void)unused;
    memcpy(candidate_key, pair, 8);
    /* A complete key is now available. Test it by ordinary forward
     * encryption of public inputs; initialization supplies no key guesses. */
    Separ_ctx c;
    Separ_Initial_State(&c, candidate_key, current_iv);
    uint16_t s[8] = {c.state_1, c.state_2, c.state_3, c.state_4,
                     c.state_5, c.state_6, c.state_7, c.state_8};
    const uint16_t probes[4] = {0, 1, 0x1234, 0xffff};
    for (unsigned p = 0; p < 4; p++) {
        uint16_t x = probes[p];
        for (unsigned i = 0; i < 8; i++)
            x = ENC_Block((uint16_t)(x + s[i]), candidate_key + 2*i, (uint8_t)(i + 1));
        uint16_t observed = ENC_Block((uint16_t)(ENC_Block(current_y[probes[p]],
                                      recursive_known + 12, 7) + current_shift8),
                                      recursive_known + 14, 8);
        if (x != observed) return;
    }
    recovered(candidate_key);
}
static int verify_contexts(Context *const *contexts, size_t count, const uint16_t key[16]) {
    static uint16_t record7[65536], record8[65536];
    uint32_t previous_key8 = 0;
    uint32_t previous_key7 = 0;
    unsigned have8 = 0, have7 = 0;
    for (unsigned i = 0; i < 8; i++)
        for (unsigned x = 0; x < 65536; x++)
            E[i][x] = ENC_Block((uint16_t)x, key + 2 * i, (uint8_t)(i + 1));
    for (size_t j = 0; j < count; j++) {
        const Context *ctx = contexts[j];
        uint32_t k8 = ((uint32_t)ctx->k8[0] << 16) | ctx->k8[1];
        uint32_t k7 = ((uint32_t)ctx->k7[0] << 16) | ctx->k7[1];
        if (!have8 || previous_key8 != k8) {
            for (unsigned x = 0; x < 65536; x++) record8[x] = ENC_Block((uint16_t)x, ctx->k8, 8);
            previous_key8 = k8;
            have8 = 1;
        }
        if (!have7 || previous_key7 != k7) {
            for (unsigned x = 0; x < 65536; x++) record7[x] = ENC_Block((uint16_t)x, ctx->k7, 7);
            previous_key7 = k7;
            have7 = 1;
        }
        Separ_ctx c;
        Separ_Initial_State(&c, key, ctx->iv);
        uint16_t s[8] = {c.state_1, c.state_2, c.state_3, c.state_4,
                         c.state_5, c.state_6, c.state_7, c.state_8};
        for (unsigned p = 0; p < 65536; p++) {
            uint16_t x = (uint16_t)p;
            for (unsigned i = 0; i < 8; i++) x = E[i][(uint16_t)(x + s[i])];
            if (x != record8[(uint16_t)(record7[ctx->y[p]] + ctx->shift8)]) return 0;
        }
        progress_advance(0);
    }
    return 1;
}
static void recursive_finish(const RecursiveBridge *b) {
    static uint16_t z[65536], inverse3[65536];
    memcpy(candidate_key, recursive_known, sizeof candidate_key);
    memcpy(candidate_key + 4, b->inner.key, 4);
    for (unsigned x = 0; x < 65536; x++) inverse3[x] = DEC_Block((uint16_t)x, b->inner.key, 3);
    for (unsigned p = 0; p < 65536; p++) {
        uint16_t x = current_y[p];
        for (unsigned i = 0; i < 3; i++) x = rb_inverse[i][(uint16_t)(x - b->shifts[i])];
        z[p] = inverse3[(uint16_t)(x - b->inner.shift)];
    }
    outer_tail(z, rb_alignment, b->inner.bmask, keep_master, NULL);
}
static unsigned first_known;
static void emit_extension(const RecursiveBridge *b) {
    if (first_known == 4) {
        recursive_finish(b);
        return;
    }
    uint16_t key[16];
    memcpy(key, recursive_known, sizeof key);
    memcpy(key + 2 * (first_known - 2), b->inner.key, 4);
    recovered(key);
}
static void recover_stage(Context *const *contexts, size_t count, const uint16_t known[16],
                          unsigned first) {
    first_known = first;
    memcpy(recursive_known, known, sizeof recursive_known);
    rb_prepare(recursive_known, 6, 7 - first_known);
    rb_emit = emit_extension;
    for (size_t i = 0; i < count; i++) {
        const Context *ctx = contexts[i];
        if (memcmp(ctx->k8, known + 14, 4) || memcmp(ctx->k7, known + 12, 4)) continue;
        memcpy(current_iv, ctx->iv, sizeof current_iv);
        current_shift8 = ctx->shift8;
        current_y = ctx->y;
        recursive_bridge(ctx->y, ctx->r, ctx->bmask);
        progress_advance(0);
    }
}
