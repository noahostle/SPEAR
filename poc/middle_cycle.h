typedef struct {
    const uint16_t *walk;
    uint16_t position[4096];
    unsigned stage, low, lane;
    void (*emit)(const uint16_t[2], unsigned, void *);
    void *opaque;
} MiddleCycle;
static void middle_cycle_candidate(const uint16_t key[2], void *opaque) {
    MiddleCycle *ctx = opaque;
    uint16_t q[4096];
    for (unsigned x = 0; x < 4096; x++)
        q[x] = (uint16_t)(ENC_Block((uint16_t)(16*x), key, (uint8_t)ctx->stage) >> 4);
    for (unsigned top = 0; top < 16; top++) {
        unsigned shift = ctx->low + 16*ctx->lane + 256*top;
        unsigned origin = ctx->position[(q[0]+shift)&4095];
        for (unsigned direction = 0; direction < 2; direction++) {
            unsigned x = 1;
            while (x < 4096 && ctx->walk[(origin + (direction ? -x : x)) & 4095] == ((q[x]+shift)&4095)) x++;
            if (x == 4096) ctx->emit(key, shift, ctx->opaque);
        }
    }
}
static void middle_cycle(const uint16_t walk[4096], unsigned stage,
                         void (*emit)(const uint16_t[2], unsigned, void *), void *opaque) {
    MiddleCycle ctx = {.walk=walk, .stage=stage, .emit=emit, .opaque=opaque};
    uint8_t seen[4096] = {0};
    for (unsigned x = 0; x < 4096; x++) {
        if (walk[x] >= 4096 || seen[walk[x]]) return;
        seen[walk[x]] = 1; ctx.position[walk[x]] = (uint16_t)x;
        if ((walk[x]&255) != (walk[x&255]&255)) return;
    }
    for (ctx.low = 0; ctx.low < 16; ctx.low++) {
        uint8_t ordered[256];
        for(unsigned x=0;x<256;x++) ordered[x]=(uint8_t)(walk[x]-ctx.low);
        (void)middle_decode(ordered, stage, &ctx.lane, middle_cycle_candidate, &ctx);
    }
}
