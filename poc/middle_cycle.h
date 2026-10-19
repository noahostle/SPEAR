/* Decode a translated 4096-vertex rotor cycle through its middle paths.
 * Streaming interface: no candidate cap or exceptional core cases. */
static int middle_paths(const uint16_t walk[4096],unsigned low,uint8_t path[16][16]) {
    uint8_t normalized[256];
    for(unsigned x=0;x<256;x++) normalized[x]=(uint8_t)(walk[x]-low);
    unsigned boundary=0,seen=0;
    while(boundary<256 && normalized[boundary]>>4==normalized[(boundary+255)&255]>>4) boundary++;
    if(boundary==256) return 0;
    for(unsigned row=0;row<16;row++) {
        unsigned start=(boundary+16*row)&255,lane=normalized[start]>>4;
        if(seen&(1u<<lane)) return 0;
        seen|=1u<<lane;
        for(unsigned c=0;c<16;c++) {
            unsigned value=normalized[(start+c)&255];
            if(value>>4!=lane) return 0;
            path[lane][c]=(uint8_t)(value&15);
        }
    }
    return 1;
}
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
        uint8_t path[16][16];
        if (middle_paths(walk,ctx.low,path)) (void)middle_decode(path, stage, &ctx.lane, middle_cycle_candidate, &ctx);
    }
}
