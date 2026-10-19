/* Acquire quotient contexts from IVs and ciphertexts. */

static uint16_t table[65536], lower[65536], inverse7[65536], inverse8[65536];
static void outer_candidate(const uint16_t key[2]) {
    outer_found(key);
}
static int inward_candidate(const uint16_t key[2],unsigned shift,unsigned mask) {
    static uint16_t next[65536];
    for(unsigned p=0;p<4111;p++) lower[p]=DEC_Block((uint16_t)(table[p]-shift),key,7);
    for(unsigned low=1;low<16;low++) if(mask&(1u<<low)) {
        for(unsigned p=0;p<4111;p++) next[p]=(uint16_t)(lower[p]-low);
        if(graph(next,small.r,neighbor,256)) return 1;
    }
    return 0;
}
typedef struct {const uint16_t *iv; unsigned r;} SaveContext;
static void seed_candidate(const ShiftedKey *key6,void *opaque) {
    const uint16_t *key7=opaque;
    seed_found(key6->key, key7);
}
static void keep_context(const ShiftedKey *key,void *opaque) {
    SaveContext *ctx=opaque;
    uint16_t key7[2]={key->key[0],key->key[1]};
    for(unsigned x=0;x<65536;x++) inverse7[x]=DEC_Block((uint16_t)x,key7,7);
    for(unsigned p=0;p<65536;p++) lower[p]=inverse7[(uint16_t)(table[p]-key->shift)];
    Context *record = malloc(sizeof *record);
    if (!record) { fputs("Out of memory\n", stderr); exit(8); }
    memcpy(record->iv, ctx->iv, sizeof record->iv);
    memcpy(record->k8, active_k8, sizeof record->k8);
    memcpy(record->k7, key7, sizeof record->k7);
    record->shift8 = key->shift;
    record->r = ctx->r;
    record->bmask = key->bmask;
    memcpy(record->y, lower, sizeof record->y);
    context_found(record);
    for(unsigned low=1;low<16;low++) if(key->bmask&(1u<<low))
        peel(lower,ctx->r,low,6,seed_candidate,key7);
}
static int acquire(unsigned n, const uint16_t *known8, Oracle oracle) {
    if (known8) {
        for (unsigned x = 0; x < 65536; x++) inverse8[x] = DEC_Block((uint16_t)x, known8, 8);
    }
    uint16_t iv[4096][8];
    for (unsigned base = 0; base < n; base += 4096) {
        unsigned count = n - base < 4096 ? n - base : 4096;
        if (BCryptGenRandom(NULL, (PUCHAR)iv, count * 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
            return 8;
        }
        for (unsigned j = 0; j < count; j++) {
            oracle.reset(iv[j]);
            unsigned mask[16];
            for (unsigned c = 0; c < 16; c++) mask[c] = known8 || !c ? 65535 : 0;
            unsigned alive = 1;
            for (unsigned strip = 0; strip < (known8?16u:12u) && alive; strip++) {
                unsigned first = (16 * 997 * strip) & 65535;
                uint16_t values[31];
                const unsigned widths[3]={6,9,16};
                unsigned previous=0;
                for(unsigned level=known8?0u:2u;level<3 && alive;level++) {
                    unsigned n=widths[level];
                    for(unsigned d=16-n;d<15+n;d++)
                        if(!previous || d<16-previous || d>=15+previous) {
                            uint16_t x=oracle.first((uint16_t)(first+d));
                            values[d]=known8?inverse8[x]:x;
                        }
                    alive=n<16?screen_partial(values,n,mask):screen_shifted_strip(values,mask,!known8);
                    previous=n;
                }
            }
            if (!alive) continue;
            for (unsigned p = 0; p < 4111; p++) {
                uint16_t x = oracle.first((uint16_t)p);
                table[p] = known8 ? inverse8[x] : x;
            }
            if (!known8) {
                for (unsigned r = 0; r < 16; r++)
                    if(mask[0]&(1u<<r)) support_outer(table,r,outer_candidate);
                continue;
            }
            unsigned useful=0;
            for(unsigned c=0;c<16 && !useful;c++) for(unsigned r=0;r<16 && !useful;r++)
                if(mask[c]&(1u<<r)) useful=small_cycle(table,r,c,7,inward_candidate);
            if(!useful) continue;
            for(unsigned p=4111;p<65536;p++) {
                uint16_t x=oracle.first((uint16_t)p);
                table[p]=inverse8[x];
            }
            for (unsigned c = 0; c < 16; c++)
                for (unsigned r = 0; r < 16; r++)
                    if (mask[c] & (1u << r)) {
                        SaveContext ctx={iv[j],r};
                        peel(table,r,c,7,keep_context,&ctx);
                    }
        }
        progress_advance(count);
    }
    return 0;
}
