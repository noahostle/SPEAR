#include "quotient_lift.h"

static uint16_t offset_q[4][4096];
static uint8_t offset_inverse[4][256], offset_level[4][256], offset_residual[256];
static const uint16_t *offset_walk, *offset_key;
static unsigned offset_h[4], offset_lane, offset_depth, offset_stage;
static void (*offset_emit)(const uint16_t[2], const unsigned[4]);

static void offset_prepare(const uint16_t key[16], unsigned stage, unsigned depth) {
    offset_stage=stage-depth; offset_depth=depth;
    for (unsigned j=1;j<=depth;j++) for (unsigned x=0;x<4096;x++) {
        offset_q[j][x]=(uint16_t)(ENC_Block((uint16_t)(16*x),
            key+2*(offset_stage+j-1),(uint8_t)(offset_stage+j))>>4);
        if (x<256) offset_inverse[j][offset_q[j][x]&255]=(uint8_t)x;
    }
}

static void offset_lifted(const unsigned h[4]) { offset_emit(offset_key,h); }
static void offset_middle(const uint16_t key[2], void *unused) {
    (void)unused;
    uint8_t m[256]; unsigned origin=256;
    for (unsigned x=0;x<256;x++)
        m[x]=(uint8_t)(ENC_Block((uint16_t)(16*x),key,(uint8_t)offset_stage)>>4);
    for (unsigned x=0;x<256;x++)
        if (offset_residual[x]==(uint8_t)(m[0]+16*offset_lane)) origin=x;
    if (origin==256) return;
    for (unsigned direction=0;direction<2;direction++) {
        unsigned x=0;
        while (x<256 && offset_residual[(origin+(direction?-x:x))&255]
               == (uint8_t)(m[x]+16*offset_lane)) x++;
        if (x<256) continue;
        offset_h[0]=(offset_h[0]&15)+16*offset_lane;
        for (unsigned a=0;a<4096;a++)
            offset_q[0][a]=(uint16_t)(ENC_Block((uint16_t)(16*a),key,(uint8_t)offset_stage)>>4);
        offset_key=key;
        quotient_lift((const uint16_t (*)[4096])offset_q,offset_depth+1,
                      offset_walk,offset_h,origin,direction,offset_lifted);
    }
}

/* Inside one input block, rotor outputs lie in sixteen consecutive byte
 * values. An output addition does not change their circular differences.
 * Any sixteen consecutive steps cross just one input block boundary, even
 * with an unknown origin or direction. A second large jump rejects a guess. */
static int offset_short_steps(const uint8_t outside[256], const uint8_t inverse[256],
                              unsigned h) {
    unsigned previous=inverse[(outside[0]-h)&255];
    for (unsigned block=0;block<16;block++) {
        unsigned jumps=0;
        for (unsigned i=1;i<=16;i++) {
            unsigned next=inverse[(outside[(16*block+i)&255]-h)&255];
            /* Differences -15 through 15 become 0 through 30. */
            if (((next-previous+15)&255)>=31 && ++jumps>1) return 0;
            previous=next;
        }
    }
    return 1;
}

static void offset_last_byte(void) {
    const uint8_t *outside=offset_level[1], *inverse=offset_inverse[1];
    for (unsigned h=0;h<256;h++) {
        if (!offset_short_steps(outside,inverse,h)) continue;
        offset_h[1]=h;
        for (unsigned f=0;f<16;f++) {
            offset_h[0]=f;
            for (unsigned x=0;x<256;x++)
                offset_residual[x]=(uint8_t)(inverse[(outside[x]-h)&255]-f);
            (void)middle_decode(offset_residual,offset_stage,&offset_lane,offset_middle,NULL);
        }
    }
}

static void offset_bytes(unsigned j) {
    if (j==1) { offset_last_byte(); return; }
    for (unsigned h=0;h<256;h++) {
        offset_h[j]=h;
        for (unsigned x=0;x<256;x++)
            offset_level[j-1][x]=offset_inverse[j][(offset_level[j][x]-h)&255];
        offset_bytes(j-1);
    }
}
static void offset_direct(const uint16_t key[2], unsigned shift, void *unused) {
    (void)unused;
    unsigned h[4]={shift,0,0,0}; offset_emit(key,h);
}
static void offset_cycle(const uint16_t walk[4096],
                         void (*emit)(const uint16_t[2],const unsigned[4])) {
    offset_emit=emit;
    if (!offset_depth) { middle_cycle(walk,offset_stage,offset_direct,NULL); return; }
    for (unsigned x=256;x<4096;x++) if ((walk[x]&255)!=(walk[x&255]&255)) return;
    unsigned seen[256]={0};
    for (unsigned x=0;x<256;x++) {
        unsigned value=walk[x]&255;
        if (seen[value]++) return;
        offset_level[offset_depth][x]=(uint8_t)value;
    }
    offset_walk=walk;
    offset_bytes(offset_depth);
}
