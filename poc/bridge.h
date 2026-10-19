/* Extend a numerical suffix with the same exact join at every depth. */
#include "joint.h"
typedef struct {
    ShiftedKey inner;
    uint16_t shifts[4];
} RecursiveBridge;
static void (*rb_emit)(const RecursiveBridge *);
static uint16_t rb_inverse[4][65536];
static unsigned rb_depth,rb_stage,rb_alignment,rb_outer_low;
static const uint16_t *rb_y;
static void rb_join_emit(const uint16_t key[2],const unsigned h[4]) {
    static uint16_t normalized[65536];
    RecursiveBridge result={{{key[0],key[1]},(uint16_t)(16*h[0]),0},{0}};
    for(unsigned j=0;j<rb_depth;j++) result.shifts[j]=(uint16_t)(16*h[rb_depth-j]+(j?0:rb_outer_low));
    for(unsigned p=0;p<65536;p++) {
        uint16_t x=rb_y[p];
        for(unsigned j=0;j<rb_depth;j++) x=rb_inverse[j][(uint16_t)(x-result.shifts[j])];
        normalized[p]=(uint16_t)(x-result.inner.shift);
    }
    Candidate candidate={{key[0],key[1]},0};
    if(!envelope(normalized,rb_alignment,&candidate,rb_stage-rb_depth)) return;
    result.inner.bmask=candidate.bmask;
    rb_emit(&result);
}
static void rb_prepare(const uint16_t key[16],unsigned stage,unsigned depth) {
    rb_stage=stage; rb_depth=depth;
    for(unsigned j=0;j<depth;j++) for(unsigned x=0;x<65536;x++)
        rb_inverse[j][x]=DEC_Block((uint16_t)x,key+2*(stage-j-1),(uint8_t)(stage-j));
    joint_prepare(key,stage,depth);
}
static void recursive_bridge(const uint16_t y[65536],unsigned alignment,unsigned low_mask) {
    static uint16_t shifted[65536];
    uint16_t walk[4096];
    rb_y=y; rb_alignment=alignment;
    for(unsigned low=0;low<16;low++) if(low_mask&(1u<<low)) {
        for(unsigned p=0;p<65536;p++) shifted[p]=(uint16_t)(y[p]-low);
        if(!graph(shifted,alignment,neighbor,4096)) continue;
        cycle_walk(neighbor,0,walk,4096); rb_outer_low=low;
        joint_cycle(walk,rb_join_emit);
    }
}
