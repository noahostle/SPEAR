/* One exact partition join for any suffix of one to three known rotors. */
#include "quotient_lift.h"
typedef struct { uint8_t partition[128]; uint16_t parameter; } JointEntry;
static JointEntry joint_right[65536];
static uint16_t joint_q[4][4096];
static uint8_t joint_m[4][256],joint_inverse[4][256],joint_residual[256];
static const uint16_t *joint_walk,*joint_key;
static unsigned joint_h[4],joint_lane,joint_alignment,joint_depth,joint_stage,joint_size;
static void (*joint_emit)(const uint16_t[2],const unsigned[4]);
static void partition_code(const uint8_t f[256],uint8_t out[128]) {
    uint8_t labels[256],names[16];
    memset(names,255,sizeof names); memset(out,0,128);
    for(unsigned x=0;x<256;x++) labels[f[x]]=(uint8_t)(x>>4);
    unsigned next=0;
    for(unsigned x=0;x<256;x++) {
        unsigned b=labels[x];
        if(names[b]==255) names[b]=(uint8_t)next++;
        out[x>>1]|=(uint8_t)(names[b]<<(4*(x&1)));
    }
}
static int joint_order(const void *a,const void *b) {
    return memcmp(((const JointEntry*)a)->partition,((const JointEntry*)b)->partition,128);
}
static void joint_prepare(const uint16_t key[16],unsigned stage,unsigned depth) {
    joint_stage=stage-depth; joint_depth=depth; joint_size=0;
    for(unsigned j=1;j<=depth;j++) for(unsigned x=0;x<4096;x++) {
        joint_q[j][x]=(uint16_t)(ENC_Block((uint16_t)(16*x),key+2*(joint_stage+j-1),(uint8_t)(joint_stage+j))>>4);
        if(x<256) { joint_m[j][x]=(uint8_t)joint_q[j][x]; joint_inverse[j][joint_m[j][x]]=(uint8_t)x; }
    }
    for(unsigned H=0;H<(depth>1?16u:1u);H++)
        for(unsigned h=0;h<(depth>2?256u:1u);h++)
            for(unsigned f=0;f<(depth>1?16u:1u);f++) {
                uint8_t map[256];
                for(unsigned x=0;x<256;x++) {
                    unsigned v=(x+f)&255;
                    for(unsigned j=1;j<depth;j++) { v=joint_m[j][v]; if(j+1<depth) v=(v+h)&255; }
                    map[x]=(uint8_t)(v+16*H);
                }
                partition_code(map,joint_right[joint_size].partition);
                joint_right[joint_size++].parameter=(uint16_t)(h+256*f+4096*H);
            }
    qsort(joint_right,joint_size,sizeof *joint_right,joint_order);
}
static void joint_lifted(const unsigned h[4]) { joint_emit(joint_key,h); }
static void joint_middle(const uint16_t key[2],void *unused) {
    (void)unused;
    uint8_t m[256]; unsigned origin=256;
    for(unsigned x=0;x<256;x++) m[x]=(uint8_t)(ENC_Block((uint16_t)(16*x),key,(uint8_t)joint_stage)>>4);
    for(unsigned x=0;x<256;x++) if(joint_residual[x]==(uint8_t)(m[0]+16*joint_lane)) origin=x;
    if(origin==256) return;
    for(unsigned direction=0;direction<2;direction++) {
        unsigned x=0;
        while(x<256 && joint_residual[(origin+(direction?-x:x))&255]==(uint8_t)(m[x]+16*joint_lane)) x++;
        if(x<256) continue;
        joint_h[0]=(joint_h[0]&15)+16*joint_lane;
        for(unsigned a=0;a<4096;a++) joint_q[0][a]=(uint16_t)(ENC_Block((uint16_t)(16*a),key,(uint8_t)joint_stage)>>4);
        joint_key=key;
        quotient_lift((const uint16_t (*)[4096])joint_q,joint_depth+1,joint_walk,joint_h,
                      (joint_alignment+origin)&255,direction,joint_lifted);
        joint_key=NULL;
    }
}
static void joint_cycle(const uint16_t walk[4096],void (*emit)(const uint16_t[2],const unsigned[4])) {
    for(unsigned x=256;x<4096;x++) if((walk[x]&255)!=(walk[x&255]&255)) return;
    unsigned seen[256]={0},depth=joint_depth;
    for(unsigned x=0;x<256;x++) if(seen[walk[x]&255]++) return;
    joint_walk=walk; joint_emit=emit;
    for(unsigned h=0;h<256;h++) for(unsigned z=0;z<16;z++) for(unsigned r=0;r<16;r++) {
        uint8_t left[256]; JointEntry probe;
        for(unsigned x=0;x<256;x++) left[x]=(uint8_t)(joint_inverse[depth][(walk[(r+x)&255]-h)&255]-z);
        partition_code(left,probe.partition);
        unsigned lo=0,hi=joint_size;
        while(lo<hi) { unsigned mid=lo+(hi-lo)/2; if(joint_order(joint_right+mid,&probe)<0) lo=mid+1; else hi=mid; }
        for(unsigned i=lo;i<joint_size && !joint_order(joint_right+i,&probe);i++) {
            unsigned id=joint_right[i].parameter,H=id>>12,mid=id&255,f=(id>>8)&15;
            for(unsigned x=0;x<256;x++) {
                unsigned v=(left[x]-16*H)&255;
                for(unsigned j=depth;j-->1;) { v=joint_inverse[j][v]; if(j>1) v=(v-mid)&255; }
                joint_residual[x]=(uint8_t)(v-f);
            }
            uint8_t paths[16][16];
            for(unsigned b=0;b<16;b++) for(unsigned c=0;c<16;c++) {
                unsigned y=joint_residual[16*b+c]; paths[y>>4][c]=(uint8_t)(y&15);
            }
            joint_h[depth]=h; joint_h[0]=depth>1?f:z;
            if(depth>1) joint_h[depth-1]=z+16*H;
            if(depth>2) joint_h[1]=mid;
            joint_alignment=r;
            (void)middle_decode(paths,(unsigned)joint_stage,&joint_lane,joint_middle,NULL);
        }
    }
    joint_walk=NULL;
}
