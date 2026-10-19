/* Screen a translated rotor using only 256 input rows. Every accepted
 * result is checked later on the complete codebook. */
typedef struct {
    const uint16_t *table;
    unsigned r,c,stage,z,lane,found;
    uint16_t edge[256][2];
    int (*accept)(const uint16_t key[2],unsigned shift,unsigned mask);
} Small;
static Small small;
static void small_key(const uint16_t key[2],void *unused) {
    (void)unused;
    if(small.found) return;
    uint8_t inverse_middle[256];
    for(unsigned x=0;x<256;x++)
        inverse_middle[(uint8_t)(ENC_Block((uint16_t)(16*x),key,(uint8_t)small.stage)>>4)]=(uint8_t)x;
    unsigned middle=small.z+16*small.lane;
    for(unsigned top=0;top<(small.stage==8?1u:16u);top++) {
        unsigned qshift=middle+256*top, good=1, crossings=0;
        for(unsigned row=0;row<256;row++) {
            unsigned a=small.edge[row][0],b=small.edge[row][1];
            unsigned ma=inverse_middle[(a-middle)&255],mb=inverse_middle[(b-middle)&255];
            if(ma>>4==mb>>4) continue;
            crossings++;
            unsigned pa=DEC_Block((uint16_t)(((a-qshift)&4095)<<4),key,(uint8_t)small.stage)>>4;
            unsigned pb=DEC_Block((uint16_t)(((b-qshift)&4095)<<4),key,(uint8_t)small.stage)>>4;
            if(((pa+1)&4095)!=pb && ((pb+1)&4095)!=pa) { good=0; break; }
        }
        if(!good || !crossings) continue;
        unsigned shift=16*qshift+small.c;
        static uint16_t normalized[65536];
        for(unsigned x=0;x<4111;x++) normalized[x]=(uint16_t)(small.table[x]-shift);
        Candidate candidate={{key[0],key[1]},0};
        if(!row_test(normalized,small.r,&candidate,small.stage,256)) continue;
        small.found=small.accept(key,shift,candidate.bmask);
        if(small.found) return;
    }
}
static unsigned small_cycle(const uint16_t table[65536],unsigned r,unsigned c,unsigned stage,
                            int (*accept)(const uint16_t[2],unsigned,unsigned)) {
    static uint16_t shifted[65536];
    for(unsigned x=0;x<4111;x++) shifted[x]=(uint16_t)(table[x]-c);
    if(!graph(shifted,r,neighbor,256)) return 0;
    uint16_t walk[4096];
    cycle_walk(neighbor,0,walk,256);
    small=(Small){.table=table,.r=r,.c=c,.stage=stage,.accept=accept};
    for(unsigned row=0;row<256;row++) {
        unsigned a,b;
        if(!dominant_pair(shifted,r+16*row,&a,&b)) return 0;
        small.edge[row][0]=(uint16_t)a; small.edge[row][1]=(uint16_t)b;
    }
    for(unsigned z=0;z<(stage==8?1u:16u) && !small.found;z++) {
        uint8_t paths[16][16];
        if(!middle_paths(walk,z,paths)) continue;
        small.z=z;
        (void)middle_decode(paths,stage,stage==8?NULL:&small.lane,small_key,NULL);
    }
    return small.found;
}
