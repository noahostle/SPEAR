static int byte_graph(const uint16_t y[65536],unsigned alignment,unsigned low,
                      unsigned nbr[4096][2]) {
    unsigned degree[256]={0};
    for(unsigned row=0;row<256;row++) {
        unsigned a=256,b=256;
        for(unsigned d=0;d<256;d++) {
            unsigned v=((uint16_t)(y[(uint16_t)(alignment+256*row+d)]-low))>>8;
            if(a==256) a=v;
            else if(v!=a && b==256) b=v;
            else if(v!=a && v!=b) return 0;
        }
        if(b==256 || degree[a]==2 || degree[b]==2) return 0;
        nbr[a][degree[a]++]=b; nbr[b][degree[b]++]=a;
    }
    for(unsigned x=0;x<256;x++) if(degree[x]!=2) return 0;
    unsigned seen[256]={0},previous=256,current=0;
    for(unsigned x=0;x<256;x++) {
        if(seen[current]) return 0;
        seen[current]=1;
        unsigned next=nbr[current][0]==previous?nbr[current][1]:nbr[current][0];
        previous=current; current=next;
    }
    return current==0;
}

/* Guess the isolated second nibble and the two compatible raw key words,
 * just as for a twelve-bit cycle. A predicted output at zero locates the
 * cycle origin; both directions and every output translation are tried. */
static void high_cycle(const uint16_t walk[4096],
                       void (*emit)(const uint16_t[2],unsigned,void *),void *opaque) {
    unsigned position[256],seen[256]={0}; uint8_t row[16];
    for(unsigned x=0;x<256;x++) {
        if(walk[x]>=256 || seen[walk[x]]) return;
        seen[walk[x]]=1; position[walk[x]]=x;
        if((walk[x]&15)!=(walk[x&15]&15)) return;
    }
    for(unsigned x=0;x<16;x++) row[x]=(uint8_t)(walk[x]&15);
    unsigned bucket=nibble_bucket(row,0,0);
    for(unsigned entry=nibble_start[bucket];entry<nibble_start[bucket+1];entry++) {
        unsigned trial=nibble_options[entry],id=trial>>5,origin=(trial>>1)&15,reverse=trial&1;
        const uint8_t *q=nibble_table[id];
        unsigned low=(row[0]-q[origin])&15,b=1;
        for(;b<16;b++)
            if(((q[(origin+(reverse?-b:b))&15]+low)&15)!=row[b]) break;
        if(b<16) continue;
        unsigned g0=(id&15)+16*((id>>8)&15),g1=((id>>4)&15)+16*(id>>12);
        for(unsigned i=word_start[0][g0];i<word_start[0][g0+1];i++)
        for(unsigned j=word_start[1][g1];j<word_start[1][g1+1];j++) {
            uint16_t key[2]={word_options[0][i],word_options[1][j]},k[4];
            prefix_key(key,k);
            unsigned zero=prefix_encrypt(0,k)>>4;
            for(unsigned top=0;top<16;top++) {
                unsigned shift=low+16*top,pos=position[(zero+shift)&255];
                if(((reverse?pos:-pos)&15)!=origin) continue;
                unsigned x=1;
                for(;x<256;x++)
                    if((((prefix_encrypt(x<<4,k)>>4)+shift)&255)!=walk[(pos+(reverse?-x:x))&255]) break;
                if(x==256) emit(key,shift,opaque);
            }
        }
    }
}

typedef struct {
    const uint16_t *z;
    uint16_t first[65536],key2[2],shift3;
    unsigned low3;
    void (*emit)(const uint16_t[4],const uint16_t[3],void *);
    void *opaque;
} OuterTail;
static void tail_first(const ShiftedKey *candidate,void *opaque) {
    OuterTail *t=opaque;
    uint16_t s1=DEC_Block((uint16_t)(t->first[0]-candidate->shift),candidate->key,1);
    for(unsigned p=0;p<65536;p++)
        if((uint16_t)(ENC_Block((uint16_t)(p+s1),candidate->key,1)+candidate->shift)!=t->first[p]) return;
    uint16_t key[4]={candidate->key[0],candidate->key[1],t->key2[0],t->key2[1]};
    uint16_t state[3]={s1,candidate->shift,t->shift3};
    t->emit(key,state,t->opaque);
}
static void tail_second(const uint16_t key[2],unsigned shift,void *opaque) {
    OuterTail *t=opaque;
    static uint16_t inverse[65536];
    memcpy(t->key2,key,4); t->shift3=(uint16_t)(256*shift+t->low3);
    for(unsigned x=0;x<65536;x++) inverse[ENC_Block((uint16_t)x,key,2)]=(uint16_t)x;
    for(unsigned p=0;p<65536;p++) t->first[p]=inverse[(uint16_t)(t->z[p]-t->shift3)];
    /* At least one alignment has a nonzero carry at the first addition. */
    for(unsigned r=0;r<2;r++) peel(t->first,r,0,1,tail_first,t);
}
static void outer_tail(const uint16_t z[65536],unsigned alignment,unsigned low_mask,
                       void (*emit)(const uint16_t[4],const uint16_t[3],void *),void *opaque) {
    OuterTail t={.z=z,.emit=emit,.opaque=opaque};
    uint16_t walk[4096];
    for(unsigned low=0;low<16;low++) if(low_mask&(1u<<low))
    for(unsigned next=0;next<16;next++) {
        t.low3=low+16*next;
        for(unsigned r=alignment;r<256;r+=16) {
            if(!byte_graph(z,r,t.low3,neighbor)) continue;
            cycle_walk(neighbor,0,walk,256);
            high_cycle(walk,tail_second,&t);
        }
    }
}
