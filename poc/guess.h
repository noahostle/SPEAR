static uint8_t nibble_table[65536][16];
static uint16_t word_options[2][65536];
static unsigned word_start[2][257];
static uint16_t round_prefix[4096],substitute_prefix[4096],scheduled_prefix[2][65536];

/* The discarded bottom nibble never affects these twelve output bits.
 * Tabulate the two public, unkeyed operations and evaluate the same formula.
 * Rotor-number constants are below 16 and disappear when shifted right by 4. */
static uint16_t prefix_encrypt(unsigned x,const uint16_t k[4]) {
    for(unsigned j=0;j<4;j++) x=round_prefix[x^k[j]];
    return (uint16_t)(substitute_prefix[x^k[0]^k[1]]^k[2]^k[3]);
}
static void prefix_key(const uint16_t raw[2],uint16_t k[4]) {
    k[0]=raw[0]>>4; k[1]=raw[1]>>4;
    k[2]=scheduled_prefix[0][raw[0]]; k[3]=scheduled_prefix[1][raw[1]];
}
/* An index of the first three relative outputs avoids rescanning the same
 * 2^21 tiny guesses. Collisions are kept and all sixteen values are checked. */
static uint32_t nibble_options[65536*32];
static unsigned nibble_start[4097];
static unsigned nibble_bucket(const uint8_t q[16],unsigned origin,unsigned reverse) {
    unsigned code=0;
    for(unsigned i=1;i<=3;i++)
        code|=((q[(origin+(reverse?-i:i))&15]-q[origin])&15)<<(4*(i-1));
    return code;
}

static void schedule(uint16_t a, uint16_t b, unsigned stage, uint16_t k[4]) {
    k[0]=a; k[1]=b;
    k[2]=(uint16_t)ROTL16(a,6); k[3]=(uint16_t)ROTL16(b,10);
    k[2]|=(uint16_t)Separ_sbox1[(k[2]>>6)&15]<<6;
    k[3]|=(uint16_t)Separ_sbox1[(k[3]>>6)&15]<<6;
    k[2]^=(uint16_t)(stage+2); k[3]^=(uint16_t)(stage+3);
}

/* A bucket contains words with specified second nibbles before and after
 * the key schedule. Prefix sums allocate exactly enough room per bucket. */
static unsigned word_bucket(unsigned word, unsigned half) {
    uint16_t k[4]; schedule((uint16_t)word,(uint16_t)word,1,k);
    return ((word>>8)&15) + 16*((k[2+half]>>8)&15);
}
static void prepare(void) {
    for(unsigned x=0;x<4096;x++) {
        uint16_t y=do_sbox((uint16_t)(x<<4));
        substitute_prefix[x]=y>>4;
        round_prefix[x]=Sep_ROTL16(y)>>4;
    }
    for(unsigned id=0;id<65536;id++) {
        uint16_t k[4]; schedule((uint16_t)id,(uint16_t)id,1,k);
        scheduled_prefix[0][id]=k[2]>>4; scheduled_prefix[1][id]=k[3]>>4;
        unsigned b[4]={id&15,(id>>4)&15,(id>>8)&15,id>>12};
        for(unsigned x=0;x<16;x++) {
            unsigned y=x;
            for(unsigned j=0;j<4;j++) y=Separ_sbox2[y^b[j]];
            nibble_table[id][x]=(uint8_t)(Separ_sbox2[y^b[0]^b[1]]^b[2]^b[3]);
        }
    }
    for(unsigned half=0;half<2;half++) {
        unsigned next[256];
        for(unsigned w=0;w<65536;w++) word_start[half][word_bucket(w,half)+1]++;
        for(unsigned g=1;g<=256;g++) word_start[half][g]+=word_start[half][g-1];
        memcpy(next,word_start[half],sizeof next);
        for(unsigned w=0;w<65536;w++) word_options[half][next[word_bucket(w,half)]++]=(uint16_t)w;
    }
    unsigned next[4096];
    for(unsigned trial=0;trial<65536*32;trial++)
        nibble_start[nibble_bucket(nibble_table[trial>>5],(trial>>1)&15,trial&1)+1]++;
    for(unsigned g=1;g<=4096;g++) nibble_start[g]+=nibble_start[g-1];
    memcpy(next,nibble_start,sizeof next);
    for(unsigned trial=0;trial<65536*32;trial++)
        nibble_options[next[nibble_bucket(nibble_table[trial>>5],(trial>>1)&15,trial&1)]++]=trial;
}

/* The observed 256-entry list is a middle-byte cycle, possibly reversed
 * and rotated, after its output low nibble has been subtracted. Find a
 * block boundary: every block must have sixteen equal second nibbles. */
static unsigned middle_decode(const uint8_t observed[256],unsigned stage,unsigned *translation,
                              void (*emit)(const uint16_t[2],void *),void *opaque) {
    (void)stage; /* Its round constant affects only the discarded bottom nibble. */
    unsigned start=0, seen=0, count=0;
    while(start<256 && (observed[start]>>4)==(observed[(start+255)&255]>>4)) start++;
    if(start==256) return 0;
    uint8_t row[16];
    for(unsigned b=0;b<16;b++) {
        row[b]=observed[(start+16*b)&255]>>4;
        if(seen&(1u<<row[b])) return 0;
        seen|=1u<<row[b];
        for(unsigned c=0;c<16;c++)
            if((observed[(start+16*b+c)&255]>>4)!=row[b]) return 0;
    }
    unsigned bucket=nibble_bucket(row,0,0);
    for(unsigned entry=nibble_start[bucket];entry<nibble_start[bucket+1];entry++) {
        unsigned trial=nibble_options[entry],id=trial>>5,origin=(trial>>1)&15,reverse=trial&1;
        const uint8_t *q=nibble_table[id];
        unsigned shift=(row[0]-q[origin])&15, b=1;
        if(!translation && shift) continue;
        for(;b<16;b++)
            if(((q[(origin+(reverse?-b:b))&15]+shift)&15)!=row[b]) break;
        if(b<16) continue;
        unsigned g0=(id&15)+16*((id>>8)&15),g1=((id>>4)&15)+16*(id>>12);
        for(unsigned i=word_start[0][g0];i<word_start[0][g0+1];i++)
        for(unsigned j=word_start[1][g1];j<word_start[1][g1+1];j++) {
            uint16_t key[2]={word_options[0][i],word_options[1][j]};
            uint16_t k[4]; prefix_key(key,k);
            unsigned x=0, input=16*origin+(reverse?15:0);
            for(;x<256;x++) {
                unsigned v=(input+(reverse?-x:x))&255;
                unsigned y=prefix_encrypt(v,k)&255;
                if(((y+16*shift)&255)!=observed[(start+x)&255]) break;
            }
            if(x<256) continue;
            if(translation) *translation=shift;
            emit(key,opaque); count++;
        }
    }
    return count;
}

