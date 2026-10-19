/* Restore the top-coordinate offsets of a factored middle-byte cycle. */
static uint64_t rotation_signature(const uint8_t f[16]) {
    uint64_t best=UINT64_MAX;
    for(unsigned r=0;r<16;r++) {
        uint64_t value=0;
        for(unsigned x=0;x<16;x++) value|=(uint64_t)((f[(x+r)&15]-f[r])&15)<<(4*x);
        if(value<best) best=value;
    }
    return best;
}
static void quotient_lift(const uint16_t q[4][4096],unsigned n,const uint16_t w[4096],
                          const unsigned h[4],unsigned origin,unsigned reverse,
                          void (*emit)(const unsigned[4])) {
    uint8_t p[4][16],inverse[4][16],carry[4],target[16],right_map[16][16];
    unsigned low=0,cut=(n+1)/2;
    for(unsigned j=0;j<n;j++) {
        for(unsigned a=0;a<16;a++) {
            p[j][a]=(uint8_t)(q[j][256*a+(low&240)]>>8);
            inverse[j][p[j][a]]=(uint8_t)a;
        }
        low=q[j][low]&255;
        carry[j]=(uint8_t)((low+h[j])>>8); low=(low+h[j])&255;
    }
    for(unsigned a=0;a<16;a++) target[a]=(uint8_t)(w[(origin+(reverse?-256*a:256*a))&4095]>>8);
    Entry right[16]; unsigned rn=1u<<(4*(cut-1));
    for(unsigned t=0;t<rn;t++) {
        for(unsigned a=0;a<16;a++) {
            unsigned v=a;
            for(unsigned j=0;j<cut;j++) { v=p[j][v]; if(j+1<cut) v=(v+((t>>(4*j))&15))&15; }
            right_map[t][a]=(uint8_t)v;
        }
        right[t]=(Entry){rotation_signature(right_map[t]),(uint16_t)t};
    }
    qsort(right,rn,sizeof *right,compare);
    for(unsigned t=0;t<(1u<<(4*(n-cut)));t++) {
        uint8_t left[16];
        for(unsigned a=0;a<16;a++) {
            unsigned v=target[a];
            for(unsigned j=n;j-->cut;) v=inverse[j][(v-((t>>(4*(j-cut)))&15))&15];
            left[a]=(uint8_t)v;
        }
        uint64_t signature=rotation_signature(left);
        for(unsigned i=0;i<rn;i++) if(right[i].signature==signature) {
            unsigned r=right[i].id;
            for(unsigned u=0;u<16;u++) {
                unsigned join=(left[0]-right_map[r][u])&15,a=1;
                while(a<16 && left[a]==((right_map[r][(a+u)&15]+join)&15)) a++;
                if(a<16) continue;
                unsigned shifts[4]={0};
                for(unsigned j=0;j<n;j++) {
                    unsigned top=j+1<cut?(r>>(4*j))&15:j+1==cut?join:(t>>(4*(j-cut)))&15;
                    shifts[j]=h[j]+256*((top-carry[j])&15);
                }
                unsigned x=0;
                while(x<4096) {
                    unsigned value=(x+256*u)&4095;
                    for(unsigned j=0;j<n;j++) value=(q[j][value]+shifts[j])&4095;
                    if(value!=w[(origin+(reverse?-x:x))&4095]) break;
                    x++;
                }
                if(x==4096) emit(shifts);
            }
        }
    }
}
