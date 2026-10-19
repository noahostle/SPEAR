/* Enumerate every rotor path contained in the observed support graph.
 * Extra edges increase work but cannot remove a true supported path. */
static uint16_t support_edge[16][16];
static uint8_t support_path[16][16];
static const uint16_t *support_table;
static unsigned support_alignment;
static void (*support_emit)(const uint16_t[2]);
static void support_key(const uint16_t key[2],void *unused) {
    (void)unused;
    unsigned mask=0xfffe;
    for(unsigned row=0;row<256 && mask;row++) {
        uint16_t values[16];
        for(unsigned d=0;d<16;d++)
            values[d]=DEC_Block(support_table[support_alignment+16*row+d],key,8);
        for(unsigned b=1;b<16;b++) if(mask&(1u<<b)) {
            unsigned label[16],count[16]={0},n=0,best=0;
            for(unsigned d=0;d<16;d++) {
                unsigned v=(uint16_t)(values[d]-b)>>4,j=0;
                while(j<n && label[j]!=v) j++;
                if(j==n) {label[n]=v; count[n++]=0;}
                if(++count[j]>best) best=count[j];
            }
            if(best<17-(b<16-b?b:16-b)) mask&=~(1u<<b);
        }
    }
    if(mask) support_emit(key);
}
static unsigned support_order[16];
/* One decoded row fixes the common core parameters and its external XORs.
 * Complete each other row by testing the 256 remaining (u,w) pairs. */
static void support_fill(unsigned level,unsigned common,unsigned input,unsigned output,unsigned used) {
    if(level==16) {
        (void)middle_decode(support_path,8,NULL,support_key,NULL);
        return;
    }
    unsigned lane=support_order[level];
    for(unsigned u=0;u<16;u++) if(!(used&(1u<<u))) for(unsigned w=0;w<16;w++) {
        unsigned id=common+u+256*w,previous=rcore(id,input)^output,x=1;
        support_path[lane][0]=(uint8_t)previous;
        for(;x<16;x++) {
            unsigned next=rcore(id,x^input)^output;
            if(!(support_edge[lane][previous]&(1u<<next))) break;
            support_path[lane][x]=(uint8_t)next; previous=next;
        }
        if(x==16) support_fill(level+1,common,input,output,used|(1u<<u));
    }
}
static void support_walk(unsigned lane,unsigned at,unsigned seen,unsigned count) {
    support_path[lane][count-1]=(uint8_t)at;
    if(count==16) {
        if(support_path[lane][0]>=at) return;
        Entry needle={canonical(support_path[lane],NULL),0};
        Entry *match=bsearch(&needle,middle_cores,65536,sizeof *middle_cores,compare);
        if(!match) return;
        unsigned id=match->id;
        for(unsigned a=0;a<16;a++) {
            unsigned b=support_path[lane][0]^rcore(id,a),x=1;
            while(x<16 && support_path[lane][x]==(rcore(id,x^a)^b)) x++;
            if(x==16) support_fill(1,id&0xf0f0,a,b,1u<<(id&15));
        }
        return;
    }
    unsigned choices=support_edge[lane][at]&~seen;
    while(choices) {
        unsigned next=(unsigned)__builtin_ctz(choices);
        choices&=choices-1;
        support_walk(lane,next,seen|(1u<<next),count+1);
    }
}
static void support_outer(const uint16_t table[65536],unsigned alignment,
                          void (*emit)(const uint16_t[2])) {
    memset(support_edge,0,sizeof support_edge);
    for(unsigned row=0;row<256;row++) {
        unsigned label[16],count[16]={0},n=0;
        for(unsigned d=0;d<16;d++) {
            unsigned value=(table[alignment+16*row+d]>>4)&255,j=0;
            while(j<n && label[j]!=value) j++;
            if(j==n) { label[n]=value; count[n++]=0; }
            count[j]++;
        }
        for(unsigned i=0;i<n;i++) for(unsigned j=i+1;j<n;j++)
            if(count[i]+count[j]>=9 && (label[i]>>4)==(label[j]>>4)) {
                unsigned lane=label[i]>>4,a=label[i]&15,b=label[j]&15;
                support_edge[lane][a]|=(uint16_t)(1u<<b);
                support_edge[lane][b]|=(uint16_t)(1u<<a);
            }
    }
    unsigned degree[16]={0};
    for(unsigned lane=0;lane<16;lane++) {
        support_order[lane]=lane;
        for(unsigned v=0;v<16;v++) degree[lane]+=(unsigned)__builtin_popcount(support_edge[lane][v]);
        unsigned seen=1,old=0;
        while(seen!=old) {
            old=seen;
            for(unsigned v=0;v<16;v++) if(seen&(1u<<v)) seen|=support_edge[lane][v];
        }
        if(seen!=65535) return;
    }
    for(unsigned i=0;i<16;i++) for(unsigned j=i+1;j<16;j++)
        if(degree[support_order[j]]<degree[support_order[i]]) {
            unsigned t=support_order[i]; support_order[i]=support_order[j]; support_order[j]=t;
        }
    support_table=table; support_alignment=alignment; support_emit=emit;
    for(unsigned start=0;start<16;start++) support_walk(support_order[0],start,1u<<start,1);
}
