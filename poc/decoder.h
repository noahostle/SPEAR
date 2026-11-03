#include "target.h"
#include "guess.h"
#include "middle_cycle.h"

typedef struct {
    uint16_t key[2];
    uint16_t bmask;
} Candidate;
static unsigned neighbor[4096][2];

static inline int dominant_labels(const uint16_t t[65536], unsigned start, unsigned *a, unsigned *b, unsigned mask) {
    unsigned label[16], count[16], n = 0;
    for (unsigned d = 0; d < 16; d++) {
        unsigned v = (t[(uint16_t)(start + d)] >> 4) & mask, k = 0;
        while (k < n && label[k] != v) k++;
        if (k == n) {
            label[n] = v;
            count[n++] = 0;
        }
        count[k]++;
    }
    if (n < 2) return 0;
    unsigned x = 0, y = 1;
    if (count[y] > count[x]) {
        x = 1;
        y = 0;
    }
    for (unsigned k = 2; k < n; k++) {
        if (count[k] > count[x]) {
            y = x;
            x = k;
        } else if (count[k] > count[y])
            y = k;
    }
    if (count[y] <= 16 - count[x] - count[y]) return 0;
    *a = label[x];
    *b = label[y];
    return 1;
}

static inline int dominant_pair(const uint16_t t[65536], unsigned start, unsigned *a, unsigned *b) {
    return dominant_labels(t,start,a,b,4095);
}

/* After removing the low part of s7, an inward event has just one split.
 * Every row has the same two class sizes: 15/1, 14/2, or 13/3. */
static int split_rows(const uint16_t t[65536], unsigned r, unsigned low, unsigned rows) {
    unsigned size=0;
    for(unsigned u=0;u<rows;u++) {
        unsigned start=r+16*u;
        unsigned a=(uint16_t)(t[(uint16_t)start]-low)>>4, b=4096, count=1;
        for(unsigned d=1;d<16;d++) {
            unsigned v=(uint16_t)(t[(uint16_t)(start+d)]-low)>>4;
            if(v==a) count++;
            else if(b==4096) b=v;
            else if(v!=b) return 0;
        }
        unsigned small=count<8?count:16-count;
        if(!small || small>3 || (u && small!=size)) return 0;
        size=small;
    }
    return 1;
}

static inline int graph(const uint16_t t[65536], unsigned r, unsigned nbr[4096][2], unsigned n) {
    unsigned deg[4096] = {0};
    for (unsigned u = 0; u < n; u++) {
        unsigned a, b;
        if (!dominant_labels(t, r + 16 * u, &a, &b, n-1) || deg[a] >= 2 || deg[b] >= 2) return 0;
        nbr[a][deg[a]++] = b;
        nbr[b][deg[b]++] = a;
    }
    for (unsigned u = 0; u < n; u++)
        if (deg[u] != 2) return 0;
    unsigned seen[4096] = {0}, prev = n, cur = 0;
    for (unsigned u = 0; u < n; u++) {
        if (seen[cur]) return 0;
        seen[cur] = 1;
        unsigned next = nbr[cur][0] == prev ? nbr[cur][1] : nbr[cur][0];
        prev = cur;
        cur = next;
    }
    return cur == 0;
}

static inline void cycle_walk(unsigned nbr[4096][2], unsigned direction, uint16_t walk[4096], unsigned n) {
    unsigned previous = n, current = 0;
    for (unsigned i = 0; i < n; i++) {
        walk[i] = (uint16_t)current;
        unsigned next = i ? (nbr[current][0] == previous ? nbr[current][1] : nbr[current][0])
                          : nbr[current][direction];
        previous = current;
        current = next;
    }
}

static inline unsigned row_test(const uint16_t t[65536], unsigned r, Candidate *candidate,
                                unsigned stage, unsigned rows) {
    static uint16_t inverse[65536];
    for (unsigned x = 0; x < 65536; x++)
        inverse[ENC_Block((uint16_t)x, candidate->key, (uint8_t)stage)] = (uint16_t)x;
    unsigned mask = 0xfffe;
    for (unsigned u = 0; u < rows && mask; u++) {
        unsigned a, b;
        if (!dominant_pair(t, r + 16 * u, &a, &b)) return 0;
        a = inverse[a << 4] >> 4;
        b = inverse[b << 4] >> 4;
        unsigned base;
        if (((a + 1) & 4095) == b)
            base = a << 4;
        else if (((b + 1) & 4095) == a)
            base = b << 4;
        else
            return 0;
        unsigned inside[16] = {0};
        for (unsigned d = 0; d < 16; d++) {
            unsigned x = inverse[t[(uint16_t)(r + 16 * u + d)]];
            for (unsigned shift = 1; shift < 16; shift++)
                if ((uint16_t)(x - base - shift) < 16) inside[shift]++;
        }
        for (unsigned shift = 1; shift < 16; shift++)
            if (mask & (1u << shift)) {
                unsigned small = shift < 8 ? shift : 16 - shift, limit = (small - 1) / 2;
                if (limit > ROW_ERRORS) limit = ROW_ERRORS;
                if (16 - inside[shift] > limit) mask &= ~(1u << shift);
            }
    }
    candidate->bmask = (uint16_t)mask;
    return mask != 0;
}
static inline unsigned envelope(const uint16_t t[65536], unsigned r, Candidate *candidate,unsigned stage) {
    return row_test(t,r,candidate,stage,4096);
}
typedef struct {
    uint16_t key[2], shift, bmask;
} ShiftedKey;
typedef struct {
    const uint16_t *y;
    unsigned r,c,stage;
    void (*emit)(const ShiftedKey *,void *);
    void *opaque;
} Peel;
static void peel_candidate(const uint16_t key[2],unsigned qshift,void *opaque) {
    Peel *p=opaque;
    static uint16_t normalized[65536];
    unsigned shift=16*qshift+p->c;
    for(unsigned x=0;x<65536;x++) normalized[x]=(uint16_t)(p->y[x]-shift);
    Candidate raw={{key[0],key[1]},0};
    if(envelope(normalized,p->r,&raw,p->stage)) {
        ShiftedKey result={{key[0],key[1]},(uint16_t)shift,raw.bmask};
        p->emit(&result,p->opaque);
    }
}
static inline void peel(const uint16_t y[65536],unsigned r,unsigned c,unsigned stage,
                 void (*emit)(const ShiftedKey *,void *),void *opaque) {
    static uint16_t shifted[65536];
    uint16_t walk[4096];
    for(unsigned x=0;x<65536;x++) shifted[x]=(uint16_t)(y[x]-c);
    if(!graph(shifted,r,neighbor,4096)) return;
    cycle_walk(neighbor,0,walk,4096);
    Peel p={y,r,c,stage,emit,opaque};
    middle_cycle(walk,stage,peel_candidate,&p);
}
