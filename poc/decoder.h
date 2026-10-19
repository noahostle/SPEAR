/* Exact rotor decoding from quotient cycles and complete rows. */
#include "target.h"

typedef struct {
    uint64_t signature;
    uint16_t id;
} Entry;
static Entry lanes[65536], cores[65536];
static uint8_t bad_core[65536];
static const uint8_t *const s1 = Separ_sbox1, *const s2 = Separ_sbox2, *const s3 = Separ_sbox3;

static inline int compare(const void *a, const void *b) {
    uint64_t x = ((const Entry *)a)->signature, y = ((const Entry *)b)->signature;
    return (x > y) - (x < y);
}
static inline uint64_t pack(const uint8_t f[16]) {
    uint64_t result = 0;
    for (unsigned x = 0; x < 16; x++) result |= (uint64_t)f[x] << (4 * x);
    return result;
}
static inline uint64_t canonical(const uint8_t f[16], unsigned *multiplicity) {
    uint64_t best = UINT64_MAX;
    unsigned count = 0;
    for (unsigned a = 0; a < 16; a++) {
        uint64_t result = 0;
        for (unsigned x = 0; x < 16; x++) result |= (uint64_t)(f[x ^ a] ^ f[a]) << (4 * x);
        if (result < best) {
            best = result;
            count = 1;
        } else if (result == best)
            count++;
    }
    if (multiplicity) *multiplicity = count;
    return best;
}
static inline uint8_t core(unsigned id, unsigned x) {
    return s1[s3[s1[s3[s1[x] ^ (id & 15)] ^ ((id >> 4) & 15)] ^ ((id >> 8) & 15)] ^ (id >> 12)];
}
static inline void lane(unsigned id, uint8_t f[16]) {
    unsigned b0 = id & 15, b1 = (id >> 4) & 15, b2 = (id >> 8) & 15, b3 = id >> 12;
    for (unsigned x = 0; x < 16; x++)
        f[x] = s2[s2[s2[s2[s2[x ^ b0] ^ b1] ^ b2] ^ b3] ^ b0 ^ b1] ^ b2 ^ b3;
}
static inline void schedule(uint16_t a, uint16_t b, unsigned stage, uint16_t k[4]) {
    k[0] = a;
    k[1] = b;
    k[2] = ROTL16(a, 6);
    k[3] = ROTL16(b, 10);
    k[2] |= (uint16_t)s1[(k[2] >> 6) & 15] << 6;
    k[3] |= (uint16_t)s1[(k[3] >> 6) & 15] << 6;
    k[2] ^= (uint16_t)(stage + 2);
    k[3] ^= (uint16_t)(stage + 3);
}

#include "middle.h"
#include "middle_cycle.h"

/* Build the two exact lookup indices. Repeated minima and duplicate
 * signatures identify ambiguous P cores; decoding uses another row. */
static inline void prepare(void) {
    middle_prepare();
    for (unsigned id = 0; id < 65536; id++) {
        uint8_t f[16];
        unsigned multiplicity;
        lane(id, f);
        lanes[id] = (Entry){pack(f), (uint16_t)id};
        for (unsigned x = 0; x < 16; x++) f[x] = core(id, x);
        cores[id] = (Entry){canonical(f, &multiplicity), (uint16_t)id};
        bad_core[id] = multiplicity > 1;
    }
    qsort(lanes, 65536, sizeof *lanes, compare);
    qsort(cores, 65536, sizeof *cores, compare);
    for (unsigned i = 1; i < 65536; i++)
        if (cores[i - 1].signature == cores[i].signature)
            bad_core[cores[i - 1].id] = bad_core[cores[i].id] = 1;
}

/* All raw keys sharing the observed high-byte quotient: at most nine.
 * The promise is that q and p are from one rotor. Two rows guarantee that
 * at least one P core is nonexceptional. Full validation is separate. */
static inline unsigned high_candidates(const uint8_t q[16], uint8_t p[2][16], unsigned stage,
                                       uint16_t out[16][2]) {
    Entry needle = {pack(q), 0}, *found = bsearch(&needle, lanes, 65536, sizeof(*lanes), compare);
    if (!found) return 0;
    unsigned nu = found->id, beta[4] = {nu & 15, (nu >> 4) & 15, (nu >> 8) & 15, nu >> 12};
    for (unsigned b = 0; b < 2; b++) {
        needle.signature = canonical(p[b], NULL);
        found = bsearch(&needle, cores, 65536, sizeof(*cores), compare);
        if (!found || bad_core[found->id]) continue;
        unsigned id = found->id, p1 = s2[s2[b ^ beta[0]] ^ beta[1]];
        unsigned p3 = s2[s2[p1 ^ beta[2]] ^ beta[3]];
        for (unsigned a0 = 0; a0 < 16; a0++) {
            unsigned B = p[b][0] ^ core(id, a0), ok = 1;
            for (unsigned x = 0; x < 16; x++)
                if (p[b][x] != (B ^ core(id, x ^ a0))) {
                    ok = 0;
                    break;
                }
            if (!ok) continue;
            unsigned a2 = ((id >> 4) & 15) ^ p1, a1 = (id >> 12) ^ a0 ^ p3, a3 = B ^ a2;
            unsigned g1 = id & 15, g3 = (id >> 8) & 15;
            unsigned g0 = ((a2 & 3) << 2) | (beta[2] >> 2);
            unsigned d1 = ((a3 & 3) << 2) | (beta[3] >> 2), count = 0;
            uint16_t raw1 = (uint16_t)((a1 << 12) | (beta[1] << 8) | (g1 << 4) | d1);
            for (unsigned d0 = 0; d0 < 16; d0++) {
                uint16_t k[4], raw0 = (uint16_t)((a0 << 12) | (beta[0] << 8) | (g0 << 4) | d0);
                schedule(raw0, raw1, stage, k);
                if ((k[2] >> 12) != a2 || (k[3] >> 12) != a3 || ((k[3] >> 4) & 15) != g3) continue;
                for (unsigned j = 0; j < 4; j++)
                    if (((k[j] >> 8) & 15) != beta[j]) ok = 0;
                if (ok) {
                    out[count][0] = raw0;
                    out[count++][1] = raw1;
                }
                ok = 1;
            }
            return count;
        }
    }
    return 0;
}

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
                if (limit > 3) limit = 3;
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
