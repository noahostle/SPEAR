/* Anchored two-rotor base case; every full-table factor is emitted. */
typedef struct {
    uint8_t first[256], second[256], low;
    uint16_t zero;
} Cycle;
typedef struct {
    uint16_t key[2], state;
} Factor;
typedef void (*Emit)(const uint16_t[4], uint16_t);

/* Exact anchored-cycle construction from the earlier recovery manuscript.
 * Returns 0 for the zero-carry case; -1 for an incompatible table. */
static int cycle(const uint16_t table[65536], uint16_t s1, uint16_t anchor, Cycle *g) {
    static unsigned counts[256][256];
    unsigned endpoint[256][2], neighbor[256][2], degree[256] = {0}, single = 0;
    unsigned position[256], seen[256] = {0}, have_anchor = 0;
    memset(counts, 0, sizeof counts);
    for (unsigned x = 0; x < 65536; x++) {
        unsigned y = table[(uint16_t)(x - s1)];
        counts[x >> 8][y >> 8]++;
        if (y == anchor) {
            g->zero = (uint16_t)x;
            have_anchor++;
        }
    }
    if (have_anchor != 1) return -1;
    for (unsigned x = 0; x < 256; x++) {
        unsigned n = 0;
        for (unsigned y = 0; y < 256; y++)
            if (counts[x][y]) {
                if (n == 2) return -1;
                endpoint[x][n++] = y;
            }
        if (n == 1)
            single++;
        else if (n != 2)
            return -1;
    }
    if (single == 256) return 0;
    if (single) return -1;
    for (unsigned x = 0; x < 256; x++)
        for (unsigned j = 0; j < 2; j++) {
            unsigned a = endpoint[x][j], b = endpoint[x][j ^ 1];
            if (degree[a] == 2) return -1;
            neighbor[a][degree[a]++] = b;
        }
    for (unsigned x = 0; x < 256; x++)
        if (degree[x] != 2) return -1;
    unsigned start = anchor >> 8, at = start, previous = 256, row = g->zero >> 8, low = 0;
    if (endpoint[row][0] != start && endpoint[row][1] != start) return -1;
    for (unsigned j = 0; j < 256; j++) {
        if (seen[at]) return -1;
        seen[at] = 1;
        position[at] = j;
        g->second[j] = (uint8_t)at;
        unsigned next = j == 0 ? (endpoint[row][0] == start ? endpoint[row][1] : endpoint[row][0])
                               : (neighbor[at][0] == previous ? neighbor[at][1] : neighbor[at][0]);
        previous = at;
        at = next;
    }
    if (at != start) return -1;
    for (unsigned x = 0; x < 256; x++) {
        unsigned a = endpoint[x][0], b = endpoint[x][1];
        unsigned pred = ((position[a] + 1) & 255) == position[b] ? a : b, succ = pred == a ? b : a;
        if (x == 0) low = counts[x][succ];
        if (counts[x][succ] != low || low == 0 || low >= 256) return -1;
        g->first[x] = (uint8_t)position[pred];
    }
    g->low = (uint8_t)low;
    return 1;
}

/* Complete high-quotient membership test. The raw scan has at most 16 lifts. */
static unsigned decode_high(const uint8_t h[256], unsigned stage, uint16_t raw[16][2]) {
    uint8_t q[16], p[2][16];
    for (unsigned b = 0; b < 16; b++) q[b] = h[b] & 15;
    for (unsigned b = 0; b < 2; b++)
        for (unsigned a = 0; a < 16; a++) p[b][a] = h[16 * a + b] >> 4;
    unsigned n = high_candidates(q, p, stage, raw);
    if (!n) return 0;
    for (unsigned x = 0; x < 256; x++)
        if ((ENC_Block((uint16_t)(x << 8), raw[0], (uint8_t)stage) >> 8) != h[x]) return 0;
    return n;
}

static int factor(const uint16_t table[65536], uint16_t s1, uint16_t anchor, Emit emit) {
    Cycle g;
    Factor f1[16], f2[4096];
    uint16_t raw[16][2];
    unsigned first = 0, second = 0;
    int status = cycle(table, s1, anchor, &g);
    if (status != 1) return status;
    unsigned n = decode_high(g.first, 1, raw);
    for (unsigned i = 0; i < n; i++)
        if (ENC_Block(g.zero, raw[i], 1) == 0) {
            memcpy(f1[first].key, raw[i], sizeof raw[i]);
            first++;
        }
    for (unsigned H = 0; H < 256; H++) {
        uint8_t h[256];
        for (unsigned x = 0; x < 256; x++) h[x] = g.second[(x - H) & 255];
        n = decode_high(h, 2, raw);
        uint16_t state = (uint16_t)((H << 8) | g.low);
        for (unsigned i = 0; i < n; i++)
            if (ENC_Block(state, raw[i], 2) == anchor) {
                memcpy(f2[second].key, raw[i], sizeof raw[i]);
                f2[second++].state = state;
            }
    }

    for (unsigned i = 0; i < first; i++)
        for (unsigned j = 0; j < second; j++) {
            unsigned valid = 1;

            for (unsigned x = 0; x < 65536; x++) {
                uint16_t y = ENC_Block((uint16_t)(x + s1), f1[i].key, 1);
                y = ENC_Block((uint16_t)(y + f2[j].state), f2[j].key, 2);

                if (y != table[x]) {
                    valid = 0;
                    break;
                }
            }
            if (valid) {
                uint16_t key[4] = {f1[i].key[0], f1[i].key[1], f2[j].key[0], f2[j].key[1]};

                emit(key, f2[j].state);
            }
        }
    return 1;
}
