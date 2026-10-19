/* Exact candidate decoder from the sixteen middle-coordinate paths.
 * Paths are indexed by OUTPUT lane; either direction is allowed in each.
 * Uses the literal S-boxes, and the pack/canonical/schedule helpers. */
static Entry middle_cores[65536], middle_lanes[65536];
static uint8_t inverse_s2[16];

static unsigned rcore(unsigned id, unsigned x) {
    return s3[s1[s3[s1[s3[x] ^ (id & 15)] ^ ((id >> 4) & 15)] ^ ((id >> 8) & 15)] ^ (id >> 12)];
}
static unsigned lane_inverse(unsigned id, unsigned y) {
    unsigned j = id & 15, r = (id >> 4) & 15, s = id >> 8;
    return inverse_s2[inverse_s2[inverse_s2[inverse_s2[y ^ r ^ s] ^ j] ^ s] ^ r];
}
static void middle_prepare(void) {
    for (unsigned x = 0; x < 16; x++) inverse_s2[s2[x]] = (uint8_t)x;
    for (unsigned id = 0; id < 65536; id++) {
        uint8_t f[16];
        for (unsigned x = 0; x < 16; x++) f[x] = (uint8_t)rcore(id, x);
        middle_cores[id] = (Entry){canonical(f, NULL), (uint16_t)id};
    }
    for (unsigned id = 0; id < 65536; id++) {
        uint8_t f[16];
        unsigned shift = id >> 12, zero = lane_inverse(id & 4095, (16-shift)&15);
        for (unsigned y = 0; y < 16; y++)
            f[y] = (uint8_t)(lane_inverse(id & 4095, (y-shift)&15) ^ zero);
        middle_lanes[id] = (Entry){pack(f), (uint16_t)id};
    }
    qsort(middle_cores, 65536, sizeof *middle_cores, compare);
    qsort(middle_lanes, 65536, sizeof *middle_lanes, compare);

}
static unsigned middle_decode(uint8_t path[16][16], unsigned stage, unsigned *translation,
                              void (*emit)(const uint16_t[2], void *), void *opaque) {
    unsigned ids[16], v = 0, t = 0, count = 0;
    uint8_t normalized[16];
    for (unsigned y = 0; y < 16; y++) {
        Entry needle = {canonical(path[y], NULL), 0};
        Entry *p = bsearch(&needle, middle_cores, 65536, sizeof *middle_cores, compare);
        if (!p) return 0;
        ids[y] = p->id;
        if (y && (((ids[y] >> 4) & 15) != v || (ids[y] >> 12) != t)) return 0;
        v = (ids[y] >> 4) & 15; t = ids[y] >> 12;
        normalized[y] = (uint8_t)((ids[y] ^ ids[0]) & 15);
    }
    Entry needle = {pack(normalized), 0};
    Entry *found = bsearch(&needle, middle_lanes, 65536, sizeof *middle_lanes, compare);
    if (!found) return 0;
    unsigned shift = found->id >> 12;
    if (!translation && shift) return 0;
    if (translation) *translation = shift;
    unsigned j = found->id & 15, r = (found->id >> 4) & 15, s = (found->id >> 8) & 15;
    unsigned constant = (ids[0] & 15) ^ lane_inverse(found->id & 4095, (16-shift)&15), a3 = 0;
    for (unsigned y = 0; y < 16; y++) {
        unsigned value = ((ids[y] >> 8) & 15) ^ s2[s2[(ids[y] & 15) ^ constant] ^ r];
        if (y && value != a3) return 0;
        a3 = value;
    }
    for (unsigned b1 = 0; b1 < 16; b1++) {
        unsigned beta[4] = {j ^ b1, b1, r, s}, a1 = b1 ^ constant;
        for (unsigned g0 = r >> 2; g0 < 16; g0 += 4) {
            uint16_t raw1 = (uint16_t)((a1 << 12) | (beta[1] << 8) | ((t ^ g0) << 4) |
                                      ((a3 & 3) << 2) | (beta[3] >> 2));
            uint16_t k[4]; schedule(0, raw1, stage, k);
            if ((k[3] >> 12) != a3 || ((k[3] >> 8) & 15) != beta[3]) continue;
            unsigned g3 = (k[3] >> 4) & 15;
            unsigned valid = 1;
            for (unsigned y = 0; y < 16 && valid; y++) {
                unsigned forward = 1, reverse = 1;
                for (unsigned x = 0; x < 16; x++) {
                    unsigned value = rcore(ids[y], x ^ g0) ^ v ^ g3;
                    forward &= value == path[y][x];
                    reverse &= value == path[y][15 - x];
                }
                valid = forward || reverse;
            }
            if (!valid) continue;
            for (unsigned a = 0; a < 4; a++) for (unsigned d = 0; d < 16; d++) {
                uint16_t raw[2] = {(uint16_t)((((v & 3) * 4 + a) << 12) | (beta[0] << 8) | (g0 << 4) | d), raw1};
                schedule(raw[0], raw[1], stage, k);
                if (((k[2] >> 8) & 15) != beta[2] || ((k[2] >> 4) & 15) != v) continue;
                emit(raw, opaque); count++;
            }
        }
    }
    return count;
}
