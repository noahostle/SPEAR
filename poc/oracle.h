/* Local first-word oracle, evaluated from the literal SEPAR rotor formula. */
#ifndef SEPAR_ORACLE_H
#define SEPAR_ORACLE_H
#include "target.h"
typedef struct {
    void (*reset)(const uint16_t iv[8]);
    uint16_t (*first)(uint16_t plaintext);
} Oracle;
static uint16_t demo_e[8][65536], demo_s[8];
static inline void demo_reset(const uint16_t iv[8]) {
    memcpy(demo_s, iv, 16);
    for (unsigned r = 0; r < 4; r++) {
        uint16_t z = demo_e[0][(uint16_t)(demo_s[0] + demo_s[2] + demo_s[4] + demo_s[6])];
        for (unsigned i = 1; i < 8; i++) {
            demo_s[i] += z;
            z = demo_e[i][demo_s[i]];
        }
        demo_s[0] += z;
    }
}
static inline uint16_t demo_first(uint16_t x) {
    for (unsigned i = 0; i < 8; i++) x = demo_e[i][(uint16_t)(x + demo_s[i])];
    return x;
}
static inline void demo_prepare(const uint16_t key[16]) {
    for (unsigned i = 0; i < 8; i++)
        for (unsigned x = 0; x < 65536; x++)
            demo_e[i][x] = ENC_Block((uint16_t)x, key + 2 * i, (uint8_t)(i + 1));
}
#endif
