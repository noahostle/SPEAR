#ifndef SEPAR_ATTACK_TYPES_H
#define SEPAR_ATTACK_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t k0;
    uint16_t k1;
} KeyPair;

typedef struct {
    uint16_t state[8];
    uint16_t lfsr;
} SeparCtx;

typedef struct {
    uint16_t pt;
    uint16_t ct;
    uint16_t s1;
    uint16_t s2;
    uint16_t s3;
    uint16_t s4;
    uint16_t s5;
    uint16_t s6;
    uint16_t s7;
    uint16_t s8;
    uint16_t s6n;
    uint16_t s7n;
    uint16_t s8n;
    uint16_t v12;
    uint16_t v23;
    uint16_t v45;
    uint16_t v56;
    uint16_t v67;
    uint16_t v78;
    uint16_t delta2;
    uint16_t delta4;
} RoundRow;

typedef struct {
    uint16_t *table;
    SeparCtx ctx;
} FullContext;

#endif
