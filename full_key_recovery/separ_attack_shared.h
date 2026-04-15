#ifndef SEPAR_ATTACK_SHARED_H
#define SEPAR_ATTACK_SHARED_H

#include "separ_attack_types.h"

#include <stddef.h>
#include <stdint.h>

void fatal(const char *fmt, ...);
uint64_t now_ms(void);
int pair_equal(KeyPair a, KeyPair b);
int pair_cmp(KeyPair a, KeyPair b);
int parse_hex_words(const char *text, uint16_t *out_words, size_t word_count);
uint64_t splitmix64(uint64_t *state);
uint8_t separ_sbox2(uint8_t x);
void derive_key23(uint16_t k0, uint16_t k1, uint8_t stage, uint16_t *key2, uint16_t *key3);
uint16_t enc_block(uint16_t pt, KeyPair pair, uint8_t stage);
uint16_t dec_block(uint16_t ct, KeyPair pair, uint8_t stage);
KeyPair stage_pair_from_key(const uint16_t key_words[16], uint8_t stage);
void separ_initial_ctx(const uint16_t key_words[16], const uint16_t iv_words[8], SeparCtx *ctx);
uint16_t separ_encrypt_word_record(uint16_t pt, SeparCtx *ctx, const uint16_t key_words[16], RoundRow *row);
uint16_t separ_encrypt_word_simple(uint16_t pt, const SeparCtx *base, const uint16_t key_words[16]);
void ctx_after_prefix(const uint16_t key_words[16], const uint16_t iv_words[8], const uint16_t *prefix_words, size_t prefix_len, SeparCtx *out);
void next_word_table_from_ctx(const SeparCtx *ctx, const uint16_t key_words[16], uint16_t *table);
FullContext build_full_context(const uint16_t key_words[16], const uint16_t iv_words[8], const uint16_t *prefix_words, size_t prefix_len);
void free_full_context(FullContext *ctx);
unsigned detect_workers(void);
void format_iv_hex(const uint16_t iv_words[8], char out[33]);

#endif
