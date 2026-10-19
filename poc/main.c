#include "poc/decoder.h"
#include "poc/row_screen.h"
#include "poc/small.h"
#include "poc/support_outer.h"
#include "poc/oracle.h"
#include "poc/bridge.h"
#include "poc/pair.h"
#include "poc/anchors.h"
#include <windows.h>
#include <bcrypt.h>

typedef struct {
    uint16_t iv[8], k8[2], k7[2], shift8;
    unsigned r, bmask;
    uint16_t y[65536];
} Context;
typedef struct { uint16_t word[16]; } Key;
typedef struct { Key *v; size_t n, cap; } KeyList;
typedef struct { Context **v; size_t n, cap; } ContextList;
static uint16_t active_k8[2];

static void outer_found(const uint16_t key[2]);
static void seed_found(const uint16_t key6[2], const uint16_t key7[2]);
static void context_found(Context *context);
static void progress_advance(uint64_t amount);
static void recovered(const uint16_t key[16]);

#include "poc/acquire.c"
#include "poc/recover.c"

static KeyList outer, seeds, *output;
static ContextList contexts;
static uint64_t started, done, total, last_second = UINT64_MAX;
static unsigned from, to;
static const char *stage;
static size_t stage_count;

static void *grow(void *p, size_t *cap, size_t size) {
    *cap = *cap ? 2 * *cap : 16;
    p = realloc(p, *cap * size);
    if (!p) { fputs("Out of memory\n", stderr); exit(8); }
    return p;
}
static int add(KeyList *list, const Key *key) {
    for (size_t i = 0; i < list->n; i++)
        if (!memcmp(&list->v[i], key, sizeof *key)) return 0;
    if (list->n == list->cap) list->v = grow(list->v, &list->cap, sizeof *key);
    list->v[list->n++] = *key;
    return 1;
}
static void show(int force) {
    uint64_t sec = (GetTickCount64() - started) / 1000;
    if (!force && sec == last_second) return;
    last_second = sec;
    unsigned percent = from + (unsigned)((uint64_t)(to - from) * done / (total ? total : 1));
    unsigned filled = percent / 10;
    printf("\r%02llu:%02llu:%02llu <%.*s%2u%%%.*s> [%s] %zu                    ",
           (unsigned long long)(sec / 3600), (unsigned long long)(sec / 60 % 60),
           (unsigned long long)(sec % 60), (int)filled, "==========", percent,
           (int)(10 - filled), "----------", stage, stage_count);
    fflush(stdout);
}
static void phase(const char *name, unsigned begin, unsigned end, uint64_t count, size_t candidates) {
    stage = name; from = begin; to = end; done = 0; total = count; stage_count = candidates;
    show(1);
}
static void progress_advance(uint64_t amount) {
    done += amount;
    show(0);
}
static void outer_found(const uint16_t key[2]) {
    Key k = {{0}};
    memcpy(k.word + 14, key, 4);
    if (add(&outer, &k)) { stage_count = outer.n; show(1); }
}
static void seed_found(const uint16_t key6[2], const uint16_t key7[2]) {
    Key k = {{0}};
    memcpy(k.word + 10, key6, 4);
    memcpy(k.word + 12, key7, 4);
    memcpy(k.word + 14, active_k8, 4);
    if (add(&seeds, &k)) { stage_count = seeds.n; show(1); }
}
static void context_found(Context *context) {
    if (contexts.n == contexts.cap)
        contexts.v = grow(contexts.v, &contexts.cap, sizeof *contexts.v);
    contexts.v[contexts.n++] = context;
}
static void recovered(const uint16_t key[16]) {
    Key k;
    memcpy(k.word, key, sizeof k.word);
    if (add(output, &k)) { stage_count = output->n; show(1); }
}
static void print_key(const uint16_t key[16]) {
    for (unsigned i = 0; i < 16; i++) printf("%04X", key[i]);
    putchar('\n');
}
int main(int argc, char **argv) {
    uint16_t key[16];
    size_t parsed = 0;
    if (argc != 2 || strlen(argv[1]) != 64 ||
        !parse_hex_words(argv[1], key, 16, &parsed) || parsed != 16) {
        fputs("usage: separ_attack KEY64\n", stderr);
        return 2;
    }
    started = GetTickCount64();
    prepare();
    demo_prepare(key);
    Oracle oracle = {demo_reset, demo_first};
    phase("K8 candidates", 0, 15, 132000, 0);
    if (acquire(132000, NULL, oracle)) goto failed;
    show(1);
    if (!outer.n) goto failed;
    phase("K6/K7 candidates", 15, 50, (uint64_t)8000000 * outer.n, 0);
    for (size_t i = 0; i < outer.n; i++) {
        memcpy(active_k8, outer.v[i].word + 14, 4);
        for (unsigned j = 0; j < 4; j++)
            if (acquire(2000000, active_k8, oracle)) goto failed;
    }
    show(1);
    KeyList known = seeds;
    for (unsigned first = 6; first >= 4; first--) {
        KeyList next = {0};
        output = &next;
        phase(first == 6 ? "K5 candidates" : first == 5 ? "K4 candidates" : "K3 candidates",
              first == 6 ? 50 : first == 5 ? 65 : 80,
              first == 6 ? 65 : first == 5 ? 80 : 95, known.n, 0);
        for (size_t i = 0; i < known.n; i++) {
            recover_stage(contexts.v, contexts.n, known.v[i].word, first);
            progress_advance(1);
        }
        show(1);
        free(known.v);
        known = next;
        if (!known.n) goto failed;
    }
    output = NULL;
    KeyList accepted = {0};
    phase("verified keys", 95, 100, known.n, 0);
    for (size_t i = 0; i < known.n; i++) {
        if (verify_contexts(contexts.v, contexts.n, known.v[i].word))
            if (add(&accepted, &known.v[i])) { stage_count = accepted.n; show(1); }
        progress_advance(1);
    }
    show(1);
    putchar('\n');
    for (size_t i = 0; i < accepted.n; i++) print_key(accepted.v[i].word);
    if (!accepted.n) goto failed_after_line;
    for (size_t i = 0; i < contexts.n; i++) free(contexts.v[i]);
    free(contexts.v); free(outer.v); free(known.v); free(accepted.v);
    return 0;
failed:
    putchar('\n');
failed_after_line:
    fputs("No complete key survived the public transcripts\n", stderr);
    return 1;
}
