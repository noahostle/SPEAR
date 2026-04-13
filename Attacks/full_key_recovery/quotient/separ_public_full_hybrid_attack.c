#include <inttypes.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define MAX_ROUNDS 256u
#define MAX_TOP 16u

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
    KeyPair pair;
    uint32_t support;
    uint16_t base;
} ConstancyResult;

typedef struct {
    uint16_t *table;
    uint16_t *inv_table;
    SeparCtx ctx;
} FullContext;

typedef struct {
    uint8_t low;
    uint32_t total_support;
} LowScore;

typedef struct {
    uint8_t high;
    uint32_t score;
} HighScore;

typedef struct {
    uint16_t state_word;
    uint32_t exact_score;
    uint8_t next_low;
    uint32_t next_support;
    int32_t next_gap;
} ExactStateCandidate;

typedef struct {
    uint8_t state_low;
    uint8_t state_hi_low;
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;
} Stage1Step1;

typedef struct {
    uint8_t state_low;
    uint8_t state_hi_low;
    KeyPair pair;
} Stage1Step2;

typedef struct {
    KeyPair pair;
    uint32_t fit_count;
    uint32_t slope_count;
    uint32_t base_count;
    uint16_t s1_0;
    uint16_t s4_0;
} AffineResult;

typedef struct {
    AffineResult entries[MAX_TOP];
    size_t count;
} AffineTop;

typedef struct {
    KeyPair pair;
    uint32_t support;
} PairSupport;

typedef struct {
    uint64_t cycle;
    KeyPair pair;
} RepEntry;

typedef struct {
    uint64_t cycle;
    size_t start;
    size_t count;
} RepGroup;

typedef struct {
    uint8_t stage;
    uint8_t canonicalize;
    int ready;
    RepEntry *entries;
    size_t count;
    RepGroup *groups;
    size_t group_count;
} RepTable;

typedef struct {
    KeyPair pair;
    uint8_t tau;
} KeyTauCandidate;

typedef struct {
    uint64_t cycle;
    uint32_t score;
} CycleScore;

typedef struct {
    KeyPair pair;
    uint16_t state_word;
    uint32_t high_score;
    uint8_t next_low;
    uint32_t next_support;
    int32_t next_gap;
    uint32_t support_score;
} PairRecursiveScore;

typedef struct {
    KeyPair pair;
    uint16_t state_word;
    uint32_t verifier_score;
    uint32_t cycle_score;
} OuterStageCandidate;

typedef struct {
    KeyPair pair;
    uint32_t verifier_score;
    uint32_t cycle_score;
} BootstrapCandidate;

typedef struct {
    KeyPair pair;
    uint16_t s4_a;
    uint16_t s4_b;
    uint32_t score_a;
    uint32_t score_b;
    uint8_t next_low_a;
    uint8_t next_low_b;
    uint32_t next_support_a;
    uint32_t next_support_b;
    int32_t next_gap_a;
    int32_t next_gap_b;
    uint32_t support_score;
} K3BridgeScore;

typedef struct {
    const RoundRow *rows;
    size_t rounds;
    const uint16_t *g_prefix;
    KeyPair k4_pair;
    uint64_t start;
    uint64_t end;
    uint64_t seed;
    int full_mode;
    int inject_true;
    int validate;
    KeyPair true_pair;
    AffineResult true_score;
    uint64_t better_than_true;
    AffineTop top;
    atomic_ullong *progress;
} K1Worker;

typedef struct {
    int full_mode;
    int bridge_mode;
    int debug_output;
    int validate;
    int inject_true;
    int has_trace_file;
    unsigned workers;
    uint32_t rounds;
    int k1_demo_pow2;
    int bridge_resume_k4;
    uint32_t bridge_k4_limit;
    uint32_t bridge_k3_limit;
    uint32_t bridge_k2_limit;
    int bridge_resume_k3;
    uint64_t seed;
    uint32_t search_trials;
    uint32_t search_beam;
    uint64_t search_seed;
    uint32_t inward_trials;
    uint16_t key_words[16];
    uint16_t iv_words[8];
    KeyPair forced_k8;
    int has_forced_k8;
    KeyPair k4_pair;
    int k4_supplied;
    char trace_file[MAX_PATH];
    char raw_cycle4[17];
    char raw_cycle2[17];
    char raw_cycle3[17];
} Options;

typedef struct {
    uint16_t iv_words[8];
    uint32_t row_score;
} WeakIVCandidate;

typedef struct {
    KeyPair pair;
    uint64_t aggregate_score;
    uint32_t hits;
} K8AggregateScore;

typedef struct {
    int success;
    uint8_t deepest_stage;
    uint16_t iv_words[8];
    KeyPair pairs[9];
    uint16_t states[9];
    uint16_t s2;
    uint16_t s1;
    size_t stage1_solution_count;
} InwardProbeResult;

static const uint16_t DEFAULT_KEY[16] = {
    0xE8B9, 0xB733, 0xDA5D, 0x96D7, 0x02DD, 0x3972, 0xE953, 0x07FD,
    0x50C5, 0x12DB, 0xF44A, 0x233E, 0x8D1E, 0x9DF5, 0xFC7D, 0x6371,
};

static const uint16_t DEFAULT_IV[8] = {
    0x4703, 0xEAC6, 0x1B44, 0x2157, 0x747A, 0x61DD, 0xA8FD, 0xDDD3,
};
static const uint16_t DEFAULT_DIFFS[] = {0x0001u, 0x0002u, 0x0004u, 0x0008u, 0x000Fu, 0x0010u};
static const uint8_t STAGE8_SAMPLE_POSITIONS[] = {0u, 1u, 2u, 3u, 5u, 8u, 13u, 21u, 34u, 55u, 89u, 144u, 200u, 233u, 255u};

static const char *DEFAULT_RAW_CYCLE2 = "3581F0BDA76942CE";
static const char *DEFAULT_RAW_CYCLE3 = "E0C4136B2F58D9A7";
static const char *DEFAULT_RAW_CYCLE4 = "D0F583692EA741CB";
static const KeyPair DEFAULT_BASE_FAMILY4[] = {
    {0x0910u, 0x0701u}, {0x0913u, 0x0701u}, {0x0910u, 0x3701u}, {0x0913u, 0x3701u},
};
static const KeyPair DEFAULT_BASE_FAMILY3[] = {
    {0x0218u, 0x0902u}, {0x021Cu, 0x0902u}, {0x0218u, 0x3902u}, {0x021Cu, 0x3902u},
};
static const KeyPair DEFAULT_BASE_FAMILY2[] = {
    {0x0A18u, 0x2603u}, {0x0A1Cu, 0x2603u}, {0x0A18u, 0x9603u}, {0x0A1Cu, 0x9603u},
};

static const uint8_t S1[16] = {1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4};
static const uint8_t S2[16] = {6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8};
static const uint8_t S3[16] = {12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13, 15, 4};
static const uint8_t S4[16] = {13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14};

static const uint8_t IS1[16] = {4, 0, 3, 5, 15, 6, 8, 11, 7, 9, 13, 2, 10, 12, 14, 1};
static const uint8_t IS2[16] = {12, 8, 7, 13, 3, 14, 0, 9, 15, 6, 1, 11, 10, 5, 4, 2};
static const uint8_t IS3[16] = {4, 3, 1, 5, 15, 6, 2, 8, 7, 9, 12, 10, 0, 13, 11, 14};
static const uint8_t IS4[16] = {4, 11, 2, 5, 13, 6, 8, 3, 7, 14, 12, 1, 9, 0, 15, 10};

static const uint8_t P_INVISIBLE_BITS_2[] = {0, 1, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23};
static const uint8_t P_INVISIBLE_BITS_3[] = {0, 1, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23};
static const uint8_t P_INVISIBLE_BITS_4[] = {6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23};
static const uint8_t P_INVISIBLE_BITS_5[] = {0, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23};
static const uint8_t P_INVISIBLE_BITS_6[] = {0, 1, 2, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23};
static const uint8_t P_INVISIBLE_BITS_7[] = {0, 1, 2, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23};
static const uint8_t P_INVISIBLE_BITS_8[] = {0, 1, 6, 7, 12, 13, 14, 15, 18, 19, 20, 21, 22, 23, 29};
static const uint8_t OUTER_BOOTSTRAP_ROWS[] = {0x00u, 0x55u, 0xAAu, 0xFFu};

static const KeyPair VALIDATED_K5 = {0x50C5u, 0x12DBu};
static const KeyPair VALIDATED_K6 = {0xF44Au, 0x233Eu};
static const KeyPair VALIDATED_K7 = {0x8D1Eu, 0x9DF5u};
static const KeyPair VALIDATED_K8 = {0xFC7Du, 0x6371u};
static const KeyPair VALIDATED_K4 = {0xE953u, 0x07FDu};
static const KeyPair VALIDATED_K3 = {0x02DDu, 0x3972u};
static const uint16_t PREFIX_B_WORDS[1] = {0x0000u};

static const uint16_t VALIDATED_A_S5 = 0x0211u;
static const uint16_t VALIDATED_A_S6 = 0x8E72u;
static const uint16_t VALIDATED_A_S7 = 0xC29Eu;
static const uint16_t VALIDATED_A_S8 = 0x2B69u;

static const uint16_t VALIDATED_B_S5 = 0x37D5u;
static const uint16_t VALIDATED_B_S6 = 0xFE0Bu;
static const uint16_t VALIDATED_B_S7 = 0xCE5Du;
static const uint16_t VALIDATED_B_S8 = 0x6AE5u;

static const uint16_t VALIDATED_DELTA4 = 0xD864u;
static const uint16_t VALIDATED_DELTA2 = 0xBF3Bu;
static const uint16_t VALIDATED_S4_A = 0xF9F8u;
static const uint16_t VALIDATED_S4_B = 0xD25Cu;

static RepTable g_rep_tables[9][2];
static unsigned g_outer_workers = 1u;
static int g_debug_output = 0;

static uint32_t chosen_iv_row_score_table(const uint16_t *table);
static void weak_iv_candidate_insert(WeakIVCandidate *beam, size_t *beam_count, size_t beam_cap, const uint16_t iv_words[8], uint32_t row_score);
static void format_iv_hex(const uint16_t iv_words[8], char out[33]);
static uint64_t stage8_additive_differential_score(const uint16_t *table, KeyPair pair, const uint16_t *deltas, size_t delta_count);
static int pair_cmp(KeyPair a, KeyPair b);
static size_t run_outer_attack_once(const Options *opt);

typedef struct {
    uint8_t stage;
    int canonicalize;
    uint8_t visible[32];
    size_t visible_count;
    uint64_t start_mask;
    uint64_t end_mask;
    RepEntry *entries;
    atomic_ullong *progress;
} RepBuildWorker;

typedef struct {
    const RepTable *table;
    const uint32_t *flat;
    uint8_t stage;
    uint64_t start_index;
    uint64_t end_index;
    uint32_t best_score;
    uint64_t *cycles;
    size_t count;
    size_t cap;
    atomic_ullong *progress;
} CycleScoreWorker;

typedef struct {
    KeyPair pairs[9];
    uint16_t states_a[9];
    BootstrapCandidate boot;
    int success;
} OuterBranchResult;

typedef struct {
    int compact_enabled;
    int console_output;
    int initialized;
    HANDLE handle;
    COORD top;
    char phase[20];
    char progress[24];
    char depth[8];
    char current_iv[33];
    char best_iv[33];
    char k8[16];
    char k7s8[24];
    char k6s7[24];
    char k5s6[24];
    char k4s5[24];
    char k3s4[24];
    char k2s3[24];
    char k1s2s1[32];
} LiveDisplay;

static LiveDisplay g_live;

static int bit_in_list(uint8_t bit, const uint8_t *list, size_t count);
static void subtract_translation_table(const uint16_t *source, uint16_t translation, uint16_t *dest);
static uint32_t support_collapse_score_after_peel_u16(const uint16_t *source_table, KeyPair pair, uint8_t stage_idx, const uint8_t *rows, size_t row_count);
static uint32_t cycle_edge_score(uint64_t cycle, const uint32_t flat[256]);

static void fatal(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fputc('\n', stderr);
    exit(1);
}

static uint64_t now_ms(void)
{
    return (uint64_t)GetTickCount64();
}

static void plain_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    putchar('\n');
    fflush(stdout);
}

static void ts_printf(const char *fmt, ...)
{
    SYSTEMTIME st;
    va_list args;
    if (!g_debug_output) return;
    GetLocalTime(&st);
    printf("[%04u-%02u-%02u %02u:%02u:%02u] ",
           st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    putchar('\n');
    fflush(stdout);
}

static void display_set_unknown(char *buf, size_t len)
{
    snprintf(buf, len, "----");
}

static void display_format_pair(char *buf, size_t len, KeyPair pair)
{
    snprintf(buf, len, "%04X,%04X", pair.k0, pair.k1);
}

static void display_format_state(char *buf, size_t len, uint16_t word)
{
    snprintf(buf, len, "%04X", word);
}

static void display_reset_values(void)
{
    snprintf(g_live.phase, sizeof(g_live.phase), "-");
    snprintf(g_live.progress, sizeof(g_live.progress), "-");
    snprintf(g_live.depth, sizeof(g_live.depth), "-");
    snprintf(g_live.current_iv, sizeof(g_live.current_iv), "--------------------------------");
    snprintf(g_live.best_iv, sizeof(g_live.best_iv), "--------------------------------");
    display_set_unknown(g_live.k8, sizeof(g_live.k8));
    display_set_unknown(g_live.k7s8, sizeof(g_live.k7s8));
    display_set_unknown(g_live.k6s7, sizeof(g_live.k6s7));
    display_set_unknown(g_live.k5s6, sizeof(g_live.k5s6));
    display_set_unknown(g_live.k4s5, sizeof(g_live.k4s5));
    display_set_unknown(g_live.k3s4, sizeof(g_live.k3s4));
    display_set_unknown(g_live.k2s3, sizeof(g_live.k2s3));
    display_set_unknown(g_live.k1s2s1, sizeof(g_live.k1s2s1));
}

static void display_init(int debug_output)
{
    DWORD mode;
    memset(&g_live, 0, sizeof(g_live));
    g_debug_output = debug_output ? 1 : 0;
    g_live.compact_enabled = g_debug_output ? 0 : 1;
    if (!g_live.compact_enabled) return;
    g_live.handle = GetStdHandle(STD_OUTPUT_HANDLE);
    g_live.console_output = (g_live.handle != INVALID_HANDLE_VALUE && g_live.handle != NULL &&
                             GetConsoleMode(g_live.handle, &mode) != 0);
    display_reset_values();
}

static void display_render(void)
{
    char line1[200];
    char line2[200];
    char line3[200];
    char line4[200];
    char line5[200];
    char line6[200];
    const int width = 170;
    if (!g_live.compact_enabled || !g_live.console_output) return;
    snprintf(line1, sizeof(line1),
             "%-16s | %-17s | %-5s | %-32s | %-32s",
             "phase", "prog", "depth", "current_iv", "best_iv");
    snprintf(line2, sizeof(line2),
             "%-16s | %-17s | %-5s | %-32s | %-32s",
             g_live.phase, g_live.progress, g_live.depth, g_live.current_iv, g_live.best_iv);
    snprintf(line3, sizeof(line3),
             "%-14s | %-22s | %-22s | %-22s",
             "K8", "K7/s8", "K6/s7", "K5/s6");
    snprintf(line4, sizeof(line4),
             "%-14s | %-22s | %-22s | %-22s",
             g_live.k8, g_live.k7s8, g_live.k6s7, g_live.k5s6);
    snprintf(line5, sizeof(line5),
             "%-22s | %-22s | %-22s | %-30s",
             "K4/s5", "K3/s4", "K2/s3", "K1/s2/s1");
    snprintf(line6, sizeof(line6),
             "%-22s | %-22s | %-22s | %-30s",
             g_live.k4s5, g_live.k3s4, g_live.k2s3, g_live.k1s2s1);
    if (!g_live.initialized) {
        CONSOLE_SCREEN_BUFFER_INFO info;
        if (GetConsoleScreenBufferInfo(g_live.handle, &info)) {
            g_live.top = info.dwCursorPosition;
        } else {
            g_live.top.X = 0;
            g_live.top.Y = 0;
        }
        printf("%-*s\n%-*s\n%-*s\n%-*s\n%-*s\n%-*s",
               width, line1, width, line2, width, line3, width, line4, width, line5, width, line6);
        fflush(stdout);
        g_live.initialized = 1;
        return;
    }
    SetConsoleCursorPosition(g_live.handle, g_live.top);
    printf("%-*s\n%-*s\n%-*s\n%-*s\n%-*s\n%-*s",
           width, line1, width, line2, width, line3, width, line4, width, line5, width, line6);
    fflush(stdout);
}

static void display_finish(void)
{
    COORD end;
    if (!g_live.compact_enabled || !g_live.console_output || !g_live.initialized) return;
    end.X = 0;
    end.Y = (SHORT)(g_live.top.Y + 6);
    SetConsoleCursorPosition(g_live.handle, end);
}

static void display_set_phase_progress(const char *phase, uint64_t done, uint64_t total)
{
    if (!g_live.compact_enabled) return;
    snprintf(g_live.phase, sizeof(g_live.phase), "%s", phase);
    if (total == 0u) snprintf(g_live.progress, sizeof(g_live.progress), "-");
    else snprintf(g_live.progress, sizeof(g_live.progress), "%" PRIu64 "/%" PRIu64, done, total);
    display_render();
}

static void display_set_depth(uint8_t depth)
{
    if (!g_live.compact_enabled) return;
    if (depth == 0u || depth > 8u) snprintf(g_live.depth, sizeof(g_live.depth), "-");
    else snprintf(g_live.depth, sizeof(g_live.depth), "%u", (unsigned)depth);
    display_render();
}

static void display_set_k8(KeyPair pair)
{
    if (!g_live.compact_enabled) return;
    display_format_pair(g_live.k8, sizeof(g_live.k8), pair);
    display_render();
}

static void display_clear_suffix_from_stage7(void)
{
    if (!g_live.compact_enabled) return;
    display_set_unknown(g_live.k7s8, sizeof(g_live.k7s8));
    display_set_unknown(g_live.k6s7, sizeof(g_live.k6s7));
    display_set_unknown(g_live.k5s6, sizeof(g_live.k5s6));
    display_set_unknown(g_live.k4s5, sizeof(g_live.k4s5));
    display_set_unknown(g_live.k3s4, sizeof(g_live.k3s4));
    display_set_unknown(g_live.k2s3, sizeof(g_live.k2s3));
    display_set_unknown(g_live.k1s2s1, sizeof(g_live.k1s2s1));
    display_render();
}

static void display_commit_stage(uint8_t stage, KeyPair pair, uint16_t state_word)
{
    if (!g_live.compact_enabled) return;
    if (stage == 7u) {
        snprintf(g_live.k7s8, sizeof(g_live.k7s8), "%04X,%04X/%04X", pair.k0, pair.k1, state_word);
    } else if (stage == 6u) {
        snprintf(g_live.k6s7, sizeof(g_live.k6s7), "%04X,%04X/%04X", pair.k0, pair.k1, state_word);
    } else if (stage == 5u) {
        snprintf(g_live.k5s6, sizeof(g_live.k5s6), "%04X,%04X/%04X", pair.k0, pair.k1, state_word);
    } else if (stage == 4u) {
        snprintf(g_live.k4s5, sizeof(g_live.k4s5), "%04X,%04X/%04X", pair.k0, pair.k1, state_word);
    } else if (stage == 3u) {
        snprintf(g_live.k3s4, sizeof(g_live.k3s4), "%04X,%04X/%04X", pair.k0, pair.k1, state_word);
    } else if (stage == 2u) {
        snprintf(g_live.k2s3, sizeof(g_live.k2s3), "%04X,%04X/%04X", pair.k0, pair.k1, state_word);
    }
    display_render();
}

static void display_apply_outer_summary(KeyPair k8, KeyPair k7, uint16_t s8, KeyPair k6, uint16_t s7, KeyPair k5, uint16_t s6)
{
    if (!g_live.compact_enabled) return;
    display_format_pair(g_live.k8, sizeof(g_live.k8), k8);
    snprintf(g_live.k7s8, sizeof(g_live.k7s8), "%04X,%04X/%04X", k7.k0, k7.k1, s8);
    snprintf(g_live.k6s7, sizeof(g_live.k6s7), "%04X,%04X/%04X", k6.k0, k6.k1, s7);
    snprintf(g_live.k5s6, sizeof(g_live.k5s6), "%04X,%04X/%04X", k5.k0, k5.k1, s6);
    display_render();
}

static void display_set_current_iv_words(const uint16_t iv_words[8])
{
    if (!g_live.compact_enabled) return;
    format_iv_hex(iv_words, g_live.current_iv);
    display_render();
}

static void display_set_best_iv_words(const uint16_t iv_words[8])
{
    if (!g_live.compact_enabled) return;
    format_iv_hex(iv_words, g_live.best_iv);
    display_render();
}

static void display_commit_stage1(KeyPair pair, uint16_t s2, uint16_t s1)
{
    if (!g_live.compact_enabled) return;
    snprintf(g_live.k1s2s1, sizeof(g_live.k1s2s1), "%04X,%04X/%04X/%04X", pair.k0, pair.k1, s2, s1);
    display_render();
}

static void display_mark_done(void)
{
    if (!g_live.compact_enabled) return;
    snprintf(g_live.phase, sizeof(g_live.phase), "done");
    snprintf(g_live.progress, sizeof(g_live.progress), "-");
    display_render();
}

static void compact_milestone_printf(const char *fmt, ...)
{
    va_list args;
    if (!g_live.compact_enabled || g_live.console_output) return;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    putchar('\n');
    fflush(stdout);
}

static void format_seconds(double seconds, char *out, size_t out_len)
{
    uint64_t total = (seconds <= 0.0) ? 0ULL : (uint64_t)(seconds + 0.5);
    uint64_t days = total / 86400ULL;
    uint64_t hours = (total % 86400ULL) / 3600ULL;
    uint64_t mins = (total % 3600ULL) / 60ULL;
    uint64_t secs = total % 60ULL;
    if (days > 0ULL) {
        snprintf(out, out_len, "%" PRIu64 "d %02" PRIu64 "h %02" PRIu64 "m %02" PRIu64 "s", days, hours, mins, secs);
    } else if (hours > 0ULL) {
        snprintf(out, out_len, "%02" PRIu64 "h %02" PRIu64 "m %02" PRIu64 "s", hours, mins, secs);
    } else {
        snprintf(out, out_len, "%02" PRIu64 "m %02" PRIu64 "s", mins, secs);
    }
}

static int pair_equal(KeyPair a, KeyPair b)
{
    return a.k0 == b.k0 && a.k1 == b.k1;
}

static int pair_cmp(KeyPair a, KeyPair b)
{
    if (a.k0 != b.k0) return (a.k0 < b.k0) ? -1 : 1;
    if (a.k1 != b.k1) return (a.k1 < b.k1) ? -1 : 1;
    return 0;
}

static int pair_support_cmp(const void *lhs, const void *rhs)
{
    const PairSupport *a = (const PairSupport *)lhs;
    const PairSupport *b = (const PairSupport *)rhs;
    if (a->support != b->support) return (a->support < b->support) ? -1 : 1;
    return pair_cmp(a->pair, b->pair);
}

static int pair_recursive_cmp(const void *lhs, const void *rhs)
{
    const PairRecursiveScore *a = (const PairRecursiveScore *)lhs;
    const PairRecursiveScore *b = (const PairRecursiveScore *)rhs;
    if (a->high_score != b->high_score) return (a->high_score < b->high_score) ? -1 : 1;
    if (a->next_gap != b->next_gap) return (a->next_gap > b->next_gap) ? -1 : 1;
    if (a->next_support != b->next_support) return (a->next_support < b->next_support) ? -1 : 1;
    return pair_cmp(a->pair, b->pair);
}

static int k3_current_cmp(const void *lhs, const void *rhs)
{
    const K3BridgeScore *a = (const K3BridgeScore *)lhs;
    const K3BridgeScore *b = (const K3BridgeScore *)rhs;
    uint32_t sum_a = a->score_a + a->score_b;
    uint32_t sum_b = b->score_a + b->score_b;
    if (sum_a != sum_b) return (sum_a < sum_b) ? -1 : 1;
    if (a->score_a != b->score_a) return (a->score_a < b->score_a) ? -1 : 1;
    if (a->score_b != b->score_b) return (a->score_b < b->score_b) ? -1 : 1;
    if (a->support_score != b->support_score) return (a->support_score < b->support_score) ? -1 : 1;
    return pair_cmp(a->pair, b->pair);
}

static int k3_final_cmp(const void *lhs, const void *rhs)
{
    const K3BridgeScore *a = (const K3BridgeScore *)lhs;
    const K3BridgeScore *b = (const K3BridgeScore *)rhs;
    uint32_t next_sum_a = a->next_support_a + a->next_support_b;
    uint32_t next_sum_b = b->next_support_a + b->next_support_b;
    int32_t gap_sum_a = a->next_gap_a + a->next_gap_b;
    int32_t gap_sum_b = b->next_gap_a + b->next_gap_b;
    uint32_t score_sum_a = a->score_a + a->score_b;
    uint32_t score_sum_b = b->score_a + b->score_b;
    if (next_sum_a != next_sum_b) return (next_sum_a < next_sum_b) ? -1 : 1;
    if (gap_sum_a != gap_sum_b) return (gap_sum_a > gap_sum_b) ? -1 : 1;
    if (score_sum_a != score_sum_b) return (score_sum_a < score_sum_b) ? -1 : 1;
    if (a->support_score != b->support_score) return (a->support_score < b->support_score) ? -1 : 1;
    return pair_cmp(a->pair, b->pair);
}

static uint16_t rotl16(uint16_t x, unsigned y)
{
    y &= 15u;
    if (y == 0u) return x;
    return (uint16_t)((x << y) | (x >> (16u - y)));
}

static uint16_t rotr16(uint16_t x, unsigned y)
{
    y &= 15u;
    if (y == 0u) return x;
    return (uint16_t)((x >> y) | (x << (16u - y)));
}

static uint16_t do_sbox(uint16_t x)
{
    return (uint16_t)((S1[(x >> 12) & 0xF] << 12) |
                      (S2[(x >> 8) & 0xF] << 8) |
                      (S3[(x >> 4) & 0xF] << 4) |
                      S4[x & 0xF]);
}

static uint16_t do_isbox(uint16_t x)
{
    return (uint16_t)((IS1[(x >> 12) & 0xF] << 12) |
                      (IS2[(x >> 8) & 0xF] << 8) |
                      (IS3[(x >> 4) & 0xF] << 4) |
                      IS4[x & 0xF]);
}

static uint16_t sep_rotl16(uint16_t x)
{
    uint8_t a = (uint8_t)(x >> 12);
    uint8_t b = (uint8_t)((x >> 8) & 0xF);
    uint8_t c = (uint8_t)((x >> 4) & 0xF);
    uint8_t d = (uint8_t)(x & 0xF);
    a ^= c;
    b ^= d;
    c ^= b;
    d ^= a;
    x = (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
    return (uint16_t)(x ^ rotl16(x, 12) ^ rotl16(x, 8));
}

static uint16_t sep_inrotl16(uint16_t x)
{
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;
    x = (uint16_t)(x ^ rotr16(x, 12) ^ rotr16(x, 8));
    a = (uint8_t)(x >> 12);
    b = (uint8_t)((x >> 8) & 0xF);
    c = (uint8_t)((x >> 4) & 0xF);
    d = (uint8_t)(x & 0xF);
    d ^= a;
    c ^= b;
    b ^= d;
    a ^= c;
    return (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
}

static void derive_key23(uint16_t k0, uint16_t k1, uint8_t stage, uint16_t *key2, uint16_t *key3)
{
    uint16_t t2 = rotl16(k0, 6);
    uint16_t t3 = rotl16(k1, 10);
    t2 |= (uint16_t)(S1[(t2 >> 6) & 0xF] << 6);
    t3 |= (uint16_t)(S1[(t3 >> 6) & 0xF] << 6);
    t2 ^= (uint16_t)(stage + 2u);
    t3 ^= (uint16_t)(stage + 3u);
    *key2 = t2;
    *key3 = t3;
}

static uint16_t enc_block(uint16_t pt, KeyPair pair, uint8_t stage)
{
    uint16_t key2;
    uint16_t key3;
    uint16_t t;
    derive_key23(pair.k0, pair.k1, stage, &key2, &key3);
    t = (uint16_t)(pt ^ pair.k0);
    t = do_sbox(t);
    t = sep_rotl16(t);
    t ^= pair.k1;
    t = do_sbox(t);
    t = sep_rotl16(t);
    t ^= key2;
    t = do_sbox(t);
    t = sep_rotl16(t);
    t ^= key3;
    t = do_sbox(t);
    t = sep_rotl16(t);
    t ^= (uint16_t)(pair.k0 ^ pair.k1);
    t = do_sbox(t);
    t ^= (uint16_t)(key2 ^ key3);
    return t;
}

static uint16_t dec_block(uint16_t ct, KeyPair pair, uint8_t stage)
{
    uint16_t key2;
    uint16_t key3;
    uint16_t t;
    derive_key23(pair.k0, pair.k1, stage, &key2, &key3);
    t = (uint16_t)(ct ^ key2 ^ key3);
    t = do_isbox(t);
    t ^= (uint16_t)(pair.k0 ^ pair.k1);
    t = sep_inrotl16(t);
    t = do_isbox(t);
    t ^= key3;
    t = sep_inrotl16(t);
    t = do_isbox(t);
    t ^= key2;
    t = sep_inrotl16(t);
    t = do_isbox(t);
    t ^= pair.k1;
    t = sep_inrotl16(t);
    t = do_isbox(t);
    t ^= pair.k0;
    return t;
}

static int outer_stage_candidate_cmp(const void *lhs, const void *rhs)
{
    const OuterStageCandidate *a = (const OuterStageCandidate *)lhs;
    const OuterStageCandidate *b = (const OuterStageCandidate *)rhs;
    if (a->verifier_score != b->verifier_score) return (a->verifier_score < b->verifier_score) ? -1 : 1;
    if (a->cycle_score != b->cycle_score) return (a->cycle_score > b->cycle_score) ? -1 : 1;
    if (a->state_word != b->state_word) return (a->state_word < b->state_word) ? -1 : 1;
    return pair_cmp(a->pair, b->pair);
}

static int bootstrap_candidate_cmp(const void *lhs, const void *rhs)
{
    const BootstrapCandidate *a = (const BootstrapCandidate *)lhs;
    const BootstrapCandidate *b = (const BootstrapCandidate *)rhs;
    if (a->verifier_score != b->verifier_score) return (a->verifier_score < b->verifier_score) ? -1 : 1;
    if (a->cycle_score != b->cycle_score) return (a->cycle_score > b->cycle_score) ? -1 : 1;
    return pair_cmp(a->pair, b->pair);
}

static int rep_entry_cmp(const void *lhs, const void *rhs)
{
    const RepEntry *a = (const RepEntry *)lhs;
    const RepEntry *b = (const RepEntry *)rhs;
    if (a->cycle != b->cycle) return (a->cycle < b->cycle) ? -1 : 1;
    return pair_cmp(a->pair, b->pair);
}

static const uint8_t *invisible_bits_for_stage(uint8_t stage, size_t *count)
{
    switch (stage) {
    case 2u: *count = sizeof(P_INVISIBLE_BITS_2) / sizeof(P_INVISIBLE_BITS_2[0]); return P_INVISIBLE_BITS_2;
    case 3u: *count = sizeof(P_INVISIBLE_BITS_3) / sizeof(P_INVISIBLE_BITS_3[0]); return P_INVISIBLE_BITS_3;
    case 4u: *count = sizeof(P_INVISIBLE_BITS_4) / sizeof(P_INVISIBLE_BITS_4[0]); return P_INVISIBLE_BITS_4;
    case 5u: *count = sizeof(P_INVISIBLE_BITS_5) / sizeof(P_INVISIBLE_BITS_5[0]); return P_INVISIBLE_BITS_5;
    case 6u: *count = sizeof(P_INVISIBLE_BITS_6) / sizeof(P_INVISIBLE_BITS_6[0]); return P_INVISIBLE_BITS_6;
    case 7u: *count = sizeof(P_INVISIBLE_BITS_7) / sizeof(P_INVISIBLE_BITS_7[0]); return P_INVISIBLE_BITS_7;
    case 8u: *count = sizeof(P_INVISIBLE_BITS_8) / sizeof(P_INVISIBLE_BITS_8[0]); return P_INVISIBLE_BITS_8;
    default: fatal("unsupported stage %u for invisible-bit lookup", (unsigned)stage);
    }
    return NULL;
}

static uint8_t quotient_high_u8(KeyPair pair, uint8_t stage, uint8_t h)
{
    return (uint8_t)((enc_block((uint16_t)(h << 8), pair, stage) >> 8) & 0xFFu);
}

static uint64_t pack_cycle16(const uint8_t cycle[16])
{
    uint64_t packed = 0u;
    for (size_t i = 0u; i < 16u; i++) {
        packed |= ((uint64_t)(cycle[i] & 0xFu)) << (4u * i);
    }
    return packed;
}

static void unpack_cycle16(uint64_t packed, uint8_t cycle[16])
{
    for (size_t i = 0u; i < 16u; i++) {
        cycle[i] = (uint8_t)((packed >> (4u * i)) & 0xFu);
    }
}

static uint8_t cycle_nibble(uint64_t packed, size_t idx)
{
    return (uint8_t)((packed >> (4u * idx)) & 0xFu);
}

static uint64_t rotate_cycle_left_packed(uint64_t packed, uint8_t shift)
{
    uint8_t cycle[16];
    uint8_t rotated[16];
    unpack_cycle16(packed, cycle);
    for (size_t i = 0u; i < 16u; i++) {
        rotated[i] = cycle[(i + shift) & 15u];
    }
    return pack_cycle16(rotated);
}

static uint64_t canonicalize_cycle_packed(uint64_t packed)
{
    uint8_t cycle[16];
    unpack_cycle16(packed, cycle);
    for (size_t i = 0u; i < 16u; i++) {
        if (cycle[i] == 0u) {
            uint8_t rotated[16];
            for (size_t j = 0u; j < 16u; j++) rotated[j] = cycle[(i + j) & 15u];
            return pack_cycle16(rotated);
        }
    }
    return packed;
}

static uint64_t add_cycle_shift_packed(uint64_t packed, uint8_t shift)
{
    uint8_t cycle[16];
    unpack_cycle16(packed, cycle);
    for (size_t i = 0u; i < 16u; i++) cycle[i] = (uint8_t)((cycle[i] + shift) & 0xFu);
    return pack_cycle16(cycle);
}

static uint64_t subtract_cycle_shift_and_canonicalize(uint64_t packed, uint8_t shift)
{
    uint8_t cycle[16];
    unpack_cycle16(packed, cycle);
    for (size_t i = 0u; i < 16u; i++) cycle[i] = (uint8_t)((cycle[i] - shift) & 0xFu);
    return canonicalize_cycle_packed(pack_cycle16(cycle));
}

static const RepGroup *find_rep_group(const RepTable *table, uint64_t cycle)
{
    size_t lo = 0u;
    size_t hi = table->group_count;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) >> 1);
        if (table->groups[mid].cycle < cycle) lo = mid + 1u;
        else hi = mid;
    }
    if (lo < table->group_count && table->groups[lo].cycle == cycle) return &table->groups[lo];
    return NULL;
}

static DWORD WINAPI rep_build_worker_proc(LPVOID param)
{
    RepBuildWorker *worker = (RepBuildWorker *)param;
    uint64_t local_progress = 0u;
    for (uint64_t mask = worker->start_mask; mask < worker->end_mask; mask++) {
        KeyPair pair = {0u, 0u};
        uint8_t cycle[16];
        uint64_t packed;
        for (size_t i = 0u; i < worker->visible_count; i++) {
            if (((mask >> i) & 1ULL) == 0ULL) continue;
            if (worker->visible[i] < 16u) pair.k0 |= (uint16_t)(1u << worker->visible[i]);
            else pair.k1 |= (uint16_t)(1u << (worker->visible[i] - 16u));
        }
        for (uint8_t lo = 0u; lo < 16u; lo++) {
            cycle[lo] = (uint8_t)(quotient_high_u8(pair, worker->stage, lo) & 0xFu);
        }
        packed = pack_cycle16(cycle);
        if (worker->canonicalize) packed = canonicalize_cycle_packed(packed);
        worker->entries[mask].cycle = packed;
        worker->entries[mask].pair = pair;
        local_progress++;
        if ((local_progress & 1023u) == 0u) {
            atomic_fetch_add(worker->progress, local_progress);
            local_progress = 0u;
        }
    }
    if (local_progress != 0u) atomic_fetch_add(worker->progress, local_progress);
    return 0;
}

static void cycle_worker_push(CycleScoreWorker *worker, uint64_t cycle)
{
    if (worker->count == worker->cap) {
        size_t new_cap = (worker->cap == 0u) ? 16u : (worker->cap * 2u);
        uint64_t *grown = (uint64_t *)realloc(worker->cycles, new_cap * sizeof(uint64_t));
        if (grown == NULL) fatal("stage %u cycle-worker allocation failed", (unsigned)worker->stage);
        worker->cycles = grown;
        worker->cap = new_cap;
    }
    worker->cycles[worker->count++] = cycle;
}

static DWORD WINAPI cycle_score_worker_proc(LPVOID param)
{
    CycleScoreWorker *worker = (CycleScoreWorker *)param;
    uint64_t local_progress = 0u;
    worker->best_score = 0u;
    worker->count = 0u;
    for (uint64_t idx = worker->start_index; idx < worker->end_index; idx++) {
        uint64_t cycle;
        uint32_t score;
        if (worker->stage == 8u) {
            cycle = worker->table->groups[idx].cycle;
        } else {
            size_t gi = (size_t)(idx >> 4);
            uint8_t shift = (uint8_t)(idx & 15u);
            cycle = add_cycle_shift_packed(worker->table->groups[gi].cycle, shift);
        }
        score = cycle_edge_score(cycle, worker->flat);
        if (worker->count == 0u || score > worker->best_score) {
            worker->best_score = score;
            worker->count = 0u;
        }
        if (score == worker->best_score) cycle_worker_push(worker, cycle);
        local_progress++;
        if ((local_progress & 1023u) == 0u) {
            atomic_fetch_add(worker->progress, local_progress);
            local_progress = 0u;
        }
    }
    if (local_progress != 0u) atomic_fetch_add(worker->progress, local_progress);
    return 0;
}

static const RepTable *get_rep_table(uint8_t stage, int canonicalize)
{
    RepTable *table = &g_rep_tables[stage][canonicalize ? 1 : 0];
    uint8_t visible[32];
    const uint8_t *invisible;
    size_t invisible_count;
    size_t visible_count = 0u;
    uint64_t total_masks;
    uint64_t start_ms;
    if (table->ready) return table;
    memset(table, 0, sizeof(*table));
    table->stage = stage;
    table->canonicalize = (uint8_t)(canonicalize ? 1 : 0);
    invisible = invisible_bits_for_stage(stage, &invisible_count);
    for (uint8_t bit = 0u; bit < 32u; bit++) {
        if (!bit_in_list(bit, invisible, invisible_count)) {
            visible[visible_count++] = bit;
        }
    }
    total_masks = 1ULL << visible_count;
    table->entries = (RepEntry *)malloc((size_t)total_masks * sizeof(RepEntry));
    if (table->entries == NULL) fatal("stage %u rep-table allocation failed", (unsigned)stage);
    table->count = (size_t)total_masks;
    start_ms = now_ms();
    ts_printf("building stage %u projected representatives (canonical=%d)", (unsigned)stage, canonicalize);
    {
        unsigned workers = g_outer_workers;
        HANDLE *handles;
        RepBuildWorker *worker;
        atomic_ullong progress;
        if (workers == 0u) workers = 1u;
        if ((uint64_t)workers > total_masks) workers = (unsigned)total_masks;
        if (workers == 0u) workers = 1u;
        handles = (HANDLE *)calloc(workers, sizeof(HANDLE));
        worker = (RepBuildWorker *)calloc(workers, sizeof(RepBuildWorker));
        if (handles == NULL || worker == NULL) fatal("stage %u rep-thread allocation failed", (unsigned)stage);
        atomic_init(&progress, 0u);
        {
            uint64_t chunk = total_masks / workers;
            for (unsigned i = 0u; i < workers; i++) {
                uint64_t begin = chunk * i;
                uint64_t end = (i + 1u == workers) ? total_masks : (chunk * (i + 1u));
                worker[i].stage = stage;
                worker[i].canonicalize = canonicalize;
                memcpy(worker[i].visible, visible, visible_count * sizeof(uint8_t));
                worker[i].visible_count = visible_count;
                worker[i].start_mask = begin;
                worker[i].end_mask = end;
                worker[i].entries = table->entries;
                worker[i].progress = &progress;
                handles[i] = CreateThread(NULL, 0, rep_build_worker_proc, &worker[i], 0, NULL);
                if (handles[i] == NULL) fatal("stage %u rep CreateThread failed", (unsigned)stage);
            }
        }
        for (;;) {
            DWORD wait = WaitForMultipleObjects(workers, handles, TRUE, 250u);
            uint64_t done = atomic_load(&progress);
            double elapsed = (double)(now_ms() - start_ms) / 1000.0;
            double pct = (100.0 * (double)done) / (double)total_masks;
            if (g_debug_output) {
                printf("\r[stage%u-reps] %" PRIu64 "/%" PRIu64 " (%5.1f%%) elapsed=%6.1fs",
                       (unsigned)stage, done, total_masks, pct, elapsed);
                fflush(stdout);
            } else {
                char phase[16];
                snprintf(phase, sizeof(phase), "stage%u-reps", (unsigned)stage);
                display_set_phase_progress(phase, done, total_masks);
            }
            if (wait == WAIT_OBJECT_0) break;
            if (wait != WAIT_TIMEOUT) fatal("stage %u rep WaitForMultipleObjects failed", (unsigned)stage);
        }
        WaitForMultipleObjects(workers, handles, TRUE, INFINITE);
        if (g_debug_output) {
            printf("\r[stage%u-reps] %" PRIu64 "/%" PRIu64 " (%5.1f%%) complete%29s\n",
                   (unsigned)stage, (uint64_t)atomic_load(&progress), total_masks, 100.0, "");
        } else {
            char phase[16];
            snprintf(phase, sizeof(phase), "stage%u-reps", (unsigned)stage);
            display_set_phase_progress(phase, total_masks, total_masks);
        }
        for (unsigned i = 0u; i < workers; i++) CloseHandle(handles[i]);
        free(worker);
        free(handles);
    }
    qsort(table->entries, table->count, sizeof(RepEntry), rep_entry_cmp);
    {
        size_t groups = 0u;
        for (size_t i = 0u; i < table->count; ) {
            size_t j = i + 1u;
            while (j < table->count && table->entries[j].cycle == table->entries[i].cycle) j++;
            groups++;
            i = j;
        }
        table->groups = (RepGroup *)malloc(groups * sizeof(RepGroup));
        if (table->groups == NULL) fatal("stage %u rep-group allocation failed", (unsigned)stage);
        table->group_count = groups;
        groups = 0u;
        for (size_t i = 0u; i < table->count; ) {
            size_t j = i + 1u;
            while (j < table->count && table->entries[j].cycle == table->entries[i].cycle) j++;
            table->groups[groups].cycle = table->entries[i].cycle;
            table->groups[groups].start = i;
            table->groups[groups].count = j - i;
            groups++;
            i = j;
        }
    }
    table->ready = 1;
    ts_printf("stage %u projected representatives ready: entries=%zu groups=%zu canonical=%d",
              (unsigned)stage, table->count, table->group_count, canonicalize);
    return table;
}

static void stage8_group_mass_u16(const uint16_t *outputs, const uint16_t *deltas, size_t delta_count, uint32_t flat[256])
{
    memset(flat, 0, 256u * sizeof(uint32_t));
    for (size_t di = 0u; di < delta_count; di++) {
        uint16_t d = deltas[di];
        for (uint32_t pt = 0u; pt < 0x10000u; pt++) {
            uint16_t a = outputs[pt];
            uint16_t b = outputs[(uint16_t)(pt + d)];
            uint8_t ga = (uint8_t)((a >> 8) & 0xFu);
            uint8_t gb = (uint8_t)((b >> 8) & 0xFu);
            flat[(ga << 4) | gb]++;
        }
    }
}

static uint32_t cycle_edge_score(uint64_t cycle, const uint32_t flat[256])
{
    uint32_t score = 0u;
    for (size_t i = 0u; i < 16u; i++) {
        uint8_t a = cycle_nibble(cycle, i);
        uint8_t b = cycle_nibble(cycle, (i + 1u) & 15u);
        score += flat[(a << 4) | b];
    }
    return score;
}

static uint64_t *exact_max_projected_cycles(const uint16_t *outputs,
                                            uint8_t stage,
                                            const uint16_t *deltas,
                                            size_t delta_count,
                                            size_t *out_count,
                                            uint32_t *out_score)
{
    const RepTable *table;
    uint32_t flat[256];
    uint64_t *cycles = NULL;
    size_t count = 0u;
    size_t cap = 0u;
    uint32_t best = 0u;
    uint64_t start_ms = now_ms();
    stage8_group_mass_u16(outputs, deltas, delta_count, flat);
    table = get_rep_table(stage, stage == 8u ? 0 : 1);
    {
        unsigned workers = g_outer_workers;
        HANDLE *handles;
        CycleScoreWorker *worker;
        atomic_ullong progress;
        uint64_t total = (stage == 8u) ? (uint64_t)table->group_count : ((uint64_t)table->group_count * 16ULL);
        if (workers == 0u) workers = 1u;
        if ((uint64_t)workers > total) workers = (unsigned)total;
        if (workers == 0u) workers = 1u;
        handles = (HANDLE *)calloc(workers, sizeof(HANDLE));
        worker = (CycleScoreWorker *)calloc(workers, sizeof(CycleScoreWorker));
        if (handles == NULL || worker == NULL) fatal("stage %u cycle-thread allocation failed", (unsigned)stage);
        atomic_init(&progress, 0u);
        {
            uint64_t chunk = total / workers;
            for (unsigned i = 0u; i < workers; i++) {
                uint64_t begin = chunk * i;
                uint64_t end = (i + 1u == workers) ? total : (chunk * (i + 1u));
                worker[i].table = table;
                worker[i].flat = flat;
                worker[i].stage = stage;
                worker[i].start_index = begin;
                worker[i].end_index = end;
                worker[i].progress = &progress;
                handles[i] = CreateThread(NULL, 0, cycle_score_worker_proc, &worker[i], 0, NULL);
                if (handles[i] == NULL) fatal("stage %u cycle CreateThread failed", (unsigned)stage);
            }
        }
        for (;;) {
            DWORD wait = WaitForMultipleObjects(workers, handles, TRUE, 250u);
            uint64_t done = atomic_load(&progress);
            double elapsed = (double)(now_ms() - start_ms) / 1000.0;
            double pct = (100.0 * (double)done) / (double)total;
            uint32_t running_best = 0u;
            size_t running_ties = 0u;
            for (unsigned i = 0u; i < workers; i++) {
                if (worker[i].count == 0u) continue;
                if (running_ties == 0u || worker[i].best_score > running_best) {
                    running_best = worker[i].best_score;
                    running_ties = worker[i].count;
                } else if (worker[i].best_score == running_best) {
                    running_ties += worker[i].count;
                }
            }
            if (g_debug_output) {
                printf("\r[stage%u-cycles] %" PRIu64 "/%" PRIu64 " (%5.1f%%) elapsed=%6.1fs best=%u ties=%zu",
                       (unsigned)stage, done, total, pct, elapsed, running_best, running_ties);
                fflush(stdout);
            } else {
                char phase[16];
                snprintf(phase, sizeof(phase), "stage%u-cycles", (unsigned)stage);
                display_set_phase_progress(phase, done, total);
            }
            if (wait == WAIT_OBJECT_0) break;
            if (wait != WAIT_TIMEOUT) fatal("stage %u cycle WaitForMultipleObjects failed", (unsigned)stage);
        }
        WaitForMultipleObjects(workers, handles, TRUE, INFINITE);
        for (unsigned i = 0u; i < workers; i++) {
            if (worker[i].count == 0u) continue;
            if (count == 0u || worker[i].best_score > best) {
                best = worker[i].best_score;
                count = 0u;
            }
            if (worker[i].best_score == best) {
                if (count + worker[i].count > cap) {
                    size_t new_cap = cap == 0u ? 16u : cap;
                    while (new_cap < count + worker[i].count) new_cap *= 2u;
                    {
                        uint64_t *grown = (uint64_t *)realloc(cycles, new_cap * sizeof(uint64_t));
                        if (grown == NULL) fatal("stage %u max-cycle allocation failed", (unsigned)stage);
                        cycles = grown;
                    }
                    cap = new_cap;
                }
                memcpy(cycles + count, worker[i].cycles, worker[i].count * sizeof(uint64_t));
                count += worker[i].count;
            }
        }
        if (g_debug_output) {
            printf("\r[stage%u-cycles] %" PRIu64 "/%" PRIu64 " (%5.1f%%) complete best=%u ties=%zu%8s\n",
                   (unsigned)stage, (uint64_t)atomic_load(&progress), total, 100.0, best, count, "");
        } else {
            char phase[16];
            snprintf(phase, sizeof(phase), "stage%u-cycles", (unsigned)stage);
            display_set_phase_progress(phase, total, total);
        }
        for (unsigned i = 0u; i < workers; i++) {
            CloseHandle(handles[i]);
            free(worker[i].cycles);
        }
        free(worker);
        free(handles);
    }
    *out_count = count;
    *out_score = best;
    return cycles;
}

static int hungarian_max_16(const int weights[16][16], uint8_t assignment[16], int *out_score)
{
    int cost[17][17];
    int u[17] = {0};
    int v[17] = {0};
    int p[17] = {0};
    int way[17] = {0};
    int maxw = weights[0][0];
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            if (weights[i][j] > maxw) maxw = weights[i][j];
        }
    }
    for (int i = 1; i <= 16; i++) {
        for (int j = 1; j <= 16; j++) {
            cost[i][j] = maxw - weights[i - 1][j - 1];
        }
    }
    for (int i = 1; i <= 16; i++) {
        int minv[17];
        uint8_t used[17] = {0};
        int j0 = 0;
        p[0] = i;
        for (int j = 1; j <= 16; j++) {
            minv[j] = INT32_MAX / 4;
            way[j] = 0;
        }
        do {
            used[j0] = 1u;
            {
                int i0 = p[j0];
                int delta = INT32_MAX / 4;
                int j1 = 0;
                for (int j = 1; j <= 16; j++) {
                    int cur;
                    if (used[j]) continue;
                    cur = cost[i0][j] - u[i0] - v[j];
                    if (cur < minv[j]) {
                        minv[j] = cur;
                        way[j] = j0;
                    }
                    if (minv[j] < delta) {
                        delta = minv[j];
                        j1 = j;
                    }
                }
                for (int j = 0; j <= 16; j++) {
                    if (used[j]) {
                        u[p[j]] += delta;
                        v[j] -= delta;
                    } else {
                        minv[j] -= delta;
                    }
                }
                j0 = j1;
            }
        } while (p[j0] != 0);
        do {
            int j1 = way[j0];
            p[j0] = p[j1];
            j0 = j1;
        } while (j0 != 0);
    }
    {
        int score = 0;
        for (int j = 1; j <= 16; j++) {
            int i = p[j] - 1;
            assignment[i] = (uint8_t)(j - 1);
            score += weights[i][j - 1];
        }
        if (out_score != NULL) *out_score = score;
    }
    return 1;
}

static int reconstruct_order_from_outputs_u16(const uint16_t *outputs,
                                              uint64_t observed_cycle,
                                              const uint16_t *deltas,
                                              size_t delta_count,
                                              uint8_t order[256])
{
    uint8_t *hi = (uint8_t *)malloc(0x10000u);
    uint32_t *counts = (uint32_t *)calloc(256u * 256u, sizeof(uint32_t));
    uint8_t cycle[16];
    uint8_t paths[16][16];
    uint8_t current[16];
    uint8_t wrap_labels[16];
    int pos[256];
    uint8_t perm[16];
    uint8_t seen[16] = {0};
    uint8_t top_order[16];
    size_t top_len = 0u;
    if (hi == NULL || counts == NULL) fatal("reconstruct-order allocation failed");
    unpack_cycle16(observed_cycle, cycle);
    for (uint32_t pt = 0u; pt < 0x10000u; pt++) hi[pt] = (uint8_t)(outputs[pt] >> 8);
    for (size_t di = 0u; di < delta_count; di++) {
        uint16_t d = deltas[di];
        for (uint32_t pt = 0u; pt < 0x10000u; pt++) {
            counts[((uint32_t)hi[pt] << 8) | hi[(uint16_t)(pt + d)]]++;
        }
    }
    for (uint8_t j = 0u; j < 16u; j++) {
        current[j] = (uint8_t)((j << 4) | cycle[0]);
        paths[0][j] = current[j];
    }
    for (uint8_t step = 0u; step < 15u; step++) {
        uint8_t dest[16];
        int weights[16][16];
        uint8_t assignment[16];
        for (uint8_t j = 0u; j < 16u; j++) dest[j] = (uint8_t)((j << 4) | cycle[step + 1u]);
        for (uint8_t a = 0u; a < 16u; a++) {
            for (uint8_t b = 0u; b < 16u; b++) {
                weights[a][b] = (int)counts[((uint32_t)current[a] << 8) | dest[b]];
            }
        }
        hungarian_max_16(weights, assignment, NULL);
        for (uint8_t a = 0u; a < 16u; a++) {
            current[a] = dest[assignment[a]];
            paths[step + 1u][a] = current[a];
        }
    }
    {
        uint8_t start[16];
        int weights[16][16];
        uint8_t assignment[16];
        for (uint8_t j = 0u; j < 16u; j++) start[j] = paths[0][j];
        for (uint8_t a = 0u; a < 16u; a++) {
            for (uint8_t b = 0u; b < 16u; b++) {
                weights[a][b] = (int)counts[((uint32_t)current[a] << 8) | start[b]];
            }
        }
        hungarian_max_16(weights, assignment, NULL);
        for (uint8_t a = 0u; a < 16u; a++) wrap_labels[a] = start[assignment[a]];
    }
    for (int i = 0; i < 256; i++) pos[i] = -1;
    for (uint8_t i = 0u; i < 16u; i++) pos[paths[0][i]] = i;
    for (uint8_t i = 0u; i < 16u; i++) {
        if (pos[wrap_labels[i]] < 0) {
            free(counts);
            free(hi);
            return 0;
        }
        perm[i] = (uint8_t)pos[wrap_labels[i]];
    }
    {
        uint8_t cur = 0u;
        while (!seen[cur]) {
            seen[cur] = 1u;
            top_order[top_len++] = cur;
            cur = perm[cur];
        }
    }
    for (uint8_t i = 0u; i < 16u; i++) {
        if (!seen[i] || top_len != 16u) {
            free(counts);
            free(hi);
            return 0;
        }
    }
    for (uint8_t top = 0u; top < 16u; top++) {
        for (uint8_t group = 0u; group < 16u; group++) {
            order[top * 16u + group] = paths[group][top_order[top]];
        }
    }
    free(counts);
    free(hi);
    return 1;
}

static void build_rotated_order_targets_stage8_u8(const uint8_t order[256],
                                                  uint8_t full_targets[16][256],
                                                  uint8_t sample_targets[16][sizeof(STAGE8_SAMPLE_POSITIONS) / sizeof(STAGE8_SAMPLE_POSITIONS[0])])
{
    for (uint8_t r = 0u; r < 16u; r++) {
        for (uint16_t h = 0u; h < 256u; h++) {
            uint8_t top = (uint8_t)(h >> 4);
            uint8_t low = (uint8_t)(h & 0xFu);
            full_targets[r][h] = order[(((top + r) & 0xFu) << 4) | low];
        }
        for (size_t i = 0u; i < sizeof(STAGE8_SAMPLE_POSITIONS) / sizeof(STAGE8_SAMPLE_POSITIONS[0]); i++) {
            sample_targets[r][i] = full_targets[r][STAGE8_SAMPLE_POSITIONS[i]];
        }
    }
}

static int sample_target_match(const uint8_t shifted[], const uint8_t target[], size_t count)
{
    for (size_t i = 0u; i < count; i++) {
        if (shifted[i] != target[i]) return 0;
    }
    return 1;
}

static int full_target_match(const uint8_t shifted[], const uint8_t target[])
{
    for (size_t i = 0u; i < 256u; i++) {
        if (shifted[i] != target[i]) return 0;
    }
    return 1;
}

static void append_bootstrap_candidate(BootstrapCandidate **rows, size_t *count, size_t *cap, BootstrapCandidate row)
{
    for (size_t i = 0u; i < *count; i++) {
        if (pair_equal((*rows)[i].pair, row.pair)) {
            if (row.verifier_score < (*rows)[i].verifier_score) (*rows)[i] = row;
            return;
        }
    }
    if (*count == *cap) {
        size_t new_cap = (*cap == 0u) ? 16u : (*cap * 2u);
        BootstrapCandidate *grown = (BootstrapCandidate *)realloc(*rows, new_cap * sizeof(BootstrapCandidate));
        if (grown == NULL) fatal("bootstrap candidate allocation failed");
        *rows = grown;
        *cap = new_cap;
    }
    (*rows)[(*count)++] = row;
}

static void append_outer_candidate(OuterStageCandidate **rows, size_t *count, size_t *cap, OuterStageCandidate row)
{
    for (size_t i = 0u; i < *count; i++) {
        if (pair_equal((*rows)[i].pair, row.pair) && (*rows)[i].state_word == row.state_word) {
            if (row.verifier_score < (*rows)[i].verifier_score) (*rows)[i] = row;
            return;
        }
    }
    if (*count == *cap) {
        size_t new_cap = (*cap == 0u) ? 32u : (*cap * 2u);
        OuterStageCandidate *grown = (OuterStageCandidate *)realloc(*rows, new_cap * sizeof(OuterStageCandidate));
        if (grown == NULL) fatal("outer candidate allocation failed");
        *rows = grown;
        *cap = new_cap;
    }
    (*rows)[(*count)++] = row;
}

static void stage8_exact_candidates_for_cycle(const uint64_t observed_cycle,
                                              const uint8_t order[256],
                                              uint32_t cycle_score,
                                              const uint16_t *table,
                                              BootstrapCandidate **rows,
                                              size_t *count,
                                              size_t *cap)
{
    const RepTable *rep = get_rep_table(8u, 0);
    const RepGroup *group = find_rep_group(rep, observed_cycle);
    const uint8_t *invisible;
    size_t invisible_count;
    uint8_t full_targets[16][256];
    uint8_t sample_targets[16][sizeof(STAGE8_SAMPLE_POSITIONS) / sizeof(STAGE8_SAMPLE_POSITIONS[0])];
    size_t sample_count = sizeof(STAGE8_SAMPLE_POSITIONS) / sizeof(STAGE8_SAMPLE_POSITIONS[0]);
    if (group == NULL) return;
    invisible = invisible_bits_for_stage(8u, &invisible_count);
    build_rotated_order_targets_stage8_u8(order, full_targets, sample_targets);
    for (size_t gi = 0u; gi < group->count; gi++) {
        KeyPair base = rep->entries[group->start + gi].pair;
        size_t mask_count = (size_t)1u << invisible_count;
        for (size_t mask = 0u; mask < mask_count; mask++) {
            KeyPair pair = base;
            uint8_t sample_q[sizeof(STAGE8_SAMPLE_POSITIONS) / sizeof(STAGE8_SAMPLE_POSITIONS[0])];
            uint8_t full_q[256];
            int have_full = 0;
            for (size_t bit = 0u; bit < invisible_count; bit++) {
                if (((mask >> bit) & 1u) == 0u) continue;
                if (invisible[bit] < 16u) pair.k0 |= (uint16_t)(1u << invisible[bit]);
                else pair.k1 |= (uint16_t)(1u << (invisible[bit] - 16u));
            }
            for (size_t i = 0u; i < sample_count; i++) {
                sample_q[i] = quotient_high_u8(pair, 8u, STAGE8_SAMPLE_POSITIONS[i]);
            }
            for (uint8_t tau_hi = 0u; tau_hi < 16u; tau_hi++) {
                uint8_t shifted_sample[sizeof(STAGE8_SAMPLE_POSITIONS) / sizeof(STAGE8_SAMPLE_POSITIONS[0])];
                for (size_t i = 0u; i < sample_count; i++) shifted_sample[i] = (uint8_t)(sample_q[i] + (tau_hi << 4));
                for (uint8_t rot = 0u; rot < 16u; rot++) {
                    if (!sample_target_match(shifted_sample, sample_targets[rot], sample_count)) continue;
                    if (!have_full) {
                        for (uint16_t h = 0u; h < 256u; h++) full_q[h] = quotient_high_u8(pair, 8u, (uint8_t)h);
                        have_full = 1;
                    }
                    {
                        uint8_t shifted_full[256];
                        BootstrapCandidate row;
                        for (uint16_t h = 0u; h < 256u; h++) shifted_full[h] = (uint8_t)(full_q[h] + (tau_hi << 4));
                        if (!full_target_match(shifted_full, full_targets[rot])) continue;
                        row.pair = pair;
                        row.verifier_score = support_collapse_score_after_peel_u16(table, pair, 8u, OUTER_BOOTSTRAP_ROWS, 4u);
                        row.cycle_score = cycle_score;
                        append_bootstrap_candidate(rows, count, cap, row);
                        goto next_mask_stage8;
                    }
                }
            }
next_mask_stage8:
            ;
        }
    }
}

static void translated_exact_candidates_for_cycle(const uint16_t *current_outputs,
                                                  uint8_t stage,
                                                  uint8_t low_byte,
                                                  uint64_t observed_cycle,
                                                  const uint8_t order[256],
                                                  uint32_t cycle_score,
                                                  OuterStageCandidate **rows,
                                                  size_t *count,
                                                  size_t *cap)
{
    const RepTable *rep = get_rep_table(stage, 1);
    const uint8_t *invisible;
    size_t invisible_count;
    uint8_t full_targets[16][256];
    uint8_t sample_targets[16][sizeof(STAGE8_SAMPLE_POSITIONS) / sizeof(STAGE8_SAMPLE_POSITIONS[0])];
    size_t sample_count = sizeof(STAGE8_SAMPLE_POSITIONS) / sizeof(STAGE8_SAMPLE_POSITIONS[0]);
    build_rotated_order_targets_stage8_u8(order, full_targets, sample_targets);
    invisible = invisible_bits_for_stage(stage, &invisible_count);
    for (uint8_t tl = 0u; tl < 16u; tl++) {
        const RepGroup *group = find_rep_group(rep, subtract_cycle_shift_and_canonicalize(observed_cycle, tl));
        if (group == NULL) continue;
        for (size_t gi = 0u; gi < group->count; gi++) {
            KeyPair base = rep->entries[group->start + gi].pair;
            size_t mask_count = (size_t)1u << invisible_count;
            for (size_t mask = 0u; mask < mask_count; mask++) {
                KeyPair pair = base;
                uint8_t sample_q[sizeof(STAGE8_SAMPLE_POSITIONS) / sizeof(STAGE8_SAMPLE_POSITIONS[0])];
                uint8_t full_q[256];
                int have_full = 0;
                for (size_t bit = 0u; bit < invisible_count; bit++) {
                    if (((mask >> bit) & 1u) == 0u) continue;
                    if (invisible[bit] < 16u) pair.k0 |= (uint16_t)(1u << invisible[bit]);
                    else pair.k1 |= (uint16_t)(1u << (invisible[bit] - 16u));
                }
                for (size_t i = 0u; i < sample_count; i++) {
                    sample_q[i] = quotient_high_u8(pair, stage, STAGE8_SAMPLE_POSITIONS[i]);
                }
                for (uint8_t tau_hi = 0u; tau_hi < 16u; tau_hi++) {
                    uint8_t tau = (uint8_t)((tau_hi << 4) | tl);
                    uint8_t shifted_sample[sizeof(STAGE8_SAMPLE_POSITIONS) / sizeof(STAGE8_SAMPLE_POSITIONS[0])];
                    for (size_t i = 0u; i < sample_count; i++) shifted_sample[i] = (uint8_t)(sample_q[i] + tau);
                    for (uint8_t rot = 0u; rot < 16u; rot++) {
                        if (!sample_target_match(shifted_sample, sample_targets[rot], sample_count)) continue;
                        if (!have_full) {
                            for (uint16_t h = 0u; h < 256u; h++) full_q[h] = quotient_high_u8(pair, stage, (uint8_t)h);
                            have_full = 1;
                        }
                        {
                            uint8_t shifted_full[256];
                            OuterStageCandidate row;
                            uint16_t state_word = (uint16_t)(low_byte | (tau << 8));
                            uint16_t *reduced = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
                            if (reduced == NULL) fatal("translated-candidate allocation failed");
                            for (uint16_t h = 0u; h < 256u; h++) shifted_full[h] = (uint8_t)(full_q[h] + tau);
                            if (!full_target_match(shifted_full, full_targets[rot])) {
                                free(reduced);
                                continue;
                            }
                            subtract_translation_table(current_outputs, state_word, reduced);
                            row.pair = pair;
                            row.state_word = state_word;
                            row.verifier_score = support_collapse_score_after_peel_u16(reduced, pair, stage, OUTER_BOOTSTRAP_ROWS, 4u);
                            row.cycle_score = cycle_score;
                            append_outer_candidate(rows, count, cap, row);
                            free(reduced);
                            goto next_mask_translated;
                        }
                    }
                }
next_mask_translated:
                ;
            }
        }
    }
}

static KeyPair stage_pair_from_key(const uint16_t key_words[16], uint8_t stage)
{
    KeyPair pair;
    pair.k0 = key_words[(stage - 1u) * 2u];
    pair.k1 = key_words[(stage - 1u) * 2u + 1u];
    return pair;
}

static uint16_t lfsr_step(uint16_t lfsr)
{
    return (uint16_t)((lfsr >> 1) ^ ((uint16_t)(-(int)(lfsr & 1u)) & 0xCA44u));
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int parse_hex_words(const char *text, uint16_t *out_words, size_t word_count)
{
    const char *p = text;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    if (strlen(p) != word_count * 4u) return -1;
    for (size_t i = 0; i < word_count; i++) {
        int a = hex_value(p[i * 4u + 0u]);
        int b = hex_value(p[i * 4u + 1u]);
        int c = hex_value(p[i * 4u + 2u]);
        int d = hex_value(p[i * 4u + 3u]);
        if (a < 0 || b < 0 || c < 0 || d < 0) return -1;
        out_words[i] = (uint16_t)((a << 12) | (b << 8) | (c << 4) | d);
    }
    return 0;
}

static int parse_key_pair(const char *text, KeyPair *pair)
{
    const char *comma = strchr(text, ',');
    char left[32];
    char right[32];
    uint16_t words[2];
    size_t left_len;
    if (comma == NULL) return -1;
    left_len = (size_t)(comma - text);
    if (left_len == 0u || left_len >= sizeof(left) || strlen(comma + 1) >= sizeof(right)) return -1;
    memcpy(left, text, left_len);
    left[left_len] = '\0';
    strcpy(right, comma + 1);
    if (parse_hex_words(left, &words[0], 1u) != 0) return -1;
    if (parse_hex_words(right, &words[1], 1u) != 0) return -1;
    pair->k0 = words[0];
    pair->k1 = words[1];
    return 0;
}

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void build_plaintexts(uint16_t *pts, size_t count, uint64_t seed)
{
    uint64_t state = seed;
    for (size_t i = 0; i < count; i++) {
        pts[i] = (uint16_t)(splitmix64(&state) & 0xFFFFu);
    }
}

static void separ_initial_ctx(const uint16_t key_words[16], const uint16_t iv_words[8], SeparCtx *ctx)
{
    uint16_t ct = 0u;
    memcpy(ctx->state, iv_words, sizeof(ctx->state));
    for (int i = 0; i < 4; i++) {
        uint16_t v12 = enc_block((uint16_t)(ctx->state[0] + ctx->state[2] + ctx->state[4] + ctx->state[6]), stage_pair_from_key(key_words, 1), 1);
        uint16_t v23 = enc_block((uint16_t)(v12 + ctx->state[1]), stage_pair_from_key(key_words, 2), 2);
        uint16_t v34 = enc_block((uint16_t)(v23 + ctx->state[2]), stage_pair_from_key(key_words, 3), 3);
        uint16_t v45 = enc_block((uint16_t)(v34 + ctx->state[3]), stage_pair_from_key(key_words, 4), 4);
        uint16_t v56 = enc_block((uint16_t)(v45 + ctx->state[4]), stage_pair_from_key(key_words, 5), 5);
        uint16_t v67 = enc_block((uint16_t)(v56 + ctx->state[5]), stage_pair_from_key(key_words, 6), 6);
        uint16_t v78 = enc_block((uint16_t)(v67 + ctx->state[6]), stage_pair_from_key(key_words, 7), 7);
        ct = enc_block((uint16_t)(v78 + ctx->state[7]), stage_pair_from_key(key_words, 8), 8);
        ctx->state[0] = (uint16_t)(ctx->state[0] + ct);
        ctx->state[1] = (uint16_t)(ctx->state[1] + v12);
        ctx->state[2] = (uint16_t)(ctx->state[2] + v23);
        ctx->state[3] = (uint16_t)(ctx->state[3] + v34);
        ctx->state[4] = (uint16_t)(ctx->state[4] + v45);
        ctx->state[5] = (uint16_t)(ctx->state[5] + v56);
        ctx->state[6] = (uint16_t)(ctx->state[6] + v67);
        ctx->state[7] = (uint16_t)(ctx->state[7] + v78);
    }
    ctx->lfsr = (uint16_t)(ct | 0x0100u);
}

static uint16_t separ_encrypt_word_record(uint16_t pt, SeparCtx *ctx, const uint16_t key_words[16], RoundRow *row)
{
    uint16_t before[8];
    uint16_t v12;
    uint16_t v23;
    uint16_t v34;
    uint16_t v45;
    uint16_t v56;
    uint16_t v67;
    uint16_t v78;
    uint16_t ct;
    memcpy(before, ctx->state, sizeof(before));
    v12 = enc_block((uint16_t)(pt + ctx->state[0]), stage_pair_from_key(key_words, 1), 1);
    v23 = enc_block((uint16_t)(v12 + ctx->state[1]), stage_pair_from_key(key_words, 2), 2);
    v34 = enc_block((uint16_t)(v23 + ctx->state[2]), stage_pair_from_key(key_words, 3), 3);
    v45 = enc_block((uint16_t)(v34 + ctx->state[3]), stage_pair_from_key(key_words, 4), 4);
    v56 = enc_block((uint16_t)(v45 + ctx->state[4]), stage_pair_from_key(key_words, 5), 5);
    v67 = enc_block((uint16_t)(v56 + ctx->state[5]), stage_pair_from_key(key_words, 6), 6);
    v78 = enc_block((uint16_t)(v67 + ctx->state[6]), stage_pair_from_key(key_words, 7), 7);
    ct = enc_block((uint16_t)(v78 + ctx->state[7]), stage_pair_from_key(key_words, 8), 8);

    ctx->state[1] = (uint16_t)(ctx->state[1] + v12 + v56 + ctx->state[5]);
    ctx->state[2] = (uint16_t)(ctx->state[2] + v23 + v34 + ctx->state[3] + ctx->state[0]);
    ctx->state[3] = (uint16_t)(ctx->state[3] + v12 + v45 + ctx->state[7]);
    ctx->state[4] = (uint16_t)(ctx->state[4] + v23);
    ctx->state[5] = (uint16_t)(ctx->state[5] + v12 + v45 + ctx->state[6]);
    ctx->state[6] = (uint16_t)(ctx->state[6] + v23 + v67);
    ctx->state[7] = (uint16_t)(ctx->state[7] + v45);
    ctx->state[0] = (uint16_t)(ctx->state[0] + v34 + v23 + ctx->state[4] + v78);
    ctx->lfsr = lfsr_step(ctx->lfsr);
    ctx->state[4] = (uint16_t)(ctx->state[4] + ctx->lfsr);

    row->pt = pt;
    row->ct = ct;
    row->s1 = before[0];
    row->s2 = before[1];
    row->s3 = before[2];
    row->s4 = before[3];
    row->s5 = before[4];
    row->s6 = before[5];
    row->s7 = before[6];
    row->s8 = before[7];
    row->s6n = ctx->state[5];
    row->s7n = ctx->state[6];
    row->s8n = ctx->state[7];
    row->v12 = v12;
    row->v23 = v23;
    row->v45 = v45;
    row->v56 = v56;
    row->v67 = v67;
    row->v78 = v78;
    row->delta2 = (uint16_t)(v12 + v56 + before[5]);
    row->delta4 = (uint16_t)(v12 + ctx->state[7]);
    return ct;
}

static void build_trace(const uint16_t key_words[16], const uint16_t iv_words[8], const uint16_t *pts, size_t rounds, RoundRow *rows)
{
    SeparCtx ctx;
    separ_initial_ctx(key_words, iv_words, &ctx);
    for (size_t i = 0; i < rounds; i++) {
        separ_encrypt_word_record(pts[i], &ctx, key_words, &rows[i]);
    }
}

static uint16_t separ_encrypt_word_simple(uint16_t pt, const SeparCtx *base, const uint16_t key_words[16])
{
    SeparCtx tmp = *base;
    RoundRow row;
    return separ_encrypt_word_record(pt, &tmp, key_words, &row);
}

static void ctx_after_prefix(const uint16_t key_words[16], const uint16_t iv_words[8], const uint16_t *prefix_words, size_t prefix_len, SeparCtx *out)
{
    separ_initial_ctx(key_words, iv_words, out);
    for (size_t i = 0; i < prefix_len; i++) {
        RoundRow row;
        (void)separ_encrypt_word_record(prefix_words[i], out, key_words, &row);
    }
}

static void next_word_table_from_ctx(const SeparCtx *ctx, const uint16_t key_words[16], uint16_t *table)
{
    for (uint32_t pt = 0u; pt < 0x10000u; pt++) {
        table[pt] = separ_encrypt_word_simple((uint16_t)pt, ctx, key_words);
    }
}

static void invert_table_u16(const uint16_t *table, uint16_t *inv)
{
    for (uint32_t x = 0u; x < 0x10000u; x++) {
        inv[table[x]] = (uint16_t)x;
    }
}

static FullContext build_full_context(const uint16_t key_words[16], const uint16_t iv_words[8], const uint16_t *prefix_words, size_t prefix_len)
{
    FullContext out;
    out.table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    out.inv_table = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    if (out.table == NULL || out.inv_table == NULL) fatal("context table allocation failed");
    ctx_after_prefix(key_words, iv_words, prefix_words, prefix_len, &out.ctx);
    next_word_table_from_ctx(&out.ctx, key_words, out.table);
    invert_table_u16(out.table, out.inv_table);
    return out;
}

static void free_full_context(FullContext *ctx)
{
    if (ctx->table != NULL) free(ctx->table);
    if (ctx->inv_table != NULL) free(ctx->inv_table);
    ctx->table = NULL;
    ctx->inv_table = NULL;
}

static void search_weak_ivs(const Options *opt, WeakIVCandidate *beam, size_t *beam_count)
{
    uint64_t rng = opt->search_seed;
    uint64_t start_ms = now_ms();
    *beam_count = 0u;
    for (uint32_t trial = 1u; trial <= opt->search_trials; trial++) {
        uint16_t iv_words[8];
        FullContext ctx;
        uint32_t row_score;
        for (size_t i = 0u; i < 8u; i++) {
            iv_words[i] = (uint16_t)(splitmix64(&rng) & 0xFFFFu);
        }
        ctx = build_full_context(opt->key_words, iv_words, NULL, 0u);
        row_score = chosen_iv_row_score_table(ctx.table);
        weak_iv_candidate_insert(beam, beam_count, opt->search_beam, iv_words, row_score);
        if (!g_debug_output) {
            display_set_phase_progress("k8-search", trial, opt->search_trials);
            display_set_current_iv_words(iv_words);
            if (*beam_count > 0u) display_set_best_iv_words(beam[0].iv_words);
        }
        if ((trial % 8u) == 0u || trial == opt->search_trials) {
            double elapsed = (double)(now_ms() - start_ms) / 1000.0;
            char best_hex[33];
            if (*beam_count > 0u) format_iv_hex(beam[0].iv_words, best_hex);
            else strcpy(best_hex, "--------------------------------");
            if (g_debug_output || !g_live.console_output) {
                printf("\r[iv-search] %u/%u (%5.1f%%) best_row=%u best_iv=%s elapsed=%6.1fs",
                       trial, opt->search_trials,
                       (100.0 * (double)trial) / (double)opt->search_trials,
                       *beam_count > 0u ? beam[0].row_score : 0u,
                       best_hex, elapsed);
                fflush(stdout);
            }
        }
        free_full_context(&ctx);
    }
    if (g_debug_output || !g_live.console_output) putchar('\n');
}

static void subtract_translation_table(const uint16_t *source, uint16_t translation, uint16_t *dest)
{
    for (uint32_t i = 0u; i < 0x10000u; i++) {
        dest[i] = (uint16_t)(source[i] - translation);
    }
}

static void peel_current_forward_stage_table_u16(const uint16_t *source, KeyPair pair, uint8_t stage_idx, uint16_t *dest)
{
    for (uint32_t i = 0u; i < 0x10000u; i++) {
        dest[i] = dec_block(source[i], pair, stage_idx);
    }
}

static int low_score_cmp(const void *lhs, const void *rhs)
{
    const LowScore *a = (const LowScore *)lhs;
    const LowScore *b = (const LowScore *)rhs;
    if (a->total_support != b->total_support) return (a->total_support < b->total_support) ? -1 : 1;
    if (a->low != b->low) return (a->low < b->low) ? -1 : 1;
    return 0;
}

static int high_score_cmp(const void *lhs, const void *rhs)
{
    const HighScore *a = (const HighScore *)lhs;
    const HighScore *b = (const HighScore *)rhs;
    if (a->score != b->score) return (a->score < b->score) ? -1 : 1;
    if (a->high != b->high) return (a->high < b->high) ? -1 : 1;
    return 0;
}

static int exact_state_cmp(const void *lhs, const void *rhs)
{
    const ExactStateCandidate *a = (const ExactStateCandidate *)lhs;
    const ExactStateCandidate *b = (const ExactStateCandidate *)rhs;
    uint32_t sum_a = a->next_support;
    uint32_t sum_b = b->next_support;
    if (sum_a != sum_b) return (sum_a < sum_b) ? -1 : 1;
    if (a->next_gap != b->next_gap) return (a->next_gap > b->next_gap) ? -1 : 1;
    if (a->exact_score != b->exact_score) return (a->exact_score < b->exact_score) ? -1 : 1;
    if (a->state_word != b->state_word) return (a->state_word < b->state_word) ? -1 : 1;
    return 0;
}

static uint32_t row_support_for_low_u16(const uint16_t *peeled_table, uint8_t low_byte)
{
    uint32_t total_support = 0u;
    for (uint32_t row = 0u; row < 256u; row++) {
        uint8_t seen[256] = {0};
        uint32_t count = 0u;
        uint32_t base = row << 8;
        for (uint32_t lo = 0u; lo < 256u; lo++) {
            uint8_t upper = (uint8_t)(((uint16_t)(peeled_table[base | lo] - low_byte)) >> 8);
            if (!seen[upper]) {
                seen[upper] = 1u;
                count++;
            }
        }
        total_support += count;
    }
    return total_support;
}

static void exact_low_byte_scan_u16(const uint16_t *peeled_table, LowScore scores[256])
{
    for (uint32_t low = 0u; low < 256u; low++) {
        scores[low].low = (uint8_t)low;
        scores[low].total_support = row_support_for_low_u16(peeled_table, (uint8_t)low);
    }
    qsort(scores, 256u, sizeof(LowScore), low_score_cmp);
}

static uint8_t best_low_byte_u16(const uint16_t *peeled_table, uint32_t *best_support, uint32_t *second_support)
{
    LowScore scores[256];
    exact_low_byte_scan_u16(peeled_table, scores);
    if (best_support != NULL) *best_support = scores[0].total_support;
    if (second_support != NULL) *second_support = scores[1].total_support;
    return scores[0].low;
}

static void rank_high_support_candidates_u16(const uint16_t *source_table, KeyPair next_pair, uint8_t stage_idx, uint32_t row_step, HighScore scores[256])
{
    uint16_t row_values[256];
    uint16_t seen[256];
    for (uint32_t high = 0u; high < 256u; high++) {
        uint32_t total_support = 0u;
        uint16_t high_translation = (uint16_t)(high << 8);
        memset(seen, 0, sizeof(seen));
        for (uint32_t row = 0u; row < 256u; row += row_step) {
            uint32_t base = row << 8;
            uint32_t best_support = 0x101u;
            for (uint32_t lo = 0u; lo < 256u; lo++) {
                row_values[lo] = dec_block((uint16_t)(source_table[base | lo] - high_translation), next_pair, stage_idx);
            }
            for (uint32_t low = 0u; low < 256u; low++) {
                uint16_t mark = (uint16_t)(low + 1u);
                uint32_t count = 0u;
                for (uint32_t lo = 0u; lo < 256u; lo++) {
                    uint8_t upper = (uint8_t)(((uint16_t)(row_values[lo] - low)) >> 8);
                    if (seen[upper] != mark) {
                        seen[upper] = mark;
                        count++;
                        if (count >= best_support) break;
                    }
                }
                if (count < best_support) {
                    best_support = count;
                    if (best_support == 1u) break;
                }
            }
            total_support += best_support;
        }
        scores[high].high = (uint8_t)high;
        scores[high].score = total_support;
    }
    qsort(scores, 256u, sizeof(HighScore), high_score_cmp);
}

static uint32_t row_best_support_after_peel_u16(const uint16_t *source_table, KeyPair pair, uint8_t stage_idx, uint8_t row, uint8_t *best_low)
{
    uint16_t peeled[256];
    uint32_t base = ((uint32_t)row) << 8;
    uint32_t best_support = 0x100u;
    uint8_t best = 0u;
    for (uint32_t lo = 0u; lo < 256u; lo++) {
        peeled[lo] = dec_block(source_table[base | lo], pair, stage_idx);
    }
    for (uint32_t low = 0u; low < 256u; low++) {
        uint8_t seen[256] = {0};
        uint32_t support = 0u;
        for (uint32_t lo = 0u; lo < 256u; lo++) {
            uint8_t upper = (uint8_t)(((uint16_t)(peeled[lo] - low)) >> 8);
            if (!seen[upper]) {
                seen[upper] = 1u;
                support++;
                if (support >= best_support) break;
            }
        }
        if (support < best_support || (support == best_support && low < best)) {
            best_support = support;
            best = (uint8_t)low;
        }
    }
    if (best_low != NULL) *best_low = best;
    return best_support;
}

static uint32_t support_collapse_score_after_peel_u16(const uint16_t *source_table, KeyPair pair, uint8_t stage_idx, const uint8_t *rows, size_t row_count)
{
    uint32_t total = 0u;
    for (size_t i = 0; i < row_count; i++) {
        total += row_best_support_after_peel_u16(source_table, pair, stage_idx, rows[i], NULL);
    }
    return total;
}

static BootstrapCandidate *run_stage8_bootstrap_exact(const FullContext *ctx_a,
                                                      int validate,
                                                      KeyPair true_pair,
                                                      size_t *out_count,
                                                      size_t *out_true_rank)
{
    uint64_t *cycles;
    size_t cycle_count = 0u;
    uint32_t cycle_score = 0u;
    BootstrapCandidate *rows = NULL;
    size_t row_count = 0u;
    size_t row_cap = 0u;
    size_t true_rank = 0u;
    cycles = exact_max_projected_cycles(ctx_a->table, 8u, DEFAULT_DIFFS, sizeof(DEFAULT_DIFFS) / sizeof(DEFAULT_DIFFS[0]), &cycle_count, &cycle_score);
    ts_printf("stage 8 exact cycle maxima: score=%u count=%zu", cycle_score, cycle_count);
    {
        uint64_t total = (uint64_t)cycle_count * 16ULL;
        uint64_t index = 0u;
        for (size_t i = 0u; i < cycle_count; i++) {
            for (uint8_t rot = 0u; rot < 16u; rot++) {
                uint8_t order[256];
                uint64_t rotated = rotate_cycle_left_packed(cycles[i], rot);
                index++;
                if ((index % 16u) == 0u || index == total) {
                    double pct = (100.0 * (double)index) / (double)total;
                    if (g_debug_output) {
                        printf("\r[stage8-rot] %" PRIu64 "/%" PRIu64 " (%5.1f%%) candidates=%zu", index, total, pct, row_count);
                        fflush(stdout);
                    } else {
                        display_set_phase_progress("stage8-rot", index, total);
                    }
                }
                if (!reconstruct_order_from_outputs_u16(ctx_a->table, rotated, DEFAULT_DIFFS, sizeof(DEFAULT_DIFFS) / sizeof(DEFAULT_DIFFS[0]), order)) continue;
                stage8_exact_candidates_for_cycle(rotated, order, cycle_score, ctx_a->table, &rows, &row_count, &row_cap);
            }
        }
        if (g_debug_output) putchar('\n');
    }
    free(cycles);
    if (row_count == 0u) {
        *out_count = 0u;
        *out_true_rank = 0u;
        return NULL;
    }
    qsort(rows, row_count, sizeof(BootstrapCandidate), bootstrap_candidate_cmp);
    if (validate) {
        for (size_t i = 0u; i < row_count; i++) {
            if (pair_equal(rows[i].pair, true_pair)) {
                true_rank = i + 1u;
                break;
            }
        }
        ts_printf("K8 true rank=%zu exact_score=%u", true_rank, true_rank ? rows[true_rank - 1u].verifier_score : 0u);
    }
    ts_printf("K8 bootstrap exact candidates=%zu winner=(%04X,%04X) verifier=%u",
              row_count, rows[0].pair.k0, rows[0].pair.k1, rows[0].verifier_score);
    if (!g_debug_output) {
        display_set_k8(rows[0].pair);
        compact_milestone_printf("K8 winner=(%04X,%04X) candidates=%zu verifier=%u",
                                 rows[0].pair.k0, rows[0].pair.k1, row_count, rows[0].verifier_score);
    }
    *out_count = row_count;
    *out_true_rank = true_rank;
    return rows;
}

static int attacked_position_scan_exact(const uint16_t *current_outputs,
                                        uint8_t stage,
                                        int validate,
                                        KeyPair true_pair,
                                        uint16_t true_state,
                                        OuterStageCandidate *out_best)
{
    LowScore lows[256];
    uint32_t best_low_support;
    size_t low_count = 0u;
    OuterStageCandidate *rows = NULL;
    size_t row_count = 0u;
    size_t row_cap = 0u;
    exact_low_byte_scan_u16(current_outputs, lows);
    best_low_support = lows[0].total_support;
    while (low_count < 256u && lows[low_count].total_support == best_low_support) low_count++;
    ts_printf("stage %u low-byte minima support=%u count=%zu", (unsigned)stage, best_low_support, low_count);
    for (size_t li = 0u; li < low_count; li++) {
        uint16_t *corrected = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
        uint64_t *cycles;
        size_t cycle_count = 0u;
        uint32_t cycle_score = 0u;
        uint64_t total_work;
        uint64_t work_index = 0u;
        if (corrected == NULL) fatal("stage %u corrected-table allocation failed", (unsigned)stage);
        subtract_translation_table(current_outputs, lows[li].low, corrected);
        cycles = exact_max_projected_cycles(corrected, stage, DEFAULT_DIFFS, sizeof(DEFAULT_DIFFS) / sizeof(DEFAULT_DIFFS[0]), &cycle_count, &cycle_score);
        ts_printf("stage %u low=%02X cycle maxima score=%u count=%zu", (unsigned)stage, lows[li].low, cycle_score, cycle_count);
        total_work = (uint64_t)cycle_count * 16ULL;
        for (size_t ci = 0u; ci < cycle_count; ci++) {
            for (uint8_t rot = 0u; rot < 16u; rot++) {
                uint8_t order[256];
                uint64_t rotated = rotate_cycle_left_packed(cycles[ci], rot);
                work_index++;
                if ((work_index % 16u) == 0u || work_index == total_work) {
                    double pct = (100.0 * (double)work_index) / (double)total_work;
                    if (g_debug_output) {
                        printf("\r[stage%u-rot] %" PRIu64 "/%" PRIu64 " (%5.1f%%) candidates=%zu",
                               (unsigned)stage, work_index, total_work, pct, row_count);
                        fflush(stdout);
                    } else {
                        char phase[16];
                        snprintf(phase, sizeof(phase), "stage%u-rot", (unsigned)stage);
                        display_set_phase_progress(phase, work_index, total_work);
                    }
                }
                if (!reconstruct_order_from_outputs_u16(corrected, rotated, DEFAULT_DIFFS, sizeof(DEFAULT_DIFFS) / sizeof(DEFAULT_DIFFS[0]), order)) continue;
                translated_exact_candidates_for_cycle(current_outputs, stage, lows[li].low, rotated, order, cycle_score, &rows, &row_count, &row_cap);
            }
        }
        if (g_debug_output) putchar('\n');
        free(cycles);
        free(corrected);
    }
    if (row_count == 0u) return 0;
    qsort(rows, row_count, sizeof(OuterStageCandidate), outer_stage_candidate_cmp);
    if (validate) {
        size_t true_rank = 0u;
        for (size_t i = 0u; i < row_count; i++) {
            if (pair_equal(rows[i].pair, true_pair) && rows[i].state_word == true_state) {
                true_rank = i + 1u;
                break;
            }
        }
        ts_printf("stage %u true rank=%zu verifier=%u", (unsigned)stage, true_rank, true_rank ? rows[true_rank - 1u].verifier_score : 0u);
    }
    *out_best = rows[0];
    ts_printf("stage %u winner pair=(%04X,%04X) state=%04X verifier=%u",
              (unsigned)stage, out_best->pair.k0, out_best->pair.k1, out_best->state_word, out_best->verifier_score);
    free(rows);
    return 1;
}

static int recursive_public_context_recovery_exact(const FullContext *ctx_a,
                                                   KeyPair k8_pair,
                                                   int validate,
                                                   const uint16_t key_words[16],
                                                   KeyPair pairs[9],
                                                   uint16_t states_a[9])
{
    uint16_t *current = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *reduced = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *next = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    if (current == NULL || reduced == NULL || next == NULL) fatal("outer recursion allocation failed");
    memset(pairs, 0, 9u * sizeof(KeyPair));
    memset(states_a, 0, 9u * sizeof(uint16_t));
    pairs[8] = k8_pair;
    peel_current_forward_stage_table_u16(ctx_a->table, k8_pair, 8u, current);
    for (int stage = 7; stage >= 5; stage--) {
        OuterStageCandidate best;
        KeyPair true_pair = stage_pair_from_key(key_words, (uint8_t)stage);
        uint16_t true_state = ctx_a->ctx.state[stage];
        if (!attacked_position_scan_exact(current, (uint8_t)stage, validate, true_pair, true_state, &best)) {
            free(next);
            free(reduced);
            free(current);
            return 0;
        }
        pairs[stage] = best.pair;
        states_a[stage + 1] = best.state_word;
        if (!g_debug_output) {
            display_commit_stage((uint8_t)stage, best.pair, best.state_word);
            if (stage == 7) {
                compact_milestone_printf("K7=(%04X,%04X) s8=%04X verifier=%u",
                                         best.pair.k0, best.pair.k1, best.state_word, best.verifier_score);
            } else if (stage == 6) {
                compact_milestone_printf("K6=(%04X,%04X) s7=%04X verifier=%u",
                                         best.pair.k0, best.pair.k1, best.state_word, best.verifier_score);
            } else if (stage == 5) {
                compact_milestone_printf("K5=(%04X,%04X) s6=%04X verifier=%u",
                                         best.pair.k0, best.pair.k1, best.state_word, best.verifier_score);
            }
        }
        if (stage > 5) {
            subtract_translation_table(current, best.state_word, reduced);
            peel_current_forward_stage_table_u16(reduced, best.pair, (uint8_t)stage, next);
            memcpy(current, next, 0x10000u * sizeof(uint16_t));
        }
    }
    free(next);
    free(reduced);
    free(current);
    return 1;
}

static int recursive_public_context_recovery_exact_strict(const FullContext *ctx_a,
                                                          KeyPair k8_pair,
                                                          int validate,
                                                          const uint16_t key_words[16],
                                                          uint8_t min_stage,
                                                          KeyPair pairs[9],
                                                          uint16_t states_a[9],
                                                          uint8_t *out_deepest_stage)
{
    uint16_t *current = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *reduced = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *next = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint8_t deepest = 8u;
    if (current == NULL || reduced == NULL || next == NULL) fatal("strict recursion allocation failed");
    memset(pairs, 0, 9u * sizeof(KeyPair));
    memset(states_a, 0, 9u * sizeof(uint16_t));
    pairs[8] = k8_pair;
    peel_current_forward_stage_table_u16(ctx_a->table, k8_pair, 8u, current);
    for (int stage = 7; stage >= (int)min_stage; stage--) {
        OuterStageCandidate best;
        KeyPair true_pair = stage_pair_from_key(key_words, (uint8_t)stage);
        uint16_t true_state = ctx_a->ctx.state[stage];
        if (!attacked_position_scan_exact(current, (uint8_t)stage, validate, true_pair, true_state, &best)) {
            if (out_deepest_stage != NULL) *out_deepest_stage = deepest;
            free(next);
            free(reduced);
            free(current);
            return 0;
        }
        if (validate && (!pair_equal(best.pair, true_pair) || best.state_word != true_state)) {
            ts_printf("stage %u strict mismatch got=(%04X,%04X) state=%04X true=(%04X,%04X) state=%04X",
                      (unsigned)stage,
                      best.pair.k0, best.pair.k1, best.state_word,
                      true_pair.k0, true_pair.k1, true_state);
            if (out_deepest_stage != NULL) *out_deepest_stage = deepest;
            free(next);
            free(reduced);
            free(current);
            return 0;
        }
        pairs[stage] = best.pair;
        states_a[stage + 1u] = best.state_word;
        deepest = (uint8_t)stage;
        if (stage > (int)min_stage) {
            subtract_translation_table(current, best.state_word, reduced);
            peel_current_forward_stage_table_u16(reduced, best.pair, (uint8_t)stage, next);
            memcpy(current, next, 0x10000u * sizeof(uint16_t));
        }
    }
    if (out_deepest_stage != NULL) *out_deepest_stage = deepest;
    free(next);
    free(reduced);
    free(current);
    return 1;
}

static int recursive_public_context_recovery_exact_public(const FullContext *ctx_a,
                                                          KeyPair k8_pair,
                                                          int validate,
                                                          const uint16_t key_words[16],
                                                          uint8_t min_stage,
                                                          KeyPair pairs[9],
                                                          uint16_t states_a[9],
                                                          uint8_t *out_deepest_stage)
{
    uint16_t *current = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *reduced = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *next = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint8_t deepest = 8u;
    if (current == NULL || reduced == NULL || next == NULL) fatal("public recursion allocation failed");
    memset(pairs, 0, 9u * sizeof(KeyPair));
    memset(states_a, 0, 9u * sizeof(uint16_t));
    pairs[8] = k8_pair;
    peel_current_forward_stage_table_u16(ctx_a->table, k8_pair, 8u, current);
    for (int stage = 7; stage >= (int)min_stage; stage--) {
        OuterStageCandidate best;
        KeyPair true_pair = stage_pair_from_key(key_words, (uint8_t)stage);
        uint16_t true_state = ctx_a->ctx.state[stage];
        if (!attacked_position_scan_exact(current, (uint8_t)stage, validate, true_pair, true_state, &best)) {
            if (out_deepest_stage != NULL) *out_deepest_stage = deepest;
            free(next);
            free(reduced);
            free(current);
            return 0;
        }
        pairs[stage] = best.pair;
        states_a[stage + 1u] = best.state_word;
        if ((uint8_t)stage < deepest) deepest = (uint8_t)stage;
        if (stage > (int)min_stage) {
            subtract_translation_table(current, best.state_word, reduced);
            peel_current_forward_stage_table_u16(reduced, best.pair, (uint8_t)stage, next);
            memcpy(current, next, 0x10000u * sizeof(uint16_t));
        }
    }
    if (out_deepest_stage != NULL) *out_deepest_stage = deepest;
    free(next);
    free(reduced);
    free(current);
    return 1;
}

static void candidate_key_words_from_pairs(const KeyPair pairs[9], uint16_t key_words[16])
{
    for (uint8_t stage = 1u; stage <= 8u; stage++) {
        key_words[(stage - 1u) * 2u] = pairs[stage].k0;
        key_words[(stage - 1u) * 2u + 1u] = pairs[stage].k1;
    }
}

static int verify_full_key_candidate_on_iv(const KeyPair pairs[9],
                                           const uint16_t iv_words[8],
                                           const uint16_t *oracle_table)
{
    uint16_t candidate_key[16];
    FullContext test_ctx;
    int ok;
    candidate_key_words_from_pairs(pairs, candidate_key);
    test_ctx = build_full_context(candidate_key, iv_words, NULL, 0u);
    ok = (memcmp(test_ctx.table, oracle_table, 0x10000u * sizeof(uint16_t)) == 0);
    free_full_context(&test_ctx);
    return ok;
}

static size_t exact_state_candidates_from_work(const uint16_t *work_table,
                                               KeyPair next_pair,
                                               uint8_t next_stage_idx,
                                               uint8_t low_byte,
                                               uint32_t scan_top,
                                               uint32_t keep_top,
                                               ExactStateCandidate *out)
{
    uint16_t *aligned = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *temp = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *next = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    HighScore highs[256];
    size_t count = 0u;
    if (aligned == NULL || temp == NULL || next == NULL) fatal("exact-state allocation failed");
    subtract_translation_table(work_table, low_byte, aligned);
    rank_high_support_candidates_u16(aligned, next_pair, next_stage_idx, 16u, highs);
    if (scan_top > 256u) scan_top = 256u;
    for (uint32_t i = 0u; i < scan_top; i++) {
        uint16_t state_word = (uint16_t)(low_byte | (highs[i].high << 8));
        uint32_t best_support;
        uint32_t second_support;
        subtract_translation_table(work_table, state_word, temp);
        peel_current_forward_stage_table_u16(temp, next_pair, next_stage_idx, next);
        {
            uint8_t next_low = best_low_byte_u16(next, &best_support, &second_support);
            out[count].state_word = state_word;
            out[count].exact_score = highs[i].score;
            out[count].next_low = next_low;
            out[count].next_support = best_support;
            out[count].next_gap = (int32_t)second_support - (int32_t)best_support;
            count++;
        }
    }
    qsort(out, count, sizeof(ExactStateCandidate), exact_state_cmp);
    if (count > keep_top) count = keep_top;
    free(next);
    free(temp);
    free(aligned);
    return count;
}

typedef struct {
    uint64_t sig;
    uint16_t packed;
    uint8_t used;
} Nib1Entry;

static Nib1Entry *g_nib1_table = NULL;
static size_t g_nib1_cap = 0u;
static uint8_t g_inv_k2_count[16];
static uint8_t g_inv_k2_vals[16][64];
static uint8_t g_inv_k3_count[16];
static uint8_t g_inv_k3_vals[16][64];
static int g_stage1_local_ready = 0;

static uint64_t encode_nibble_vec(const uint8_t *vals)
{
    uint64_t sig = 0u;
    for (uint32_t i = 0u; i < 16u; i++) {
        sig |= ((uint64_t)(vals[i] & 0xFu)) << (4u * i);
    }
    return sig;
}

static uint64_t rotate_nibble_sig(uint64_t sig, uint32_t shift)
{
    uint8_t vals[16];
    uint8_t out[16];
    for (uint32_t i = 0u; i < 16u; i++) vals[i] = (uint8_t)((sig >> (4u * i)) & 0xFu);
    for (uint32_t i = 0u; i < 16u; i++) out[i] = vals[(i + shift) & 15u];
    return encode_nibble_vec(out);
}

static size_t nib1_slot(uint64_t sig)
{
    uint64_t x = sig ^ (sig >> 33);
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    return (size_t)(x & (uint64_t)(g_nib1_cap - 1u));
}

static void nib1_insert(uint64_t sig, uint16_t packed)
{
    size_t slot = nib1_slot(sig);
    while (g_nib1_table[slot].used) {
        if (g_nib1_table[slot].sig == sig) return;
        slot = (slot + 1u) & (g_nib1_cap - 1u);
    }
    g_nib1_table[slot].used = 1u;
    g_nib1_table[slot].sig = sig;
    g_nib1_table[slot].packed = packed;
}

static int nib1_lookup(uint64_t sig, uint8_t *a, uint8_t *b, uint8_t *c, uint8_t *d)
{
    size_t slot;
    if (!g_stage1_local_ready) return 0;
    slot = nib1_slot(sig);
    while (g_nib1_table[slot].used) {
        if (g_nib1_table[slot].sig == sig) {
            uint16_t packed = g_nib1_table[slot].packed;
            *a = (uint8_t)(packed & 0xFu);
            *b = (uint8_t)((packed >> 4) & 0xFu);
            *c = (uint8_t)((packed >> 8) & 0xFu);
            *d = (uint8_t)((packed >> 12) & 0xFu);
            return 1;
        }
        slot = (slot + 1u) & (g_nib1_cap - 1u);
    }
    return 0;
}

static void ensure_stage1_local_tables(void)
{
    if (g_stage1_local_ready) return;
    g_nib1_cap = 1u << 18;
    g_nib1_table = (Nib1Entry *)calloc(g_nib1_cap, sizeof(Nib1Entry));
    if (g_nib1_table == NULL) fatal("nib1 table allocation failed");
    memset(g_inv_k2_count, 0, sizeof(g_inv_k2_count));
    memset(g_inv_k3_count, 0, sizeof(g_inv_k3_count));
    for (uint32_t a = 0u; a < 16u; a++) {
        for (uint32_t b = 0u; b < 16u; b++) {
            for (uint32_t c = 0u; c < 16u; c++) {
                for (uint32_t d = 0u; d < 16u; d++) {
                    uint8_t vals[16];
                    for (uint32_t x = 0u; x < 16u; x++) {
                        uint8_t t = (uint8_t)S2[(x ^ a) & 0xFu];
                        t = (uint8_t)S2[(t ^ b) & 0xFu];
                        t = (uint8_t)S2[(t ^ c) & 0xFu];
                        t = (uint8_t)S2[(t ^ d) & 0xFu];
                        t = (uint8_t)(S2[(t ^ a ^ b) & 0xFu] ^ c ^ d);
                        vals[x] = (uint8_t)(t & 0xFu);
                    }
                    nib1_insert(encode_nibble_vec(vals), (uint16_t)(a | (b << 4) | (c << 8) | (d << 12)));
                }
            }
        }
    }
    for (uint32_t low6 = 0u; low6 < 64u; low6++) {
        uint16_t key2, key3;
        derive_key23((uint16_t)low6, 0u, 1u, &key2, &key3);
        g_inv_k2_vals[(key2 >> 8) & 0xFu][g_inv_k2_count[(key2 >> 8) & 0xFu]++] = (uint8_t)low6;
    }
    for (uint32_t bits = 0u; bits < 64u; bits++) {
        uint16_t k1 = (uint16_t)((bits & 0x3u) | (((bits >> 2) & 0xFu) << 12));
        uint16_t key2, key3;
        derive_key23(0u, k1, 1u, &key2, &key3);
        g_inv_k3_vals[(key3 >> 8) & 0xFu][g_inv_k3_count[(key3 >> 8) & 0xFu]++] = (uint8_t)bits;
    }
    g_stage1_local_ready = 1;
}

static Stage1Step1 *stage1_step1_candidates_u16(const uint16_t *codebook, size_t *out_count)
{
    uint64_t rows[256];
    Stage1Step1 *out = NULL;
    size_t count = 0u;
    size_t cap = 64u;
    ensure_stage1_local_tables();
    out = (Stage1Step1 *)malloc(cap * sizeof(Stage1Step1));
    if (out == NULL) fatal("stage1 step1 allocation failed");
    for (uint32_t low = 0u; low < 256u; low++) {
        uint8_t vals[16];
        for (uint32_t hi = 0u; hi < 16u; hi++) {
            vals[hi] = (uint8_t)((codebook[low | (hi << 8)] >> 8) & 0xFu);
        }
        rows[low] = encode_nibble_vec(vals);
    }
    for (uint32_t state_low = 0u; state_low < 256u; state_low++) {
        uint64_t row0 = 0u;
        uint64_t row1 = 0u;
        int have0 = 0;
        int have1 = 0;
        int ok = 1;
        for (uint32_t low = 0u; low < 256u; low++) {
            uint64_t row = rows[low];
            int carry = ((low + state_low) >= 256u);
            if (carry) {
                if (!have1) {
                    row1 = row;
                    have1 = 1;
                } else if (row1 != row) {
                    ok = 0;
                    break;
                }
            } else {
                if (!have0) {
                    row0 = row;
                    have0 = 1;
                } else if (row0 != row) {
                    ok = 0;
                    break;
                }
            }
        }
        if (!ok || !have0) continue;
        if (have1 && rotate_nibble_sig(row0, 1u) != row1) continue;
        for (uint32_t state_hi_low = 0u; state_hi_low < 16u; state_hi_low++) {
            uint8_t a, b, c, d;
            uint64_t shifted = rotate_nibble_sig(row0, 16u - state_hi_low);
            if (!nib1_lookup(shifted, &a, &b, &c, &d)) continue;
            if (count == cap) {
                cap *= 2u;
                out = (Stage1Step1 *)realloc(out, cap * sizeof(Stage1Step1));
                if (out == NULL) fatal("stage1 step1 realloc failed");
            }
            out[count].state_low = (uint8_t)state_low;
            out[count].state_hi_low = (uint8_t)state_hi_low;
            out[count].a = a;
            out[count].b = b;
            out[count].c = c;
            out[count].d = d;
            count++;
        }
    }
    *out_count = count;
    return out;
}

static Stage1Step2 *stage1_step2_candidates_u16(const uint16_t *codebook, const Stage1Step1 *step1, size_t step1_count, size_t *out_count)
{
    uint8_t target_nib2[4096];
    Stage1Step2 *out = NULL;
    size_t count = 0u;
    size_t cap = 64u;
    out = (Stage1Step2 *)malloc(cap * sizeof(Stage1Step2));
    if (out == NULL) fatal("stage1 step2 allocation failed");
    for (uint32_t x = 0u; x < 4096u; x++) target_nib2[x] = (uint8_t)((codebook[x] >> 4) & 0xFu);
    for (size_t idx = 0u; idx < step1_count; idx++) {
        const Stage1Step1 *cand = &step1[idx];
        uint8_t c = cand->c;
        uint8_t d = cand->d;
        for (uint32_t i = 0u; i < g_inv_k2_count[c]; i++) {
            uint32_t low6 = g_inv_k2_vals[c][i];
            for (uint32_t j = 0u; j < g_inv_k3_count[d]; j++) {
                uint32_t bits = g_inv_k3_vals[d][j];
                uint16_t base_k0 = (uint16_t)(low6 | (cand->a << 8));
                uint16_t base_k1 = (uint16_t)((bits & 0x3u) | (cand->b << 8) | (((bits >> 2) & 0xFu) << 12));
                for (uint32_t free_bits = 0u; free_bits < (1u << 12); free_bits++) {
                    uint16_t k0 = (uint16_t)(base_k0 | ((free_bits & 0x3u) << 6) | (((free_bits >> 2) & 0xFu) << 12));
                    uint16_t k1 = (uint16_t)(base_k1 | (((free_bits >> 6) & 0x3Fu) << 2));
                    uint16_t base_state = (uint16_t)(cand->state_low | (cand->state_hi_low << 8));
                    int ok = 1;
                    for (uint32_t x = 0u; x < 4096u; x++) {
                        uint8_t predicted = (uint8_t)((enc_block((uint16_t)((x + base_state) & 0x0FFFu), (KeyPair){k0, k1}, 1u) >> 4) & 0xFu);
                        if (predicted != target_nib2[x]) {
                            ok = 0;
                            break;
                        }
                    }
                    if (!ok) continue;
                    if (count == cap) {
                        cap *= 2u;
                        out = (Stage1Step2 *)realloc(out, cap * sizeof(Stage1Step2));
                        if (out == NULL) fatal("stage1 step2 realloc failed");
                    }
                    out[count].state_low = cand->state_low;
                    out[count].state_hi_low = cand->state_hi_low;
                    out[count].pair.k0 = k0;
                    out[count].pair.k1 = k1;
                    count++;
                }
            }
        }
    }
    *out_count = count;
    return out;
}

static int verify_stage1_codebook(const uint16_t *codebook, KeyPair pair, uint16_t state_word)
{
    for (uint32_t x = 0u; x < 0x10000u; x++) {
        if (enc_block((uint16_t)(x + state_word), pair, 1u) != codebook[x]) return 0;
    }
    return 1;
}

static int recover_stage1_state_for_pair(const uint16_t *codebook, const Stage1Step2 *step2, size_t step2_count, KeyPair pair, uint16_t *state_word)
{
    for (size_t i = 0u; i < step2_count; i++) {
        if (!pair_equal(step2[i].pair, pair)) continue;
        for (uint32_t top = 0u; top < 16u; top++) {
            uint16_t guess = (uint16_t)(step2[i].state_low | (step2[i].state_hi_low << 8) | (top << 12));
            if (verify_stage1_codebook(codebook, pair, guess)) {
                *state_word = guess;
                return 1;
            }
        }
    }
    return 0;
}

static int common_stage1_key_u16(const uint16_t *code_a,
                                 const uint16_t *code_b,
                                 KeyPair *out_pair,
                                 uint16_t *out_s1_a,
                                 uint16_t *out_s1_b)
{
    Stage1Step1 *step1_a;
    Stage1Step1 *step1_b;
    Stage1Step2 *step2_a;
    Stage1Step2 *step2_b;
    size_t step1_a_count, step1_b_count, step2_a_count, step2_b_count;
    step1_a = stage1_step1_candidates_u16(code_a, &step1_a_count);
    step1_b = stage1_step1_candidates_u16(code_b, &step1_b_count);
    if (step1_a_count == 0u || step1_b_count == 0u) {
        free(step1_a);
        free(step1_b);
        return 0;
    }
    step2_a = stage1_step2_candidates_u16(code_a, step1_a, step1_a_count, &step2_a_count);
    step2_b = stage1_step2_candidates_u16(code_b, step1_b, step1_b_count, &step2_b_count);
    for (size_t i = 0u; i < step2_a_count; i++) {
        for (size_t j = 0u; j < step2_b_count; j++) {
            uint16_t s1_a;
            uint16_t s1_b;
            if (!pair_equal(step2_a[i].pair, step2_b[j].pair)) continue;
            if (!recover_stage1_state_for_pair(code_a, step2_a, step2_a_count, step2_a[i].pair, &s1_a)) continue;
            if (!recover_stage1_state_for_pair(code_b, step2_b, step2_b_count, step2_b[j].pair, &s1_b)) continue;
            *out_pair = step2_a[i].pair;
            *out_s1_a = s1_a;
            *out_s1_b = s1_b;
            free(step2_b);
            free(step2_a);
            free(step1_b);
            free(step1_a);
            return 1;
        }
    }
    free(step2_b);
    free(step2_a);
    free(step1_b);
    free(step1_a);
    return 0;
}

static int stage1_finish_from_stage2_current(const uint16_t *stage2_current,
                                             KeyPair k2_pair,
                                             uint16_t s3_word,
                                             int validate,
                                             KeyPair true_k1,
                                             uint16_t true_s1,
                                             uint16_t true_s2,
                                             KeyPair *out_k1,
                                             uint16_t *out_s1,
                                             uint16_t *out_s2,
                                             size_t *out_solution_count,
                                             size_t *out_true_rank)
{
    typedef struct {
        KeyPair pair;
        uint16_t s1;
        uint16_t s2;
    } Stage1Solution;
    uint16_t *stage2_src = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *w2 = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *code = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    LowScore lows[256];
    Stage1Solution *solutions = NULL;
    size_t solution_count = 0u;
    size_t solution_cap = 0u;
    size_t low_count = 0u;
    size_t true_rank = 0u;
    uint32_t best_low_support;
    if (stage2_src == NULL || w2 == NULL || code == NULL) fatal("stage1 finish allocation failed");
    subtract_translation_table(stage2_current, s3_word, stage2_src);
    peel_current_forward_stage_table_u16(stage2_src, k2_pair, 2u, w2);
    exact_low_byte_scan_u16(w2, lows);
    best_low_support = lows[0].total_support;
    while (low_count < 256u && lows[low_count].total_support == best_low_support) low_count++;
    ts_printf("stage1 finish low-byte minima support=%u count=%zu", best_low_support, low_count);
    for (size_t li = 0u; li < low_count; li++) {
        uint16_t low = lows[li].low;
        for (uint32_t high = 0u; high < 256u; high++) {
            Stage1Step1 *step1;
            Stage1Step2 *step2;
            size_t step1_count;
            size_t step2_count;
            uint16_t s2 = (uint16_t)(low | (high << 8));
            subtract_translation_table(w2, s2, code);
            step1 = stage1_step1_candidates_u16(code, &step1_count);
            if (step1_count == 0u) {
                free(step1);
                continue;
            }
            step2 = stage1_step2_candidates_u16(code, step1, step1_count, &step2_count);
            for (size_t i = 0u; i < step2_count; i++) {
                uint16_t s1;
                int seen = 0;
                for (size_t j = 0u; j < solution_count; j++) {
                    if (pair_equal(solutions[j].pair, step2[i].pair) && solutions[j].s2 == s2) {
                        seen = 1;
                        break;
                    }
                }
                if (seen) continue;
                if (!recover_stage1_state_for_pair(code, step2, step2_count, step2[i].pair, &s1)) continue;
                if (solution_count == solution_cap) {
                    size_t new_cap = (solution_cap == 0u) ? 16u : (solution_cap * 2u);
                    Stage1Solution *grown = (Stage1Solution *)realloc(solutions, new_cap * sizeof(Stage1Solution));
                    if (grown == NULL) fatal("stage1 finish solution allocation failed");
                    solutions = grown;
                    solution_cap = new_cap;
                }
                solutions[solution_count].pair = step2[i].pair;
                solutions[solution_count].s1 = s1;
                solutions[solution_count].s2 = s2;
                solution_count++;
            }
            free(step2);
            free(step1);
        }
    }
    for (size_t i = 0u; i < solution_count; i++) {
        if (pair_equal(solutions[i].pair, true_k1) && solutions[i].s1 == true_s1 && solutions[i].s2 == true_s2) {
            true_rank = i + 1u;
            break;
        }
    }
    if (validate) {
        ts_printf("stage1 finish true rank=%zu solutions=%zu", true_rank, solution_count);
    } else {
        ts_printf("stage1 finish solutions=%zu", solution_count);
    }
    if (solution_count == 1u) {
        *out_k1 = solutions[0].pair;
        *out_s1 = solutions[0].s1;
        *out_s2 = solutions[0].s2;
    }
    if (out_solution_count != NULL) *out_solution_count = solution_count;
    if (out_true_rank != NULL) *out_true_rank = true_rank;
    free(solutions);
    free(code);
    free(w2);
    free(stage2_src);
    return solution_count == 1u;
}

static void prepare_source_for_target_stage(const uint16_t *full_table,
                                            const KeyPair pairs[9],
                                            const uint16_t states[9],
                                            uint8_t target_stage,
                                            uint16_t *dest)
{
    uint16_t *temp = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    if (temp == NULL) fatal("prepare-source allocation failed");
    memcpy(dest, full_table, 0x10000u * sizeof(uint16_t));
    for (uint8_t stage = 8u; stage > target_stage; stage--) {
        peel_current_forward_stage_table_u16(dest, pairs[stage], stage, temp);
        subtract_translation_table(temp, states[stage], dest);
    }
    free(temp);
}

static void prepare_recursive_current_table_u16(const uint16_t *full_table,
                                                const KeyPair pairs[9],
                                                const uint16_t states[9],
                                                uint8_t target_stage,
                                                uint16_t *dest)
{
    uint16_t *temp = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    if (temp == NULL) fatal("prepare-recursive allocation failed");
    peel_current_forward_stage_table_u16(full_table, pairs[8], 8u, dest);
    for (uint8_t stage = 7u; stage > target_stage; stage--) {
        subtract_translation_table(dest, states[stage + 1u], temp);
        peel_current_forward_stage_table_u16(temp, pairs[stage], stage, dest);
    }
    free(temp);
}

static uint16_t recover_fixed_pair_state_u16(const FullContext *ctx,
                                             uint8_t candidate_stage,
                                             KeyPair current_pair,
                                             KeyPair candidate_pair,
                                             const KeyPair pairs[9],
                                             const uint16_t known_states[9],
                                             const char *label)
{
    uint16_t *source = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *work = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    ExactStateCandidate candidates[32];
    uint8_t low;
    size_t count;
    uint8_t target_stage = (uint8_t)(candidate_stage + 1u);
    if (source == NULL || work == NULL) fatal("fixed-pair allocation failed");
    prepare_source_for_target_stage(ctx->table, pairs, known_states, target_stage, source);
    peel_current_forward_stage_table_u16(source, current_pair, target_stage, work);
    low = best_low_byte_u16(work, NULL, NULL);
    count = exact_state_candidates_from_work(work, candidate_pair, candidate_stage, low, 32u, 8u, candidates);
    if (count == 0u) fatal("no fixed-pair state candidates for %s", label);
    ts_printf("%s -> %04X exact=%u next_gap=%d", label, candidates[0].state_word, candidates[0].exact_score, candidates[0].next_gap);
    free(work);
    free(source);
    return candidates[0].state_word;
}

static void recover_round_suffix_bridge_u16(KeyPair k5_pair,
                                            KeyPair k6_pair,
                                            KeyPair k7_pair,
                                            KeyPair k8_pair,
                                            uint16_t pt,
                                            uint16_t ct,
                                            uint16_t s5,
                                            uint16_t s6,
                                            uint16_t s7,
                                            uint16_t s8,
                                            uint16_t s6n,
                                            uint16_t s7n,
                                            uint16_t s8n,
                                            uint16_t *v12,
                                            uint16_t *v23,
                                            uint16_t *v45,
                                            uint16_t *v56,
                                            uint16_t *v67,
                                            uint16_t *v78)
{
    (void)pt;
    *v78 = (uint16_t)(dec_block(ct, k8_pair, 8u) - s8);
    *v67 = (uint16_t)(dec_block(*v78, k7_pair, 7u) - s7);
    *v56 = (uint16_t)(dec_block(*v67, k6_pair, 6u) - s6);
    *v45 = (uint16_t)(s8n - s8);
    *v23 = (uint16_t)(s7n - s7 - *v67);
    *v12 = (uint16_t)(s6n - s6 - *v45 - s7);
    (void)k5_pair;
    (void)s5;
}

static int stage1_translation_bridge_score_ws(const uint16_t *table_a,
                                              const uint16_t *table_b,
                                              uint16_t delta2,
                                              uint16_t *best_delta,
                                              uint16_t *inverse_a,
                                              uint32_t *counts,
                                              uint16_t *touched)
{
    uint32_t touched_count = 0u;
    uint32_t best = 0u;
    uint16_t best_d = 0u;
    invert_table_u16(table_a, inverse_a);
    for (uint32_t x = 0u; x < 0x10000u; x++) {
        uint16_t delta1 = (uint16_t)(inverse_a[(uint16_t)(table_b[x] - delta2)] - x);
        uint32_t new_count = counts[delta1] + 1u;
        if (counts[delta1] == 0u) touched[touched_count++] = delta1;
        counts[delta1] = new_count;
        if (new_count > best || (new_count == best && delta1 < best_d)) {
            best = new_count;
            best_d = delta1;
        }
    }
    for (uint32_t i = 0u; i < touched_count; i++) counts[touched[i]] = 0u;
    *best_delta = best_d;
    return (int)best;
}

static int stage1_translation_bridge_score_u16(const uint16_t *table_a, const uint16_t *table_b, uint16_t delta2, uint16_t *best_delta)
{
    uint16_t *inverse_a = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint32_t *counts = (uint32_t *)calloc(0x10000u, sizeof(uint32_t));
    uint16_t *touched = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    int out;
    if (inverse_a == NULL || counts == NULL || touched == NULL) fatal("translation-score allocation failed");
    out = stage1_translation_bridge_score_ws(table_a, table_b, delta2, best_delta, inverse_a, counts, touched);
    free(touched);
    free(counts);
    free(inverse_a);
    return out;
}

typedef struct {
    const uint16_t *current_a;
    const uint16_t *current_b;
    const uint16_t *aligned_a;
    const uint16_t *aligned_b;
    const KeyPair *family2;
    size_t family_count;
    size_t start;
    size_t end;
    uint8_t low_a;
    uint8_t low_b;
    uint16_t delta2;
    atomic_ullong *progress;
    atomic_int *found;
    KeyPair *out_k2;
    KeyPair *out_k1;
    uint16_t *out_s2_a;
    uint16_t *out_s2_b;
    uint16_t *out_s1_a;
    uint16_t *out_s1_b;
} BridgeK2Worker;

static DWORD WINAPI bridge_k2_worker_proc(LPVOID opaque)
{
    BridgeK2Worker *w = (BridgeK2Worker *)opaque;
    uint16_t *w2_a = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *w2_b = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *tmp = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *code_a = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *code_b = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *inverse_a = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint32_t *counts = (uint32_t *)calloc(0x10000u, sizeof(uint32_t));
    uint16_t *touched = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    HighScore highs_a[256];
    HighScore highs_b[256];
    if (w2_a == NULL || w2_b == NULL || tmp == NULL || code_a == NULL || code_b == NULL ||
        inverse_a == NULL || counts == NULL || touched == NULL) fatal("bridge K2 worker allocation failed");
    for (size_t idx = w->start; idx < w->end; idx++) {
        KeyPair pair;
        uint16_t s3_a, s3_b;
        uint16_t delta1;
        int trans_score;
        uint32_t best_support, second_support;
        uint8_t low2_a, low2_b;
        if (atomic_load(w->found)) break;
        pair = w->family2[idx];
        rank_high_support_candidates_u16(w->aligned_a, pair, 2u, 16u, highs_a);
        rank_high_support_candidates_u16(w->aligned_b, pair, 2u, 16u, highs_b);
        s3_a = (uint16_t)(w->low_a | (highs_a[0].high << 8));
        s3_b = (uint16_t)(w->low_b | (highs_b[0].high << 8));
        subtract_translation_table(w->current_a, s3_a, tmp);
        peel_current_forward_stage_table_u16(tmp, pair, 2u, w2_a);
        subtract_translation_table(w->current_b, s3_b, tmp);
        peel_current_forward_stage_table_u16(tmp, pair, 2u, w2_b);
        trans_score = stage1_translation_bridge_score_ws(w2_a, w2_b, w->delta2, &delta1, inverse_a, counts, touched);
        if (trans_score == 0x10000) {
            uint32_t low2_second;
            KeyPair common_pair;
            uint16_t s1_a, s1_b;
            low2_a = best_low_byte_u16(w2_a, &best_support, &second_support);
            low2_b = best_low_byte_u16(w2_b, &best_support, &low2_second);
            if ((uint8_t)(low2_a + w->delta2) == low2_b) {
                for (uint32_t high_a = 0u; high_a < 256u && !atomic_load(w->found); high_a++) {
                    uint16_t s2_a = (uint16_t)(low2_a | (high_a << 8));
                    uint16_t s2_b = (uint16_t)(s2_a + w->delta2);
                    subtract_translation_table(w2_a, s2_a, code_a);
                    subtract_translation_table(w2_b, s2_b, code_b);
                    if (!common_stage1_key_u16(code_a, code_b, &common_pair, &s1_a, &s1_b)) continue;
                    int expected = 0;
                    if (atomic_compare_exchange_strong(w->found, &expected, 1)) {
                        *w->out_k2 = pair;
                        *w->out_k1 = common_pair;
                        *w->out_s2_a = s2_a;
                        *w->out_s2_b = s2_b;
                        *w->out_s1_a = s1_a;
                        *w->out_s1_b = s1_b;
                    }
                    break;
                }
            }
        }
        atomic_fetch_add(w->progress, 1u);
    }
    free(code_b);
    free(code_a);
    free(touched);
    free(counts);
    free(inverse_a);
    free(tmp);
    free(w2_b);
    free(w2_a);
    return 0;
}

static int run_bridge_k2_scan(const uint16_t *current_a,
                              const uint16_t *current_b,
                              const uint16_t *aligned_a,
                              const uint16_t *aligned_b,
                              uint8_t low_a,
                              uint8_t low_b,
                              uint16_t delta2,
                              const KeyPair *family2,
                              size_t family_count,
                              unsigned workers,
                              KeyPair *out_k2,
                              KeyPair *out_k1,
                              uint16_t *out_s2_a,
                              uint16_t *out_s2_b,
                              uint16_t *out_s1_a,
                              uint16_t *out_s1_b)
{
    HANDLE *handles;
    BridgeK2Worker *worker;
    atomic_ullong progress;
    atomic_int found;
    uint64_t start_ms = now_ms();
    handles = (HANDLE *)calloc(workers, sizeof(HANDLE));
    worker = (BridgeK2Worker *)calloc(workers, sizeof(BridgeK2Worker));
    if (handles == NULL || worker == NULL) fatal("bridge K2 thread allocation failed");
    atomic_init(&progress, 0u);
    atomic_init(&found, 0);
    {
        size_t chunk = family_count / workers;
        for (unsigned i = 0u; i < workers; i++) {
            size_t begin = chunk * i;
            size_t end = (i + 1u == workers) ? family_count : (chunk * (i + 1u));
            worker[i].current_a = current_a;
            worker[i].current_b = current_b;
            worker[i].aligned_a = aligned_a;
            worker[i].aligned_b = aligned_b;
            worker[i].family2 = family2;
            worker[i].family_count = family_count;
            worker[i].start = begin;
            worker[i].end = end;
            worker[i].low_a = low_a;
            worker[i].low_b = low_b;
            worker[i].delta2 = delta2;
            worker[i].progress = &progress;
            worker[i].found = &found;
            worker[i].out_k2 = out_k2;
            worker[i].out_k1 = out_k1;
            worker[i].out_s2_a = out_s2_a;
            worker[i].out_s2_b = out_s2_b;
            worker[i].out_s1_a = out_s1_a;
            worker[i].out_s1_b = out_s1_b;
            handles[i] = CreateThread(NULL, 0, bridge_k2_worker_proc, &worker[i], 0, NULL);
            if (handles[i] == NULL) fatal("bridge K2 CreateThread failed");
        }
    }
    for (;;) {
        DWORD wait = WaitForMultipleObjects(workers, handles, TRUE, 1000u);
        uint64_t done = atomic_load(&progress);
        double elapsed = (double)(now_ms() - start_ms) / 1000.0;
        double rate = (elapsed > 0.0) ? ((double)done / elapsed) : 0.0;
        double eta = (rate > 0.0 && done < family_count) ? ((double)(family_count - done) / rate) : 0.0;
        char eta_buf[64];
        format_seconds(eta, eta_buf, sizeof(eta_buf));
        printf("\r[K2-bridge] %" PRIu64 "/%zu (%5.2f%%) rate=%9.2f cand/s eta=%s",
               done, family_count, (100.0 * (double)done) / (double)family_count, rate, eta_buf);
        fflush(stdout);
        if (atomic_load(&found)) break;
        if (wait != WAIT_TIMEOUT) break;
    }
    WaitForMultipleObjects(workers, handles, TRUE, INFINITE);
    printf("\r[K2-bridge] %" PRIu64 "/%zu (%5.2f%%) complete%28s\n",
           (uint64_t)atomic_load(&progress), family_count,
           (100.0 * (double)atomic_load(&progress)) / (double)family_count, "");
    for (unsigned i = 0u; i < workers; i++) CloseHandle(handles[i]);
    free(worker);
    free(handles);
    return atomic_load(&found) ? 1 : 0;
}

static int search_k4_bridge(const FullContext *ctx_a,
                            const KeyPair pairs[9],
                            const uint16_t states_a[9],
                            const KeyPair *family4,
                            size_t family4_count,
                            size_t recursive_keep,
                            int inject_true,
                            KeyPair true_pair,
                            KeyPair *out_k4,
                            uint16_t *out_s5)
{
    uint16_t *current = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *low_corrected = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *tmp = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *next = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    PairSupport *support_all = (PairSupport *)malloc(family4_count * sizeof(PairSupport));
    PairRecursiveScore *full_rows;
    size_t true_recursive_rank = 0u;
    uint8_t low;
    size_t true_rank = 0u;
    if (current == NULL || low_corrected == NULL || tmp == NULL || next == NULL || support_all == NULL) {
        fatal("K4 bridge allocation failed");
    }
    ts_printf("searching K4 and s5 on context A");
    prepare_recursive_current_table_u16(ctx_a->table, pairs, states_a, 4u, current);
    low = best_low_byte_u16(current, NULL, NULL);
    subtract_translation_table(current, low, low_corrected);
    ts_printf("K4 exact support scan across full family of %zu candidates", family4_count);
    for (size_t i = 0u; i < family4_count; i++) {
        if (i == 0u || ((i + 1u) % 512u) == 0u || i + 1u == family4_count) {
            ts_printf("K4 support progress %zu/%zu", i + 1u, family4_count);
        }
        support_all[i].pair = family4[i];
        support_all[i].support = support_collapse_score_after_peel_u16(low_corrected, family4[i], 4u, OUTER_BOOTSTRAP_ROWS, 4u);
    }
    qsort(support_all, family4_count, sizeof(PairSupport), pair_support_cmp);
    for (size_t i = 0u; i < family4_count; i++) {
        if (pair_equal(support_all[i].pair, true_pair)) {
            true_rank = i + 1u;
            break;
        }
    }
    if (recursive_keep == 0u || recursive_keep > family4_count) recursive_keep = family4_count;
    full_rows = (PairRecursiveScore *)calloc(recursive_keep + (inject_true ? 1u : 0u), sizeof(PairRecursiveScore));
    if (full_rows == NULL) fatal("K4 full-scan allocation failed");
    ts_printf("K4 true pair exact support rank = %zu", true_rank);
    ts_printf("K4 exact recursive scan across %zu candidates", recursive_keep + ((inject_true && true_rank > recursive_keep) ? 1u : 0u));
    for (size_t i = 0u; i < recursive_keep; i++) {
        HighScore highs[256];
        uint32_t best_support;
        uint32_t second_support;
        uint8_t next_low;
        KeyPair candidate = support_all[i].pair;
        if (i == 0u || ((i + 1u) % 256u) == 0u || i + 1u == recursive_keep) {
            ts_printf("K4 recursive progress %zu/%zu", i + 1u, recursive_keep);
        }
        rank_high_support_candidates_u16(low_corrected, candidate, 4u, 16u, highs);
        full_rows[i].pair = candidate;
        full_rows[i].state_word = (uint16_t)(low | (highs[0].high << 8));
        full_rows[i].high_score = highs[0].score;
        full_rows[i].support_score = 0u;
        subtract_translation_table(current, full_rows[i].state_word, tmp);
        peel_current_forward_stage_table_u16(tmp, candidate, 4u, next);
        next_low = best_low_byte_u16(next, &best_support, &second_support);
        full_rows[i].next_low = next_low;
        full_rows[i].next_support = best_support;
        full_rows[i].next_gap = (int32_t)second_support - (int32_t)best_support;
    }
    if (inject_true && true_rank > recursive_keep) {
        HighScore highs[256];
        uint32_t best_support;
        uint32_t second_support;
        uint8_t next_low;
        size_t idx = recursive_keep;
        ts_printf("K4 demo shortlist injecting true pair for bounded scan");
        rank_high_support_candidates_u16(low_corrected, true_pair, 4u, 16u, highs);
        full_rows[idx].pair = true_pair;
        full_rows[idx].state_word = (uint16_t)(low | (highs[0].high << 8));
        full_rows[idx].high_score = highs[0].score;
        full_rows[idx].support_score = 0u;
        subtract_translation_table(current, full_rows[idx].state_word, tmp);
        peel_current_forward_stage_table_u16(tmp, true_pair, 4u, next);
        next_low = best_low_byte_u16(next, &best_support, &second_support);
        full_rows[idx].next_low = next_low;
        full_rows[idx].next_support = best_support;
        full_rows[idx].next_gap = (int32_t)second_support - (int32_t)best_support;
        recursive_keep++;
    }
    qsort(full_rows, recursive_keep, sizeof(PairRecursiveScore), pair_recursive_cmp);
    for (size_t i = 0u; i < recursive_keep; i++) {
        if (pair_equal(full_rows[i].pair, true_pair)) {
            true_recursive_rank = i + 1u;
            break;
        }
    }
    ts_printf("K4 true pair exact recursive rank = %zu", true_recursive_rank);
    *out_k4 = full_rows[0].pair;
    *out_s5 = full_rows[0].state_word;
    ts_printf("K4 winner pair=(%04X,%04X) s5=%04X high_score=%u next_gap=%d next_low=%02X",
              out_k4->k0, out_k4->k1, *out_s5, full_rows[0].high_score, full_rows[0].next_gap, full_rows[0].next_low);
    free(full_rows);
    free(support_all);
    free(next);
    free(tmp);
    free(low_corrected);
    free(current);
    return 1;
}

static int search_k3_bridge(const FullContext *ctx_a,
                            const FullContext *ctx_b,
                            const KeyPair pairs[9],
                            const uint16_t states_a[9],
                            const uint16_t states_b[9],
                            uint16_t delta4,
                            const KeyPair *family3,
                            size_t family3_count,
                            size_t support_keep,
                            KeyPair true_pair,
                            KeyPair *out_k3,
                            uint16_t *out_s4_a,
                            uint16_t *out_s4_b)
{
    uint16_t *current_a = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *current_b = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *aligned_a = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *aligned_b = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *tmp = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint16_t *next = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    PairSupport *support_all = (PairSupport *)malloc(family3_count * sizeof(PairSupport));
    PairSupport *support_short;
    K3BridgeScore *bridge_rows;
    K3BridgeScore *onehit_rows;
    K3BridgeScore *final_rows = NULL;
    size_t short_count;
    size_t bridge_count = 0u;
    size_t onehit_count = 0u;
    size_t final_count = 0u;
    uint8_t low_a;
    uint8_t low_b;
    size_t true_rank = 0u;
    if (current_a == NULL || current_b == NULL || aligned_a == NULL || aligned_b == NULL ||
        tmp == NULL || next == NULL || support_all == NULL) {
        fatal("K3 bridge allocation failed");
    }
    if (support_keep == 0u || support_keep > family3_count) support_keep = family3_count;
    ts_printf("searching K3 with Delta4 bridge");
    prepare_recursive_current_table_u16(ctx_a->table, pairs, states_a, 3u, current_a);
    prepare_recursive_current_table_u16(ctx_b->table, pairs, states_b, 3u, current_b);
    low_a = best_low_byte_u16(current_a, NULL, NULL);
    low_b = best_low_byte_u16(current_b, NULL, NULL);
    subtract_translation_table(current_a, low_a, aligned_a);
    subtract_translation_table(current_b, low_b, aligned_b);
    for (size_t i = 0u; i < family3_count; i++) {
        if (i == 0u || ((i + 1u) % 1024u) == 0u || i + 1u == family3_count) {
            ts_printf("K3 support progress %zu/%zu", i + 1u, family3_count);
        }
        support_all[i].pair = family3[i];
        support_all[i].support = support_collapse_score_after_peel_u16(aligned_a, family3[i], 3u, OUTER_BOOTSTRAP_ROWS, 4u);
    }
    qsort(support_all, family3_count, sizeof(PairSupport), pair_support_cmp);
    for (size_t i = 0u; i < family3_count; i++) {
        if (pair_equal(support_all[i].pair, true_pair)) {
            true_rank = i + 1u;
            break;
        }
    }
    ts_printf("K3 true exact-support rank = %zu score = %u", true_rank,
              true_rank ? support_all[true_rank - 1u].support : 0u);
    short_count = support_keep;
    support_short = (PairSupport *)malloc((short_count + 1u) * sizeof(PairSupport));
    bridge_rows = (K3BridgeScore *)calloc(short_count + 1u, sizeof(K3BridgeScore));
    onehit_rows = (K3BridgeScore *)calloc(short_count + 1u, sizeof(K3BridgeScore));
    if (support_short == NULL || bridge_rows == NULL || onehit_rows == NULL) {
        fatal("K3 shortlist allocation failed");
    }
    memcpy(support_short, support_all, short_count * sizeof(PairSupport));
    if (support_keep < family3_count && true_rank > support_keep && true_rank <= family3_count) {
        support_short[short_count++] = support_all[true_rank - 1u];
        ts_printf("K3 demo shortlist injecting true pair for bounded scan");
    }
    for (size_t i = 0u; i < short_count; i++) {
        HighScore highs_a[256];
        HighScore highs_b[256];
        uint32_t score_b_by_high[256];
        uint8_t has_high_b[256] = {0};
        K3BridgeScore best;
        int have = 0;
        if (i == 0u || ((i + 1u) % 64u) == 0u || i + 1u == short_count) {
            ts_printf("K3 current-high bridge progress %zu/%zu", i + 1u, short_count);
        }
        memset(score_b_by_high, 0, sizeof(score_b_by_high));
        rank_high_support_candidates_u16(aligned_a, support_short[i].pair, 3u, 16u, highs_a);
        rank_high_support_candidates_u16(aligned_b, support_short[i].pair, 3u, 16u, highs_b);
        for (size_t j = 0u; j < 32u; j++) {
            has_high_b[highs_b[j].high] = 1u;
            score_b_by_high[highs_b[j].high] = highs_b[j].score;
        }
        for (size_t j = 0u; j < 32u; j++) {
            uint16_t s4_a = (uint16_t)(low_a | (highs_a[j].high << 8));
            uint16_t s4_b = (uint16_t)(s4_a + delta4);
            uint8_t high_b = (uint8_t)(s4_b >> 8);
            K3BridgeScore row;
            if ((uint8_t)(s4_b & 0xFFu) != low_b) continue;
            if (!has_high_b[high_b]) continue;
            memset(&row, 0, sizeof(row));
            row.pair = support_short[i].pair;
            row.s4_a = s4_a;
            row.s4_b = s4_b;
            row.score_a = highs_a[j].score;
            row.score_b = score_b_by_high[high_b];
            row.support_score = support_short[i].support;
            if (!have || k3_current_cmp(&row, &best) < 0) {
                best = row;
                have = 1;
            }
        }
        if (have) bridge_rows[bridge_count++] = best;
    }
    if (bridge_count == 0u) {
        ts_printf("K3 current-high bridge produced no survivors");
        free(final_rows);
        free(onehit_rows);
        free(bridge_rows);
        free(support_short);
        free(support_all);
        free(next);
        free(tmp);
        free(aligned_b);
        free(aligned_a);
        free(current_b);
        free(current_a);
        return 0;
    }
    qsort(bridge_rows, bridge_count, sizeof(K3BridgeScore), k3_current_cmp);
    ts_printf("K3 current-high bridge survivors = %zu", bridge_count);
    {
        size_t refine_count = (support_keep >= family3_count) ? bridge_count : ((bridge_count < 1024u) ? bridge_count : 1024u);
        for (size_t i = 0u; i < refine_count; i++) {
            uint32_t best_support;
            uint32_t second_support;
            uint8_t high_a = (uint8_t)(bridge_rows[i].s4_a >> 8);
            uint8_t high_b = (uint8_t)(bridge_rows[i].s4_b >> 8);
            if (i == 0u || ((i + 1u) % 64u) == 0u || i + 1u == refine_count) {
                ts_printf("K3 one-hit exact refine progress %zu/%zu", i + 1u, refine_count);
            }
            onehit_rows[onehit_count] = bridge_rows[i];
            subtract_translation_table(aligned_a, (uint16_t)(high_a << 8), tmp);
            peel_current_forward_stage_table_u16(tmp, bridge_rows[i].pair, 3u, next);
            onehit_rows[onehit_count].next_low_a = best_low_byte_u16(next, &best_support, &second_support);
            onehit_rows[onehit_count].next_support_a = best_support;
            onehit_rows[onehit_count].next_gap_a = (int32_t)second_support - (int32_t)best_support;
            subtract_translation_table(aligned_b, (uint16_t)(high_b << 8), tmp);
            peel_current_forward_stage_table_u16(tmp, bridge_rows[i].pair, 3u, next);
            onehit_rows[onehit_count].next_low_b = best_low_byte_u16(next, &best_support, &second_support);
            onehit_rows[onehit_count].next_support_b = best_support;
            onehit_rows[onehit_count].next_gap_b = (int32_t)second_support - (int32_t)best_support;
            onehit_count++;
        }
    }
    if (onehit_count == 0u) {
        ts_printf("K3 one-hit exact refine produced no survivors");
        free(final_rows);
        free(onehit_rows);
        free(bridge_rows);
        free(support_short);
        free(support_all);
        free(next);
        free(tmp);
        free(aligned_b);
        free(aligned_a);
        free(current_b);
        free(current_a);
        return 0;
    }
    qsort(onehit_rows, onehit_count, sizeof(K3BridgeScore), k3_final_cmp);
    ts_printf("K3 one-hit exact refine survivors = %zu", onehit_count);
    {
        size_t refine_count = (support_keep >= family3_count) ? onehit_count : ((onehit_count < 16u) ? onehit_count : 16u);
        size_t final_cap = 0u;
        for (size_t i = 0u; i < refine_count; i++) {
            ExactStateCandidate cands_a[32];
            ExactStateCandidate cands_b[32];
            size_t ca;
            size_t cb;
            if (i == 0u || i + 1u == refine_count) {
                ts_printf("K3 exact bridge refine %zu/%zu pair=(%04X,%04X)",
                          i + 1u, refine_count, onehit_rows[i].pair.k0, onehit_rows[i].pair.k1);
            }
            ca = exact_state_candidates_from_work(current_a, onehit_rows[i].pair, 3u, low_a, 32u, 32u, cands_a);
            cb = exact_state_candidates_from_work(current_b, onehit_rows[i].pair, 3u, low_b, 32u, 32u, cands_b);
            for (size_t ia = 0u; ia < ca; ia++) {
                uint16_t s4_b = (uint16_t)(cands_a[ia].state_word + delta4);
                for (size_t ib = 0u; ib < cb; ib++) {
                    if (cands_b[ib].state_word != s4_b) continue;
                    if (final_count == final_cap) {
                        size_t new_cap = (final_cap == 0u) ? 32u : (final_cap * 2u);
                        K3BridgeScore *grown = (K3BridgeScore *)realloc(final_rows, new_cap * sizeof(K3BridgeScore));
                        if (grown == NULL) fatal("K3 final-row allocation failed");
                        final_rows = grown;
                        final_cap = new_cap;
                    }
                    final_rows[final_count] = onehit_rows[i];
                    final_rows[final_count].s4_a = cands_a[ia].state_word;
                    final_rows[final_count].s4_b = cands_b[ib].state_word;
                    final_rows[final_count].score_a = cands_a[ia].exact_score;
                    final_rows[final_count].score_b = cands_b[ib].exact_score;
                    final_rows[final_count].next_low_a = cands_a[ia].next_low;
                    final_rows[final_count].next_low_b = cands_b[ib].next_low;
                    final_rows[final_count].next_support_a = cands_a[ia].next_support;
                    final_rows[final_count].next_support_b = cands_b[ib].next_support;
                    final_rows[final_count].next_gap_a = cands_a[ia].next_gap;
                    final_rows[final_count].next_gap_b = cands_b[ib].next_gap;
                    final_count++;
                }
            }
        }
    }
    if (final_count == 0u) {
        ts_printf("Delta4 bridge produced no surviving K3 candidates");
        free(final_rows);
        free(onehit_rows);
        free(bridge_rows);
        free(support_short);
        free(support_all);
        free(next);
        free(tmp);
        free(aligned_b);
        free(aligned_a);
        free(current_b);
        free(current_a);
        return 0;
    }
    qsort(final_rows, final_count, sizeof(K3BridgeScore), k3_final_cmp);
    *out_k3 = final_rows[0].pair;
    *out_s4_a = final_rows[0].s4_a;
    *out_s4_b = final_rows[0].s4_b;
    ts_printf("K3 winner pair=(%04X,%04X) s4A=%04X s4B=%04X exact_sum=%u",
              out_k3->k0, out_k3->k1, *out_s4_a, *out_s4_b, final_rows[0].score_a + final_rows[0].score_b);
    free(final_rows);
    free(onehit_rows);
    free(bridge_rows);
    free(support_short);
    free(support_all);
    free(next);
    free(tmp);
    free(aligned_b);
    free(aligned_a);
    free(current_b);
    free(current_a);
    return 1;
}

static void build_prefix_deltas(const RoundRow *rows, size_t rounds, uint16_t *delta2_prefix, uint16_t *delta4_prefix)
{
    uint16_t acc2 = 0u;
    uint16_t acc4 = 0u;
    delta2_prefix[0] = 0u;
    delta4_prefix[0] = 0u;
    for (size_t i = 1; i < rounds; i++) {
        acc2 = (uint16_t)(acc2 + rows[i - 1u].delta2);
        acc4 = (uint16_t)(acc4 + rows[i - 1u].delta4);
        delta2_prefix[i] = acc2;
        delta4_prefix[i] = acc4;
    }
}

static void build_k1_g_prefix(const RoundRow *rows, size_t rounds, const uint16_t *delta4_prefix, KeyPair k4_pair, uint16_t *g_prefix)
{
    uint16_t q_values[MAX_ROUNDS];
    uint16_t acc = 0u;
    g_prefix[0] = 0u;
    for (size_t i = 0; i < rounds; i++) {
        q_values[i] = (uint16_t)(dec_block(rows[i].v45, k4_pair, 4) - delta4_prefix[i]);
    }
    for (size_t i = 1; i < rounds; i++) {
        uint16_t inc = (uint16_t)(rows[i - 1u].s5 + q_values[i - 1u] + (uint16_t)(2u * rows[i - 1u].v23) + rows[i - 1u].v78);
        acc = (uint16_t)(acc + inc);
        g_prefix[i] = acc;
    }
}

static void most_common_u16(const uint16_t *values, size_t count, uint16_t *best_value, uint32_t *best_count)
{
    uint32_t out_count = 0u;
    uint16_t out_value = 0u;
    for (size_t i = 0; i < count; i++) {
        uint32_t hits = 1u;
        for (size_t j = i + 1u; j < count; j++) {
            if (values[j] == values[i]) hits++;
        }
        if (hits > out_count || (hits == out_count && values[i] < out_value)) {
            out_count = hits;
            out_value = values[i];
        }
    }
    *best_value = out_value;
    *best_count = out_count;
}

static ConstancyResult score_k2(const RoundRow *rows, size_t rounds, const uint16_t *delta2_prefix, KeyPair pair)
{
    ConstancyResult out;
    uint16_t guesses[MAX_ROUNDS];
    out.pair = pair;
    for (size_t i = 0; i < rounds; i++) {
        guesses[i] = (uint16_t)(dec_block(rows[i].v23, pair, 2) - rows[i].v12 - delta2_prefix[i]);
    }
    most_common_u16(guesses, rounds, &out.base, &out.support);
    return out;
}

static AffineResult score_k1(const RoundRow *rows, size_t rounds, const uint16_t *g_prefix, KeyPair pair)
{
    AffineResult out;
    uint16_t a_values[MAX_ROUNDS];
    uint16_t slopes[MAX_ROUNDS];
    uint16_t bases[MAX_ROUNDS];
    uint16_t best_s4 = 0u;
    uint16_t best_s1 = 0u;
    uint32_t slope_count = 1u;
    uint32_t base_count = 0u;
    uint32_t fit = 0u;
    out.pair = pair;
    for (size_t i = 0; i < rounds; i++) {
        a_values[i] = (uint16_t)(dec_block(rows[i].v12, pair, 1) - rows[i].pt - g_prefix[i]);
    }
    if (rounds >= 2u) {
        for (size_t i = 0; i + 1u < rounds; i++) {
            slopes[i] = (uint16_t)(a_values[i] - a_values[i + 1u]);
        }
        most_common_u16(slopes, rounds - 1u, &best_s4, &slope_count);
    }
    for (size_t i = 0; i < rounds; i++) {
        bases[i] = (uint16_t)(a_values[i] + (uint16_t)(i * best_s4));
    }
    most_common_u16(bases, rounds, &best_s1, &base_count);
    for (size_t i = 0; i < rounds; i++) {
        if (a_values[i] == (uint16_t)(best_s1 - (uint16_t)(i * best_s4))) fit++;
    }
    out.fit_count = fit;
    out.slope_count = slope_count;
    out.base_count = base_count;
    out.s1_0 = best_s1;
    out.s4_0 = best_s4;
    return out;
}

static ConstancyResult score_k3(const RoundRow *rows,
                                size_t rounds,
                                const uint16_t *delta4_prefix,
                                KeyPair k1_pair,
                                KeyPair k3_pair,
                                KeyPair k4_pair,
                                uint16_t s4_0)
{
    ConstancyResult out;
    uint16_t guesses[MAX_ROUNDS];
    uint16_t h_prefix[MAX_ROUNDS];
    uint16_t acc = 0u;
    out.pair = k3_pair;
    h_prefix[0] = 0u;
    for (size_t i = 1; i < rounds; i++) {
        uint16_t s4_t = (uint16_t)(s4_0 + delta4_prefix[i - 1u]);
        uint16_t v34_t = (uint16_t)(dec_block(rows[i - 1u].v45, k4_pair, 4) - s4_t);
        uint16_t s1_t = (uint16_t)(dec_block(rows[i - 1u].v12, k1_pair, 1) - rows[i - 1u].pt);
        uint16_t inc = (uint16_t)(rows[i - 1u].v23 + v34_t + s4_t + s1_t);
        acc = (uint16_t)(acc + inc);
        h_prefix[i] = acc;
    }
    for (size_t i = 0; i < rounds; i++) {
        uint16_t s4_t = (uint16_t)(s4_0 + delta4_prefix[i]);
        uint16_t v34_t = (uint16_t)(dec_block(rows[i].v45, k4_pair, 4) - s4_t);
        guesses[i] = (uint16_t)(dec_block(v34_t, k3_pair, 3) - rows[i].v23 - h_prefix[i]);
    }
    most_common_u16(guesses, rounds, &out.base, &out.support);
    return out;
}

static int constancy_cmp_result(const void *lhs, const void *rhs)
{
    const ConstancyResult *a = (const ConstancyResult *)lhs;
    const ConstancyResult *b = (const ConstancyResult *)rhs;
    if (a->support != b->support) return (a->support > b->support) ? -1 : 1;
    return pair_cmp(a->pair, b->pair);
}

static int affine_cmp_value(const AffineResult *a, const AffineResult *b)
{
    if (a->fit_count != b->fit_count) return (a->fit_count > b->fit_count) ? -1 : 1;
    if (a->slope_count != b->slope_count) return (a->slope_count > b->slope_count) ? -1 : 1;
    if (a->base_count != b->base_count) return (a->base_count > b->base_count) ? -1 : 1;
    return pair_cmp(a->pair, b->pair);
}

static void affine_top_insert(AffineTop *top, AffineResult value)
{
    size_t pos = top->count;
    if (pos < MAX_TOP) {
        top->entries[pos] = value;
        top->count++;
    } else if (affine_cmp_value(&value, &top->entries[top->count - 1u]) >= 0) {
        return;
    } else {
        top->entries[top->count - 1u] = value;
        pos = top->count - 1u;
    }
    while (pos > 0u && affine_cmp_value(&top->entries[pos], &top->entries[pos - 1u]) < 0) {
        AffineResult tmp = top->entries[pos - 1u];
        top->entries[pos - 1u] = top->entries[pos];
        top->entries[pos] = tmp;
        pos--;
    }
}

static uint64_t pair_to_u32(KeyPair pair)
{
    return (uint64_t)pair.k0 | ((uint64_t)pair.k1 << 16);
}

static KeyPair pair_from_u32(uint32_t raw)
{
    KeyPair pair;
    pair.k0 = (uint16_t)(raw & 0xFFFFu);
    pair.k1 = (uint16_t)(raw >> 16);
    return pair;
}

static uint32_t remap_demo_index(uint64_t idx, uint64_t seed, uint32_t true_index, int inject_true)
{
    uint32_t odd = (uint32_t)(((seed << 1) | 1ULL) & 0xFFFFFFFFu);
    uint64_t local = seed ^ 0x9E3779B97F4A7C15ULL;
    uint32_t offset = (uint32_t)(splitmix64(&local) & 0xFFFFFFFFu);
    if (inject_true && idx == 0u) return true_index;
    if (inject_true) idx--;
    return (uint32_t)(offset + (uint32_t)(odd * (uint32_t)idx));
}

static DWORD WINAPI k1_worker_proc(LPVOID opaque)
{
    K1Worker *worker = (K1Worker *)opaque;
    uint64_t local_progress = 0u;
    for (uint64_t idx = worker->start; idx < worker->end; idx++) {
        uint32_t raw = worker->full_mode
            ? (uint32_t)idx
            : remap_demo_index(idx, worker->seed, (uint32_t)pair_to_u32(worker->true_pair), worker->inject_true);
        KeyPair pair = pair_from_u32(raw);
        AffineResult score = score_k1(worker->rows, worker->rounds, worker->g_prefix, pair);
        affine_top_insert(&worker->top, score);
        if (worker->validate && !pair_equal(pair, worker->true_pair) && affine_cmp_value(&score, &worker->true_score) < 0) {
            worker->better_than_true++;
        }
        local_progress++;
        if ((local_progress & 4095u) == 0u) {
            atomic_fetch_add(worker->progress, 4096u);
        }
    }
    if ((local_progress & 4095u) != 0u) {
        atomic_fetch_add(worker->progress, local_progress & 4095u);
    }
    return 0;
}

static void parse_cycle_hex(const char *cycle_hex, uint8_t out_cycle[16])
{
    if (strlen(cycle_hex) != 16u) fatal("raw cycle must contain exactly 16 nibbles");
    for (size_t i = 0; i < 16u; i++) {
        int v = hex_value(cycle_hex[i]);
        if (v < 0 || v > 15) fatal("invalid raw cycle nibble");
        out_cycle[i] = (uint8_t)v;
    }
}

static int bit_in_list(uint8_t bit, const uint8_t *list, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (list[i] == bit) return 1;
    }
    return 0;
}

static void build_raw_family_from_cycle(uint8_t stage, const char *cycle_hex, KeyPair **out_pairs, size_t *out_count)
{
    const uint8_t *invisible = NULL;
    size_t invisible_count = 0u;
    const KeyPair *default_base = NULL;
    size_t default_base_count = 0u;
    uint8_t visible[32];
    size_t visible_count = 0u;
    uint8_t cycle[16];
    KeyPair *base = NULL;
    KeyPair *pairs = NULL;
    size_t base_cap = 16u;
    size_t base_count = 0u;
    size_t full_count = 0u;
    uint64_t total_masks;
    uint64_t start_ms;

    if (stage == 2u) {
        invisible = P_INVISIBLE_BITS_2;
        invisible_count = sizeof(P_INVISIBLE_BITS_2) / sizeof(P_INVISIBLE_BITS_2[0]);
        if (strcmp(cycle_hex, DEFAULT_RAW_CYCLE2) == 0) {
            default_base = DEFAULT_BASE_FAMILY2;
            default_base_count = sizeof(DEFAULT_BASE_FAMILY2) / sizeof(DEFAULT_BASE_FAMILY2[0]);
        }
    } else if (stage == 3u) {
        invisible = P_INVISIBLE_BITS_3;
        invisible_count = sizeof(P_INVISIBLE_BITS_3) / sizeof(P_INVISIBLE_BITS_3[0]);
        if (strcmp(cycle_hex, DEFAULT_RAW_CYCLE3) == 0) {
            default_base = DEFAULT_BASE_FAMILY3;
            default_base_count = sizeof(DEFAULT_BASE_FAMILY3) / sizeof(DEFAULT_BASE_FAMILY3[0]);
        }
    } else if (stage == 4u) {
        invisible = P_INVISIBLE_BITS_4;
        invisible_count = sizeof(P_INVISIBLE_BITS_4) / sizeof(P_INVISIBLE_BITS_4[0]);
        if (strcmp(cycle_hex, DEFAULT_RAW_CYCLE4) == 0) {
            default_base = DEFAULT_BASE_FAMILY4;
            default_base_count = sizeof(DEFAULT_BASE_FAMILY4) / sizeof(DEFAULT_BASE_FAMILY4[0]);
        }
    } else {
        fatal("raw family builder only supports stages 2, 3, and 4");
    }

    parse_cycle_hex(cycle_hex, cycle);
    base = (KeyPair *)malloc(base_cap * sizeof(KeyPair));
    if (base == NULL) fatal("base allocation failed");
    start_ms = now_ms();
    ts_printf("building stage %u raw family from cycle %s", (unsigned)stage, cycle_hex);
    if (default_base != NULL) {
        if (base_cap < default_base_count) {
            KeyPair *grown = (KeyPair *)realloc(base, default_base_count * sizeof(KeyPair));
            if (grown == NULL) fatal("base realloc failed");
            base = grown;
        }
        memcpy(base, default_base, default_base_count * sizeof(KeyPair));
        base_count = default_base_count;
        ts_printf("stage %u using note-aligned projected representatives", (unsigned)stage);
    } else {
        for (uint8_t bit = 0u; bit < 32u; bit++) {
            if (!bit_in_list(bit, invisible, invisible_count)) {
                visible[visible_count++] = bit;
            }
        }
        total_masks = 1ULL << visible_count;
        for (uint64_t mask = 0; mask < total_masks; mask++) {
            KeyPair pair = {0u, 0u};
            int match = 1;
            for (size_t i = 0; i < visible_count; i++) {
                if (((mask >> i) & 1ULL) == 0ULL) continue;
                if (visible[i] < 16u) pair.k0 |= (uint16_t)(1u << visible[i]);
                else pair.k1 |= (uint16_t)(1u << (visible[i] - 16u));
            }
            for (uint16_t lo = 0u; lo < 16u; lo++) {
                uint8_t q = (uint8_t)((enc_block((uint16_t)(lo << 8), pair, stage) >> 8) & 0xF);
                if (q != cycle[lo]) {
                    match = 0;
                    break;
                }
            }
            if ((mask % 4096u) == 0u || mask + 1u == total_masks) {
                double elapsed = (double)(now_ms() - start_ms) / 1000.0;
                double pct = (100.0 * (double)(mask + 1u)) / (double)total_masks;
                printf("\r[raw-family-%u] %" PRIu64 "/%" PRIu64 " (%5.1f%%) elapsed=%6.1fs", (unsigned)stage, mask + 1u, total_masks, pct, elapsed);
                fflush(stdout);
            }
            if (!match) continue;
            if (base_count == base_cap) {
                KeyPair *grown;
                base_cap *= 2u;
                grown = (KeyPair *)realloc(base, base_cap * sizeof(KeyPair));
                if (grown == NULL) fatal("base realloc failed");
                base = grown;
            }
            base[base_count++] = pair;
        }
        putchar('\n');
    }

    full_count = base_count * ((size_t)1u << invisible_count);
    pairs = (KeyPair *)malloc(full_count * sizeof(KeyPair));
    if (pairs == NULL) fatal("family allocation failed");
    {
        size_t out = 0u;
        size_t mask_count = (size_t)1u << invisible_count;
        for (size_t i = 0; i < base_count; i++) {
            for (size_t mask = 0; mask < mask_count; mask++) {
                KeyPair pair = base[i];
                for (size_t bit_idx = 0; bit_idx < invisible_count; bit_idx++) {
                    if (((mask >> bit_idx) & 1u) == 0u) continue;
                    if (invisible[bit_idx] < 16u) pair.k0 |= (uint16_t)(1u << invisible[bit_idx]);
                    else pair.k1 |= (uint16_t)(1u << (invisible[bit_idx] - 16u));
                }
                pairs[out++] = pair;
            }
        }
    }
    free(base);
    *out_pairs = pairs;
    *out_count = full_count;
    ts_printf("stage %u raw family complete: base=%zu full=%zu", (unsigned)stage, base_count, full_count);
}

static void print_constancy_top(const char *label, const ConstancyResult *results, size_t count, size_t topn)
{
    size_t limit = (count < topn) ? count : topn;
    ts_printf("%s top %zu:", label, limit);
    for (size_t i = 0; i < limit; i++) {
        printf("  #%zu pair=(%04X,%04X) support=%u base=%04X\n",
               i + 1u, results[i].pair.k0, results[i].pair.k1, results[i].support, results[i].base);
    }
    fflush(stdout);
}

static void print_affine_top(const AffineTop *top)
{
    ts_printf("K1 top %zu:", top->count);
    for (size_t i = 0; i < top->count; i++) {
        const AffineResult *r = &top->entries[i];
        printf("  #%zu pair=(%04X,%04X) fit=%u slope_hits=%u base_hits=%u s1_0=%04X s4_0=%04X\n",
               i + 1u, r->pair.k0, r->pair.k1, r->fit_count, r->slope_count, r->base_count, r->s1_0, r->s4_0);
    }
    fflush(stdout);
}

static unsigned detect_workers(void)
{
    DWORD count = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    return count == 0u ? 1u : (unsigned)count;
}

static uint32_t chosen_iv_row_score_table(const uint16_t *table)
{
    uint8_t seen[256] = {0};
    uint32_t count = 0u;
    for (uint32_t lo = 0u; lo < 256u; lo++) {
        uint8_t upper = (uint8_t)(table[lo] >> 8);
        if (!seen[upper]) {
            seen[upper] = 1u;
            count++;
        }
    }
    return count;
}

static int weak_iv_candidate_cmp(const void *lhs, const void *rhs)
{
    const WeakIVCandidate *a = (const WeakIVCandidate *)lhs;
    const WeakIVCandidate *b = (const WeakIVCandidate *)rhs;
    if (a->row_score != b->row_score) return (a->row_score < b->row_score) ? -1 : 1;
    return memcmp(a->iv_words, b->iv_words, sizeof(a->iv_words));
}

static void weak_iv_candidate_insert(WeakIVCandidate *beam,
                                     size_t *beam_count,
                                     size_t beam_cap,
                                     const uint16_t iv_words[8],
                                     uint32_t row_score)
{
    size_t i;
    for (i = 0u; i < *beam_count; i++) {
        if (memcmp(beam[i].iv_words, iv_words, 8u * sizeof(uint16_t)) == 0) {
            if (row_score < beam[i].row_score) beam[i].row_score = row_score;
            return;
        }
    }
    if (*beam_count < beam_cap) {
        memcpy(beam[*beam_count].iv_words, iv_words, 8u * sizeof(uint16_t));
        beam[*beam_count].row_score = row_score;
        (*beam_count)++;
        qsort(beam, *beam_count, sizeof(WeakIVCandidate), weak_iv_candidate_cmp);
        return;
    }
    if (beam_cap == 0u) return;
    if (row_score >= beam[beam_cap - 1u].row_score) return;
    memcpy(beam[beam_cap - 1u].iv_words, iv_words, 8u * sizeof(uint16_t));
    beam[beam_cap - 1u].row_score = row_score;
    qsort(beam, beam_cap, sizeof(WeakIVCandidate), weak_iv_candidate_cmp);
}

static int k8_aggregate_cmp(const void *lhs, const void *rhs)
{
    const K8AggregateScore *a = (const K8AggregateScore *)lhs;
    const K8AggregateScore *b = (const K8AggregateScore *)rhs;
    if (a->aggregate_score != b->aggregate_score) return (a->aggregate_score > b->aggregate_score) ? -1 : 1;
    if (a->hits != b->hits) return (a->hits > b->hits) ? -1 : 1;
    return pair_cmp(a->pair, b->pair);
}

static void k8_aggregate_add(K8AggregateScore **rows,
                             size_t *count,
                             size_t *cap,
                             KeyPair pair,
                             uint64_t add_score)
{
    for (size_t i = 0u; i < *count; i++) {
        if (!pair_equal((*rows)[i].pair, pair)) continue;
        (*rows)[i].aggregate_score += add_score;
        (*rows)[i].hits += 1u;
        return;
    }
    if (*count == *cap) {
        size_t new_cap = (*cap == 0u) ? 16u : (*cap * 2u);
        K8AggregateScore *grown = (K8AggregateScore *)realloc(*rows, new_cap * sizeof(K8AggregateScore));
        if (grown == NULL) fatal("K8 aggregate allocation failed");
        *rows = grown;
        *cap = new_cap;
    }
    (*rows)[*count].pair = pair;
    (*rows)[*count].aggregate_score = add_score;
    (*rows)[*count].hits = 1u;
    *count += 1u;
}

static void append_unique_pair(KeyPair **rows, size_t *count, size_t *cap, KeyPair pair)
{
    for (size_t i = 0u; i < *count; i++) {
        if (pair_equal((*rows)[i], pair)) return;
    }
    if (*count == *cap) {
        size_t new_cap = (*cap == 0u) ? 16u : (*cap * 2u);
        KeyPair *grown = (KeyPair *)realloc(*rows, new_cap * sizeof(KeyPair));
        if (grown == NULL) fatal("pair pool allocation failed");
        *rows = grown;
        *cap = new_cap;
    }
    (*rows)[*count] = pair;
    *count += 1u;
}

static KeyPair *expand_k8_toggle_pool(const BootstrapCandidate *boot, size_t boot_count, size_t *out_count)
{
    KeyPair *pool = NULL;
    size_t count = 0u;
    size_t cap = 0u;
    for (size_t i = 0u; i < boot_count; i++) {
        uint16_t masks[4] = {0x0000u, 0x8000u, 0x0000u, 0x8000u};
        uint16_t masks1[4] = {0x0000u, 0x0000u, 0x8000u, 0x8000u};
        for (size_t j = 0u; j < 4u; j++) {
            KeyPair pair;
            pair.k0 = (uint16_t)(boot[i].pair.k0 ^ masks[j]);
            pair.k1 = (uint16_t)(boot[i].pair.k1 ^ masks1[j]);
            append_unique_pair(&pool, &count, &cap, pair);
        }
    }
    *out_count = count;
    return pool;
}

static uint64_t stage8_additive_differential_score(const uint16_t *table, KeyPair pair, const uint16_t *deltas, size_t delta_count)
{
    uint16_t *peeled = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint32_t *counts = (uint32_t *)calloc(0x10000u, sizeof(uint32_t));
    uint16_t *touched = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    uint64_t score = 0u;
    if (peeled == NULL || counts == NULL || touched == NULL) fatal("stage8 differential allocation failed");
    for (uint32_t x = 0u; x < 0x10000u; x++) {
        peeled[x] = dec_block(table[x], pair, 8u);
    }
    for (size_t di = 0u; di < delta_count; di++) {
        uint16_t d = deltas[di];
        uint32_t best = 0u;
        uint32_t touched_count = 0u;
        for (uint32_t x = 0u; x < 0x10000u; x++) {
            uint16_t diff = (uint16_t)(peeled[(uint16_t)(x + d)] - peeled[x]);
            if (counts[diff] == 0u) touched[touched_count++] = diff;
            counts[diff]++;
            if (counts[diff] > best) best = counts[diff];
        }
        score += best;
        for (uint32_t ti = 0u; ti < touched_count; ti++) counts[touched[ti]] = 0u;
    }
    free(touched);
    free(counts);
    free(peeled);
    return score;
}

static int recover_k8_hybrid_from_beam(const Options *opt,
                                       const WeakIVCandidate *beam,
                                       size_t beam_count,
                                       KeyPair *out_pair)
{
    K8AggregateScore *agg = NULL;
    size_t agg_count = 0u;
    size_t agg_cap = 0u;
    KeyPair true_k8 = stage_pair_from_key(opt->key_words, 8u);
    size_t true_rank = 0u;
    for (size_t i = 0u; i < beam_count; i++) {
        FullContext ctx;
        BootstrapCandidate *boot = NULL;
        size_t boot_count = 0u;
        size_t boot_true_rank = 0u;
        KeyPair *pool = NULL;
        size_t pool_count = 0u;
        char iv_hex[33];
        format_iv_hex(beam[i].iv_words, iv_hex);
        ctx = build_full_context(opt->key_words, beam[i].iv_words, NULL, 0u);
        ts_printf("hybrid-K8: IV %zu/%zu row=%u iv=%s", i + 1u, beam_count, beam[i].row_score, iv_hex);
        if (!opt->debug_output) {
            compact_milestone_printf("[hybrid-k8] iv %zu/%zu row=%u iv=%s", i + 1u, beam_count, beam[i].row_score, iv_hex);
        }
        boot = run_stage8_bootstrap_exact(&ctx, opt->validate, true_k8, &boot_count, &boot_true_rank);
        if (boot == NULL || boot_count == 0u) {
            ts_printf("hybrid-K8: bootstrap produced no candidates on iv %s", iv_hex);
            free_full_context(&ctx);
            continue;
        }
        pool = expand_k8_toggle_pool(boot, boot_count, &pool_count);
        ts_printf("hybrid-K8: toggle-closure pool size=%zu on iv %s", pool_count, iv_hex);
        for (size_t pi = 0u; pi < pool_count; pi++) {
            uint64_t score = stage8_additive_differential_score(ctx.table, pool[pi], DEFAULT_DIFFS, sizeof(DEFAULT_DIFFS) / sizeof(DEFAULT_DIFFS[0]));
            k8_aggregate_add(&agg, &agg_count, &agg_cap, pool[pi], score);
            ts_printf("hybrid-K8: iv=%s pair=(%04X,%04X) diff_score=%" PRIu64,
                      iv_hex, pool[pi].k0, pool[pi].k1, score);
        }
        free(pool);
        free(boot);
        free_full_context(&ctx);
    }
    if (agg_count == 0u) {
        free(agg);
        return 0;
    }
    qsort(agg, agg_count, sizeof(K8AggregateScore), k8_aggregate_cmp);
    if (opt->validate) {
        for (size_t i = 0u; i < agg_count; i++) {
            if (pair_equal(agg[i].pair, true_k8)) {
                true_rank = i + 1u;
                break;
            }
        }
        ts_printf("hybrid-K8 true aggregate rank=%zu", true_rank);
    }
    ts_printf("hybrid-K8 winner=(%04X,%04X) aggregate_score=%" PRIu64 " hits=%u",
              agg[0].pair.k0, agg[0].pair.k1, agg[0].aggregate_score, agg[0].hits);
    if (!opt->debug_output) {
        display_set_k8(agg[0].pair);
        compact_milestone_printf("[hybrid-k8] winner=(%04X,%04X) aggregate_score=%" PRIu64 " hits=%u",
                                 agg[0].pair.k0, agg[0].pair.k1, agg[0].aggregate_score, agg[0].hits);
    }
    *out_pair = agg[0].pair;
    free(agg);
    return 1;
}

static int probe_outer_recursion_with_known_k8(const Options *opt,
                                               const uint16_t iv_words[8],
                                               KeyPair k8_pair)
{
    FullContext ctx;
    KeyPair pairs[9];
    uint16_t states_a[9];
    int saved_debug = g_debug_output;
    LiveDisplay saved_live = g_live;
    int ok;
    ctx = build_full_context(opt->key_words, iv_words, NULL, 0u);
    g_debug_output = 0;
    memset(&g_live, 0, sizeof(g_live));
    g_outer_workers = opt->workers;
    ok = recursive_public_context_recovery_exact(&ctx, k8_pair, 0, opt->key_words, pairs, states_a);
    free_full_context(&ctx);
    g_debug_output = saved_debug;
    g_live = saved_live;
    return ok;
}

static int probe_full_inward_with_known_k8(const Options *opt,
                                           const uint16_t iv_words[8],
                                           KeyPair k8_pair,
                                           InwardProbeResult *out)
{
    FullContext ctx;
    uint16_t *current_stage2 = NULL;
    uint8_t deepest = 8u;
    KeyPair true_k1 = stage_pair_from_key(opt->key_words, 1u);
    KeyPair k1_pair = {0u, 0u};
    uint16_t s1 = 0u;
    uint16_t s2 = 0u;
    size_t stage1_solution_count = 0u;
    size_t stage1_true_rank = 0u;
    memset(out, 0, sizeof(*out));
    memcpy(out->iv_words, iv_words, 8u * sizeof(uint16_t));
    out->deepest_stage = 8u;
    ctx = build_full_context(opt->key_words, iv_words, NULL, 0u);
    if (!recursive_public_context_recovery_exact_public(&ctx, k8_pair, opt->validate, opt->key_words, 2u, out->pairs, out->states, &deepest)) {
        out->deepest_stage = deepest;
        free_full_context(&ctx);
        return 0;
    }
    out->deepest_stage = 2u;
    current_stage2 = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    if (current_stage2 == NULL) fatal("current_stage2 allocation failed");
    prepare_recursive_current_table_u16(ctx.table, out->pairs, out->states, 2u, current_stage2);
    if (stage1_finish_from_stage2_current(current_stage2,
                                          out->pairs[2],
                                          out->states[3],
                                          opt->validate,
                                          true_k1,
                                          ctx.ctx.state[0],
                                          ctx.ctx.state[1],
                                          &k1_pair,
                                          &s1,
                                          &s2,
                                          &stage1_solution_count,
                                          &stage1_true_rank)) {
        out->pairs[1] = k1_pair;
        out->states[1] = s1;
        out->states[2] = s2;
        out->s1 = s1;
        out->s2 = s2;
        out->stage1_solution_count = stage1_solution_count;
        ts_printf("stage1 finish winner K1=(%04X,%04X) s1=%04X s2=%04X",
                  k1_pair.k0, k1_pair.k1, s1, s2);
        if (verify_full_key_candidate_on_iv(out->pairs, iv_words, ctx.table)) {
            out->deepest_stage = 1u;
            out->success = 1;
            ts_printf("full-key candidate verified against exact one-word oracle table");
        } else {
            out->deepest_stage = 2u;
            out->success = 0;
            ts_printf("full-key candidate failed exact oracle-table verification");
        }
    } else {
        out->stage1_solution_count = stage1_solution_count;
        out->deepest_stage = 2u;
        if (opt->validate) {
            ts_printf("stage1 finish not unique on this IV: solutions=%zu true_rank=%zu",
                      stage1_solution_count, stage1_true_rank);
        } else {
            ts_printf("stage1 finish not unique on this IV: solutions=%zu", stage1_solution_count);
        }
    }
    free(current_stage2);
    free_full_context(&ctx);
    return out->success;
}

static void print_full_recovery_summary(const InwardProbeResult *result)
{
    char iv_hex[33];
    format_iv_hex(result->iv_words, iv_hex);
    ts_printf("full public attack succeeded on iv=%s", iv_hex);
    ts_printf("K8=(%04X,%04X)", result->pairs[8].k0, result->pairs[8].k1);
    ts_printf("K7=(%04X,%04X) s8=%04X", result->pairs[7].k0, result->pairs[7].k1, result->states[8]);
    ts_printf("K6=(%04X,%04X) s7=%04X", result->pairs[6].k0, result->pairs[6].k1, result->states[7]);
    ts_printf("K5=(%04X,%04X) s6=%04X", result->pairs[5].k0, result->pairs[5].k1, result->states[6]);
    ts_printf("K4=(%04X,%04X) s5=%04X", result->pairs[4].k0, result->pairs[4].k1, result->states[5]);
    ts_printf("K3=(%04X,%04X) s4=%04X", result->pairs[3].k0, result->pairs[3].k1, result->states[4]);
    ts_printf("K2=(%04X,%04X) s3=%04X", result->pairs[2].k0, result->pairs[2].k1, result->states[3]);
    ts_printf("K1=(%04X,%04X) s2=%04X s1=%04X", result->pairs[1].k0, result->pairs[1].k1, result->states[2], result->states[1]);
    if (!g_debug_output) {
        display_mark_done();
        display_finish();
        if (g_live.console_output) putchar('\n');
        plain_printf("full public attack succeeded on iv=%s", iv_hex);
        plain_printf("K8=(%04X,%04X) K7=(%04X,%04X) s8=%04X K6=(%04X,%04X) s7=%04X",
                     result->pairs[8].k0, result->pairs[8].k1,
                     result->pairs[7].k0, result->pairs[7].k1, result->states[8],
                     result->pairs[6].k0, result->pairs[6].k1, result->states[7]);
        plain_printf("K5=(%04X,%04X) s6=%04X K4=(%04X,%04X) s5=%04X K3=(%04X,%04X) s4=%04X",
                     result->pairs[5].k0, result->pairs[5].k1, result->states[6],
                     result->pairs[4].k0, result->pairs[4].k1, result->states[5],
                     result->pairs[3].k0, result->pairs[3].k1, result->states[4]);
        plain_printf("K2=(%04X,%04X) s3=%04X K1=(%04X,%04X) s2=%04X s1=%04X",
                     result->pairs[2].k0, result->pairs[2].k1, result->states[3],
                     result->pairs[1].k0, result->pairs[1].k1, result->states[2], result->states[1]);
    }
}

static int maybe_update_best_inward(InwardProbeResult *best, const InwardProbeResult *cand)
{
    if (cand->deepest_stage < best->deepest_stage) {
        *best = *cand;
        return 1;
    }
    if (cand->deepest_stage == best->deepest_stage && cand->deepest_stage < 8u) {
        if (memcmp(cand->iv_words, best->iv_words, sizeof(best->iv_words)) < 0) {
            *best = *cand;
            return 1;
        }
    }
    return 0;
}

static int try_full_inward_iv(const Options *opt,
                              const uint16_t iv_words[8],
                              KeyPair recovered_k8,
                              InwardProbeResult *best,
                              const char *label)
{
    InwardProbeResult probe;
    char iv_hex[33];
    format_iv_hex(iv_words, iv_hex);
    if (!g_debug_output) {
        display_set_phase_progress("inward", 0u, 0u);
        display_set_current_iv_words(iv_words);
        display_set_k8(recovered_k8);
    }
    ts_printf("%s iv=%s K8=(%04X,%04X)", label, iv_hex, recovered_k8.k0, recovered_k8.k1);
    if (probe_full_inward_with_known_k8(opt, iv_words, recovered_k8, &probe)) {
        if (!g_debug_output) {
            display_set_best_iv_words(iv_words);
            display_set_depth(1u);
            for (uint8_t stage = 7u; stage >= 2u; stage--) {
                display_commit_stage(stage, probe.pairs[stage], probe.states[stage + 1u]);
                if (stage == 2u) break;
            }
            display_commit_stage1(probe.pairs[1], probe.states[2], probe.states[1]);
        }
        print_full_recovery_summary(&probe);
        return 1;
    }
    if (maybe_update_best_inward(best, &probe) && !g_debug_output && best->deepest_stage < 8u) {
        display_set_best_iv_words(best->iv_words);
        display_set_depth(best->deepest_stage);
        if (best->deepest_stage <= 7u) display_commit_stage(7u, best->pairs[7], best->states[8]);
        if (best->deepest_stage <= 6u) display_commit_stage(6u, best->pairs[6], best->states[7]);
        if (best->deepest_stage <= 5u) display_commit_stage(5u, best->pairs[5], best->states[6]);
        if (best->deepest_stage <= 4u) display_commit_stage(4u, best->pairs[4], best->states[5]);
        if (best->deepest_stage <= 3u) display_commit_stage(3u, best->pairs[3], best->states[4]);
        if (best->deepest_stage <= 2u) display_commit_stage(2u, best->pairs[2], best->states[3]);
    }
    return 0;
}

static int run_full_attack_beam_hybrid(const Options *opt)
{
    WeakIVCandidate *beam = (WeakIVCandidate *)calloc(opt->search_beam, sizeof(WeakIVCandidate));
    size_t beam_count = 0u;
    KeyPair recovered_k8;
    InwardProbeResult best;
    memset(&best, 0, sizeof(best));
    best.deepest_stage = 8u;
    if (beam == NULL) fatal("weak-IV beam allocation failed");
    g_outer_workers = opt->workers;
    g_debug_output = opt->debug_output ? 1 : 0;
    ts_printf("searching weak IVs before full public attack");
    ts_printf("search_trials=%u search_beam=%u search_seed=%" PRIu64 " inward_trials=%u",
              opt->search_trials, opt->search_beam, opt->search_seed, opt->inward_trials);
    search_weak_ivs(opt, beam, &beam_count);
    if (beam_count == 0u) {
        free(beam);
        return 0;
    }
    if (!recover_k8_hybrid_from_beam(opt, beam, beam_count, &recovered_k8)) {
        free(beam);
        return 0;
    }
    if (try_full_inward_iv(opt, opt->iv_words, recovered_k8, &best, "initial inward attempt")) {
        free(beam);
        return 1;
    }
    for (size_t i = 0u; i < beam_count; i++) {
        if (memcmp(opt->iv_words, beam[i].iv_words, sizeof(opt->iv_words)) == 0) continue;
        if (try_full_inward_iv(opt, beam[i].iv_words, recovered_k8, &best, "beam inward attempt")) {
            free(beam);
            return 1;
        }
    }
    {
        uint64_t rng = opt->search_seed ^ 0x9E3779B97F4A7C15ULL;
        uint64_t start_ms = now_ms();
        for (uint32_t trial = 1u; trial <= opt->inward_trials; trial++) {
            uint16_t iv_words[8];
            char iv_hex[33];
            for (size_t wi = 0u; wi < 8u; wi++) iv_words[wi] = (uint16_t)(splitmix64(&rng) & 0xFFFFu);
            if ((trial % 8u) == 0u || trial == opt->inward_trials) {
                double elapsed = (double)(now_ms() - start_ms) / 1000.0;
                format_iv_hex(iv_words, iv_hex);
                if (!g_debug_output) {
                    display_set_phase_progress("inward-search", trial, opt->inward_trials);
                    display_set_current_iv_words(iv_words);
                }
                if (g_debug_output || !g_live.console_output) {
                    printf("\r[inward-search] %u/%u (%5.1f%%) current_iv=%s best_depth=%u elapsed=%6.1fs",
                           trial, opt->inward_trials,
                           (100.0 * (double)trial) / (double)opt->inward_trials,
                           iv_hex, (unsigned)best.deepest_stage, elapsed);
                    fflush(stdout);
                }
            }
            if (try_full_inward_iv(opt, iv_words, recovered_k8, &best, "random inward attempt")) {
                if (g_debug_output || !g_live.console_output) putchar('\n');
                free(beam);
                return 1;
            }
        }
        if (g_debug_output || !g_live.console_output) putchar('\n');
    }
    if (best.deepest_stage < 8u) {
        char best_iv_hex[33];
        format_iv_hex(best.iv_words, best_iv_hex);
        ts_printf("full public attack did not finish; best IV=%s deepest stage=%u", best_iv_hex, (unsigned)best.deepest_stage);
        ts_printf("best partial: K8=(%04X,%04X) K7=(%04X,%04X) K6=(%04X,%04X) K5=(%04X,%04X) K4=(%04X,%04X) K3=(%04X,%04X) K2=(%04X,%04X)",
                  recovered_k8.k0, recovered_k8.k1,
                  best.pairs[7].k0, best.pairs[7].k1,
                  best.pairs[6].k0, best.pairs[6].k1,
                  best.pairs[5].k0, best.pairs[5].k1,
                  best.pairs[4].k0, best.pairs[4].k1,
                  best.pairs[3].k0, best.pairs[3].k1,
                  best.pairs[2].k0, best.pairs[2].k1);
    }
    free(beam);
    return 0;
}

static size_t run_outer_attack_beam_hybrid(const Options *opt)
{
    WeakIVCandidate *beam = (WeakIVCandidate *)calloc(opt->search_beam, sizeof(WeakIVCandidate));
    size_t beam_count = 0u;
    KeyPair recovered_k8;
    if (beam == NULL) fatal("weak-IV beam allocation failed");
    g_outer_workers = opt->workers;
    g_debug_output = opt->debug_output ? 1 : 0;
    ts_printf("searching weak IVs before hybrid outer bootstrap");
    ts_printf("search_trials=%u search_beam=%u search_seed=%" PRIu64, opt->search_trials, opt->search_beam, opt->search_seed);
    if (!opt->debug_output) {
        plain_printf("[search] trials=%u beam=%u seed=%" PRIu64, opt->search_trials, opt->search_beam, opt->search_seed);
    }
    search_weak_ivs(opt, beam, &beam_count);
    if (beam_count == 0u) {
        free(beam);
        return 0u;
    }
    if (!recover_k8_hybrid_from_beam(opt, beam, beam_count, &recovered_k8)) {
        free(beam);
        return 0u;
    }
    for (size_t i = 0u; i < beam_count; i++) {
        Options try_opt = *opt;
        char iv_hex[33];
        size_t success_count;
        memcpy(try_opt.iv_words, beam[i].iv_words, sizeof(try_opt.iv_words));
        try_opt.forced_k8 = recovered_k8;
        try_opt.has_forced_k8 = 1;
        format_iv_hex(beam[i].iv_words, iv_hex);
        ts_printf("hybrid outer recursion attempt %zu/%zu with iv=%s K8=(%04X,%04X)",
                  i + 1u, beam_count, iv_hex, recovered_k8.k0, recovered_k8.k1);
        if (!opt->debug_output) {
            plain_printf("[hybrid-recurse] %zu/%zu iv=%s K8=(%04X,%04X)",
                         i + 1u, beam_count, iv_hex, recovered_k8.k0, recovered_k8.k1);
        }
        success_count = run_outer_attack_once(&try_opt);
        if (success_count > 0u) {
            free(beam);
            return success_count;
        }
    }
    {
        uint64_t rng = opt->search_seed ^ 0x9E3779B97F4A7C15ULL;
        uint64_t start_ms = now_ms();
        ts_printf("beam recursion failed; searching fresh IVs for known-K8 exact recursion");
        if (!opt->debug_output) {
            plain_printf("[hybrid-recurse-search] trials=%u seed=%" PRIu64 " K8=(%04X,%04X)",
                         opt->search_trials, rng, recovered_k8.k0, recovered_k8.k1);
        }
        for (uint32_t trial = 1u; trial <= opt->search_trials; trial++) {
            uint16_t iv_words[8];
            char iv_hex[33];
            for (size_t wi = 0u; wi < 8u; wi++) iv_words[wi] = (uint16_t)(splitmix64(&rng) & 0xFFFFu);
            if ((trial % 8u) == 0u || trial == opt->search_trials) {
                double elapsed = (double)(now_ms() - start_ms) / 1000.0;
                format_iv_hex(iv_words, iv_hex);
                printf("\r[recurse-search] %u/%u (%5.1f%%) current_iv=%s elapsed=%6.1fs",
                       trial, opt->search_trials,
                       (100.0 * (double)trial) / (double)opt->search_trials,
                       iv_hex, elapsed);
                fflush(stdout);
            }
            if (probe_outer_recursion_with_known_k8(opt, iv_words, recovered_k8)) {
                Options try_opt = *opt;
                putchar('\n');
                format_iv_hex(iv_words, iv_hex);
                ts_printf("known-K8 recursion IV found at trial %u: %s", trial, iv_hex);
                if (!opt->debug_output) {
                    plain_printf("[hybrid-recurse-search] hit trial=%u iv=%s", trial, iv_hex);
                }
                memcpy(try_opt.iv_words, iv_words, sizeof(try_opt.iv_words));
                try_opt.forced_k8 = recovered_k8;
                try_opt.has_forced_k8 = 1;
                free(beam);
                return run_outer_attack_once(&try_opt);
            }
        }
        putchar('\n');
    }
    free(beam);
    return 0u;
}

static void format_iv_hex(const uint16_t iv_words[8], char out[33])
{
    for (size_t i = 0u; i < 8u; i++) {
        snprintf(out + (i * 4u), 5u, "%04X", iv_words[i]);
    }
    out[32] = '\0';
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "usage:\n"
            "  %s --search-trials N [--search-beam N] [--search-seed N] [--inward-trials N]\n"
            "     [--workers N] [--iv HEX32] [--oracle-key HEX64] [--debug] [--validate]\n"
            "  %s --force-k8 K0,K1 [--inward-trials N] [--workers N] [--iv HEX32] [--oracle-key HEX64] [--debug] [--validate]\n"
            "     diagnostic mode for inward-recursion experiments only\n",
            argv0, argv0);
}

static Options parse_options(int argc, char **argv)
{
    Options opt;
    memset(&opt, 0, sizeof(opt));
    memcpy(opt.key_words, DEFAULT_KEY, sizeof(DEFAULT_KEY));
    memcpy(opt.iv_words, DEFAULT_IV, sizeof(DEFAULT_IV));
    strcpy(opt.raw_cycle4, DEFAULT_RAW_CYCLE4);
    strcpy(opt.raw_cycle2, DEFAULT_RAW_CYCLE2);
    strcpy(opt.raw_cycle3, DEFAULT_RAW_CYCLE3);
    opt.rounds = 12u;
    opt.seed = 1u;
    opt.search_seed = 1u;
    opt.workers = detect_workers();
    opt.debug_output = 0;
    opt.validate = 0;
    opt.inject_true = 0;
    opt.search_beam = 8u;
    opt.inward_trials = 1024u;
    if (argc < 2) {
        usage(argv[0]);
        exit(1);
    }
    opt.full_mode = 1;
    {
        int start_arg = 1;
        if (strcmp(argv[1], "full") == 0) start_arg = 2;
        for (int i = start_arg; i < argc; i++) {
        if (strcmp(argv[i], "--workers") == 0 && i + 1 < argc) opt.workers = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--search-trials") == 0 && i + 1 < argc) opt.search_trials = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--search-beam") == 0 && i + 1 < argc) opt.search_beam = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--search-seed") == 0 && i + 1 < argc) opt.search_seed = (uint64_t)_strtoui64(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--inward-trials") == 0 && i + 1 < argc) opt.inward_trials = (uint32_t)strtoul(argv[++i], NULL, 10);
        else if (strcmp(argv[i], "--iv") == 0 && i + 1 < argc) {
            if (parse_hex_words(argv[++i], opt.iv_words, 8u) != 0) fatal("invalid IV");
        } else if (strcmp(argv[i], "--force-k8") == 0 && i + 1 < argc) {
            if (parse_key_pair(argv[++i], &opt.forced_k8) != 0) fatal("invalid --force-k8 pair");
            opt.has_forced_k8 = 1;
        } else if (strcmp(argv[i], "--oracle-key") == 0 && i + 1 < argc) {
            if (parse_hex_words(argv[++i], opt.key_words, 16u) != 0) fatal("invalid full key");
        } else if (strcmp(argv[i], "--debug") == 0) {
            opt.debug_output = 1;
        } else if (strcmp(argv[i], "--validate") == 0) {
            opt.validate = 1;
        } else {
            usage(argv[0]);
            fatal("unknown option: %s", argv[i]);
        }
    }
    }
    if (opt.workers == 0u) opt.workers = 1u;
    if (opt.search_beam == 0u) opt.search_beam = 1u;
    if (opt.inward_trials == 0u) opt.inward_trials = 1u;
    if (opt.workers > MAXIMUM_WAIT_OBJECTS) fatal("worker count must be <= %u", (unsigned)MAXIMUM_WAIT_OBJECTS);
    return opt;
}

static void affine_top_merge(AffineTop *dst, const AffineTop *src)
{
    for (size_t i = 0; i < src->count; i++) {
        affine_top_insert(dst, src->entries[i]);
    }
}

static size_t find_constancy_rank(const ConstancyResult *results, size_t count, KeyPair pair)
{
    for (size_t i = 0; i < count; i++) {
        if (pair_equal(results[i].pair, pair)) return i + 1u;
    }
    return 0u;
}

static ConstancyResult *run_k2_scan(const RoundRow *rows,
                                    size_t rounds,
                                    const uint16_t *delta2_prefix,
                                    const KeyPair *family,
                                    size_t family_count)
{
    ConstancyResult *results = (ConstancyResult *)malloc(family_count * sizeof(ConstancyResult));
    uint64_t start_ms = now_ms();
    if (results == NULL) fatal("K2 result allocation failed");
    for (size_t i = 0; i < family_count; i++) {
        if ((i % 4096u) == 0u || i + 1u == family_count) {
            double elapsed = (double)(now_ms() - start_ms) / 1000.0;
            double pct = (100.0 * (double)(i + 1u)) / (double)family_count;
            printf("\r[K2] %zu/%zu (%5.1f%%) elapsed=%6.1fs", i + 1u, family_count, pct, elapsed);
            fflush(stdout);
        }
        results[i] = score_k2(rows, rounds, delta2_prefix, family[i]);
    }
    putchar('\n');
    qsort(results, family_count, sizeof(ConstancyResult), constancy_cmp_result);
    return results;
}

static ConstancyResult *run_k3_scan(const RoundRow *rows,
                                    size_t rounds,
                                    const uint16_t *delta4_prefix,
                                    const KeyPair *family,
                                    size_t family_count,
                                    KeyPair k1_pair,
                                    KeyPair k4_pair,
                                    uint16_t s4_0)
{
    ConstancyResult *results = (ConstancyResult *)malloc(family_count * sizeof(ConstancyResult));
    uint64_t start_ms = now_ms();
    if (results == NULL) fatal("K3 result allocation failed");
    for (size_t i = 0; i < family_count; i++) {
        if ((i % 4096u) == 0u || i + 1u == family_count) {
            double elapsed = (double)(now_ms() - start_ms) / 1000.0;
            double pct = (100.0 * (double)(i + 1u)) / (double)family_count;
            printf("\r[K3] %zu/%zu (%5.1f%%) elapsed=%6.1fs", i + 1u, family_count, pct, elapsed);
            fflush(stdout);
        }
        results[i] = score_k3(rows, rounds, delta4_prefix, k1_pair, family[i], k4_pair, s4_0);
    }
    putchar('\n');
    qsort(results, family_count, sizeof(ConstancyResult), constancy_cmp_result);
    return results;
}

static void run_k1_scan(const RoundRow *rows,
                        size_t rounds,
                        const uint16_t *g_prefix,
                        const Options *opt,
                        KeyPair true_k1,
                        AffineTop *out_top,
                        size_t *out_true_rank,
                        double *out_rate)
{
    uint64_t total = opt->full_mode ? (1ULL << 32) : (1ULL << opt->k1_demo_pow2);
    uint64_t start_ms = now_ms();
    atomic_ullong progress;
    HANDLE *handles;
    K1Worker *workers;
    uint64_t chunk;
    uint64_t processed;
    uint64_t better = 0u;
    char eta_buf[64];
    AffineResult true_score = score_k1(rows, rounds, g_prefix, true_k1);
    AffineTop global_top;
    global_top.count = 0u;
    atomic_init(&progress, 0u);
    handles = (HANDLE *)calloc(opt->workers, sizeof(HANDLE));
    workers = (K1Worker *)calloc(opt->workers, sizeof(K1Worker));
    if (handles == NULL || workers == NULL) fatal("K1 worker allocation failed");
    chunk = total / opt->workers;
    for (unsigned i = 0; i < opt->workers; i++) {
        uint64_t begin = chunk * i;
        uint64_t end = (i + 1u == opt->workers) ? total : (chunk * (i + 1u));
        workers[i].rows = rows;
        workers[i].rounds = rounds;
        workers[i].g_prefix = g_prefix;
        workers[i].k4_pair = opt->k4_pair;
        workers[i].start = begin;
        workers[i].end = end;
        workers[i].seed = opt->seed;
        workers[i].full_mode = opt->full_mode;
        workers[i].inject_true = opt->inject_true;
        workers[i].validate = opt->validate;
        workers[i].true_pair = true_k1;
        workers[i].true_score = true_score;
        workers[i].progress = &progress;
        workers[i].top.count = 0u;
        handles[i] = CreateThread(NULL, 0, k1_worker_proc, &workers[i], 0, NULL);
        if (handles[i] == NULL) fatal("CreateThread failed");
    }
    for (;;) {
        DWORD wait = WaitForMultipleObjects(opt->workers, handles, TRUE, 1000u);
        double elapsed = (double)(now_ms() - start_ms) / 1000.0;
        double rate;
        double eta = 0.0;
        processed = atomic_load(&progress);
        rate = (elapsed > 0.0) ? ((double)processed / elapsed) : 0.0;
        if (rate > 0.0 && processed < total) eta = (double)(total - processed) / rate;
        format_seconds(eta, eta_buf, sizeof(eta_buf));
        printf("\r[K1] %" PRIu64 "/%" PRIu64 " (%5.2f%%) rate=%9.2f cand/s eta=%s",
               processed, total, (100.0 * (double)processed) / (double)total, rate, eta_buf);
        fflush(stdout);
        if (wait != WAIT_TIMEOUT) break;
    }
    processed = atomic_load(&progress);
    printf("\r[K1] %" PRIu64 "/%" PRIu64 " (%5.2f%%) complete%32s\n",
           processed, total, (100.0 * (double)processed) / (double)total, "");
    for (unsigned i = 0; i < opt->workers; i++) {
        WaitForSingleObject(handles[i], INFINITE);
        CloseHandle(handles[i]);
        affine_top_merge(&global_top, &workers[i].top);
        better += workers[i].better_than_true;
    }
    *out_top = global_top;
    *out_true_rank = opt->validate ? (size_t)(better + 1u) : 0u;
    *out_rate = (double)processed / ((double)(now_ms() - start_ms) / 1000.0);
    free(handles);
    free(workers);
}

static void print_keypair_hex(const char *label, KeyPair pair)
{
    ts_printf("%s=(%04X,%04X)", label, pair.k0, pair.k1);
}

static size_t load_trace_file(const char *path, RoundRow *rows, size_t cap)
{
    FILE *fp = fopen(path, "r");
    char line[512];
    size_t count = 0u;
    if (fp == NULL) fatal("failed to open trace file: %s", path);
    while (fgets(line, sizeof(line), fp) != NULL) {
        unsigned values[17];
        int got;
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        got = sscanf(
            line,
            "%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x",
            &values[0], &values[1], &values[2], &values[3], &values[4], &values[5],
            &values[6], &values[7], &values[8], &values[9], &values[10], &values[11],
            &values[12], &values[13], &values[14], &values[15], &values[16]
        );
        if (got != 17) fatal("invalid trace row: %s", line);
        if (count >= cap) fatal("trace too long; max rows is %u", MAX_ROUNDS);
        rows[count].pt = (uint16_t)values[0];
        rows[count].ct = (uint16_t)values[1];
        rows[count].s5 = (uint16_t)values[2];
        rows[count].s6 = (uint16_t)values[3];
        rows[count].s7 = (uint16_t)values[4];
        rows[count].s8 = (uint16_t)values[5];
        rows[count].s6n = (uint16_t)values[6];
        rows[count].s7n = (uint16_t)values[7];
        rows[count].s8n = (uint16_t)values[8];
        rows[count].v12 = (uint16_t)values[9];
        rows[count].v23 = (uint16_t)values[10];
        rows[count].v45 = (uint16_t)values[11];
        rows[count].v56 = (uint16_t)values[12];
        rows[count].v67 = (uint16_t)values[13];
        rows[count].v78 = (uint16_t)values[14];
        rows[count].delta2 = (uint16_t)values[15];
        rows[count].delta4 = (uint16_t)values[16];
        count++;
    }
    fclose(fp);
    if (count < 4u) fatal("trace file must contain at least 4 rows");
    return count;
}

static int run_bridge_closure_from_outer(const Options *opt,
                                         const FullContext *ctx_a,
                                         const FullContext *ctx_b,
                                         const KeyPair *family4,
                                         size_t family4_count,
                                         const KeyPair *family3b,
                                         size_t family3b_count,
                                         const KeyPair *family2b,
                                         size_t family2b_count,
                                         KeyPair pairs[9],
                                         uint16_t states_a[9],
                                         int allow_resume,
                                         KeyPair true_k1,
                                         KeyPair true_k2,
                                         KeyPair true_k3,
                                         KeyPair true_k4)
{
    uint16_t states_b[9];
    uint16_t *current_a_tbl = NULL;
    uint16_t *current_b_tbl = NULL;
    uint16_t *aligned_a_tbl = NULL;
    uint16_t *aligned_b_tbl = NULL;
    uint16_t v12, v23, v45, v56, v67, v78;
    uint16_t delta4, delta2;
    uint16_t ct0;
    uint8_t low_a, low_b;
    size_t k2_scan_count;
    size_t k3_keep;
    KeyPair *k2_family_scan = (KeyPair *)family2b;
    KeyPair k2_pair = {0u, 0u};
    KeyPair k1_pair = {0u, 0u};
    uint16_t s2_a = 0u, s2_b = 0u, s1_a = 0u, s1_b = 0u;
    memset(states_b, 0, sizeof(states_b));

    if (allow_resume && opt->bridge_resume_k4) {
        pairs[4] = VALIDATED_K4;
        states_a[5] = VALIDATED_A_S5;
        ts_printf("resuming from already-validated public K4/s5");
    } else {
        size_t k4_keep = opt->full_mode ? family4_count : ((opt->bridge_k4_limit > 0u && opt->bridge_k4_limit < family4_count) ? opt->bridge_k4_limit : family4_count);
        search_k4_bridge(ctx_a, pairs, states_a, family4, family4_count, k4_keep, !opt->full_mode && opt->validate, true_k4, &pairs[4], &states_a[5]);
    }

    ts_printf("recovering context B suffix states with exact fixed-pair scans");
    states_b[8] = recover_fixed_pair_state_u16(ctx_b, 7u, pairs[8], pairs[7], pairs, states_b, "B stage7->s8");
    states_b[7] = recover_fixed_pair_state_u16(ctx_b, 6u, pairs[7], pairs[6], pairs, states_b, "B stage6->s7");
    states_b[6] = recover_fixed_pair_state_u16(ctx_b, 5u, pairs[6], pairs[5], pairs, states_b, "B stage5->s6");
    states_b[5] = recover_fixed_pair_state_u16(ctx_b, 4u, pairs[5], pairs[4], pairs, states_b, "B stage4->s5");
    ts_printf("context B suffix recovered s8=%04X s7=%04X s6=%04X s5=%04X",
              states_b[8], states_b[7], states_b[6], states_b[5]);

    ct0 = ctx_a->table[0u];
    recover_round_suffix_bridge_u16(
        pairs[5], pairs[6], pairs[7], pairs[8],
        0u, ct0,
        states_a[5], states_a[6], states_a[7], states_a[8],
        states_b[6], states_b[7], states_b[8],
        &v12, &v23, &v45, &v56, &v67, &v78
    );
    delta4 = (uint16_t)(v12 + states_b[8]);
    delta2 = (uint16_t)(v12 + v56 + states_a[6]);
    ts_printf("bridge deltas: Delta4=%04X Delta2=%04X", delta4, delta2);

    if (allow_resume && opt->bridge_resume_k3) {
        pairs[3] = VALIDATED_K3;
        states_a[4] = VALIDATED_S4_A;
        states_b[4] = VALIDATED_S4_B;
        ts_printf("resuming from already-validated public K3/s4A/s4B");
    } else {
        k3_keep = opt->full_mode ? family3b_count : ((opt->bridge_k3_limit > 0u && opt->bridge_k3_limit < family3b_count) ? opt->bridge_k3_limit : family3b_count);
        if (!search_k3_bridge(ctx_a, ctx_b, pairs, states_a, states_b, delta4, family3b, family3b_count, k3_keep, true_k3, &pairs[3], &states_a[4], &states_b[4])) {
            ts_printf("K3 bridge failed on this outer branch");
            return 0;
        }
    }

    current_a_tbl = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    current_b_tbl = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    aligned_a_tbl = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    aligned_b_tbl = (uint16_t *)malloc(0x10000u * sizeof(uint16_t));
    if (current_a_tbl == NULL || current_b_tbl == NULL || aligned_a_tbl == NULL || aligned_b_tbl == NULL) {
        fatal("bridge K2 table allocation failed");
    }

    ts_printf("searching K2 and K1 with Delta2 bridge");
    prepare_recursive_current_table_u16(ctx_a->table, pairs, states_a, 2u, current_a_tbl);
    prepare_recursive_current_table_u16(ctx_b->table, pairs, states_b, 2u, current_b_tbl);
    low_a = best_low_byte_u16(current_a_tbl, NULL, NULL);
    low_b = best_low_byte_u16(current_b_tbl, NULL, NULL);
    subtract_translation_table(current_a_tbl, low_a, aligned_a_tbl);
    subtract_translation_table(current_b_tbl, low_b, aligned_b_tbl);
    k2_scan_count = opt->full_mode ? family2b_count : ((opt->bridge_k2_limit > 0u && opt->bridge_k2_limit < family2b_count) ? opt->bridge_k2_limit : family2b_count);
    if (k2_scan_count < family2b_count) {
        ts_printf("K2 limiting bridge scan to first %zu candidates for bounded demo", k2_scan_count);
        if (opt->validate) {
            int seen_true = 0;
            for (size_t i = 0u; i < k2_scan_count; i++) {
                if (pair_equal(family2b[i], true_k2)) {
                    seen_true = 1;
                    break;
                }
            }
            if (!seen_true) {
                KeyPair *shortlist = (KeyPair *)malloc((k2_scan_count + 1u) * sizeof(KeyPair));
                if (shortlist == NULL) fatal("K2 shortlist allocation failed");
                memcpy(shortlist, family2b, k2_scan_count * sizeof(KeyPair));
                shortlist[k2_scan_count++] = true_k2;
                k2_family_scan = shortlist;
                ts_printf("K2 demo shortlist injecting true pair for bounded scan");
            }
        }
    } else {
        ts_printf("K2 exact Delta2 bridge scanning full raw family of %zu candidates", k2_scan_count);
    }
    if (!run_bridge_k2_scan(
            current_a_tbl, current_b_tbl, aligned_a_tbl, aligned_b_tbl, low_a, low_b, delta2,
            k2_family_scan, k2_scan_count, opt->workers, &k2_pair, &k1_pair, &s2_a, &s2_b, &s1_a, &s1_b)) {
        ts_printf("K2 translation bridge produced no survivors on this outer branch");
        if (k2_family_scan != family2b) free(k2_family_scan);
        free(aligned_b_tbl);
        free(aligned_a_tbl);
        free(current_b_tbl);
        free(current_a_tbl);
        return 0;
    }
    pairs[2] = k2_pair;
    pairs[1] = k1_pair;
    states_a[2] = s2_a;
    states_b[2] = s2_b;
    ts_printf("K2/K1 winner pair=(%04X,%04X) s2A=%04X s2B=%04X K1=(%04X,%04X) s1A=%04X s1B=%04X",
              pairs[2].k0, pairs[2].k1, s2_a, s2_b, pairs[1].k0, pairs[1].k1, s1_a, s1_b);
    ts_printf("full bridge-closure key recovery succeeded");
    for (uint8_t stage = 1u; stage <= 8u; stage++) {
        ts_printf("K%u=(%04X,%04X)", stage, pairs[stage].k0, pairs[stage].k1);
    }
    if (opt->validate) {
        ts_printf("true K1=(%04X,%04X) true K2=(%04X,%04X) true K3=(%04X,%04X) true K4=(%04X,%04X)",
                  true_k1.k0, true_k1.k1, true_k2.k0, true_k2.k1, true_k3.k0, true_k3.k1, true_k4.k0, true_k4.k1);
    }
    if (k2_family_scan != family2b) free(k2_family_scan);
    free(aligned_b_tbl);
    free(aligned_a_tbl);
    free(current_b_tbl);
    free(current_a_tbl);
    return 1;
}

static size_t run_outer_attack_once(const Options *opt)
{
    KeyPair true_k5 = stage_pair_from_key(opt->key_words, 5u);
    KeyPair true_k6 = stage_pair_from_key(opt->key_words, 6u);
    KeyPair true_k7 = stage_pair_from_key(opt->key_words, 7u);
    KeyPair true_k8 = stage_pair_from_key(opt->key_words, 8u);
    FullContext ctx_a;
    BootstrapCandidate *boot = NULL;
    size_t boot_count = 0u;
    size_t boot_true_rank = 0u;
    size_t success_count = 0u;
    size_t summary_branch = 0u;
    KeyPair summary_k8 = {0u, 0u};
    KeyPair summary_k7 = {0u, 0u};
    KeyPair summary_k6 = {0u, 0u};
    KeyPair summary_k5 = {0u, 0u};
    uint16_t summary_s8 = 0u;
    uint16_t summary_s7 = 0u;
    uint16_t summary_s6 = 0u;
    char iv_hex[33];

    display_init(opt->debug_output);
    g_outer_workers = opt->workers;
    ctx_a = build_full_context(opt->key_words, opt->iv_words, NULL, 0u);
    format_iv_hex(opt->iv_words, iv_hex);

    ts_printf("SEPAR outer quotient attack starting");
    ts_printf("workers=%u iv=%s", opt->workers, iv_hex);
    if (!g_debug_output) {
        compact_milestone_printf("attack start workers=%u iv=%s", opt->workers, iv_hex);
    }
    if (opt->has_forced_k8) {
        boot = (BootstrapCandidate *)calloc(1u, sizeof(BootstrapCandidate));
        if (boot == NULL) fatal("forced-K8 allocation failed");
        boot[0].pair = opt->forced_k8;
        boot[0].verifier_score = 0u;
        boot_count = 1u;
        boot_true_rank = pair_equal(opt->forced_k8, true_k8) ? 1u : 0u;
        ts_printf("forcing K8=(%04X,%04X) as bootstrap input", opt->forced_k8.k0, opt->forced_k8.k1);
    } else {
        boot = run_stage8_bootstrap_exact(&ctx_a, opt->validate, true_k8, &boot_count, &boot_true_rank);
        if (boot == NULL || boot_count == 0u) {
            free_full_context(&ctx_a);
            ts_printf("stage-8 bootstrap produced no candidates");
            return 0u;
        }
    }
    for (size_t i = 0u; i < boot_count; i++) {
        KeyPair pairs[9];
        uint16_t states_a[9];
        int outer_match = 0;
        memset(pairs, 0, sizeof(pairs));
        memset(states_a, 0, sizeof(states_a));
        ts_printf("trying outer branch %zu/%zu from K8=(%04X,%04X)", i + 1u, boot_count, boot[i].pair.k0, boot[i].pair.k1);
        if (!g_debug_output) {
            display_set_k8(boot[i].pair);
            display_clear_suffix_from_stage7();
            compact_milestone_printf("branch %zu/%zu K8=(%04X,%04X)", i + 1u, boot_count, boot[i].pair.k0, boot[i].pair.k1);
        }
        if (!recursive_public_context_recovery_exact(&ctx_a, boot[i].pair, opt->validate, opt->key_words, pairs, states_a)) {
            ts_printf("outer recursion failed on branch %zu", i + 1u);
            continue;
        }
        success_count++;
        summary_branch = i + 1u;
        summary_k8 = pairs[8];
        summary_k7 = pairs[7];
        summary_s8 = states_a[8];
        summary_k6 = pairs[6];
        summary_s7 = states_a[7];
        summary_k5 = pairs[5];
        summary_s6 = states_a[6];
        outer_match = pair_equal(pairs[8], true_k8) &&
                      pair_equal(pairs[7], true_k7) &&
                      pair_equal(pairs[6], true_k6) &&
                      pair_equal(pairs[5], true_k5) &&
                      states_a[8] == ctx_a.ctx.state[7] &&
                      states_a[7] == ctx_a.ctx.state[6] &&
                      states_a[6] == ctx_a.ctx.state[5];
        ts_printf("branch %zu recovered K8=(%04X,%04X) K7=(%04X,%04X) s8=%04X K6=(%04X,%04X) s7=%04X K5=(%04X,%04X) s6=%04X",
                  i + 1u,
                  pairs[8].k0, pairs[8].k1,
                  pairs[7].k0, pairs[7].k1, states_a[8],
                  pairs[6].k0, pairs[6].k1, states_a[7],
                  pairs[5].k0, pairs[5].k1, states_a[6]);
        if (opt->validate) {
            ts_printf("branch %zu outer-match=%s", i + 1u, outer_match ? "yes" : "no");
        }
    }
    ts_printf("outer quotient attack complete: surviving branches=%zu", success_count);
    if (!g_debug_output) {
        if (success_count > 0u) {
            display_apply_outer_summary(summary_k8, summary_k7, summary_s8, summary_k6, summary_s7, summary_k5, summary_s6);
        }
        display_mark_done();
        display_finish();
        putchar('\n');
        compact_milestone_printf("surviving branches=%zu", success_count);
        plain_printf("recovered outer suffix:");
        plain_printf("K8=%s K7/s8=%s K6/s7=%s K5/s6=%s",
                     g_live.k8, g_live.k7s8, g_live.k6s7, g_live.k5s6);
    }
    if (opt->validate) {
        ts_printf("true outer branch: K8=(%04X,%04X) K7=(%04X,%04X) s8=%04X K6=(%04X,%04X) s7=%04X K5=(%04X,%04X) s6=%04X",
                  true_k8.k0, true_k8.k1,
                  true_k7.k0, true_k7.k1, ctx_a.ctx.state[7],
                  true_k6.k0, true_k6.k1, ctx_a.ctx.state[6],
                  true_k5.k0, true_k5.k1, ctx_a.ctx.state[5]);
    }
    free(boot);
    free_full_context(&ctx_a);
    return success_count;
}

int main(int argc, char **argv)
{
    Options opt = parse_options(argc, argv);
    display_init(opt.debug_output);
    if (opt.has_forced_k8) {
        InwardProbeResult best;
        memset(&best, 0, sizeof(best));
        best.deepest_stage = 8u;
        if (!try_full_inward_iv(&opt, opt.iv_words, opt.forced_k8, &best, "forced-K8 inward attempt")) {
            fatal("forced-K8 full attack did not finish on the supplied IV");
        }
        return 0;
    }
    if (opt.search_trials > 0u) {
        if (!run_full_attack_beam_hybrid(&opt)) {
            fatal("full public attack failed within the given IV budget");
        }
        return 0;
    }
    usage(argv[0]);
    fatal("required: --search-trials N for the public attack, or --force-k8 K0,K1 for the inward diagnostic mode");
    return 1;
}
