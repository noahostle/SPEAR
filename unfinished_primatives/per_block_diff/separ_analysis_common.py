import ctypes
from pathlib import Path


S1 = [1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4]
S2 = [6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8]
S3 = [12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13, 15, 4]
S4 = [13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14]

IS1 = [4, 0, 3, 5, 15, 6, 8, 11, 7, 9, 13, 2, 10, 12, 14, 1]
IS2 = [12, 8, 7, 13, 3, 14, 0, 9, 15, 6, 1, 11, 10, 5, 4, 2]
IS3 = [4, 3, 1, 5, 15, 6, 2, 8, 7, 9, 12, 10, 0, 13, 11, 14]
IS4 = [4, 11, 2, 5, 13, 6, 8, 3, 7, 14, 12, 1, 9, 0, 15, 10]

DEFAULT_KEY = [
    0xE8B9, 0xB733, 0xDA5D, 0x96D7, 0x02DD, 0x3972, 0xE953, 0x07FD,
    0x50C5, 0x12DB, 0xF44A, 0x233E, 0x8D1E, 0x9DF5, 0xFC7D, 0x6371,
]
DEFAULT_IV = [0x0000] * 8


def rotl16(x, y):
    y &= 15
    return ((x << y) | (x >> (16 - y))) & 0xFFFF


def rotr16(x, y):
    y &= 15
    return ((x >> y) | (x << (16 - y))) & 0xFFFF


def do_sbox(x):
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF
    return (S1[a] << 12) | (S2[b] << 8) | (S3[c] << 4) | S4[d]


def do_isbox(x):
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF
    return (IS1[a] << 12) | (IS2[b] << 8) | (IS3[c] << 4) | IS4[d]


def sep_rotl16(x):
    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF

    a ^= c
    b ^= d
    c ^= b
    d ^= a

    x = ((a << 12) | (b << 8) | (c << 4) | d) & 0xFFFF
    return (x ^ rotl16(x, 12) ^ rotl16(x, 8)) & 0xFFFF


def sep_inrotl16(x):
    y = rotr16(x, 12)
    z = rotr16(x, 8)
    x ^= y ^ z
    x &= 0xFFFF

    a = (x >> 12) & 0xF
    b = (x >> 8) & 0xF
    c = (x >> 4) & 0xF
    d = x & 0xF

    d ^= a
    c ^= b
    b ^= d
    a ^= c

    return ((a << 12) | (b << 8) | (c << 4) | d) & 0xFFFF


def derive_key23(key0, key1, stage_n):
    key2 = rotl16(key0, 6)
    b = (key2 >> 6) & 0xF
    key2 |= S1[b] << 6
    key2 ^= (stage_n + 2)
    key2 &= 0xFFFF

    key3 = rotl16(key1, 10)
    b = (key3 >> 6) & 0xF
    key3 |= S1[b] << 6
    key3 ^= (stage_n + 3)
    key3 &= 0xFFFF

    return key2, key3


def enc_block(pt, key_pair, stage_n):
    key0, key1 = key_pair
    key2, key3 = derive_key23(key0, key1, stage_n)

    t = pt ^ key0
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= key1
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= key2
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= key3
    t = do_sbox(t)
    t = sep_rotl16(t)

    t ^= key1 ^ key0
    t = do_sbox(t)
    t ^= key2 ^ key3
    return t & 0xFFFF


def dec_block(ct, key_pair, stage_n):
    key0, key1 = key_pair
    key2, key3 = derive_key23(key0, key1, stage_n)

    t = (ct ^ key3 ^ key2) & 0xFFFF
    t = do_isbox(t)
    t ^= key0 ^ key1
    t &= 0xFFFF

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= key3
    t &= 0xFFFF

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= key2
    t &= 0xFFFF

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= key1
    t &= 0xFFFF

    t = sep_inrotl16(t)
    t = do_isbox(t)
    t ^= key0
    return t & 0xFFFF


def parse_hex_word(token):
    token = token.strip().lower()
    if token.startswith("0x"):
        token = token[2:]
    if not token:
        raise ValueError("empty hex token")
    return int(token, 16) & 0xFFFF


def parse_word_list(text):
    if not text.strip():
        return []
    return [parse_hex_word(part) for part in text.split(",")]


def parse_key_pair(text):
    parts = parse_word_list(text)
    if len(parts) != 2:
        raise ValueError(f"expected exactly two 16-bit words, got {len(parts)}")
    return tuple(parts)


def parse_full_key_hex(text):
    cleaned = text.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 64:
        raise ValueError("full key must be exactly 64 hex chars (16 x 16-bit words)")
    return [int(cleaned[i:i + 4], 16) for i in range(0, 64, 4)]


def parse_full_iv_hex(text):
    cleaned = text.strip().lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) != 32:
        raise ValueError("IV must be exactly 32 hex chars (8 x 16-bit words)")
    return [int(cleaned[i:i + 4], 16) for i in range(0, 32, 4)]


def build_table_from_function(func):
    return [func(x) for x in range(0x10000)]


def scan_table_for_input_diff(table, input_diff, mode, topn):
    counts = [0] * 0x10000
    touched = []

    if mode == "xor":
        for x in range(0x10000):
            out_diff = table[x] ^ table[x ^ input_diff]
            if counts[out_diff] == 0:
                touched.append(out_diff)
            counts[out_diff] += 1
    elif mode == "add":
        for x in range(0x10000):
            out_diff = (table[(x + input_diff) & 0xFFFF] - table[x]) & 0xFFFF
            if counts[out_diff] == 0:
                touched.append(out_diff)
            counts[out_diff] += 1
    else:
        raise ValueError(f"unsupported mode: {mode}")

    hits = sorted(
        ((counts[out_diff], out_diff) for out_diff in touched),
        key=lambda item: (-item[0], item[1]),
    )
    return hits[:topn]


def best_count(table, input_diff, mode):
    return scan_table_for_input_diff(table, input_diff, mode, topn=1)[0]


class SeparOracle:
    def __init__(self, dll_path=None):
        if dll_path is None:
            here = Path(__file__).resolve()
            candidates = [
                here.parent / "SEPAR" / "SEPAR.dll",
                here.parent.parent / "SEPAR" / "SEPAR.dll",
                here.parent.parent.parent / "SEPAR" / "SEPAR.dll",
            ]
            for candidate in candidates:
                if candidate.exists():
                    dll_path = candidate
                    break
            else:
                raise FileNotFoundError("could not locate SEPAR/SEPAR.dll relative to separ_analysis_common.py")
        self.lib = ctypes.CDLL(str(dll_path))

        self.enc = self.lib.separ_encrypt_words
        self.enc.argtypes = [
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(ctypes.c_uint16),
        ]
        self.enc.restype = ctypes.c_int

        self.dec = self.lib.separ_decrypt_words
        self.dec.argtypes = self.enc.argtypes
        self.dec.restype = ctypes.c_int

    @staticmethod
    def _u16_array(values):
        arr_t = ctypes.c_uint16 * len(values)
        return arr_t(*values)

    def encrypt_words(self, words, key_words, iv_words):
        n = len(words)
        pt = self._u16_array(words)
        ct = (ctypes.c_uint16 * n)()
        key = self._u16_array(key_words)
        iv = self._u16_array(iv_words)
        rc = self.enc(pt, n, key, iv, ct)
        if rc != 0:
            raise RuntimeError(f"encryption failed with code {rc}")
        return list(ct)

    def decrypt_words(self, words, key_words, iv_words):
        n = len(words)
        ct = self._u16_array(words)
        pt = (ctypes.c_uint16 * n)()
        key = self._u16_array(key_words)
        iv = self._u16_array(iv_words)
        rc = self.dec(ct, n, key, iv, pt)
        if rc != 0:
            raise RuntimeError(f"decryption failed with code {rc}")
        return list(pt)


def build_matched_context_codebook(prefix_words, key_words=None, iv_words=None, oracle=None):
    if key_words is None:
        key_words = DEFAULT_KEY
    if iv_words is None:
        iv_words = DEFAULT_IV
    if oracle is None:
        oracle = SeparOracle()

    prefix_words = list(prefix_words)
    prefix_ct = oracle.encrypt_words(prefix_words, key_words, iv_words)
    table = [0] * 0x10000
    for x in range(0x10000):
        ct = oracle.encrypt_words(prefix_words + [x], key_words, iv_words)
        table[x] = ct[-1]
    return prefix_ct, table


def separ_initial_ctx(key_words=None, iv_words=None):
    if key_words is None:
        key_words = list(DEFAULT_KEY)
    if iv_words is None:
        iv_words = list(DEFAULT_IV)

    state = list(iv_words)
    ct = 0
    for _ in range(4):
        v12 = enc_block((state[0] + state[2] + state[4] + state[6]) & 0xFFFF, (key_words[0], key_words[1]), 1)
        v23 = enc_block((v12 + state[1]) & 0xFFFF, (key_words[2], key_words[3]), 2)
        v34 = enc_block((v23 + state[2]) & 0xFFFF, (key_words[4], key_words[5]), 3)
        v45 = enc_block((v34 + state[3]) & 0xFFFF, (key_words[6], key_words[7]), 4)
        v56 = enc_block((v45 + state[4]) & 0xFFFF, (key_words[8], key_words[9]), 5)
        v67 = enc_block((v56 + state[5]) & 0xFFFF, (key_words[10], key_words[11]), 6)
        v78 = enc_block((v67 + state[6]) & 0xFFFF, (key_words[12], key_words[13]), 7)
        ct = enc_block((v78 + state[7]) & 0xFFFF, (key_words[14], key_words[15]), 8)

        state[0] = (state[0] + ct) & 0xFFFF
        state[1] = (state[1] + v12) & 0xFFFF
        state[2] = (state[2] + v23) & 0xFFFF
        state[3] = (state[3] + v34) & 0xFFFF
        state[4] = (state[4] + v45) & 0xFFFF
        state[5] = (state[5] + v56) & 0xFFFF
        state[6] = (state[6] + v67) & 0xFFFF
        state[7] = (state[7] + v78) & 0xFFFF

    return {"state": state, "lfsr": (ct | 0x100) & 0xFFFF}


def separ_encrypt_word(pt, ctx, key_words):
    state = ctx["state"]

    v12 = enc_block((pt + state[0]) & 0xFFFF, (key_words[0], key_words[1]), 1)
    v23 = enc_block((v12 + state[1]) & 0xFFFF, (key_words[2], key_words[3]), 2)
    v34 = enc_block((v23 + state[2]) & 0xFFFF, (key_words[4], key_words[5]), 3)
    v45 = enc_block((v34 + state[3]) & 0xFFFF, (key_words[6], key_words[7]), 4)
    v56 = enc_block((v45 + state[4]) & 0xFFFF, (key_words[8], key_words[9]), 5)
    v67 = enc_block((v56 + state[5]) & 0xFFFF, (key_words[10], key_words[11]), 6)
    v78 = enc_block((v67 + state[6]) & 0xFFFF, (key_words[12], key_words[13]), 7)
    ct = enc_block((v78 + state[7]) & 0xFFFF, (key_words[14], key_words[15]), 8)

    state[1] = (state[1] + v12 + v56 + state[5]) & 0xFFFF
    state[2] = (state[2] + v23 + v34 + state[3] + state[0]) & 0xFFFF
    state[3] = (state[3] + v12 + v45 + state[7]) & 0xFFFF
    state[4] = (state[4] + v23) & 0xFFFF
    state[5] = (state[5] + v12 + v45 + state[6]) & 0xFFFF
    state[6] = (state[6] + v23 + v67) & 0xFFFF
    state[7] = (state[7] + v45) & 0xFFFF
    state[0] = (state[0] + v34 + v23 + state[4] + v78) & 0xFFFF
    ctx["lfsr"] = ((ctx["lfsr"] >> 1) ^ ((-(ctx["lfsr"] & 1)) & 0xCA44)) & 0xFFFF
    state[4] = (state[4] + ctx["lfsr"]) & 0xFFFF

    return ct


def separ_ctx_after_prefix(prefix_words, key_words=None, iv_words=None):
    if key_words is None:
        key_words = list(DEFAULT_KEY)
    if iv_words is None:
        iv_words = list(DEFAULT_IV)

    ctx = separ_initial_ctx(key_words, iv_words)
    for pt in prefix_words:
        separ_encrypt_word(pt, ctx, key_words)
    return ctx
