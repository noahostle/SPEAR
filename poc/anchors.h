/* Four-round inverse-initialization cone, consolidated prior work.
 * Only the stated known suffix entries are read from key/state arrays. */
static uint16_t cone_s1(const uint16_t s[8], const uint16_t iv[8], const uint16_t key[16]) {
    uint16_t a[4], answer = iv[0];
    memcpy(a, s + 4, sizeof a);
    for (unsigned r = 0; r < 4; r++) {
        answer = (uint16_t)(answer + ENC_Block(a[3], key + 14, 8));
        for (unsigned j = 3; j > r; j--)
            a[j] = (uint16_t)(a[j] - ENC_Block(a[j - 1], key + 2 * (3 + j), (uint8_t)(4 + j)));
    }
    return answer;
}
/* For t=2,3,4: obtain E_t(s_t) from s_(t+1)..s_(t+4), IV_(t+4),
 * and K_(t+1)..K_(t+3). In particular K_t is NOT consulted. */
static uint16_t cone_anchor(const uint16_t s[8], const uint16_t iv[8], const uint16_t key[16],
                            unsigned t) {
    uint16_t row[4][4] = {{0}};
    memcpy(row[0], s + t, sizeof row[0]);
    for (unsigned r = 1; r < 4; r++)
        for (unsigned j = r; j < 4; j++)
            row[r][j] =
                (uint16_t)(row[r - 1][j] -
                           ENC_Block(row[r - 1][j - 1], key + 2 * (t + j - 1), (uint8_t)(t + j)));
    uint16_t x = iv[t + 3];
    for (unsigned j = 3; j; j--)
        x = DEC_Block((uint16_t)(row[j][j] - x), key + 2 * (t + j - 1), (uint8_t)(t + j));
    return (uint16_t)(s[t] - x);
}
