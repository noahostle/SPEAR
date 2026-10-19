/* Exact sliding version of dominant_pair's acceptance predicate. The caller
 * supplies 31 public outputs; bit r denotes their length-16 window at r.
 * No probability model, key or internal state is used. */
#ifndef SEPAR_ROW_SCREEN_H
#define SEPAR_ROW_SCREEN_H
#include <stdint.h>
static unsigned screen_count(uint8_t count[4096], unsigned bins[17], unsigned bits, unsigned label,
                             int step) {
    unsigned old = count[label], now = (unsigned)((int)old + step);
    if (old && !--bins[old]) bits &= ~(1u << old);
    count[label] = (uint8_t)now;
    if (now && !bins[now]++) bits |= 1u << now;
    return bits;
}
/* Any n samples in a sufficient inward row have at most three points
 * outside their two largest labels. Slide all sixteen output translations. */
static unsigned partial_labels(const uint16_t *values,unsigned n) {
    static uint8_t count[4096];
    unsigned bins[17]={0},bits=0,accepted=0;
    for(unsigned i=0;i<n;i++) bits=screen_count(count,bins,bits,values[i]>>4,1);
    for(unsigned c=0;c<16;c++) {
        unsigned a=31u-(unsigned)__builtin_clz(bits),rest=bits&~(1u<<a);
        unsigned b=bins[a]>1?a:(rest?31u-(unsigned)__builtin_clz(rest):0);
        if(a+b+3>=n) accepted|=1u<<c;
        if(c<15) for(unsigned i=0;i<n;i++) if((values[i]&15)==c) {
            bits=screen_count(count,bins,bits,values[i]>>4,-1);
            bits=screen_count(count,bins,bits,((values[i]>>4)-1)&4095,1);
        }
    }
    for(unsigned i=0;i<n;i++) count[(uint16_t)(values[i]-15)>>4]=0;
    return accepted;
}
static unsigned screen_partial(const uint16_t values[31],unsigned n,unsigned mask[16]) {
    unsigned left=partial_labels(values+16-n,n),right=partial_labels(values+15,n),alive=0;
    for(unsigned c=0;c<16;c++) {
        if(!(left&(1u<<c))) mask[c]&=~((1u<<(17-n))-1);
        if(!(right&(1u<<c))) mask[c]&=(1u<<(n-1))-1;
        alive|=mask[c];
    }
    return alive;
}
static unsigned screen_shifted_strip(const uint16_t values[31], unsigned mask[16],unsigned support) {
    static uint8_t count[4096];
    unsigned alive = 0;
    for (unsigned c = 0; c < 16; c++)
        if (mask[c]) {
            uint16_t label[31];
            unsigned bins[17] = {0}, bits = 0, next = 0;
            for (unsigned i = 0; i < 31; i++) label[i] = (uint16_t)((uint16_t)(values[i] - c) >> 4);
            for (unsigned i = 0; i < 16; i++) bits = screen_count(count, bins, bits, label[i], 1);
            for (unsigned r = 0; r < 16; r++) {
                unsigned a = 31u - (unsigned)__builtin_clz(bits), rest = bits & ~(1u << a);
                unsigned b = bins[a] > 1 ? a : (rest ? 31u - (unsigned)__builtin_clz(rest) : 0);
                if (support ? a+b>=9 : a+b>=13 && a+2*b>16) next|=1u<<r;
                if (r < 15 && label[r] != label[r + 16]) {
                    bits = screen_count(count, bins, bits, label[r], -1);
                    bits = screen_count(count, bins, bits, label[r + 16], 1);
                }
            }
            for (unsigned i = 15; i < 31; i++) count[label[i]] = 0;
            mask[c] &= next;
            alive |= mask[c];
        }
    return alive;
}
#endif
