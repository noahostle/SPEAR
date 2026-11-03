#ifndef SEPAR_QUOTIENT_LIFT_H
#define SEPAR_QUOTIENT_LIFT_H
static unsigned quotient_value(const uint16_t q[4][4096], unsigned n,
                               const unsigned shifts[4], unsigned x) {
    for (unsigned j=0;j<n;j++) x=(q[j][x]+shifts[j])&4095;
    return x;
}
static void quotient_lift(const uint16_t q[4][4096], unsigned n, const uint16_t w[4096],
                          const unsigned h[4], unsigned origin, unsigned reverse,
                          void (*emit)(const unsigned[4])) {
    for (unsigned trial=0;trial<(1u<<(4*n));trial++) {
        unsigned u=trial&15, shifts[4]={0};
        for (unsigned j=0;j+1<n;j++) shifts[j]=h[j]+256*((trial>>(4*(j+1)))&15);
        unsigned value=quotient_value(q,n,shifts,256*u);
        shifts[n-1]=(w[origin]-value)&4095;
        if ((shifts[n-1]&255)!=h[n-1]) continue;
        /* Spaced probes reject wrong top choices. Acceptance uses all entries. */
        unsigned a=1;
        for (;a<16;a++) {
            unsigned x=256*a;
            if (quotient_value(q,n,shifts,(x+256*u)&4095)!=
                w[(origin+(reverse?-x:x))&4095]) break;
        }
        if (a<16) continue;
        unsigned x=0;
        for (;x<4096;x++)
            if (quotient_value(q,n,shifts,(x+256*u)&4095)!=
                w[(origin+(reverse?-x:x))&4095]) break;
        if (x==4096) emit(shifts);
    }
}
#endif
