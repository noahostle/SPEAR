#ifndef SEPAR_ROW_SCREEN_H
#define SEPAR_ROW_SCREEN_H
#include <stdint.h>

static void largest_two(const uint16_t *label,unsigned n,unsigned *first,unsigned *second) {
    unsigned counts[16]={0}; *first=0; *second=0;
    for(unsigned i=0;i<n;i++) {
        unsigned j=0;
        while(j<i && label[j]!=label[i]) j++;
        counts[j]++;
    }
    for(unsigned i=0;i<n;i++) {
        unsigned v=counts[i];
        if(v>*first) {*second=*first; *first=v;} else if(v>*second) *second=v;
    }
}
static unsigned possible_subset(const uint16_t *values,unsigned n,unsigned allowed,unsigned errors) {
    unsigned result=0;
    if(n==errors+3) {
        /* These points need three in two classes: this is equivalent to one
         * repeated label. Only equal or adjacent original labels can merge. */
        for(unsigned i=0;i<n;i++) for(unsigned j=0;j<i;j++) {
            unsigned delta=((values[i]>>4)-(values[j]>>4))&4095;
            if(delta>1 && delta<4095) continue;
            for(unsigned c=0;c<16;c++)
                if(((uint16_t)(values[i]-c)>>4)==((uint16_t)(values[j]-c)>>4)) result|=1u<<c;
        }
    } else for(unsigned c=0;c<16;c++) if(allowed&(1u<<c)) {
        uint16_t labels[16]; unsigned a,b;
        for(unsigned i=0;i<n;i++) labels[i]=(uint16_t)(values[i]-c)>>4;
        largest_two(labels,n,&a,&b);
        if(a+b+errors>=n) result|=1u<<c;
    }
    return result;
}
static unsigned screen_partial(const uint16_t values[31],unsigned n,unsigned mask[16],unsigned errors) {
    unsigned allowed=0,alive=0;
    for(unsigned c=0;c<16;c++) if(mask[c]) allowed|=1u<<c;
    unsigned left=possible_subset(values+16-n,n,allowed,errors),right=possible_subset(values+15,n,allowed,errors);
    for(unsigned c=0;c<16;c++) {
        if(!(left&(1u<<c))) mask[c]&=~((1u<<(17-n))-1);
        if(!(right&(1u<<c))) mask[c]&=(1u<<(n-1))-1;
        alive|=mask[c];
    }
    return alive;
}
static unsigned screen_shifted_strip(const uint16_t values[31],unsigned mask[16],unsigned errors) {
    unsigned alive=0;
    for(unsigned c=0;c<16;c++) if(mask[c]) {
        uint16_t label[31];
        for(unsigned i=0;i<31;i++) label[i]=(uint16_t)(values[i]-c)>>4;
        for(unsigned r=0;r<16;r++) if(mask[c]&(1u<<r)) {
            unsigned first,second;
            largest_two(label+r,16,&first,&second);
            if(first+second<16-errors || first+2*second<=16) mask[c]&=~(1u<<r);
        }
        alive|=mask[c];
    }
    return alive;
}
#endif
