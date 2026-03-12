//*****************************************************
// main.c
//Arsalan Vahi       email:arsalan.vahi2009@gmail.com
//*******************************************************
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#ifndef ROTL16
#define ROTL16(x, y) (((x)<<(y&(15))) | ((x)>>(16-(y&(15)))))
#define ROTR16(x, y) (((x)>>(y&(15))) | ((x)<<(16-(y&(15)))))
#endif

#if defined(_WIN32)
#define SEPAR_EXPORT __declspec(dllexport)
#else
#define SEPAR_EXPORT __attribute__((visibility("default")))
#endif

typedef struct
{
    uint16_t state_1;       //states
    uint16_t state_2;
    uint16_t state_3;
    uint16_t state_4;
    uint16_t state_5;
    uint16_t state_6;
    uint16_t state_7;
    uint16_t state_8;
    uint16_t lfsr;
} Separ_ctx;

void Separ_Initial_State(Separ_ctx *,const uint16_t key[16],const uint16_t iv[8]);



static inline uint16_t ENC_Block(uint16_t pt, const uint16_t *key, uint8_t n);
static inline uint16_t DEC_Block(uint16_t ct, const uint16_t *key, uint8_t n);

/* Command-line parsing helpers for variable-length plaintext plus optional key/IV overrides. */
static void print_usage(const char *program_name);
static int hex_nibble(char c);
static const char *skip_hex_prefix(const char *hex);
static int parse_hex_words(const char *input, uint16_t *words, size_t expected_words, size_t *parsed_words);
static void print_hex_words(const uint16_t *words, size_t word_count);

static const uint16_t default_key[16] = {
    0xE8b9,0xB733,0xDA5d,0x96D7,0x02DD,0x3972,0xE953,0x07FD,
    0x50C5,0x12DB,0xF44A,0x233E,0x8D1E,0x9DF5,0xFC7D,0x6371
};

static const uint16_t default_iv[8] = {
    0x0000,0x0000,0x0000,0x0000,0x0000,0x0000,0x0000,0x0000
};

// Golden s-boxe 

const uint8_t Separ_sbox1[16] = {1, 15, 11, 2, 0, 3, 5, 8, 6, 9, 12, 7, 13, 10, 14, 4 };
const uint8_t Separ_sbox2[16] = {6, 10, 15, 4, 14, 13, 9, 2, 1, 7, 12, 11, 0, 3, 5, 8 };
const uint8_t Separ_sbox3[16] = {12, 2, 6, 1, 0, 3, 5, 8, 7, 9, 11, 14, 10, 13 , 15, 4 };
const uint8_t Separ_sbox4[16] = {13, 11, 2, 7, 0, 3, 5, 8, 6, 12, 15, 1, 10, 4, 9, 14 };

const uint8_t Separ_isbox1[16] = {4, 0, 3, 5, 15, 6, 8, 11, 7, 9, 13, 2, 10, 12, 14, 1 };
const uint8_t Separ_isbox2[16] = {12, 8 , 7, 13, 3, 14, 0, 9, 15, 6, 1, 11, 10, 5, 4, 2 };
const uint8_t Separ_isbox3[16] = {4, 3, 1, 5, 15, 6 , 2,8, 7 , 9, 12, 10, 0 , 13, 11, 14 };
const uint8_t Separ_isbox4[16] = {4, 11, 2, 5, 13 , 6, 8 ,3 , 7, 14 ,12, 1, 9 ,0, 15, 10};

//****************************************************
static inline uint16_t do_sbox(uint16_t X)
{
    uint8_t a, b, c, d;
    uint16_t y,z;
    uint16_t ret;
    
    a = X >> 12;
    b = X >> 8 & 0xf;
    c = X >> 4 & 0xf;
    d = X & 0xf;
    
    a = Separ_sbox1[a];
    b = Separ_sbox2[b];
    c = Separ_sbox3[c];
    d = Separ_sbox4[d];
    
    X =  a << 12;
    X |= b << 8;
    X |= c << 4;
    X |= d;
    	
    return X;
}
//****************do_isbox*******************
static inline uint16_t do_isbox(uint16_t x)
{
    uint8_t a, b, c, d;
    uint16_t y,z;
    uint16_t ret;
    
    a = x >> 12;
    b = x >> 8 & 0xf;
    c = x >> 4 & 0xf;
    d = x & 0xf;
    
    a = Separ_isbox1[a];
    b = Separ_isbox2[b];
    c = Separ_isbox3[c];
    d = Separ_isbox4[d];
    
        
    ret =  a << 12;
    ret |= b << 8;
    ret |= c << 4;
    ret |= d;

    return ret;
}
//*****************Separ_ROTL16***********************
static inline uint16_t Sep_ROTL16(uint16_t X)
{
    uint16_t y,z;
    uint8_t a, b, c, d;
    
        
	a = X >> 12;
    b = X >> 8 & 0xf;
   	c = X >> 4 & 0xf;
    d = X & 0xf;
		
	a = a ^ c;
	b = b ^ d;
	c = c ^ b;
	d = d ^ a;
			
	X =  a << 12;
    X |= b << 8;
    X |= c << 4;
    X |= d;
    	
    y = ROTL16(X, 12);
    z = ROTL16(X, 8);
    X ^= y ^ z;
    return X;
		
}
//**********************inROTL16*****************************
static inline uint16_t Sep_inROTL16(uint16_t X)
{
    uint16_t y,z;
    uint8_t a, b, c, d;
    
    y = ROTR16(X, 12);
    z = ROTR16(X, 8);
    X ^= y ^ z;
    
	a = X >> 12;
    b = X >> 8 & 0xf;
   	c = X >> 4 & 0xf;
    d = X & 0xf;
	
	d = d ^ a;
	c = c ^ b;
	b = b ^ d;
	a = a ^ c;
	
	X =  a << 12;
    X |= b << 8;
    X |= c << 4;
    X |= d;
    	
    return X;
		
}			
//***************************ENC_Block*****************       
static inline uint16_t ENC_Block(uint16_t pt, const uint16_t* key, uint8_t n)
{
    uint16_t t,b,key2,key3;
		
	key2 = ROTL16(key[0], 6);
    b = key2 >> 6 &0xf;
  	b = Separ_sbox1[b];
  	key2 |= b << 6;
  	key2 = key2 ^ (n+2);
  	
  	key3 = ROTL16(key[1], 10);
    b = key3 >> 6 &0xf;
  	b = Separ_sbox1[b];
  	key3 |= b << 6;
  	key3 = key3 ^ (n+3);
  	
    t = pt ^ key[0];    //k0
    t = do_sbox(t);
    t = Sep_ROTL16(t);
    
    t ^= key[1];         //k1
    t = do_sbox(t);
    t = Sep_ROTL16(t);
    
    t ^= key2;		     //k2
    t = do_sbox(t);
    t = Sep_ROTL16(t);
    
    t ^= key3;		    //k3
    t = do_sbox(t);
    t = Sep_ROTL16(t);

    t ^= key[1] ^ key[0];	//k4
    t = do_sbox(t);
    t ^= key2 ^ key3;   //k5 = k0 ^ k1

    return t;
}
//*****************DEC_Block****************************
static inline uint16_t DEC_Block(uint16_t ct, const uint16_t* key,uint8_t n)
{
    uint16_t t,b,key2,key3;
	//produce key2 , key3 ,key4 , key5 , key6 from key[0] and key[1] and use in encryption

    key2 = ROTL16(key[0], 6);
    b = key2 >> 6 &0xf;
  	b = Separ_sbox1[b];
  	key2 |= b << 6;
  	key2 = key2 ^ (n+2);
  	
  	key3 = ROTL16(key[1], 10);
    b = key3 >> 6 &0xf;
  	b = Separ_sbox1[b];
  	key3 |= b << 6;
  	key3 = key3 ^ (n+3);
  	
	t = ct ^ key3 ^ key2;   //k5
	t = do_isbox(t);
    t = t ^ key[0] ^ key[1];   //k4
	
	t = Sep_inROTL16(t);
    t = do_isbox(t);
    t = t ^ key3;          //k3
    
    t = Sep_inROTL16(t);
    t = do_isbox(t);
    t = t ^ key2;            //k2
    
    t = Sep_inROTL16(t);
    t = do_isbox(t);
    t = t ^ key[1];          //k1
    
    t = Sep_inROTL16(t);
    t = do_isbox(t);
    t = t ^ key[0];         //k0
    
    return t;
}
//*************************Separ_Initial_State*************************
void Separ_Initial_State(Separ_ctx* c, const uint16_t key[16], const uint16_t iv[8])  //64-bit nonce
{
    int i;
    uint16_t v12 = 0, v23= 0, v34= 0, v45= 0, v56= 0, v67= 0, v78= 0, ct= 0;

    c->state_1 = iv[0];
    c->state_2 = iv[1];
    c->state_3 = iv[2];
    c->state_4 = iv[3];
    c->state_5 = iv[4];
    c->state_6 = iv[5];
    c->state_7 = iv[6];
    c->state_8 = iv[7];
    
	
    for(i = 0; i < 4; i++) {
        v12 = ENC_Block(c->state_1 + c->state_3 + c->state_5 + c->state_7, &key[0],1);   //rotor 1
        v23 = ENC_Block(v12 + c->state_2, &key[2],2);          //rotor 2
        v34 = ENC_Block(v23 + c->state_3, &key[4],3);          //rotor 3
        v45 = ENC_Block(v34 + c->state_4, &key[6],4);
		v56 = ENC_Block(v45 + c->state_5, &key[8],5);
		v67 = ENC_Block(v56 + c->state_6, &key[10],6);
		v78 = ENC_Block(v67 + c->state_7, &key[12],7);
		ct  = ENC_Block(v78 + c->state_8, &key[14],8);
		
		
		c->state_1 += ct;
        c->state_2 += v12;
        c->state_3 += v23;
        c->state_4 += v34;
        c->state_5 += v45;
        c->state_6 += v56;
        c->state_7 += v67;
        c->state_8 += v78;
	    
    }
	c->lfsr = ct | 0x100;   //always set bit 9 in case of zero.
       	
}
//**********************Separ_Encryption****************************
uint16_t Separ_Encryption(uint16_t pt, Separ_ctx* c,const uint16_t key[16])
{
    uint16_t v12,v23,v34,v45,v56,v67,v78,ct;
    
    v12 = ENC_Block( pt + c->state_1, &key[0],1);  //state 1   
    v23 = ENC_Block(v12 + c->state_2, &key[2],2);  //state 2
    v34 = ENC_Block(v23 + c->state_3, &key[4],3);  //state 3
    v45 = ENC_Block(v34 + c->state_4, &key[6],4);  //state 4
    v56 = ENC_Block(v45 + c->state_5, &key[8],5);  //state 5
    v67 = ENC_Block(v56 + c->state_6, &key[10],6);  //state 6
    v78 = ENC_Block(v67 + c->state_7, &key[12],7);  //state 7
    ct =  ENC_Block(v78 + c->state_8, &key[14],8);  //state 8
    
	
	c->state_2 += v12 + v56 + c->state_6;
	c->state_3 += v23 + v34 + c->state_4 + c->state_1 ;
	c->state_4 += v12 + v45 + c->state_8;
	c->state_5 += v23;
	c->state_6 += v12 + v45 + c->state_7;
    c->state_7 += v23 + v67;
	c->state_8 += v45;
	c->state_1 += v34 + v23 + c->state_5 + v78;
	
	
	c->lfsr = (c->lfsr >> 1) ^ (-(c->lfsr & 1u) & 0xCA44u);
	c->state_5 += c->lfsr;
	
	

    return ct;
}
//*******************Separ_Decryption******************************
uint16_t Separ_Decryption(uint16_t ct, Separ_ctx* c,const uint16_t key[16])
{
    uint16_t v12,v23,v34,v45,v56,v67,v78,pt;
    
    v78 = DEC_Block( ct, &key[14],8) - c->state_8;		//state 8
	v67 = DEC_Block(v78, &key[12],7) - c->state_7;		//state 7
	v56 = DEC_Block(v67, &key[10],6) - c->state_6;		//state 6
	v45 = DEC_Block(v56, &key[8],5) - c->state_5;		//state 5
	v34 = DEC_Block(v45, &key[6],4) - c->state_4;      //state 4
    v23 = DEC_Block(v34, &key[4],3) - c->state_3;      //state 3
    v12 = DEC_Block(v23, &key[2],2) - c->state_2;      //state 2
    pt =  DEC_Block(v12, &key[0],1) - c->state_1;      //state 1
    
    c->state_2 += v12 + v56 + c->state_6;
	c->state_3 += v23 + v34 + c->state_4 + c->state_1 ;
	c->state_4 += v12 + v45 + c->state_8;
	c->state_5 += v23;
	c->state_6 += v12 + v45 + c->state_7;
    c->state_7 += v23 + v67;
	c->state_8 += v45;
	c->state_1 += v34 + v23 + c->state_5 + v78;
	
	c->lfsr = (c->lfsr >> 1) ^ (-(c->lfsr & 1u) & 0xCA44u);
	c->state_5 += c->lfsr;
	
	return pt;
}

/*
 * High-throughput FFI entry point for Python/ctypes or other foreign-function callers.
 * Encrypts `word_count` 16-bit plaintext words from `pt` into caller-provided `ct`.
 * If `key` or `iv` is NULL, the built-in defaults are used.
 * Returns 0 on success and 1 for invalid non-zero-length buffers.
 */
SEPAR_EXPORT int separ_encrypt_words(
    const uint16_t *pt,
    size_t word_count,
    const uint16_t *key,
    const uint16_t *iv,
    uint16_t *ct)
{
    Separ_ctx ctx;
    const uint16_t *active_key = (key != NULL) ? key : default_key;
    const uint16_t *active_iv = (iv != NULL) ? iv : default_iv;
    size_t i;

    if (word_count != 0 && (pt == NULL || ct == NULL)) {
        return 1;
    }

    Separ_Initial_State(&ctx, active_key, active_iv);
    for (i = 0; i < word_count; i++) {
        ct[i] = Separ_Encryption(pt[i], &ctx, active_key);
    }

    return 0;
}

/* Command-line interface: plaintext is required, while key/IV may be omitted to use defaults. */
static void print_usage(const char *program_name)
{
    fprintf(stderr, "Usage: %s <plaintext_hex> [key_hex] [iv_hex]\n", program_name);
    fprintf(stderr, "  plaintext_hex: positive multiple of 4 hex chars (16-bit blocks)\n");
    fprintf(stderr, "  key_hex:       optional, exactly 64 hex chars (16 x 16-bit words)\n");
    fprintf(stderr, "  iv_hex:        optional, exactly 32 hex chars (8 x 16-bit words)\n");
    fprintf(stderr, "If key_hex or iv_hex are omitted, the built-in defaults are used.\n");
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

static const char *skip_hex_prefix(const char *hex)
{
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
        return hex + 2;
    }
    return hex;
}

static int parse_hex_words(const char *input, uint16_t *words, size_t expected_words, size_t *parsed_words)
{
    const char *hex = skip_hex_prefix(input);
    size_t hex_len = strlen(hex);
    size_t word_count;
    size_t i;

    if (hex_len == 0 || (hex_len % 4) != 0) {
        return 0;
    }

    word_count = hex_len / 4;
    if (expected_words != 0 && word_count != expected_words) {
        return 0;
    }

    for (i = 0; i < word_count; i++) {
        int nibble0 = hex_nibble(hex[(i * 4)]);
        int nibble1 = hex_nibble(hex[(i * 4) + 1]);
        int nibble2 = hex_nibble(hex[(i * 4) + 2]);
        int nibble3 = hex_nibble(hex[(i * 4) + 3]);

        if (nibble0 < 0 || nibble1 < 0 || nibble2 < 0 || nibble3 < 0) {
            return 0;
        }

        if (words != NULL) {
            words[i] = (uint16_t)((nibble0 << 12) | (nibble1 << 8) | (nibble2 << 4) | nibble3);
        }
    }

    if (parsed_words != NULL) {
        *parsed_words = word_count;
    }

    return 1;
}

static void print_hex_words(const uint16_t *words, size_t word_count)
{
    size_t i;

    for (i = 0; i < word_count; i++) {
        printf("%04hX", words[i]);
    }
}

/* Command-line driver retained for manual runs and scripting that still wants stdout text output. */
int main(int argc, char *argv[]) {
	Separ_ctx ctx ;    //size optimized
	uint16_t key[16];
	uint16_t iv[8];
	uint16_t *pt;
	uint16_t *ct;
	uint16_t *ptnext;
	size_t pt_words = 0;
	size_t j;

    memcpy(key, default_key, sizeof(key));
    memcpy(iv, default_iv, sizeof(iv));

    if (argc < 2 || argc > 4) {
        print_usage(argv[0]);
        return 1;
    }

    if (!parse_hex_words(argv[1], NULL, 0, &pt_words)) {
        fprintf(stderr, "Invalid plaintext. Expected a positive multiple of 4 hex chars.\n");
        print_usage(argv[0]);
        return 1;
    }

    pt = (uint16_t *)malloc(pt_words * sizeof(uint16_t));
    ct = (uint16_t *)malloc(pt_words * sizeof(uint16_t));
    ptnext = (uint16_t *)malloc(pt_words * sizeof(uint16_t));

    if (pt == NULL || ct == NULL || ptnext == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        free(pt);
        free(ct);
        free(ptnext);
        return 1;
    }

    if (!parse_hex_words(argv[1], pt, 0, &pt_words)) {
        fprintf(stderr, "Invalid plaintext. Expected a positive multiple of 4 hex chars.\n");
        free(pt);
        free(ct);
        free(ptnext);
        return 1;
    }

    if (argc >= 3) {
        if (!parse_hex_words(argv[2], key, 16, NULL)) {
            fprintf(stderr, "Invalid key. Expected exactly 64 hex chars.\n");
            print_usage(argv[0]);
            free(pt);
            free(ct);
            free(ptnext);
            return 1;
        }
    }

    if (argc >= 4) {
        if (!parse_hex_words(argv[3], iv, 8, NULL)) {
            fprintf(stderr, "Invalid IV. Expected exactly 32 hex chars.\n");
            print_usage(argv[0]);
            free(pt);
            free(ct);
            free(ptnext);
            return 1;
        }
    }

//************************sized optimized*************************
	printf("KEY is:");
    print_hex_words(key, 16);
    printf("\n");
    printf("IV is:");
    print_hex_words(iv, 8);
    Separ_Initial_State(&ctx, key, iv);
    //encryption***************
	for (j = 0; j < pt_words; j++) 
           ct[j] = Separ_Encryption(pt[j], &ctx,key);
            
    //decryption***************
	Separ_Initial_State(&ctx, key, iv);
	for (j = 0; j < pt_words; j++) 
            ptnext[j] = Separ_Decryption(ct[j], &ctx,key);
    printf("\n");
    printf("PT is:");
    print_hex_words(ptnext, pt_words);
    printf("\n");
	printf("CT is:");
    print_hex_words(ct, pt_words);
    printf("\n");

    free(pt);
    free(ct);
    free(ptnext);
	return 0;
 }
