#include "pbc/pbc.h"
#include "types.h"
#include "bigint/bi.h"
#include "fp/fp.h"
#include "ec/ec.h"
#include "fp/fp12.h"
#include "rand.h"
#include "hash/hashing.h"





//safe clear memory
// Implementation that should never be optimized out by the compiler
void bls_clear( void *v, short n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}


//reduce 256 bits random to BN254 field
short bls_reduce(fp_t x)
{
 fp_t c;

 fp_copy(c, x);
 c[7]&=0x3FFFFFFF;
 fp_rdc_n(c);  //reduce x to field
 if(bi_compare(c, bi_zero) == 0) return 0;
 fp_copy(x, c); //x is private key
 bls_clear(c, sizeof(c));
 return 1;
}

//generate signer's public keys
//input: 256 bit random in x
//output: private key in x, publik key in G2 in XX,
//optionally output public key in G1 in X (for blind signatures)
short bls_key(ecpoint_fp2 *XX, ecpoint_fp *X, fp_t x)
{
 fp_t c;

 fp_copy(c, x);
 c[7]&=0x3FFFFFFF;
 fp_rdc_n(c);  //reduce x to field
 if(bi_compare(c, bi_zero) == 0) return 0;

 ecfp2_mul(XX, &ECFP2_GENERATOR, c);  //XX is public key in G2
 if(X) ecfp_mul(X, &ECFP_GENERATOR, c);  //X is public key in G1
 fp_copy(x, c); //x is private key
 bls_clear(c, sizeof(c));
 return 1;
}


short bls_mult(ecpoint_fp *S, ecpoint_fp *X, fp_t x)
{
 fp_t c;

 fp_copy(c, x);
 c[7]&=0x3FFFFFFF;
 fp_rdc_n(c);  //reduce x to field
 if(bi_compare(c, bi_zero) == 0) return 0;

 ecfp_mul(S, X, c);
 fp_copy(x, c); //x is private key
 bls_clear(c, sizeof(c));
 return 1;
}

//convert message hash to point in G1
//input: 256 bits message hash in m
//output: point in G1
short bls_hash(ecpoint_fp *h, fp_t m)
{
 fp_t c;

 fp_copy(c, m);
 c[7]&=0x3FFFFFFF;
 fp_rdc_n(c);  //reduce m to field
 if(bi_compare(c, bi_zero) == 0) return 0;

 ecfp_hash_to_point(h, c);  //message point PM in G1
 fp_copy(m, c); //message hash
 bls_clear(c, sizeof(c));
 return 1;
}

//blind  message point before sending to signer
//input: message point in h,  blindign random 256 bits value in r
//output: blinding message point in G1 in b
short bls_blind(ecpoint_fp *b, const ecpoint_fp *h, fp_t r)
{
 fp_t c;
 ecpoint_fp  pr; //mask point

 fp_copy(c, r);
 c[7]&=0x3FFFFFFF;
 fp_rdc_n(c);  //reduce r to field
 if(bi_compare(c, bi_zero) == 0) return 0;

 ecfp_mul(&pr, &ECFP_GENERATOR, c);  //mask point PR=G^r
 ecfp_add_affine(b, h, &pr); //blinded message point PB=PM+PR

 fp_copy(r, c); //message hash
 bls_clear(c, sizeof(c));
 bls_clear(&pr, sizeof(pr));
 return 1;
}

//sign message point
//input: message point in G1 in m,  private key in x
//output signature point in G1 in s
//note: point m MUST be cheched (in uncompress procedure)
void bls_sign(ecpoint_fp *s, const ecpoint_fp *h, const fp_t x)
{
 ecfp_mul(s, h, x);  //sign
}

//unblind signature
//input: signature point in s, signer's G1 public key in X, blinding value in r
//output: unblinded signature in u
void bls_unblind(ecpoint_fp *u, const ecpoint_fp *s, const ecpoint_fp *X, const fp_t r)
{
  ecpoint_fp  pru; //unmask point

  ecfp_mul(&pru, X, r);  //unmask point PRU=X^r
  ecfp_neg_affine(&pru); //negate unmask point
  ecfp_add_affine(u, s, &pru); //unblinded signature point PS=PB-PRU
  bls_clear(&pru, sizeof(pru));
}

//verify signature
//input: message G1 point in m, signature G1 point in s, signer's G2 public key in XX
//return: 1 if OK 
short bls_verify(const ecpoint_fp *h, const ecpoint_fp *s, const ecpoint_fp2 *XX)
{
 fp12_t res1;
 fp12_t res2;
 word_t* p0;
 word_t* p1;
 word_t d;
 short i;

 pbc_map_opt_ate(res1, s, &ECFP2_GENERATOR);
 pbc_map_opt_ate(res2, h, XX);

 p0=(word_t*)&res1;
 p1=(word_t*)&res2;
 d=0;
 for(i=0;i<FP_WORDS;i++) d|=(p0[i]^p1[i]);

 return (short)(!d);
}



/**
 * only for BN254!
 * Compress a point in an elliptic curve group over a prime field to
 * to x only coordinate and flag of y sign
 * @param t the resulting x coordinate with PRIME_P size
 * @param p the point to be compressed
 */
 void bls_compress(fp_t t, const ecpoint_fp *p)
 {
  fp_t t0;

  fp_copy(t, p->x);
  bi_shift_right_one(t0, PRIME_P);
  if(1==bi_compare(p->y, t0)) t[7]|=0x80000000;
 }


 /**
 * only for BN254!
 * Decompress a x coordinate + sign to point in an elliptic curve group over a prime field to
 * @param t the x coordinate with PRIME_P size + sign of y in MSB
 * @param p the  resulting point
 */
 short bls_uncompress(ecpoint_fp *p, const fp_t t)
 {
        short ret=1;
        fp_t t0;
        fp_t t1;
        word_t w=t[7]&0x80000000;  //sign of y

        fp_copy(p->x, t);        //x
        p->x[7]&=0x3FFFFFFF;
        fp_rdc(p->x);  //reduce x to field

        fp_sqr(t0, p->x);       //compute y
	fp_mul(t0, t0, p->x);
	fp_add(t0, t0, EC_PARAM_B);
	fp_sqrt(p->y, t0);

        fp_sqr(t1, p->y);  //check point
        if(bi_compare(t0, t1)) ret=0;
        if(!bi_compare(p->x, bi_zero)) ret=0;

        bi_shift_right_one(t0, PRIME_P); //check sign
        if(1==bi_compare(p->y, t0)) w^=0x80000000;
        if(w) fp_neg(p->y, p->y);

        p->infinity=0;
        return ret;
  }
