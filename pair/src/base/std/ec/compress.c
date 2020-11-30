#include "bigint/bi.h"
#include "ec/ec.h"
#include "fp/fp.h"
#include "param.h"
#include "rand.h"


/**
 * only for BN254!
 * Compress a point in an elliptic curve group over a prime field to
 * to x only coordinate and flag of y sign
 * @param t the resulting x coordinate with PRIME_P size
 * @param p the point to be compressed
 */
 void ecfp_compress_std(fp_t t, const ecpoint_fp *p)
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
 short ecfp_uncompress_std(ecpoint_fp *p, const fp_t t)
 {
        short ret=1;
        fp_t t0;
        fp_t t1;
        word_t w=t[7]&0x80000000;  //sign of y

        fp_copy(p->x, t);        //x
        p->x[7]&=0x3FFFFFFF; //mask unused MSB
		fp_rdc_n(p->x);  //reduce x to field

        fp_sqr(t0, p->x);       //compute y
		fp_mul(t0, t0, p->x);
		fp_add(t0, t0, EC_PARAM_B);
		fp_sqrt(p->y, t0);

        fp_sqr(t1, p->y);  //check point
        if(bi_compare(t0, t1)) ret=0;
        if(!bi_compare(p->x, bi_zero)) ret=0;

        bi_shift_right_one(t0, PRIME_P); //check sign
        if(1==bi_compare(p->y, t0)) w^=0x80000000;
        if(w) fp_neg(p->y, p->y); //negate y depends sign flag

        p->infinity=0;
        return ret;
  }
