
#include "pbc/pbc.h"
#include "types.h"
#include "bigint/bi.h"
#include "fp/fp.h"
#include "ec/ec.h"
#include "fp/fp12.h"
#include "myutil.h"
#include "rand.h"
#include "hash/hashing.h"

#define FP2_PK_LEN 128

void bls_clear( void *v, short n );
short bls_reduce(fp_t x);
short bls_key(ecpoint_fp2 *XX, ecpoint_fp *X, fp_t x);
short bls_hash(ecpoint_fp *h, fp_t m);
short bls_blind(ecpoint_fp *b, const ecpoint_fp *h, fp_t r);
void bls_sign(ecpoint_fp *s, const ecpoint_fp *h, const fp_t x);
void bls_unblind(ecpoint_fp *u, const ecpoint_fp *s, const ecpoint_fp *X, const fp_t r);
short bls_verify(const ecpoint_fp *h, const ecpoint_fp *s, const ecpoint_fp2 *XX);
void bls_compress(fp_t t, const ecpoint_fp *p);
short bls_uncompress(ecpoint_fp *p, const fp_t t);
short bls_mult(ecpoint_fp *S, ecpoint_fp *X, fp_t x);

