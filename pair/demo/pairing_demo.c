/****************************************************************************
**
** Copyright (C) 2015 Stiftung Secure Information and
**                    Communication Technologies SIC and
**                    Graz University of Technology
** Contact: http://opensource.iaik.tugraz.at
**
**
** Commercial License Usage
** Licensees holding valid commercial licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and SIC. For further information
** contact us at http://opensource.iaik.tugraz.at.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3.0 as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU General Public License version 3.0 requirements will be
** met: http://www.gnu.org/copyleft/gpl.html.
**
** This software is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this software. If not, see http://www.gnu.org/licenses/.
**
**
****************************************************************************/
#include <stdlib.h>



#include "bls.h"


int my_main(void) {
	fp12_t res1;
        fp12_t res2;
        fp12_t res3;
        fp12_t res4;
	ecpoint_fp  p, pp;
        //ecpoint_fp  pm;
	ecpoint_fp2 q;
	bigint_t k1, k2;

        fp_t cc;
        fp_t c;
        fp_t x;
        fp_t s;
        fp_t r;
        fp_t rr;
        int i, j;

        word_t* p0;
        word_t* p1;
        word_t d;



        char* m="test"; //string
        ecpoint_fp  pm; //message point
        ecpoint_fp  pm1; //message point
        ecpoint_fp  pr; //mask point
        ecpoint_fp  pru; //unmask point

        ecpoint_fp  pb; //blinded point
        ecpoint_fp  pb1; //blinded point
        ecpoint_fp  pbs; //blind signature
        ecpoint_fp  pbs1; //blind signature
        ecpoint_fp  ps; //signature
        ecpoint_fp  ps1; //signature
        ecpoint_fp  pu; //unblinded signature
        ecpoint_fp X;
        ecpoint_fp2 XX;

        fp_t u; //message
        fp_t b; //blinded message

        unsigned char sss[256];

 //-----------------BLS library test---------------------------------------
    //use 32 bytes random value x

    //seed PRNG
   // randomize();
   // for(i=0;i<256;i++) sss[i]=rand()%256;
    cprng_init(sss, sizeof(sss));


    //generate signing keys
    cprng_get_bytes(x, BI_BYTES);
    i=bls_key(&XX, &X, x); //output: XX is G2 public key, X is G1 public key, x is private key

    //output 32 bytes SK x, 128 bytes G2_PK, 64 bytes G1_PK

 //---------------------------issuer:-----------------------

 //input is message string m
 //use 32 bytes random value r

for(j=0;j<256;j++)
{
    //generate message
        do {
        cprng_get_bytes(cc, BI_BYTES);
        fp_rdc_n(cc);
        } while (bi_compare(cc, bi_zero) == 0); //message


    //hashing message
    //hash_id(c, m);
    bls_hash(&pm, c); //output: pm is message point in G1

    //compressing clear message point
    bls_compress(u, &pm);

    //blinding
    cprng_get_bytes(r, BI_BYTES);
    bls_blind(&pb, &pm, r);  //output: pb is blinded message point in G1, r is blinding value

    //compressing blinded message point
    bls_compress(b, &pb);

    //32 bytes message in b

 //------------------------signer:-------------------------
 //input is 32-bytes message b
 //use 32 bytes secret key x

    //uncompressing
    bls_uncompress(&pb1, b);

    //signing
    bls_sign(&pbs, &pb1, x); //output: pbs is blinded signatute point in G1

    //compressing
    bls_compress(s, &pbs);

    //32 bytes signature in s

 //-----------------verifier:------------------------------------
 //input is 32 bytes signature s,
 //use 32 bytes message d, 128 bytes G2_PK, 64 bytes G1_PK


    //uncompressing
    bls_uncompress(&pm1, u);   //message
    bls_uncompress(&pbs1, s);  //signature


    //unblinding
    bls_unblind(&ps, &pbs1, &X, r); //output: ps is unblinded signature point in G1

    //verifing
    i=bls_verify(&pm1, &ps, &XX); //output is returns 1 if signature valid

    //verification result in i
    if(i!=1)
    {
     i=i;

    }

 //------------------------------------------------------------------------

}


        //generate signing keypair
        do {
        cprng_get_bytes(x, BI_BYTES);
        fp_rdc_n(x);
        } while (bi_compare(x, bi_zero) == 0); //private key



         ecfp2_mul(&XX, &ECFP2_GENERATOR, x);  //XX is public key in G2
        ecfp_mul(&X, &ECFP_GENERATOR, x);  //X is public key in G1

        //pbc_map_opt_ate(res3, &ECFP_GENERATOR, &ECFP2_GENERATOR);
	//fp12_exp_cyclotomic(res4, (const fp4_t*)res3, x);



        //hash to point
        hash_id(c, m);
        fp_rdc_n(c);
        ecfp_hash_to_point(&pm, c);  //message point PM in G1



        //blind
        do {cprng_get_bytes(r, BI_BYTES);
        fp_rdc_n(r);
        } while (bi_compare(r, bi_zero) == 0);

        ecfp_mul(&pr, &ECFP_GENERATOR, r);  //mask point PR=G^r
        ecfp_add_affine(&pb, &pm, &pr); //blinded message point PB=PM+PR





        //sign
        ecfp_mul(&pbs, &pb, x);  //blinded signature

        //ecfp_mul(&ps1, &pm, x);  //unblinded signature


        //compress
        //ecfp_compress_std(s, &ps);

        //decompress
        //i=ecfp_uncompress_std(&ps1, s); //must be 1





        //unblind
        ecfp_mul(&pru, &X, r);  //unmask point PRU=X^r
        ecfp_neg_affine(&pru); //negate unmask point
        ecfp_add_affine(&ps, &pbs, &pru); //unblinded signature point PS=PB-PRU


        //verify
        pbc_map_opt_ate(res1, &ps, &ECFP2_GENERATOR);
        pbc_map_opt_ate(res2, &pm, &XX);

        //pbc_map_opt_ate(res3, &pm, &ECFP2_GENERATOR);
        //fp12_exp_cyclotomic(res4, (const fp4_t*)res3, x);

        p0=(word_t*)&res1;
        p1=(word_t*)&res2;
        d=0;
        for(i=0;i<FP_WORDS;i++) d|=(p0[i]^p1[i]);


        PRINT_GT("res1: ", res1);
	PRINT_GT("res2: ", res2);


        /*
        //compression test
        for(i=0;i<1024;i++)
        {

         if(i==6)
         {
          i=i;
         }

        do {
		cprng_get_bytes(k1, BI_BYTES);
                fp_rdc_n(k1);
	} while (bi_compare(k1, bi_zero) == 0);
        ecfp_mul(&p, &ECFP_GENERATOR, k1);
        ecfp_compress_std(c, &p);
        ecfp_uncompress_std(&pp, c);
        if(p.y[7]!=pp.y[7])
        {
         i=i;
        }

}

       */


	do {
		cprng_get_bytes(k1, BI_BYTES);
                fp_rdc_n(k1);
	} while (bi_compare(k1, bi_zero) == 0);
	do {
		cprng_get_bytes(k2, BI_BYTES); fp_rdc_n(k2);
	} while (bi_compare(k2, bi_zero) == 0);

	pbc_map_opt_ate(res1, &ECFP_GENERATOR, &ECFP2_GENERATOR);
	fp12_exp_cyclotomic(res2, (const fp4_t*)res1, k1);
	fp12_exp_cyclotomic(res1, (const fp4_t*)res2, k2);

	ecfp_mul(&p, &ECFP_GENERATOR, k1);

        //-----------------------------------
        //ecfp_compress_std(c, &p);
        //ecfp_uncompress_std(&pp, c);

        //ecfp_to_montgomery_std(&pm, &p);
        //ecfp_from_montgomery_std(&pp, &pm);
        //------------------------------------


	ecfp2_mul(&q, &ECFP2_GENERATOR, k2);
	pbc_map_opt_ate(res2, &p, &q);

	PRINT_GT("res1: ", res1);
	PRINT_GT("res2: ", res2);
        return 0;
}
