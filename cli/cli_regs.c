#include "client.h"


//compose client's regs request to server
short cli_regs_req(unsigned char* pkt)
{
 fp_t q; //ECC field value
 ecpoint_fp P; //ECC uncompressed point
 ecpoint_fp R; //ECC multiplication result
 unsigned int crc;
 short i; //general
 unsigned char e=0; //error flag


 while(1)
 {

  if(!(cli->flags & FLAG_INIT))
  {
   e=ERC_REGS_R_NOIDNT;
   break;
  }

 //get message point from key
  sh_ini();
  sh_upd(cli->key, sizeof(cli->key));
  sh_xof();
  sh_out((unsigned char*)q, sizeof(q)); //hash key[16] to fp[32] value

  //hash message to point
  i=bls_hash(&P, q);
  if(!i) //point invalid
  {
   printf("Invalid point!"); //set error verbose
   e=ERC_REGS_R_HASH;
   break;
  }

  //blind message point
  i=bls_blind(&R, &P, cli->b);
  if(!i) //point invalid
  {
   printf("Invalid blinding!"); //set error verbose
   e=ERC_REGS_R_BLIND;
   break;
  }

  //compress blinded point
   bls_compress(q, &R);

   //output data
  my_memclr(pkt, REGS_RL); //clear  data
  stom(pkt, REGS_RL);  //packet's len
  pkt[2]=REGS; //type
  pkt[3]=0; //note

  itom(pkt+REGS_RD, cli->id); //output id
  memcpy(pkt+REGS_RQ, q, REGS_RQ_LEN);  //output blinded mesage

  //output mac
  sh_ini();
  sh_upd(cli->shr, sizeof(cli->shr));
  sh_upd(pkt, REGS_RM);
  sh_xof();
  sh_out(pkt+REGS_RM, REGS_RM_LEN);

  break;
 }

 //compute crc
 if(!e)
 {
  crc=crc32_le(pkt, REGS_RC); //compute CRC
  itom(pkt+REGS_RC, crc);  //output
  cli_fwrite(FILE_REGSR, pkt, REGS_RL); //save packet
  i=REGS_RL;
 } else i=-e;

 printf("Client: regs req %d\r\n", e);

  //clear data
  crc=0;
  sh_clr();
  my_memclr(q, sizeof(q));
  my_memclr(&P, sizeof(P));
  my_memclr(&R, sizeof(R));
  return i;
}

//=====================================================================

//process server's idnt answer
short cli_regs_ans(unsigned char* pkt)
{
 fp_t q; //ECC field value
 ecpoint_fp P; //ECC uncompressed point
 ecpoint_fp R; //ECC multiplication result
 ecpoint_fp K; //registrators public key in Q1
 short i; //general
 unsigned char e=0; //error flag
 unsigned char ee=pkt[3]; //external error flag
 int id=mtoi(pkt+REGS_AD); //user's id
 unsigned int crc=mtoi(pkt+REGS_AC); //packets crc


 while(1)
 {

  //check packet's type
  if(REGS!=pkt[2])
  {
   e=ERC_REGS_A_TYPE;
   break;
  }

 //check packet's length
  if(REGS_AL!=mtos(pkt))
  {
   e=ERC_REGS_A_LEN;
   break;
  }

  //check server's error
  if(ee&CLI_FATAL_ERR)
  {
   e=ee;
   break;
  }

  //check client ready for idnt
  if(!(cli->flags & FLAG_IDNT))
  {
   e=ERC_REGS_A_NOIDNT;
   break;
  }

  if(id!=cli->id)
  {
   e=ERC_REGS_A_ID;
   break;
  }

  //check crc
  if(crc!=crc32_le(pkt, REGS_AC))
  {
   e=ERC_REGS_A_CRC;
   break; //no send any answer
  }

    //decompress  into point (blinded signature)
  memcpy(q, pkt+REGS_AB, sizeof(q));
  i=bls_uncompress(&P, q);
  if(!i) //point invalid
  {
   printf("Invalid point!"); //set error verbose
   e=ERC_REGS_A_POINT_SIG;
   break;
  }

     //decompress  into point (registrator's Q1 public key)
  memcpy(q, pkt+REGS_AG, REGS_AG_LEN);
  i=bls_uncompress(&K, q);
  if(!i) //point invalid
  {
   printf("Invalid point!"); //set error verbose
   e=ERC_REGS_A_POINT_RP1;
   break;
  }

  //unblind signature
  bls_unblind(&R, &P, &K, cli->b);

  //get message point from key
  sh_ini();
  sh_upd(cli->key, sizeof(cli->key));
  sh_xof();
  sh_out((unsigned char*)q, sizeof(q)); //hash key[16] to fp[32] value

  //hash message to point
  i=bls_hash(&P, q);
  if(!i) //point invalid
  {
   printf("Invalid point!"); //set error verbose
   e=ERC_REGS_A_HASH_OURK;
   break;
  }

  //verify registrator's signature of our key
  i=bls_verify(&P, &R, &cli->RR);
  if(!i)
  {
   printf("Invalid psignature!"); //set error verbose
   e=ERC_REGS_A_VERIFY_BSIG;
   break;
  }

  //compress unblinded signature
  bls_compress(cli->sig, &R);

  //save signature
  i=cli_fwrite(FILE_SIGN, (unsigned char*)cli->sig, sizeof(cli->sig));
  if(i!=sizeof(cli->sig))
  {
   e=ERC_REGS_A_SAVE_BSIG;
   break;
  }


  cli->flags|=FLAG_REGS; //registration compleet
  cli_fwrite(FILE_REGSA, pkt, REGS_AL); //save packet
  break;
 }

 printf("Client: regs ans %d\r\n", e);
 i=0; if(e) i=-e; else if(ee) i=ee+CLI_NOTE;

 crc=0; id=0;
  sh_clr();
  my_memclr(q, sizeof(q));
  my_memclr(&P, sizeof(P));
  my_memclr(&R, sizeof(R));
  my_memclr(&K, sizeof(K));
  my_memclr(pkt, REGS_AL);
 return i;
}

