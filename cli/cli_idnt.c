#include "ecc.h"
#include "client.h"


//compose client's idnt request to server
short cli_idnt_req(unsigned char* pkt)
{
 fp_t q; //ECC field value
 ecpoint_fp P; //ECC uncompressed point
 ecpoint_fp R; //ECC multiplication result
 unsigned int crc;
 short i; //general
 unsigned char e=0; //error flag

 unsigned char BP[32];  //SPEKE X25519 base point


 while(1)
 {

  if(!(cli->flags & FLAG_GETS))
  {
   e=ERC_IDNT_R_NOGETS;
   break;
  }

  //hash password
  cli->pwd[sizeof(cli->pwd)-1]=0;
  sh_ini();
  sh_upd(cli->pwd, strlen(cli->pwd));
  sh_xof();
  sh_out((unsigned char*)q, sizeof(q)); //hash to fp value

 //------------------------------------------
 /*
  i=bls_hash(&P, q); //hash to point

  if(!i) //invalid point
  {
   printf("Error hash\r\n");
   e=ERC_IDNT_R_HASH;
   break;
  }

  //compute SPECE public key
  i=bls_mult(&R, &P, cli->s);
  if(!i)
  {
   printf("Error mult\r\n");
   e=ERC_IDNT_R_BADQ;
   break;
  }

  //compress SPEKE public key to fp value
  bls_compress(q, &R);
 */
 //--------------------------------------------

 r2p(BP, (unsigned char*)q); //hash fp value to X25519 point
 scalarmult((unsigned char*)q, (unsigned char*)cli->s, BP); //compute SPEKE pubkey

 //-------------------------------------------


   //output
  my_memclr(pkt, IDNT_RL); //clear  data
  stom(pkt, IDNT_RL);  //packet's len
  pkt[2]=IDNT; //type
  pkt[3]=0; //note

  itom(pkt+IDNT_RD, cli->id); //output id
  memcpy(pkt+IDNT_RP, q, IDNT_RP_LEN);  //output compressed SPEKE pubkey

  break;
 }

 if(!e)
 {
  crc=crc32_le(pkt, IDNT_RC); //compute CRC
  itom(pkt+IDNT_RC, crc);  //output
  //save packet
  cli_fwrite(FILE_IDNTR, pkt, IDNT_RL);
  i=IDNT_RL;
 } else i=-e;


  printf("Client: idnt req %d\r\n", e);


  //clear data
  crc=0;
  sh_clr();
  my_memclr(q, sizeof(q));
  my_memclr(&P, sizeof(P));
  my_memclr(&R, sizeof(R));
  my_memclr(BP, sizeof(BP));
  return i;
}

 //=====================================================================
//process server's idnt answer
short cli_idnt_ans(unsigned char* pkt)
{
 fp_t q; //ECC field value
 ecpoint_fp P; //ECC uncompressed point
 ecpoint_fp R; //ECC multiplication result
 ecpoint_fp S;
 ecpoint_fp2 PP; 
 short i; //general
 unsigned char e=0; //error flag
 unsigned char ee=pkt[3]; //external error flag
 unsigned int crc=mtoi(pkt+IDNT_AC); //packets crc
 unsigned char BP[32];  //SPEKE X25519 base point

 while(1)
 {

  //check packet's type
  if(IDNT!=pkt[2])
  {
   e=ERC_IDNT_A_TYPE;
   break;
  }

 //check packet's length
  if(IDNT_AL!=mtos(pkt))
  {
   e=ERC_IDNT_A_LEN;
   break;
  }

  //check server's error
  if(ee&CLI_FATAL_ERR)
  {
   e=ee;
   break;
  }

  //check client ready for idnt
  if(!(cli->flags & FLAG_GETS))
  {
   e=ERC_IDNT_A_NOGETS;
   break;
  }

  //check crc
  if(crc!=crc32_le(pkt, IDNT_AC))
  {
   e=ERC_IDNT_A_CRC;
   break; //no send any answer
  }


  //get and verify registrator's public key
  memset(&PP, 0, sizeof(PP));
  memcpy(&PP, pkt+IDNT_AR, IDNT_AR_LEN);

  //hash registration pk
  sh_ini();
  sh_upd(&PP, FP2_PK_LEN);
  sh_xof();
  sh_out(q, sizeof(q)); //hash key[16] to fp[32] value
  i=bls_hash(&R, q); //hash to poin M

  if(!i) //point invalid
  {
   printf("Invalid point!"); //set error verbose
   e=ERC_IDNT_A_HASH_RPK;
   break;
  }

  //uncompress vote's signature of registrator's pk
  i=bls_uncompress(&S, cli->rps);
  if(!i) //point invalid
  {
   printf("Invalid point!"); //set error verbose
   e=ERC_IDNT_A_POINT_SIG;
   break;
  }

  i=bls_verify(&R, &S, &cli->YY); //verify voters signature of registrator's pk
  if(!i) //point invalid
  {
   printf("Registrator's PK invalid!"); //set error verbose
   e=ERC_IDNT_A_VERIFY_RPK;
   break;
  }


   //save registrator's public key
  memcpy(&cli->RR, &PP, sizeof(cli->RR)); //store
  i=cli_fwrite(FILE_RPK , (unsigned char*)&cli->RR, sizeof(cli->RR)); //save
  if(i!=sizeof(cli->RR))
  {
    e=ERC_IDNT_A_SAVE_RPK;
    break;
  }


    //decompress pkt+IDNT_AP[32] into point (their SPEKE pubkey)
  memcpy(q, pkt+IDNT_AP, sizeof(q));


  scalarmult(BP, (unsigned char*)cli->s, (unsigned char*)q); //compute SPEKE
  //hash SPEKE shared secret in point R to 16 bytes in res
  sh_ini();
  sh_upd(BP, 32);
  sh_xof();
  sh_out(cli->shr, 16);

  /*
  i=bls_uncompress(&P, q);
  if(!i) //point invalid
  {
   printf("Invalid point!"); //set error verbose
   e=ERC_IDNT_A_POINT_Q;
   break;
  }

  //compute SPEKE shared secret
  i=bls_mult(&R, &P, cli->s);
  if(!i)
  {
   printf("Error mult\r\n");
   e=ERC_IDNT_A_GET_SS;
   break;
  }

  //hash SPEKE shared secret in point R to 16 bytes in res
  sh_ini();
  sh_upd(&R, 64);
  sh_xof();
  sh_out(cli->shr, 16);
  */
  
  //save shared secret
  i=cli_fwrite(FILE_SHR, cli->shr, sizeof(cli->shr));
  if(i!=sizeof(cli->shr))
  {
   e=ERC_IDNT_A_SAVE_SS;
   break;
  }

  cli->flags|=FLAG_IDNT; //alsedy idnt, ready for regs
  cli_fwrite(FILE_IDNTA, pkt, IDNT_AL); //save packet
  break;
 }
 i=0; if(e) i=-e; else if(ee) i=ee+CLI_NOTE;
 printf("Client: idnt asw %d\r\n", e);

  //clear data
  crc=0;
  sh_clr();
  my_memclr(q, sizeof(q));
  my_memclr(&P, sizeof(P));
  my_memclr(&R, sizeof(R));
  my_memclr(&S, sizeof(S));
  my_memclr(&PP, sizeof(PP));
  my_memclr(pkt, IDNT_AL);
  my_memclr(BP, sizeof(BP));
 return i;
}