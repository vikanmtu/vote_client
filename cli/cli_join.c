#include "client.h"


//compose client's join request to server
short cli_join_req(unsigned char* pkt)
{
 unsigned int crc;
 short i; //general
 unsigned char e=0; //error flag


 while(1)
 {

  if(!(cli->flags & FLAG_REGS))
  {
   e=ERC_JOIN_R_NOREGS;
   break;
  }

   //check we inited and not opened
 if(cli->flags & FLAG_JOIN)
 {
 /// e=ERC_JOIN_R_JOINED;
 /// break;
 }
   //output data
  my_memclr(pkt, JOIN_RL); //clear  data
  stom(pkt, JOIN_RL);  //packet's len
  pkt[2]=JOIN; //type
  pkt[3]=0; //note

  memcpy(pkt+JOIN_RS, cli->key, JOIN_RS_LEN);  //output hash key
  memcpy(pkt+JOIN_RU, cli->sig, JOIN_RU_LEN);  //output registrator's signature
  break;
 }

 //compute crc
 if(!e)
 {
  crc=crc32_le(pkt, JOIN_RC); //compute CRC
  itom(pkt+JOIN_RC, crc);  //output
  cli_fwrite(FILE_JOINR, pkt, JOIN_RL); //save packet
  i=JOIN_RL;
 } else i=-e;

 printf("Client: join req %d\r\n", e);

  //clear data
  crc=0;

  return i;
}

//=====================================================================
//process server's join answer
short cli_join_ans(unsigned char* pkt)
{
 fp_t q; //ECC field value
 ecpoint_fp P; //ECC uncompressed point
 ecpoint_fp R; //ECC multiplication result
 unsigned char res[64];
 
 short i; //general
 unsigned char e=0; //error flag
 unsigned char ee=pkt[3]; //external error flag
 unsigned int id=mtoi(pkt+JOIN_AN); //user's id
 unsigned int crc=mtoi(pkt+JOIN_AC); //packets crc


 while(1)
 {
 //check packet's type
  if(JOIN!=pkt[2])
  {
   e=ERC_JOIN_A_TYPE;
   break;
  }

 //check packet's length
  if(JOIN_AL!=mtos(pkt))
  {
   e=ERC_JOIN_A_LEN;
   break;
  }

  //check server's error
  if(ee&CLI_FATAL_ERR)
  {
   e=ee;
   break;
  }

  //check client ready for idnt
  if(!(cli->flags & FLAG_REGS))
  {
   e=ERC_JOIN_A_NOREGS;
   break;
  }

  //check we inited and not opened
 if(cli->flags & FLAG_JOIN)
 {
  //e=ERC_JOIN_A_JOINED;
  //break;
 }

   //check crc
  if(crc!=crc32_le(pkt, JOIN_AC))
  {
   e=ERC_JOIN_A_CRC;
   break; //no send any answer
  }


  //check key in ticket is equal with our key
  i=isequal(cli->key, pkt+JOIN_AS, JOIN_AS_LEN);
  if(!i)
  {
   e=ERC_JOIN_T_KEY;
   break; //no send any answer
  }




  //decompress  into point (tickets signature)
  memcpy(q, pkt+JOIN_AT, sizeof(q));
  i=bls_uncompress(&P, q);
  if(!i) //point invalid
  {
   printf("Invalid point!"); //set error verbose
   e=ERC_JOIN_T_POINT;
   break;
  }

  //hash packet
   memcpy(res, "JOIN", 4); //salt for join ticket
   sh_ini();
   sh_upd(res, 4); //hash salt
   sh_upd(pkt, JOIN_AT); //hash packet
   sh_xof();
   sh_out(res, 32); //output fp[32] message

   //convert message to point
   memcpy(q, res, sizeof(q));
   i=bls_hash(&R, q); //message
   if(!i) //point invalid
   {
    printf("Invalid point!"); //set error verbose
    e=ERC_JOIN_T_HASH;
   }

   //check ticket
   i=bls_verify(&R, &P, &(cli->YY));
  if(!i)
  {
   printf("Invalid ticket!"); //set error verbose
   e=ERC_JOIN_T_VERIFY;
   break;
  }


  //save id
  cli->num=id;
  memcpy(cli->cnd, pkt+JOIN_AK, sizeof(cli->cnd));
  i=cli_fwrite(FILE_NUM , pkt+JOIN_AN, JOIN_AN_LEN+JOIN_AK_LEN);
  if(i!=(JOIN_AN_LEN+JOIN_AK_LEN))
  {
   e=ERC_JOIN_A_SAVE_ID;
   break;
  }


  //set voting counter
  if(!cli->cnt)
  {
   cli->cnt=1;
   itom(res, cli->cnt);
   i=cli_fwrite(FILE_CNT , res, 4);
   if(i!=4)
   {
    e=ERC_JOIN_A_SAVE_TMR;
    break;
   }
  }



  cli->flags|=FLAG_JOIN; //registration compleet
  cli_fwrite(FILE_JOINA, pkt, JOIN_AL); //save packet
  break;
 }

 printf("Client: join as %d ans %d\r\n", id, e);
 i=0; if(e) i=-e; else if(ee) i=ee+CLI_NOTE;
 
 crc=0; id=0;
  sh_clr();
  my_memclr(q, sizeof(q));
  my_memclr(&P, sizeof(P));
  my_memclr(&R, sizeof(R));
  my_memclr(res, sizeof(res));
  my_memclr(pkt, JOIN_AL);
 return i;
}


