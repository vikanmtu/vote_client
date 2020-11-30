#include "client.h"

//compose client's join request to server
short cli_open_req(unsigned char* pkt)
{
 unsigned int crc;
 short i; //general
 unsigned char e=0; //error flag


 while(1)
 {

  if(!(cli->flags & FLAG_VOTE))
  {
   e=ERC_OPEN_R_NOVOTE;
   break;
  }

     //check we inited and not opened
  if(cli->flags & FLAG_OPEN)
  {
   e=ERC_OPEN_R_OPENED;
   break;
  }

  //output data
  my_memclr(pkt, OPEN_RL); //clear  data
  stom(pkt, OPEN_RL);  //packet's len
  pkt[2]=OPEN; //type
  pkt[3]=0; //note

  itom(pkt+OPEN_RN, cli->num);
  memcpy(pkt+OPEN_RE, cli->enc, OPEN_RE_LEN);  //output enc key

  break;
 }

 //compute crc
 if(!e)
 {
  crc=crc32_le(pkt, OPEN_RC); //compute CRC
  itom(pkt+OPEN_RC, crc);  //output
  cli_fwrite(FILE_OPENR, pkt, OPEN_RL); //save packet
  i=OPEN_RL;
 } else i=-e;


 printf("Client: open req %d\r\n", e);

  //clear data
  crc=0;


  return i;
}

//=====================================================================

//process server's join answer
short cli_open_ans(unsigned char* pkt)
{
 fp_t q; //ECC field value
 ecpoint_fp P; //ECC uncompressed point
 ecpoint_fp R; //ECC multiplication result
 unsigned char res[64];
 
 short i; //general
 unsigned char e=0; //error flag
 unsigned char ee=pkt[3]; //external error flag
 int id=mtoi(pkt+OPEN_AN); //user's id
 unsigned int crc=mtoi(pkt+OPEN_AC); //packets crc


 while(1)
 {
  //check packet's type
  if(OPEN!=pkt[2])
  {
   e=ERC_OPEN_A_TYPE;
   break;
  }

 //check packet's length
  if(OPEN_AL!=mtos(pkt))
  {
   e=ERC_OPEN_A_LEN;
   break;
  }

  //check server's error
  if(ee&CLI_FATAL_ERR)
  {
   e=ee;
   break;
  }

  //check client ready for idnt
  if(!(cli->flags & FLAG_VOTE))
  {
   e=ERC_OPEN_A_NOVOTE;
   break;
  }

     //check we inited and not opened
  if(cli->flags & FLAG_OPEN)
  {
   e=ERC_OPEN_A_OPENED;
   break;
  }

  if(id!=cli->num)
  {
   e=ERC_OPEN_T_NUM;
   break; //no send any answer
  }


  //check opened vote is equal with our vote
  i=isequal(cli->votd, pkt+OPEN_AO, OPEN_AO_LEN);
  if(!i)
  {
   e=ERC_OPEN_T_VOTD;
   break; //no send any answer
  }


   //check crc
  if(crc!=crc32_le(pkt, OPEN_AC))
  {
   e=ERC_OPEN_A_CRC;
   break; //no send any answer
  }


  //decompress  into point (tickets signature)
  memcpy(q, pkt+OPEN_AT, sizeof(q));
  i=bls_uncompress(&P, q);
  if(!i) //point invalid
  {
   printf("Invalid point!"); //set error verbose
   e=ERC_OPEN_T_POINT_SIG;
   break;
  }

 //signing header, id and key
   memcpy(res, "OPEN", 4); //salt for open ticket
   sh_ini();
   sh_upd(res, 4); //hash salt
   sh_upd(pkt, OPEN_AT); //hash packet
   sh_xof();
   sh_out(res, 32); //output fp[32] message

   //convert message to point
   memcpy(q, res, sizeof(q));
   i=bls_hash(&R, q); //message
   if(!i) //point invalid
   {
    printf("Invalid point!"); //set error verbose
    e=ERC_OPEN_T_HASH;
   }

   //check ticket
   i=bls_verify(&R, &P, &(cli->YY));
   if(!i)
   {
    printf("Invalid ticket!"); //set error verbose
    e=ERC_OPEN_T_VERIFY;
    break;
   }

  //finalize voting, save voting result
   i=cli_fwrite(FILE_VOTR , cli->votd, sizeof(cli->votd));
   if(i!=sizeof(cli->votr))
   {
    e=ERC_OPEN_A_SAVE_VOTR;
    break;
   }

  memcpy(cli->votr, cli->votd, 16); //copy voting result
  cli->flags|=FLAG_OPEN; //opening compleet
  cli_fwrite(FILE_OPENA, pkt, OPEN_AL); //save packet
  break;
 }

 printf("Client: open ans %d\r\n", e);
 i=0; if(e) i=-e; else if(ee) i=ee+CLI_NOTE;
  crc=0; id=0;
  sh_clr();
  my_memclr(q, sizeof(q));
  my_memclr(&P, sizeof(P));
  my_memclr(&R, sizeof(R));
  my_memclr(res, sizeof(res));
  my_memclr(pkt, OPEN_AL);
  return i;
}

