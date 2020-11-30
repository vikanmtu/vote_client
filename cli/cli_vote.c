#include "client.h"


short cli_vote_set(char* vote)
{
 short i;
 unsigned char res[4];
 unsigned char e=0; //error flag
 unsigned char r=0; //replay flag


 while(1)
 {

 //check we inited and not opened
 if(cli->flags & FLAG_OPEN)
 {
  e=ERC_VOTE_S_OPENED;
  break;
 }
 if(!(cli->flags & FLAG_INIT))
 {
  e=ERC_VOTE_S_NOINIT;
  break;
 }

  if(cli->cnt>1)
  {
   i=strcmp(cli->votd, vote);
   if(i) r=CLI_VOTE_REWRITE;
  }

 //increment voting counter
   cli->cnt++;
   itom(res, cli->cnt);
   i=cli_fwrite(FILE_CNT , res, 4);
   if(i!=4)
   {
    e=ERC_VOTE_S_SAVE_TMR;
    break;
   }

   //set new vote
   strncpy(cli->votd, vote, sizeof(cli->votd));
   i=strlen(cli->votd);

   i=cli_fwrite(FILE_VOTD , cli->votd, sizeof(cli->votd));
   if(i!=sizeof(cli->votd))
   {
    e=ERC_VOTE_S_SAVE_VOTD;
    break;
   }
   
   break;
  }

   if(e) i=-e; else i=r+CLI_WARN;
   return i;
}

short cli_vote_set_once(char* vote)
{
 short i;
 unsigned char res[4];
 unsigned char e=0; //error flag
 unsigned char r=0; //replay flag


 while(1)
 {

 //check we not voted yet
 if(cli->flags & (FLAG_OPEN + FLAG_VOTE))
 {
  e=ERC_VOTE_S_OPENED;
  break;
 }
 if(!(cli->flags & FLAG_INIT))
 {
  e=ERC_VOTE_S_NOINIT;
  break;
 }

   if(vote[0]) //check vote is specified
   {
    //========vote is specified=========================
    if(cli->votd[0]) //check vote already setted
    {
     //------vote alredy setted----------------------------
     if(strcmp(vote, cli->votd)) //attemp to reqrite vote
     {
      e=CLI_VOTE_REWRITE;
      break;
     }
    }
  //--------vote is not setted yet---------------------
    else //no vote setted: set new
    {
     //set voting counter
     cli->cnt=1;
     itom(res, cli->cnt);
     i=cli_fwrite(FILE_CNT , res, 4);
     if(i!=4)
     {
      e=ERC_VOTE_S_SAVE_TMR;
      cli->cnt=0;
      break;
     }

     //set vote
     strncpy(cli->votd, vote, sizeof(cli->votd));
     i=cli_fwrite(FILE_VOTD , cli->votd, sizeof(cli->votd));
     if(i!=sizeof(cli->votd))
     {
      e=ERC_VOTE_S_SAVE_VOTD;
      cli->votd[0]=0;
      break;
     }
    }
   }
   else
   {
    //=================vote is not specified
    if(cli->votd[0]) //check vote already setted
    {
     //-------------vote is already setted-----------------
     r=CLI_VOTE_REWRITE;  //note: existed vote will be used
    }
    else
    {
      //--------vote is not setted yet---------------------
      e=ERC_VOTE_EMPTY;  //error: vote must be specified
      break;
    }
   }


   break;
  }

   if(e) i=-e; else i=r+CLI_WARN;
   return i;
}



//=====================================================================

//compose client's vote request to server
short cli_vote_req(unsigned char* pkt)
{
 unsigned int crc;
 short i; //general
 unsigned char e=0; //error flag
 fp_t q; //ECC field value
 ecpoint_fp P; //ECC uncompressed point
 ecpoint_fp R; //ECC multiplication result
 unsigned char res[64];

 while(1)
 {

  if(!(cli->flags & FLAG_JOIN))
  {
   e=ERC_VOTE_R_NOJOIN;
   break;
  }

   //check we inited and not opened
 if(cli->flags & FLAG_OPEN)
 {
   e=ERC_VOTE_R_OPENED;
   break;
 }

 if(!cli->votd[0])
 {
  e=ERC_VOTE_EMPTY;
  break;
 }

  //encrypt voting
  sh_ini();
  sh_upd(&cli->cnt, sizeof(cli->cnt));  //use vote counter
  sh_upd(cli->enc, sizeof(cli->enc));  //use symmetric encrypting key
  sh_xof();
  sh_enc(cli->votd, cli->vote, 16);  //encrypt
  sh_xof();
  sh_out(cli->vote+16, 16); //output mac


  //output data
  my_memclr(pkt, VOTE_RL); //clear  data
  stom(pkt, VOTE_RL);  //packet's len
  pkt[2]=VOTE; //type
  pkt[3]=0; //note

  itom(pkt+VOTE_RN, cli->num);
  itom(pkt+VOTE_RW, cli->cnt);
  memcpy(pkt+VOTE_RV, cli->vote, VOTE_RV_LEN);  //output vote
  memcpy(pkt+VOTE_RM, cli->vote+16, VOTE_RM_LEN);  //output mac

  //hash packet to message
  sh_ini();
  sh_upd(pkt, VOTE_RA);
  sh_xof();
  sh_out(res, 32); //output fp value

  //hash to point
  memcpy(q, res, sizeof(q));
  i=bls_hash(&P, q);   //message
  if(!i) //point invalid
  {
   printf("Invalid point!"); //set error verbose
   e=ERC_VOTE_R_HASH_V;
   break;
  }

  //sign message
  bls_sign(&R, &P, cli->x); //sign message
  //compress signature
  bls_compress(q, &R);

  memcpy(pkt+VOTE_RA, q, VOTE_RA_LEN);  //output signature
  memcpy(pkt+VOTE_RK, &cli->XX, VOTE_RK_LEN);  //output client's Q2 pubkey
  break;
 }

 //compute crc
 if(!e)
 {
  crc=crc32_le(pkt, VOTE_RC); //compute CRC
  itom(pkt+VOTE_RC, crc);  //output
  cli_fwrite(FILE_VOTER, pkt, VOTE_RL); //save packet
  i=VOTE_RL;
 } else i=-e;

 printf("Client: vote %d req %d\r\n", cli->cnt, e);

  //clear data
  crc=0;
  sh_clr();
  my_memclr(q, sizeof(q));
  my_memclr(&P, sizeof(P));
  my_memclr(&R, sizeof(R));
  my_memclr(res, sizeof(res));
  return i;
}


//=====================================================================

//process server's join answer
short cli_vote_ans(unsigned char* pkt)
{
 fp_t q; //ECC field value
 ecpoint_fp P; //ECC uncompressed point
 ecpoint_fp R; //ECC multiplication result
 unsigned char res[64];
 
 short i; //general
 unsigned char e=0; //error flag
 unsigned char ee=pkt[3]; //external error flag
 int id=mtoi(pkt+VOTE_AN); //user's id
 int cnt=mtoi(pkt+VOTE_AW); //counter 
 unsigned int crc=mtoi(pkt+VOTE_AC); //packets crc


 while(1)
 {
 //check packet's type
  if(VOTE!=pkt[2])
  {
   e=ERC_VOTE_A_TYPE;
   break;
  }

 //check packet's length
  if(VOTE_AL!=mtos(pkt))
  {
   e=ERC_VOTE_A_LEN;
   break;
  }

  //check server's error
  if(ee&CLI_FATAL_ERR)
  {
   e=ee;
   break;
  }

  //check client ready for idnt
  if(!(cli->flags & FLAG_JOIN))
  {
   e=ERC_VOTE_A_NOJOIN;
   break;
  }

    //check we inited and not opened
 if(cli->flags & FLAG_OPEN)
 {
   e=ERC_VOTE_A_OPENED;
   break;
 }


  if(id!=cli->num)
  {
   e=ERC_VOTE_T_NUM;
   break; //no send any answer
  }

  if(cnt!=cli->cnt)
  {
   e=ERC_VOTE_T_TMR;
   break; //no send any answer
  }


  //check key in ticket is equal with our key
  i=isequal(cli->vote, pkt+VOTE_AV, VOTE_AV_LEN);
  if(!i)
  {
   e=ERC_VOTE_T_VOTE;
   break; //no send any answer
  }

  //check key in ticket is equal with our key
  i=isequal(cli->vote+16, pkt+VOTE_AM, VOTE_AM_LEN);
  if(!i)
  {
   e=ERC_VOTE_T_MAC;
   break; //no send any answer
  }


   //check crc
  if(crc!=crc32_le(pkt, VOTE_AC))
  {
   e=ERC_VOTE_A_CRC;
   break; //no send any answer
  }


  //decompress  into point (tickets signature)
  memcpy(q, pkt+VOTE_AT, sizeof(q));
  i=bls_uncompress(&P, q);
  if(!i) //point invalid
  {
   printf("Invalid point!"); //set error verbose
   e=ERC_VOTE_T_POINT_SIG;
   break;
  }

  //signing header, id and key
   memcpy(res, "VOTE", 4); //salt for joivote ticket
   sh_ini();
   sh_upd(res, 4); //hash salt
   sh_upd(pkt, VOTE_AT); //hash packet
   sh_xof();
   sh_out(res, 32); //output fp[32] message

   //convert message to point
   memcpy(q, res, sizeof(q));
   i=bls_hash(&R, q); //message
   if(!i) //point invalid
   {
    printf("Invalid point!"); //set error verbose
    e=ERC_VOTE_T_HASH;
   }

   //check ticket
   i=bls_verify(&R, &P, &(cli->YY));
   if(!i)
   {
    printf("Invalid ticket!"); //set error verbose
    e=ERC_VOTE_T_VERIFY;
    break;
   }


   //save encrypted vote
   i=cli_fwrite(FILE_VOTE, cli->vote, sizeof(cli->vote));
   if(i!=sizeof(cli->vote))
   {
    e=ERC_VOTE_A_SAVE_VOTE;
    break;
   }

  cli->flags|=FLAG_VOTE; //registration compleet
  cli_fwrite(FILE_VOTEA, pkt, VOTE_AL); //save packet
  break;
 }
  i=0; if(e) i=-e; else if(ee) i=ee+CLI_NOTE;
  printf("Client: vote %d ans %d\r\n", cli->cnt, e);

  crc=0; id=0;
  sh_clr();
  my_memclr(q, sizeof(q));
  my_memclr(&P, sizeof(P));
  my_memclr(&R, sizeof(R));
  my_memclr(res, sizeof(res));
  my_memclr(pkt, VOTE_AL);
  return i;
}





