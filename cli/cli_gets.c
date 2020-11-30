#include "client.h"


//compose client's join request to server
short cli_gets_req(unsigned char* pkt)
{
 unsigned int crc;
 short i; //general
 unsigned char e=0; //error flag


 while(1)
 {

  if(!(cli->flags & FLAG_SCAN))
  {
   e=ERC_GETS_R_NOSCAN;
   break;
  }



   //output data
  my_memclr(pkt, GETS_RL); //clear  data
  stom(pkt, GETS_RL);  //packet's len
  pkt[2]=GETS; //type
  pkt[3]=0; //note

  //empty output
  break;
 }

 //compute crc
 if(!e)
 {
  i=GETS_RC;
  crc=crc32_le(pkt, GETS_RC); //compute CRC
  itom(pkt+GETS_RC, crc);  //output
  cli_fwrite(FILE_GETSR, pkt, GETS_RL); //save packet
  i=GETS_RL;
 } else i=-e;

  printf("Client: gets req %d\r\n", e);

  //clear data
  crc=0;

  return i;
}

//=====================================================================
//process server's join answer
short cli_gets_ans(unsigned char* pkt)
{

 unsigned int crc=mtoi(pkt+GETS_AC); //packets crc
 unsigned char e=0;
 unsigned char ee=pkt[3];
 short i;

 while(1)
 {
  //check packet's type
  if(GETS!=pkt[2])
  {
   e=ERC_GETS_A_TYPE;
   break;
  }

 //check packet's length
  if(GETS_AL!=mtos(pkt))
  {
   e=ERC_GETS_A_LEN;
   break;
  }

  //check server's error
  if(ee&CLI_FATAL_ERR)
  {
   e=ee;
   break;
  }


  //check client ready for idnt
  if(!(cli->flags & FLAG_SCAN))
  {
   e=ERC_GETS_A_NOSCAN;
   break;
  }


   //check crc
  if(crc!=crc32_le(pkt, GETS_AC))
  {
   e=ERC_GETS_A_CRC;
   break; //no send any answer
  }



  //save voter's signature of registrator's pk
  memcpy(cli->rps, pkt+GETS_AS, GETS_AS_LEN);
  i=cli_fwrite(FILE_RPS , (unsigned char*)cli->rps, sizeof(cli->rps));
  if(i!=sizeof(cli->rps))
  {
    e=ERC_GETS_A_SAVES;
    break;
  }



  //save voter's pk
  memset(&cli->YY, 0, sizeof(cli->YY));
  memcpy(&cli->YY, pkt+GETS_AV, GETS_AV_LEN);
  i=cli_fwrite(FILE_VPK , (unsigned char*)&cli->YY, sizeof(cli->YY));
  if(i!=sizeof(cli->YY))
  {
    e=ERC_GETS_A_SAVEP;
    break;
  }



  cli->flags|=FLAG_GETS; //getting compleet
  cli_fwrite(FILE_GETSA, pkt, GETS_AL); //save packet
  break;
 }


 printf("Client: gets ans %d\r\n", e);

 my_memclr(pkt, GETS_AL);
 crc=0;
 i=0; if(e) i=-e; else if(ee) i=ee+CLI_NOTE;

 return i;
}

