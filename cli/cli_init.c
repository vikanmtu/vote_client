#include "cli_scan.h"
#include "client.h"

 #if defined _WIN32
#include <direct.h>
#elif defined __GNUC__
#include <sys/types.h>
#include <sys/stat.h>
#endif

//initialize client
short cli_init(char* prvdir, char* pubdir)
{
 char path[512];
 char str[272];
 char buf[256];
 char sec[32]; //secret material
 int pathlen=0;
 int i;
 short ret;
 unsigned char e=0;

 while(1)
 {
  //initialize trng
  for(i=0;i<1000;i++)
  {
   ret=trng_init();
   if(ret==3) break;
  }
  if(ret!=3)
  {
   e=ERC_INIT_RNG;
   break;
  }


  trng_get((unsigned char*)cli->x, sizeof(cli->x));
  cprng_init(cli->x, sizeof(cli->x));


 //set path

  pathlen=strlen(prvdir);
  i=cli_set_prvpath(prvdir);
  if(i!=pathlen)
  {
   e=ERC_INIT_PRVP;
   break;
  }


  pathlen=strlen(pubdir);
  i=cli_set_pubpath(pubdir);
  if(i!=pathlen)
  {
   e=ERC_INIT_PUBP;
   break;
  }






  my_memclr(cli, sizeof(*cli)); //clear flags
  cli->flags=0;
  cli->cnt=0;

  //read secret material
  i=cli_fread(FILE_SEC, sec, sizeof(sec));
  if(i!=sizeof(sec))  //no secret material yet
  {
   cprng_get_bytes(sec, sizeof(sec)); //generate new secret nmaterial

   //write to file
   i=cli_fwrite(FILE_SEC, sec, sizeof(sec));
   if(i!=sizeof(sec))
   {
   e=ERC_INIT_WRITESEC;
   break;
   }
  }

  //compute secret keys from material
  sh_ini();
  sh_upd((sec), sizeof(sec)); //use secret material
  sh_xof();
  sh_out(cli->x, sizeof(cli->x)); //output client's secret key
  sh_out(cli->s, sizeof(cli->s)); //output SPEKE secret key
  sh_out(cli->b, sizeof(cli->b)); //output blindigg secret value
  sh_out(cli->enc, sizeof(cli->enc)); //output symmetric encrtpting key
  sh_clr(); //clear secrets as fast as possible
  my_memclr(sec, sizeof(sec));

  //reduce secret keys to field
  i=bls_reduce(cli->x);
  if(!i)
  {
   e=ERC_INIT_X;
   break;
  }

  //skip for X25519
  //i=bls_reduce(cli->s);
  //if(!i)
  //{
  // e=ERC_INIT_S;
  // break;
  //}

  i=bls_reduce(cli->b);
  if(!i)
  {
   e=ERC_INIT_X;
   break;
  }

  //compute client's public keys
  i=bls_key(&(cli->XX), &(cli->X), cli->x); //output: XX is G2 public key, X is G1 public key, x is private key
  if(!i)
  {
   e=ERC_INIT_GETXX;
   break;
  }

  //compute hash of our pubkey
  sh_ini();
  sh_upd((unsigned char*)(&cli->XX), FP2_PK_LEN);
  sh_xof();
  sh_out(cli->key, sizeof(cli->key));

  cli->flags|=FLAG_INIT; //already init, ready for scan

  //read QR-code data
  i=cli_fread(FILE_SCAN, buf, QRCD_L);
  if(i!=QRCD_L)
  {
   e=ERC_INIT_LOAD_QR;
   break;
  }
  cli_set_scan(buf);

  cli->flags|=FLAG_SCAN; //alsedy scan, ready for gets



  //load voter's signature of registrator's pk
  i=cli_fread(FILE_RPS, (unsigned char*)cli->rps, sizeof(cli->rps));
  if(i!=sizeof(cli->rps))
  {
   e=ERC_INIT_LOAD_RPS;
   break;
  }

  //load voter's pk
  i=cli_fread(FILE_VPK, (unsigned char*)&cli->YY, sizeof(cli->YY));
  if(i!=sizeof(cli->YY))
  {
   e=ERC_INIT_LOAD_VPK;
   break;
  }

  cli->flags|=FLAG_GETS; //alsedy gets, ready for idnt

  //load SPEKE shared secret
  i=cli_fread(FILE_SHR, cli->shr, sizeof(cli->shr));
  if(i!=sizeof(cli->shr))
  {
   e=ERC_INIT_LOAD_SHR;
   break;
  }

   //read registartor's pubkey
  i=cli_fread(FILE_RPK, (unsigned char*)&(cli->RR), sizeof(cli->RR));
  if(i!=sizeof(cli->RR))
  {
   e=ERC_INIT_LOAD_RPK;
   break;
  }

  cli->flags|=FLAG_IDNT; //alsedy idnt, ready for regs

  //read registrator's signature of our public key
  i=cli_fread(FILE_SIGN, (unsigned char*)cli->sig, sizeof(cli->sig));
  if(i!=sizeof(cli->sig))
  {
   e=ERC_INIT_LOAD_SIG;
   break;
  }

  cli->flags|=FLAG_REGS; //alsedy regs, ready for join

  //read clint's number in voter's list
  i=cli_fread(FILE_NUM, buf, 4+sizeof(cli->cnd));
  if(i!=(4+sizeof(cli->cnd)))
  {
   e=ERC_INIT_LOAD_NUM;
   break;
  }
  cli->num = mtoi(buf);
  memcpy(cli->cnd, buf+4, sizeof(cli->cnd));

  cli->flags|=FLAG_JOIN; //alredy join, ready for vote


    //read votes counter
  i=cli_fread(FILE_CNT, buf, 4);
  if(i!=4)
  {
   e=ERC_INIT_LOAD_CNT;
   break;
  }
  cli->cnt = mtoi(buf);

  //read voting decrypted data
  i=cli_fread(FILE_VOTD, cli->votd, sizeof(cli->votd));
  if(i!=sizeof(cli->votd))
  {
   e=ERC_INIT_LOAD_VOTD;
   break;
  }

  //read voting encrypted data
  i=cli_fread(FILE_VOTE, cli->vote, sizeof(cli->vote));
  if(i!=sizeof(cli->vote))
  {
   e=ERC_INIT_LOAD_VOTE;
   break;
  }


  cli->flags|=FLAG_VOTE; //alredy vote, ready for open

  //read voting result
  i=cli_fread(FILE_VOTR, cli->votr, sizeof(cli->votr));
  if(i!=sizeof(cli->votr))
  {
   e=ERC_INIT_LOAD_VOTR;
   break;
  }

  cli->flags|=FLAG_OPEN; //alsedy open, success
  
  break;
 }


 printf("client: state %02X inited %d\r\n", cli->flags, e);  


 sh_clr();
 my_memclr(sec, sizeof(sec));
 my_memclr(path, sizeof(path));
 my_memclr(str, sizeof(str));
 my_memclr(buf, sizeof(buf));

  return e+CLI_NOTE;
}



