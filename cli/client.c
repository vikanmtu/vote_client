#include "client.h"
#include "srv_verb.h"
#include "tcc.h"

#ifdef _WIN32
    #include "conio.h"
#endif


 #if defined _WIN32
#include <direct.h>
#elif defined __GNUC__
#include <sys/types.h>
#include <sys/stat.h>
#endif


#define MAX_PLEN 512  //maximal length of execution path
#define MAX_FILE 24   //maximal number of files
#define MAX_PRV 11    //maximal number of private file
#define MAX_DATA 512  //maximal file length (double bin size + 1)


unsigned char cli_pkt[TCC_MAXLEN];
unsigned char cli_request=IDDL;

const char* cli_files[MAX_FILE]={
"sec.txt",  //client's secret material
"qrc.txt",  //QR code data (clint's id, server's address, registration password)
"rps.txt",  //voter's signature of registrator's pk
"vpk.txt",  //voter;s public key

"shr.txt",  //SPEKE shared secret
"rpk.txt",  //registrator's public key
"sig.txt",  //registrator's signature of client's public key
"num.txt",  //clint's number in voter's list


"cnt.txt",  //votes one-way counter
"vod.txt",   //decrypted voting data
"vot.txt",  //encrypted voting data
"vor.txt",  //voting result

"0_r.txt",  //gets
"0_a.txt",
"1_r.txt", //indf
"1_a.txt",

"2_r.txt", //regs
"2_a.txt",
"3_r.txt",  //join
"3_a.txt",

"4_r.txt",  //vote
"4_a.txt",
"5_a.txt",  //open
"5_r.txt"
};





cli_data scli;
cli_data* cli = &scli;

char pub_path[MAX_PLEN]={0,};
char prv_path[MAX_PLEN]={0,};
short pub_path_len=0;
short prv_path_len=0;



short cli_set_pubpath(char* p)
{
 strncpy(pub_path, p, sizeof(pub_path)-16);
 pub_path_len=strlen(pub_path);
 return pub_path_len;
}


short cli_set_prvpath(char* p)
{
 strncpy(prv_path, p, sizeof(prv_path)-16);
 prv_path_len=strlen(prv_path);
 return prv_path_len;
}


short cli_fread(short file, unsigned char* data, short len)
{
 FILE * pFile;
 char str[512];
 short l=0;

 if(len>255) return 0;

 if(file>MAX_PRV)
 {
  strncpy(pub_path+pub_path_len, cli_files[file], 12);
  pFile = fopen (pub_path,"rt"); //try open for read
 }
 else
 {
  strncpy(prv_path+prv_path_len, cli_files[file], 12);
  pFile = fopen (prv_path,"rt"); //try open for read
 }

 if(pFile) //opened
 {
   str[0]=0;
   fgets(str, sizeof(str), pFile);
   fclose (pFile);
   l=str2bin(str, data, len);
   my_memclr(str, sizeof(str));
 }
 
 return l;
}


short cli_fwrite(short file, unsigned char* data, short len)
{
 FILE * pFile;
 char str[512];
 short l=0;

 if(len>255) return 0;

 if(file>MAX_PRV)
 {
  strncpy(pub_path+pub_path_len, cli_files[file], 12);
  pFile = fopen (pub_path,"wt"); //try open for write
 }
 else
 {
  strncpy(prv_path+prv_path_len, cli_files[file], 12);
  pFile = fopen (prv_path,"wt"); //try open for write
 }

 if(pFile) //opened
 {
  bin2str(data, str, len);
  fprintf(pFile, "%s\r\n", str);
  fclose (pFile);
  l=len;
 }

 return l;
}


unsigned char cli_getflags(void)
{
 return cli->flags;
}


//==============Interface====================================



//startup client
//returns 0 on success
short cli_start(void)
{
 short i;

 //general init
        srv_verb_ini();
        cli_verb_ini();

  //client init
        i=cli_init("D:/votesec/","D:/votepub/");
        cli_outresult(CLI_STEP_INIT, i);

    i=tcc_init();
    if(i) return -1;

    tcc_setsrv(cli->adr, 9055);



  //--------------test1----------------------
        //scan
       // i=cli_set_test(cli_pkt);
       // if(i) return -1; //!!!!!!!
       // i=cli_save_scan(cli_pkt);
       // cli_outresult(CLI_STEP_SCAN, i);
       // if(i) return -1; //!!!!!!!

   //--------------test2----------------------
  // i=cli_req(GETS);

  printf("*******************************************************\r\n");


        return 0;
}





//send request to server
//returns 0 if success
short cli_req(unsigned char req)
{
  short i=0;


  tcc_close(); //close prevoius session
  cli_request=IDDL; //ckear request type
  switch(req)  //switch by specified request's type and compose packet
   {
    case GETS:
        i=cli_gets_req(cli_pkt);
        cli_outresult(CLI_STEP_GETS_R, i);
        break;
    case IDNT:
        i=cli_idnt_req(cli_pkt);
        cli_outresult(CLI_STEP_IDNT_R, i);
        break;
    case REGS:
        i=cli_regs_req(cli_pkt);
        cli_outresult(CLI_STEP_REGS_R, i);
        break;
    case JOIN:
        i=cli_join_req(cli_pkt);
        cli_outresult(CLI_STEP_JOIN_R, i);
        break;
    case VOTE:
        i=cli_vote_req(cli_pkt);
        cli_outresult(CLI_STEP_VOTE_R, i);
        break;
    case OPEN:
        i=cli_open_req(cli_pkt);
        cli_outresult(CLI_STEP_OPEN_R, i);
   }

   if(i>TCC_HDR_LEN)  //check compose OK
   {
     i=tcc_send(cli_pkt); //send packet to server
     if(!i) cli_request=req; //check OK and set requst type
     else
     {
      cli_outresult(CLI_STEP_SEND, i);
     }
     i=0;// request OK
   }
   else i=-1; //requst fail

   return i;
}

//client's task
void cli_process(void)
{
 short i, j;
 char c;

 while(1) //ininite loop
 {

  #ifdef _WIN32
   //scan keyboard
     if(kbhit()) //if key was pressed
     {
      printf("........................................................\r\n");
      j=getch(); //read char

      if(j==113) //q
      {
       i=cli_set_test(cli_pkt);
       if(i) printf("QR set error\r\n");
       else
       {
        i=cli_save_scan(cli_pkt);
        cli_outresult(CLI_STEP_SCAN, i);
        if(i) printf("QR save error\r\n");
       }
      }

      else if(j==103) //g
      {
       i=cli_req(GETS);
      }

      else if(j==105) //i
      {
       i=cli_req(IDNT);
      }

      else if(j==114) //r
      {
       i=cli_req(REGS);
      }

      else if(j==106) //j
      {
       i=cli_req(JOIN);
      }

      else if(j==115) //s
      {
       i=cli_vote_set("gegel");
       cli_outresult(CLI_STEP_SCAN, i);
      }

      else if(j==118) //v
      {
       i=cli_req(VOTE);
      }

      else if(j==111) //o
      {
       i=cli_req(OPEN);
      }






     }


 #endif

   //try read data from server
   i=tcc_read(cli_pkt);
   if(!i) continue; //no data and no errors and no warnings


   if(i<0)   //error
   {
    cli_outresult(CLI_STEP_RCVD, i);
    cli_request=IDDL;  //clear request  on error
   }

   else if(i>=CLI_WARN)  //warning
   {
    cli_outresult(CLI_STEP_RCVD, i);
   }

   //check packet in sufficient and answer type is matches request
   else if((i>TCC_HDR_LEN)&&(cli_request==cli_pkt[2]))  //ok
   {
    switch(cli_request) //process answer by type
    {
     case GETS:
        j=cli_gets_ans(cli_pkt);
        cli_outresult(CLI_STEP_GETS_A, j);
        break;
     case IDNT:
        j=cli_idnt_ans(cli_pkt);
        cli_outresult(CLI_STEP_IDNT_A, j);
        break;
     case REGS:
        j=cli_regs_ans(cli_pkt);
        cli_outresult(CLI_STEP_REGS_A, j);
        break;
     case JOIN:
        j=cli_join_ans(cli_pkt);
        cli_outresult(CLI_STEP_JOIN_A, j);
        break;
     case VOTE:
        j=cli_vote_ans(cli_pkt);
        cli_outresult(CLI_STEP_VOTE_A, j);
        break;
     case OPEN:
        j=cli_open_ans(cli_pkt);
        cli_outresult(CLI_STEP_OPEN_A, j);
    }
    cli_request=IDDL;  //clear request
   }



 }

}
