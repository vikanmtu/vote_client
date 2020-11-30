#include "client.h"
#include "srv_verb.h"
#include "tcc.h"

#include "cli_ui.h"



#define UI_EVENT_SETSTAGE 0xFF
#define UI_MAXEVENTS 16

#define MSG_SRV 128

#define UI_STAGE_IDDL   0   //after start
#define UI_STAGE_INIT   1   //client must initialize (generate his key)
#define UI_STAGE_SCAN   2   //QR must scan QR code(or enter own number, psw and server's address)
#define UI_STAGE_GETS   3   //client must request voter's pk and voter's signature of registrator's pk)
#define UI_STAGE_IDNT   4   //client must authenticated on registrator's server
#define UI_STAGE_REGS   5  //client must registering on registartor's server
#define UI_STAGE_RSTR   6
#define UI_STAGE_JOIN   7  //client must join to voter's server (have id)
#define UI_STAGE_VOTE   8  //client must votes
#define UI_STAGE_OPEN   9 //client can open his vote (have encrypted vote)
#define UI_STAGE_FINE   10 //client already open his vote (have decrypted vote)

#define UI_CMD_IDLE 0
#define UI_CMD_GETS 1
#define UI_CMD_IDNT 2
#define UI_CMD_REGS 3
#define UI_CMD_JOIN 4
#define UI_CMD_VOTE 5
#define UI_CMD_OPEN 6

unsigned char ui_phase=0;  //0-not-anonimous phase, 1-anonomius
unsigned char ui_istcp=0; //flag of transport ready

unsigned char ui_events[UI_MAXEVENTS]={0,}
; //queue for events for GUI
unsigned char ui_evin=0; //pointer to input event
unsigned char ui_evout=0; //pointer to output event


unsigned char ui_pkt[TCC_MAXLEN]; //work buffer
unsigned char ui_req=0; //currently request to server

//client initialization (called from FormCreate on app start)
//arguments are system-specific private and public directories for store data
//returns 0 if sucess or client's error codes (1-127) on init process
short ui_init(char* prvdir, char* pubdir)
{
 unsigned char flags;
 short i;

 ui_setevent(UI_EVENT_SETSTAGE);  //set GUI to iddle state
 i=cli_init(prvdir, pubdir); //initialize client
 i-=CLI_NOTE; //error code 0-127
 if(i<0) i=0; if(i>127) i=127;  //0 is ok or 1-127 is errcode

 flags = cli_getflags(); //get current state
 if(flags & FLAG_SCAN) //run tcp server on having address
 {
  tcc_setsrv(cli->adr, 9055); //open tcp is server address was specified
  ui_istcp=1; //set flag of transport ready
 }
 if(flags & FLAG_REGS) ui_phase=1;  //set anonimous phase after registrator's mission sucess

 ui_setevent(UI_EVENT_SETSTAGE); //set new GUI stage
 ui_setevent(MSG_STAGE_INIT + MSG_SRV); //set note for initialization
 ui_setevent(i); //set initialization errcode

 return i; //returns error code on initialization
}



//try scan QR-code
short ui_scanqr(unsigned char* img, short w, short h)
{
 short i;
 unsigned char flags;

 i=cli_qr_rec(img, w, h); //scan image
 if(!i)
 {
  flags=cli_getflags();
  if(flags & FLAG_SCAN) //run tcp server on having address
  {
   tcc_setsrv(cli->adr, 9055); //open tcp is server address was specified
   ui_istcp=1; //set flag of transport ready
  }
  ui_setevent(UI_EVENT_SETSTAGE); //change GUI stage if success
 }
 return i; //return 0 if success
}

//get user data from file
short ui_setfile(char* path)
{
 FILE * pFile;
 unsigned char str[128];
 unsigned char data[32];
 short i;

 //try open file by path+name
 pFile = fopen (path,"rt"); //try open for read
 if(!pFile) //fule not exist
 {
  ui_setevent(ERR_SCAN_LOAD + MSG_SRV);
  return -1;
 }

 //load string from file
 str[0]=0;
 fgets(str, sizeof(str), pFile);
 fclose (pFile);

 //convert string to binary data
 i=str2bin(str, data, sizeof(data));
 if(i!=32) //check data length
 {
  ui_setevent(ERR_SCAN_LOAD + MSG_SRV);
  return -2;
 }

 //set user data
 i=cli_save_scan(data);
 if(i<0) //on data error
 {
  i=-i;
  if(i<128) ui_setevent(i);
  return -3;
 }

 //change GUI stage if success
 ui_setevent(UI_EVENT_SETSTAGE);
 return 0;
}

short ui_setuser(int num, char* psw, char* srv)
{
 char str[32];
 unsigned char data[32]={0,};
 short i, len;
 unsigned short w;


 //check password length
 len=strlen(psw);
 if((!len)||(len>15)) //wrong
 {
  ui_setevent(ERR_SCAN_PSW + MSG_SRV);
  return -1;
 }

 //check server's onion address
 strncpy(str, srv, sizeof(str));
 len=strlen(str);
 for(i=0;i<len;i++) if(str[i]=='.') str[i]=0; //skip suffix
 len=strlen(str);
 if(len!=16) //check length
 if((!len)||(len>15))
 {
  ui_setevent(ERR_SCAN_SRV + MSG_SRV);
  return -2;
 }

 //convert server's onion address from base32 to binary
 i=base32_decode(data+20, str);
 if(i) //if base32 string fail
 {
  ui_setevent(ERR_SCAN_SRV + MSG_SRV);
  return -3;
 }

 //copy pawwors and id to data
 strncpy((char*)data, psw, 16);
 itom(data+16, num);


 //add crc16 to  data
 w=telcrc16(data, 30);
 data[30]=w&0xFF;
 data[31]=w>>8;

 //set user data
 i=cli_save_scan(data);
 if(i<0) //on data error
 {
  i=-i;
  if(i<128) ui_setevent(i);
  return -3;
 }

 //change GUI stage if success
 ui_setevent(UI_EVENT_SETSTAGE);
 return 0;
}

//set user's vote 
short ui_setvote(char* vote)
{
  short i;
  short ret=0;

  //i=cli_vote_set(vote); //depricated version with revote
  i=cli_vote_set_once(vote); //client can vote only once
  if(i<0) //on error
  {
   i=-i;
   if(i<128) ui_setevent(i);
   ret=-1;
  }
  else ui_setevent(UI_EVENT_SETSTAGE); //change GUI stage if success

  if(i>CLI_WARN) //on notify
  {
   i-=CLI_WARN;
   if(i<128) ui_setevent(i);
  }

  return ret;
}

//get user data from QR-code: server and passwor, returns personal id
int ui_getuser(char** srv, char** psw)
{
 *srv = cli->adr;
 *psw = cli->pwd;
 return cli->id;
}

//get votes: ready for voter and opened result
int ui_getvote(char** voted, char** voter)
{
 *voted = cli->votd;
 *voter = cli->votr;
 return cli->num;
}

//get pointer to list of candidates
char* ui_getcnd(void)
{
 return (cli->cnd);
}


//Execute user's action
void ui_cmd(unsigned char cmd)
{
 short i;
 unsigned char req;
 switch(cmd) //process command by type
 {
  case UI_CMD_GETS:  //get server's keys
      ui_setevent(MSG_STAGE_GETS + MSG_SRV); //notify command
      i=cli_gets_req(ui_pkt); //process command
      req=GETS; //set state of waiting server's answer
      break;

  case UI_CMD_IDNT: //personal identification
      ui_setevent(MSG_STAGE_IDNT + MSG_SRV);
      i=cli_idnt_req(ui_pkt);
      req=IDNT;
      break;

  case UI_CMD_REGS: //personal registration
      ui_setevent(MSG_STAGE_REGS + MSG_SRV);
      i=cli_regs_req(ui_pkt);
      req=REGS;
      break;

  case UI_CMD_JOIN: //anonimous registration
      ui_setevent(MSG_STAGE_JOIN + MSG_SRV);
      i=cli_join_req(ui_pkt);
      req=JOIN;
      break;

  case UI_CMD_VOTE: //voting
      ui_setevent(MSG_STAGE_VOTE + MSG_SRV);
      i=cli_vote_req(ui_pkt);
      req=VOTE;
      break;

  case UI_CMD_OPEN: //opening vote
      ui_setevent(MSG_STAGE_OPEN + MSG_SRV);
      i=cli_open_req(ui_pkt);
      req=OPEN;
      break;

  default: //invalid command
      ui_setevent(ERR_CMD_WRONG + MSG_SRV); //notify invalid command
      i=0;
 }

 if(i<0) //check request error
 {
  i=-i;
  if(i<128) ui_setevent(i); //note request error
 }
 else if(i>TCC_HDR_LEN)  //check compose OK
 {
  ui_setevent(MSG_STAGE_RCVD + MSG_SRV); //notify sending
  i=tcc_send(ui_pkt); //connectto server
  if(!i) ui_req=req; //check OK and set requst type
  else if(i<0) //or notify error
  {
   i=-i;
   if(i<127) ui_setevent(i); //notify connecting error
  }
 }
 else ui_setevent(ERR_PKT_WRONG + MSG_SRV); //notify packet error
}


//transport thread: wait answer from server
void ui_process(void)
{
 short i=0, j=0;

 while(1)  //infinite loop
 {
  i=tcc_read(ui_pkt); //check transport and sleep
  if(!i) continue; //no data and no errors and no warnings

  if(i<0)  //transport error
  {
   i = -i;
   if(i<128) ui_setevent(i);
   ui_req=IDDL;  //clear request
   continue;
  }

  else if(i>CLI_WARN)  //transport warning
  {
    i-=CLI_WARN;
    if(i<128) ui_setevent(i); //notify warning
    continue;
  }

  //check packet in sufficient and answer type is matches request
   else if((i>TCC_HDR_LEN)&&(ui_req==ui_pkt[2]))  //ok
   {

    switch(ui_req) //process answer by type
    {
     case GETS:
        j=cli_gets_ans(ui_pkt);
        break;
     case IDNT:
        j=cli_idnt_ans(ui_pkt);
        break;
     case REGS:
        j=cli_regs_ans(ui_pkt);
        break;
     case JOIN:
        j=cli_join_ans(ui_pkt);
        break;
     case VOTE:
        j=cli_vote_ans(ui_pkt);
        break;
     case OPEN:
        j=cli_open_ans(ui_pkt);
        break;
     default:
        j=ERR_STAGE_WRONG+MSG_SRV;
    }

    if(j<-128) //server's error
    {
     j=-j;
     if(j<255) ui_setevent(j);
    }
    else if(j<0) //client's error
    {
     j=-j;
     if(j<128) ui_setevent(j);
    }
    else if(j>CLI_NOTE) //server's notification
    {
     j-=CLI_NOTE;
     if((j>0)&&(j<127)) ui_setevent(j+128);
     ui_setevent(MSG_SERVER_OK+MSG_SRV);
     ui_setevent(MSG_NEXT_STEP+MSG_SRV);
     ui_setevent(255);
    }
    else if(j<256)
    {
     ui_setevent(j);  //other
     ui_setevent(MSG_SERVER_OK+MSG_SRV);
     ui_setevent(MSG_NEXT_STEP+MSG_SRV);
     ui_setevent(255);
    }

    ui_req=IDDL;  //clear request
   }

 }
}

//========================event's queue===================

void ui_setevent(unsigned char ev)
{
 ui_events[ui_evin]=ev;
 ui_evin++;
 if(ui_evin>=UI_MAXEVENTS) ui_evin=0;
}

unsigned char ui_getevent(void)
{
 unsigned char ev;

 if(ui_evin == ui_evout) return 0;
 ev=ui_events[ui_evout];
 ui_events[ui_evout]=0;
 ui_evout++;
 if(ui_evout>=UI_MAXEVENTS) ui_evout=0;
 return ev;
}

unsigned char ui_get_stage(void)
{
 unsigned char flags;
 unsigned char stage=UI_STAGE_INIT;

 flags = cli_getflags();

 if(flags & FLAG_INIT) stage = UI_STAGE_SCAN;
 else return stage;

 if(flags & FLAG_SCAN) stage = UI_STAGE_GETS;
 else return stage;

 if(flags & FLAG_GETS) stage = UI_STAGE_IDNT;
 else return stage;

 if(flags & FLAG_IDNT) stage = UI_STAGE_REGS;
 else return stage;

 if(flags & FLAG_REGS) stage = UI_STAGE_RSTR;
 else return stage;

 if(ui_phase) stage = UI_STAGE_JOIN;
 else return stage;

 if(flags & FLAG_JOIN) stage = UI_STAGE_VOTE;
 else return stage;

 if(flags & FLAG_VOTE) stage = UI_STAGE_OPEN;
 else return stage;

 if(flags & FLAG_OPEN) stage = UI_STAGE_FINE;
 else return stage;
 
 return stage;
}

 //stop Tor (for Windows only)
 void tor_stop(void)
 {
   //kill old Tor process
#ifdef _WIN32
  char torcmd[64];
  strcpy(torcmd, (char*)"taskkill /IM tf_tor.exe /F");
  system(torcmd);
#endif

 }


 //start Tor (for Windows only)
 short tor_run(char* pp)
{
 #define TOR_TCP_PORT 6543
 #define TOR_WEB_PORT 8000
 #define TOR_SOC_PORT 9055
 //#define TOR_SERVER

 char path[512]={0,};
 char torcmd[1024];
 int i;
 int l;
 int pathlen;
 int showtor=0;
 FILE * pFile;

  //kill old Tor process
#ifdef _WIN32
  strcpy(torcmd, (char*)"taskkill /IM tf_tor.exe /F");
#else
  strcpy(torcmd, (char*)"killall -9 tf_tor");
#endif
  system(torcmd);

  //set tor directory path
  pathlen=strlen(pp);
  strncpy(path, pp, sizeof(path));
  if(pathlen!=strlen(path)) return -1;

  //check show tor window
  strncpy(path+pathlen, (char*)"show.txt", sizeof(path)-pathlen); //set torrc path
  pFile = fopen(path, "r" );
  if(pFile)
  {
   showtor=1;
   fclose(pFile);
   pFile=0;
  }

  strncpy(path+pathlen, (char*)"torrc", sizeof(path)-pathlen); //set torrc path
  pFile = fopen(path, "r" );
  if(pFile)
  {
   fclose(pFile);
   pFile=0;
  }
  else
  {
    pFile = fopen(path, "w" ); //try write to torrc
    if(pFile)
    {
     strcpy(torcmd, (char*)"RunAsDaemon 1"); //demonize Tor after run
 #ifndef _WIN32
	fprintf(pFile, "%s\r\n", torcmd); //this options only for Linux
 #endif
     strcpy(torcmd, (char*)"DataDirectory "); //Work directory will be created by Tor
     strncpy(path+pathlen, (char*)"tor_data", sizeof(path)-pathlen);
     strcpy(torcmd+strlen(torcmd), path);
     fprintf(pFile, "%s\r\n", torcmd);

#ifdef TOR_SERVER
      strcpy(torcmd, (char*)"HiddenServiceDir "); //Hidden service directore will be create by Tor
      strncpy(path+pathlen, (char*)"hidden_service", sizeof(path)-pathlen);
      strcpy(torcmd+strlen(torcmd), path);
      fprintf(pFile, "%s\r\n", torcmd);

      strcpy(torcmd, (char*)"HiddenServiceVersion 2"); //Version 2 of HS: short onion address with RCA key
      fprintf(pFile, "%s\r\n", torcmd);

      sprintf(torcmd, (char*)"HiddenServicePort %d", TOR_TCP_PORT);
      fprintf(pFile, "%s\r\n", torcmd);

      sprintf(torcmd, (char*)"HiddenServicePort %d", TOR_WEB_PORT);
      fprintf(pFile, "%s\r\n", torcmd);
 #else
      sprintf(torcmd, (char*)"SocksPort %d", TOR_SOC_PORT);
      fprintf(pFile, "%s\r\n", torcmd);
 #endif

     fclose (pFile);
     pFile=0;
    }
  }

  //set path to Tor executable

   strncpy(path+pathlen, (char*)"tf_tor.exe -f ", sizeof(path)-pathlen);
   strcpy(torcmd, path);
   //add path to torrc as parameter
   strncpy(path+pathlen, (char*)"torrc", sizeof(path)-pathlen);
   strncpy(torcmd+strlen(torcmd), path, sizeof(torcmd)-strlen(torcmd));

   i=0;
    //run Tor in separated thread
#ifdef _WIN32



if(0) //use CreateProcess and wait 2 sec for Tor will be stable before next steps
{
   STARTUPINFOA si;
   PROCESS_INFORMATION pi;
   memset(&si, 0, sizeof(si));
   si.cb = sizeof(si);
   si.wShowWindow=SW_HIDE;
   //si.wShowWindow=SW_SHOWNORMAL;
   memset(&pi, 0, sizeof(pi));
   if( !CreateProcessA( NULL,   // No module name (use command line)
        torcmd,        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        0,              // Set handle inheritance to FALSE
        CREATE_NEW_CONSOLE,              // Creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory
        &si,            // Pointer to STARTUPINFO structure
        &pi )           // Pointer to PROCESS_INFORMATION structure
    )
    {
      i=(int)GetLastError();
     printf( "CreateProcess failed (%d)\r\n", (int)GetLastError() );
    }
    else WaitForSingleObject( pi.hProcess, 2000 );

}
else
{
  //run tor
  if(showtor) WinExec(torcmd, SW_SHOW); //test mode
  else WinExec(torcmd, SW_HIDE); //runs Tor hide  SW_HIDE
}
#else
   system(torcmd); //Linux: start Tor, wait for demonize
#endif

 return i;
}





short tor_run1(void)
{
 #define TOR_TCP_PORT 6543
 #define TOR_WEB_PORT 8000
 #define TOR_SOC_PORT 9055
 //#define TOR_SERVER

 char path[512]={0,};
 char torcmd[1024];
 int i;
 int l;
 int pathlen;
 FILE * pFile;

  //kill old Tor process
#ifdef _WIN32
  strcpy(torcmd, (char*)"taskkill /IM tf_tor.exe /F");
#else
  strcpy(torcmd, (char*)"killall -9 tf_tor");
#endif
  system(torcmd);


 //get path
  i=wai_getExecutablePath(NULL, 0, NULL);
  if(i<(sizeof(path)-64)) wai_getExecutablePath(path, i, &l);
  if(!l) path[0]=0;
  else for(i=l; i>=0; i--) if((path[i]==92)||(path[i]==47)) break;
  if(i) path[i]=0;
  pathlen=strlen(path);

  //create registrator's data directory
  strncpy(path+pathlen, (char*)"/tor", sizeof(path)-pathlen); //set directory path
  #ifdef _WIN32
  mkdir(path);
  #else
  mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  #endif


  strncpy(path+pathlen, (char*)"/tor/torrc", sizeof(path)-pathlen); //set directory path
  pFile = fopen(path, "r" );
  if(pFile)
  {
   fclose(pFile);
   pFile=0;
  }
  else
  {
    pFile = fopen(path, "w" ); //try write to torrc
    if(pFile)
    {
     strcpy(torcmd, (char*)"RunAsDaemon 1"); //demonize Tor after run
 #ifndef _WIN32
	fprintf(pFile, "%s\r\n", torcmd); //this options only for Linux
 #endif
     strcpy(torcmd, (char*)"DataDirectory "); //Work directory will be created by Tor
     strncpy(path+pathlen, (char*)"\\tor\\tor_data", sizeof(path)-pathlen);
     strcpy(torcmd+strlen(torcmd), path);
     fprintf(pFile, "%s\r\n", torcmd);

#ifdef TOR_SERVER
      strcpy(torcmd, (char*)"HiddenServiceDir "); //Hidden service directore will be create by Tor
      strncpy(path+pathlen, (char*)"\\tor\\hidden_service", sizeof(path)-pathlen);
      strcpy(torcmd+strlen(torcmd), path);
      fprintf(pFile, "%s\r\n", torcmd);

      strcpy(torcmd, (char*)"HiddenServiceVersion 2"); //Version 2 of HS: short onion address with RCA key
      fprintf(pFile, "%s\r\n", torcmd);

      sprintf(torcmd, (char*)"HiddenServicePort %d", TOR_TCP_PORT);
      fprintf(pFile, "%s\r\n", torcmd);

      sprintf(torcmd, (char*)"HiddenServicePort %d", TOR_WEB_PORT);
      fprintf(pFile, "%s\r\n", torcmd);
 #else
      sprintf(torcmd, (char*)"SocksPort %d", TOR_SOC_PORT);
      fprintf(pFile, "%s\r\n", torcmd);
 #endif

     fclose (pFile);
     pFile=0;
    }
  }

  //set path to Tor executable
   strncpy(path+pathlen, (char*)"\\tor\\tf_tor -f ", sizeof(path)-pathlen);
   strcpy(torcmd, path);
   //add path to torrc as parameter
   strncpy(path+pathlen, (char*)"\\tor\\torrc", sizeof(path)-pathlen);
   strncpy(torcmd+strlen(torcmd), path, sizeof(torcmd)-strlen(torcmd));




    //run Tor in separated thread
#ifdef _WIN32
if(1) //use CreateProcess and wait 2 sec for Tor will be stable before next steps
{
   STARTUPINFO si;
   PROCESS_INFORMATION pi;
   memset(&si, 0, sizeof(si));
   si.cb = sizeof(si);
   //si.wShowWindow=SW_HIDE;
   si.wShowWindow=SW_SHOWNORMAL;
   memset(&pi, 0, sizeof(pi));
   if( !CreateProcess( NULL,   // No module name (use command line)
        torcmd,        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        0,              // Set handle inheritance to FALSE
        CREATE_NEW_CONSOLE,              // Creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory
        &si,            // Pointer to STARTUPINFO structure
        &pi )           // Pointer to PROCESS_INFORMATION structure
    )
    printf( "CreateProcess failed (%d)\r\n", (int)GetLastError() );
    else WaitForSingleObject( pi.hProcess, 2000 );

}
#else
   system(torcmd); //Linux: start Tor, wait for demonize
#endif




 return 0;
}



