#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "amath.h"

#include "srv_verb.h"
#include "cli_verb.h"

const char* cli_steps[MAX_CLI_STEPS]={
"CLI_STEP_INIT",
"CLI_STEP_SCAN",
"CLI_STEP_GETS_R",
"CLI_STEP_GETS_A",
"CLI_STEP_IDNT_R",
"CLI_STEP_IDNT_A",
"CLI_STEP_REGS_R",
"CLI_STEP_REGS_A",
"CLI_STEP_JOIN_R",
"CLI_STEP_JOIN_A",
"CLI_STEP_VOTE_R",
"CLI_STEP_VOTE_A",
"CLI_STEP_OPEN_R",
"CLI_STEP_OPEN_A",
"CLI_STEP_SEND",
"CLI_STEP_RCVD",
};


const char* cli_empty_str=" ";
const char* cli_verbs_data[MAX_CLI_VERBS]={
"0: SUCCESS",

"1: ERC_INIT_RNG",
"2: ERC_INIT_PRVP",
"3: ERC_INIT_PUBP",
"4: ERC_INIT_WRITESEC",

"5: ERC_INIT_X",
"6: ERC_INIT_S",
"7; ERC_INIT_B",
"8: ERC_INIT_GETXX",

"9: ERC_INIT_LOAD_QR",
"10: ERC_INIT_LOAD_RPS",
"11: ERC_INIT_LOAD_VPK",
"12: ERC_INIT_LOAD_SHR",

"13: ERC_INIT_LOAD_RPK",
"14: ERC_INIT_LOAD_SIG",
"15: ERC_INIT_LOAD_NUM",
"16: ERC_INIT_LOAD_CNT",

"17: ERC_INIT_LOAD_VOTD",
"18: ERC_INIT_LOAD_VOTE",
"19: ERC_INIT_LOAD_VOTR",
"20: ERC_GETS_R_NOSCAN",

"21: ERC_GETS_A_TYPE",
"22: ERC_GETS_A_LEN",
"23: ERC_GETS_A_NOSCAN",
"24: ERC_GETS_A_CRC",

"25: ERC_GETS_A_SAVES",
"26: ERC_GETS_A_SAVEP",
"27: ERC_IDNT_R_NOGETS",
"28: ERC_IDNT_R_HASH",

"29: ERC_IDNT_R_BADQ",
"30: ERC_IDNT_A_TYPE",
"31: ERC_IDNT_A_LEN",
"32: ERC_IDNT_A_SRV",

"33: ERC_IDNT_A_NOGETS",
"34: ERC_IDNT_A_CRC",
"35: ERC_IDNT_A_HASH_RPK",
"36: ERC_IDNT_A_POINT_SIG",

"37: ERC_IDNT_A_VERIFY_RPK",
"38: ERC_IDNT_A_SAVE_RPK",
"39: ERC_IDNT_A_POINT_Q",
"40: ERC_IDNT_A_GET_SS",

"41: ERC_IDNT_A_SAVE_SS",
"42: ERC_REGS_R_NOIDNT",
"43: ERC_REGS_R_HASH",
"44: ERC_REGS_R_BLIND",

"45: ERC_REGS_A_TYPE",
"46: ERC_REGS_A_LEN",
"47: ERC_REGS_A_NOIDNT",
"48: ERC_REGS_A_ID",

"49: ERC_REGS_A_CRC",
"50: ERC_REGS_A_POINT_SIG",
"51: ERC_REGS_A_POINT_RP1",
"52: ERC_REGS_A_HASH_OURK",

"53: ERC_REGS_A_VERIFY_BSIG",
"54: ERC_REGS_A_SAVE_BSIG",
"55: ERC_JOIN_R_NOREGS",
"56: ERC_JOIN_R_JOINED",
"57: ERC_JOIN_A_TYPE",

"58: ERC_JOIN_A_LEN",
"59: ERC_JOIN_A_NOREGS",
"60: ERC_JOIN_A_JOINED",
"61: ERC_JOIN_A_CRC",

"62: ERC_JOIN_T_KEY",
"63: ERC_JOIN_T_POINT",
"64: ERC_JOIN_T_HASH",
"65: ERC_JOIN_T_VERIFY",

"66: ERC_JOIN_A_SAVE_ID",
"67: ERC_JOIN_A_SAVE_TMR",
"68: ERC_VOTE_S_OPENED",
"69: ERC_VOTE_S_NOINIT",

"70: ERC_VOTE_S_SAVE_TMR",
"71: ERC_VOTE_S_SAVE_VOTD",
"72: ERC_VOTE_R_NOJOIN",
"73: ERC_VOTE_R_OPENED",

"74: ERC_VOTE_R_HASH_V",
"75: ERC_VOTE_A_TYPE",
"76: ERC_VOTE_A_LEN",
"77: ERC_VOTE_A_NOJOIN",

"78: ERC_VOTE_A_OPENED",
"79: ERC_VOTE_T_NUM",
"80: ERC_VOTE_T_TMR",
"81: ERC_VOTE_T_VOTE",

"82: ERC_VOTE_T_MAC",
"83: ERC_VOTE_A_CRC",
"84: ERC_VOTE_T_POINT_SIG",
"85: ERC_VOTE_T_HASH",

"86: ERC_VOTE_T_VERIFY",
"87: ERC_VOTE_A_SAVE_VOTE",
"88: ERC_OPEN_R_NOVOTE",
"89: ERC_OPEN_R_OPENED",

"90: ERC_OPEN_A_TYPE",
"91: ERC_OPEN_A_LEN",
"92: ERC_OPEN_A_NOVOTE",
"93: ERC_OPEN_A_OPENED",

"94: ERC_OPEN_T_NUM",
"95: ERC_OPEN_T_VOTD",
"96: ERC_OPEN_A_CRC",
"97: ERC_OPEN_T_POINT_SIG",

"98: ERC_OPEN_T_HASH",
"99: ERC_OPEN_T_VERIFY",
"100: ERC_OPEN_A_SAVE_VOTR",
"101: ERC_SCAN_SAVE",
"102: CLI_VOTE_REWRITE",
"103: ERC_VOTE_EMPTY",

"104: ERC_SEND_LEN",
"105: ERC_SEND_SRV",
"106: ERC_SEND_PRT",
"107: ERC_SEND_DNS",
"108: ERC_SEND_SOC",
"109: ERC_SEND_NGL",

"110: ERC_READ_TOUT",
"111: ERC_READ_LEN_WTCP",
"112: ERC_READ_SEND_WTCP",
"113: CLI_READ_CON_TCP",
"114: ERC_READ_TLEN",
"115: ERC_READ_SEND_TH",
"116: CLI_READ_CON_TOR",
"117: ERC_READ_TCLOSEH",
"118: ERC_READ_LEN_WTOR",
"119: ERC_READ_TCLOSED",
"120: ERC_READ_TCLOSEA",
"121: CLI_READ_SEND_TD",
"122: CLI_READ_SEND_TA",
"123: ERC_READ_WTLEN",
"124: ERC_READ_ANS_WTOR",
"125: ERC_READ_ANS_LEN",
"126: ERC_READ_ANS_PKT",
"127: ERC_SCAN_CRC"
};


const char* cli_verbs[MAX_CLI_VERBS]={0,};


void cli_verb_ini(void)
{
 int d;
 short i;
 short ii;

 memset(cli_verbs, 0, sizeof(cli_verbs));
 cli_verbs[0]=cli_verbs_data[0]; //OK iteam

 //scan iteams
 for(i=0;i<MAX_CLI_VERBS;i++)
 {
  if(!cli_verbs_data[i]) break;  //first NULL iteam
  d=myatoi((char*)cli_verbs_data[i]); //get iteam code
  if(d<MAX_CLI_VERBS)
  {
    if(d) cli_verbs[d]=cli_verbs_data[i]; //set iteam by code
  }
 }
}


const char* cli_verb(short code)
{
 if(code>=MAX_CLI_VERBS) return cli_empty_str;
 else return cli_verbs[code];
}

const char* cli_note(short code)
{
 if(!code || (code>=MAX_CLI_VERBS)) return cli_empty_str;
 else return cli_verbs[code];
}



void cli_outresult(unsigned char step, short ret)
{
 const char* p;

 if(step>=MAX_CLI_STEPS) step=0;
 p=cli_steps[step]; //current mode

 if(ret<=0) //error
 {
  ret=-ret;  //to positive
  if(ret&0x80) //server's error
  {
   ret&=0x7F; //error code
   printf("%s: server error %s\r\n", p, srv_verb(ret));
  }
  else printf("%s: app %s\r\n", p, cli_verb(ret)); //app error or success
 }
 else //server's notification
 {
  if(ret>CLI_NOTE)
  {
   ret-=CLI_NOTE;
   if(step) printf("%s: srv: %s app %s\r\n", p, srv_note(ret), cli_verb(0)); //server note, app ok
   else printf("%s: step %s\r\n", p, cli_verb(ret)); //initialization: step
  }
  else if(ret==CLI_NOTE) printf("%s: %s\r\n", p, cli_verb(0));
  else if(ret>CLI_WARN)
  {
   ret-=CLI_WARN;
   if(step) printf("%s: note: %s app %s\r\n", p, cli_note(ret), cli_verb(0)); //server note, app ok
   else printf("%s: step %s\r\n", p, cli_verb(ret)); //initialization: step
  }
  else printf("%s: %s\r\n", p, cli_verb(0));
 }
}