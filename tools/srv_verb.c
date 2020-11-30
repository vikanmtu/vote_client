#include <string.h>
#include "amath.h"

#include "srv_verb.h"

const char* srv_empty_str=" ";

const char* srv_verbs_data[MAX_SRV_VERBS]={
"0: SUCCESS",
"1: ERR_INIR_RNG",
"2: ERR_INIR_DBOPEN",
"3: ERR_INIR_DBTAB",

"4: ERR_INIR_GENX",
"5: ERR_INIR_SAVEX",
"6: ERR_INIR_SAVEXX",
"7: ERR_INIR_GENXX",

"8: ERR_INIR_LOADXX",
"9: ERR_INIR_LENXX",
"10: ERR_INIR_CHECKXX",
"11: ERR_INIR_TEST",
"12: ERR_INIR_LOADYY",

"13: ERR_INIR_LENYY",

"14: ERR_INIV_RNG",
"15: ERR_INIV_DBOPEN",
"16: ERR_INIV_DBTAB",

"17: ERR_INIV_GENX",
"18: ERR_INIV_SAVEX",
"19: ERR_INIV_SAVEXX",
"20: ERR_INIV_GENXX",

"21: ERR_INIV_LOADXX",
"22: ERR_INIV_LENXX",
"23: ERR_INIV_CHECKXX",
"24: ERR_INIV_TEST",
"25: ERR_INIV_LOADYY",

"26: ERR_INIV_LENYY",
"27: ERR_INIV_HASHYY",
"28: ERR_GETS_TYPE",
"29: ERR_GETS_LEN",

"30: ERR_GETS_CRC",
"31: ERR_IDNT_TYPE",
"32: ERR_IDNT_LEN",
"33: ERR_IDNT_CRC",

"34: ERR_IDNT_DBOPEN",
"35: ERR_IDNT_DBREAD",
"36: ERR_IDNT_DBFIND",
"37: ERR_IDNT_NOPASS",

"38: ERR_IDNT_POINT",
"39: ERR_IDNT_SSEC",
"40: ERR_IDNT_DBSAVESS",
"41: ERR_IDNT_HASH",

"42: ERR_IDNT_GETQ",
"43: ERR_REGS_TYPE",
"44: ERR_REGS_LEN",
"45: ERR_REGS_CRC",

"46: ERR_REGS_DBOPEN",
"47: ERR_REGS_DBREAD",
"48: ERR_REGS_DBFIND",
"49: ERR_REGS_NOPASS",

"50: ERR_REGS_NOSSEC",
"51: ERR_REGS_SSLEN",
"52: ERR_REGS_MAC",
"53: ERR_REGS_BADSIG",

"54: ERR_REGS_POINT",
"55: ERR_REGS_DBSAVESIG",
"56: ERR_JOIN_TYPE",
"57: ERR_JOIN_LEN",

"58: ERR_JOIN_CRC",
"59: ERR_JOIN_DBOPEN",
"60: ERR_JOIN_DBREAD",
"61: ERR_JOIN_DBFIND",

"62: ERR_JOIN_POINT",
"63: ERR_JOIN_HASH",
"64: ERR_JOIN_VERIFY",
"65: ERR_JOIN_DBSAVEK",

"66: ERR_VOTE_TYPE",
"67: ERR_VOTE_LEN",
"68: ERR_VOTE_CRC",
"69: ERR_VOTE_DBOPEN",

"70: ERR_VOTE_DBREAD",
"71: ERR_VOTE_DBFIND",
"72: ERR_VOTE_TMRF",
"73: ERR_VOTE_TMRL",

"74: ERR_VOTE_KEY",
"75: ERR_VOTE_PUB",
"76: ERR_VOTE_HASH",
"77: ERR_VOTE_SIG",

"78: ERR_VOTE_VERIFY",
"79: ERR_VOTE_DBSAVEV",
"80: ERR_VOTE_DBSAVEM",
"81: ERR_VOTE_DBSAVET",

"82: ERR_OPEN_TYPE",
"83: ERR_OPEN_LEN",
"84: ERR_OPEN_CRC",
"85: ERR_OPEN_DBOPEN",

"86: ERR_OPEN_DBREAD",
"87: ERR_OPEN_DBFIND",
"88: ERR_OPEN_VLEN",
"89: ERR_OPEN_MLEN",

"90: ERR_OPEN_MAC",
"91: ERR_OPEN_DBSAVEV",
"92: ERR_OPEN_DBSAVET",
"93: ERR_JOIN_TI_HASH",

"94: ERR_VOTE_TI_HASH",
"95: ERR_OPEN_TI_HASH",
"96: SRV_IDNT_ISREGS",
"97: SRV_REGS_ISREGS",

"98: SRV_JOIN_ISJOIN",
"99: SRV_VOTE_REPLAY",
"100: SRV_VOTE_REVOTE",
"101: SRV_OPEN_ISOPEN",

"102: MSG_STAGE_INIT",
"103: MSG_STAGE_SCAN",
"104: MSG_STAGE_GETS",
"105: MSG_STAGE_IDNT",
"106: MSG_STAGE_REGS",
"107: MSG_STAGE_JOIN",
"108: MSG_STAGE_SETV",
"109: MSG_STAGE_VOTE",
"110: MSG_STAGE_OPEN",
"111: MSG_STAGE_RCVD",
"112: ERR_STAGE_WRONG",
"113: ERR_CMD_WRONG",
"114: ERR_PKT_WRONG",
"115: ERR_SCAN_LOAD",
"116: ERR_SCAN_PSW",
"117: ERR_SCAN_SRV",
"118: MSG_SERVER_OK",
"119: MSG_NEXT_STEP",
"120: ERR_NO_CANDIDATES"
};


const char* srv_verbs[MAX_SRV_VERBS]={0,};


void srv_verb_ini(void)
{
 int d;
 short i;

 memset(srv_verbs, 0, sizeof(srv_verbs));
 srv_verbs[0]=srv_verbs_data[0]; //OK iteam

 //scan iteams
 for(i=0;i<MAX_SRV_VERBS;i++)
 {
  if(!srv_verbs_data[i]) break;  //first NULL iteam
  d=myatoi((char*)srv_verbs_data[i]); //get iteam code
  if(d<MAX_SRV_VERBS)
  {
   if(d) srv_verbs[d]=srv_verbs_data[i]; //set iteam by code
  }
 }
}


const char* srv_verb(unsigned char code)
{
 if(code>=MAX_SRV_VERBS) return srv_empty_str;
 else return srv_verbs[code];
}

const char* srv_note(unsigned char code)
{
 if(!code || (code>=MAX_SRV_VERBS)) return srv_empty_str;
 else return srv_verbs[code];
}

