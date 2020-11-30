#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "amath.h"
#include "packets.h" //data  fields
#include "shake.h"
#include "trng.h"
#include "b64.h"
#include "base32.h"
#include "bls.h"
#include "whereami.h"

#include "cli_verb.h"
#include "cli_init.h"
#include "cli_scan.h"
#include "cli_gets.h"
#include "cli_idnt.h"
#include "cli_regs.h"
#include "cli_join.h"
#include "cli_vote.h"
#include "cli_open.h"

//================state flags===========

#define FLAG_INIT   1   //client initialized (have his key)
#define FLAG_SCAN   2   //QR code scaned (have own number and psw)
#define FLAG_GETS   4   //client attached (have voter's pk and voter's signature of registrator's pk)
#define FLAG_IDNT   8   //client authenticated on registrator's server (have shared secret and registrator's pk)
#define FLAG_REGS   16  //client registered on registartor's server (have signature)
#define FLAG_JOIN   32  //client joined to voter's server (have id)
#define FLAG_VOTE   64  //client votes (have voting encrypting key and encrypted vote)
#define FLAG_OPEN   128 //client open his vote (have decrtpted vote)

//==============files==================

#define FILE_SEC 0  //"sec.txt",  //client's signing secret key
#define FILE_SCAN   1  //"qrc.txt",  //QR code data (clint's id, server's address, registration password)
#define FILE_RPS    2  //"rps.txt",  //voter's signature of registrator's pk
#define FILE_VPK    3  //"vpk.txt",  //voter's public key

#define FILE_SHR    4  //"shr.txt",  //SPEKE shared secret
#define FILE_RPK    5  //"rpk.txt",  //registrator's public key
#define FILE_SIGN   6  //"sig.txt",  //registrator's signature of client's public key
#define FILE_NUM    7  //"num.txt",  //clint's number in voter's list

#define FILE_CNT    8  //"cnt.txt",  //votes one-way counter
#define FILE_VOTD   9  //"vod.txt"   //decrypted voting data
#define FILE_VOTE   10  //"vot.txt",  //encrypted voting data
#define FILE_VOTR   11 //"vor.txt",  //voting result

#define FILE_GETSR  12   //"0_r.txt"  //raw clint's<->server packets:
#define FILE_GETSA  13   //"0_a.txt"
#define FILE_IDNTR  14   //"1_r.txt",
#define FILE_IDNTA  15   //"1_a.txt",

#define FILE_REGSR  16   //"2_r.txt",
#define FILE_REGSA  17   //"2_a.txt",
#define FILE_JOINR  18   //"3_r.txt",
#define FILE_JOINA  19   //"3_a.txt",

#define FILE_VOTER  20   //"4_r.txt",
#define FILE_VOTEA  21   //"4_a.txt",
#define FILE_OPENR  22   //"5_a.txt",
#define FILE_OPENA  23   //"5_r.txt"

//client's data
typedef struct
{
 fp_t x;
 fp_t s;
 fp_t b;

 char adr[32];
 char pwd[32];
 int id;

 unsigned char shr[16];

 ecpoint_fp X; //my Q1 public key [68]
 ecpoint_fp2 XX; //my Q2 public key [132]
 ecpoint_fp2 YY; //voter's Q2 public key [132]
 ecpoint_fp2 RR; //registrator's public key [128]
 fp_t rps; //voter's signature of registrator's pk
 fp_t sig; //registrators signature of hash of my Q2 pubkey
 unsigned char key[16]; //hash of my Q2 pubkey
 unsigned char enc[16]; //encryption key
 int num; //clients number in voter's list
 unsigned char cnd[12*16]; //list of candidates
 int cnt; //voting counter
 char votd[16]; //decrypted vote
 unsigned char vote[32]; //encrypted vote + mac
 char votr[16]; //voting result
 unsigned char flags;
} cli_data;

extern cli_data* cli;

short cli_set_pubpath(char* p);
short cli_set_prvpath(char* p);
short cli_fread(short file, unsigned char* data, short len);
short cli_fwrite(short file, unsigned char* data, short len);
unsigned char cli_getflags(void);

short cli_start(void);
void cli_process(void);

short cli_req(unsigned char req);



