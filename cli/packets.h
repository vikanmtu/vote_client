//packets types
#define GETS 0  //request of public key
#define IDNT 1  //personal identification
#define REGS 2  //personal registration
#define JOIN 3  //joining
#define VOTE 4  //voting
#define OPEN 5  //opening
#define IDDL 127 //no request

//error codes
#define ERR_ALREADY 0x10;  //already registered
#define DEF_PORT 8888


#define ERR_NOPSW 0x20  //password not specified
#define ERR_INVPNT 0x30 //invalid point


#define ERR_NOTIDNT 0x40 //not identified try regs
#define ERR_BADMAC 0x50 //bas mac


//======================Length of packet;s fields===============



//---------------QR code-----------------------------------
#define QRCD_I_LEN 4    //user ID
#define QRCD_O_LEN 12   //binary server's onion address
#define QRCD_P_LEN 16   //password

#define QRCD_I 0
#define QRCD_O QRCD_I+QRCD_I_LEN
#define QRCD_P QRCD_O+QRCD_O_LEN
#define QRCD_L QRCD_P+QRCD_P_LEN



//-------------General (in all packets)--------------------
#define H_LEN 4   //length of header on start of packet
#define C_LEN 4   //length of crc on end of packet
//----------Step 0: public key reauest (GETS)----------
//request
//--emty--
//answer
#define GETS_AS_LEN 32  //voter's signature of registrator's public key
#define GETS_AV_LEN 128 //voter's public key

//----------Step 1: personal identification (IDNT)----------
//request
#define IDNT_RD_LEN 4  //client's ID[4]
#define IDNT_RP_LEN 32 //client's SPEKE key[32]
//answer
#define IDNT_AP_LEN 32 //server's SPEKE key[32]
#define IDNT_AR_LEN 128 //registrator's public key in Q2 (uncompressed)

//----------Step 2: personal registration (REGS)------------
//request
#define REGS_RD_LEN 4 //client's ID
#define REGS_RQ_LEN 32 //blinded point (hash of clients pkey[128])
#define REGS_RM_LEN 16 //MAC
//answer
#define REGS_AD_LEN 4 //client's ID
#define REGS_AB_LEN 32 //blind signature of Q
#define REGS_AG_LEN 32 //registrators's private key in Q1 (compressed)
#define REGS_AM_LEN 16 //MAC

//---------Step 3: join by registrator----------------------
//request
#define JOIN_RS_LEN 16 //stamp of clients publick key in Q2
#define JOIN_RU_LEN 32 //unblinded signature
//answer
#define JOIN_AN_LEN 4 //clients number in list of voters
#define JOIN_AK_LEN 192 //list of candidates
#define JOIN_AS_LEN 16 //stamp of clients publick key in Q2
#define JOIN_AT_LEN 32 //ticket for joining (registrator's signature of N+S)

//-----------Step 4: voting ---------------------------------
//request
#define VOTE_RN_LEN 4 //clients number
#define VOTE_RW_LEN 4 //one-way revoting counter
#define VOTE_RV_LEN 16 //encrypted voting
#define VOTE_RM_LEN 16 //MAC
#define VOTE_RA_LEN 32 //cliemt's signature of N+V+M
#define VOTE_RK_LEN 128 //clients public key in Q2

//answer
#define VOTE_AN_LEN 4 //clients number
#define VOTE_AW_LEN 4  //one-way revoting counter
#define VOTE_AV_LEN 16 //encrypted voting
#define VOTE_AM_LEN 16 //MAC
#define VOTE_AT_LEN 32 //ticket for voting

//----------Step 5: opening---------------------------------
//request
#define OPEN_RN_LEN 4 //clients  number
#define OPEN_RE_LEN 16 //symmetric encryption key
//answer
#define OPEN_AN_LEN 4 //clients  number
#define OPEN_AO_LEN 16 //opened voting
#define OPEN_AT_LEN 32 //ticket for opening


//=================Pointers to Fields==========================

#define GETS_RC H_LEN
#define GETS_RL GETS_RC+C_LEN

#define GETS_AS H_LEN
#define GETS_AV (GETS_AS+GETS_AS_LEN)
#define GETS_AC (GETS_AV+GETS_AV_LEN)
#define GETS_AL (GETS_AC+C_LEN)

#define IDNT_RD H_LEN
#define IDNT_RP (IDNT_RD+IDNT_RD_LEN)
#define IDNT_RC (IDNT_RP+IDNT_RP_LEN)
#define IDNT_RL (IDNT_RC+C_LEN)

#define IDNT_AP H_LEN
#define IDNT_AR (IDNT_AP+IDNT_AP_LEN)
#define IDNT_AC (IDNT_AR+IDNT_AR_LEN)
#define IDNT_AL (IDNT_AC+C_LEN)

#define REGS_RD H_LEN
#define REGS_RQ (REGS_RD+REGS_RD_LEN)
#define REGS_RM (REGS_RQ+REGS_RQ_LEN)
#define REGS_RC (REGS_RM+REGS_RM_LEN)
#define REGS_RL (REGS_RC+C_LEN)

#define REGS_AD H_LEN
#define REGS_AB (REGS_AD+REGS_AD_LEN)
#define REGS_AG (REGS_AB+REGS_AB_LEN)
#define REGS_AM (REGS_AG+REGS_AG_LEN)
#define REGS_AC (REGS_AM+REGS_AM_LEN)
#define REGS_AL (REGS_AC+C_LEN)

#define JOIN_RS H_LEN
#define JOIN_RU (JOIN_RS+JOIN_RS_LEN)
#define JOIN_RC (JOIN_RU+JOIN_RU_LEN)
#define JOIN_RL (JOIN_RC+C_LEN)

#define JOIN_AN H_LEN
#define JOIN_AK (JOIN_AN+JOIN_AN_LEN)
#define JOIN_AS (JOIN_AK+JOIN_AK_LEN)
#define JOIN_AT (JOIN_AS+JOIN_AS_LEN)
#define JOIN_AC (JOIN_AT+JOIN_AT_LEN)
#define JOIN_AL (JOIN_AC+C_LEN)

#define VOTE_RN H_LEN
#define VOTE_RW (VOTE_RN+VOTE_RN_LEN)
#define VOTE_RV (VOTE_RW+VOTE_RW_LEN)
#define VOTE_RM (VOTE_RV+VOTE_RV_LEN)
#define VOTE_RA (VOTE_RM+VOTE_RM_LEN)
#define VOTE_RK (VOTE_RA+VOTE_RA_LEN)
#define VOTE_RC (VOTE_RK+VOTE_RK_LEN)
#define VOTE_RL (VOTE_RC+C_LEN)

#define VOTE_AN H_LEN
#define VOTE_AW (VOTE_AN+VOTE_AN_LEN)
#define VOTE_AV (VOTE_AW+VOTE_AW_LEN)
#define VOTE_AM (VOTE_AV+VOTE_AV_LEN)
#define VOTE_AT (VOTE_AM+VOTE_AM_LEN)
#define VOTE_AC (VOTE_AT+VOTE_AT_LEN)
#define VOTE_AL (VOTE_AC+C_LEN)

#define OPEN_RN H_LEN
#define OPEN_RE (OPEN_RN+OPEN_RN_LEN)
#define OPEN_RC (OPEN_RE+OPEN_RE_LEN)
#define OPEN_RL (OPEN_RC+C_LEN)

#define OPEN_AN H_LEN
#define OPEN_AO (OPEN_AN+OPEN_AN_LEN)
#define OPEN_AT (OPEN_AO+OPEN_AO_LEN)
#define OPEN_AC (OPEN_AT+OPEN_AT_LEN)
#define OPEN_AL (OPEN_AC+C_LEN)





