#define MAX_SRV_VERBS 128

extern const char* srv_verbs[MAX_SRV_VERBS];

void srv_verb_ini(void);
const char* srv_verb(unsigned char code);
const char* srv_note(unsigned char code);


#define SRV_FATAL_ERR 0x80

//inir
#define ERR_OK 0
#define ERR_INIR_RNG 1
#define ERR_INIR_DBOPEN 2
#define ERR_INIR_DBTAB 3
#define ERR_INIR_GENX 4
#define ERR_INIR_SAVEX 5
#define ERR_INIR_SAVEXX 6
#define ERR_INIR_GENXX 7
#define ERR_INIR_LOADXX 8
#define ERR_INIR_LENXX 9
#define ERR_INIR_CHECKXX 10
#define ERR_INIR_TEST 11
#define ERR_INIR_LOADYY 12
#define ERR_INIR_LENYY 13

//iniv
#define ERR_INIV_RNG 14
#define ERR_INIV_DBOPEN 15
#define ERR_INIV_DBTAB 16
#define ERR_INIV_GENX 17
#define ERR_INIV_SAVEX 18
#define ERR_INIV_SAVEXX 19
#define ERR_INIV_GENXX 20
#define ERR_INIV_LOADXX 21
#define ERR_INIV_LENXX 22
#define ERR_INIV_CHECKXX 23
#define ERR_INIV_TEST 24
#define ERR_INIV_LOADYY 25
#define ERR_INIV_LENYY 26
#define ERR_INIV_HASHYY 27

//gets
#define ERR_GETS_TYPE 28
#define ERR_GETS_LEN 29
#define ERR_GETS_CRC 30

//idnt
#define ERR_IDNT_TYPE 31
#define ERR_IDNT_LEN 32
#define ERR_IDNT_CRC 33
#define ERR_IDNT_DBOPEN 34
#define ERR_IDNT_DBREAD 35
#define ERR_IDNT_DBFIND 36
#define ERR_IDNT_NOPASS 37
#define ERR_IDNT_POINT 38
#define ERR_IDNT_SSEC 39
#define ERR_IDNT_DBSAVESS 40
#define ERR_IDNT_HASH 41
#define ERR_IDNT_GETQ 42

//regs
#define ERR_REGS_TYPE 43
#define ERR_REGS_LEN 44
#define ERR_REGS_CRC 45
#define ERR_REGS_DBOPEN 46
#define ERR_REGS_DBREAD 47
#define ERR_REGS_DBFIND 48
#define ERR_REGS_NOPASS 49
#define ERR_REGS_NOSSEC 50
#define ERR_REGS_SSLEN 51
#define ERR_REGS_MAC 52
#define ERR_REGS_BADSIG 53
#define ERR_REGS_POINT 54
#define ERR_REGS_DBSAVESIG 55

//join
#define ERR_JOIN_TYPE 56
#define ERR_JOIN_LEN 57
#define ERR_JOIN_CRC 58
#define ERR_JOIN_DBOPEN 59
#define ERR_JOIN_DBREAD 60
#define ERR_JOIN_DBFIND 61
#define ERR_JOIN_POINT 62
#define ERR_JOIN_HASH 63
#define ERR_JOIN_VERIFY 64
#define ERR_JOIN_DBSAVEK 65

//vote
#define ERR_VOTE_TYPE 66
#define ERR_VOTE_LEN 67
#define ERR_VOTE_CRC 68
#define ERR_VOTE_DBOPEN 69
#define ERR_VOTE_DBREAD 70
#define ERR_VOTE_DBFIND 71
#define ERR_VOTE_TMRF 72
#define ERR_VOTE_TMRL 73
#define ERR_VOTE_KEY 74
#define ERR_VOTE_PUB 75
#define ERR_VOTE_HASH 76
#define ERR_VOTE_SIG 77
#define ERR_VOTE_VERIFY 78
#define ERR_VOTE_DBSAVEV 79
#define ERR_VOTE_DBSAVEM 80
#define ERR_VOTE_DBSAVET 81


//open
#define ERR_OPEN_TYPE 82
#define ERR_OPEN_LEN 83
#define ERR_OPEN_CRC 84
#define ERR_OPEN_DBOPEN 85
#define ERR_OPEN_DBREAD 86
#define ERR_OPEN_DBFIND 87
#define ERR_OPEN_VLEN 88
#define ERR_OPEN_MLEN 89
#define ERR_OPEN_MAC 90
#define ERR_OPEN_DBSAVEV 91
#define ERR_OPEN_DBSAVET 92


//made tickets
#define ERR_JOIN_TI_HASH 93
#define ERR_VOTE_TI_HASH 94
#define ERR_OPEN_TI_HASH 95

//Notes
#define SRV_IDNT_ISREGS 96
#define SRV_REGS_ISREGS 97
#define SRV_JOIN_ISJOIN 98
#define SRV_VOTE_REPLAY 99
#define SRV_VOTE_REVOTE 100
#define SRV_OPEN_ISOPEN 101


//Messages
#define MSG_STAGE_INIT   102
#define MSG_STAGE_SCAN   103
#define MSG_STAGE_GETS   104
#define MSG_STAGE_IDNT   105
#define MSG_STAGE_REGS   106
#define MSG_STAGE_JOIN   107
#define MSG_STAGE_SETV   108
#define MSG_STAGE_VOTE   109
#define MSG_STAGE_OPEN   110
#define MSG_STAGE_RCVD  111
#define ERR_STAGE_WRONG  112
#define ERR_CMD_WRONG  113
#define ERR_PKT_WRONG 114
#define ERR_SCAN_LOAD 115
#define ERR_SCAN_PSW 116
#define ERR_SCAN_SRV 117
#define MSG_SERVER_OK 118
#define MSG_NEXT_STEP 119
#define ERR_NO_CANDIDATES 120









