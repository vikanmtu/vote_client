#define MAX_CLI_VERBS 128
#define MAX_CLI_STEPS 16

#define CLI_NOTE 16384
#define CLI_WARN 8192
#define CLI_FATAL_ERR 0x80

extern const char* cli_verbs[MAX_CLI_VERBS];

void cli_verb_ini(void);
const char* cli_verb(short code);
const char* cli_note(short code);
void cli_outresult(unsigned char step, short ret);

//steps
#define CLI_STEP_INIT 0
#define CLI_STEP_SCAN 1
#define CLI_STEP_GETS_R 2
#define CLI_STEP_GETS_A 3
#define CLI_STEP_IDNT_R 4
#define CLI_STEP_IDNT_A 5
#define CLI_STEP_REGS_R 6
#define CLI_STEP_REGS_A 7
#define CLI_STEP_JOIN_R 8
#define CLI_STEP_JOIN_A 9
#define CLI_STEP_VOTE_R 10
#define CLI_STEP_VOTE_A 11
#define CLI_STEP_OPEN_R 12
#define CLI_STEP_OPEN_A 13
#define CLI_STEP_SEND 14
#define CLI_STEP_RCVD 15


//init
#define ERR_OK 0
#define ERC_INIT_RNG 1
#define ERC_INIT_PRVP 2
#define ERC_INIT_PUBP 3
#define ERC_INIT_WRITESEC 4
#define ERC_INIT_X 5
#define ERC_INIT_S 6
#define ERC_INIT_B 7
#define ERC_INIT_GETXX 8
#define ERC_INIT_LOAD_QR 9
#define ERC_INIT_LOAD_RPS 10
#define ERC_INIT_LOAD_VPK 11
#define ERC_INIT_LOAD_SHR 12
#define ERC_INIT_LOAD_RPK 13
#define ERC_INIT_LOAD_SIG 14
#define ERC_INIT_LOAD_NUM 15
#define ERC_INIT_LOAD_CNT 16
#define ERC_INIT_LOAD_VOTD 17
#define ERC_INIT_LOAD_VOTE 18
#define ERC_INIT_LOAD_VOTR 19

//gets
#define ERC_GETS_R_NOSCAN 20
#define ERC_GETS_A_TYPE 21
#define ERC_GETS_A_LEN 22
#define ERC_GETS_A_NOSCAN 23
#define ERC_GETS_A_CRC 24
#define ERC_GETS_A_SAVES 25
#define ERC_GETS_A_SAVEP 26

//idnt
#define ERC_IDNT_R_NOGETS 27
#define ERC_IDNT_R_HASH 28
#define ERC_IDNT_R_BADQ 29
#define ERC_IDNT_A_TYPE 30
#define ERC_IDNT_A_LEN 31
#define ERC_IDNT_A_SRV 32
#define ERC_IDNT_A_NOGETS 33
#define ERC_IDNT_A_CRC 34
#define ERC_IDNT_A_HASH_RPK 35
#define ERC_IDNT_A_POINT_SIG 36
#define ERC_IDNT_A_VERIFY_RPK 37
#define ERC_IDNT_A_SAVE_RPK 38
#define ERC_IDNT_A_POINT_Q 39
#define ERC_IDNT_A_GET_SS 40
#define ERC_IDNT_A_SAVE_SS 41

//regs
#define ERC_REGS_R_NOIDNT 42
#define ERC_REGS_R_HASH 43
#define ERC_REGS_R_BLIND 44
#define ERC_REGS_A_TYPE 45
#define ERC_REGS_A_LEN 46
#define ERC_REGS_A_NOIDNT 47
#define ERC_REGS_A_ID 48
#define ERC_REGS_A_CRC 49
#define ERC_REGS_A_POINT_SIG 50
#define ERC_REGS_A_POINT_RP1 51
#define ERC_REGS_A_HASH_OURK 52
#define ERC_REGS_A_VERIFY_BSIG 53
#define ERC_REGS_A_SAVE_BSIG 54

//join
#define ERC_JOIN_R_NOREGS 55
#define ERC_JOIN_R_JOINED 56
#define ERC_JOIN_A_TYPE 57
#define ERC_JOIN_A_LEN 58
#define ERC_JOIN_A_NOREGS 59
#define ERC_JOIN_A_JOINED 60
#define ERC_JOIN_A_CRC 61
#define ERC_JOIN_T_KEY 62
#define ERC_JOIN_T_POINT 63
#define ERC_JOIN_T_HASH 64
#define ERC_JOIN_T_VERIFY 65
#define ERC_JOIN_A_SAVE_ID 66
#define ERC_JOIN_A_SAVE_TMR 67

//vote
#define ERC_VOTE_S_OPENED 68
#define ERC_VOTE_S_NOINIT 69
#define ERC_VOTE_S_SAVE_TMR 70
#define ERC_VOTE_S_SAVE_VOTD 71
#define ERC_VOTE_R_NOJOIN 72
#define ERC_VOTE_R_OPENED 73
#define ERC_VOTE_R_HASH_V 74
#define ERC_VOTE_A_TYPE 75
#define ERC_VOTE_A_LEN 76
#define ERC_VOTE_A_NOJOIN 77
#define ERC_VOTE_A_OPENED 78
#define ERC_VOTE_T_NUM 79
#define ERC_VOTE_T_TMR 80
#define ERC_VOTE_T_VOTE 81
#define ERC_VOTE_T_MAC 82
#define ERC_VOTE_A_CRC 83
#define ERC_VOTE_T_POINT_SIG 84
#define ERC_VOTE_T_HASH 85
#define ERC_VOTE_T_VERIFY 86
#define ERC_VOTE_A_SAVE_VOTE 87

//open
#define ERC_OPEN_R_NOVOTE 88
#define ERC_OPEN_R_OPENED 89
#define ERC_OPEN_A_TYPE 90
#define ERC_OPEN_A_LEN 91
#define ERC_OPEN_A_NOVOTE 92
#define ERC_OPEN_A_OPENED 93
#define ERC_OPEN_T_NUM 94
#define ERC_OPEN_T_VOTD 95
#define ERC_OPEN_A_CRC 96
#define ERC_OPEN_T_POINT_SIG 97
#define ERC_OPEN_T_HASH 98
#define ERC_OPEN_T_VERIFY 99
#define ERC_OPEN_A_SAVE_VOTR 100

//scan
#define ERC_SCAN_SAVE 101

//set vote
#define CLI_VOTE_REWRITE 102
#define ERC_VOTE_EMPTY 103

//send
#define ERC_SEND_LEN 104
#define ERC_SEND_PRT 105
#define ERC_SEND_SRV 106
#define ERC_SEND_DNS 107
#define ERC_SEND_SOC 108
#define ERC_SEND_NGL 109

//rcvd
#define ERC_READ_TOUT 110
#define ERC_READ_LEN_WTCP 111
#define ERC_READ_SEND_WTCP 112
#define CLI_READ_CON_TCP 113
#define ERC_READ_TLEN 114
#define ERC_READ_SEND_TH 115;
#define CLI_READ_CON_TOR 116
#define ERC_READ_TCLOSEH 117
#define ERC_READ_LEN_WTOR 118
#define ERC_READ_TCLOSED 119
#define ERC_READ_TCLOSEA 120
#define CLI_READ_SEND_TD 121
#define CLI_READ_SEND_TA 122
#define ERC_READ_WTLEN 123
#define ERC_READ_ANS_WTOR 124
#define ERC_READ_ANS_LEN 125
#define ERC_READ_ANS_PKT 126
#define ERC_SCAN_CRC 127


