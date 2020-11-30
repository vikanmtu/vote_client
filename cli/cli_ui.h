//int C thread context

void ui_process(void); //client's C-code thread

//in GUI timer
unsigned char ui_getevent(void); //get event from Client C thread
unsigned char ui_get_stage(void); //get current voting stage

//In GUI user
short ui_init(char* prvdir, char* pubdir); //initialize client, returns state flags
void ui_setevent(unsigned char ev); //set event for GUI over Client thread
void ui_cmd(unsigned char cmd);  //do command

short ui_scanqr(unsigned char* img, short w, short h); //process QR code image
short ui_setfile(char* path); //set user's data from file
short ui_setuser(int num, char* psw, char* srv); //set user's data manually
short ui_setvote(char* vote); //set vote string
int ui_getuser(char** srv, char** psw); //get server, password and personal id
int ui_getvote(char** voted, char** voter); //get vote< result and anonimous id
char* ui_getcnd(void);
short tor_run(char* pp); //run tor
void tor_stop(void); //stop Tor
