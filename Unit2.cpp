

//--------------------------------------------------------------------------

#include <fmx.h>

#pragma hdrstop
//this
#include "Unit2.h"
//Android
#include <System.IOUtils.hpp>
#include <System.UITypes.hpp>
#include <System.DateUtils.hpp>


//C utilites
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <wchar.h>

//C task
#include "ui.h"
#include "whereami.h" //for check current path

//---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma resource "*.fmx"
#pragma resource ("*.XLgXhdpiTb.fmx", _PLAT_ANDROID)
#pragma resource ("*.LgXhdpiPh.fmx", _PLAT_ANDROID)
#pragma resource ("*.iPhone55in.fmx", _PLAT_IOS)

#define clBlack 0xFF000000
#define clBlue 0xFF0000FF
#define clGreen 0xFF00FF00
#define clRed 0xFFFF0000

    //resourses
    #define T_ONION 0
    #define T_NUM 1
    #define T_PSW 2
    #define T_ID 3
    #define T_VOTE 4
    #define T_STEP 5
    #define B_FILE 6
    #define T_HEADERQR 7
    #define T_QUAL 8
    #define B_FRONT 9
    #define B_BACK 10
    #define B_FLAH 11
    #define B_NOFLASH 12
    #define B_STOP 13
    #define B_RESTART 14
    #define T_COMPLEET 15
    #define T_OK 16
    #define M_FOLDER 17
    #define M_TORERR 18
    #define T_FORM 19
    #define T_SELECT 20
    #define T_CANCEL 21


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


//globals
TForm2 *Form2;   //form
TStringList *List = new TStringList;  //String list for easy save/load test files


TStringList *ListMsg = new TStringList; //Error messages
TStringList *ListStp = new TStringList; //Notification for voting steps
TStringList *ListRes = new TStringList; //Resources



unsigned int lastip=0xFFFFFFFF; //current IP address of main interface for detect changing

//status flags
unsigned char InCall=0;  //call mode
unsigned char InTalk=0;  //talk/mute mode
unsigned char InDir=0;   //allow direct mode flag
unsigned char InList=0;  //allow key receiving flag
unsigned char InWork=0;  //work mode (in call after IKE stage)
unsigned char InInit=0;  //Initialization
unsigned char InSave=0;  //need save changed configuration
unsigned char InRun=0;   //thread run flag
unsigned char InLock=0;  //wake lock mode
unsigned char InSelf=0; //call to himself
unsigned char InPing=0; //ping Tor
unsigned char InCnt=0; //counter of lock interval after Tor restart


unsigned int InTmr=0; //counter for periodicall unlock interval
int InTst=0; //counter for debug lock evnts

char torpath[512]={0}; //command string for Tor with parameters (set up on FormCreate, use for restart Tor
char par[32];  //notification parameter

 String SLOG="";

//#include "whereami.h" //for check current path
//#include "if.h"    //Torfone core general definitions
//#include "ui.h"   //Torfone core interface GUI to UI


//Application flags
char IsCamera=0; //flag of camera is active
char IsImage=0;  //flag of Camera image ready
char IsFront=0;  //flag of frontal camera selected
char IsFlash=0;  //flag of flash is on
char IsChange=0; //flag of resolution was changed manually
char IsUser=0; //flag of user changes personal data
int ImageW=0;    //width of camera image
int ImageH=0;    //height of camera image

#define CANDIDATE_LEN 16
#define MAX_CANDIDATES 12 //maximal count of candidates in list
#define NO_CANDIDATES_ERR 248 //event if no candidates in bulleten
char Cnd[MAX_CANDIDATES];
//bitmap for resize camera image
Graphics::TBitmap *gBitmap = new Graphics::TBitmap();


//Interface GUI to C-code Thread of Vote engine
#ifdef __cplusplus
extern "C" {
#endif

//short qr_rec(unsigned char* img, short w, short h);
//short qr_get(unsigned char* res);

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
short tor_run(char* pp); //run tor
void tor_stop(void); //stop Tor
//short tor_run1(void);
char* ui_getcnd(void); //get pointer to list of candidates (win1251 coded!)

#ifdef __cplusplus
}  /* end of the 'extern "C"' block */
#endif


//---------------------------------------------------------------------------
//Create Thread for business logic of C code
//---------------------------------------------------------------------------

    class MyThread: public TThread   //derive our thread class from TThread
    {
       public:
          __fastcall MyThread( int aParam ); //optionally pass parameter to our class

       protected:
          void __fastcall Execute();

       private:
          int param;
    };
//---------------------------------------------------------------------------
    __fastcall MyThread::MyThread( int aParam ): TThread( true )  //constructor
    {
       param = aParam; //save parameter
       Resume(); //run thread
    }
//---------------------------------------------------------------------------

    void __fastcall MyThread::Execute() //task body
    {   //C Thread body

     InRun=1; //set run flag

     while(InRun)  //thread loop
     {
      ui_process();
     }
    }

 //---------------------------------------------------------------------------

MyThread *Thread = NULL; //create object of our thread (will be run from FormCreate)

//Thread constructor
//---------------------------------------------------------------------------
__fastcall TForm2::TForm2(TComponent* Owner)
    : TForm(Owner)
{
}
//---------------------------------------------------------------------------


 void win2wc(wchar_t* wc, const char* str, int maxlen)
 {
  int i, j;
  unsigned char c;
  unsigned int u;
  void* pp = (void*)wc;
  unsigned char* p = (unsigned char*)pp;


  const unsigned short unescape[64] = {
      0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021, 0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x040C, 0x040B, 0x040F,
      0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x0000, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F,
      0x00A0, 0x040E, 0x045E, 0x0408, 0x00A4, 0x0490, 0x00A6, 0x00A7, 0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x0407,
      0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6, 0x00B7, 0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455, 0x0457,
	  };

  for(i=0;i<(maxlen-1);i++)
  {
   c=(unsigned char)str[i];
   if(c<' ') break;
   else if(c >= 0xC0) u = (unsigned int)c - 0xC0 + 0x0410;
   else if(c >= 0x80) u = (unsigned int)unescape[c - 0x80];
   else u = (unsigned int)c;

   for(j=0;j<sizeof(wchar_t);j++)
   {
    (*p++) = u&0xFF;
    u>>=8;
   }
  }
  memset(p, 0, 4);
 }

//Startup initilization specified for Windows
 void __fastcall TForm2::InitWindows()
 {
 #ifdef _WIN32
    AnsiString S;
    AnsiString PubDir;
    AnsiString PrvDir;
    AnsiString ResDir;
    AnsiString TorDir;
    String T;
    short i;
  //set directories
    S=GetCurrentDir();  //app dir
    PubDir = S+ PathDelim + "pub" + PathDelim;  //subdir for public files
    PrvDir = S+ PathDelim + "prv" + PathDelim;  //subdirs for secrets
    ResDir = S+ PathDelim + "res" + PathDelim;  //subdir for resourses
    TorDir = S+ PathDelim + "wintor" + PathDelim; //subdir for Tor
    if(!DirectoryExists(PubDir)) CreateDir(PubDir); //create public and secret subdirs
    if(!DirectoryExists(PrvDir)) CreateDir(PrvDir);



    //load resources from file
    try{ ListRes->LoadFromFile(ResDir+PathDelim+"res.txt"); }
    catch(...){ }

    //load About from file
    MultiViewAbout->Width=Form2->Width-20;
    MultiViewInfo->Width=Form2->Width-20;
    try{ MemoLogo->Lines->LoadFromFile(ResDir+PathDelim+"hlp.txt"); }
    catch(...){ }

    //load error messages from file
    try{ ListMsg->LoadFromFile(ResDir+PathDelim+"msg.txt"); }
    catch(...){ }

    //loads steps from file
    try{ ListStp->LoadFromFile(ResDir+PathDelim+"stp.txt"); }
    catch(...){ }

    //output name of public documents folder
    if(ListRes->Count > M_FOLDER) T=ListRes->Strings[M_FOLDER]; else T=L"Folder: ";
    MemoInfo->Lines->Add(T+S);

    //run tor
    i=tor_run(TorDir.c_str());
    if(ListRes->Count > M_TORERR) T=ListRes->Strings[M_TORERR]; else T=L"Tor run errror: ";
    if(i) MemoInfo->Lines->Add(T+IntToStr(i));

    //initialize app
    i=ui_init(PrvDir.c_str(), PubDir.c_str());

 #endif
 }



 //Startup initialization specified for Android
 void __fastcall TForm2::InitAndroid()
 {
 #ifdef __ANDROID__
  String SS;
  String T;
  AnsiString PubDir;
  AnsiString PrvDir;
  int i, j, l;
  FILE* fl=0;

  char str[512];
  char par[512];
  char torpath[512]={0}; //command string for Tor with parameters (set up on FormCreate, use for restart Tor
  AnsiString S;
  int length, dirname_length;
  int status=-9999;

  //private path
   SS=System::Ioutils::TPath::GetDocumentsPath()+PathDelim;

     MemoLogo->Font->Size=10;  //About
     MemoHelp->Font->Size=10;  //Up
     MemoInfo->Font->Size=12;  //Bottom

  //load resources from deployed file
    try{ ListRes->LoadFromFile(SS+"res.txt"); }
    catch(...){ }

    //load About info
    try{ MemoLogo->Lines->LoadFromFile(SS+"hlp.txt"); }
    catch(...){ }

    //load error messages from file
    try{ ListMsg->LoadFromFile(SS+"msg.txt"); }
    catch(...){ }

    //loads steps from file
    try{ ListStp->LoadFromFile(SS+"stp.txt"); }
    catch(...){ }



    SS=System::Ioutils::TPath::GetSharedDocumentsPath()+PathDelim+"vote";
    if(!DirectoryExists(SS)) CreateDir(SS);
    if(ListRes->Count > M_FOLDER) T=ListRes->Strings[M_FOLDER]; else T=L"Folder: ";
    MemoInfo->Lines->Add(T+SS);

    //----------------initialize Tor------------------

    //create torrc
    SS=System::Ioutils::TPath::GetSharedDocumentsPath()+PathDelim+"vote"+PathDelim+"torrc";
    if(!FileExists(SS)) //check torrc not exist
    {
     S=AnsiString(SS); //convert Unicode to Ansi
     strncpy(str, S.c_str(), sizeof(str)); //copy ansi to c_str
     fl = fopen(str, "w" );  //open file for write
     if(fl) //if file opened
     {
      //runs Tor as demon (shell must be exited for further work)
      SS="RunAsDaemon 1";
      S=AnsiString(SS);
      strncpy(str, S.c_str(), sizeof(str));
      fprintf(fl, "%s\r\n", str);

      //Tor's SOCKS5 port: default is 9160 but we use 9155 avoiding conflict with OrBot
      SS="SocksPort 9055";
      S=AnsiString(SS);
      strncpy(str, S.c_str(), sizeof(str));
      fprintf(fl, "%s\r\n", str);

      //Tor's data directory in private storage
      SS="DataDirectory "+System::Ioutils::TPath::GetDocumentsPath()+PathDelim+"tor_data";
      S=AnsiString(SS);
      strncpy(str, S.c_str(), sizeof(str));
      fprintf(fl, "%s\r\n", str);

      fclose(fl);
     }
    }


    //get path to our executable
  length = wai_getModulePath(NULL, 0, &dirname_length);  //get path length
  if(length > sizeof(torpath)) length = sizeof(torpath); //check we have space
  if (length > 0) //check we have path
  { //get path to module currently executed
   wai_getModulePath(torpath, length, &dirname_length);
  }

  //change name of Torfone executable to Tor executable
  j=0;
  l=strlen(torpath); //total length of path to our executable
  for(i=0;i<l;i++) if(torpath[i]=='/') j=i; //search last delimiter
  if(j) torpath[++j]=0; //cut module file name
  strncpy(torpath+strlen(torpath), (char*)"libTor.so", sizeof(torpath)-strlen(torpath)); //add Tor name

   //set command option: path to torrc
  SS=System::Ioutils::TPath::GetSharedDocumentsPath()+PathDelim+"vote"+PathDelim+"torrc";
  S=AnsiString(SS); //full path to torrc
  strncpy(par, " -f ", sizeof(par)-strlen(par));
  strncpy(par+strlen(par), S.c_str(), sizeof(par)-strlen(par)); //option with parameter

  //add path to log file in extern storage
  SS=System::Ioutils::TPath::GetSharedDocumentsPath()+PathDelim+"vote"+PathDelim+"log.txt";
  S=AnsiString(SS); //path to log file
  strncpy(par+strlen(par), " > ", sizeof(par)-strlen(par));
  strncpy(par+strlen(par), S.c_str(), sizeof(par)-strlen(par)); //option with parameter and output redirecting for shell

  //add options to Tor command line
  strncpy(torpath+strlen(torpath), par, sizeof(torpath)-strlen(torpath));
  //start Tor
  status = system(torpath);

  //set private and public path
  SS=System::Ioutils::TPath::GetSharedDocumentsPath()+PathDelim+"vote"+PathDelim;
  PubDir = AnsiString(SS);
  SS=System::Ioutils::TPath::GetDocumentsPath()+PathDelim;
  PrvDir = AnsiString(SS);

  //initialize app
  i=ui_init(PrvDir.c_str(), PubDir.c_str());


 #endif
 }

 //set GUI state for new voting step
 void __fastcall TForm2::SetState(void)
 {
  unsigned char state;
  int n=0;
  String T;

  state=ui_get_stage(); //get current state

  if(state&1)
  {
   ButtonB->Enabled=true; //set buttonB avaliable for odd states
   ButtonA->Enabled=false; //set buttonB avaliable for odd states
  }
  else
  {
   ButtonB->Enabled=false;
   ButtonA->Enabled=true; //set buttonB avaliable for odd states
  }

  //if(state==UI_STAGE_OPEN) ButtonA->Enabled=true; //enable revoting is depecated

  if(state) state--; //number of states in textfile
  if(state > 9) state=0; //restrict

  //search first string of state by it's number (or 0 for state 0)
  if(state) while(n<ListStp->Count)
  {
   if(ListStp->Strings[n++]=="#") state--;  //count states section in textfile
   if(!state) break;  //requested state, n is the number of first string of this state
  }

  //set buttons
  if(n<(3+ListStp->Count))
  {
   LabelHeader->Text=ListStp->Strings[n]; //caption
   ButtonA->Text=ListStp->Strings[n+1]; //left buttonA
   ButtonB->Text=ListStp->Strings[n+2];  //right buttonB
  }

  //output Help for current state
  MemoHelp->Lines->Clear(); //clear old help
  n+=3; //first help string
  while(n<ListStp->Count)
  {
   T=ListStp->Strings[n++]; //get help
   if(T=="#") break;  //check there is start of next state
   MemoHelp->Lines->Add(T); //output string to memo
  }

 }


//stop camera and show main panel
void __fastcall TForm2::ButtonStopClick(TObject *Sender)
{
 TimerQR->Enabled=false;
 CameraComponent1->Active = false;
 IsCamera=0;
 PanelQR->Visible=false;
 PanelMain->Visible=true;
 IsImage=0;
 tor_stop();
}
//---------------------------------------------------------------------------

//callback of camera image ready (in context of main thread)
void __fastcall TForm2::GetImage()
{
 CameraComponent1->SampleBufferToBitmap(ImageQR->Bitmap, true); //assign camera image to image component
 IsImage = 1; //set flag of unprocessed image
 ImageW=ImageQR->Bitmap->Width; //set image width
 ImageH=ImageQR->Bitmap->Height;  //set image heights
}

//image redy callback (in camera thread)
void __fastcall TForm2::CameraComponent1SampleBufferReady(TObject *Sender, const TMediaTime ATime)
{
 TThread::Synchronize(TThread::CurrentThread, GetImage); //subcall in main thread
}

//event of App is inactivate (mostly for Android)
bool __fastcall TForm2::AppEvent(TApplicationEvent AAppEvent, System::TObject* AContext)
{

    String T;
	switch (AAppEvent) {
		case TApplicationEvent::WillBecomeInactive:
		case TApplicationEvent::EnteredBackground:
		case TApplicationEvent::WillTerminate:
			CameraComponent1->Active = false;
            IsCamera=0;
            if(ListRes->Count > B_RESTART) T=ListRes->Strings[B_RESTART]; else T=L"Restart";
            ButtonStop->Text=T;
            if(ListRes->Count > B_FLAH) T=ListRes->Strings[B_FLAH]; else T=L"Light";
            ButtonFlash->Text=T;
            IsFlash=0;
            TimerQR->Enabled=false;
            IsImage=0;
			return true;
			break;
	}

	return false;
}


//---------------------------------------------------------------------------

//get avaliable Resolutions from camera and put list to selection box
void TForm2::FillResolutions()
{
	System::DynamicArray<TVideoCaptureSetting> LSettings = CameraComponent1->AvailableCaptureSettings;
	ComboBoxRes->Clear();
	for (int i = LSettings.Low; i <= LSettings.High; i++)
		ComboBoxRes->Items->Add(UnicodeString(LSettings[i].Width) + " x " + LSettings[i].Height + " x " + LSettings[i].FrameRate);
	ComboBoxRes->ItemIndex = 0;
}

//Show resolution of Camera
void TForm2::ShowCurrentResolution()
{
	TVideoCaptureSetting LSettings;
	UnicodeString LText;
    String T;

    if(ListRes->Count > T_QUAL) T=ListRes->Strings[T_QUAL]; else T=L"Quality: ";
    LText = T;
	LSettings = CameraComponent1->CaptureSetting;
	LabelRes->Text = LText + " " + LSettings.Width + "x" + LSettings.Height + " at " + LSettings.FrameRate + " FPS.";
}

 //Application startup
void __fastcall TForm2::FormCreate(TObject *Sender)
{
  String T;
  IFMXApplicationEventService *AppEventSvc;
	// Fill the resolutions.
    CameraComponent1->Active = false;
    IsCamera=0;
    IsImage=0;
    FillResolutions();
    //CameraComponent1->CaptureSettingPriority = TVideoCaptureSettingPriority::FrameRate;
    CameraComponent1->Quality = TVideoCaptureQuality::MediumQuality;
    ShowCurrentResolution();
	// Add platform service to see camera state. This is nedded to enable or disable the camera when the application
	// goes to background.
	if (TPlatformServices::Current->SupportsPlatformService(__uuidof(IFMXApplicationEventService), &AppEventSvc))
		AppEventSvc->SetApplicationEventHandler(AppEvent);


    //setup windows
    InitWindows();

    //setup Android
    InitAndroid();

    //run main thread
    if(!Thread) Thread = new MyThread(0);
    //start GUI update
    TimerGUI->Enabled = true;


    if(ListRes->Count > T_FORM)
    Form2->Caption=ListRes->Strings[T_FORM];
    if(ListRes->Count > T_SELECT)
    LabelSelect->Text=ListRes->Strings[T_SELECT];
    if(ListRes->Count > T_OK)
    ButtonVote->Text=ListRes->Strings[T_OK];
    if(ListRes->Count > T_CANCEL)
    ButtonCancel->Text=ListRes->Strings[T_CANCEL];

    if(ListRes->Count > T_ONION)
    Label3->Text=ListRes->Strings[T_ONION];
    if(ListRes->Count > T_NUM)
    Label4->Text=ListRes->Strings[T_NUM];
    if(ListRes->Count > T_PSW)
    Label5->Text=ListRes->Strings[T_PSW];
    if(ListRes->Count > T_ID)
    Label6->Text=ListRes->Strings[T_ID];
    if(ListRes->Count > T_VOTE)
    Label8->Text=ListRes->Strings[T_VOTE];
    if(ListRes->Count > T_STEP)
    Label10->Text=ListRes->Strings[T_STEP];
    //if(ListRes->Count > B_FILE)
    //ButtonLoad->Text=ListRes->Strings[B_FILE];



    if(ListRes->Count > T_HEADERQR)
    LabelHeaderQR->Text=ListRes->Strings[T_HEADERQR];
    if(ListRes->Count > T_QUAL)
    LabelRes->Text=ListRes->Strings[T_QUAL];

    if(ListRes->Count >B_FRONT)
    ButtonFront->Text=ListRes->Strings[B_FRONT];
    if(ListRes->Count >B_STOP)
    ButtonStop->Text=ListRes->Strings[B_STOP];
    if(ListRes->Count >B_FLAH)
    ButtonFlash->Text=ListRes->Strings[B_FLAH];
}
//---------------------------------------------------------------------------

 //Change Camera Back (default) / Front
void __fastcall TForm2::ButtonFrontClick(TObject *Sender)
{
     String T;
    //bool LActive = CameraComponent1->Active;
    CameraComponent1->Active = false;
    IsCamera=0;

    if(ListRes->Count > B_RESTART) T=ListRes->Strings[B_RESTART]; else T=L"Restart";
    ButtonStop->Text=T;
    TimerQR->Enabled=false;
    IsImage=0;


	// Select Front Camera
	if(!IsFront)
        {
         CameraComponent1->Kind = TCameraKind::FrontCamera;
         if(ListRes->Count > B_BACK) T=ListRes->Strings[B_BACK]; else T=L"Back";
         ButtonFront->Text=T;
         IsFront = 1;
        }
        else
        {
         CameraComponent1->Kind = TCameraKind::BackCamera;
         if(ListRes->Count > B_FRONT) T=ListRes->Strings[B_FRONT]; else T=L"Front";
         ButtonFront->Text=T;
         IsFront = 0;
        }

    FillResolutions();
    CameraComponent1->Quality = TVideoCaptureQuality::MediumQuality;
    ShowCurrentResolution();

}
//---------------------------------------------------------------------------

//change Camera resolution
void __fastcall TForm2::ComboBoxResChange(TObject *Sender)
{
    String T;
    bool LActive = CameraComponent1->Active;
    int LIndex;
	DynamicArray<TVideoCaptureSetting> LSettings;

    CameraComponent1->Active = false;
    TimerQR->Enabled=false;
    IsImage=0;

	LIndex = ComboBoxRes->ItemIndex;


	LSettings = CameraComponent1->AvailableCaptureSettings;
	if ((LSettings.Length > 0) && IsChange) CameraComponent1->CaptureSetting = LSettings[LIndex];
    else CameraComponent1->Quality = TVideoCaptureQuality::MediumQuality;
     IsChange=0;
     ShowCurrentResolution();

     if(IsCamera)
     {
      if(ListRes->Count > B_STOP) T=ListRes->Strings[B_STOP]; else T=L"Stop";
      ButtonStop->Text=T;
      CameraComponent1->Active = true;
      TimerQR->Enabled=true;
     }
     else
     {
      if(ListRes->Count > B_RESTART) T=ListRes->Strings[B_RESTART]; else T=L"Restart";
      ButtonStop->Text=T;
     }

}
//---------------------------------------------------------------------------

//on/off Camera Light
void __fastcall TForm2::ButtonFlashClick(TObject *Sender)
{
     String T;
     bool LActive;
	 // Turn on the Torch, if supported
	 if (CameraComponent1->HasTorch) {
		LActive = CameraComponent1->Active;
        CameraComponent1->Active = false;
        //IsCamera=0;
        //ButtonStop->Text=L"Рестарт";
        //TimerQR->Enabled=false;

		if(!IsFlash)
                {
                 CameraComponent1->TorchMode = TTorchMode::ModeOn;
                 IsFlash=1;
                 if(ListRes->Count > B_NOFLASH) T=ListRes->Strings[B_NOFLASH]; else T=L"No light";
                 ButtonFlash->Text = T;
                }
                else
                {
                 CameraComponent1->TorchMode = TTorchMode::ModeOff;
                 IsFlash=0;
                 if(ListRes->Count > B_FLAH) T=ListRes->Strings[B_FLAH]; else T=L"Light";
                 ButtonFlash->Text = T;
                }
		CameraComponent1->Active = LActive;
	 }
}
//---------------------------------------------------------------------------

//Timer for periodic QR recognizer every 100 mS
void __fastcall TForm2::TimerQRTimer(TObject *Sender)
{
  int X, Y;
  int W, H;
  TBitmapData CurrentData;
  TAlphaColorRec ColorRec;
  unsigned char im[240*320];
  short i;
   String T;

  //check there is new image from camera
  if(!IsImage)
  {
   LabelHeaderQR->Text = " N";
   return;
  }
  IsImage=0; //clear new image flag (processed)

  //check portrat or landscape orientation, set size
  if(ImageW > ImageH) { W=320; H=240;} //landscape
  else {W=240; H=320;} //portrat

  //copy camera image and resize to fixed size 320*240 or 240*320
  gBitmap->Assign(ImageQR->Bitmap);
  gBitmap->Resize(W, H);


  LabelHeaderQR->Text="w="+IntToStr((int)gBitmap->Width)+" h="+ IntToStr((int)gBitmap->Height);

  if(gBitmap->Width !=W)
  {
    LabelHeaderQR->Text = LabelHeaderQR->Text + " W";
    return;
  }

  if(gBitmap->Height !=H)
  {
   LabelHeaderQR->Text = LabelHeaderQR->Text + " W";
   return;
  }


  //get image data for read
  if(!(gBitmap->Map(TMapAccess::Read, CurrentData)))
  {
   LabelHeaderQR->Text = LabelHeaderQR->Text + " R";
   return;
  }

  //convert image's pixels to 8bit grayscale array
  for (Y = 0; Y < H; Y++)
  {
   for (X = 0; X < W; X++)
   {
    ColorRec.Color = CurrentData.GetPixel(X, Y);
    im[Y*W + X] = (unsigned char)((ColorRec.R + ColorRec.G + ColorRec.B) / 3);
   }
  }

  gBitmap->Unmap(CurrentData);

  //recognize image: <0 is error, >0 is code length
  i=ui_scanqr(im, W, H);

  LabelHeaderQR->Text = LabelHeaderQR->Text + " K=" + IntToStr(i);

  if(!i)
  {
   //char str[32];
   //qr_get((unsigned char*)str);
   //str[15]=0;
   //LabelHeaderQR->Text = String(str);
   TimerQR->Enabled=false;

   if(ListRes->Count > T_COMPLEET) T=ListRes->Strings[T_COMPLEET]; else T=L"Compleet!";
   LabelHeaderQR->Text = T;
   if(ListRes->Count > T_OK) T=ListRes->Strings[T_OK]; else T=L"OK";
   ButtonStop->Text=T;
   ButtonStop->FontColor=clRed;
   LabelHeaderQR->FontColor=clRed;
  }

}
//---------------------------------------------------------------------------
//stop application
void __fastcall TForm2::FormClose(TObject *Sender, TCloseAction &Action)
{
 ButtonStopClick(NULL);
}
//---------------------------------------------------------------------------

//set focus on Camera resolution selection by user
void __fastcall TForm2::ComboBoxResCanFocus(TObject *Sender, bool &ACanFocus)
{
 IsChange=1;
}
//---------------------------------------------------------------------------

//Click on Camera resolusion selecting by user
void __fastcall TForm2::ComboBoxResClick(TObject *Sender)
{
 IsChange=1;
}
//---------------------------------------------------------------------------



//Open Help driver
void __fastcall TForm2::ButtonAboutClick(TObject *Sender)
{
 MultiViewAbout->ShowMaster();
}
//---------------------------------------------------------------------------

//Open Info driver
void __fastcall TForm2::ButtonInfoClick(TObject *Sender)
{
 wchar_t wc[32];
 char* voted;
 char* voter;
 char* psw;
 char* srv;
 int pid;
 int aid;
 unsigned char stage;

 String fn;
 String path;
 String F;
 String T;
 TSearchRec sr;

 stage=ui_get_stage();
 pid=ui_getuser(&srv, &psw);
 aid=ui_getvote(&voted, &voter);
 if(srv) EditServer->Text=String(srv);
 if(psw) EditPas->Text=String(psw);
 if(pid) EditNum->Text=IntToStr(pid);
 if(aid) LabelId->Text=IntToStr(aid);

 EditServer->FontColor = clBlack;
 EditPas->FontColor = clBlack;
 EditNum->FontColor = clBlack;
 IsUser=0;

 if(stage==UI_STAGE_FINE) voted=voter;
 if(voted)
 {
  win2wc(wc, voted, CANDIDATE_LEN);  //convert to wide string
  T=wc; //convert to UnicodeString
  LabelVote->Text=T;
 }

 LabelState->Text = LabelHeader->Text;

 if(stage==UI_STAGE_SCAN)
 {
  EditServer->Enabled = true;
  EditPas->Enabled = true;
  EditNum->Enabled = true;
 }
 else
 {
  EditServer->Enabled = false;
  EditPas->Enabled = false;
  EditNum->Enabled = false;
 }

 //search files with personal data and add to list for select
 if(stage==UI_STAGE_SCAN)
 {
 #ifdef __ANDROID__
  path = System::Ioutils::TPath::GetSharedDownloadsPath(); //download folder
 #else
  path = GetCurrentDir();
  path = path + PathDelim + "pub"; //public subfolder in app folder
 #endif

 ComboBoxFile->Visible = true; //set selector visible
 ComboBoxFile->Items->Clear(); //clear
 F="* "; //set Iteam0 as caption
 if(ListRes->Count > B_FILE) T=ListRes->Strings[B_FILE]; else T=L"from file";
 F = F + T;
 ComboBoxFile->Items->Add(F);
 ComboBoxFile->ItemIndex = 0; //set index to caption
 //search files in specified path
 if ( !FindFirst( path + "/*", faAnyFile, sr) )
		{
			do
				{
					if ( sr.Name=="." || sr.Name==".." ) {}
					else if ( (sr.Attr & faDirectory) == faDirectory ) {} // dir
					else {} // file
					// add sr.Name to list
					F=System::Ioutils::TPath::GetExtension(sr.Name);
                    if(F==".dat")  //check file extension
                    {
                     F=System::Ioutils::TPath::GetFileName(sr.Name);
                     ComboBoxFile->Items->Add(F); //add file name to list
                    }
				}
			while ( !FindNext(sr) );
			FindClose(sr);
			// get on click fn = path + "/" + name;
		}
 }
 else  ComboBoxFile->Visible = false; //not show selector in stages not allowed code scanning

 MultiViewInfo->ShowMaster(); //show Info panel
}
//---------------------------------------------------------------------------
 //close Info driver and back to main panel
void __fastcall TForm2::SpeedButtonBackClick(TObject *Sender)
{
 MultiViewInfo->HideMaster();
}
//---------------------------------------------------------------------------

//close Help driver and back to main panel
void __fastcall TForm2::MemoLogoClick(TObject *Sender)
{
 MultiViewAbout->HideMaster();
}
//---------------------------------------------------------------------------

//timer for periodically processing events for GUI
void __fastcall TForm2::TimerGUITimer(TObject *Sender)
{
 unsigned char ev;

 while(ev=ui_getevent())  //get event and check it is nonzero
 {
  if(ev==255) SetState(); //set new state for event 255 or output message by event
  else if(ev<ListMsg->Count) MemoInfo->Lines->Add(ListMsg->Strings[ev]);
 }

}
//---------------------------------------------------------------------------
//before stop app
void __fastcall TForm2::FormCloseQuery(TObject *Sender, bool &CanClose)
{
 ButtonStopClick(NULL);
}
//---------------------------------------------------------------------------

//load personal data from file
void __fastcall TForm2::ComboBoxFileChange(TObject *Sender)
{
 String T;
 String E;
 AnsiString S;
 short i;

 char str[256];

 if(ComboBoxFile->ItemIndex <1) return;

 T=ComboBoxFile->Items->operator [](ComboBoxFile->ItemIndex);
 E=System::Ioutils::TPath::GetExtension(T);
 if(E != ".dat") return;
  #ifdef __ANDROID__
  E = System::Ioutils::TPath::GetSharedDownloadsPath() + PathDelim + T;
 #else
  E = GetCurrentDir() + PathDelim + "pub" + PathDelim + T;
 #endif
 S=(AnsiString)E;
 i = ui_setfile(S.c_str());

 strncpy(str,  S.c_str(), sizeof(str));
 LabelState->Text = String(str);

}
//---------------------------------------------------------------------------

//ButtonA (left button on main panel) user's actions depends state
void __fastcall TForm2::ButtonAClick(TObject *Sender)
{
 String T;
 String V;

 wchar_t wc[CANDIDATE_LEN];
 unsigned char stage;
  char* p;
  char* pp;
  int i;
  int n;

 MemoInfo->Lines->Clear();  //clear memo for states other then init
 stage = ui_get_stage();

 if(stage<UI_STAGE_SCAN) SpeedButtonExitClick(NULL); //not inited
 else if(stage==UI_STAGE_SCAN) //scan
 {
  PanelMain->Visible=false;
  PanelQR->Visible=true;
 
  CameraComponent1->Active = true;
  IsCamera=1;
  if(ListRes->Count > B_STOP) T=ListRes->Strings[B_STOP]; else T=L"Stop";
  ButtonStop->Text=T;
  if(ListRes->Count > B_FLAH) T=ListRes->Strings[B_FLAH]; else T=L"Light";
  ButtonFlash->Text=T;
  IsFlash=0;
  TimerQR->Enabled=true;
  IsImage=0;
  ButtonStop->FontColor=clBlack;
  LabelHeaderQR->FontColor=clBlack;
  ShowCurrentResolution();
 }
 else if(stage==UI_STAGE_IDNT) ui_cmd(UI_CMD_IDNT); //idnt
 else if(stage==UI_STAGE_RSTR) SpeedButtonExitClick(NULL); //reset
 else if((stage==UI_STAGE_VOTE)||(stage==UI_STAGE_OPEN)) //vote
 {
   //count candidates in list
   ComboBoxVote->Clear(); //clear candidates combobox
   memset(Cnd, 0, sizeof(Cnd)); //clear candidate's indexes
   n=0; //clear total candidates
   p=ui_getcnd(); //get pointer to candidate's list (chars in win1251 code
   for(i=0;i<MAX_CANDIDATES;i++) //process chars
   {
     pp=p+i*CANDIDATE_LEN; //pinter to next candidate
     if(!(*pp)) continue; //check this candidate is set
     win2wc(wc, pp, CANDIDATE_LEN);  //convert to wide string
     T=wc; //convert to UnicodeString
     ComboBoxVote->Items->Add(T); //add candidate to combobox
     Cnd[n++]=i; //set index and count
   }

   //check we have candidates
   if(n)
   {
    if(ListRes->Count > T_SELECT) T=ListRes->Strings[T_SELECT];
    else T="Select candidate from ";
    LabelSelect->Text=T+IntToStr(n);
    ComboBoxVote->ItemIndex = -1;
    PanelMain->Visible = false;
    PanelVote->Visible = true;
   }
   else ui_setevent(NO_CANDIDATES_ERR);
 }
 else if(stage==UI_STAGE_FINE) SpeedButtonExitClick(NULL); //opened

}
//---------------------------------------------------------------------------

//ButtonB (right button on main panel) user's actions depends state
void __fastcall TForm2::ButtonBClick(TObject *Sender)
{
 unsigned char stage;

 MemoInfo->Lines->Clear();  //clear memo for states other then init
 stage = ui_get_stage();

 if(stage == UI_STAGE_GETS) ui_cmd(UI_CMD_GETS);
 else if(stage == UI_STAGE_REGS) ui_cmd(UI_CMD_REGS);
 else if(stage == UI_STAGE_JOIN) ui_cmd(UI_CMD_JOIN);
 else if(stage == UI_STAGE_OPEN) ui_cmd(UI_CMD_OPEN);
}
//---------------------------------------------------------------------------

//Cancel select of vote
void __fastcall TForm2::ButtonCancelClick(TObject *Sender)
{
 PanelVote->Visible = false;
 PanelMain->Visible = true;
}
//---------------------------------------------------------------------------

//Voting
void __fastcall TForm2::ButtonVoteClick(TObject *Sender)
{
 int i;
 char str[16];
 char* p;

 i=ComboBoxVote->ItemIndex; //index of selected candidate in combobox
 if((i<0)||(i>(MAX_CANDIDATES-1))) return;  //restrict
 i=Cnd[i]; //index of this candidate in list
 if((i<0)||(i>(MAX_CANDIDATES-1))) return; //restrict

 p=ui_getcnd(); //get pointer to candidate's list (chars in win1251 code)
 p+=i*CANDIDATE_LEN; //pointer to selected candidate
 if(!(*p)) return;   //check candidate is not empty
 strncpy(str, p, CANDIDATE_LEN); //copy selected candidate
 i=ui_setvote(str); //set selected candidate
 if(!i) ui_cmd(UI_CMD_VOTE); //start voting process
 PanelVote->Visible = false; //back to main panel
 PanelMain->Visible = true;
}
//---------------------------------------------------------------------------

//Exitin App
void __fastcall TForm2::SpeedButtonExitClick(TObject *Sender)
{
 //kill old Tor process
#ifdef _WIN32
  system( (char*)"taskkill /IM tf_tor.exe /F");
#else
  system( (char*)"killall -9 tf_tor");
#endif

  Application->Terminate();
}
//---------------------------------------------------------------------------


//Apply manually entered settings
void __fastcall TForm2::SpeedButtonApplyClick(TObject *Sender)
{
  AnsiString S;
  char psw[16];
  char srv[32];
  int n;
  short i;
  unsigned char stage;

  //check stage
  if(!IsUser) return;
  stage = ui_get_stage();
  if(stage!=UI_STAGE_SCAN) return;
  //check settings
  S=EditPas->Text;
  LabelState->Text=IntToStr(S.Length());
  if((S.Length()<1)||(S.Length()>15)) return;
  S=EditNum->Text;
  n=StrToIntDef(S, 0);
  if(n<1) return;
  S=EditServer->Text;
  if(S.Length()<16) return;
  else if(S.Length()>16)
  {
   LabelState->Text=S.SubString(17, 1);
   if(S.SubString(17, 1)!=".") return;
  }

  i=ui_setuser(n, psw, srv);
  if(!i)
  {
   //clear changes
   EditServer->FontColor = clBlack;
   EditPas->FontColor = clBlack;
   EditNum->FontColor = clBlack;
   IsUser=0;
  }
}
//---------------------------------------------------------------------------


void __fastcall TForm2::EditNumChange(TObject *Sender)
{
 IsUser=1;
 EditNum->FontColor = clRed;
}
//---------------------------------------------------------------------------

void __fastcall TForm2::EditPasChange(TObject *Sender)
{
 IsUser=1;
 EditPas->FontColor = clRed;
}
//---------------------------------------------------------------------------

void __fastcall TForm2::EditServerChange(TObject *Sender)
{
 IsUser=1;
 EditServer->FontColor = clRed;
}
//---------------------------------------------------------------------------

