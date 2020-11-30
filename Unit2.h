//---------------------------------------------------------------------------

#ifndef Unit2H
#define Unit2H
//---------------------------------------------------------------------------
#include <System.Classes.hpp>
#include <FMX.Controls.hpp>
#include <FMX.Forms.hpp>
#include <FMX.Layouts.hpp>
#include <FMX.Types.hpp>
#include <FMX.Controls.Presentation.hpp>
#include <FMX.Edit.hpp>
#include <FMX.StdCtrls.hpp>
#include <FMX.TabControl.hpp>
#include <FMX.ImgList.hpp>
#include <System.ImageList.hpp>
#include <FMX.Objects.hpp>
#include <FMX.MultiView.hpp>
#include <FMX.ListBox.hpp>
#include <FMX.Memo.hpp>
#include <FMX.ScrollBox.hpp>
#include <System.Notification.hpp>
#include <IdBaseComponent.hpp>
#include <IdComponent.hpp>
#include <IdGlobal.hpp>
#include <IdSocketHandle.hpp>
#include <IdUDPBase.hpp>
#include <IdUDPServer.hpp>
#include <FMX.ExtCtrls.hpp>
#include <FMX.Media.hpp>
//---------------------------------------------------------------------------
class TForm2 : public TForm
{
__published:	// IDE-managed Components
    TTimer *TimerGUI;
    TStyleBook *StyleBook1;
    TMultiView *MultiViewInfo;
    TMultiView *MultiViewAbout;
    TSpeedButton *SpeedButtonBack;
    TSpeedButton *SpeedButtonApply;
    TSpeedButton *SpeedButtonExit;
    TRectangle *RectangleBack;
    TRectangle *RectangleApply;
    TRectangle *RectangleExit;
    TImage *ImageBack;
    TImage *ImageApply;
    TImage *ImageExit;
    TEdit *EditServer;
    TGridPanelLayout *GridPanelLayout4;
    TLabel *Label3;
    TLabel *Label4;
    TEdit *EditNum;
    TLabel *Label5;
    TEdit *EditPas;
    TLabel *Label6;
    TLabel *LabelId;
    TLabel *Label8;
    TLabel *LabelVote;
    TLabel *Label10;
    TLabel *LabelState;
    TMemo *MemoLogo;
    TImage *ImageLogo;
    TMemo *MemoInfo;
    TPanel *PanelQR;
    TCameraComponent *CameraComponent1;
    TGridPanelLayout *GridPanelLayout3;
    TButton *ButtonFront;
    TButton *ButtonFlash;
    TButton *ButtonStop;
    TGridPanelLayout *GridPanelLayout5;
    TLabel *LabelRes;
    TComboBox *ComboBoxRes;
    TPanel *PanelMain;
    TGridPanelLayout *GridPanelLayout2;
    TButton *ButtonA;
    TButton *ButtonB;
    TGridPanelLayout *GridPanelLayout1;
    TButton *ButtonAbout;
    TLabel *LabelHeader;
    TButton *ButtonInfo;
    TMemo *MemoHelp;
    TMemo *MemoResult;
    TLabel *LabelHeaderQR;
    TImage *ImageQR;
    TTimer *TimerQR;
    TComboBox *ComboBoxFile;
    TPanel *PanelVote;
    TGridPanelLayout *GridPanelLayout6;
    TButton *ButtonVote;
    TButton *ButtonCancel;
    TComboBox *ComboBoxVote;
    TImage *Image1;
    TLabel *LabelSelect;
    void __fastcall ButtonStopClick(TObject *Sender);
    void __fastcall ButtonAClick(TObject *Sender);
    void __fastcall CameraComponent1SampleBufferReady(TObject *Sender, const TMediaTime ATime);
    void __fastcall FormCreate(TObject *Sender);
    void __fastcall ButtonFrontClick(TObject *Sender);
    void __fastcall ComboBoxResChange(TObject *Sender);
    void __fastcall ButtonFlashClick(TObject *Sender);
    void __fastcall TimerQRTimer(TObject *Sender);
    void __fastcall FormClose(TObject *Sender, TCloseAction &Action);
    void __fastcall ComboBoxResCanFocus(TObject *Sender, bool &ACanFocus);
    void __fastcall ComboBoxResClick(TObject *Sender);
    void __fastcall ButtonAboutClick(TObject *Sender);
    void __fastcall ButtonInfoClick(TObject *Sender);
    void __fastcall SpeedButtonBackClick(TObject *Sender);
    void __fastcall MemoLogoClick(TObject *Sender);
    void __fastcall TimerGUITimer(TObject *Sender);
    void __fastcall FormCloseQuery(TObject *Sender, bool &CanClose);
    void __fastcall ComboBoxFileChange(TObject *Sender);
    void __fastcall ButtonBClick(TObject *Sender);
    void __fastcall ButtonCancelClick(TObject *Sender);
    void __fastcall ButtonVoteClick(TObject *Sender);
    void __fastcall SpeedButtonExitClick(TObject *Sender);
    void __fastcall SpeedButtonApplyClick(TObject *Sender);
    void __fastcall EditNumChange(TObject *Sender);
    void __fastcall EditPasChange(TObject *Sender);
    void __fastcall EditServerChange(TObject *Sender);




private:	// User declarations
    void __fastcall GetImage();
    void __fastcall InitWindows();
    void __fastcall InitAndroid();
    void __fastcall SetState(void);
    bool __fastcall AppEvent(TApplicationEvent AAppEvent, System::TObject* AContext);
    void FillResolutions();
    void ShowCurrentResolution();
public:		// User declarations
    __fastcall TForm2(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TForm2 *Form2;
//---------------------------------------------------------------------------
#endif
