
#include "client.h"
#include "quirc.h"

//Qr code recognition
short cli_qr_rec(unsigned char* img, short w, short h)
{

 struct quirc_code code;
 struct quirc *q=0;
 struct quirc_data qd;
 unsigned char qrdata[32];
 uint8_t *image=0;
 int id_count=-1;
 short len;
 short i;

    //create Qr code recognition object
    q = quirc_new();
	if (!q) return -1;

    //set size of image
	id_count=quirc_resize(q, w, h);
	if (id_count<0)
	{
		quirc_destroy(q);
        return -2;
	}

    //get internal image pointer
	image = quirc_begin(q, NULL, NULL);
	if(!image)
	{
        quirc_destroy(q);
        return -3;
	}

    //copy image to internal array and recognize
    memcpy(image, img, w*h);
    id_count=0;
	quirc_end(q);

    //get number of QR codes finded in image
    id_count = quirc_count(q);
    if (id_count == 0)
    {
		quirc_destroy(q);
		return -4;
	}

    //decode recognized QR-code
	quirc_extract(q, 0, &code);
	quirc_decode(&code, &qd);
	quirc_destroy(q);

	//S="Ver: "+IntToStr(qd.version);
        //S=S+" Type: "+IntToStr(qd.data_type);
        //S= S+" Len: "+IntToStr(qd.payload_len);

    //get data length
    len=qd.payload_len;
    if(len!=32) return -5;
    i=cli_save_scan(qd.payload);

    return i;
}



//extract client's id, password and  server's onion address
//from 32-bytes binary string from QR-code 
short cli_set_scan(unsigned char* data)
{
 unsigned char qrd[32];
 char str[256];
 unsigned short w;


 memcpy(qrd, data, 32);
 //check crc16
 w=telcrc16(qrd, 30);
 qrd[30]^=(w&0xFF);
 qrd[31]^=(w>>8);
 w=qrd[30]|qrd[31];
 if(w) return -1;

 cli->id=mtoi(qrd+16);
 base32_encode(str, qrd+20);
 str[16]=0;
 sprintf(str+16, ".onion");
 strncpy(cli->adr, str, sizeof(cli->adr));
 qrd[16]=0;
 strncpy(cli->pwd, (char*)qrd, sizeof(cli->pwd));
 return 0;
}



short cli_save_scan(unsigned char* data)
{
  unsigned char e=0;
  short i;
 while(1)
 {

  i=cli_set_scan(data);
  if(i)
  {
   e=ERC_SCAN_CRC;
   break;
  }

  //save data to files
   i=cli_fwrite(FILE_SCAN, (unsigned char*)data, 32);
   if(i!=32)
   {
    e=ERC_SCAN_SAVE;
    break;
   }

  //set scan flag
  cli->flags |= FLAG_SCAN;
  break;
 }
  if(e) i=-e; else i=0;
  return i;
}








short cli_set_test(unsigned char* pkt)
{
 int id=2;
 char psw[]="2222";
 char ona[]="snu27k76oyuqov3m";
 unsigned char data[32]={0,};
 short i;
 unsigned short w;


 strncpy((char*)data, psw, 16);
 itom(data+16, id);
 i=base32_decode(data+20, ona);

 //add crc16 to qrcode data
 w=telcrc16(data, 30);
 data[30]=w&0xFF;
 data[31]=w>>8;

 memcpy(pkt, data, 32);
 return i; //0 - sucess
}
