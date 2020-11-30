/* Sine and cosine without mathematic library. Optimized for doubleing
   point single precision. 
   Copyright (c) Nikitin V.F. 2000

   Calculate sine and cosine within [0, PI/4]:
   void _Sico(double arg,double *sine,double *cosi);

   Calculate sine and cosine within [0, PI/2]:
   void Sico(double arg,double *sine,double *cosi);

   Calculate sine and cosine within one period [-PI, PI]:
   void Sico1p(double arg,double *sine,double *cosi);

   No argument domain check is performed: insert yourself.
*/



#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "amath.h"

#define CRCPOLY_LE 0xedb88320
#define TELCRCPOLY 0xA001


static const unsigned char SetBitTable[16]={0,1,1,2, 1,2,2,3, 1,2,2,3, 2,3,3,4};

unsigned int crc32_le(unsigned char const *p, unsigned int len)
{
  unsigned int i;
  unsigned int crc4=0xffffffff;
  while(len--) {
    crc4^=*p++;
    for(i=0; i<8; i++)
      crc4=(crc4&1) ? (crc4>>1)^CRCPOLY_LE : (crc4>>1);
    }
  crc4^=0xffffffff;
  return crc4;
}
  
unsigned int crc32_leupd(unsigned char const *p, unsigned int len, unsigned int crc4)
{
  unsigned int i;
  //u32 crc4=0xffffffff;
  while(len--) {
    crc4^=*p++;
    for(i=0; i<8; i++)
      crc4=(crc4&1) ? (crc4>>1)^CRCPOLY_LE : (crc4>>1);
    }
 // crc4^=0xffffffff;
  return crc4;
}

/*
 crc=crc32_le(h, 16);
 b=(0xFF&(crc>>24));
 buff[XD+0x0C]=b;
 b=(0xFF&(crc>>16));
 buff[XD+0x0D]=b;
 b=(0xFF&(crc>>8));
 buff[XD+0x0E]=b;
 b=0xFF&crc;
 buff[XD+0x0F]=b;
*/


 unsigned char dutcrc8(unsigned char* data, int len)
{
 int j;
 unsigned char crc=0;
 unsigned char i;
 for(j=0;j<len;j++)
 {
   i=crc^data[j];
   crc=0;
   if(i & 0x01) crc ^= 0x5e;
   if(i & 0x02) crc ^= 0xbc;
   if(i & 0x04) crc ^= 0x61;
   if(i & 0x08) crc ^= 0xc2;
   if(i & 0x10) crc ^= 0x9d;
   if(i & 0x20) crc ^= 0x23;
   if(i & 0x40) crc ^= 0x46;
   if(i & 0x80) crc ^= 0x8c;
 }
 return crc;
}



unsigned int mtoi(unsigned char const *p)
{
 unsigned int ret=0;
 ret+=(0x1000000* *p++);
 ret+=(0x10000* *p++);
 ret+=(0x100* *p++);
 ret+=(*p);
 return ret;
}

void mtom(unsigned char *pd, unsigned char const *ps, int const a)
{
 int ii;
 for (ii=0; ii<a; ii++) pd[ii]=ps[ii];
}

void itom(unsigned char *p, unsigned int const a)
{
 *p++=(unsigned char) (a>>24)&0xFF;
 *p++=(unsigned char) (a>>16)&0xFF;
 *p++=(unsigned char) (a>>8)&0xFF;
 *p++=(unsigned char) a&0xFF;
}


unsigned short mtos(unsigned char const *p)
{
 unsigned short ret;
 
 ret=p[1];
 ret<<=8;
 ret+=p[0];
 return ret;
}

void stom(unsigned char *p, unsigned short const a)
{
 p[0]=a&0xFF;
 p[1]=a>>8;

}

unsigned short telcrc16(unsigned char const *p, int len)
{
  int i;

  unsigned short crc=0xffff; // zlib mod  
  //unsigned short crc=0; 

//unsigned short crc=0; 
  while(len--) {
    crc^=*p++;
    for(i=0; i<8; i++)
      crc=(crc&1) ? (crc>>1)^TELCRCPOLY : (crc>>1);
    }
  //crc^=0xffff; /* zlib mod  */
  return crc;
}


unsigned short telcrc16n(unsigned char const *p, int len)
{
  int i;

  //unsigned short crc=0xffff; // zlib mod  
  unsigned short crc=0; 

//unsigned short crc=0; 
  while(len--) {
    crc^=*p++;
    for(i=0; i<8; i++)
      crc=(crc&1) ? (crc>>1)^TELCRCPOLY : (crc>>1);
    }
  //crc^=0xffff; /* zlib mod  */
  return crc;
}

//portable atoi
 int myatoi(char* p)
 {
  #define MAXDIGITS 5 //maximal number of digits (5 for short)
  
  short i; //counter
  char c; //processed digit
  int d=0; //result
  char minus=0; //flag of negative value
  
  //check negative value
  if(p[0]=='-') 
  {
   minus=1; //set negative flag
   p++; //move pointer to first digit
  }
  
  //process digits to first not-digit char
  for(i=0;i<MAXDIGITS;i++) 
  {
   c=p[i]; //char
   if((c>'9')||(c<'0')) break; //must be in rabhe '0'-'9'
   c-='0'; //to bin
   d=d*10+c; //add as low decimal
  }
  
  if(minus) d=-d; //check negative flag and negate result
  return d; //return result
 }

 //helper: portable convert u8[4]->u32
unsigned int m2u(unsigned char* m)
{
 unsigned int u;
 u=(unsigned int)m[0];
 u|=((unsigned int)m[1]<<8);
 u|=((unsigned int)m[2]<<16);
 u|=((unsigned int)m[3]<<24);
 return u;	
}

//helper: portable convert u32->u8[4]
void u2m(unsigned int u, unsigned char* m)
{
 m[0]=u&0xFF;
 m[1]=(u>>8)&0xFF;
 m[2]=(u>>16)&0xFF;
 m[3]=(u>>24)&0xFF;		
}

short bitcnt(unsigned char* data, short len)
{
 short i;
 unsigned short ret=0;

 for(i=0;i<len;i++)
 {
  ret+=SetBitTable[data[i]&0x0F];
  ret+=SetBitTable[data[i]>>4];
 }

 return ret;
}


unsigned char iszero(unsigned char* data, short len)
{
 short i;
 unsigned char b=0;

 for(i=0;i<len;i++) b|=data[i];

 return (unsigned char)(!b);

}


unsigned char isequal(unsigned char* data0, unsigned char* data1, short len)
{
 short i;
 unsigned char b=0;

 for(i=0;i<len;i++) b|=(data0[i]^data1[i]);

 return (unsigned char)(!b);
}


 //convert binlen bytes in binary array to hex string in str
void bin2str(unsigned char* bin, char* str, short binlen)
{
 short i;
 signed char c;

 //proces all bytes
 for(i=0;i<binlen;i++)
 {
  c=bin[i]>>4;  //hight nibble
  if(c<10) c+='0'; else c+=('A'-10); //convert to hex char
  *str++=c; //put to string
  c=bin[i]&0x0F; //low nibble
  if(c<10) c+='0'; else c+=('A'-10); //convert to hex char
  *str++=c; //put to string
 }
 *str=0; //terminate string
}


 //convert hex string to binary array with specified maximal length
short str2bin(char* str, unsigned char* bin, short maxbinlen)
{
  short i, n;
  signed char c;
  unsigned char b;

  maxbinlen*=2; b=0; n=0; //twice binlen for get requested number of hex chars
  for(i=0;i<maxbinlen;i++) //process all hex chars
  {
   c=str[i]; //get next char
   if((c>='0')&&(c<='9')) c-='0'; //convert decimal char to bin
   else if((c>='A')&&(c<='F')) c-=('A'-10); //convert hex char to bin
   else break; //all other chars: terminate

   if(i&1) //odd char
   {
    b|=c; //set low nibble of accumulator
    bin[n]=b; //output byte
    n++; //count oututted bytes
    b=0; //clear accumulator
   }
   else b=((unsigned char)c<<4); //even char: set hight nibble of accumulator
  }
  return n; //returns number of outputted bytes
}


