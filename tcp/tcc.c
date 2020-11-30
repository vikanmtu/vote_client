//**************************************************************************
//ORFone project
//Core of transport module
//**************************************************************************

#include <limits.h>
#include <stdio.h>

#ifdef _WIN32

#include <stddef.h>
#include <stdlib.h>
#include <basetsd.h>
#include <stdint.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>

#ifndef __BORLANDC__
 #include <ws2tcpip.h>
 #include <sys/time.h>
#endif

#define ioctl ioctlsocket
#define close closesocket
#define EWOULDBLOCK WSAEWOULDBLOCK  //no data for assync polling
#define ENOTCONN WSAENOTCONN        //wait for connection for assinc polling
#define ECONNRESET WSAECONNRESET    //no remote udp interface in local network

#include "amath.h"
#include "shake.h"
#include "tcc.h"

char sock_buf[32768];   //WSA sockets buffer
//------------------------------------------------------------------
//some Windows compilators not have gettimeofday and require own realization
//------------------------------------------------------------------
#ifndef gettimeofday
 int gettimeofday(struct timeval *tv, void* tz)
{

  FILETIME ft;
  const __int64 DELTA_EPOCH_IN_MICROSECS= 11644473600000000;
  unsigned __int64 tmpres = 0;
  unsigned __int64 tmpres_h = 0;
  //static int tzflag;

  if (NULL != tv)
  {
    GetSystemTimeAsFileTime(&ft);

    tmpres |= ft.dwHighDateTime;
    tmpres <<= 32;
    tmpres |= ft.dwLowDateTime;

    //converting file time to unix epoch
    tmpres /= 10;  //convert into microseconds
    tmpres -= DELTA_EPOCH_IN_MICROSECS;

    tmpres_h=tmpres / 1000000UL; //sec
    tv->tv_sec = (long)(tmpres_h);
    tv->tv_usec = (long)(tmpres % 1000000UL);
  }
  return 0;

}
#endif


#else //linux
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/tcp.h>
#include <netdb.h>

#ifdef LINUX_FPU_FIX
#include <fpu_control.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "string.h"
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <fcntl.h>
//#include <ifaddrs.h>

#endif


#ifndef INVALID_SOCKET
 #define INVALID_SOCKET -1
#endif

#ifndef SOCKET_ERROR
 #define SOCKET_ERROR -1
#endif


#include "tcc.h"
#include "cli_verb.h"

char tcc_server[32]={0,};  //servers address
unsigned short tcc_srvport=0;
unsigned short tcc_torport=0; //Tor sock5 port 

unsigned char tcc_state=TCC_STATE_IDDLE; //state of connecting
unsigned char tcc_torout[48]; //SOCK5 adress request for Tor
unsigned char tcc_torin[48]; //SOCK5 adress request for Tor
short tcc_torlen=0;  //length of SOCK5 adress request

unsigned char tcc_buf[TCC_MAXLEN];
short tcc_outlen=0; //length of data will be send
short tcc_ptr=0; //bytes in buffer
short tcc_req=0; //bytes to be readed
unsigned int tcc_timenow=0; //last timestamp
unsigned int tcc_timecnt=TCC_TIMECNT; //counter for renew timestamp
unsigned int tcc_timeout=0;  //time for close socket (0 - not read)
short tcc_job=0; //thread job flag

int tcc_sock=INVALID_SOCKET; //outgoing socket
 


//suspend excuting of the thread  for paus msec
void psleep(int paus)
{
 #ifdef _WIN32
    Sleep(paus);
 #else
    usleep(paus*1000);
 #endif
}
 
 
 //force terminate
 void tcc_close(void)
 {
  //if(!invalid) close, set invalid
 if(tcc_sock!=INVALID_SOCKET)
 {
  close(tcc_sock);
  tcc_sock=INVALID_SOCKET;
 }
  tcc_ptr=0; //clear receiving buffer
  tcc_req=0;
  tcc_timeout=0;
  tcc_outlen=0; 
  tcc_torlen=0;
  tcc_state=TCC_STATE_IDDLE; 
  my_memclr(tcc_buf, sizeof(tcc_buf));
 }
 
 short tcc_init(void)
 {
   struct timeval tt1; 
   
    
   //check for first start and inialize WinSocket (windows only)

  #ifdef _WIN32
    //Initializing WinSocks
   if (WSAStartup(0x202, (WSADATA *)&sock_buf[0]))
   {
    return -1;
    //if(TR_DBG) printf("ti_init: WSAStartup error: %d\n", WSAGetLastError());
   }
  #endif

  
   tcc_close();
  
   gettimeofday(&tt1, NULL); //get timestamp
   tcc_timenow=(unsigned int) tt1.tv_sec; //set global value
   tcc_timecnt=TCC_TIMECNT; //init timeloop

   return 0;
  
 }
 
//set server's address and port 
void tcc_setsrv(char* server, unsigned short torport)
{
 char str[32];
 short i, len;
 int port=0;
 
 tcc_torport=torport;
 
 strncpy(str, server, sizeof(str));
 str[sizeof(str)-1]=0;
 len=strlen(str);
 for(i=0; i<len;i++)
 {
  if(str[i]==':') break;
 }
 
 if(i<len)
 {
  str[i]=0;
  i++;
  port=atoi(str+i);
  if((port<1)||(port>65535)) port=0;
 }
 
 if(port) tcc_srvport=port; else tcc_srvport=TCC_DEFPORT;
 strncpy(tcc_server, str, sizeof(tcc_server));
 
} 
 
 //connect and send packet to remote
 short tcc_send(unsigned char* pkt)
 {

  struct timeval tt1; 
   struct sockaddr_in saddr;  //work address structure
  unsigned long opt = 1; //for ioctl
  int flag=1; //for setsockopt
  unsigned long  ip;
  unsigned short port;
  short len;
  unsigned long naddr;
  char str[256];
  struct hostent *hh; //for resolving
  short pktlen;
  int i;
  

  //close existed connecting
   tcc_close();
  
  //check data
  pktlen=mtos(pkt);
  if((pktlen<=TCC_HDR_LEN)||(pktlen>=TCC_MAXLEN)) return -ERC_SEND_LEN;
  
  
  
  //check remote port and address string
  if(!tcc_srvport) return -ERC_SEND_PRT;
  strncpy(str, tcc_server, sizeof(str));
  len=strlen(str);
  if(!len) return -ERC_SEND_SRV;
  
  //check for specified address is IP-address
  naddr=inet_addr(str); 
  
 //setup tor connecting
 if(tcc_torport)
 {
  //check truncated onion adress and append suffix
  if( (!strchr(str, '.') ) && (len==16) )  strcpy(str+len, (char*)".onion");
 
  //Make socks5 request in tr.torbuf
  strcpy((char*)tcc_torout+5, str); //hostname or IP string
  i=4; //IPv4 Len
  tcc_torout[3]=0x01; //for IPv4 socks request
  //check for adress string is IP, replace string by integer
  if(naddr!= INADDR_NONE) (*(unsigned int *)(tcc_torout+4)) = (unsigned int)naddr;
  else //or use string as a hostname for Tor
  {
   i=strlen((const char*)tcc_torout+5); //length of hostname string
   tcc_torout[3]=0x03; //for hostname socks request
  }
  tcc_torout[4]=i;  //length of hostname or integer IP
  tcc_torout[0]=0x05; //socks5 ver
  tcc_torout[1]=0x01; //socks request type: connect
  tcc_torout[2]=0x00; //reserved
  tcc_torout[i+5]=(tcc_srvport>>8);
  tcc_torout[i+6]=(tcc_srvport&0xFF); //remote port
  
  tcc_torlen=i+7; //total length of request packet
  ip=INADDR_LOCAL; //set connetctin target is a Tor SOCKS5 interface
  port=tcc_torport;
 }
 else  //setup tcp connecting
 {
  //if(TR_DBG) printf("tr_call_setup: TCP call to %s\r\n", str);
  if(naddr==INADDR_NONE) //check for adress string is not IP
  {
   hh = gethostbyname(str); //resolve domain name
   if (hh == 0) //if no DNS reported
   {
    //if(TR_DBG) printf("unknown host %s\r\n", str);
    tcc_close();
    return -ERC_SEND_DNS;
   }
   memcpy((char *) &naddr, (char *) hh->h_addr, sizeof naddr);
   //if(TR_DBG) printf("tr_call_setup: Resolved: %s\r\n", inet_ntoa(tr.saddr.sin_addr));  //notify
  }
  
  tcc_torlen=0;
  ip=naddr; //set their IP
  port=tcc_srvport;
 }
   
   
   //create new tcp socket for outgoing connecting
  if((tcc_sock = socket(AF_INET, SOCK_STREAM, 0)) <0)
  {
   perror("tr.sock_tcp_out");
   tcc_sock=INVALID_SOCKET;
   return -ERC_SEND_SOC;
  }


   //disable nagle algo
 if (setsockopt(tcc_sock, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag)) < 0)
 {
  perror( "tr.sock_tcp_out TCP_NODELAY" );
  tcc_close();
  return -ERC_SEND_NGL;
 }

 //unblock socket
 opt=1;
 ioctl(tcc_sock, FIONBIO, &opt);
  
 
 //set remote adress structure
 memset(&saddr, 0, sizeof(saddr));
 saddr.sin_family = AF_INET;
 saddr.sin_port = htons(port);
 saddr.sin_addr.s_addr=ip;

 //start connecting procedure
 connect(tcc_sock, (const struct sockaddr*)&saddr, sizeof(saddr));
 tcc_timeout=tcc_timenow + TCC_TCPTOUT;
 //set status of outgoing connecting.
 if(tcc_torlen) tcc_state=TCC_STATE_WAIT_TOR; 
 else tcc_state=TCC_STATE_WAIT_TCP; //set state and timeout depend connecting tipe
 
   
 //store data for sending
 memcpy(tcc_buf, pkt, pktlen);
 tcc_outlen=pktlen; 
 
  return 0;
   
  
 }
 
 //get answer packet from remote
 short tcc_read(unsigned char* pkt)
 {
  struct timeval tt1;
  int len=0;
  int i;
  short ret=0;

  //sleep on no job	  
	if(!tcc_job) psleep(TCC_SLEEP);
        tcc_job=0;

  //renew timenow here
  tcc_timecnt--;
  if(!tcc_timecnt)
  {
   gettimeofday(&tt1, NULL); //get timestamp
   tcc_timenow=(unsigned int) tt1.tv_sec; //set global value
   tcc_timecnt=TCC_TIMECNT; //init timeloop
    //check timeout
   if(tcc_timeout && (tcc_timenow > tcc_timeout))
   {
    tcc_close();
    return -ERC_READ_TOUT;
   }
  }
  
  if((tcc_state==TCC_STATE_IDDLE)||(tcc_sock==INVALID_SOCKET)) return 0; //normal return TCC_STATE_IDDLE


  
 //============================================================================== 
  //check for connect to remote TCP
  if(tcc_state==TCC_STATE_WAIT_TCP)
  {
   if(!send(tcc_sock, (char*)&len, 0, MSG_NOSIGNAL))
   {
     tcc_job=1;
	
	//check there are data for sending
     if(!tcc_outlen) 
	 {
	  tcc_close();
	  return -ERC_READ_LEN_WTCP;
	 }
	 
	 //send data to server
	 i=send(tcc_sock, (char*)tcc_buf, tcc_outlen, MSG_NOSIGNAL); //send connectin event
     //check data were sended success
	 if(i!=tcc_outlen) 
     {
      tcc_close();
      return -ERC_READ_SEND_WTCP;
     }
	
	//set state for wait answer
	tcc_outlen=0; //data was sended
	tcc_state=TCC_STATE_WAIT_ANS; //set state of receive answer
	tcc_ptr=0; //clear receiving buffer
        tcc_req=TCC_HDR_LEN; //set length of header for receive
	return CLI_READ_CON_TCP + CLI_WARN; //notification of connect TCP
   }
   return 0; //normal return in TCC_STATE_WAIT_TCP
  }
  
 //==============================================================================   
  //check to connect to Tor SOCK5 interface
  if(tcc_state==TCC_STATE_WAIT_TOR)
  {
   
   if(!send(tcc_sock, (char*)&len, 0, MSG_NOSIGNAL))
   {
    
	tcc_job=1;
	
	if(!tcc_torlen) 
	{
	  tcc_close();
	  return -ERC_READ_TLEN;
	}

	i=send(tcc_sock, (const char*)tcc_torout, 3, MSG_NOSIGNAL); //Client hello: 05 01 00

	if(i!=3) 
    {
      tcc_close();
      return -ERC_READ_SEND_TH;
    }
	
	tcc_state=TCC_STATE_WAIT_SOC;
    tcc_timeout=tcc_timenow + TCC_TORTOUT;
     return CLI_READ_CON_TOR + CLI_WARN;  //nor,al connect to tor
   }
   return 0;  //normal return waiting connect to Tor
  }
  
 //============================================================================== 

  //after connected to Tor perform to SOCK5 connecting
  if(tcc_state==TCC_STATE_WAIT_SOC)
  {
   len=recv(tcc_sock, (char*)tcc_torin, sizeof(tcc_torin), 0);
   if(len<0) return 0; //normal return wait soc
   
   tcc_job=1;
   
   
   if(!len)
   {
    tcc_close();
    return -ERC_READ_TCLOSEH;
   }
   
   if( (len>9) && (tcc_torin[0]==5) && (tcc_torin[1]==0) )
   {
     //SOCK5 protocol:  result 05 00 00 01 AA AA AA AA PH PL
    //if(TR_DBG) printf("wait_connect: recv len=%d\r\n", len);
   
    //--------------------------------------------------------------------------
  
	 //check there are data for sending
      if(!tcc_outlen) 
	  {
	   tcc_close();
	   return -ERC_READ_LEN_WTOR;
	  }
	 
	  //send data to server
	  i=send(tcc_sock, (char*)tcc_buf, tcc_outlen, MSG_NOSIGNAL); //send connectin event
      //check data were sended success
	  if(i!=tcc_outlen) 
      {
       tcc_close();
       return -ERC_READ_TCLOSED;
      }
	
	  //set state for wait answer
	  tcc_outlen=0; //data was sended
	  tcc_state=TCC_STATE_WAIT_ANS; //set state of receive answer
      tcc_ptr=0; //clear receiving buffer
      tcc_req=TCC_HDR_LEN; //set length of header for receive  
      return CLI_READ_SEND_TD + CLI_WARN;  //normal send data to server over tor
    }
//--------------------------------------------------------------------------
    //SOCK5: answer to Hello: 05 00
    else if( (len<10) && (tcc_torin[0]==5) && (tcc_torin[1]==0) ) //check for SOCK5 ACK
    {
	 if(!tcc_torlen) 
	 {
	  tcc_close();
	  return -ERC_READ_TCLOSEA;
	 } 
	 i=send(tcc_sock, (const char*)tcc_torout, tcc_torlen, MSG_NOSIGNAL); //send sock5 HS-request to Tor
	 if(i!=tcc_torlen)
     {
      tcc_close();
      return -ERC_READ_WTLEN;
     }
     return CLI_READ_SEND_TA + CLI_WARN; //normal send sock5 address to tor
    }
//--------------------------------------------------------------------------	
	else //somthing wrong
	{
	 tcc_close();
         return -ERC_READ_ANS_WTOR;
	}
//--------------------------------------------------------------------------
   }
  

   //============================================================================== 
  if(tcc_state==TCC_STATE_WAIT_ANS)
  { 
    len=recv(tcc_sock, (char*)tcc_buf+tcc_ptr, tcc_req, 0);  //try read to buf
    if(len<0) return 0;	//<0 break  //normal wait server answ
	
	tcc_job=1;
	
    if((!len)||(len>tcc_req)) //0 close
    {	
	 tcc_close();
	 return -ERC_READ_ANS_LEN;
    }


	//req-=len, ptr+=len
    tcc_ptr+=len;
    tcc_req-=len;		
	//req!=0  - break
    if(tcc_req) return 0;   //normal wait whole packet
		//check ptr==4
    if(tcc_ptr==TCC_HDR_LEN)
    {	
          //get pktlen
		  len=mtos(tcc_buf);
		  //check pktlen
		  if((len<=TCC_HDR_LEN)||(len>=TCC_MAXLEN))
		  {
		   tcc_close();
	           return -ERC_READ_ANS_PKT;
		  }
		  //set req=pktlen-4
		  tcc_req=len-TCC_HDR_LEN;
    }
    else //(ptr>4)
    {
      //memcpy data, ret=ptr
	  memcpy(pkt, tcc_buf, tcc_ptr);
	  ret=tcc_ptr;
	  tcc_close();
	  return ret;
    }	      


  
  }
	

	return 0;

	
 } //end of read funct
 