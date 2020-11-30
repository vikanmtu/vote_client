 #define TCC_MAXLEN 256 //maximal length of packet
  #define TCC_DEFPORT 6543  //default server's TCP port
  #define TCC_TCPTOUT 5     //in sec
  #define TCC_TORTOUT 15     //in sec
  #define TCC_HDR_LEN 4  //bytes in packet's header
  #define TCC_SLEEP 1  //sleep time for tcp task in iddle in ms
  #define TCC_TIMECNT 200  //200 ms

  
  
  //socket states
#define TCC_STATE_IDDLE    0  //inactive (not exist)
#define TCC_STATE_WAIT_TCP 1 //after creating, wait connect to TCP
#define TCC_STATE_WAIT_TOR 2 //after creating, wait connect to Tor
#define TCC_STATE_WAIT_SOC 3 //after was connected to Tor, wait socks5 hello[<10] or ack[>10]
#define TCC_STATE_WAIT_ANS 4 //after send, wait answer

  

#ifdef _WIN32

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <basetsd.h>
#include <stdint.h>
#include <winsock2.h>
#include <windows.h>
#include <time.h>

#define ioctl ioctlsocket
#define close closesocket
#define EWOULDBLOCK WSAEWOULDBLOCK //no data for assync polling
#define ENOTCONN WSAENOTCONN //wait for connection for assinc polling
#define ECONNRESET WSAECONNRESET //no remote udp interface in local network


#else //linux

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include <stdint.h>
#include <stdarg.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>

#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <fcntl.h>
//#include <ifaddrs.h>

#endif


//some socket definitions
#ifndef INVALID_SOCKET
 #define INVALID_SOCKET -1
#endif

#ifndef SOCKET_ERROR
 #define SOCKET_ERROR -1
#endif

#ifndef INADDR_LOCAL
 #define INADDR_LOCAL 0x0100007F
#endif

#ifndef socklen_t
 #define socklen_t int
#endif

#ifndef MSG_NOSIGNAL
 #define MSG_NOSIGNAL 0
#endif


 void tcc_close(void);
 short tcc_init(void);
 void tcc_setsrv(char* server, unsigned short torport);
 short tcc_send(unsigned char* pkt);
 short tcc_read(unsigned char* pkt);
 
