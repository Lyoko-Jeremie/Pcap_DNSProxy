// This code is part of Pcap_DNSProxy
// A local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2015 Chengr28
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either
// version 2 of the License, or (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.


//////////////////////////////////////////////////
// Operating system
// 
/* This code is from Qt source, which is in qglobal.h header file.
// See https://www.qt.io/developers

	The operating system, must be one of: (PLATFORM_x)

	MACX       - Mac OS X
	MAC9       - Mac OS 9
	DARWIN     - Darwin OS (Without Mac OS X)
	MSDOS      - MS-DOS and Windows
	OS2        - OS/2
	OS2EMX     - XFree86 on OS/2 (not PM)
	WIN32      - Win32 (Windows 95/98/ME and Windows NT/2000/XP or newer versions)
	CYGWIN     - Cygwin
	SOLARIS    - Sun Solaris
	HPUX       - HP-UX
	ULTRIX     - DEC Ultrix
	LINUX      - Linux
	FREEBSD    - FreeBSD
	NETBSD     - NetBSD
	OPENBSD    - OpenBSD
	BSDI       - BSD/OS
	IRIX       - SGI Irix
	OSF        - HP Tru64 UNIX
	SCO        - SCO OpenServer 5
	UNIXWARE   - UnixWare 7, Open UNIX 8
	AIX        - AIX
	HURD       - GNU Hurd
	DGUX       - DG/UX
	RELIANT    - Reliant UNIX
	DYNIX      - DYNIX/ptx
	QNX        - QNX
	QNX6       - QNX RTP 6.1
	LYNX       - LynxOS
	BSD4       - Any BSD 4.4 system
	UNIX       - Any UNIX BSD/SYSV system
*/

#if defined(__DARWIN_X11__)
#  define PLATFORM_DARWIN
#elif defined(__APPLE__) && (defined(__GNUC__) || defined(__xlC__))
#  define PLATFORM_MACX
#elif defined(__MACOSX__)
#  define PLATFORM_MACX
#elif defined(macintosh)
#  define PLATFORM_MAC9
#elif defined(__CYGWIN__)
#  define PLATFORM_CYGWIN
#elif defined(MSDOS) || defined(_MSDOS)
#  define PLATFORM_MSDOS
#elif defined(__OS2__)
#  if defined(__EMX__)
#    define PLATFORM_OS2EMX
#  else
#    define PLATFORM_OS2
#  endif
#elif !defined(SAG_COM) && (defined(WIN64) || defined(_WIN64) || defined(__WIN64__))
#  define PLATFORM_WIN32
#  define PLATFORM_WIN64
#elif !defined(SAG_COM) && (defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__))
#  define PLATFORM_WIN32
#elif defined(__MWERKS__) && defined(__INTEL__)
#  define PLATFORM_WIN32
#elif defined(__sun) || defined(sun)
#  define PLATFORM_SOLARIS
#elif defined(hpux) || defined(__hpux)
#  define PLATFORM_HPUX
#elif defined(__ultrix) || defined(ultrix)
#  define PLATFORM_ULTRIX
#elif defined(sinix)
#  define PLATFORM_RELIANT
#elif defined(__linux__) || defined(__linux)
#  define PLATFORM_LINUX
#elif defined(__FreeBSD__) || defined(__DragonFly__)
#  define PLATFORM_FREEBSD
#  define PLATFORM_BSD4
#elif defined(__NetBSD__)
#  define PLATFORM_NETBSD
#  define PLATFORM_BSD4
#elif defined(__OpenBSD__)
#  define PLATFORM_OPENBSD
#  define PLATFORM_BSD4
#elif defined(__bsdi__)
#  define PLATFORM_BSDI
#  define PLATFORM_BSD4
#elif defined(__sgi)
#  define PLATFORM_IRIX
#elif defined(__osf__)
#  define PLATFORM_OSF
#elif defined(_AIX)
#  define PLATFORM_AIX
#elif defined(__Lynx__)
#  define PLATFORM_LYNX
#elif defined(__GNU_HURD__)
#  define PLATFORM_HURD
#elif defined(__DGUX__)
#  define PLATFORM_DGUX
#elif defined(__QNXNTO__)
#  define PLATFORM_QNX6
#elif defined(__QNX__)
#  define PLATFORM_QNX
#elif defined(_SEQUENT_)
#  define PLATFORM_DYNIX
#elif defined(_SCO_DS)                   /* SCO OpenServer 5 + GCC */
#  define PLATFORM_SCO
#elif defined(__USLC__)                  /* all SCO platforms + UDK or OUDK */
#  define PLATFORM_UNIXWARE
#  define PLATFORM_UNIXWARE7
#elif defined(__svr4__) && defined(i386) /* Open UNIX 8 + GCC */
#  define PLATFORM_UNIXWARE
#  define PLATFORM_UNIXWARE7
#elif defined(__MAcDEPEND__)
#else
#  error "Qt has not been ported to this OS - talk to qt-bugs@trolltech.com"
#endif

//System series defines
#if defined(PLATFORM_WIN32) || defined(PLATFORM_WIN64)
#  define PLATFORM_WIN
#endif
#if defined(PLATFORM_MAC9) || defined(PLATFORM_MACX)
#  define PLATFORM_MAC
#endif
#if defined(PLATFORM_MAC9) || defined(PLATFORM_MSDOS) || defined(PLATFORM_OS2) || defined(PLATFORM_WIN)
#  undef PLATFORM_UNIX
#elif !defined(PLATFORM_UNIX)
#  define PLATFORM_UNIX
#endif
/* XCode support
#if defined(PLATFORM_MACX)
#  ifdef MAC_OS_X_VERSION_MIN_REQUIRED
#    undef MAC_OS_X_VERSION_MIN_REQUIRED
#  endif
#  define MAC_OS_X_VERSION_MIN_REQUIRED MAC_OS_X_VERSION_10_2
#  include <AvailabilityMacros.h>
#  if !defined(MAC_OS_X_VERSION_10_3)
#     define MAC_OS_X_VERSION_10_3 MAC_OS_X_VERSION_10_2 + 1
#  endif
#  if !defined(MAC_OS_X_VERSION_10_4)
#       define MAC_OS_X_VERSION_10_4 MAC_OS_X_VERSION_10_3 + 1
#  endif
#  if (MAC_OS_X_VERSION_MAX_ALLOWED > MAC_OS_X_VERSION_10_4)
#    error "This version of Mac OS X is unsupported"
#  endif
#endif
*/


//////////////////////////////////////////////////
// Base header
// 
//Linux and Mac OS X compatible(Part 1)
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define _FILE_OFFSET_BITS   64     //File offset data type size(64 bits).
#endif

//C Standard Library and C++ Standard Template Library/STL headers
//#include <cstdlib>                 //C Standard Library
//#include <cstdio>                  //File Input/Output support
//#include <ctime>                   //Date and Time support
//#include <string>                  //String support
//#include <vector>                  //Vector support
#include <deque>                   //Double-ended queue support
#include <set>                     //Set support
#include <map>                     //Map support
#include <memory>                  //Manage dynamic memory support
#include <regex>                   //Regular expression support
#include <thread>                  //Thread support
#include <mutex>                   //Mutex lock support
#include <random>                  //Random-number generator support
//#include <functional>              //Function object support
//#include <algorithm>               //Algorithm support

#if defined(PLATFORM_WIN)
//LibSodium header
	#define ENABLE_LIBSODIUM       //LibSodium is always enable on Windows.
	#if defined(ENABLE_LIBSODIUM)
		#include "..\\LibSodium\\sodium.h"
	#endif

//WinPcap header
	#define ENABLE_PCAP           //WinPcap is always enable on Windows.
	#if defined(ENABLE_PCAP)
		#include "WinPcap\\pcap.h"
	#endif

//Windows API headers
//	#include <tchar.h>                 //Unicode(UTF-8/UTF-16)/Wide-Character Support
	#include <winsock2.h>              //WinSock 2.0+(MUST be including before windows.h)
//	#include <winsvc.h>                //Service Control Manager
	#include <iphlpapi.h>              //IP Stack for MIB-II and related functionality
	#include <ws2tcpip.h>              //WinSock 2.0+ Extension for TCP/IP protocols
//	#include <mstcpip.h>               //Microsoft-specific extensions to the core Winsock definitions.
//	#include <windns.h>                //Windows DNS definitions and DNS API
	#include <sddl.h>                  //Support and conversions routines necessary for SDDL
//	#include <windows.h>               //Master include file
/* Minimum supported system of Windows Version Helpers is Windows Vista.
	#if defined(PLATFORM_WIN64)
		#include <VersionHelpers.h>        //Version Helper functions
	#endif
*/
//Static libraries
	#pragma comment(lib, "ws2_32.lib")            //Winsock Library, WinSock 2.0+
	#pragma comment(lib, "iphlpapi.lib")          //IP Helper Library, IP Stack for MIB-II and related functionality
	//WinPcap and LibSodium libraries
	#if defined(PLATFORM_WIN64)
		#if defined(ENABLE_PCAP)
			#pragma comment(lib, "WinPcap\\WPCAP_x64.lib")
		#endif
		#if defined(ENABLE_LIBSODIUM)
			#pragma comment(lib, "..\\LibSodium\\LibSodium_x64.lib")
		#endif
	#elif (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		#if defined(ENABLE_PCAP)
			#pragma comment(lib, "WinPcap\\WPCAP_x86.lib")
		#endif
		#if defined(ENABLE_LIBSODIUM)
			#pragma comment(lib, "..\\LibSodium\\LibSodium_x86.lib")
		#endif
	#endif

	#if defined(PLATFORM_WIN)
		#define __LITTLE_ENDIAN            1U                        //Little Endian
//		#define __BIG_ENDIAN               2U                        //Big Endian
		#define __BYTE_ORDER               __LITTLE_ENDIAN           //x86 and x86-64/x64 is Little Endian.

	//Code defines
		#define WINSOCK_VERSION_LOW        2                         //Low byte of Winsock version(2.2)
		#define WINSOCK_VERSION_HIGH       2                         //High byte of Winsock version(2.2)
		#define SIO_UDP_CONNRESET          _WSAIOW(IOC_VENDOR, 12)   //Block connection reset error message from system.
	#endif

//	#pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup") //Hide console.
//Add "WPCAP", "HAVE_REMOTE", "SODIUM_STATIC" and "SODIUM_EXPORT=" to preprocessor options.
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#include <climits>                 //Data limits
	#include <cstring>                 //C-Style strings
	#include <cwchar>                  //Wide characters
	#include <cerrno>                  //Error report
	#include <csignal>                 //Signals

//Portable Operating System Interface/POSIX and Unix system header
	#include <pthread.h>               //Threads
	#include <unistd.h>                //Standard library API
	#include <netdb.h>                 //Network database operations
	#include <ifaddrs.h>               //Getting network interface addresses
	#include <fcntl.h>                 //Manipulate file descriptor
	#include <sys/stat.h>              //Getting information about files attributes
	#include <sys/socket.h>            //Socket
	#include <sys/time.h>              //Date and time
	#include <arpa/inet.h>             //Internet operations

//LibPcap and LibSodium header
	#if defined(PLATFORM_LINUX)
		#if defined(ENABLE_PCAP)
			#include <pcap/pcap.h>
		#endif
		#if defined(ENABLE_LIBSODIUM)
			#include <sodium.h>
		#endif
	#elif defined(PLATFORM_MACX)
		#define ENABLE_PCAP                //LibPcap is always enable on Mac OS X.
		#define ENABLE_LIBSODIUM           //LibSodium is always enable on Mac OS X.
		#include <pcap/pcap.h>
		#include "../LibSodium/sodium.h"
		#pragma comment(lib, "../LibSodium/LibSodium_Mac.a")
	#endif

//Internet Protocol version 4/IPv4 Address(From Microsoft Windows)
	typedef struct _in_addr_windows_
	{
		union {
			union {
				struct {
					uint8_t    s_b1, s_b2, s_b3, s_b4;
				}S_un_b;
				struct {
					uint16_t   s_w1, s_w2;
				}S_un_w;
				uint32_t       S_addr;
			}S_un;
			uint32_t           s_addr;
		};
	}in_addr_Windows;
//	#define s_addr             S_un.S_addr
	#define s_host             S_un.S_un_b.s_b2
	#define s_net              S_un.S_un_b.s_b1
	#define s_imp              S_un.S_un_w.s_w2
	#define s_impno            S_un.S_un_b.s_b4
	#define s_lh               S_un.S_un_b.s_b3

//Internet Protocol version 6/IPv6 Address(From Microsoft Windows)
	typedef struct _in6_addr_windows_
	{
		union {
			union {
				uint8_t        Byte[16U];
				uint16_t       Word[8U];
			}u;
			union {
				uint8_t	       __u6_addr8[16U];
				uint16_t       __u6_addr16[8U];
				uint32_t       __u6_addr32[4U];
			};
		};
	}in6_addr_Windows;
//	#define _S6_un             u
//	#define _S6_u8             Byte
//	#define s6_addr            _S6_un._S6_u8
	#define s6_bytes           u.Byte
	#define s6_words           u.Word

//Internet Protocol version 4/IPv4 Socket Address(From Microsoft Windows)
	typedef struct _sockaddr_in_windows_
	{
		sa_family_t       sin_family;     /* address family: AF_INET */
		in_port_t         sin_port;       /* port in network byte order */
		in_addr_Windows   sin_addr;       /* internet address */
		uint8_t           sin_zero[8U];   /* Zero */
	}sockaddr_in_Windows;

//Internet Protocol version 6/IPv6 Socket Address(From Microsoft Windows)
	typedef struct _sockaddr_in6_windows_ 
	{
		sa_family_t        sin6_family;   /* AF_INET6 */
		in_port_t          sin6_port;     /* port number */
		uint32_t           sin6_flowinfo; /* IPv6 flow information */
		in6_addr_Windows   sin6_addr;     /* IPv6 address */
		uint32_t           sin6_scope_id; /* Scope ID (new in 2.4) */
	}sockaddr_in6_Windows;

//Linux and Mac OS X compatible(Part 2)
	#define RETURN_ERROR             (-1)
	#define SOCKET_ERROR             (-1)
	#define INVALID_SOCKET           (-1)
	#define MAX_PATH                 PATH_MAX
	#define SD_SEND                  SHUT_WR
	#define SD_BOTH                  SHUT_RDWR
	#define WSAETIMEDOUT             ETIMEDOUT
	#define WSAEWOULDBLOCK           EINPROGRESS
	#define WSAEAFNOSUPPORT          EAFNOSUPPORT
	#define in_addr                  in_addr_Windows
	#define in6_addr                 in6_addr_Windows
	#define sockaddr_in              sockaddr_in_Windows
	#define sockaddr_in6             sockaddr_in6_Windows
	#define in6addr_loopback         *(in6_addr *)&in6addr_loopback
	#define in6addr_any              *(in6_addr *)&in6addr_any
	typedef unsigned char            UCHAR;
	typedef unsigned char            *PUCHAR;
	typedef int                      *PINT;
	typedef unsigned int             UINT;
	typedef unsigned short           *PUINT16;
	typedef unsigned long            ULONG, DWORD;
	typedef unsigned long long       ULONGLONG;
	typedef ssize_t                  SSIZE_T;
	typedef int                      SOCKET;
	typedef addrinfo                 ADDRINFOA;
	typedef char                     *PSTR;
	typedef uint8_t                  *PUINT8;
	typedef sockaddr                 *PSOCKADDR;
	typedef sockaddr_in              *PSOCKADDR_IN;
	typedef sockaddr_in6             *PSOCKADDR_IN6;
	typedef addrinfo                 *PADDRINFOA;

//Function defines(Part 1)
	#define __fastcall
	#define strnlen_s                                                    strnlen
	#define strncpy_s(Dst, DstSize, Src, Size)                           strncpy(Dst, Src, Size)
	#define memcpy_s(Dst, DstSize, Src, Size)                            memcpy(Dst, Src, Size)
	#define memmove_s(Dst, DstSize, Src, Size)                           memmove(Dst, Src, Size)
	#define sprintf_s                                                    snprintf
	#define wcsnlen_s                                                    wcsnlen
	#define wcsncpy_s(Dst, DstSize, Src, Size)                           wcsncpy(Dst, Src, Size)
	#define wprintf_s                                                    wprintf
	#define fread_s(Dst, DstSize, ElementSize, Count, File)              fread(Dst, ElementSize, Count, File)
	#define fwprintf_s                                                   fwprintf
	#if defined(PLATFORM_LINUX)
		#define send(Socket, Buffer, Length, Signal)                         send(Socket, Buffer, Length, MSG_NOSIGNAL)
		#define sendto(Socket, Buffer, Length, Signal, SockAddr, AddrLen)    sendto(Socket, Buffer, Length, MSG_NOSIGNAL, SockAddr, AddrLen)
	#endif
	#define GetLastError()                                               errno
	#define closesocket                                                  close
	#define WSAGetLastError()                                            GetLastError()
	#define WSACleanup()
	#define GetCurrentProcessId()                                        pthread_self()
	#define localtime_s(TimeStructure, TimeValue)                        localtime_r(TimeValue, TimeStructure)
#endif


//////////////////////////////////////////////////
// Base defines
// 
#pragma pack(1)                              //Memory alignment: 1 bytes/8 bits
#define KILOBYTE_TIMES         1024U         //1KB = 1024 bytes
#define MEGABYTE_TIMES         1048576U      //1MB = 1048576 bytes
#define GIGABYTE_TIMES         1073741824U   //1GB = 1073741824 bytes
#define CODEPAGE_ANSI          1U            //Microsoft Windows Codepage of ANSI
#define CODEPAGE_UTF_8         65001U        //Microsoft Windows Codepage of UTF-8
#define CODEPAGE_UTF_16_LE     1200U         //Microsoft Windows Codepage of UTF-16 Little Endian/LE
#define CODEPAGE_UTF_16_BE     1201U         //Microsoft Windows Codepage of UTF-16 Big Endian/BE
#define CODEPAGE_UTF_32_LE     12000U        //Microsoft Windows Codepage of UTF-32 Little Endian/LE
#define CODEPAGE_UTF_32_BE     12001U        //Microsoft Windows Codepage of UTF-32 Big Endian/BE


//////////////////////////////////////////////////
// Protocol header structures
// 
/* Ethernet II Frame header in OSI Layer 2(RFC 894, https://tools.ietf.org/html/rfc894)

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Destination Address                      |
|                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                        Source Address                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
/                                                               /
/                             Data                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Ethernet Frame Check Sequence                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define OSI_L2_IPV4         0x0800   //IPv4
#define OSI_L2_IPV6         0x86DD   //IPv6
//#define OSI_L2_PPPD         0x8863   //PPPoE(Discovery Stage)
#define OSI_L2_PPPS         0x8864   //PPPoE(Session Stage)
//#define FCS_TABLE_SIZE      256U     //FCS Table size
typedef struct _eth_hdr_
{
	uint8_t                Dst[6U];
	uint8_t                Src[6U];
	uint16_t               Type;
//	PUCHAR                 Payload;
//	uint32_t               FCS;
}eth_hdr, *peth_hdr;

/* Apple IEEE 1394/FireWire header(RFC 2734 and RFC3146, https://www.ietf.org/rfc/rfc2734 and https://www.ietf.org/rfc/rfc3146)

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Destination Address                      |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Source Address                         |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
/                                                               /
/                             Data                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _ieee_1394_hdr_
{
	uint8_t                Dst[8U];
	uint8_t                Src[8U];
	uint16_t               Type;
}ieee_1394_hdr, *pieee_1394_hdr;

/* Point-to-Point Protocol /PPP header(RFC 2516, https://tools.ietf.org/rfc/rfc2516)

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  Type |     Code      |           SessionID           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Length            |            Protocol           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define PPP_IPV4           0x0021   //IPv4 over PPP
#define PPP_IPV6           0x0057   //IPv6 over PPP
typedef struct _ppp_hdr_
{
	uint8_t                VersionType;
	uint8_t                Code;
	uint16_t               SessionID;
	uint16_t               Length;
	uint16_t               Protocol;
}ppp_hdr, *pppp_hdr;

//Internet Protocol Numbers
//About this list, see http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
//#define IPPROTO_HOPOPTS           0                    //IPv6 Hop-by-Hop Option
//#define IPPROTO_ICMP              1U                   //Internet Control Message
//#define IPPROTO_IGMP              2U                   //Internet Group Management
#if defined(PLATFORM_LINUX)
	#define IPPROTO_GGP               3U                   //Gateway-to-Gateway
	#define IPPROTO_IPV4              4U                   //IPv4 encapsulation
	#define IPPROTO_ST                5U                   //Stream
#endif
//#define IPPROTO_TCP               6U                   //Transmission Control
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define IPPROTO_CBT             7U                     //Core Based Tree
#endif
//#define IPPROTO_EGP               8U                   //Exterior Gateway Protocol
#if defined(PLATFORM_LINUX)
	#define IPPROTO_IGP               9U                   //Any private interior gateway
#endif
#define IPPROTO_BBN_RCC_MON       10U                  //BBN RCC Monitoring
#define IPPROTO_NVP_II            11U                  //Network Voice Protocol
//#define IPPROTO_PUP               12U                  //PUP
#if !defined(PLATFORM_MACX)
	#define IPPROTO_ARGUS             13U                  //ARGUS
	#define IPPROTO_EMCON             14U                  //EMCON
	#define IPPROTO_XNET              15U                  //Cross Net Debugger
	#define IPPROTO_CHAOS             16U                  //Chaos
#endif
//#define IPPROTO_UDP               17U                  //User Datagram
#if !defined(PLATFORM_MACX)
	#define IPPROTO_MUX               18U                  //Multiplexing
#endif
#define IPPROTO_DCN               19U                  //DCN Measurement Subsystems
#if !defined(PLATFORM_MACX)
	#define IPPROTO_HMP               20U                  //Host Monitoring
	#define IPPROTO_PRM               21U                  //Packet Radio Measurement
#endif
//#define IPPROTO_IDP               22U                  //XEROX NS IDP
#define IPPROTO_TRUNK_1           23U                  //Trunk-1
#define IPPROTO_TRUNK_2           24U                  //Trunk-2
#define IPPROTO_LEAF_1            25U                  //Leaf-1
#define IPPROTO_LEAF_2            26U                  //Leaf-2
#if defined(PLATFORM_LINUX)
	#define IPPROTO_RDP               27U                  //Reliable Data Protocol
#endif
#if !defined(PLATFORM_MACX)
	#define IPPROTO_IRTP              28U                  //Internet Reliable Transaction
#endif
#define IPPROTO_ISO_TP4           29U                  //ISO Transport Protocol Class 4
#define IPPROTO_NETBLT            30U                  //Bulk Data Transfer Protocol
#define IPPROTO_MFE               31U                  //MFE Network Services Protocol
#define IPPROTO_MERIT             32U                  //MERIT Internodal Protocol
#if (defined(PLATFORM_WIN) || defined(PLATFORM_MACX))
	#define IPPROTO_DCCP              33U                  //Datagram Congestion Control Protocol
#endif
#if !defined(PLATFORM_MACX)
	#define IPPROTO_3PC               34U                  //Third Party Connect Protocol
	#define IPPROTO_IDPR              35U                  //Inter-Domain Policy Routing Protocol
	#define IPPROTO_XTP               36U                  //XTP
	#define IPPROTO_DDP               37U                  //Datagram Delivery Protocol
#endif
#define IPPROTO_IDPR_CMTP         38U                  //IDPR Control Message Transport Proto
#define IPPROTO_TPPLUS            39U                  //TP++ Transport Protocol
#if !defined(PLATFORM_MACX)
	#define IPPROTO_IL                40U                  //IL Transport Protocol
#endif
//#define IPPROTO_IPv6              41U                  //IPv6 encapsulation
#if !defined(PLATFORM_MACX)
	#define IPPROTO_SDRP              42U                  //Source Demand Routing Protocol
#endif
//#define IPPROTO_ROUTING           43U                  //Route Routing Header for IPv6
//#define IPPROTO_FRAGMENT          44U                  //Frag Fragment Header for IPv6
#if !defined(PLATFORM_MACX)
	#define IPPROTO_IDRP              45U                  //Inter - Domain Routing Protocol
#endif
#if defined(PLATFORM_WIN)
	#define IPPROTO_RSVP              46U                  //Reservation Protocol
	#define IPPROTO_GRE               47U                  //Generic Routing Encapsulation
#endif
#define IPPROTO_DSR               48U                  //Dynamic Source Routing Protocol
#define IPPROTO_BNA               49U                  //BNA
//#define IPPROTO_ESP               50U                  //Encap Security Payload
//#define IPPROTO_AH                51U                  //Authentication Header
#define IPPROTO_NLSP              52U                  //Integrated Net Layer Security TUBA
#if !defined(PLATFORM_MACX)
	#define IPPROTO_SWIPE             53U                  //IP with Encryption
#endif
#define IPPROTO_NARP              54U                  //NBMA Address Resolution Protocol
#define IPPROTO_MOBILE            55U                  //IP Mobility
#define IPPROTO_TLSP              56U                  //Transport Layer Security Protocol using Kryptonet key management
#define IPPROTO_SKIP              57U                  //SKIP
//#define IPPROTO_ICMPV6            58U                  //ICMP for IPv6
//#define IPPROTO_NONE              59U                  //No Next Header for IPv6
//#define IPPROTO_DSTOPTS           6OU                  //Destination Options for IPv6
#define IPPROTO_AHI               61U                  //Any host internal protocol
#if !defined(PLATFORM_MACX)
	#define IPPROTO_CFTP              62U                  //CFTP
#endif
#define IPPROTO_ALN               63U                  //Any local network
#define IPPROTO_SAT               64U                  //EXPAK SATNET and Backroom EXPAK
#if !defined(PLATFORM_MACX)
	#define IPPROTO_KRYPTOLAN         65U                  //Kryptolan
	#define IPPROTO_RVD               66U                  //MIT Remote Virtual Disk Protocol
	#define IPPROTO_IPPC              67U                  //Internet Pluribus Packet Core
#endif
#define IPPROTO_ADF               68U                  //Any distributed file system
#define IPPROTO_SAT_MON           69U                  //SATNET Monitoring
#if !defined(PLATFORM_MACX)
	#define IPPROTO_VISA              70U                  //VISA Protocol
	#define IPPROTO_IPCV              71U                  //Internet Packet Core Utility
	#define IPPROTO_CPNX              72U                  //Computer Protocol Network Executive
	#define IPPROTO_CPHB              73U                  //Computer Protocol Heart Beat
	#define IPPROTO_WSN               74U                  //Wang Span Network
	#define IPPROTO_PVP               75U                  //Packet Video Protocol
#endif
#define IPPROTO_BR                76U                  //SAT - MON Backroom SATNET Monitoring
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#if !defined(PLATFORM_MACX)
		#define IPPROTO_ND                77U                  //SUN ND PROTOCOL - Temporary
	#endif
	#define IPPROTO_ICLFXBM           78U                  //WIDEBAND Monitoring
#endif
#if !defined(PLATFORM_MACX)
	#define IPPROTO_WBEXPAK           79U                  //WIDEBAND EXPAK
#endif
#define IPPROTO_ISO               80U                  //IP ISO Internet Protocol
#if !defined(PLATFORM_MACX)
	#define IPPROTO_VMTP              81U                  //VMTP
	#define IPPROTO_SVMTP             82U                  //SECURE - VMTP
	#define IPPROTO_VINES             83U                  //VINES
	#define IPPROTO_TTP               84U                  //Transaction Transport Protocol
#endif
#define IPPROTO_IPTM              85U                  //Internet Protocol Traffic ManageR
#define IPPROTO_NSFNET            86U                  //NSFNET - IGP
#if !defined(PLATFORM_MACX)
	#define IPPROTO_DGP               87U                  //Dissimilar Gateway Protocol
	#define IPPROTO_TCF               88U                  //TCF
#endif
#define IPPROTO_EIGRP             89U                  //EIGRP
#define IPPROTO_SPRITE            90U                  //RPC Sprite RPC Protocol
#if !defined(PLATFORM_MACX)
	#define IPPROTO_LARP              91U                  //Locus Address Resolution Protocol
#endif
#if defined(PLATFORM_WIN)
	#define IPPROTO_MTP               92U                  //Multicast Transport Protocol
#endif
#if !defined(PLATFORM_MACX)
	#define IPPROTO_AX25              93U                  //AX.25 Frames
#endif
#if defined(PLATFORM_WIN)
	#define IPPROTO_IPIP              94U                  //IP - within - IP Encapsulation Protocol
#endif
#if !defined(PLATFORM_MACX)
	#define IPPROTO_MICP              95U                  //Mobile Internetworking Control Pro.
#endif
#define IPPROTO_SCC               96U                  //Semaphore Communications Sec.Pro.
#if !defined(PLATFORM_MACX)
	#define IPPROTO_ETHERIP           97U                  //Ethernet - within - IP Encapsulation
#endif
#if defined(PLATFORM_WIN)
	#define IPPROTO_ENCAP             98U                  //Encapsulation Header
#endif
#if !defined(PLATFORM_MACX)
	#define IPPROTO_APES              100U                 //Any private encryption scheme
	#define IPPROTO_GMTP              101U                 //GMTP
#endif
#define IPPROTO_IFMP              102U                 //Ipsilon Flow Management Protocol
#define IPPROTO_PNNI              103U                 //PNNI over IP
//#define IPPROTO_PIM               104U                 //Protocol Independent Multicast
#define IPPROTO_ARIS              105U                 //ARIS
#define IPPROTO_SCPS              106U                 //SCPS
#define IPPROTO_QNX               107U                 //QNX
#define IPPROTO_AN                108U                 //Active Networks
#if !defined(PLATFORM_MACX)
	#define IPPROTO_IPCOMP            109U                 //IP Payload Compression Protocol
#endif
#define IPPROTO_SNP               110U                 //Sitara Networks Protocol
#define IPPROTO_COMPAQ            111U                 //Peer Compaq Peer Protocol
#define IPPROTO_IPX               112U                 //IP IPX in IP
#if defined(PLATFORM_LINUX)
	#define IPPROTO_PGM               113U                 //PGM Reliable Transport Protocol
#endif
#define IPPROTO_0HOP              114U                 //Any 0-hop protocol
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define IPPROTO_L2TP              115U                 //Layer Two Tunneling Protocol
#endif
#define IPPROTO_DDX               116U                 //D - II Data Exchange(DDX)
#define IPPROTO_IATP              117U                 //Interactive Agent Transfer Protocol
#define IPPROTO_STP               118U                 //Schedule Transfer Protocol
#define IPPROTO_SRP               119U                 //SRP SpectraLink Radio Protocol
#define IPPROTO_UTI               120U                 //UTI UTI
#define IPPROTO_SMP               121U                 //SMP Simple Message Protocol
#define IPPROTO_SM                122U                 //SM Simple Multicast Protocol
#define IPPROTO_PTP               123U                 //PTP Performance Transparency Protocol
#define IPPROTO_ISIS              124U                 //ISIS over IPv4
#define IPPROTO_FIRE              125U                 //FIRE
#define IPPROTO_CRTP              126U                 //Combat Radio Transport Protocol
#define IPPROTO_CRUDP             127U                 //Combat Radio User Datagram
#define IPPROTO_SSCOPMCE          128U                 //SSCOPMCE
#define IPPROTO_IPLT              129U                 //IPLT
#define IPPROTO_SPS               130U                 //Secure Packet Shield
#define IPPROTO_PIPE              131U                 //Private IP Encapsulation within IP
//#define IPPROTO_SCTP              132U                 //Stream Control Transmission Protocol
#define IPPROTO_FC                133U                 //Fibre Channel
#define IPPROTO_RSVP_E2E          134U                 //RSVP-E2E-IGNORE
#define IPPROTO_MOBILITY          135U                 //Mobility Header
#if (defined(PLATFORM_WIN) || defined(PLATFORM_MACX))
	#define IPPROTO_UDPLITE           136U                 //UDP Lite
#endif
#define IPPROTO_MPLS              137U                 //MPLS in IP
#define IPPROTO_MANET             138U                 //MANET Protocols
#define IPPROTO_HIP               139U                 //Host Identity Protocol
#define IPPROTO_SHIM6             140U                 //Shim6 Protocol
#define IPPROTO_WESP              141U                 //Wrapped Encapsulating Security Payload
#define IPPROTO_ROHC              142U                 //Robust Header Compression
#define IPPROTO_TEST_1            253U                 //Use for experimentation and testing
#define IPPROTO_TEST_2            254U                 //Use for experimentation and testing
//#define IPPROTO_RESERVED          255U                 //Reserved

/* Internet Protocol version 4/IPv4 header(RFC 791, https://www.ietf.org/rfc/rfc791)

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |   DSCP    |ECN|         Total Length          |  IHL/Internet Header Length, DSCP/Differentiated Services Code Point and ECN/Explicit Congestion Notification
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Identification         |Z|D|M|     Fragment Offset     |  Flags(Z/Zero/Reserved bit, D/DF/More Fragments bit and M/MF/More Fragments bit)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Time To Live  |   Protocol    |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Source Address                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Destination Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Options                            /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define IPV4_STANDARD_IHL            0x05   //Standard IPv4 header length(0x05/20 bytes)
#define IPv4_IHL_BYTES_TIMES         4U     //IHL is number of 32-bit words(4 bytes).
typedef struct _ipv4_hdr_
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t                IHL:4;
	uint8_t                Version:4;
#else //BIG_ENDIAN
	uint8_t                Version:4;
	uint8_t                IHL:4;
#endif
	union {
		uint8_t            TOS;           //Type of service, but RFC 2474 redefine it to DSCP/DiffServ and ECN/Explicit Congestion Notification.
		struct {
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t        ECN:2;
			uint8_t        DSCP:6;
		#else //BIG_ENDIAN
			uint8_t        DSCP:6;
			uint8_t        ECN:2;
		#endif
		}TOSBits;
	};
	uint16_t               Length;
	uint16_t               ID;
	union {
		uint16_t           Flags;
		struct {
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t        FO_First:5;
			uint8_t        MF:1;
			uint8_t        DF:1;
			uint8_t        Zero:1;
			uint8_t        FO_Second;
		#else //BIG_ENDIAN
			uint8_t        Zero:1;
			uint8_t        DF:1;
			uint8_t        MF:1;
			uint8_t        FO_First:5;
			uint8_t        FO_Second;
		#endif
		}FlagsBits;
	};
	uint8_t                TTL;
	uint8_t                Protocol;
	uint16_t               Checksum;
	in_addr                Source;
	in_addr                Destination;
}ipv4_hdr, *pipv4_hdr;

/* Internet Protocol version 6/IPv6 header(RFC 2460, https://tools.ietf.org/html/rfc2460)

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|    DSF    |T|E|              Flow Label               |  DSF/Differentiated Services Field, E/ECT/Explicit Congestion Notification - Capable Transport, T/ECN-CE/Explicit Congestion Notification - Congestion Encountered
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         \Traffic Class/
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Payload Length         |  Next Header  |   Hop Limit   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                        Source Address                         |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      Destination Address                      |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _ipv6_hdr_
{
	union {
		uint32_t               VerTcFlow;
		struct {
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			union {
				uint8_t        TrafficClass_First:4;
				uint8_t        DSF_First:4;
			};
			uint8_t            Version:4;
			uint8_t            FlowLabel_First:4;
			union {
				uint8_t        TrafficClass_Second:4;
				struct {
					uint8_t    DSF_Second:2;
					uint8_t    ECT:1;
					uint8_t    ECN_CE:1;
				}TrafficClassBits_Second;
			};
		#else //BIG_ENDIAN
			uint8_t            Version:4;
			union {
				uint8_t        TrafficClass_First:4;
				uint8_t        DSF_First:4;
			};
			union {
				uint8_t        TrafficClass_Second:4;
				struct {
					uint8_t    DSF_Second:2;
					uint8_t    ECT:1;
					uint8_t    ECN_CE:1;
				}TrafficClassBits_Second;
			};
			uint8_t            FlowLabel_First:4;
		#endif
			uint16_t           FlowLabel_Second;
		}VerTcFlowBits;
	};
	uint16_t                   PayloadLength;
	uint8_t                    NextHeader;
	uint8_t                    HopLimit;
	in6_addr                   Source;
	in6_addr                   Destination;
}ipv6_hdr, *pipv6_hdr;

/* Internet Control Message Protocol/ICMP header(RFC 792, https://tools.ietf.org/html/rfc792)

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Identification         |           Sequence            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      TimeStamp(Optional)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define ICMP_TYPE_ECHO      0
#define ICMP_TYPE_REQUEST   8U
#define ICMP_CODE_ECHO      0
#define ICMP_CODE_REQUEST   0
typedef struct _icmp_hdr_
{
	uint8_t                Type;
	uint8_t                Code;
	uint16_t               Checksum;
	uint16_t               ID;
	uint16_t               Sequence;
//ICMP Timestamp option is defalut ON on Linux and Mac OS X.
#if defined(PLATFORM_LINUX)
	uint64_t               Timestamp;
	uint64_t               Nonce;
#elif defined(PLATFORM_MACX)
	uint64_t               Timestamp;
#endif
}icmp_hdr, *picmp_hdr;

/* Internet Control Message Protocol version 6/ICMPv6 header(RFC 4443, https://tools.ietf.org/html/rfc4443)

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Identification         |           Sequence            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Nonce(Optional)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define ICMPV6_TYPE_REQUEST    128U
#define ICMPV6_TYPE_REPLY      129U
#define ICMPV6_CODE_REQUEST    0
#define ICMPV6_CODE_REPLY      0
typedef struct _icmpv6_hdr_
{
	uint8_t                Type;
	uint8_t                Code;
	uint16_t               Checksum;
	uint16_t               ID;
	uint16_t               Sequence;
//ICMPv6 Timestamp option is defalut ON on Linux and Mac OS X.
#if defined(PLATFORM_LINUX)
	uint64_t               Timestamp;
	uint64_t               Nonce;
#elif defined(PLATFORM_MACX)
	uint64_t               Timestamp;
#endif
}icmpv6_hdr, *picmpv6_hdr;

/* Transmission Control Protocol/TCP header
RFC 675: https://tools.ietf.org/html/rfc675
RFC 793: https://tools.ietf.org/html/rfc793
RFC 1122: https://tools.ietf.org/html/rfc1122
RFC 2581: https://tools.ietf.org/html/rfc2581
RFC 5681: https://tools.ietf.org/html/rfc5681

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |        Destination Port       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Acknowledgment Number                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Data  |  R  |N|C|E|U|A|P|R|S|F|                               |  RES/Reserved
|Offset |  E  |S|W|C|R|C|S|S|Y|I|          Window Size          |  NS/ECN-nonce concealment protection, CWR/Congestion Window Reduced, ECE/ECN-Echo indicates, URG/Urgent pointer, ACK/Acknowledgment
|       |  S  | |R|E|G|K|H|T|N|N|                               |  PSH/Push function, RST/Reset the connection, SYN/Synchronize sequence numbers, FIN/No more data from sender
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |        Urgent Pointer         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                           Options                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define TCP_STANDARDHL       5U      //Standard TCP header length
#define TCP_SYN_ACK_STATUS   0x012   //SYN bit and ACK bit was set.
#define TCP_RST_STATUS       0x004   //RST bit was set.

//Port definitions(1 - 1024, well-known ports)
//About this list, see https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define IPPORT_TCPMUX               1U
#endif
#if defined(PLATFORM_MACX)
	#define IPPORT_ECHO                 7U
	#define IPPORT_DISCARD              9U
	#define IPPORT_SYSTAT               11U
	#define IPPORT_DAYTIME              13U
	#define IPPORT_NETSTAT              15U
#endif
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define IPPORT_QOTD                 17U
	#define IPPORT_MSP                  18U
	#define IPPORT_CHARGEN              19U
	#define IPPORT_FTP_DATA             20U
#endif
#if defined(PLATFORM_MACX)
	#define IPPORT_FTP                  21U
#endif
#define IPPORT_SSH                  22U
#if defined(PLATFORM_MACX)
	#define IPPORT_TELNET               23U
	#define IPPORT_SMTP                 25U
	#define IPPORT_TIMESERVER           37U
#endif
#define IPPORT_RAP                  38U
#define IPPORT_RLP                  39U
#if defined(PLATFORM_MACX)
	#define IPPORT_NAMESERVER           42U
	#define IPPORT_WHOIS                43U
#endif
#define IPPORT_TACACS               49U
#define IPPORT_XNSAUTH              56U
#if defined(PLATFORM_MACX)
	#define IPPORT_MTP                  57U
#endif
#define IPPORT_BOOTPS               67U
#define IPPORT_BOOTPC               68U
#if defined(PLATFORM_MACX)
	#define IPPORT_TFTP                 69U
	#define IPPORT_RJE                  77U
	#define IPPORT_FINGER               79U
#endif
#define IPPORT_HTTP                 80U
#define IPPORT_HTTPBACKUP           81U
#if defined(PLATFORM_MACX)
	#define IPPORT_TTYLINK              87U
	#define IPPORT_SUPDUP               95U
#endif
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define IPPORT_POP3                 110U
#endif
#define IPPORT_SUNRPC               111U
#define IPPORT_SQL                  118U
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define IPPORT_NTP                  123U
	#define IPPORT_EPMAP                135U
	#define IPPORT_NETBIOS_NS           137U
	#define IPPORT_NETBIOS_DGM          138U
	#define IPPORT_NETBIOS_SSN          139U
	#define IPPORT_IMAP                 143U
#endif
#define IPPORT_BFTP                 152U
#define IPPORT_SGMP                 153U
#define IPPORT_SQLSRV               156U
#define IPPORT_DMSP                 158U
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define IPPORT_SNMP                 161U
	#define IPPORT_SNMP_TRAP            162U
#endif
#define IPPORT_ATRTMP               201U
#define IPPORT_ATHBP                202U
#define IPPORT_QMTP                 209U
#define IPPORT_IPX                  213U
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define IPPORT_IMAP3                220U
#endif
#define IPPORT_BGMP                 264U
#define IPPORT_TSP                  318U
#define IPPORT_IMMP                 323U
#define IPPORT_ODMR                 366U
#define IPPORT_RPC2PORTMAP          369U
#define IPPORT_CLEARCASE            371U
#define IPPORT_HPALARMMGR           383U
#define IPPORT_ARNS                 384U
#define IPPORT_AURP                 387U
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define IPPORT_LDAP                 389U
#endif
#define IPPORT_UPS                  401U
#define IPPORT_SLP                  427U
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define IPPORT_HTTPS                443U
#endif
#define IPPORT_SNPP                 444U
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define IPPORT_MICROSOFT_DS         445U
#endif
#define IPPORT_KPASSWD              464U
#define IPPORT_TCPNETHASPSRV        475U
#define IPPORT_RETROSPECT           497U
#define IPPORT_ISAKMP               500U
#if defined(PLATFORM_MACX)
	#define IPPORT_BIFFUDP              512U
	#define IPPORT_WHOSERVER			513U
#endif
#define IPPORT_SYSLOG               514U
#if defined(PLATFORM_MACX)
	#define IPPORT_ROUTESERVER          520U
#endif
#define IPPORT_NCP                  524U
#define IPPORT_COURIER              530U
#define IPPORT_COMMERCE             542U
#define IPPORT_RTSP                 554U
#define IPPORT_NNTP                 563U
#define IPPORT_HTTPRPCEPMAP         593U
#define IPPORT_IPP                  631U
#define IPPORT_LDAPS                636U
#define IPPORT_MSDP                 639U
#define IPPORT_AODV                 654U
#define IPPORT_FTPSDATA             989U
#define IPPORT_FTPS                 990U
#define IPPORT_NAS                  991U
#define IPPORT_TELNETS              992U
typedef struct _tcp_hdr_
{
	uint16_t               SrcPort;
	uint16_t               DstPort;
	uint32_t               Sequence;
	uint32_t               Acknowledge;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t                Nonce_Bits:1;
	uint8_t			       Reserved_Bits:3;
	uint8_t                HeaderLength:4;
	union {
		struct {
			uint8_t        Flags:6;
			uint8_t        ECNEcho:1;
			uint8_t        CWR:1;
		}StatusFlags;
		struct {
			uint8_t        FIN:1;
			uint8_t        SYN:1;
			uint8_t        RST:1;
			uint8_t        PSH:1;
			uint8_t        ACK:1;
			uint8_t        URG:1;
			uint8_t        ECNEcho:1;
			uint8_t        CWR:1;
#else //BIG_ENDIAN
	uint8_t                HeaderLength:4;
	uint8_t			       Reserved_Bits:3;
	uint8_t                Nonce_Bits:1;
	union {
		struct {
			uint8_t        CWR:1;
			uint8_t        ECNEcho:1;
			uint8_t        Flags:6;
		}StatusFlags;
		struct {
			uint8_t        CWR:1;
			uint8_t        ECNEcho:1;
			uint8_t        URG:1;
			uint8_t        ACK:1;
			uint8_t        PSH:1;
			uint8_t        RST:1;
			uint8_t        SYN:1;
			uint8_t        FIN:1;
#endif
		}FlagsBits;
	};
	uint16_t               Windows;
	uint16_t               Checksum;
	uint16_t               UrgentPointer;
}tcp_hdr, *ptcp_hdr;

/* User Datagram Protocol/UDP header(RFC 768, https://tools.ietf.org/html/rfc768)

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define IPPORT_TEREDO      3544U        //Teredo tunneling port
typedef struct _udp_hdr_
{
	uint16_t               SrcPort;
	uint16_t               DstPort;
	uint16_t               Length;
	uint16_t               Checksum;
}udp_hdr, *pudp_hdr;

/* Transmission Control Protocol/TCP and User Datagram Protocol/UDP Pseudo header with IPv4
RFC 675: https://tools.ietf.org/html/rfc675
RFC 768: https://tools.ietf.org/html/rfc768
RFC 793: https://tools.ietf.org/html/rfc793
RFC 1122: https://tools.ietf.org/html/rfc1122
RFC 2581: https://tools.ietf.org/html/rfc2581
RFC 5681: https://tools.ietf.org/html/rfc5681

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Source Address                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Destination Address                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Zeros     |   Protocol    |          Data Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _ipv4_psd_hdr_
{
	in_addr               Source;
	in_addr               Destination;
	uint8_t               Zero;
	uint8_t               Protocol;
	uint16_t              Length;
}ipv4_psd_hdr, *pipv4_psd_hdr;

/* Internet Control Message Protocol version 6/ICMPv6, Transmission Control Protocol/TCP and User Datagram Protocol/UDP Pseudo header with IPv4
RFC 675: https://tools.ietf.org/html/rfc675
RFC 768: https://tools.ietf.org/html/rfc768
RFC 793: https://tools.ietf.org/html/rfc793
RFC 1122: https://tools.ietf.org/html/rfc1122
RFC 2581: https://tools.ietf.org/html/rfc2581
RFC 4443: https://tools.ietf.org/html/rfc4443
RFC 5681: https://tools.ietf.org/html/rfc5681

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                        Source Address                         |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                      Destination Address                      |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Data Length                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Zeros                     |  Next Header  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _ipv6_psd_hdr_
{
	in6_addr              Source;
	in6_addr              Destination;
	uint32_t              Length;
	uint8_t               Zero[3U];
	uint8_t               NextHeader;
}ipv6_psd_hdr, *pipv6_psd_hdr;

//Domain Name System/DNS Part
/* About RFC standards
RFC 920(https://tools.ietf.org/html/rfc920), Domain Requirements – Specified original top-level domains
RFC 1032(https://tools.ietf.org/html/rfc1032), Domain Administrators Guide
RFC 1033(https://tools.ietf.org/html/rfc1033), Domain Administrators Operations Guide
RFC 1034(https://tools.ietf.org/html/rfc1034), Domain Names - Concepts and Facilities
RFC 1035(https://tools.ietf.org/html/rfc1035), Domain Names - Implementation and Specification
RFC 1101(https://tools.ietf.org/html/rfc1101), DNS Encodings of Network Names and Other Types
RFC 1123(https://tools.ietf.org/html/rfc1123), Requirements for Internet Hosts—Application and Support
RFC 1178(https://tools.ietf.org/html/rfc1178), Choosing a Name for Your Computer (FYI 5)
RFC 1183(https://tools.ietf.org/html/rfc1183), New DNS RR Definitions
RFC 1348(https://tools.ietf.org/html/rfc1348), DNS NSAP RRs
RFC 1591(https://tools.ietf.org/html/rfc1591), Domain Name System Structure and Delegation (Informational)
RFC 1664(https://tools.ietf.org/html/rfc1664), Using the Internet DNS to Distribute RFC1327 Mail Address Mapping Tables
RFC 1706(https://tools.ietf.org/html/rfc1706), DNS NSAP Resource Records
RFC 1712(https://tools.ietf.org/html/rfc1712), DNS Encoding of Geographical Location
RFC 1876(https://tools.ietf.org/html/rfc1876), A Means for Expressing Location Information in the Domain Name System
RFC 1886(https://tools.ietf.org/html/rfc1886), DNS Extensions to support IP version 6
RFC 1912(https://tools.ietf.org/html/rfc1912), Common DNS Operational and Configuration Errors
RFC 1995(https://tools.ietf.org/html/rfc1995), Incremental Zone Transfer in DNS
RFC 1996(https://tools.ietf.org/html/rfc1996), A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
RFC 2052(https://tools.ietf.org/html/rfc2052), A DNS RR for specifying the location of services (DNS SRV)
RFC 2100(https://tools.ietf.org/html/rfc2100), The Naming of Hosts (Informational)
RFC 2136(https://tools.ietf.org/html/rfc2136), Dynamic Updates in the domain name system (DNS UPDATE)
RFC 2181(https://tools.ietf.org/html/rfc2181), Clarifications to the DNS Specification
RFC 2182(https://tools.ietf.org/html/rfc2182), Selection and Operation of Secondary DNS Servers
RFC 2230(https://tools.ietf.org/html/rfc2230), Key Exchange Delegation Record for the DNS
RFC 2308(https://tools.ietf.org/html/rfc2308), Negative Caching of DNS Queries (DNS NCACHE)
RFC 2317(https://tools.ietf.org/html/rfc2317), Classless IN-ADDR.ARPA delegation (BCP 20)
RFC 2535(https://tools.ietf.org/html/rfc2535), Domain Name System Security Extensions
RFC 2536(https://tools.ietf.org/html/rfc2536), DSA KEYs and SIGs in the Domain Name System (DNS)
RFC 2537(https://tools.ietf.org/html/rfc2537), RSA/MD5 KEYs and SIGs in the Domain Name System (DNS)
RFC 2539(https://tools.ietf.org/html/rfc2539), Storage of Diffie-Hellman Keys in the Domain Name System (DNS)
RFC 2671(https://tools.ietf.org/html/rfc2671), Extension Mechanisms for DNS (EDNS)
RFC 2672(https://tools.ietf.org/html/rfc2672), Non-Terminal DNS Name Redirection
RFC 2845(https://tools.ietf.org/html/rfc2845), Secret Key Transaction Authentication for DNS (TSIG)
RFC 2874(https://tools.ietf.org/html/rfc2874), DNS Extensions to Support IPv6 Address Aggregation and Renumbering
RFC 2930(https://tools.ietf.org/html/rfc2930), Secret Key Establishment for DNS (TKEY RR)
RFC 3110(https://tools.ietf.org/html/rfc3110), RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS)
RFC 3123(https://tools.ietf.org/html/rfc3123), A DNS RR Type for Lists of Address Prefixes (APL RR)
RFC 3225(https://tools.ietf.org/html/rfc3225), Indicating Resolver Support of DNSSEC
RFC 3226(https://tools.ietf.org/html/rfc3226), DNSSEC and IPv6 A6 aware server/resolver message size requirements
RFC 3403(https://tools.ietf.org/html/rfc3403), Dynamic Delegation Discovery System (DDDS) Part Three: The Domain Name System (DNS) Database
RFC 3597(https://tools.ietf.org/html/rfc3597), Handling of Unknown DNS Resource Record (RR) Types
RFC 3696(https://tools.ietf.org/html/rfc3696), Application Techniques for Checking and Transformation of Names (Informational)
RFC 4025(https://tools.ietf.org/html/rfc4025), A Method for Storing IPsec Keying Material in DNS
RFC 4034(https://tools.ietf.org/html/rfc4034), Resource Records for the DNS Security Extensions
RFC 4255(https://tools.ietf.org/html/rfc4255), Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints
RFC 4343(https://tools.ietf.org/html/rfc4343), Domain Name System (DNS) Case Insensitivity Clarification
RFC 4398(https://tools.ietf.org/html/rfc4398), Storing Certificates in the Domain Name System (DNS)
RFC 4408(https://tools.ietf.org/html/rfc4408), Sender Policy Framework (SPF) for Authorizing Use of Domains in E-Mail, Version 1
RFC 4431(https://tools.ietf.org/html/rfc4431), The DNSSEC Lookaside Validation (DLV) DNS Resource Record
RFC 4592(https://tools.ietf.org/html/rfc4592), The Role of Wildcards in the Domain Name System
RFC 4635(https://tools.ietf.org/html/rfc4635), HMAC SHA TSIG Algorithm Identifiers
RFC 4701(https://tools.ietf.org/html/rfc4701), A DNS Resource Record (RR) for Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID RR)
RFC 4892(https://tools.ietf.org/html/rfc4892), Requirements for a Mechanism Identifying a Name Server Instance (Informational)
RFC 5001(https://tools.ietf.org/html/rfc5001), DNS Name Server Identifier (NSID) Option
RFC 5155(https://tools.ietf.org/html/rfc5155), DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
RFC 5205(https://tools.ietf.org/html/rfc5205), Host Identity Protocol (HIP) Domain Name System (DNS) Extension
RFC 5452(https://tools.ietf.org/html/rfc5452), Measures for Making DNS More Resilient against Forged Answers
RFC 5625(https://tools.ietf.org/html/rfc5625), DNS Proxy Implementation Guidelines (BCP 152)
RFC 5890(https://tools.ietf.org/html/rfc5890), Internationalized Domain Names for Applications (IDNA):Definitions and Document Framework
RFC 5891(https://tools.ietf.org/html/rfc5891), Internationalized Domain Names in Applications (IDNA): Protocol
RFC 5892(https://tools.ietf.org/html/rfc5892), The Unicode Code Points and Internationalized Domain Names for Applications (IDNA)
RFC 5893(https://tools.ietf.org/html/rfc5893), Right-to-Left Scripts for Internationalized Domain Names for Applications (IDNA)
RFC 5894(https://tools.ietf.org/html/rfc5894), Internationalized Domain Names for Applications (IDNA):Background, Explanation, and Rationale (Informational)
RFC 5895(https://tools.ietf.org/html/rfc5895), Mapping Characters for Internationalized Domain Names in Applications (IDNA) 2008 (Informational)
RFC 5936(https://tools.ietf.org/html/rfc5936), DNS Zone Transfer Protocol (AXFR)
RFC 5966(https://tools.ietf.org/html/rfc5966), DNS Transport over TCP - Implementation Requirements
RFC 6195(https://tools.ietf.org/html/rfc6195), Domain Name System (DNS) IANA Considerations (BCP 42)
RFC 6698(https://tools.ietf.org/html/rfc6698), The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA
RFC 6742(https://tools.ietf.org/html/rfc6742), DNS Resource Records for the Identifier-Locator Network Protocol (ILNP)
RFC 6844(https://tools.ietf.org/html/rfc6844), DNS Certification Authority Authorization (CAA) Resource Record
RFC 6975(https://tools.ietf.org/html/rfc6975), Signaling Cryptographic Algorithm Understanding in DNS Security Extensions (DNSSEC)
RFC 7043(https://tools.ietf.org/html/rfc7043), Resource Records for EUI-48 and EUI-64 Addresses in the DNS
RFC 7314(https://tools.ietf.org/html/rfc7314), Extension Mechanisms for DNS (EDNS) EXPIRE Option
*/

//About this list, see https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
//Port and Flags definitions
#define IPPORT_DNS                    53U        //Standard DNS(TCP and UDP) Port
#define IPPORT_MDNS                   5353U      //Multicast Domain Name System/mDNS  Port
#define IPPORT_LLMNR                  5355U      //Link-Local Multicast Name Resolution/LLMNR Port
#define DNS_STANDARD                  0x0100     //System Standard query
#define DNS_SQR_NE                    0x8180     //Standard query response and No Error.
#define DNS_SQR_NEA                   0x8580     //Standard query response, No Error and Authoritative.
#define DNS_SQR_NETC                  0x8380     //Standard query response and No Error, but Truncated.
#define DNS_SQR_FE                    0x8181     //Standard query response, Format Error
#define DNS_SQR_SF                    0x8182     //Standard query response, Server failure
#define DNS_SQR_SNH                   0x8183     //Standard query response, No Such Name
#define DNS_GET_BIT_RESPONSE          0x8000     //Get Response bit in DNS flags.
#define DNS_GET_BIT_OPCODE            0x7800     //Get OPCode in DNS flags.
#define DNS_GET_BIT_AA                0x0400     //Get Authoritative bit in DNS flags.
#define DNS_GET_BIT_TC                0x0200     //Get Truncated bit in DNS flags.
#define DNS_GET_BIT_RD                0x0100     //Get Recursion Desired bit in DNS flags.
#define DNS_GET_BIT_AD                0x0020     //Get Authentic Data bit in DNS flags.
#define DNS_GET_BIT_CD                0x0010     //Get Checking Disabled bit in DNS flags.
#define DNS_GET_BIT_RCODE             0x000F     //Get RCode in DNS flags.
#define DNS_SET_R                     0x8000     //Set Response bit.
#define DNS_SET_RTC                   0x8200     //Set Response bit and Truncated bit.
#define DNS_SER_RA                    0x8580     //Set Response bit and Authoritative bit.
#define DNS_SET_R_FE                  0x8001     //Set Response bit and Format Error RCode.
#define DNS_SET_R_SNH                 0x8003     //Set Response bit and No Such Name RCode.
#define DNS_POINTER_BITS              0xC0       //DNS compression pointer(1100000000000000)
#define DNS_POINTER_BITS_STRING       ('\xC0')
#define DNS_POINTER_BITS_GET_LOCATE   0x3FFF     //Get location of DNS compression pointer(00111111111111111)
#define DNS_POINTER_QUERY             0xC00C     //Pointer of first query

//OPCode definitions
#define DNS_OPCODE_QUERY        0        //Query, ID is 0.
#define DNS_OPCODE_IQUERY       1U       //Inverse Query(Obsolete), ID is 1.
#define DNS_OPCODE_STATUS       2U       //Status, ID is 2.
#define DNS_OPCODE_NOTIFY       4U       //Notify, ID is 3.
#define DNS_OPCODE_UPDATE       5U       //Update, ID is 4.

//Classes definitions
#define DNS_CLASS_IN            0x0001   //DNS INTERNET, ID is 1.
#define DNS_CLASS_CSNET         0x0002   //DNS CSNET Classes, ID is 2.
#define DNS_CLASS_CHAOS         0x0003   //DNS CHAOS Classes, ID is 3.
#define DNS_CLASS_HESIOD        0x0004   //DNS HESIOD Classes, ID is 4.
#define DNS_CLASS_NONE          0x00FE   //DNS NONE Classes, ID is 254.
#define DNS_CLASS_ALL           0x00FF   //DNS ALL Classes, ID is 255.
#define DNS_CLASS_ANY           0x00FF   //DNS ANY Classes, ID is 255.

//RCode definitions
#define DNS_RCODE_NOERROR       0        //No Error, ID is 0.
#define DNS_RCODE_FORMERR       0x0001   //Format Error, ID is 1.
#define DNS_RCODE_SERVFAIL      0x0002   //Server Failure, ID is 2.
#define DNS_RCODE_NXDOMAIN      0x0003   //Non-Existent Domain, ID is 3.
#define DNS_RCODE_NOTIMP        0x0004   //Not Implemented, ID is 4.
#define DNS_RCODE_REFUSED       0x0005   //Query Refused, ID is 5.
#define DNS_RCODE_YXDOMAIN      0x0006   //Name Exists when it should not, ID is 6.
#define DNS_RCODE_YXRRSET       0x0007   //RR Set Exists when it should not, ID is 7.
#define DNS_RCODE_NXRRSET       0x0008   //RR Set that should exist does not, ID is 8.
#define DNS_RCODE_NOTAUTH       0x0009   //Server Not Authoritative for zone/Not Authorized, ID is 9.
#define DNS_RCODE_NOTZONE       0x000A   //Name not contained in zone, ID is 10.
#define DNS_RCODE_BADVERS       0x0010   //Bad OPT Version/TSIG Signature Failure, ID is 16.
#define DNS_RCODE_BADKEY        0x0011   //Key not recognized, ID is 17.
#define DNS_RCODE_BADTIME       0x0012   //Signature out of time window, ID is 18.
#define DNS_RCODE_BADMODE       0x0013   //Bad TKEY Mode, ID is 19.
#define DNS_RCODE_BADNAME       0x0014   //Duplicate key name, ID is 20.
#define DNS_RCODE_BADALG        0x0015   //Algorithm not supported, ID is 21.
#define DNS_RCODE_BADTRUNC      0x0016   //Bad Truncation, ID is 22.
#define DNS_RCODE_PRIVATE_A     0xFF00   //DNS Reserved Private use opcodes, ID is begin at 3841.
#define DNS_RCODE_PRIVATE_B     0xFFFE   //DNS Reserved Private use opcodes, ID is end at 4095.
#define DNS_OPCODE_RESERVED     0xFFFF   //DNS Reserved opcodes, ID is 65535.

//Record Types definitions
#define DNS_RECORD_A            0x0001   //DNS A Record, ID is 1.
#define DNS_RECORD_NS           0x0002   //DNS NS Record, ID is 2.
#define DNS_RECORD_MD           0x0003   //DNS MD Record, ID is 3.(Obsolete)
#define DNS_RECORD_MF           0x0004   //DNS MF Record, ID is 4.(Obsolete)
#define DNS_RECORD_CNAME        0x0005   //DNS CNAME Record, ID is 5.
#define DNS_RECORD_SOA          0x0006   //DNS SOA Record, ID is 6.
#define DNS_RECORD_MB           0x0007   //DNS MB Record, ID is 7.(Experimental)
#define DNS_RECORD_MG           0x0008   //DNS MG Record, ID is 8.(Experimental)
#define DNS_RECORD_MR           0x0009   //DNS MR Record, ID is 9.(Experimental)
#define DNS_RECORD_NULL         0x000A   //DNS NULL Record, ID is 10.(Experimental)
#define DNS_RECORD_WKS          0x000B   //DNS WKS Record, ID is 11.
#define DNS_RECORD_PTR          0x000C   //DNS PTR Record, ID is 12.
#define DNS_RECORD_HINFO        0x000D   //DNS HINFO Record, ID is 13.
#define DNS_RECORD_MINFO        0x000E   //DNS MINFO Record, ID is 14.
#define DNS_RECORD_MX           0x000F   //DNS MX Record, ID is 15.
#define DNS_RECORD_TXT          0x0010   //DNS TXT Record, ID is 16.
#define DNS_RECORD_RP           0x0011   //DNS RP Record, ID is 17.
#define DNS_RECORD_AFSDB        0x0012   //DNS AFSDB Record, ID is 18.
#define DNS_RECORD_X25          0x0013   //DNS X25 Record, ID is 19.
#define DNS_RECORD_ISDN         0x0014   //DNS ISDN Record, ID is 20.
#define DNS_RECORD_RT           0x0015   //DNS RT Record, ID is 21.
#define DNS_RECORD_NSAP         0x0016   //DNS NSAP Record, ID is 22.
#define DNS_RECORD_NSAP_PTR     0x0017   //DNS NSAP PTR Record, ID is 23.(Obsolete)
#define DNS_RECORD_SIG          0x0018   //DNS SIG Record, ID is 24.
#define DNS_RECORD_KEY          0x0019   //DNS KEY Record, ID is 25.
#define DNS_RECORD_PX           0x001A   //DNS PX Record, ID is 26.
#define DNS_RECORD_GPOS         0x001B   //DNS GPOS Record, ID is 27.
#define DNS_RECORD_AAAA         0x001C   //DNS AAAA Record, ID is 28.
#define DNS_RECORD_LOC          0x001D   //DNS LOC Record, ID is 29.
#define DNS_RECORD_NXT          0x001E   //DNS NXT Record, ID is 30.
#define DNS_RECORD_EID          0x001F   //DNS EID Record, ID is 31.
#define DNS_RECORD_NIMLOC       0x0020   //DNS NIMLOC Record, ID is 32.
#define DNS_RECORD_SRV          0x0021   //DNS SRV Record, ID is 33.
#define DNS_RECORD_ATMA         0x0022   //DNS ATMA Record, ID is 34.
#define DNS_RECORD_NAPTR        0x0023   //DNS NAPTR Record, ID is 35.
#define DNS_RECORD_KX           0x0024   //DNS KX Record, ID is 36.
#define DNS_RECORD_CERT         0x0025   //DNS CERT Record, ID is 37.
#define DNS_RECORD_A6           0x0026   //DNS A6 Record, ID is 38.(Obsolete)
#define DNS_RECORD_DNAME        0x0027   //DNS DNAME Record, ID is 39.
#define DNS_RECORD_SINK         0x0028   //DNS SINK Record, ID is 40.
#define DNS_RECORD_OPT          0x0029   //DNS OPT/EDNS Record, ID is 41.
#define DNS_RECORD_APL          0x002A   //DNS APL Record, ID is 42.
#define DNS_RECORD_DS           0x002B   //DNS DS Record, ID is 43.
#define DNS_RECORD_SSHFP        0x002C   //DNS SSHFP Record, ID is 44.
#define DNS_RECORD_IPSECKEY     0x002D   //DNS IPSECKEY Record, ID is 45.
#define DNS_RECORD_RRSIG        0x002E   //DNS RRSIG Record, ID is 46.
#define DNS_RECORD_NSEC         0x002F   //DNS NSEC Record, ID is 47.
#define DNS_RECORD_DNSKEY       0x0030   //DNS DNSKEY Record, ID is 48.
#define DNS_RECORD_DHCID        0x0031   //DNS DHCID Record, ID is 49.
#define DNS_RECORD_NSEC3        0x0032   //DNS NSEC3 Record, ID is 50.
#define DNS_RECORD_NSEC3PARAM   0x0033   //DNS NSEC3PARAM Record, ID is 51.
#define DNS_RECORD_TLSA         0x0034   //DNS TLSA Record, ID is 52.
#define DNS_RECORD_HIP          0x0037   //DNS HIP Record, ID is 55.
#define DNS_RECORD_NINFO        0x0038   //DNS NINFO Record, ID is 56.
#define DNS_RECORD_RKEY         0x0039   //DNS RKEY Record, ID is 57.
#define DNS_RECORD_TALINK       0x003A   //DNS TALINK Record, ID is 58.
#define DNS_RECORD_CDS          0x003B   //DNS CDS Record, ID is 59.
#define DNS_RECORD_CDNSKEY      0x003C   //DNS CDNSKEY Record, ID is 60.
#define DNS_RECORD_OPENPGPKEY   0x003D   //DNS OPENPGPKEY Record, ID is 61.
#define DNS_RECORD_SPF          0x0063   //DNS SPF Record, ID is 99.
#define DNS_RECORD_UINFO        0x0064   //DNS UINFO Record, ID is 100.
#define DNS_RECORD_UID          0x0065   //DNS UID Record, ID is 101.
#define DNS_RECORD_GID          0x0066   //DNS GID Record, ID is 102.
#define DNS_RECORD_UNSPEC       0x0067   //DNS UNSPEC Record, ID is 103.
#define DNS_RECORD_NID          0x0068   //DNS NID Record, ID is 104.
#define DNS_RECORD_L32          0x0069   //DNS L32 Record, ID is 105.
#define DNS_RECORD_L64          0x006A   //DNS L64 Record, ID is 106.
#define DNS_RECORD_LP           0x006B   //DNS LP Record, ID is 107.
#define DNS_RECORD_EUI48        0x006C   //DNS EUI48 Record, ID is 108.
#define DNS_RECORD_EUI64        0x006D   //DNS EUI64 Record, ID is 109.
#define DNS_RECORD_TKEY         0x00F9   //DNS TKEY Record, ID is 249.
#define DNS_RECORD_TSIG         0x00FA   //DNS TSIG Record, ID is 250.
#define DNS_RECORD_IXFR         0x00FB   //DNS IXFR Record, ID is 251.
#define DNS_RECORD_AXFR         0x00FC   //DNS AXFR Record, ID is 252.
#define DNS_RECORD_MAILB        0x00FD   //DNS MAILB Record, ID is 253.
#define DNS_RECORD_MAILA        0x00FE   //DNS MAILA Record, ID is 254.
#define DNS_RECORD_ANY          0x00FF   //DNS ANY Record, ID is 255.
#define DNS_RECORD_URI          0x0100   //DNS URI Record, ID is 256.
#define DNS_RECORD_CAA          0x0101   //DNS CAA Record, ID is 257.
#define DNS_RECORD_TA           0x8000   //DNS TA Record, ID is 32768.
#define DNS_RECORD_DLV          0x8001   //DNS DLVS Record, ID is 32769.
#define DNS_RECORD_PRIVATE_A    0xFF00   //DNS Reserved Private use records, ID is begin at 65280.
#define DNS_RECORD_PRIVATE_B    0xFFFE   //DNS Reserved Private use records, ID is end at 65534.
#define DNS_RECORD_RESERVED     0xFFFF   //DNS Reserved records, ID is 65535.

/* Domain Name System/DNS header
// With User Datagram Protocol/UDP

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Identification         |Q|OPCode |A|T|R|R|Z|A|C| RCode |  QR/Query and Response, AA/Authoritative Answer, TC/Truncated, RD/Recursion Desired, RA/Recursion Available
|                               |R|       |A|C|D|A| |D|D|       |  Z/Zero, AD/Authenticated Data, CD/Checking Disabled, RCode/Return Code
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Total Questions        |       Total Answer RRs        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Total Authority RRs      |     Total Additional RRs      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define DNS_PACKET_MAXSIZE_TRADITIONAL 512U   //Traditional DNS packet maximum size(512 bytes)
typedef struct _dns_hdr_
{
	uint16_t              ID;
	union {
		uint16_t          Flags;
		struct {
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t       RD:1;
			uint8_t       TC:1;
			uint8_t       AA:1;
			uint8_t       OPCode_Second:1;
			uint8_t       OPCode_First:3;
			uint8_t       QR:1;
			uint8_t       RCode:4;
			uint8_t       AD:1;
			uint8_t       CD:1;
			uint8_t       Zero:1;
			uint8_t       RA:1;
		#else //BIG_ENDIAN
			uint8_t       QR:1;
			uint8_t       OPCode:4;
			uint8_t       AA:1;
			uint8_t       TC:1;
			uint8_t       RD:1;
			uint8_t       RA:1;
			uint8_t       Zero:1;
			uint8_t       AD:1;
			uint8_t       CD:1;
			uint8_t       RCode:4;
		#endif
		}FlagsBits;
	};
	uint16_t              Questions;
	uint16_t              Answer;
	uint16_t              Authority;
	uint16_t              Additional;
}dns_hdr, *pdns_hdr;

/* Domain Name System/DNS header
//With Transmission Control Protocol/TCP

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |        Identification         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Q|OPCode |A|T|R|R|Z|A|C| RCode |        Total Questions        |  QR/Query and Response, AA/Authoritative Answer, TC/Truncated, RD/Recursion Desired, RA/Recursion Available
|R|       |A|C|D|A| |D|D|       |                               |  Z/Zero, AD/Authenticated Data, CD/Checking Disabled, RCode/Return Code
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Total Answer RRs        |      Total Authority RRs      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Total Additional RRs      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_tcp_hdr_
{
	uint16_t              Length;
	uint16_t              ID;
	union {
		uint16_t          Flags;
		struct {
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t       RD:1;
			uint8_t       TC:1;
			uint8_t       AA:1;
			uint8_t       OPCode_Second:1;
			uint8_t       OPCode_First:3;
			uint8_t       QR:1;
			uint8_t       RCode:4;
			uint8_t       CD:1;
			uint8_t       AD:1;
			uint8_t       Zero:1;
			uint8_t       RA:1;
		#else //BIG_ENDIAN
			uint8_t       QR:1;
			uint8_t       OPCode:4;
			uint8_t       AA:1;
			uint8_t       TC:1;
			uint8_t       RD:1;
			uint8_t       RA:1;
			uint8_t       Zero:1;
			uint8_t       AD:1;
			uint8_t       CD:1;
			uint8_t       RCode:4;
		#endif
		}FlagsBits;
	};
	uint16_t              Questions;
	uint16_t              Answer;
	uint16_t              Authority;
	uint16_t              Additional;
}dns_tcp_hdr, *pdns_tcp_hdr;

/* Domain Name System/DNS Query

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Domain                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |            Classes            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_qry_
{
//	PUCHAR                Name;
	uint16_t              Type;
	uint16_t              Classes;
}dns_qry, *pdns_qry;

/* Domain Name System/DNS Standard Resource Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                             Name                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |           Classes             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Time To Live          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                             Data                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_record_standard_
{
//	PUCHAR                Name;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
//	PUCHAR                Data;
}dns_record_standard, *pdns_record_standard;

/* Domain Name System/DNS A(IPv4) Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Domain                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |            Classes            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Time To Live                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |            Address            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Address            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_record_a_
{
	uint16_t              Name;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
	in_addr               Addr;
}dns_record_a, *pdns_record_a;

/* Domain Name System/DNS Canonical Name/CNAME Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Domain                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |            Classes            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Time To Live                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
/                                                               /
/                         Primary Name                          /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_record_cname_
{
	uint16_t              Name;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
//	PUCHAR                PrimaryName;
}dns_record_cname, *pdns_record_cname;

/* Domain Name System/DNS Start Of a zone of Authority/SOA Resource Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                         Primary Name                          /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                         Mailbox Name                          /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Serial                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Refresh Interval                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Retry Interval                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Expire Limit                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Minimum TTL                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_record_soa_
{
//	PUCHAR                PrimaryName;
//	PUCHAR                MailboxName;
	uint32_t              Serial;
	uint32_t              RefreshInterval;
	uint32_t              RetryInterval;
	uint32_t              ExpireLimit;
	uint32_t              MinimumTTL;
}dns_record_soa, *pdns_record_soa;

/* Domain Name System/DNS Pointer/PTR Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Pointer            |             Type              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Classes            |         Time To Live          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Time To Live          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Domain                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_record_ptr_
{
	uint16_t              PTR;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
//	PUCHAR                Name;
}dns_record_ptr, *pdns_record_ptr;

/* Domain Name System/DNS Mail eXchange/MX Resource Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Preference           |                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
/                                                               /
/                      Mail Exchange Name                       /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_record_mx_
{
	uint16_t              Preference;
//	PUCHAR                MailExchangeName;
}dns_record_mx, *pdns_record_mx;

/* Domain Name System/DNS Test Strings/TXT Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Name              |             Type              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Classes            |         Time To Live          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Time To Live          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          TXT Length           |                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
/                                                               /
/                           TXT Data                            /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_record_txt_
{
	uint16_t              Name;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
	uint8_t               TXT_Length;
//	PUCHAR                TXT;
}dns_record_txt, *pdns_record_txt;

/* Domain Name System/DNS AAAA(IPv6) Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Pointer            |             Type              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Classes            |         Time To Live          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Time To Live          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Domain                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_record_aaaa_
{
	uint16_t              Name;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
	in6_addr              Addr;
}dns_record_aaaa, *pdns_record_aaaa;

/* Domain Name System/DNS Server Selection/SRV Resource Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Priority            |            Weight             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Port              |                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
/                                                               /
/                            Target                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_record_srv_
{
	uint16_t             Priority;
	uint16_t             Weight;
	uint16_t             Port;
//	PUCHAR               Target;
}dns_record_srv, *pdns_record_srv;

/* Extension Mechanisms for Domain Name System/DNS, EDNS Label/OPT Resource Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Domain                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |       UDP Payload Size        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Extended RCode |EDNS Version |D|           Reserved            |  Extended RCode/Higher bits in extended Return Code, D/DO bit
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |\---------- Z Field -----------/
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define EDNS_PACKET_MINSIZE    1220U
#define EDNS_GET_BIT_DO        0x8000        //Get DO bit in Z field.
typedef struct _dns_record_opt_
{
	uint8_t               Name;
	uint16_t              Type;              //Additional RRs Type
	uint16_t              UDPPayloadSize;
	uint8_t               Extended_RCode;
	uint8_t               Version;           //EDNS Version
	union {
		uint16_t          Z_Field;
		struct {
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t       Reserved_First:7;
			uint8_t       DO:1;              //DO bit
		#else //BIG_ENDIAN
			uint8_t       DO:1;              //DO bit
			uint8_t       Reserved_First:7;
		#endif
			uint8_t       Reserved_Second;
		}Z_Bits;
	};
	uint16_t              DataLength;
}dns_record_opt, *pdns_record_opt, edns_header, *pedns_header;

/* Extension Mechanisms for Domain Name System/DNS, Client subnet in EDNS requests(https://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02)

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Code              |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Family             |Source Netmask | Scope Netmask |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
/                                                               /
/                           Address                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define EDNS_CODE_LLQ                 0x0001   //Long-lived query
#define EDNS_CODE_UL                  0x0002   //Update lease
#define EDNS_CODE_NSID                0x0003   //Name Server Identifier (RFC 5001)
#define EDNS_CODE_OWNER               0x0004   //Owner, reserved
#define EDNS_CODE_DAU                 0x0005   //DNSSEC Algorithm Understood (RFC6975)
#define EDNS_CODE_DHU                 0x0006   //DS Hash Understood (RFC6975)
#define EDNS_CODE_N3U                 0x0007   //DSEC3 Hash Understood (RFC6975)
#define EDNS_CODE_CSUBNET             0x0008   //Client subnet as assigned by IANA
#define EDNS_CODE_EDNS_EXPIRE         0x0009   //EDNS Expire (RFC7314)

//About Address Family Numbers, see https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml.
#define ADDRESS_FAMILY_IPV4           0x0001
#define ADDRESS_FAMILY_IPV6           0x0002
typedef struct _edns_client_subnet_
{
	uint16_t              Code;
	uint16_t              Length;
	uint16_t              Family;
	uint8_t               Netmask_Source;
	uint8_t               Netmask_Scope;
//	PUCHAR                Address;
}edns_client_subnet, *pedns_client_subnet;

/* Domain Name System/DNS Delegation Signer/DS Resource Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Key Tag            |   Algorithm   |     Type      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Digest                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define DNSSEC_DS_DIGEST_RESERVED              0
#define DNSSEC_DS_DIGEST_SHA1                  1U       //Delegation Signer (DS) Resource Record (RR), see https://tools.ietf.org/html/rfc3658
#define DNSSEC_DS_DIGEST_SHA256                2U       //Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs), see https://tools.ietf.org/html/rfc4509
#define DNSSEC_DS_DIGEST_GOST                  3U       //Use of GOST Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC, see https://tools.ietf.org/html/rfc5933
#define DNSSEC_DS_DIGEST_SHA384                4U       //Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC, see https://tools.ietf.org/html/rfc6605

//About this list, see https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
#define DNSSEC_DS_TYPE_RESERVED                0
#define DNSSEC_DS_TYPE_SHA1                    1U
#define DNSSEC_DS_TYPE_SHA256                  2U
#define DNSSEC_DS_TYPE_GOST                    3U
#define DNSSEC_DS_TYPE_SHA384                  4U
#define SHA1_LENGTH                            20       //SHA-1 output is 160 bits/20 bytes lentgh
#define SHA256_LENGTH                          32       //SHA-256 output is 256 bits/32 bytes lentgh
#define GOST_LENGTH                            32       //GOST R 34.11-94 output is 256 bits/32 bytes lentgh
#define SHA384_LENGTH                          48       //SHA-384 output is 384 bits/48 bytes lentgh
typedef struct _dns_record_ds_
{
	uint16_t              KeyTag;
	uint8_t               Algorithm;
	uint8_t               Type;
//	PUCHAR                Digest;
}dns_record_ds, *pdns_record_ds;

/* Domain Name System/DNS Resource Record Digital Signature/RRSIG Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Type Covered           |   Algorithm   |    Labels     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Original TTL                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Signature Expiration                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Signature Inception                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Key Tag            |                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Signature                          /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define DNSSEC_AlGORITHM_RESERVED_0            0        //Reserved(Resource Records for the DNS Security Extensions, see https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_RSA_MD5               1U       //RSA-MD5(RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS), see https://tools.ietf.org/html/rfc3110)
#define DNSSEC_AlGORITHM_DH                    2U       //Diffie-Hellman(Storage of Diffie-Hellman Keys in the Domain Name System (DNS), see https://tools.ietf.org/html/rfc2539)
#define DNSSEC_AlGORITHM_DSA                   3U       //DSA-SHA1(Legacy Resolver Compatibility for Delegation Signer (DS), see https://tools.ietf.org/html/rfc3755)
#define DNSSEC_AlGORITHM_RESERVED_4            4U       //Reserved(DNS Security (DNSSEC) DNSKEY Algorithm IANA Registry Updates, see https://tools.ietf.org/html/rfc6725)
#define DNSSEC_AlGORITHM_RSA_SHA1              5U       //RSA-SHA-1(Resource Records for the DNS Security Extensions, see https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_DSA_NSEC3_SHA1        6U       //DSA-NSEC3-SHA-1(DNS Security (DNSSEC) Hashed Authenticated Denial of Existence, see https://tools.ietf.org/html/rfc5155)
#define DNSSEC_AlGORITHM_RSA_SHA1_NSEC3_SHA1   7U       //RSA-SHA-1-NSEC3-SHA-1(DNS Security (DNSSEC) Hashed Authenticated Denial of Existence, see https://tools.ietf.org/html/rfc5155)
#define DNSSEC_AlGORITHM_RSA_SHA256            8U       //RSA-SHA-256(Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC, see https://tools.ietf.org/html/rfc5702)
#define DNSSEC_AlGORITHM_RESERVED_9            9U       //Reserved(DNS Security (DNSSEC) DNSKEY Algorithm IANA Registry Updates, see https://tools.ietf.org/html/rfc6725)
#define DNSSEC_AlGORITHM_RSA_SHA512            10U      //RSA-SHA-512(Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC, see https://tools.ietf.org/html/rfc5702)
#define DNSSEC_AlGORITHM_RESERVED_11           11U      //Reserved(DNS Security (DNSSEC) DNSKEY Algorithm IANA Registry Updates, see https://tools.ietf.org/html/rfc6725)
#define DNSSEC_AlGORITHM_ECC_GOST              12U      //GOST R 34.10-2001(Use of GOST Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC, see https://tools.ietf.org/html/rfc5933)
#define DNSSEC_AlGORITHM_ECDSA_P256_SHA256     13U      //ECDSA Curve P-256 with SHA-256(Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC, see https://tools.ietf.org/html/rfc6605)
#define DNSSEC_AlGORITHM_ECDSA_P386_SHA386     14U      //ECDSA Curve P-384 with SHA-384(Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC, see https://tools.ietf.org/html/rfc6605)
#define DNSSEC_AlGORITHM_RESERVED_123          123U     //Reserved area between 123 and 251(Resource Records for the DNS Security Extensions, see https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_RESERVED_251          251U     //Reserved area between 123 and 251(Resource Records for the DNS Security Extensions, see https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_INDIRECT              252U     //Reserved for Indirect Keys(Resource Records for the DNS Security Extensions, see https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_PRIVATE_DNS           253U     //Private algorithm(Resource Records for the DNS Security Extensions, see https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_PRIVATE_OID           254U     //Private algorithm(Resource Records for the DNS Security Extensions, see https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_RESERVED_255          255U     //Reserved(Resource Records for the DNS Security Extensions, see https://tools.ietf.org/html/rfc4034)
#define RSA_MIN_LENGTH                         64U
#define DH_MIN_LENGTH                          96U
#define DSA_MIN_LENGTH                         128U
#define ECC_MIN_LENGTH                         24U
typedef struct _dns_record_rrsig_
{
	uint16_t              TypeCovered;
	uint8_t               Algorithm;
	uint8_t               Labels;
	uint32_t              TTL;
	uint32_t              Expiration;
	uint32_t              Inception;
	uint16_t              KeyTag;
//	PUCHAR                SignerName;
//	PUCHAR                Signature;
}dns_record_rrsig, *pdns_record_rrsig;

/* Domain Name System/DNS DNS Key/DNSKEY Resource Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Flags             |    Protocol   |   Algorithm   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Digest                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define DNSSEC_DNSKEY_FLAGS_ZK                 0x0100
#define DNSSEC_DNSKEY_FLAGS_KR                 0x0080
#define DNSSEC_DNSKEY_FLAGS_SEP                0x0001
#define DNSSEC_DNSKEY_FLAGS_RSV                0xFE7E
#define DNSSEC_DNSKEY_PROTOCOL                 3U
typedef struct _dns_record_dnskey_
{
	union {
		uint16_t          Flags;
		struct {
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t       ZoneKey:1;         //Zone Key bit
			uint8_t       Zero_A:7;
			uint8_t       KeySigningKey:1;   //Key Signing Key bit
			uint8_t       Zero_B:6;
			uint8_t       KeyRevoked:1;      //Key Revoked bit
		#else //BIG_ENDIAN
			uint8_t       Zero_A:7;
			uint8_t       ZoneKey:1;         //Zone Key bit
			uint8_t       KeyRevoked:1;      //Key Revoked bit
			uint8_t       Zero_B:6;
			uint8_t       KeySigningKey:1;   //Key Signing Key bit
		#endif
		}FlagsBits;
	};
	uint8_t               Protocol;
	uint8_t               Algorithm;
//	PUCHAR                PublicKey;
}dns_record_dnskey, *pdns_record_dnskey;

/* Domain Name System/DNS Next-Secure/NSEC Resource Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                       Next Domain Name                        /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                        Type Bit Maps                          /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

typedef struct _dns_record_nsec_
{
//	PUCHAR                NextDomainName;
//	PUCHAR                TypeBitMap;
}dns_record_nsec, *pdns_record_nsec;
*/

/* Domain Name System/DNS NSEC version 3/NSEC3 Resource Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Hash      |     Flags     |          Iterations           |
|   Algorithm   |               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Salt Length  |                     Salt                      /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Hash Length  |            Next Hashed Owner Name             /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                         Type Bit Maps                         /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
//About this list, see https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml
#define DNSSEC_NSEC3_ALGORITHM_SHA1            1U
typedef struct _dns_record_nsec3_
{
	uint8_t               Algorithm;
	union {
		uint8_t           Flags;
		struct {
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t       OptOut:1;
			uint8_t       Zero:7;
		#else //BIG_ENDIAN
			uint8_t       Zero:7;
			uint8_t       OptOut:1;
		#endif
		}FlagsBits;
	};
	uint16_t              Iterations;
	uint8_t               SaltLength;
//	PUCHAR                Salt;
//	uint8_t               HashLength;
//	PUCHAR                NextHashedOwnerName;
//	PUCHAR                TypeBitMap;
}dns_record_nsec3, *pdns_record_nsec3;

/* Domain Name System/DNS NSEC version 3 Parameters/NSEC3PARAM Resource Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Hash      |     Flags     |          Iterations           |
|   Algorithm   |               |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Salt Length  |                     Salt                      /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
//About this list, see https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml
typedef struct _dns_record_nsec3param_
{
	uint8_t               Algorithm;
	union {
		uint8_t           Flags;
		struct {
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t       Reserved:1;
			uint8_t       Zero:7;
		#else //BIG_ENDIAN
			uint8_t       Zero:7;
			uint8_t       Reserved:1;
		#endif
		}FlagsBits;
	};
	uint16_t              Iterations;
	uint8_t               SaltLength;
//	PUCHAR                Salt;
}dns_record_nsec3param, *pdns_record_nsec3param;

/* Domain Name System/DNS Certification Authority Authorization/CAA Resource Records

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Flags     |    Length     |                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
/                             Tag                               /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Value                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_record_caa_
{
	union {
		uint8_t           Flags;
		struct {
		#if __BYTE_ORDER == __LITTLE_ENDIAN
			uint8_t       Zero:7;
			uint8_t       IssuerCritical:1;
		#else //BIG_ENDIAN
			uint8_t       IssuerCritical:1;
			uint8_t       Zero:7;
		#endif
		}FlagsBits;
	};
	uint8_t               Length;
//	PUCHAR                Tag;
//	PUCHAR                Value;
}dns_record_caa, *pdns_record_caa;

//Domain Name System Curve/DNSCurve Part
#if defined(ENABLE_LIBSODIUM)
// About DNSCurve standards, see http://dnscurve.org. Also about DNSCrypt, see http://dnscrypt.org
#define DNSCURVE_MAGIC_QUERY_LEN     8U
#define DNSCRYPT_RECEIVE_MAGIC       ("r6fnvWj8")                   //Receive Magic Number
#define DNSCRYPT_CERT_MAGIC          ("DNSC")                       //Signature Magic Number
#define crypto_box_HALF_NONCEBYTES   (crypto_box_NONCEBYTES / 2U)
#define DNSCRYPT_TXT_RECORDS_LEN     124U                           //Length of DNScrypt TXT Records

/* Domain Name System Curve/DNSCurve Test Strings/TXT Data header

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Certificate Magic Number                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Version(Major)         |        Version(Minor)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define DNSCURVE_VERSION_MAJOR     0x0001    //Latest major version of DNSCurve
#define DNSCURVE_VERSION_MINOR     0         //Latest minor version of DNSCurve
typedef struct _dnscurve_txt_hdr_
{
	uint32_t              CertMagicNumber;
	uint16_t              MajorVersion;
	uint16_t              MinorVersion;
}dnscurve_txt_hdr, *pdnscurve_txt_hdr;

/* Domain Name System Curve/DNSCurve Signature with Test Strings/TXT Data

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                                                               |
|                                                               |
|                       Server Public Key                       |
|                                                               |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Server Magic Number                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Serial                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Certificate Time(Begin)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Certificate Time(End)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dnscurve_txt_signature_
{
	uint8_t               PublicKey[crypto_box_PUBLICKEYBYTES];
	uint8_t               MagicNumber[8U];
	uint32_t              Serial;
	uint32_t              CertTime_Begin;
	uint32_t              CertTime_End;
}dnscurve_txt_signature, *pdnscurve_txt_signature;
#endif


//////////////////////////////////////////////////
// Main header
// 
#if defined(PLATFORM_WIN)
	#define MBSTOWCS_NULLTERMINATE   (-1)            //MultiByteToWideChar() find null-terminate.
#endif
#if defined(ENABLE_LIBSODIUM)
	#define LIBSODIUM_ERROR          (-1)
#endif
#define BYTES_TO_BITS           8U
#define U16_NUM_ONE             0x0001

//ASCII values defines
#define ASCII_HT                9                    //"␉"
#define ASCII_LF                0x0A                 //10, Line Feed or LF
#define ASCII_FF                12                   //"␌"
#define ASCII_CR                0x0D                 //13, Carriage Return or CR
#define ASCII_SPACE             32                   //" "
#define ASCII_HASHTAG           35                   //"#"
#define ASCII_AMPERSAND         38                   //"&"
#define ASCII_COMMA             44                   //","
#define ASCII_MINUS             45                   //"-"
#define ASCII_PERIOD            46                   //"."
#define ASCII_SLASH             47                   //"/"
#define ASCII_ZERO              48                   //"0"
#define ASCII_ONE               49                   //"1"
#define ASCII_TWO               50                   //"2"
#define ASCII_THREE             51                   //"3"
#define ASCII_NINE              57                   //"9"
#define ASCII_COLON             58                   //":"
#define ASCII_AT                64                   //"@"
#define ASCII_UPPERCASE_A       65                   //"A"
#define ASCII_UPPERCASE_F       70                   //"F"
#define ASCII_BRACKETS_LEAD     91                   //"["
#define ASCII_BACKSLASH         92                   //"\"
#define ASCII_BRACKETS_TRAIL    93                   //"]"
#define ASCII_ACCENT            96                   //"`"
#define ASCII_LOWERCASE_A       97                   //"a"
#define ASCII_LOWERCASE_F       102                  //"f"
#define ASCII_BRACES_LEAD       123                  //"{"
#define ASCII_VERTICAL          124                  //"|"
#define ASCII_TILDE             126                  //"~"
#define ASCII_UPPER_TO_LOWER    32U                  //Uppercase to lowercase
#define ASCII_LOWER_TO_UPPER    32U                  //Lowercase to uppercase

//Version defines
#define CONFIG_VERSION_POINT_THREE   0.3
#define CONFIG_VERSION               0.4             //Current configuration version
#define FULL_VERSION                 L"0.4.2.1"

//Exit code defines
#define EXIT_CHECK_HOSTS_TYPE_LOCAL                2U   //Type is Local in CheckHosts function.
#define EXIT_CHECK_RESPONSE_DATA_MARK_HOP_LIMITS   2U   //Mark Hop Limits in CheckresponseData function.

//Size and length defines
#define BOM_UTF_8_LENGTH               3U                                         //UTF-8 BOM length
#define BOM_UTF_16_LENGTH              2U                                         //UTF-16 BOM length
#define BOM_UTF_32_LENGTH              4U                                         //UTF-32 BOM length
#define COMMAND_BUFFER_MAXSIZE         4096U                                      //Maximum size of commands buffer(4096 bytes)
#define FILE_BUFFER_SIZE               4096U                                      //Maximum size of file buffer(4KB/4096 bytes)
#define DEFAULT_FILE_MAXSIZE           1073741824U                                //Maximum size of whole reading file(1GB/1073741824 bytes).
#define DEFAULT_LOG_MAXSIZE            8388608U                                   //Maximum size of whole log file(8MB/8388608 bytes).
#define DEFAULT_LOG_MINSIZE            4096U                                      //Minimum size of whole log file(4KB/4096 bytes).
#define PACKET_MAXSIZE                 1500U                                      //Maximum size of packets, Standard MTU of Ethernet II network
#define ORIGINAL_PACKET_MAXSIZE        1512U                                      //Maximum size of original Ethernet II packets(1500 bytes maximum payload length + 8 bytes Ethernet header + 4 bytes FCS)
#define LARGE_PACKET_MAXSIZE           4096U                                      //Maximum size of packets(4KB/4096 bytes) of TCP protocol
#define BUFFER_QUEUE_MAXNUM            1488095U                                   //Number of maximum packet buffer queues, 1488095 pps or 1.488Mpps in Gigabit Ethernet
#define BUFFER_QUEUE_MINNUM            8U                                         //Number of minimum packet buffer queues
#define DEFAULT_BUFFER_QUEUE           64U                                        //Default number of packet buffer queues
#define UINT16_MAX_STRING_LENGTH       6U                                         //Maximum number of 16 bits is 65535, its length is 6.
#define UINT32_MAX_STRING_LENGTH       10U                                        //Maximum number of 32 bits is 4294967295, its length is 10.
#define ADDR_STRING_MAXSIZE            64U                                        //Maximum size of addresses(IPv4/IPv6) words(64 bytes)
#define IPV4_SHORTEST_ADDRSTRING       6U                                         //The shortest IPv4 address strings(*.*.*.*).
#define IPV6_SHORTEST_ADDRSTRING       3U                                         //The shortest IPv6 address strings(::).
#define ICMP_PADDING_MAXSIZE           1484U                                      //Length of ICMP padding data must between 18 bytes and 1464 bytes(Ethernet MTU - IPv4 Standard Header - ICMP Header).
#if defined(PLATFORM_LINUX)
	#define ICMP_STRING_START_NUM_LINUX    16U
	#define ICMP_PADDING_LENGTH_LINUX      40U
#elif defined(PLATFORM_MACX)
	#define ICMP_STRING_START_NUM_MAC      8U
	#define ICMP_PADDING_LENGTH_MAC        48U
#endif
#define MULTI_REQUEST_TIMES_MAXNUM     8U                                                                              //Maximum times of multi requesting.
#define NETWORK_LAYER_PARTNUM          2U                                                                              //Number of network layer protocols(IPv6 and IPv4)
#define TRANSPORT_LAYER_PARTNUM        4U                                                                              //Number of transport layer protocols(00: IPv6/UDP, 01: IPv4/UDP, 02: IPv6/TCP, 03: IPv4/TCP)
#define ALTERNATE_SERVERNUM            12U                                                                             //Alternate switching of Main(00: TCP/IPv6, 01: TCP/IPv4, 02: UDP/IPv6, 03: UDP/IPv4), Local(04: TCP/IPv6, 05: TCP/IPv4, 06: UDP/IPv6, 07: UDP/IPv4), DNSCurve(08: TCP/IPv6, 09: TCP/IPv4, 10: UDP/IPv6, 11: UDP/IPv4)
#define DOMAIN_MAXSIZE                 256U                                                                            //Maximum size of whole level domain is 256 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_DATA_MAXSIZE            253U                                                                            //Maximum data length of whole level domain is 253 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_LEVEL_DATA_MAXSIZE      63U                                                                             //Domain length is between 3 and 63(Labels must be 63 characters/bytes or less, Section 2.3.1 in RFC 1035).
#define DOMAIN_MINSIZE                 2U                                                                              //Minimum size of whole level domain is 3 bytes(Section 2.3.1 in RFC 1035).
#define DOMAIN_RAMDOM_MINSIZE          6U                                                                              //Minimum size of ramdom domain requesting
#define DNS_PACKET_MINSIZE             (sizeof(dns_hdr) + 4U + sizeof(dns_qry))                                        //Minimum DNS packet size(DNS Header + Minimum Domain + DNS Query)
#define DNS_RR_MAXCOUNT_AAAA           43U                                                                             //Maximum Record Resources size of AAAA answers, 28 bytes * 43 = 1204 bytes
#define DNS_RR_MAXCOUNT_A              75U                                                                             //Maximum Record Resources size of A answers, 16 bytes * 75 = 1200 bytes
#define EDNS_ADDITIONAL_MAXSIZE        (sizeof(dns_record_opt) * 2U + sizeof(edns_client_subnet) + sizeof(in6_addr))   //Maximum of EDNS Additional Record Resources size

//Code defines
#if defined(PLATFORM_WIN)
	#define QUERY_SERVICE_CONFIG_BUFFER_MAXSIZE   8192U      //Buffer maximum size of QueryServiceConfig() function(8KB/8192 Bytes)
	#define SYSTEM_SOCKET                         UINT_PTR   //System Socket defined(WinSock2.h), not the same in x86(unsigned int) and x64(unsigned __int64) platform, which define in WinSock2.h file.
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define SYSTEM_SOCKET                         int
#endif
#if defined(ENABLE_PCAP)
	#define PCAP_READ_TIMEOUT                     0          //Pcap read timeout with pcap_open_live() has elapsed. In this case pkt_header and pkt_data don't point to a valid packet.
	#define PCAP_READ_SUCCESS                     1          //Pcap packet has been read without problems.
	#define PCAP_COMPILE_OPTIMIZE                 1U         //Pcap optimization on the resulting code is performed.
#endif
#define SHA3_512_SIZE                         64U        //SHA3-512 instance as specified in the FIPS 202 draft in April 2014(http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf), 512 bits/64 bytes.
#define CHECKSUM_SUCCESS                      0          //Result of getting correct checksum.
#define DYNAMIC_MIN_PORT                      1024U      //Well-known port is from 1 to 1023.

//Time defines
#define LOOP_MAX_TIMES                     8U        //Maximum of loop times, 8 times
#define LOOP_INTERVAL_TIME                 10U       //Loop interval time, 10 ms
#define STANDARD_TIMEOUT                   1000U     //Standard timeout, 1000 ms(1 second)
#define MONITOR_LOOP_INTERVAL_TIME         10000U    //Monitor loop interval time, 10000 ms(10 seconds)
#define SECOND_TO_MILLISECOND              1000U     //1000 milliseconds(1 second)
#define MICROSECOND_TO_MILLISECOND         1000U     //1000 microseconds(1 millisecond)
#if defined(PLATFORM_WIN)
	#define UPDATE_SERVICE_TIME                3U        //Update service timeout, 3 seconds
#endif
#if defined(ENABLE_PCAP)
	#define PCAP_DEVICES_RECHECK_TIME          10U       //Time between every WinPcap/LibPcap devices recheck, 10 seconds
	#define PCAP_CAPTURE_MIN_TIMEOUT           10U       //Minimum Pcap Capture reading timeout, 10 ms
	#define DEFAULT_PCAP_CAPTURE_TIMEOUT       200U      //Default Pcap Capture reading timeout, 200 ms
#endif
#define SOCKET_MIN_TIMEOUT                 500U      //The shortset socket timeout, 500 ms
#if defined(PLATFORM_WIN)
	#define DEFAULT_RELIABLE_SOCKET_TIMEOUT     3000U     //Default timeout of reliable sockets(Such as TCP, 3 seconds/3000ms)
	#define DEFAULT_UNRELIABLE_SOCKET_TIMEOUT   2000U     //Default timeout of unreliable sockets(Such as ICMP/ICMPv6/UDP, 2 seconds/2000ms)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define DEFAULT_RELIABLE_SOCKET_TIMEOUT     3U        //Default timeout of reliable sockets(Such as TCP, 3 seconds)
	#define DEFAULT_UNRELIABLE_SOCKET_TIMEOUT   2U        //Default timeout of unreliable sockets(Such as ICMP/ICMPv6/UDP, 2 seconds)
#endif
#define DEFAULT_FILEREFRESH_TIME           10U       //Default time between files auto-refreshing, 10 seconds
#define DEFAULT_ICMPTEST_TIME              5U        //Default time between ICMP Test, 5 seconds
#define DEFAULT_DOMAINTEST_INTERVAL_TIME   900U      //Default Domain Test time between every sending, 15 minutes(900 seconds)
#define DEFAULT_ALTERNATE_TIMES            5U        //Default times of requesting timeout, 5 times
#define DEFAULT_ALTERNATE_RANGE            10U       //Default time of checking timeout, 10 seconds
#define DEFAULT_ALTERNATE_RESET_TIME       180U      //Default time to reset switching of alternate servers, 180 seconds
#define DEFAULT_HOSTS_TTL                  900U      //Default Hosts DNS TTL, 15 minutes(900 seconds)
#define SHORTEST_FILEREFRESH_TIME          5U        //The shortset time between files auto-refreshing, 5 seconds
#define SENDING_INTERVAL_TIME              5U        //Time between every sending, 5 seconds
#define SENDING_ONCE_INTERVAL_TIMES        3U        //Repeat 3 times between every sending.
#if defined(ENABLE_LIBSODIUM)
	#define DEFAULT_DNSCURVE_RECHECK_TIME      3600U     //Default DNSCurve keys recheck time, 1 hour(3600 seconds)
	#define SHORTEST_DNSCURVE_RECHECK_TIME     10U       //The shortset DNSCurve keys recheck time, 10 seconds
#endif

//Data defines
#define DEFAULT_LOCAL_SERVERNAME              ("pcap-dnsproxy.localhost.server")                                                                                                            //Default Local DNS server name
#if defined(PLATFORM_WIN)
	#define COMMAND_LONG_PRINT_VERSION            L"--version"
	#define COMMAND_SHORT_PRINT_VERSION           L"-v"
	#define COMMAND_LONG_HELP                     L"--help"
	#define COMMAND_SHORT_HELP                    L"-h"
	#define COMMAND_FIREWALL_TEST                 L"--first-setup"
	#define COMMAND_FLUSH_DNS                     L"--flush-dns"
	#define COMMAND_LONG_SET_PATH                 L"--config-file"
	#define COMMAND_SHORT_SET_PATH                L"-c"
	#define SID_ADMINISTRATORS_GROUP              L"S-1-5-32-544"                                                                                                                               //Windows SID of Administrators group
	#define MAILSLOT_NAME                         L"\\\\.\\mailslot\\pcap_dnsproxy_mailslot"                                                                                                    //MailSlot name
	#define MAILSLOT_MESSAGE_FLUSH_DNS            L"Flush DNS cache of Pcap_DNSProxy."                                                                                                          //The mailslot message to flush dns cache
	#define DEFAULT_LOCAL_SERVICE_NAME            L"PcapDNSProxyService"                                                                                                                        //Default service name of system
	#define DEFAULT_PADDINGDATA                   ("abcdefghijklmnopqrstuvwabcdefghi")                                                                                                          //ICMP padding data on Windows
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define COMMAND_LONG_PRINT_VERSION            ("--version")
	#define COMMAND_SHORT_PRINT_VERSION           ("-v")
	#define COMMAND_LONG_HELP                     ("--help")
	#define COMMAND_SHORT_HELP                    ("-h")
	#define COMMAND_FLUSH_DNS                     ("--flush-dns")
	#define COMMAND_LONG_SET_PATH                 ("--config-file")
	#define COMMAND_SHORT_SET_PATH                ("-c")
	#define FIFO_PATH_NAME                        ("/tmp/pcap_dnsproxy_fifo")                                                                                                                   //FIFO pathname
	#define FIFO_MESSAGE_FLUSH_DNS                ("Flush DNS cache of Pcap_DNSProxy.")                                                                                                         //The FIFO message to flush dns cache
#endif
#define RFC_DOMAIN_TABLE                      (".-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")                                                                          //Preferred name syntax(Section 2.3.1 in RFC 1035)
#if defined(ENABLE_LIBSODIUM)
	#define DNSCURVE_TEST_NONCE                   0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23   //DNSCurve Test Nonce, 0x00 - 0x23(ASCII)
#endif
#if defined(PLATFORM_MACX)
	#define DEFAULT_SEQUENCE                      0
#else 
	#define DEFAULT_SEQUENCE                      0x0001                                                                                                                                        //Default sequence of protocol
#endif
#define DNS_PACKET_QUERY_LOCATE(Buffer)       (sizeof(dns_hdr) + CheckDNSQueryNameLength(Buffer + sizeof(dns_hdr)) + 1U)                                                                    //Location the beginning of DNS Query
#define DNS_TCP_PACKET_QUERY_LOCATE(Buffer)   (sizeof(dns_tcp_hdr) + CheckDNSQueryNameLength(Buffer + sizeof(dns_tcp_hdr)) + 1U)
#define DNS_PACKET_RR_LOCATE(Buffer)          (sizeof(dns_hdr) + CheckDNSQueryNameLength(Buffer + sizeof(dns_hdr)) + 1U + sizeof(dns_qry))                                                  //Location the beginning of DNS Resource Records

//Function Type defines
//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	#define FUNCTION_GETTICKCOUNT64        1U
	#define FUNCTION_INET_NTOP             2U
#endif

//Compare addresses own defines
#define ADDRESS_COMPARE_LESS           1U
#define ADDRESS_COMPARE_EQUAL          2U
#define ADDRESS_COMPARE_GREATER        3U

//Error type defines
#define LOG_MESSAGE_NOTICE             1U            // 01: Notice Message
#define LOG_ERROR_SYSTEM               2U            // 02: System Error
#define LOG_ERROR_PARAMETER            3U            // 03: Parameter Error
#define LOG_ERROR_IPFILTER             4U            // 04: IPFilter Error
#define LOG_ERROR_HOSTS                5U            // 05: Hosts Error
#define LOG_ERROR_NETWORK              6U            // 06: Network Error
#if defined(ENABLE_PCAP)
	#define LOG_ERROR_PCAP                 7U            // 07: Pcap Error
#endif
#if defined(ENABLE_LIBSODIUM)
	#define LOG_ERROR_DNSCURVE             8U            // 08: DNSCurve Error
#endif

//Codes and types defines
#define LISTEN_PROTOCOL_NETWORK_BOTH     0
#define LISTEN_PROTOCOL_IPV6             1U
#define LISTEN_PROTOCOL_IPV4             2U
#define LISTEN_PROTOCOL_TRANSPORT_BOTH   0
#define LISTEN_PROTOCOL_TCP              1U
#define LISTEN_PROTOCOL_UDP              2U
#define LISTEN_MODE_PROXY                0
#define LISTEN_MODE_PRIVATE              1U 
#define LISTEN_MODE_SERVER               2U
#define LISTEN_MODE_CUSTOM               3U
#define REQUEST_MODE_NETWORK_BOTH        0
#define REQUEST_MODE_IPV6                1U
#define REQUEST_MODE_IPV4                2U
#define REQUEST_MODE_UDP                 0
#define REQUEST_MODE_TCP                 1U
#define HOSTS_TYPE_NORMAL                0
#define HOSTS_TYPE_WHITE                 1U
#define HOSTS_TYPE_LOCAL                 2U
#define HOSTS_TYPE_BANNED                3U
#define CACHE_TYPE_TIMER                 1U
#define CACHE_TYPE_QUEUE                 2U
#if defined(ENABLE_LIBSODIUM)
	#define DNSCURVE_REQUEST_MODE_UDP         0
	#define DNSCURVE_REQUEST_MODE_TCP         1U
#endif

//Server type defines
#if defined(ENABLE_LIBSODIUM)
	#define DNSCURVE_MAIN_IPV6             1U           //DNSCurve Main(IPv6)
	#define DNSCURVE_MAIN_IPV4             2U           //DNSCurve Main(IPv4)
	#define DNSCURVE_ALTERNATE_IPV6        3U           //DNSCurve Alternate(IPv6)
	#define DNSCURVE_ALTERNATE_IPV4        4U           //DNSCurve Alternate(IPv4)
#endif

//Function Pointer defines
//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	typedef ULONGLONG(CALLBACK *GetTickCount64Function)(void);
	typedef PCSTR(CALLBACK *Inet_Ntop_Function)(INT, PVOID, PSTR, size_t);
#endif


//////////////////////////////////////////////////
// Function defines(Part 2)
#if defined(PLATFORM_WIN)
	#define Sleep(Millisecond)    Sleep((DWORD)(Millisecond))
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define Sleep(Millisecond)    usleep((useconds_t)((Millisecond) * MICROSECOND_TO_MILLISECOND))
	#define usleep(Millisecond)   usleep((useconds_t)(Millisecond))
#endif


//////////////////////////////////////////////////
// Main structures and classes
// 
//File Data structure
typedef struct _file_data_
{
	std::wstring             FileName;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string              sFileName;
#endif
	time_t                   ModificationTime;
}FileData, FILE_DATA, *PFileData, *PFILE_DATA;

//Socket Data structure
typedef struct _socket_data_
{
	SYSTEM_SOCKET            Socket;
	sockaddr_storage         SockAddr;
	socklen_t                AddrLen;
}SocketData, SOCKET_DATA, *PSocketData, *PSOCKET_DATA;

//Address Prefix Block structure
typedef struct _address_prefix_block_
{
	sockaddr_storage         Address;
	size_t                   Prefix;
}AddressPrefixBlock, ADDRESS_PREFIX_BLOCK, *PAddressPrefixBlock, *PADDRESS_PREFIX_BLOCK;

//DNS Server Data structure
typedef struct _dns_server_data_
{
	union _address_data_ {
		sockaddr_storage     Storage;
		sockaddr_in6         IPv6;
		sockaddr_in          IPv4;
	}AddressData;
#if defined(ENABLE_PCAP)
	union _hoplimit_data_ {
		uint8_t              TTL;
		uint8_t              HopLimit;
	}HopLimitData;
#endif
}DNSServerData, DNS_SERVER_DATA, *PDNSServerData, *PDNS_SERVER_DATA;

//DNS Cache structure
typedef struct _dnscache_data_
{
	std::string              Domain;
	std::shared_ptr<char>    Response;
	size_t                   Length;
	uint16_t                 RecordType;
	uint64_t                 ClearCacheTime;
}DNSCacheData, DNSCACHE_DATA, *PDNSCacheData, *PDNSCACHE_DATA;

//DNSCurve Server Data structure
#if defined(ENABLE_LIBSODIUM)
typedef struct _dnscurve_server_data_
{
	union _address_data_ {
		sockaddr_storage     Storage;
		sockaddr_in6         IPv6;
		sockaddr_in          IPv4;
	}AddressData;
	PSTR                     ProviderName;           //Server Provider Name
	PUINT8                   PrecomputationKey;      //DNSCurve Precomputation Keys
	PUINT8                   ServerPublicKey;        //Server Public Keys
	PUINT8                   ServerFingerprint;      //Server Fingerprints
	PSTR                     ReceiveMagicNumber;     //Receive Magic Number(Same from server receive)
	PSTR                     SendMagicNumber;        //Server Magic Number(Send to server)
}DNSCurveServerData, DNSCURVE_SERVER_DATA, *PDNSCurveServerData, *PDNSCURVE_SERVER_DATA;
#endif

//Class defines
//Configuration class
typedef class ConfigurationTable {
public:
// Parameters from configure files
//[Base] block
	double                               Version;
	size_t                               FileRefreshTime;
	size_t                               BufferQueueSize;
	size_t                               QueueResetTime;
//[Log] block
	bool                                 PrintError;
	size_t                               LogMaxSize;
//[DNS] block
	size_t                               RequestMode_Network;
	size_t                               RequestMode_Transport;
	bool                                 HostsOnly;
	bool                                 LocalMain;
	bool                                 LocalHosts;
	bool                                 LocalRouting;
	size_t                               CacheType;
	size_t                               CacheParameter;
	uint32_t                             HostsDefaultTTL;
//[Listen] block
#if defined(ENABLE_PCAP)
	bool                                 PcapCapture;
	size_t                               PcapReadingTimeout;
#endif
	size_t                               OperationMode;
	size_t                               ListenProtocol_Network;
	size_t                               ListenProtocol_Transport;
	std::vector<uint16_t>                *ListenPort;
	bool                                 IPFilterType;
	size_t                               IPFilterLevel;
	bool                                 AcceptType;
//[Addresses] block
	std::vector<sockaddr_storage>        *ListenAddress_IPv6;
	std::vector<sockaddr_storage>        *ListenAddress_IPv4;
	struct _localhost_subnet_ {
		ADDRESS_PREFIX_BLOCK             *IPv6;
		bool                             Setting_IPv6;
		ADDRESS_PREFIX_BLOCK             *IPv4;
		bool                             Setting_IPv4;
	}LocalhostSubnet;
	struct _dns_target_ {
		DNS_SERVER_DATA                  IPv6;
		DNS_SERVER_DATA                  Alternate_IPv6;
		DNS_SERVER_DATA                  IPv4;
		DNS_SERVER_DATA                  Alternate_IPv4;
		DNS_SERVER_DATA                  Local_IPv6;
		DNS_SERVER_DATA                  Alternate_Local_IPv6;
		DNS_SERVER_DATA                  Local_IPv4;
		DNS_SERVER_DATA                  Alternate_Local_IPv4;
		std::vector<DNS_SERVER_DATA>     *IPv6_Multi;
		std::vector<DNS_SERVER_DATA>     *IPv4_Multi;
	}DNSTarget;
//[Values] block
	size_t                               EDNSPayloadSize;
#if defined(ENABLE_PCAP)
	uint8_t                              HopLimitFluctuation;
	uint16_t                             ICMP_ID;
	uint16_t                             ICMP_Sequence;
	size_t                               ICMP_Speed;
//[Data] block(A part)
	PSTR                                 ICMP_PaddingData;
	size_t                               ICMP_PaddingLength;
	PSTR                                 DomainTest_Data;
	uint16_t                             DomainTest_ID;
	size_t                               DomainTest_Speed;
#endif
	size_t                               AlternateTimes;
	size_t                               AlternateTimeRange;
	size_t                               AlternateResetTime;
	size_t                               MultiRequestTimes;
//[Switches] block
	bool                                 DomainCaseConversion;
	bool                                 CompressionPointerMutation;
	bool                                 CPM_PointerToHeader;
	bool                                 CPM_PointerToRR;
	bool                                 CPM_PointerToAdditional;
	bool                                 EDNS_Label;
	bool                                 EDNS_ClientSubnet;
	bool                                 DNSSEC_Request;
	bool                                 DNSSEC_Validation;
	bool                                 DNSSEC_ForceValidation;
	bool                                 AlternateMultiRequest;
#if defined(ENABLE_PCAP)
	bool                                 HeaderCheck_IPv4;
	bool                                 HeaderCheck_TCP;
#endif
	bool                                 DNSDataCheck;
	bool                                 BlacklistCheck;
//[Data] block(B part)
	std::string                          *LocalFQDN_String;
	PSTR                                 LocalFQDN_Response;
	size_t                               LocalFQDN_Length;
#if !defined(PLATFORM_MACX)
	PSTR                                 LocalServer_Response;
	size_t                               LocalServer_Length;
#endif
//[DNSCurve/DNSCrypt] block
#if defined(ENABLE_LIBSODIUM)
	bool                                 DNSCurve;
#endif

// Global parameters from status
//Global block
	bool                                 Console;
	std::vector<SYSTEM_SOCKET>           *LocalSocket;
	std::default_random_engine           *RamdomEngine;
	std::vector<std::wstring>            *Path_Global;
	std::wstring                         *Path_ErrorLog;
	std::vector<std::wstring>            *FileList_Hosts;
	std::vector<std::wstring>            *FileList_IPFilter;
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::vector<std::string>             *sPath_Global;
	std::string                          *sPath_ErrorLog;
	std::vector<std::string>             *sFileList_Hosts;
	std::vector<std::string>             *sFileList_IPFilter;
#endif
#if defined(PLATFORM_WIN)
	int                                  SocketTimeout_Reliable;
	int                                  SocketTimeout_Unreliable;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	timeval                              SocketTimeout_Reliable;
	timeval                              SocketTimeout_Unreliable;
#endif
	size_t                               ReceiveWaiting;
	PSTR                                 DomainTable;
	PSTR                                 LocalAddress_Response[NETWORK_LAYER_PARTNUM];
	size_t                               LocalAddress_Length[NETWORK_LAYER_PARTNUM];
#if !defined(PLATFORM_MACX)
	std::vector<std::string>             *LocalAddress_ResponsePTR[NETWORK_LAYER_PARTNUM];
#endif
	std::vector<uint16_t>                *AcceptTypeList;

//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	HINSTANCE                            GetTickCount64_DLL;
	GetTickCount64Function               GetTickCount64_PTR;
	HINSTANCE                            Inet_Ntop_DLL;
	Inet_Ntop_Function                   Inet_Ntop_PTR;
#endif

//IPv6 support block
	bool                                 GatewayAvailable_IPv6;
	bool                                 GatewayAvailable_IPv4;
	bool                                 TunnelAvailable_IPv6;

	ConfigurationTable(void);
	~ConfigurationTable(void);
}CONFIGURATION_TABLE;

//IPv4/IPv6 addresses ranges class
typedef class AddressRangeTable {
public:
	sockaddr_storage         Begin;
	sockaddr_storage         End;
	size_t                   Level;

	AddressRangeTable(void);
}ADDRESS_RANGE_TABLE;

//Hosts lists class
typedef class HostsTable {
public:
	std::shared_ptr<char>    Response;
	std::regex               Pattern;
	std::string              PatternString;
	std::vector<uint16_t>    Type_Record;
	size_t                   Type_Hosts;
	size_t                   Length;
	bool                     Type_Operation;

	HostsTable(void);
}HOSTS_TABLE;

//Alternate swap table class
typedef class AlternateSwapTable {
public:
	bool                     IsSwap[ALTERNATE_SERVERNUM];
	size_t                   TimeoutTimes[ALTERNATE_SERVERNUM];

	AlternateSwapTable(void);
}ALTERNATE_SWAP_TABLE;

//Blacklist of results class
typedef class ResultBlacklistTable {
public:
	std::vector<AddressRangeTable>   Addresses;
	std::regex                       Pattern;
	std::string                      PatternString;
}RESULT_BLACKLIST_TABLE;

//Address Hosts class
typedef class AddressHostsTable {
public:
	std::vector<sockaddr_storage>    Address_Target;
	std::vector<AddressRangeTable>   Address_Source;
}ADDRESS_HOSTS_TABLE;

//Address routing table(IPv6) class
typedef class AddressRoutingTable_IPv6 {
public:
	size_t                                   Prefix;
	std::map<uint64_t, std::set<uint64_t>>   AddressRoutingList_IPv6;

	AddressRoutingTable_IPv6(void);
}ADDRESS_ROUTING_TABLE_IPV6;

//Address routing table(IPv4) class
typedef class AddressRoutingTable_IPv4 {
public:
	size_t                   Prefix;
	std::set<uint32_t>       AddressRoutingList_IPv4;

	AddressRoutingTable_IPv4(void);
}ADDRESS_ROUTING_TABLE_IPV4;

//Port table class
#if defined(ENABLE_PCAP)
typedef class OutputPacketTable {
public:
	std::vector<SOCKET_DATA>   SocketData_Output;
	SOCKET_DATA                SocketData_Input;
	uint16_t                   Protocol_Network;
	uint16_t                   Protocol_Transport;
	ULONGLONG                  ClearPortTime;
	size_t                     ReceiveIndex;

	OutputPacketTable(void);
}OUTPUT_PACKET_TABLE;
#endif

//Differnet IPFilter file sets structure
typedef class DiffernetIPFilterFileSet
{
public:
	std::vector<ADDRESS_RANGE_TABLE>          AddressRange;
	std::vector<RESULT_BLACKLIST_TABLE>       ResultBlacklist;
	std::vector<ADDRESS_ROUTING_TABLE_IPV6>   LocalRoutingList_IPv6;
	std::vector<ADDRESS_ROUTING_TABLE_IPV4>   LocalRoutingList_IPv4;
	size_t                                    FileIndex;

	DiffernetIPFilterFileSet(void);
}DIFFERNET_IPFILTER_FILE_SET;

//Differnet Hosts file sets structure
typedef class DiffernetHostsFileSet
{
public:
	std::vector<HOSTS_TABLE>           HostsList;
	std::vector<ADDRESS_HOSTS_TABLE>   AddressHostsList;
	size_t                             FileIndex;

	DiffernetHostsFileSet(void);
}DIFFERNET_HOSTS_FILE_SET;


//DNSCurve Configuration class
#if defined(ENABLE_LIBSODIUM)
typedef class DNSCurveConfigurationTable {
public:
//[DNSCurve] block
	size_t                   DNSCurvePayloadSize;
	size_t                   DNSCurveMode;
	bool                     IsEncryption;
	bool                     IsEncryptionOnly;
	size_t                   KeyRecheckTime;
//[DNSCurve Addresses] block
	PUINT8                   Client_PublicKey;
	PUINT8                   Client_SecretKey;
	struct _dnscurve_target_ {
		DNSCURVE_SERVER_DATA   IPv6;
		DNSCURVE_SERVER_DATA   Alternate_IPv6;
		DNSCURVE_SERVER_DATA   IPv4;
		DNSCURVE_SERVER_DATA   Alternate_IPv4;
	}DNSCurveTarget;

	DNSCurveConfigurationTable(void);
	~DNSCurveConfigurationTable(void);
}DNSCURVE_CONFIGURATON_TABLE;
#endif


//////////////////////////////////////////////////
// Main functions
// 
//Base.cpp
bool __fastcall CheckEmptyBuffer(const void *Buffer, const size_t Length);
uint64_t __fastcall hton64(const uint64_t Val);
uint64_t __fastcall ntoh64(const uint64_t Val);
void __fastcall MBSToWCSString(std::wstring &Target, const char *Buffer);
void __fastcall CaseConvert(const bool IsLowerUpper, PSTR Buffer, const size_t Length);
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	uint64_t GetTickCount64(void);
#endif
//Windows XP with SP3 support
#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
	BOOL WINAPI IsGreaterThanVista(void);
	BOOL WINAPI GetFunctionPointer(const size_t FunctionType);
#endif

//PrintLog.h
size_t __fastcall PrintError(const size_t ErrType, const wchar_t *Message, const SSIZE_T ErrCode, const wchar_t *FileName, const size_t Line);

//PacketData.h
//uint32_t __fastcall GetFCS(const unsigned char *Buffer, const size_t Length);
uint16_t __fastcall GetChecksum(const uint16_t *Buffer, const size_t Length);
uint16_t __fastcall GetICMPv6Checksum(const unsigned char *Buffer, const size_t Length, const in6_addr &Destination, const in6_addr &Source);
uint16_t __fastcall GetTCPUDPChecksum(const unsigned char *Buffer, const size_t Length, const uint16_t Protocol_Network, const uint16_t Protocol_Transport);
size_t __fastcall AddLengthDataToDNSHeader(PSTR Buffer, const size_t RecvLen, const size_t MaxLen);
size_t __fastcall CharToDNSQuery(const char *FName, PSTR TName);
size_t __fastcall DNSQueryToChar(const char *TName, PSTR FName);
void __fastcall MakeRamdomDomain(PSTR Buffer);
void __fastcall MakeDomainCaseConversion(PSTR Buffer);
size_t __fastcall AddEDNS_LabelToAdditionalRR(PSTR Buffer, const size_t Length);
size_t __fastcall MakeCompressionPointerMutation(PSTR Buffer, const size_t Length);

//Protocol.h
bool __fastcall AddressStringToBinary(const char *AddrString, void *OriginalAddr, const uint16_t Protocol, SSIZE_T &ErrCode);
size_t __fastcall AddressesComparing(const void *OriginalAddrBegin, const void *OriginalAddrEnd, const uint16_t Protocol);
bool __fastcall CheckSpecialAddress(void *Addr, const uint16_t Protocol, const bool IsPrivateUse, char *Domain);
bool __fastcall CheckAddressRouting(const void *Addr, const uint16_t Protocol);
bool __fastcall CheckCustomModeFilter(const void *OriginalAddr, const uint16_t Protocol);
size_t __fastcall CheckDNSQueryNameLength(const char *Buffer);
size_t __fastcall CheckResponseData(const char *Buffer, const size_t Length, const bool IsLocal);

//Configuration.h
bool __fastcall ReadParameter(void);
void __fastcall ReadIPFilter(void);
void __fastcall ReadHosts(void);
uint16_t __fastcall ServiceNameToHex(const char *OriginalBuffer);
uint16_t __fastcall DNSTypeNameToHex(const char *OriginalBuffer);

//Monitor.h
bool __fastcall MonitorInit(void);
void __fastcall NetworkInformationMonitor(void);

//DNSCurve.h
#if defined(ENABLE_LIBSODIUM)
	bool __fastcall DNSCurveVerifyKeypair(const unsigned char *PublicKey, const unsigned char *SecretKey);
	void __fastcall DNSCurveInit(void);
	size_t __fastcall DNSCurveTCPRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);
	size_t __fastcall DNSCurveTCPRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);
	size_t __fastcall DNSCurveUDPRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);
	size_t __fastcall DNSCurveUDPRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);
#endif

//Process.h
bool __fastcall EnterRequestProcess(const char *OriginalSend, const size_t Length, const SOCKET_DATA LocalSocketData, const uint16_t Protocol);
bool __fastcall MarkDomainCache(const char *Buffer, const size_t Length);

//Captrue.h
#if defined(ENABLE_PCAP)
	void __fastcall CaptureInit(void);
#endif

//Network.h
#if defined(ENABLE_PCAP)
bool __fastcall DomainTestRequest(const uint16_t Protocol);
bool __fastcall ICMPEcho(const uint16_t Protocol);
#endif
size_t __fastcall TCPRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const bool IsLocal);
size_t __fastcall TCPRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);
#if defined(ENABLE_PCAP)
	size_t __fastcall UDPRequest(const char *OriginalSend, const size_t Length, const SOCKET_DATA *LocalSocketData, const uint16_t Protocol);
	size_t __fastcall UDPRequestMulti(const char *OriginalSend, const size_t Length, const SOCKET_DATA *LocalSocketData, const uint16_t Protocol);
#endif
size_t __fastcall UDPCompleteRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const bool IsLocal);
size_t __fastcall UDPCompleteRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);

//Service.h
#if defined(PLATFORM_WIN)
	BOOL WINAPI CtrlHandler(const DWORD fdwCtrlType);
	size_t WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
	bool WINAPI FlushDNSMailSlotMonitor(void);
	bool WINAPI FlushDNSMailSlotSender(void);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	bool FlushDNSFIFOMonitor(void);
	bool FlushDNSFIFOSender(void);
#endif
void __fastcall FlushAllDNSCache(void);
