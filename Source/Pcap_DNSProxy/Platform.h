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
/* This code is from Qt source, which in qglobal.h header file.
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
#elif defined(__USLC__)                  /* All SCO platforms + UDK or OUDK */
#  define PLATFORM_UNIXWARE
#  define PLATFORM_UNIXWARE7
#elif defined(__svr4__) && defined(i386) /* Open UNIX 8 + GCC */
#  define PLATFORM_UNIXWARE
#  define PLATFORM_UNIXWARE7
#elif defined(__MAcDEPEND__)
#else
#  error "Qt has not been ported to this OS - talk to qt-bugs@trolltech.com"
#endif

//System series definitions
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
/* Apple Mac OS X XCode support
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
// Base Header
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
#include <algorithm>               //Algorithm support

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
//		#define __BIG_ENDIAN               2U                        //Big Endian, Little Endian is always on Windows.
		#define __BYTE_ORDER               __LITTLE_ENDIAN           //x86 and x86-64/x64 is Little Endian.

	//Code definitions
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
	#include <netinet/tcp.h>           //TCP protocol support

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

//TCP Fast Open
	#if defined(PLATFORM_LINUX)
		#ifndef _KERNEL_FASTOPEN
			#define _KERNEL_FASTOPEN

		//Conditional define for TCP_FASTOPEN
			#ifndef TCP_FASTOPEN
				#define TCP_FASTOPEN   23
			#endif

		//Conditional define for MSG_FASTOPEN
			#ifndef MSG_FASTOPEN
				#define MSG_FASTOPEN   0x20000000
			#endif
		#endif

	//A hint value for the Linux Kernel with TCP Fast Open
		#define TCP_FASTOPEN_HINT      5
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
		sa_family_t       sin_family;     /* Address family: AF_INET */
		in_port_t         sin_port;       /* Port in network byte order */
		in_addr_Windows   sin_addr;       /* Internet address */
		uint8_t           sin_zero[8U];   /* Zero */
	}sockaddr_in_Windows;

//Internet Protocol version 6/IPv6 Socket Address(From Microsoft Windows)
	typedef struct _sockaddr_in6_windows_ 
	{
		sa_family_t        sin6_family;   /* AF_INET6 */
		in_port_t          sin6_port;     /* Port number */
		uint32_t           sin6_flowinfo; /* IPv6 flow information */
		in6_addr_Windows   sin6_addr;     /* IPv6 address */
		uint32_t           sin6_scope_id; /* Scope ID (new in 2.4) */
	}sockaddr_in6_Windows;

//Linux and Mac OS X compatible(Part 2)
	#define FALSE                    0
	#define RETURN_ERROR             (-1)
	#define SOCKET_ERROR             (-1)
	#define INVALID_SOCKET           (-1)
	#define MAX_PATH                 PATH_MAX
	#define SD_SEND                  SHUT_WR
	#define SD_BOTH                  SHUT_RDWR
	#define WSAETIMEDOUT             ETIMEDOUT
	#define WSAEAFNOSUPPORT          EAFNOSUPPORT
	#define in_addr                  in_addr_Windows
	#define in6_addr                 in6_addr_Windows
	#define sockaddr_in              sockaddr_in_Windows
	#define sockaddr_in6             sockaddr_in6_Windows
	#define in6addr_loopback         *(in6_addr *)&in6addr_loopback
	#define in6addr_any              *(in6_addr *)&in6addr_any
	typedef char                     *PSTR;
	typedef signed char              INT8, *PINT8;
	typedef signed short             INT16, *PINT16;
	typedef signed int               INT32, *PINT, *PINT32;
	typedef signed long long         INT64, *PINT64;
	typedef unsigned char            UCHAR, UINT8, *PUINT8, *PUCHAR;
	typedef unsigned short           UINT16, *PUINT16;
	typedef unsigned int             UINT, UINT32, *PUINT32;
	typedef unsigned long            ULONG, DWORD;
	typedef unsigned long long       ULONGLONG, UINT64, *PUINT64;
	typedef ssize_t                  SSIZE_T;
	typedef int                      SOCKET;
	typedef addrinfo                 ADDRINFOA;
	typedef wchar_t                  *PWSTR;
	typedef sockaddr                 *PSOCKADDR;
	typedef sockaddr_in              *PSOCKADDR_IN;
	typedef sockaddr_in6             *PSOCKADDR_IN6;
	typedef addrinfo                 *PADDRINFOA;

//Function definitions(Part 1)
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
		#define send(Socket, Buffer, Length, Signal)                         send(Socket, Buffer, Length, Signal|MSG_NOSIGNAL)
		#define sendto(Socket, Buffer, Length, Signal, SockAddr, AddrLen)    sendto(Socket, Buffer, Length, Signal|MSG_NOSIGNAL, SockAddr, AddrLen)
	#endif
	#define GetLastError()                                               errno
	#define closesocket                                                  close
	#define WSAGetLastError()                                            GetLastError()
	#define WSACleanup()
	#define GetCurrentProcessId()                                        pthread_self()
#endif

//Memory alignment: 1 bytes/8 bits
#pragma pack(1)
