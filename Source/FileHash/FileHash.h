// This code is part of Pcap_DNSProxy
// A local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2016 Chengr28
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
#elif defined(__MAKEDEPEND__)
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
// Base header
// 
//Preprocessor definitions
#if (defined(PLATFORM_WIN) || defined(PLATFORM_MACX))
	#define ENABLE_LIBSODIUM           //LibSodium is always enable in Windows and Mac OS X.
#endif

//C Standard Library and C++ Standard Template Library/STL headers
#include <cerrno>                  //Error report
#include <cstdio>                  //File Input/Output
#include <cstdlib>                 //Several general purpose functions
#include <cstring>                 //String support
#include <cwchar>                  //Wide-Character Support
#include <memory>                  //Manage dynamic memory support
#include <string>                  //String support(STL)

#if defined(ENABLE_LIBSODIUM)
#if defined(PLATFORM_WIN)
	#include <windows.h>               //Master include file in Windows

//SHA-3 header
	#include "SHA3\\KeccakHash.h"

//LibSodium header and static libraries
	#pragma comment(lib, "ws2_32.lib")            //Windows WinSock 2.0+ support
	#define SODIUM_STATIC                         //LibSodium static linking always enable in Windows and Mac OS X
	#include "..\\LibSodium\\sodium.h"
	#if defined(PLATFORM_WIN64)
		#pragma comment(lib, "..\\LibSodium\\LibSodium_x64.lib")
	#elif (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		#pragma comment(lib, "..\\LibSodium\\LibSodium_x86.lib")
	#endif

//Endian definitions
	#define __LITTLE_ENDIAN            1234                      //Little Endian
	#define __BIG_ENDIAN               4321                      //Big Endian
	#define __BYTE_ORDER               __LITTLE_ENDIAN           //x86 and x86-64/x64 is Little Endian in Windows.
	#define LITTLE_ENDIAN              __LITTLE_ENDIAN
	#define BIG_ENDIAN                 __BIG_ENDIAN
	#define BYTE_ORDER                 __BYTE_ORDER
#elif defined(PLATFORM_LINUX)
	#include <endian.h>                //Endian
	#include <arpa/inet.h>             //Internet operations

//SHA-3 header
	#include "SHA3/KeccakHash.h"

//LibSodium header
	#include <sodium.h>   
#elif defined(PLATFORM_MACX)
//SHA-3 header
	#include "SHA3/KeccakHash.h"

//LibSodium header and static libraries
	#define SODIUM_STATIC              //LibSodium static linking always enable in Windows and Mac OS X
	#include "../LibSodium/sodium.h"
	#pragma comment(lib, "../LibSodium/LibSodium_Mac.a")

//Endian definitions
	#define __LITTLE_ENDIAN            1234                      //Little Endian
	#define __BIG_ENDIAN               4321                      //Big Endian
	#define __BYTE_ORDER               __LITTLE_ENDIAN           //x86 and x86-64/x64 is Little Endian in OS X.
/* Already define in OS X.
	#define LITTLE_ENDIAN              __LITTLE_ENDIAN
	#define BIG_ENDIAN                 __BIG_ENDIAN
	#define BYTE_ORDER                 __BYTE_ORDER
*/
#endif


//////////////////////////////////////////////////
// Base definitions
// 
#pragma pack(1)                                 //Memory alignment: 1 bytes/8 bits
#define BYTES_TO_BITS            8U
#define FILE_BUFFER_SIZE         4096U
#if defined(PLATFORM_WIN)
	#define MBSTOWCS_NULLTERMINATE   (-1)            //MultiByteToWideChar() find null-terminate.
#endif

//Version definitions
#define FULL_VERSION                 L"0.4.5.3"
#define COPYRIGHT_MESSAGE            L"Copyright (C) 2012-2016 Chengr28"

//Command definitions
#if defined(PLATFORM_WIN)
	#define COMMAND_LONG_PRINT_VERSION              L"--VERSION"
	#define COMMAND_SHORT_PRINT_VERSION             L"-V"
	#define COMMAND_LONG_HELP                       L"--HELP"
	#define COMMAND_SHORT_HELP                      L"-H"
	#define COMMAND_SIGN_HELP                       L"-?"
	#define COMMAND_LIB_VERSION                     L"--LIB-VERSION"
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define COMMAND_LONG_PRINT_VERSION              ("--VERSION")
	#define COMMAND_SHORT_PRINT_VERSION             ("-V")
	#define COMMAND_LONG_HELP                       ("--HELP")
	#define COMMAND_SHORT_HELP                      ("-H")
	#define COMMAND_SIGN_HELP                       ("-?")
	#define COMMAND_LIB_VERSION                     ("--LIB-VERSION")
#endif

//Hash definitions
#define HASH_ID_CRC              1U
#define HASH_ID_CHECKSUM         2U
#define HASH_ID_MD2              3U
#define HASH_ID_MD4              4U
#define HASH_ID_ED2K             5U
#define HASH_ID_MD5              6U
#define HASH_ID_MD               HASH_ID_MD5
#define HASH_ID_SHA1             7U
#define HASH_ID_SHA2             8U
#define HASH_ID_SHA3             9U
#define HASH_ID_SHA              HASH_ID_SHA3
#define DEFAULT_HASH_ID          HASH_ID_SHA3
#if defined(PLATFORM_WIN)
	#define HASH_COMMAND_CRC                        L"-CRC"
	#define HASH_COMMAND_CHECKSUM                   L"-CHECKSUM"
	#define HASH_COMMAND_MD                         L"-MD"
	#define HASH_COMMAND_MD2                        L"-MD2"
	#define HASH_COMMAND_MD4                        L"-MD4"
	#define HASH_COMMAND_ED2K                       L"-ED2K"
	#define HASH_COMMAND_MD5                        L"-MD5"
	#define HASH_COMMAND_SHA                        L"-SHA"
	#define HASH_COMMAND_SHA1                       L"-SHA1"
	#define HASH_COMMAND_SHA2                       L"-SHA2"
	#define HASH_COMMAND_SHA2_384                   L"-SHA384"
	#define HASH_COMMAND_SHA2_512                   L"-SHA512"
	#define HASH_COMMAND_SHA3                       L"-SHA3"
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define HASH_COMMAND_CRC                        ("-CRC")
	#define HASH_COMMAND_CHECKSUM                   ("-CHECKSUM")
	#define HASH_COMMAND_MD                         ("-MD")
	#define HASH_COMMAND_MD2                        ("-MD2")
	#define HASH_COMMAND_MD4                        ("-MD4")
	#define HASH_COMMAND_ED2K                       ("-ED2K")
	#define HASH_COMMAND_MD5                        ("-MD5")
	#define HASH_COMMAND_SHA                        ("-SHA")
	#define HASH_COMMAND_SHA1                       ("-SHA1")
	#define HASH_COMMAND_SHA2                       ("-SHA2")
	#define HASH_COMMAND_SHA2_384                   ("-SHA384")
	#define HASH_COMMAND_SHA2_512                   ("-SHA512")
	#define HASH_COMMAND_SHA3                       ("-SHA3")
#endif

#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Linux and Mac OS X compatible
	#define RETURN_ERROR                                                 (-1)
	#define __fastcall
	#define strnlen_s                                                    strnlen
	#define fwprintf_s                                                   fwprintf
	#define memcpy_s(Dst, DstSize, Src, Size)                            memcpy(Dst, Src, Size)
	#define fread_s(Dst, DstSize, ElementSize, Count, File)              fread(Dst, ElementSize, Count, File)
#endif

//Function definitions
#define ntoh64                hton64


//////////////////////////////////////////////////
// Main functions
// 
//FileHash.cpp
void __fastcall PrintDescription(
	void);

//Base.cpp
bool __fastcall CheckEmptyBuffer(
	const void *Buffer, 
	const size_t Length);
uint64_t __fastcall hton64(
	const uint64_t Value);
bool __fastcall MBSToWCSString(
	const char *Buffer, 
	const size_t MaxLen, 
	std::wstring &Target);
#if defined(PLATFORM_WIN)
void __fastcall CaseConvert(
	const bool IsLowerToUpper, 
	std::wstring &Buffer);
#endif
void __fastcall CaseConvert(
	const bool IsLowerToUpper, 
	std::string &Buffer);

//Checksum.cpp
bool __fastcall Checksum_Hash(
	FILE *Input);

//CRC.cpp
bool __fastcall ReadCommand_CRC(
#if defined(PLATFORM_WIN)
	std::wstring &Command);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string &Command);
#endif
bool __fastcall CRC_Hash(
	FILE *Input);

//MD2.cpp
bool __fastcall MD2_Hash(
	FILE *Input);

//MD4.cpp
bool __fastcall MD4_Hash(
	FILE *Input);

//MD5.cpp
bool __fastcall MD5_Hash(
	FILE *Input);

//SHA-1.cpp
bool __fastcall SHA1_Hash(
	FILE *Input);

//SHA-2.cpp
bool __fastcall SHA2_Hash(
	FILE *Input);
bool __fastcall ReadCommand_SHA2(
#if defined(PLATFORM_WIN)
	std::wstring &Command);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string &Command);
#endif

//SHA-3.cpp
bool __fastcall SHA3_Hash(
	FILE *Input);
bool __fastcall ReadCommand_SHA3(
#if defined(PLATFORM_WIN)
	std::wstring &Command);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::string &Command);
#endif
#endif
