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
// Base Header
// 
//Preprocessor definitions
#if (defined(PLATFORM_WIN) || defined(PLATFORM_MACX))
	#define ENABLE_LIBSODIUM           //LibSodium is always enable in Windows and Mac OS X.
#endif

//C Standard Library and C++ Standard Template Library/STL headers
#include <cerrno>                  //Error report
#include <cstdio>                  //File Input/Output
#include <cstdlib>                 //Several general purpose functions
#include <cstring>                 //String support(C-style)
#include <cwchar>                  //Wide-Character Support
#include <memory>                  //Manage dynamic memory support
#include <string>                  //String support(C++)

#if defined(ENABLE_LIBSODIUM)
#if defined(PLATFORM_WIN)
	#include <windows.h>               //Master include file in Windows

//SHA-3 header
	#include "SHA3\\KeccakHash.h"

//LibSodium header and static libraries
	#define SODIUM_STATIC              //LibSodium static linking always enable in Windows and Mac OS X
	#include "..\\LibSodium\\sodium.h"
	#if defined(PLATFORM_WIN64)
		#pragma comment(lib, "..\\LibSodium\\LibSodium_x64.lib")
	#elif (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		#pragma comment(lib, "..\\LibSodium\\LibSodium_x86.lib")
	#endif
#elif defined(PLATFORM_LINUX)
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
#endif


//////////////////////////////////////////////////
// Base definitions
// 
#pragma pack(1)                                 //Memory alignment: 1 bytes/8 bits
#define BYTES_TO_BITS            8U
#define FILE_BUFFER_SIZE         4096U
#define DEFAULT_HASH_ID          HASH_ID_SHA3

//SHA-3 definitions
#define HASH_ID_SHA1             1U
#define HASH_ID_SHA2             2U
#define HASH_ID_SHA3             3U
#define HASH_ID_SHA              HASH_ID_SHA3
#if defined(PLATFORM_WIN)
	#define COMMAND_SHA              L"-SHA"
	#define COMMAND_SHA1             L"-SHA1"
	#define COMMAND_SHA2             L"-SHA2"
	#define COMMAND_SHA2_384         L"-SHA384"
	#define COMMAND_SHA2_512         L"-SHA512"
	#define COMMAND_SHA3             L"-SHA3"
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	#define COMMAND_SHA				 ("-SHA")
	#define COMMAND_SHA1             ("-SHA1")
	#define COMMAND_SHA2             ("-SHA2")
	#define COMMAND_SHA2_384         ("-SHA384")
	#define COMMAND_SHA2_512         ("-SHA512")
	#define COMMAND_SHA3             ("-SHA3")
#endif

#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Linux and Mac OS X compatible
	typedef char               *PSTR;
	#define __fastcall
	#define strnlen_s          strnlen
	#define fwprintf_s         fwprintf
	#define fread_s(Dst, DstSize, ElementSize, Count, File)              fread(Dst, ElementSize, Count, File)

//Microsoft source-code annotation language/SAL compatible
	#define _In_
	#define _Inout_
	#define _Out_
	#define _Outptr_
	#define _In_opt_
	#define _Inout_opt_
	#define _Out_opt_
	#define _Outptr_opt_
#endif


//////////////////////////////////////////////////
// Main functions
// 
//FileHash.cpp
#if defined(PLATFORM_WIN)
void __fastcall CaseConvert(
	_In_ const bool IsLowerToUpper, 
	_Inout_opt_ std::wstring &Buffer);
#endif
void __fastcall CaseConvert(
	_In_ const bool IsLowerToUpper, 
	_Inout_opt_ std::string &Buffer);

//SHA-1.cpp
bool __fastcall SHA1_Hash(
	_In_ FILE *Input);

//SHA-2.cpp
bool __fastcall SHA2_Hash(
	_In_ FILE *Input);
bool __fastcall ReadCommand_SHA2(
#if defined(PLATFORM_WIN)
	_In_ std::wstring &Command);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	_In_ std::string &Command);
#endif

//SHA-3.cpp
bool __fastcall SHA3_Hash(
	_In_ FILE *Input);
bool __fastcall ReadCommand_SHA3(
#if defined(PLATFORM_WIN)
	_In_ std::wstring &Command);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	_In_ std::string &Command);
#endif
#endif
