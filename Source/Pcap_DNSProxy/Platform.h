// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on packet capturing
// Copyright (C) 2012-2019 Chengr28
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


#ifndef PCAP_DNSPROXY_PLATFORM_H
#define PCAP_DNSPROXY_PLATFORM_H

#include "Version.h"

//////////////////////////////////////////////////
// Operating system detection
// 
/* This code is from Qt source, which in /src/corelib/global/qsystemdetection.h header file, please visit https://www.qt.io/developers.

   The operating system, must be one of: (PLATFORM_x)

     DARWIN   - Any Darwin system (macOS, iOS, watchOS, tvOS)
     MACOS    - macOS
     IOS      - iOS
     WATCHOS  - watchOS
     TVOS     - tvOS
     WIN32    - Win32 (Windows 2000/XP/Vista/7 and Windows Server 2003/2008)
     WINRT    - WinRT (Windows Runtime)
     CYGWIN   - Cygwin
     SOLARIS  - Sun Solaris
     HPUX     - HP-UX
     LINUX    - Linux [has variants]
     FREEBSD  - FreeBSD [has variants]
     NETBSD   - NetBSD
     OPENBSD  - OpenBSD
     INTERIX  - Interix
     AIX      - AIX
     HURD     - GNU Hurd
     QNX      - QNX [has variants]
     QNX6     - QNX RTP 6.1
     LYNX     - LynxOS
     BSD4     - Any BSD 4.4 system
     UNIX     - Any UNIX BSD/SYSV system
     ANDROID  - Android platform
     HAIKU    - Haiku

   The following operating systems have variants:
     LINUX    - both PLATFORM_LINUX and PLATFORM_ANDROID are defined when building for Android
              - only PLATFORM_LINUX is defined if building for other Linux systems
     FREEBSD  - PLATFORM_FREEBSD is defined only when building for FreeBSD with a BSD userland
              - PLATFORM_FREEBSD_KERNEL is always defined on FreeBSD, even if the userland is from GNU
*/

#if defined(__APPLE__) && (defined(__GNUC__) || defined(__xlC__) || defined(__xlc__))
#  include <TargetConditionals.h>
#  if defined(TARGET_OS_MAC) && TARGET_OS_MAC
#    define PLATFORM_DARWIN
#    define PLATFORM_BSD4
#    ifdef __LP64__
#      define PLATFORM_DARWIN64
#    else
#      define PLATFORM_DARWIN32
#    endif
#    if defined(TARGET_OS_IPHONE) && TARGET_OS_IPHONE
#      define QT_PLATFORM_UIKIT
#      if defined(TARGET_OS_WATCH) && TARGET_OS_WATCH
#        define PLATFORM_WATCHOS
#      elif defined(TARGET_OS_TV) && TARGET_OS_TV
#        define PLATFORM_TVOS
#      else
#        // TARGET_OS_IOS is only available in newer SDKs, 
#        // so assume any other iOS-based platform is iOS for now
#        define PLATFORM_IOS
#      endif
#    else
#      // TARGET_OS_OSX is only available in newer SDKs, 
#      // so assume any non iOS-based platform is macOS for now
#      define PLATFORM_MACOS
#    endif
#  else
#    error "Qt has not been ported to this Apple platform - see https://www.qt.io/developers"
#  endif
#elif defined(__ANDROID__) || defined(ANDROID)
#  define PLATFORM_ANDROID
#  define PLATFORM_LINUX
#elif defined(__CYGWIN__)
#  define PLATFORM_CYGWIN
#elif !defined(SAG_COM) && (!defined(WINAPI_FAMILY) || WINAPI_FAMILY==WINAPI_FAMILY_DESKTOP_APP) && (defined(WIN64) || defined(_WIN64) || defined(__WIN64__))
#  define PLATFORM_WIN32
#  define PLATFORM_WIN64
#elif !defined(SAG_COM) && (defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__))
#  if defined(WINAPI_FAMILY)
#    ifndef WINAPI_FAMILY_PC_APP
#      define WINAPI_FAMILY_PC_APP WINAPI_FAMILY_APP
#    endif
#    if defined(WINAPI_FAMILY_PHONE_APP) && WINAPI_FAMILY==WINAPI_FAMILY_PHONE_APP
#      define PLATFORM_WINRT
#    elif WINAPI_FAMILY==WINAPI_FAMILY_PC_APP
#      define PLATFORM_WINRT
#    else
#      define PLATFORM_WIN32
#    endif
#  else
#    define PLATFORM_WIN32
#  endif
#elif defined(__sun) || defined(sun)
#  define PLATFORM_SOLARIS
#elif defined(hpux) || defined(__hpux)
#  define PLATFORM_HPUX
#elif defined(__native_client__)
#  define PLATFORM_NACL
#elif defined(__EMSCRIPTEN__)
#  define PLATFORM_WASM
#elif defined(__linux__) || defined(__linux)
#  define PLATFORM_LINUX
#elif defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__)
#  ifndef __FreeBSD_kernel__
#    define PLATFORM_FREEBSD
#  endif
#  define PLATFORM_FREEBSD_KERNEL
#  define PLATFORM_BSD4
#elif defined(__NetBSD__)
#  define PLATFORM_NETBSD
#  define PLATFORM_BSD4
#elif defined(__OpenBSD__)
#  define PLATFORM_OPENBSD
#  define PLATFORM_BSD4
#elif defined(__INTERIX)
#  define PLATFORM_INTERIX
#  define PLATFORM_BSD4
#elif defined(_AIX)
#  define PLATFORM_AIX
#elif defined(__Lynx__)
#  define PLATFORM_LYNX
#elif defined(__GNU__)
#  define PLATFORM_HURD
#elif defined(__QNXNTO__)
#  define PLATFORM_QNX
#elif defined(__INTEGRITY)
#  define PLATFORM_INTEGRITY
#elif defined(VXWORKS) /* there is no "real" VxWorks define - this has to be set in the mkspec! */
#  define PLATFORM_VXWORKS
#elif defined(__HAIKU__)
#  define PLATFORM_HAIKU
#elif defined(__MAKEDEPEND__)
#else
#  error "Qt has not been ported to this OS - see https://www.qt.io/developers"
#endif

#if defined(PLATFORM_WIN32) || defined(PLATFORM_WIN64) || defined(PLATFORM_WINRT)
#  define PLATFORM_WIN
#endif

#if defined(PLATFORM_WIN)
#  undef PLATFORM_UNIX
#elif !defined(PLATFORM_UNIX)
#  define PLATFORM_UNIX
#endif

// Compatibility synonyms
#ifdef PLATFORM_DARWIN
#define PLATFORM_MAC
#endif
#ifdef PLATFORM_DARWIN32
#define PLATFORM_MAC32
#endif
#ifdef PLATFORM_DARWIN64
#define PLATFORM_MAC64
#endif
#ifdef PLATFORM_MACOS
#define PLATFORM_MACX
#define PLATFORM_OSX
#endif

#ifdef PLATFORM_DARWIN
#  include <Availability.h>
#  include <AvailabilityMacros.h>
# 
#  ifdef PLATFORM_MACOS
#    if !defined(__MAC_OS_X_VERSION_MIN_REQUIRED) || __MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_6
#       undef __MAC_OS_X_VERSION_MIN_REQUIRED
#       define __MAC_OS_X_VERSION_MIN_REQUIRED __MAC_10_6
#    endif
#    if !defined(MAC_OS_X_VERSION_MIN_REQUIRED) || MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_6
#       undef MAC_OS_X_VERSION_MIN_REQUIRED
#       define MAC_OS_X_VERSION_MIN_REQUIRED MAC_OS_X_VERSION_10_6
#    endif
#  endif
# 
#  // Numerical checks are preferred to named checks, but to be safe
#  // we define the missing version names in case Qt uses them.
# 
#  if !defined(__MAC_10_11)
#       define __MAC_10_11 101100
#  endif
#  if !defined(__MAC_10_12)
#       define __MAC_10_12 101200
#  endif
#  if !defined(__MAC_10_13)
#       define __MAC_10_13 101300
#  endif
#  if !defined(__MAC_10_14)
#       define __MAC_10_14 101400
#  endif
#  if !defined(MAC_OS_X_VERSION_10_11)
#       define MAC_OS_X_VERSION_10_11 101100
#  endif
#  if !defined(MAC_OS_X_VERSION_10_12)
#       define MAC_OS_X_VERSION_10_12 101200
#  endif
#  if !defined(MAC_OS_X_VERSION_10_13)
#       define MAC_OS_X_VERSION_10_13 101300
#  endif
#  if !defined(MAC_OS_X_VERSION_10_14)
#       define MAC_OS_X_VERSION_10_14 101400
#  endif
# 
#  if !defined(__IPHONE_10_0)
#       define __IPHONE_10_0 100000
#  endif
#  if !defined(__IPHONE_10_1)
#       define __IPHONE_10_1 100100
#  endif
#  if !defined(__IPHONE_10_2)
#       define __IPHONE_10_2 100200
#  endif
#  if !defined(__IPHONE_10_3)
#       define __IPHONE_10_3 100300
#  endif
#  if !defined(__IPHONE_11_0)
#       define __IPHONE_11_0 110000
#  endif
#  if !defined(__IPHONE_12_0)
#       define __IPHONE_12_0 120000
#  endif
#endif

#ifdef __LSB_VERSION__
#  if __LSB_VERSION__ < 40
#    error "This version of the Linux Standard Base is unsupported"
#  endif
#ifndef QT_LINUXBASE
#  define QT_LINUXBASE
#endif
#endif


//////////////////////////////////////////////////
// Supported platform check
// 
#if !(defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS) || defined(PLATFORM_WIN))
	#error "This platform is unsupported."
#endif


//////////////////////////////////////////////////
// Language header
// 
//Large file size support
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	#define _FILE_OFFSET_BITS   64     //File offset data type size(64 bits).
#endif

//C Standard Library and C++ Standard Template Library/STL header
#include <algorithm>               //Collection of functions especially designed to be used on ranges of elements algorithm support
#include <array>                   //Container that encapsulates fixed size arrays support
#include <atomic>                  //Atomic type support
#include <condition_variable>      //Condition variable support
#include <deque>                   //Double-ended queue support
#include <functional>              //Function objects are objects specifically designed to be used with a syntax similar to that of functions support
#include <list>                    //List container support
#include <memory>                  //General utilities to manage dynamic memory support
#include <mutex>                   //Facilities that allow mutual exclusion (mutex) of concurrent execution of critical sections of code, allowing to explicitly avoid data races support
#include <queue>                   //Queue and priority_queue container adaptor support
#include <random>                  //Random number generation facilities support
#include <regex>                   //Regular expressions are a standardized way to express patterns to be matched against sequences of characters support
#include <stack>                   //Stack container support
#include <thread>                  //Thread support
#include <unordered_map>           //Unordered_map and unordered_multimap container support
#include <unordered_set>           //Unordered_set and unordered_multiset container support

//Library header
#if defined(PLATFORM_WIN)
//LibEvent
	#include "..\\Dependency\\LibEvent\\Include_Windows\\event2\\event.h"
	#include "..\\Dependency\\LibEvent\\Include_Windows\\event2\\buffer.h"
	#include "..\\Dependency\\LibEvent\\Include_Windows\\event2\\bufferevent.h"

//LibSodium
#ifndef ENABLE_LIBSODIUM
	#define ENABLE_LIBSODIUM
#ifndef SODIUM_STATIC
	#define SODIUM_STATIC
#endif
#endif
#if defined(ENABLE_LIBSODIUM)
	#include "..\\Dependency\\LibSodium\\Include_Windows\\sodium.h"
#endif

//Npcap header
#ifndef ENABLE_PCAP
	#define ENABLE_PCAP
#ifndef WPCAP
	#define WPCAP
#endif
#ifndef HAVE_REMOTE
	#define HAVE_REMOTE
#endif
#endif
#if defined(ENABLE_PCAP)
	#include "..\\Dependency\\Npcap\\Include\\pcap.h"
#endif

/*
//Windows API header
//Part 1 including files
	#include <direct.h>                //Functions for directory handling and creation
	#include <winsock2.h>              //WinSock 2.0+ support

//Part 2 including files(MUST be included after Part 1)
*/
	#include <mstcpip.h>               //Microsoft-specific extensions to the core Winsock definitions
	#include <mswsock.h>               //Microsoft-specific extensions to the Windows Sockets API
/*
	#include <windns.h>                //Windows DNS definitions and DNS API
	#include <ws2tcpip.h>              //WinSock 2.0+ Extension for TCP/IP protocols

//Part 3 including files(MUST be included after Part 2)
//	#include <windows.h>               //Windows master header file

//Part 4 including files(MUST be included after Part 3)
	#include <iphlpapi.h>              //IP Stack for MIB-II and related functionality
*/
	#include <sddl.h>                  //Support and conversions routines necessary for SDDL
/*
//Part 5 including files(MUST be included after Part 4)
#ifndef ENABLE_TLS
//	#define ENABLE_TLS
#endif
#if defined(ENABLE_TLS)
	#define SECURITY_WIN32
	#include <schannel.h>              //Public Definitions for SSPI/SCHANNEL Security Provider
	#include <sspi.h>                  //Security Support Provider Interface
#endif
*/

//Library linking
	#pragma comment(lib, "iphlpapi.lib")   //Windows IP Helper, IP Stack for MIB-II and related functionality support
	#pragma comment(lib, "ws2_32.lib")     //Windows WinSock 2.0+ support
#if defined(ENABLE_TLS)
	#pragma comment(lib, "secur32.lib")    //Security Support Provider Interface support
#endif
#if defined(PLATFORM_WIN64)
	#pragma comment(lib, "..\\Dependency\\LibEvent\\LibEvent_Core_x64.lib")
#if defined(ENABLE_LIBSODIUM)
	#pragma comment(lib, "..\\Dependency\\LibSodium\\LibSodium_x64.lib")
#endif
#if defined(ENABLE_PCAP)
	#pragma comment(lib, "..\\Dependency\\Npcap\\WPCAP_x64.lib")
	#pragma comment(lib, "..\\Dependency\\Npcap\\Packet_x64.lib")
#endif
#elif defined(PLATFORM_WIN32)
	#pragma comment(lib, "..\\Dependency\\LibEvent\\LibEvent_Core_x86.lib")
#if defined(ENABLE_LIBSODIUM)
	#pragma comment(lib, "..\\Dependency\\LibSodium\\LibSodium_x86.lib")
#endif
#if defined(ENABLE_PCAP)
	#pragma comment(lib, "..\\Dependency\\Npcap\\WPCAP_x86.lib")
	#pragma comment(lib, "..\\Dependency\\Npcap\\Packet_x86.lib")
#endif
#endif

//Endian definition
//x86 and x86-64/x64 is Little Endian.
	#define __LITTLE_ENDIAN            1234
	#define __BIG_ENDIAN               4321
	#define __BYTE_ORDER               __LITTLE_ENDIAN
	#define LITTLE_ENDIAN              __LITTLE_ENDIAN
	#define BIG_ENDIAN                 __BIG_ENDIAN
	#define BYTE_ORDER                 __BYTE_ORDER

//Winsock definition
	#define WINSOCK_VERSION_BYTE_HIGH  2
	#define WINSOCK_VERSION_BYTE_LOW   2

//Compatible definition
	typedef SSIZE_T                    ssize_t;
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//C Standard Library and C++ Standard Template Library/STL header
	#include <cerrno>                      //Error report support
	#include <climits>                     //Data limits support
	#include <csignal>                     //Signals support
	#include <cstdarg>                     //Variable arguments handling support
	#include <cstddef>                     //Definitions support
	#include <cstdint>                     //Integer types support
	#include <cstring>                     //Strings support
	#include <cwchar>                      //Wide characters support

//Portable Operating System Interface/POSIX and Unix system header
	#include <fcntl.h>                     //Manipulate file descriptor support
	#include <ifaddrs.h>                   //Getting network interface addresses support
	#include <netdb.h>                     //Network database operations support
	#include <pthread.h>                   //Threads support
	#include <unistd.h>                    //Standard library API support
	#include <arpa/inet.h>                 //Internet operations support
	#include <netinet/tcp.h>               //TCP protocol support
	#include <sys/file.h>                  //File descriptor support
	#include <sys/socket.h>                //Socket support
	#include <sys/stat.h>                  //Getting information about files attributes support
	#include <sys/time.h>                  //Date and time support
	#include <sys/types.h>                 //Types support

#if defined(PLATFORM_FREEBSD)
	#include <netinet/in.h>                //Internet Protocol family support
	#include <sys/endian.h>                //Endian support
#elif defined(PLATFORM_LINUX)
	#include <endian.h>                    //Endian support
#elif defined(PLATFORM_MACOS)
	#define __LITTLE_ENDIAN                1234                         //Little Endian
	#define __BIG_ENDIAN                   4321                         //Big Endian
	#define __BYTE_ORDER                   __LITTLE_ENDIAN              //x86 and x86-64/x64 is Little Endian.
#endif

//Library header
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX))
//LibEvent
	#include <event2/event.h>
	#include <event2/buffer.h>
	#include <event2/bufferevent.h>

//LibSodium
#if defined(ENABLE_LIBSODIUM)
	#include <sodium.h>
#endif

//LibPcap
#if defined(ENABLE_PCAP)
	#include <pcap/pcap.h>
#endif

//OpenSSL
#if defined(ENABLE_TLS)
	#include <openssl/bio.h>
	#include <openssl/conf.h>
	#include <openssl/err.h>
	#include <openssl/ssl.h>
	#include <openssl/x509v3.h>
#endif
#elif defined(PLATFORM_MACOS)
//LibEvent
#if defined(PLATFORM_MACOS_XCODE)
	#include "../Dependency/LibEvent/Include_macOS/event2/event.h"
	#include "../Dependency/LibEvent/Include_macOS/event2/buffer.h"
	#include "../Dependency/LibEvent/Include_macOS/event2/bufferevent.h"
	#pragma comment(lib, "../Dependency/LibEvent/LibEvent_Core_macOS.a")
#else
	#include <event2/event.h>
	#include <event2/buffer.h>
	#include <event2/bufferevent.h>
#endif

//LibSodium
#if defined(PLATFORM_MACOS_XCODE)
#ifndef ENABLE_LIBSODIUM
	#define ENABLE_LIBSODIUM
#endif
#ifndef SODIUM_STATIC
	#define SODIUM_STATIC
#endif
	#include "../Dependency/LibSodium/Include_macOS/sodium.h"
	#pragma comment(lib, "../Dependency/LibSodium/LibSodium_macOS.a")
#else
#if defined(ENABLE_LIBSODIUM)
#ifndef SODIUM_STATIC
	#define SODIUM_STATIC
#endif
	#include <sodium.h>
#endif
#endif

//LibPcap
#if defined(PLATFORM_MACOS_XCODE)
#ifndef ENABLE_PCAP
	#define ENABLE_PCAP
#endif
#endif
#if defined(ENABLE_PCAP)
	#include <pcap/pcap.h>
#endif

//OpenSSL
#if defined(PLATFORM_MACOS_XCODE)
#ifndef ENABLE_TLS
	#define ENABLE_TLS
#endif
	#include "../Dependency/OpenSSL/Include/openssl/bio.h"
	#include "../Dependency/OpenSSL/Include/openssl/conf.h"
	#include "../Dependency/OpenSSL/Include/openssl/err.h"
	#include "../Dependency/OpenSSL/Include/openssl/ssl.h"
	#include "../Dependency/OpenSSL/Include/openssl/x509v3.h"
	#pragma comment(lib, "../Dependency/OpenSSL/LibCrypto_macOS.a")
	#pragma comment(lib, "../Dependency/OpenSSL/LibSSL_macOS.a")
#else
#if defined(ENABLE_TLS)
	#include <openssl/bio.h>
	#include <openssl/conf.h>
	#include <openssl/err.h>
	#include <openssl/ssl.h>
	#include <openssl/x509v3.h>
#endif
#endif
#endif

//Conditional define for TCP Fast Open
#if defined(PLATFORM_FREEBSD)
#ifndef TCP_FASTOPEN
	#define TCP_FASTOPEN                   1025
#endif
#elif defined(PLATFORM_LINUX)
#ifndef _KERNEL_FASTOPEN
	#define _KERNEL_FASTOPEN
#ifndef TCP_FASTOPEN
	#define TCP_FASTOPEN                   23
#endif
#ifndef TCP_FASTOPEN_CONNECT
	#define TCP_FASTOPEN_CONNECT           30
#endif
#ifndef MSG_FASTOPEN
	#define MSG_FASTOPEN                   0x20000000
#endif
#endif
#endif

//Network definition
#ifndef INVALID_SOCKET
	#define INVALID_SOCKET             (-1)
#endif
	#define SOCKET_ERROR               (-1)
	#define SD_BOTH                    SHUT_RDWR
	#define SD_RECV                    SHUT_RD
	#define SD_SEND                    SHUT_WR
	#define WSAEAFNOSUPPORT            EAFNOSUPPORT
	#define WSAEHOSTUNREACH            EHOSTUNREACH
	#define WSAENETUNREACH             ENETUNREACH
	#define WSAENOTSOCK                ENOTSOCK
	#define WSAETIMEDOUT               ETIMEDOUT

//Function definition
	#define closesocket                                                       close
	#define fwprintf_s                                                        fwprintf
	#define strnlen_s                                                         strnlen
	#define vfwprintf_s                                                       vfwprintf
	#define wcsnlen_s                                                         wcsnlen
	#define WSAGetLastError()                                                 (errno)
	#define _set_errno(Value)                                                 (errno = (Value))
	#define fread_s(Destination, DestinationSize, ElementSize, Count, File)   fread((Destination), (ElementSize), (Count), (File))
	#define memcpy_s(Destination, DestinationSize, Source, Size)              memcpy((Destination), (Source), (Size))
	#define memmove_s(Destination, DestinationSize, Source, Size)             memmove((Destination), (Source), (Size))
	#define strncpy_s(Destination, DestinationSize, Source, Size)             strncpy((Destination), (Source), (Size))
	#define wcsncpy_s(Destination, DestinationSize, Source, Size)             wcsncpy((Destination), (Source), (Size))
#endif


//////////////////////////////////////////////////
// Library version check
// 
//LibEvent, require 2.1.8-stable and above.
#define VERSION_REQUIRE_LIBEVENT          0x02010800
#if LIBEVENT_VERSION_NUMBER < VERSION_REQUIRE_LIBEVENT
	#error "The version of LibEvent is too old."
#endif

//LibSodium, require 1.0.17 and above.
#if defined(ENABLE_LIBSODIUM)
#define VERSION_REQUIRE_LIBSODIUM_MAJOR   10
#define VERSION_REQUIRE_LIBSODIUM_MINOR   2
#if !(SODIUM_LIBRARY_VERSION_MAJOR >= VERSION_REQUIRE_LIBSODIUM_MAJOR && SODIUM_LIBRARY_VERSION_MINOR >= VERSION_REQUIRE_LIBSODIUM_MINOR)
	#error "The version of LibSodium is too old."
#endif
#endif

//Npcap or Libpcap
#if defined(ENABLE_PCAP)
#if defined(PLATFORM_WIN)
//Windows: Require level 2 + 4 and above.
#define VERSION_REQUIRE_PCAP_MAJOR        2
#define VERSION_REQUIRE_PCAP_MINOR        4
#if !(PCAP_VERSION_MAJOR >= VERSION_REQUIRE_PCAP_MAJOR && PCAP_VERSION_MINOR >= VERSION_REQUIRE_PCAP_MINOR)
	#error "The version of Npcap is too old."
#endif
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//FreeBSD, Linux and macOS: Require level 2 + 4 and above.
#define VERSION_REQUIRE_PCAP_MAJOR        2
#define VERSION_REQUIRE_PCAP_MINOR        4
#if !(PCAP_VERSION_MAJOR >= VERSION_REQUIRE_PCAP_MAJOR && PCAP_VERSION_MINOR >= VERSION_REQUIRE_PCAP_MINOR)
	#error "The version of LibPcap is too old."
#endif
#endif
#endif

//OpenSSL, require 1.0.2 and above.
#if defined(ENABLE_TLS)
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	#define OPENSSL_VERSION_1_0_2             0x10002000L
	#define OPENSSL_VERSION_1_1_0             0x10100000L
	#define OPENSSL_VERSION_1_1_1             0x10101000L
	#define VERSION_REQUIRE_OPENSSL           OPENSSL_VERSION_1_0_2
#if OPENSSL_VERSION_NUMBER < VERSION_REQUIRE_OPENSSL
	#error "The version of OpenSSL is too old."
#endif
#endif
#endif
#endif
