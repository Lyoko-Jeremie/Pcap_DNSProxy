// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
// Copyright (C) 2012-2014 Chengr28
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
// Base Header
//C Standard Library Headers
//#include <cstdlib>                 //C Standard Library
//#include <cstdio>                  //File Input/Output
#include <ctime>                   //Date&Time

//C++ Standard Template Library/STL Headers
//#include <string>                  //String support
#include <vector>                  //Vector support
#include <deque>                   //Double-ended queue support
#include <memory>                  //Manage dynamic memory support
#include <regex>                   //Regular expression support
#include <thread>                  //Thread support
#include <mutex>                   //Mutex lock‎ support
#include <random>                  //Random-number generator support
//#include <functional>              //Function object support

//LibSodium Headers
/*
#include "LibSodium\core.h"
#include "LibSodium\crypto_box.h"
#include "LibSodium\crypto_sign_ed25519.h"
#include "LibSodium\crypto_box_curve25519xsalsa20poly1305.h"
#include "LibSodium\randombytes.h"
#include "LibSodium\randombytes_salsa20_random.h"
*/
#include "LibSodium\sodium.h"

//SHA-3(Keccak, FIPS-202 Draft) Header
#include "Keccak\KeccakHash.h"

//WinPcap Header
#include "WinPcap\pcap.h"

//Windows API Headers
//#include <VersionHelpers.h>        //Version Helper functions
#include <tchar.h>                 //Unicode(UTF-8/UTF-16)/Wide-Character Support
//#include <winsock2.h>              //WinSock 2.0+(MUST be including before windows.h)
//#include <winsvc.h>                //Service Control Manager
//#include <iphlpapi.h>              //IP Stack for MIB-II and related functionality
//#include <ws2tcpip.h>              //WinSock 2.0+ Extension for TCP/IP protocols
//#include <mstcpip.h>               //Microsoft-specific extensions to the core Winsock definitions.
//#include <windns.h>
//#include <windows.h>               //Master include file

//Static librarys
#pragma comment(lib, "ws2_32.lib")            //WinSock 2.0+
//#pragma comment(lib, "iphlpapi.lib")        //IP Stack for MIB-II and related functionality
#ifdef _WIN64
	#pragma comment(lib, "WinPcap/wpcap_x64.lib") //WinPcap library(x64)
	#pragma comment(lib, "LibSodium/libsodium_x64.lib") //LibSodium library(x64)
#else 
	#pragma comment(lib, "WinPcap/wpcap_x86.lib") //WinPcap library(x86)
	#pragma comment(lib, "LibSodium/libsodium_x86.lib") //LibSodium library(x86)
#endif


//////////////////////////////////////////////////
// Base defines
#pragma pack(1)                             //Memory alignment: 1 bytes/8 bits
#define __LITTLE_ENDIAN   1U                //Little Endian
#define __BIG_ENDIAN      2U                //Big Endian
#define __BYTE_ORDER      __LITTLE_ENDIAN   //x86 and x86-64/x64

// Code defines
#define WINSOCK_VERSION_LOW    2                         //Low byte of Winsock version
#define WINSOCK_VERSION_HIGH   2                         //High byte of Winsock version
#define KILOBYTE_TIMES         1024U                     //1KB = 1024 bytes
#define MEGABYTE_TIMES         1048576U                  //1MB = 1048576 bytes
#define GIGABYTE_TIMES         1073741824U               //1GB = 1073741824 bytes
#define LineFeed               0x0A                      //Line Feed, LF
#define CarriageReturn         0x0D                      //Carriage Return, CR
#define SIO_UDP_CONNRESET      _WSAIOW(IOC_VENDOR, 12)

// Text Codepage define
#define ANSI              1U       //ANSI Codepage
#define UTF_8             65001U   //Microsoft Windows Codepage of UTF-8
#define UTF_16_LE         1200U    //Microsoft Windows Codepage of UTF-16 Little Endian/LE
#define UTF_16_BE         1201U    //Microsoft Windows Codepage of UTF-16 Big Endian/BE
#define UTF_32_LE         12000U   //Microsoft Windows Codepage of UTF-32 Little Endian/LE
#define UTF_32_BE         12001U   //Microsoft Windows Codepage of UTF-32 Big Endian/BE

//#pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup") //Hide console.
//Remember to add "WPCAP" and "HAVE_REMOTE" to preprocessor options!
//Remember to add "SODIUM_STATIC" and "SODIUM_EXPORT=" to preprocessor options!

//////////////////////////////////////////////////
// Protocol Header structures
/* Ethernet II Frame Header in OSI Layer 2(RFC 894, https://tools.ietf.org/html/rfc894)

                    1                   2                   3
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
|  FCS  |                                                          FCS/Ethernet Frame Check Sequence
+-+-+-+-+

*/
//Type defines
//#define ETHERTYPE_ARP      0x0806  //(Dynamic)RARP
//#define ETHERTYPE_RARP     0x8035  //RARP
#define ETHERTYPE_IP       0x0800  //IPv4 over Ethernet
#define ETHERTYPE_IPV6     0x86DD  //IPv6 over Ethernet
//#define ETHERTYPE_PPPOED   0x8863  //PPPoE(Discovery Stage)
#define ETHERTYPE_PPPOES   0x8864  //PPPoE(Session Stage)
//#define ETHERTYPE_EAPOL    0x888E  //802.1X
typedef struct _eth_hdr
{
	uint8_t                Dst[6U];
	uint8_t                Src[6U];
	uint16_t               Type;
}eth_hdr;

/* Point-to-Point Protocol over Ethernet/PPPoE Header(RFC 2516, https://tools.ietf.org/rfc/rfc2516)

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  Type |     Code      |           SessionID           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Length            |            Protocol           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
//Type defines
#define PPPOETYPE_IPV4     0x0021  //IPv4 over PPPoE
#define PPPOETYPE_IPV6     0x0057  //IPv6 over PPPoE
typedef struct _pppoe_hdr
{
	uint8_t                VersionType;
	uint8_t                Code;
	uint16_t               SessionID;
	uint16_t               Length;
	uint16_t               Protocol;
}pppoe_hdr;

/* 802.1X Protocol Header(RFC 3580, https://tools.ietf.org/html/rfc3580)

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Type      |             Length            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

typedef struct _802_1x_hdr
{
	uint8_t                Version;
	uint8_t                Type;
	uint16_t               Length;
};
*/

/* Internet Protocol version 4/IPv4 Header(RFC 791, https://www.ietf.org/rfc/rfc791)

                    1                   2                   3
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
#define IPV4_STANDARDIHL             0x05 //Standard IPv4 header length(0x05/20 bytes)
#define IPv4_IHL_BYTES_TIMES         4U   //IHL is the number of 32-bit words(4 bytes).
#define IPV4_SHORTEST_ADDRSTRING     6U   //The shortest address strings(*.*.*.*).
typedef struct _ipv4_hdr
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
	in_addr                Src;
	in_addr                Dst;
}ipv4_hdr;

/* Internet Protocol version 6/IPv6 Header(RFC 2460, https://tools.ietf.org/html/rfc2460‎)

                    1                   2                   3
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
#define IPV6_SHORTEST_ADDRSTRING     3U   //The shortest address strings(::).
typedef struct _ipv6_hdr
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
	in6_addr                   Src;
	in6_addr                   Dst;
}ipv6_hdr;

/* Generic Routing Encapsulation/GRE Protocol Header(RFC 2784, https://tools.ietf.org/html/rfc2784)

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|C|K|S|     Reserved0     |VER|          Protocol Type          |  VER/Version
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Checksum(Optional)       |      Reserved1(Optional)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Key(Optional)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Sequence Number(Optional)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#define IPPROTO_GRE 47
typedef struct _gre_hdr
{
	uint16_t               Flags_Version;
	uint16_t               Type;
}gre_hdr;
*/

/* Internet Control Message Protocol/ICMP Header(RFC 792, https://tools.ietf.org/html/rfc792)

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Identification         |           Sequence            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      TimeStamp(Optional)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define ICMP_TYPE_ECHO   0
#define ICMP_CODE_ECHO   0
typedef struct _icmp_hdr
{
	uint8_t                Type;
	uint8_t                Code;
	uint16_t               Checksum;
	uint16_t               ID;
	uint16_t               Sequence;
//	uint32_t               TimeStamp;
}icmp_hdr;

/* Internet Control Message Protocol version 6/ICMPv6 Header(RFC 4443, https://tools.ietf.org/html/rfc4443)

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Identification         |           Sequence            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Nonce(Optional)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define ICMPV6_REQUEST     128
#define ICMPV6_TYPE_REPLY  129
#define ICMPV6_CODE_REPLY  0
typedef struct _icmpv6_hdr
{
	uint8_t                Type;
	uint8_t                Code;
	uint16_t               Checksum;
	uint16_t               ID;
	uint16_t               Sequence;
//	uint16_t               Nonce;
}icmpv6_hdr;

/* Transmission Control Protocol/TCP Header(RFC 675/793/1122/2581/5681, https://tools.ietf.org/html/rfc675, https://tools.ietf.org/html/rfc793, https://tools.ietf.org/html/rfc1122, https://tools.ietf.org/html/rfc2581, https://tools.ietf.org/html/rfc5681)

                    1                   2                   3
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
/                            Options                            /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#define TCP_STANDARDHL     5       //Standard TCP header length
#define TCP_SYN_ACK_STATUS 0x012   //SYN bit and ACK bit was set.
#define TCP_RST_STATUS     0x004   //RST bit was set.

//Port defines(1 - 1024)
//About this list, see https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
#define IPPORT_SSH                  22U
#define IPPORT_RAP                  38U
#define IPPORT_RLP                  39U
#define IPPORT_TACACS               49U
#define IPPORT_XNSAUTH              56U
#define IPPORT_BOOTPS               67U
#define IPPORT_BOOTPC               68U
#define IPPORT_HTTP                 80U
#define IPPORT_HTTPBACKUP           81U
#define IPPORT_SUNRPC               111U
#define IPPORT_SQL                  118U
#define IPPORT_BFTP                 152U
#define IPPORT_SGMP                 153U
#define IPPORT_SQLSRV               156U
#define IPPORT_DMSP                 158U
#define IPPORT_ATRTMP               201U
#define IPPORT_ATHBP                202U
#define IPPORT_QMTP                 209U
#define IPPORT_IPX                  213U
#define IPPORT_BGMP                 264U
#define IPPORT_TSP                  318U
#define IPPORT_IMMP                 323U
#define IPPORT_ODMR                 366U
#define IPPORT_RPC2PORTMAP          369U
#define IPPORT_CLEARCASE            371U
#define IPPORT_HPALARMMGR           383U
#define IPPORT_ARNS                 384U
#define IPPORT_AURP                 387U
#define IPPORT_UPS                  401U
#define IPPORT_SLP                  427U
#define IPPORT_SNPP                 444U
#define IPPORT_KPASSWD              464U
#define IPPORT_TCPNETHASPSRV        475U
#define IPPORT_RETROSPECT           497U
#define IPPORT_ISAKMP               500U
#define IPPORT_SYSLOG               514U
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

typedef struct _tcp_hdr
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
}tcp_hdr;

/* User Datagram Protocol/UDP Header(RFC 768, https://tools.ietf.org/html/rfc768)

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define IPPORT_TEREDO      3544U        //Teredo tunneling port
typedef struct _udp_hdr
{
	uint16_t               SrcPort;
	uint16_t               DstPort;
	uint16_t               Length;
	uint16_t               Checksum;
}udp_hdr;

/* Transmission Control Protocol/TCP and User Datagram Protocol/UDP Pseudo Header with IPv4(RFC 675/768/793/1122/2581/5681, https://tools.ietf.org/html/rfc675, https://tools.ietf.org/html/rfc768, https://tools.ietf.org/html/rfc793, https://tools.ietf.org/html/rfc1122, https://tools.ietf.org/html/rfc2581, https://tools.ietf.org/html/rfc5681)

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Source Address                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Destination Address                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Zeros     |   Protocol    |          Data Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _ipv4_psd_hdr
{
	in_addr               Src;
	in_addr               Dst;
	uint8_t               Zero;
	uint8_t               Protocol;
	uint16_t              Length;
}ipv4_psd_hdr;

/* Internet Control Message Protocol version 6/ICMPv6, Transmission Control Protocol/TCP and User Datagram Protocol/UDP Pseudo Header with IPv4(RFC 675/768/793/1122/2581/4443/5681, https://tools.ietf.org/html/rfc675, https://tools.ietf.org/html/rfc768, https://tools.ietf.org/html/rfc793, https://tools.ietf.org/html/rfc1122, https://tools.ietf.org/html/rfc2581, https://tools.ietf.org/html/rfc4443, https://tools.ietf.org/html/rfc5681)

                    1                   2                   3
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
typedef struct _ipv6_psd_hdr
{
	in6_addr              Src;
	in6_addr              Dst;
	uint32_t              Length;
	uint8_t               Zero[3U];
	uint8_t               Next_Header;
}ipv6_psd_hdr;

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
RFC 1591(https://tools.ietf.org/html/rfc1591), Domain Name System Structure and Delegation (Informational)
RFC 1912(https://tools.ietf.org/html/rfc1912), Common DNS Operational and Configuration Errors
RFC 1995(https://tools.ietf.org/html/rfc1995), Incremental Zone Transfer in DNS
RFC 1996(https://tools.ietf.org/html/rfc1996), A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
RFC 2100(https://tools.ietf.org/html/rfc2100), The Naming of Hosts (Informational)
RFC 2136(https://tools.ietf.org/html/rfc2136), Dynamic Updates in the domain name system (DNS UPDATE)
RFC 2181(https://tools.ietf.org/html/rfc2181), Clarifications to the DNS Specification
RFC 2182(https://tools.ietf.org/html/rfc2182), Selection and Operation of Secondary DNS Servers
RFC 2308(https://tools.ietf.org/html/rfc2308), Negative Caching of DNS Queries (DNS NCACHE)
RFC 2317(https://tools.ietf.org/html/rfc2317), Classless IN-ADDR.ARPA delegation (BCP 20)
RFC 2671(https://tools.ietf.org/html/rfc2671), Extension Mechanisms for DNS (EDNS0)
RFC 2672(https://tools.ietf.org/html/rfc2672), Non-Terminal DNS Name Redirection
RFC 2845(https://tools.ietf.org/html/rfc2845), Secret Key Transaction Authentication for DNS (TSIG)
RFC 3225(https://tools.ietf.org/html/rfc3225), Indicating Resolver Support of DNSSEC
RFC 3226(https://tools.ietf.org/html/rfc3226), DNSSEC and IPv6 A6 aware server/resolver message size requirements
RFC 3597(https://tools.ietf.org/html/rfc3597), Handling of Unknown DNS Resource Record (RR) Types
RFC 3696(https://tools.ietf.org/html/rfc3696), Application Techniques for Checking and Transformation of Names (Informational)
RFC 4343(https://tools.ietf.org/html/rfc4343), Domain Name System (DNS) Case Insensitivity Clarification
RFC 4592(https://tools.ietf.org/html/rfc4592), The Role of Wildcards in the Domain Name System
RFC 4635(https://tools.ietf.org/html/rfc4635), HMAC SHA TSIG Algorithm Identifiers
RFC 4892(https://tools.ietf.org/html/rfc4892), Requirements for a Mechanism Identifying a Name Server Instance (Informational)
RFC 5001(https://tools.ietf.org/html/rfc5001), DNS Name Server Identifier (NSID) Option
RFC 5452(https://tools.ietf.org/html/rfc5452), Measures for Making DNS More Resilient against Forged Answers
RFC 5625(https://tools.ietf.org/html/rfc5625), DNS Proxy Implementation Guidelines (BCP 152)
RFC 5890(https://tools.ietf.org/html/rfc5890), Internationalized Domain Names for Applications (IDNA):Definitions and Document Framework
RFC 5891(https://tools.ietf.org/html/rfc5891), Internationalized Domain Names in Applications (IDNA): Protocol
RFC 5892(https://tools.ietf.org/html/rfc5892), The Unicode Code Points and Internationalized Domain Names for Applications (IDNA)
RFC 5893(https://tools.ietf.org/html/rfc5893), Right-to-Left Scripts for Internationalized Domain Names for Applications (IDNA)
RFC 5894(https://tools.ietf.org/html/rfc5894), Internationalized Domain Names for Applications (IDNA):Background, Explanation, and Rationale (Informational)
RFC 5895(https://tools.ietf.org/html/rfc5895), Mapping Characters for Internationalized Domain Names in Applications (IDNA) 2008 (Informational)
RFC 5966(https://tools.ietf.org/html/rfc5966), DNS Transport over TCP - Implementation Requirements
RFC 6195(https://tools.ietf.org/html/rfc6195), Domain Name System (DNS) IANA Considerations (BCP 42)
*/

//Default Port and Record Types defines
#define IPPORT_DNS              53U      //DNS Port(TCP and UDP)
#define DNS_STANDARD            0x0100   //System Standard query
#define DNS_SQRNE               0x8180   //Standard query response and no error.
#define DNS_SQRNE_TC            0x8380   //Standard query response and no error, but Truncated.
#define DNS_SQRNE_FE            0x8181   //Standard query response, Format Error
#define DNS_SQRNE_SF            0x8182   //Standard query response, Server failure
#define DNS_NO_SUCH_NAME        0x8183   //Standard query response, but no such name.
#define DNS_RCODE_NO_SUCH_NAME  0x0003   //RCode is 0x0003(No Such Name).
#define DNS_A_RECORDS           0x0001   //DNS A records, its ID is 1.
#define DNS_NS_RECORDS          0x0002   //DNS NS records, its ID is 2.
#define DNS_CNAME_RECORDS       0x0005   //DNS CNAME records, its ID is 5.
#define DNS_SOA_RECORDS         0x0006   //DNS SOA records, its ID is 6.
#define DNS_PTR_RECORDS         0x000C   //DNS PTR records, its ID is 12.
#define DNS_MX_RECORDS          0x000F   //DNS MX records, its ID is 15.
#define DNS_TXT_RECORDS         0x0010   //DNS TXT records, its ID is 16.
#define DNS_RP_RECORDS          0x0011   //DNS RP records, its ID is 17.
#define DNS_SIG_RECORDS         0x0018   //DNS SIG records, its ID is 24.
#define DNS_KEY_RECORDS         0x0019   //DNS KEY records, its ID is 25.
#define DNS_AAAA_RECORDS        0x001C   //DNS AAAA records, its ID is 28.
#define DNS_LOC_RECORDS         0x001D   //DNS LOC records, its ID is 29.
#define DNS_SRV_RECORDS         0x0021   //DNS SRV records, its ID is 33.
#define DNS_NAPTR_RECORDS       0x0023   //DNS NAPTR records, its ID is 35.
#define DNS_KX_RECORDS          0x0024   //DNS KX records, its ID is 36.
#define DNS_CERT_RECORDS        0x0025   //DNS CERT records, its ID is 37.
#define DNS_DNAME_RECORDS       0x0027   //DNS DNAME records, its ID is 39.
#define DNS_EDNS0_RECORDS       0x0029   //DNS EDNS0 Label/OPT records, its ID is 41.
#define DNS_APL_RECORDS         0x002A   //DNS APL records, its ID is 42.
#define DNS_DS_RECORDS          0x002B   //DNS DS records, its ID is 43.
#define DNS_SSHFP_RECORDS       0x002C   //DNS SSHFP records, its ID is 44.
#define DNS_IPSECKEY_RECORDS    0x002D   //DNS IPSECKEY records, its ID is 45.
#define DNS_RRSIG_RECORDS       0x002E   //DNS RRSIG records, its ID is 46.
#define DNS_NSEC_RECORDS        0x002F   //DNS NSEC records, its ID is 47.
#define DNS_DNSKEY_RECORDS      0x0030   //DNS DNSKEY records, its ID is 48.
#define DNS_DHCID_RECORDS       0x0031   //DNS DHCID records, its ID is 49.
#define DNS_NSEC3_RECORDS       0x0032   //DNS NSEC3 records, its ID is 50.
#define DNS_NSEC3PARAM_RECORDS  0x0033   //DNS NSEC3PARAM records, its ID is 51.
#define DNS_HIP_RECORDS         0x0037   //DNS HIP records, its ID is 55.
#define DNS_SPF_RECORDS         0x0063   //DNS SPF records, its ID is 99.
#define DNS_TKEY_RECORDS        0x00F9   //DNS TKEY records, its ID is 249.
#define DNS_TSIG_RECORDS        0x00FA   //DNS TSIG records, its ID is 250.
#define DNS_IXFR_RECORDS        0x00FB   //DNS IXFR records, its ID is 251.
#define DNS_AXFR_RECORDS        0x00FC   //DNS AXFR records, its ID is 252.
#define DNS_ANY_RECORDS         0x00FF   //DNS ANY records, its ID is 255.
#define DNS_TA_RECORDS          0x8000   //DNS TA records, its ID is 32768.
#define DNS_DLV_RECORDS         0x8001   //DNS DLV records, its ID is 32769.
#define DNS_CLASS_IN            0x0001   //DNS Class INTERNET, its ID is 1.
#define DNS_CLASS_CSNET         0x0002   //DNS Class CSNET, its ID is 2.
#define DNS_CLASS_CHAOS         0x0003   //DNS Class CHAOS, its ID is 3.
#define DNS_CLASS_HESIOD        0x0004   //DNS Class HESIOD, its ID is 4.
#define DNS_CLASS_NONE          0x00FE   //DNS Class NONE, its ID is 254.
#define DNS_CLASS_ALL           0x00FF   //DNS Class ALL, its ID is 255.
#define DNS_CLASS_ANY           0x00FF   //DNS Class ANY, its ID is 255.
#define DNS_QUERY_PTR           0xC00C   //Pointer of first query
#define DNS_TTL_PROBABLY_FAKE_1 300U     //DNS TTL witch is probably fake, 300 seconds or 5 minutes.
#define DNS_TTL_PROBABLY_FAKE_2 25600U   //DNS TTL witch is probably fake, 25600 seconds.

/*
// With User Datagram Protocol/UDP

                    1                   2                   3
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
#define OLD_DNS_MAXSIZE 512U
typedef struct _dns_hdr
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
}dns_hdr;

/*
//With Transmission Control Protocol/TCP

                    1                   2                   3
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
typedef struct _tcp_dns_hdr
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
}tcp_dns_hdr;

/* Domain Name System/DNS Query

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Domain                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |            Classes            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_qry
{
//	PUCHAR                Name;
	uint16_t              Type;
	uint16_t              Classes;
}dns_qry;

/* Domain Name System/DNS A(IPv4) Records

                    1                   2                   3
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
typedef struct _dns_a_
{
	uint16_t              Name;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
	in_addr               Addr;
}dns_a_record;

/* Domain Name System/DNS Canonical Name/CNAME Records

                    1                   2                   3
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
typedef struct _dns_cname_
{
	uint16_t              Name;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
//	PUCHAR                PrimaryName;
}dns_cname_record;

/* Domain Name System/DNS Pointer/PTR Records

                    1                   2                   3
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
typedef struct _dns_ptr_
{
	uint16_t              PTR;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
//	PUCHAR                Name;
}dns_ptr_record;

/* Domain Name System/DNS AAAA(IPv6) Records

                    1                   2                   3
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
typedef struct _dns_aaaa_
{
	uint16_t              Name;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
	in6_addr              Addr;
}dns_aaaa_record;

/* Domain Name System/DNS Test Strings/TXT Records

                    1                   2                   3
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
/                              TXT                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _dns_txt_
{
	uint16_t              Name;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
	uint8_t               TXT_Length;
//	PUCHAR                TXT;
}dns_txt_record;

/* Extension Mechanisms for Domain Name System/DNS, EDNS0 Label/OPT Resource

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Domain                             /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Type              |       UDP Payload Size        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Extended RCode | EDNS0 Version |D|          Reserved           |  Extended RCode/Higher bits in extended Return Code, D/DO bit
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |\---------- Z Field -----------/
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define EDNS0_MINSIZE 1220U
typedef struct _dns_edns0_
{
	uint8_t               Name;
	uint16_t              Type;              //Additional RRs Type
	uint16_t              UDPPayloadSize;
	uint8_t               Extended_RCode;
	uint8_t               Version;           //EDNS0 Version
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
}dns_edns0_label;

//Domain Name System Curve/DNSCurve Part
// About DNSCurve standards, see http://dnscurve.org
// About DNSCrypt, see http://dnscrypt.org
#define DNSCURVE_MAGIC_QUERY_LEN   8U
#define DNSCRYPT_RECEIVE_MAGIC     ("r6fnvWj8")                //Receive Magic Number
#define DNSCRYPT_CERT_MAGIC        ("DNSC")                    //Signature Magic Number
#define crypto_box_HALF_NONCEBYTES (crypto_box_NONCEBYTES / 2U)
#define DNSCRYPT_TXT_RECORDS_LEN   124U                        //Length of DNScrypt TXT records

/* Domain Name System Curve/DNSCurve Test Strings/TXT Data Header

                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Certificate Magic Number                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Version(Major)         |        Version(Minor)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define DNSCURVE_VERSION_MAJOR     0x0001    //Major version of DNSCurve
#define DNSCURVE_VERSION_MINOR     0         //Minor version of DNSCurve
typedef struct _dnscurve_txt_hdr_
{
	uint32_t              CertMagicNumber;
	uint16_t              MajorVersion;
	uint16_t              MinorVersion;
}dnscurve_txt_hdr;

/* Domain Name System Curve/DNSCurve Signature with Test Strings/TXT Data

                    1                   2                   3
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
}dnscurve_txt_signature;
