// This code is part of Pcap_DNSProxy
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
//C Standard Library header
#include <cstdio>                   //I/O Functions
#include <ctime>                   //Time Functions
#include <cstring>                 //C Style String
#include <cerrno>                  //System Error report

//C++ Standard Template Library/STL header
#include <thread>                  //Thread
#include <vector>                  //Vector
#include <string>                  //String

//Linux header
#include <regex.h>                   //Regular Expression
#include <unistd.h>
#include <limits.h>
#include <sys/socket.h>
#include <wchar.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

//LibPcap header
#include <pcap/pcap.h>


//////////////////////////////////////////////////
// Base Define
#pragma pack(1)                    //Memory alignment: 1 bytes/8 bits


//////////////////////////////////////////////////
// Protocol Header structures
//Ethernet Frame Header
//ARP = ETHERTYPE_ARP/0x0806 & RARP = ETHERTYPE_RARP/0x8035
//PPPoE(Connecting) = ETHERTYPE_PPPOED/0x8863
//802.1X = ETHERTYPE_EAPOL/0x888E
#define ETHERTYPE_IP       0x0800  //IPv4 over Ethernet
#define ETHERTYPE_IPV6     0x86DD  //IPv6 over Ethernet
#define ETHERTYPE_PPPOES   0x8864  //PPPoE(Transmission)
typedef struct _eth_hdr
{
	uint8_t                  Dst[6];
	uint8_t                  Src[6];
	uint16_t                 Type;
}eth_hdr;

//Point-to-Point Protocol over Ethernet/PPPoE Header
#define PPPOETYPE_IPV4     0x0021  //IPv4 over PPPoE
#define PPPOETYPE_IPV6     0x0057  //IPv6 over PPPoE
typedef struct _pppoe_hdr
{
	uint8_t                  VersionType;
	uint8_t                  Code;
	uint16_t                 SessionID;
	uint16_t                 Length;
	uint16_t                 Protocol;
}pppoe_hdr;

/*
//802.1X Protocol Header
typedef struct _802_1x_hdr
{
	uint8_t                  Version;
	uint8_t                  Type;
	uint16_t                 Length;
};
*/

//Internet Protocol version 4/IPv4 Address(From Microsoft Windows)
typedef struct _in_addr_windows_
{
	union {
		struct {
			uint8_t s_b1, s_b2, s_b3, s_b4;
		}S_un_b;
		struct {
			uint16_t s_w1, s_w2;
		}S_un_w;
	uint32_t S_addr;
	}S_un;
}in_addr_Windows;

//Internet Protocol version 4/IPv4 Header
typedef struct _ipv4_hdr
{
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t                  IHL:4;         //Header Length
	uint8_t                  Version:4;
#else //BIG_ENDIAN
	uint8_t                  Version:4;
	uint8_t                  IHL:4;         //Header Length
#endif
	union {
		uint8_t              TOS;           //Type of service, but RFC 2474 redefine it to DSCP and ECN
		struct {
		#if BYTE_ORDER == LITTLE_ENDIAN
			uint8_t          DSCP_First:4;  //DiffServ/Differentiated Services first part
			uint8_t          ECN:2;         //Explicit Congestion Notification
			uint8_t          DSCP_Second:2; //DiffServ/Differentiated Services second part
		#else //BIG_ENDIAN
			uint8_t          DSCP:6;        //DiffServ/Differentiated Services
			uint8_t          ECN:2;         //Explicit Congestion Notification
		#endif
		}TOSBits;
	};
	uint16_t                 Length;
	uint16_t                 ID;
	union {
		uint16_t             Flags;
		struct {
		#if BYTE_ORDER == LITTLE_ENDIAN
			uint8_t          FO_First:4;    //Fragment Offset first part
			uint8_t          Zero:1;        //Reserved bit
			uint8_t          DF:1;          //Don't Fragment
			uint8_t          MF:1;          //More Fragments
			uint8_t          FO_Second_A:1; //Fragment Offset Second-A part
			uint8_t          FO_Second_B;   //Fragment Offset Second-B part
		#else //BIG_ENDIAN
			uint8_t          Zero:1;        //Reserved bit
			uint8_t          DF:1;          //Don't Fragment
			uint8_t          MF:1;          //More Fragments
			uint8_t          FO_First_A:1;  //Fragment Offset First-A part
			uint8_t          FO_First_B:4;  //Fragment Offset First-B part
			uint8_t          FO_Second;     //Fragment Offset second part
		#endif
		}FlagsBits;
	};
	uint8_t                  TTL;
	uint8_t                  Protocol;
	uint16_t                 Checksum;
	in_addr                Src;
	in_addr                Dst;
}ipv4_hdr;

//Internet Protocol version 6/IPv6 Header
typedef struct _ipv6_hdr
{
	union {
		uint32_t              VerTcFlow;
		struct {
#if BYTE_ORDER == LITTLE_ENDIAN
			uint8_t          TrafficClass_First:4;     //Traffic Class first part
			uint8_t          Version:4;
			uint8_t          FlowLabel_First:4;        //Traffic Class second part
			uint8_t          TrafficClass_Second:4;    //Traffic Class second part
			uint16_t         FlowLabel_Second;         //Flow Label second part
#else //BIG_ENDIAN
			uint8_t          Version:4;
			uint8_t          TrafficClass_First:4;     //Traffic Class first part
			uint8_t          TrafficClass_Second:4;    //Traffic Class second part
			uint8_t          FlowLabel_First:4;        //Flow Label first part
			uint16_t         FlowLabel_Second;         //Flow Label second part
#endif
		}VerTcFlowBits;
	};
	uint16_t                 PayloadLength;
	uint8_t                  NextHeader;
	uint8_t                  HopLimit;
	in6_addr               Src;
	in6_addr               Dst;
}ipv6_hdr;

/*
//Generic Routing Encapsulation/GRE Protocol Header
#define IPPROTO_GRE 47
typedef struct _gre_hdr
{
	uint16_t                Flags_Version;
	uint16_t                Type;
}gre_hdr;
*/

//Internet Control Message Protocol/ICMP Header(Linux)
typedef struct _icmp_hdr
{
	uint8_t                 Type;
	uint8_t                 Code;
	uint16_t                Checksum;
	uint16_t                ID;
	uint16_t                Sequence;
	uint64_t                TimeStamp;
	uint64_t                Nonce;
}icmp_hdr;

//Internet Control Message Protocol version 6/ICMPv6 Header
#define ICMPV6_REQUEST    128
#define ICMPV6_REPLY      129
typedef struct _icmpv6_hdr
{
	uint8_t                 Type;
	uint8_t                 Code;
	uint16_t                Checksum;
	uint16_t                ID;
	uint16_t                Sequence;
//	uint8_t                Nonce;
}icmpv6_hdr;

//Transmission Control Protocol/TCP Header
typedef struct _tcp_hdr
{
	uint16_t                Src_Port;
	uint16_t                Dst_Port;
	uint32_t                 Sequence;
	uint32_t                 Acknowledge;
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t                 Reserved_First:4;
	uint8_t                 HeaderLength:4;
	union {
		struct {
			uint8_t         Flags:6;
			uint8_t         Reseverd_Second:2;
		}FlagsAll;
		struct {
			uint8_t         PSH:1;
			uint8_t         RST:1;
			uint8_t         SYN:1;
			uint8_t         FIN:1;
			uint8_t         URG:1;
			uint8_t         ACK:1;
			uint8_t         Reseverd_Second:2;
		}FlagsBits;
	};
#else //BIG_ENDIAN
	uint8_t                 Header_Length:4;
	uint8_t                 Reserved_First:4;
	union {
		struct {
			uint8_t         Reseverd_Second:2;
			uint8_t         Flags:6;
		}FlagsAll;
		struct {
			uint8_t         Reseverd_Second:2;
			uint8_t         URG:1;
			uint8_t         ACK:1;
			uint8_t         PSH:1;
			uint8_t         RST:1;
			uint8_t         SYN:1;
			uint8_t         FIN:1;
		}FlagsBits;
	};
#endif
	uint16_t                Windows;
	uint16_t                Checksum;
	uint16_t                Urgent_Pointer;
}tcp_hdr;

//User Datagram Protocol/UDP Header
typedef struct _udp_hdr
{
	uint16_t                Src_Port;
	uint16_t                Dst_Port;
	uint16_t                Length;
	uint16_t                Checksum;
}udp_hdr;

//TCP or UDP Pseudo Header(Get Checksum) with IPv4
typedef struct _ipv4_psd_hdr
{
	in_addr               Src;
	in_addr               Dst;
	uint8_t                 Zero;
	uint8_t                 Protocol;
	uint16_t                Length;
}ipv4_psd_hdr;

//ICMPv6, TCP or UDP Pseudo Header(Get Checksum) with IPv6
typedef struct _ipv6_psd_hdr
{
	in6_addr              Src;
	in6_addr              Dst;
	uint32_t                 Length;
	uint8_t                 Zero[3];
	uint8_t                 Next_Header;
}ipv6_psd_hdr;

//DNS Header
#define DNS_Port          53       //DNS Port(TCP and UDP)
// DNS Records ID
#define Class_IN          0x0001   //DNS Class IN, its ID is 1
#define A_Records         0x0001   //DNS A records, its ID is 1
#define CNAME_Records     0x0005   //DNS CNAME records, its ID is 5
#define PTR_Records       0x000C   //DNS PTR records, its ID is 12
#define AAAA_Records      0x001C   //DNS AAAA records, its ID is 28
typedef struct _dns_hdr
{
	uint16_t                ID;
	union {
		uint16_t            Flags;
	#if BYTE_ORDER == LITTLE_ENDIAN
		struct {
			uint8_t         OPCode_Second:1;
			uint8_t         AA:1;             //Authoritative Answer
			uint8_t         TC:1;             //Truncated
			uint8_t         RD:1;             //Recursion Desired
			uint8_t         QR:1;             //Response
			uint8_t         OPCode_First:3;
			uint8_t         RCode:4;          //Reply code
			uint8_t         RA:1;             //Recursion available
			uint8_t         Zero:1;           //Reserved
			uint8_t         AD:1;             //Answer authenticated
			uint8_t         CD:1;             //Non-authenticated data
	#else //BIG_ENDIAN
		struct {
			uint8_t         QR:1;             //Response
			uint8_t         OPCode:4;
			uint8_t         AA:1;             //Authoritative
			uint8_t         TC:1;             //Truncated
			uint8_t         RD:1;             //Recursion desired
			uint8_t         RA:1;             //Recursion available
			uint8_t         Zero:1;           //Reserved
			uint8_t         AD:1;             //Answer authenticated
			uint8_t         CD:1;             //Non-authenticated data
			uint8_t         RCode:4;          //Reply code
	#endif
		}FlagsBits;
	};
	uint16_t                Questions;
	uint16_t                Answer;
	uint16_t                Authority;
	uint16_t                Additional;
}dns_hdr;

//DNS Query
typedef struct _dns_qry
{
//	u_char                   *Name;
	uint16_t                Type;
	uint16_t                Classes;
}dns_qry;

//DNS A record response
typedef struct _dns_a_
{
	uint16_t                Name;
	uint16_t                Type;
	uint16_t                Classes;
	uint32_t                 TTL;
	uint16_t                Length;
	in_addr                Addr;
}dns_a_record;

//DNS CNAME record response
typedef struct _dns_cname_
{
	uint16_t                PTR;
	uint16_t                Type;
	uint16_t                Classes;
	uint32_t                TTL;
	uint16_t                Length;
//	u_char                   *PrimaryName;
}dns_cname_record;

//DNS PTR record response
typedef struct _dns_ptr_
{
	uint16_t                Name;
	uint16_t                Type;
	uint16_t                Classes;
	uint32_t                TTL;
	uint16_t                Length;
//	u_char                   *DomainName;
}dns_ptr_record;

//DNS AAAA record response
typedef struct _dns_aaaa_
{
	uint16_t                Name;
	uint16_t                Type;
	uint16_t                Classes;
	uint32_t                 TTL;
	uint16_t                Length;
	in6_addr                 Addr;
}dns_aaaa_record;
