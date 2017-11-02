// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2017 Chengr28
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


#ifndef PCAP_DNSPROXY_STRUCTURE_H
#define PCAP_DNSPROXY_STRUCTURE_H

#include "Platform.h"

//Memory alignment settings(Part 1)
#pragma pack(push) //Push current alignment to stack.
#pragma pack(1) //Set alignment to 1 byte boundary.

//////////////////////////////////////////////////
// Protocol Header structures
// 
/* Ethernet II Frame header in OSI Layer 2
* IEEE 802.2/802.3, IEEE Standard for Local and Metropolitan Area Networks(https://standards.ieee.org/about/get/802/802.html)
* RFC 894, A Standard for the Transmission of IP Datagrams over Ethernet Networks(https://tools.ietf.org/html/rfc894)

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
#define OSI_L2_VLAN         0x8100   //Virtual Bridged LAN
#define OSI_L2_PPPD         0x8863   //PPPoE(Discovery Stage)
#define OSI_L2_PPPS         0x8864   //PPPoE(Session Stage)
//#define FCS_TABLE_SIZE      256U     //FCS Table size
typedef struct _eth_hdr_
{
	uint8_t                Destination[6U];
	uint8_t                Source[6U];
	uint16_t               Type;
//	uint8_t                *Payload;
//	uint32_t               FCS;
}eth_hdr;

/* Apple IEEE 1394/FireWire header
* IEEE 1394-1995, IEEE Standard for a High Performance Serial Bus(https://standards.ieee.org/findstds/standard/1394-1995.html)
* RFC 2734, IPv4 over IEEE 1394(https://tools.ietf.org/html/rfc2734)
* RFC 3146, Transmission of IPv6 Packets over IEEE 1394 Networks(https://tools.ietf.org/html/rfc3146)

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
	uint8_t                Destination[8U];
	uint8_t                Source[8U];
	uint16_t               Type;
}ieee_1394_hdr;

/* IEEE 802.1Q
* Media Access Control Bridges and Virtual Bridged Local Area Networks/VLAN(https://www.ietf.org/meeting/86/tutorials/86-IEEE-8021-Thaler.pdf)

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  P  |C|          ID           |             Type              |   P/Priority, C/CFI/Canonical
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _ieee_8021q_hdr_
{
	union {
		uint16_t           Flags;
		struct {
		#if BYTE_ORDER == LITTLE_ENDIAN
			uint8_t        ID_First:4;
			uint8_t        Canonical:1;
			uint8_t        Priority:3;
			uint8_t        ID_Second;
		#else //BIG_ENDIAN
			uint8_t        Priority:3;
			uint8_t        Canonical:1;
			uint8_t        ID_First:4;
			uint8_t        ID_Second;
		#endif
		}Flags_Bits;
	};
	uint16_t               Type;
}ieee_8021q_hdr;


/* Point-to-Point Protocol /PPP header
* RFC 2516, A Method for Transmitting PPP Over Ethernet (PPPoE)(https://tools.ietf.org/html/rfc2516)

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
}ppp_hdr;

//Internet Protocol Numbers
//About this list, please visit IANA Assigned Internet Protocol Numbers(https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
#ifndef IPPROTO_HOPOPTS
	#define IPPROTO_HOPOPTS           0                    //IPv6 Hop-by-Hop Option
#endif
#ifndef IPPROTO_ICMP
	#define IPPROTO_ICMP              1U                   //Internet Control Message
#endif
#ifndef IPPROTO_IGMP
	#define IPPROTO_IGMP              2U                   //Internet Group Management
#endif
#ifndef IPPROTO_GGP
	#define IPPROTO_GGP               3U                   //Gateway-to-Gateway
#endif
#ifndef IPPROTO_IPV4
	#define IPPROTO_IPV4              4U                   //IPv4 encapsulation
#endif
#ifndef IPPROTO_ST
	#define IPPROTO_ST                5U                   //Stream
#endif
#ifndef IPPROTO_TCP
	#define IPPROTO_TCP               6U                   //Transmission Control
#endif
#ifndef IPPROTO_CBT
	#define IPPROTO_CBT               7U                   //Core Based Tree
#endif
#ifndef IPPROTO_EGP
	#define IPPROTO_EGP               8U                   //Exterior Gateway Protocol
#endif
#ifndef IPPROTO_IGP
	#define IPPROTO_IGP               9U                   //Any private interior gateway
#endif
#ifndef IPPROTO_BBN_RCC_MON
	#define IPPROTO_BBN_RCC_MON       10U                  //BBN RCC Monitoring
#endif
#ifndef IPPROTO_NVP_II
	#define IPPROTO_NVP_II            11U                  //Network Voice Protocol
#endif
#ifndef IPPROTO_PUP
	#define IPPROTO_PUP               12U                  //PUP
#endif
#ifndef IPPROTO_ARGUS
	#define IPPROTO_ARGUS             13U                  //ARGUS
#endif
#ifndef IPPROTO_EMCON
	#define IPPROTO_EMCON             14U                  //EMCON
#endif
#ifndef IPPROTO_XNET
	#define IPPROTO_XNET              15U                  //Cross Net Debugger
#endif
#ifndef IPPROTO_CHAOS
	#define IPPROTO_CHAOS             16U                  //Chaos
#endif
#ifndef IPPROTO_UDP
	#define IPPROTO_UDP               17U                  //User Datagram
#endif
#ifndef IPPROTO_MUX
	#define IPPROTO_MUX               18U                  //Multiplexing
#endif
#ifndef IPPROTO_DCN
	#define IPPROTO_DCN               19U                  //DCN Measurement Subsystems
#endif
#ifndef IPPROTO_HMP
	#define IPPROTO_HMP               20U                  //Host Monitoring
#endif
#ifndef IPPROTO_PRM
	#define IPPROTO_PRM               21U                  //Packet Radio Measurement
#endif
#ifndef IPPROTO_IDP
	#define IPPROTO_IDP               22U                  //XEROX NS IDP
#endif
#ifndef IPPROTO_TRUNK_1
	#define IPPROTO_TRUNK_1           23U                  //Trunk-1
#endif
#ifndef IPPROTO_TRUNK_2
	#define IPPROTO_TRUNK_2           24U                  //Trunk-2
#endif
#ifndef IPPROTO_LEAF_1
	#define IPPROTO_LEAF_1            25U                  //Leaf-1
#endif
#ifndef IPPROTO_LEAF_2
	#define IPPROTO_LEAF_2            26U                  //Leaf-2
#endif
#ifndef IPPROTO_RDP
	#define IPPROTO_RDP               27U                  //Reliable Data Protocol
#endif
#ifndef IPPROTO_IRTP
	#define IPPROTO_IRTP              28U                  //Internet Reliable Transaction
#endif
#ifndef IPPROTO_ISO_TP4
	#define IPPROTO_ISO_TP4           29U                  //ISO Transport Protocol Class 4
#endif
#ifndef IPPROTO_NETBLT
	#define IPPROTO_NETBLT            30U                  //Bulk Data Transfer Protocol
#endif
#ifndef IPPROTO_MFE
	#define IPPROTO_MFE               31U                  //MFE Network Services Protocol
#endif
#ifndef IPPROTO_MERIT
	#define IPPROTO_MERIT             32U                  //MERIT Internodal Protocol
#endif
#ifndef IPPROTO_DCCP
	#define IPPROTO_DCCP              33U                  //Datagram Congestion Control Protocol
#endif
#ifndef IPPROTO_3PC
	#define IPPROTO_3PC               34U                  //Third Party Connect Protocol
#endif
#ifndef IPPROTO_IDPR
	#define IPPROTO_IDPR              35U                  //Inter-Domain Policy Routing Protocol
#endif
#ifndef IPPROTO_XTP
	#define IPPROTO_XTP               36U                  //XTP
#endif
#ifndef IPPROTO_DDP
	#define IPPROTO_DDP               37U                  //Datagram Delivery Protocol
#endif
#ifndef IPPROTO_IDPR_CMTP
	#define IPPROTO_IDPR_CMTP         38U                  //IDPR Control Message Transport Proto
#endif
#ifndef IPPROTO_TPPLUS
	#define IPPROTO_TPPLUS            39U                  //TP++ Transport Protocol
#endif
#ifndef IPPROTO_IL
	#define IPPROTO_IL                40U                  //IL Transport Protocol
#endif
#ifndef IPPROTO_IPV6
	#define IPPROTO_IPV6              41U                  //IPv6 encapsulation
#endif
#ifndef IPPROTO_SDRP
	#define IPPROTO_SDRP              42U                  //Source Demand Routing Protocol
#endif
#ifndef IPPROTO_ROUTING
	#define IPPROTO_ROUTING           43U                  //Route Routing Header for IPv6
#endif
#ifndef IPPROTO_FRAGMENT
	#define IPPROTO_FRAGMENT          44U                  //Frag Fragment Header for IPv6
#endif
#ifndef IPPROTO_IDRP
	#define IPPROTO_IDRP              45U                  //Inter - Domain Routing Protocol
#endif
#ifndef IPPROTO_RSVP
	#define IPPROTO_RSVP              46U                  //Reservation Protocol
#endif
#ifndef IPPROTO_GRE
	#define IPPROTO_GRE               47U                  //Generic Routing Encapsulation
#endif
#ifndef IPPROTO_DSR
	#define IPPROTO_DSR               48U                  //Dynamic Source Routing Protocol
#endif
#ifndef IPPROTO_BNA
	#define IPPROTO_BNA               49U                  //BNA
#endif
#ifndef IPPROTO_ESP
	#define IPPROTO_ESP               50U                  //Encap Security Payload
#endif
#ifndef IPPROTO_AH
	#define IPPROTO_AH                51U                  //Authentication Header
#endif
#ifndef IPPROTO_NLSP
	#define IPPROTO_NLSP              52U                  //Integrated Net Layer Security TUBA
#endif
#ifndef IPPROTO_SWIPE
	#define IPPROTO_SWIPE             53U                  //IP with Encryption
#endif
#ifndef IPPROTO_NARP
	#define IPPROTO_NARP              54U                  //NBMA Address Resolution Protocol
#endif
#ifndef IPPROTO_MOBILE
	#define IPPROTO_MOBILE            55U                  //IP Mobility
#endif
#ifndef IPPROTO_TLSP
	#define IPPROTO_TLSP              56U                  //Transport Layer Security Protocol using Kryptonet key management
#endif
#ifndef IPPROTO_SKIP
	#define IPPROTO_SKIP              57U                  //SKIP
#endif
#ifndef IPPROTO_ICMPV6
	#define IPPROTO_ICMPV6            58U                  //ICMP for IPv6
#endif
#ifndef IPPROTO_NONE
	#define IPPROTO_NONE              59U                  //No Next Header for IPv6
#endif
#ifndef IPPROTO_DSTOPTS
	#define IPPROTO_DSTOPTS           60U                  //Destination Options for IPv6
#endif
#ifndef IPPROTO_AHI
	#define IPPROTO_AHI               61U                  //Any host internal protocol
#endif
#ifndef IPPROTO_CFTP
	#define IPPROTO_CFTP              62U                  //CFTP
#endif
#ifndef IPPROTO_ALN
	#define IPPROTO_ALN               63U                  //Any local network
#endif
#ifndef IPPROTO_SAT
	#define IPPROTO_SAT               64U                  //EXPAK SATNET and Backroom EXPAK
#endif
#ifndef IPPROTO_KRYPTOLAN
	#define IPPROTO_KRYPTOLAN         65U                  //Kryptolan
#endif
#ifndef IPPROTO_RVD
	#define IPPROTO_RVD               66U                  //MIT Remote Virtual Disk Protocol
#endif
#ifndef IPPROTO_IPPC
	#define IPPROTO_IPPC              67U                  //Internet Pluribus Packet Core
#endif
#ifndef IPPROTO_ADF
	#define IPPROTO_ADF               68U                  //Any distributed file system
#endif
#ifndef IPPROTO_SAT_MON
	#define IPPROTO_SAT_MON           69U                  //SATNET Monitoring
#endif
#ifndef IPPROTO_VISA
	#define IPPROTO_VISA              70U                  //VISA Protocol
#endif
#ifndef IPPROTO_IPCV
	#define IPPROTO_IPCV              71U                  //Internet Packet Core Utility
#endif
#ifndef IPPROTO_CPNX
	#define IPPROTO_CPNX              72U                  //Computer Protocol Network Executive
#endif
#ifndef IPPROTO_CPHB
	#define IPPROTO_CPHB              73U                  //Computer Protocol Heart Beat
#endif
#ifndef IPPROTO_WSN
	#define IPPROTO_WSN               74U                  //Wang Span Network
#endif
#ifndef IPPROTO_PVP
	#define IPPROTO_PVP               75U                  //Packet Video Protocol
#endif
#ifndef IPPROTO_BR
	#define IPPROTO_BR                76U                  //SAT - MON Backroom SATNET Monitoring
#endif
#ifndef IPPROTO_ND
	#define IPPROTO_ND                77U                  //SUN ND PROTOCOL - Temporary
#endif
#ifndef IPPROTO_ICLFXBM
	#define IPPROTO_ICLFXBM           78U                  //WIDEBAND Monitoring
#endif
#ifndef IPPROTO_WBEXPAK
	#define IPPROTO_WBEXPAK           79U                  //WIDEBAND EXPAK
#endif
#ifndef IPPROTO_ISO
	#define IPPROTO_ISO               80U                  //IP ISO Internet Protocol
#endif
#ifndef IPPROTO_VMTP
	#define IPPROTO_VMTP              81U                  //VMTP
#endif
#ifndef IPPROTO_SVMTP
	#define IPPROTO_SVMTP             82U                  //SECURE - VMTP
#endif
#ifndef IPPROTO_VINES
	#define IPPROTO_VINES             83U                  //VINES
#endif
#ifndef IPPROTO_TTP
	#define IPPROTO_TTP               84U                  //Transaction Transport Protocol
#endif
#ifndef IPPROTO_IPTM
	#define IPPROTO_IPTM              85U                  //Internet Protocol Traffic ManageR
#endif
#ifndef IPPROTO_NSFNET
	#define IPPROTO_NSFNET            86U                  //NSFNET - IGP
#endif
#ifndef IPPROTO_DGP
	#define IPPROTO_DGP               87U                  //Dissimilar Gateway Protocol
#endif
#ifndef IPPROTO_TCF
	#define IPPROTO_TCF               88U                  //TCF
#endif
#ifndef IPPROTO_EIGRP
	#define IPPROTO_EIGRP             89U                  //EIGRP
#endif
#ifndef IPPROTO_SPRITE
	#define IPPROTO_SPRITE            90U                  //RPC Sprite RPC Protocol
#endif
#ifndef IPPROTO_LARP
	#define IPPROTO_LARP              91U                  //Locus Address Resolution Protocol
#endif
#ifndef IPPROTO_MTP
	#define IPPROTO_MTP               92U                  //Multicast Transport Protocol
#endif
#ifndef IPPROTO_AX25
	#define IPPROTO_AX25              93U                  //AX.25 Frames
#endif
#ifndef IPPROTO_IPIP
	#define IPPROTO_IPIP              94U                  //IP - within - IP Encapsulation Protocol
#endif
#ifndef IPPROTO_MICP
	#define IPPROTO_MICP              95U                  //Mobile Internetworking Control Pro.
#endif
#ifndef IPPROTO_SCC
	#define IPPROTO_SCC               96U                  //Semaphore Communications Sec.Pro.
#endif
#ifndef IPPROTO_ETHERIP
	#define IPPROTO_ETHERIP           97U                  //Ethernet - within - IP Encapsulation
#endif
#ifndef IPPROTO_ENCAP
	#define IPPROTO_ENCAP             98U                  //Encapsulation Header
#endif
#ifndef IPPROTO_APES
	#define IPPROTO_APES              100U                 //Any private encryption scheme
#endif
#ifndef IPPROTO_GMTP
	#define IPPROTO_GMTP              101U                 //GMTP
#endif
#ifndef IPPROTO_IFMP
	#define IPPROTO_IFMP              102U                 //Ipsilon Flow Management Protocol
#endif
#ifndef IPPROTO_PNNI
	#define IPPROTO_PNNI              103U                 //PNNI over IP
#endif
#ifndef IPPROTO_PIM
	#define IPPROTO_PIM               104U                 //Protocol Independent Multicast
#endif
#ifndef IPPROTO_ARIS
	#define IPPROTO_ARIS              105U                 //ARIS
#endif
#ifndef IPPROTO_SCPS
	#define IPPROTO_SCPS              106U                 //SCPS
#endif
#ifndef IPPROTO_QNX
	#define IPPROTO_QNX               107U                 //QNX
#endif
#ifndef IPPROTO_AN
	#define IPPROTO_AN                108U                 //Active Networks
#endif
#ifndef IPPROTO_IPCOMP
	#define IPPROTO_IPCOMP            109U                 //IP Payload Compression Protocol
#endif
#ifndef IPPROTO_SNP
	#define IPPROTO_SNP               110U                 //Sitara Networks Protocol
#endif
#ifndef IPPROTO_COMPAQ
	#define IPPROTO_COMPAQ            111U                 //Peer Compaq Peer Protocol
#endif
#ifndef IPPROTO_IPX
	#define IPPROTO_IPX               112U                 //IP IPX in IP
#endif
#ifndef IPPROTO_PGM
	#define IPPROTO_PGM               113U                 //PGM Reliable Transport Protocol
#endif
#ifndef IPPROTO_0HOP
	#define IPPROTO_0HOP              114U                 //Any 0-hop protocol
#endif
#ifndef IPPROTO_L2TP
	#define IPPROTO_L2TP              115U                 //Layer Two Tunneling Protocol
#endif
#ifndef IPPROTO_DDX
	#define IPPROTO_DDX               116U                 //D - II Data Exchange(DDX)
#endif
#ifndef IPPROTO_IATP
	#define IPPROTO_IATP              117U                 //Interactive Agent Transfer Protocol
#endif
#ifndef IPPROTO_STP
	#define IPPROTO_STP               118U                 //Schedule Transfer Protocol
#endif
#ifndef IPPROTO_SRP
	#define IPPROTO_SRP               119U                 //SRP SpectraLink Radio Protocol
#endif
#ifndef IPPROTO_UTI
	#define IPPROTO_UTI               120U                 //UTI
#endif
#ifndef IPPROTO_SMP
	#define IPPROTO_SMP               121U                 //SMP Simple Message Protocol
#endif
#ifndef IPPROTO_SM
	#define IPPROTO_SM                122U                 //SM Simple Multicast Protocol
#endif
#ifndef IPPROTO_PTP
	#define IPPROTO_PTP               123U                 //PTP Performance Transparency Protocol
#endif
#ifndef IPPROTO_ISIS
	#define IPPROTO_ISIS              124U                 //ISIS over IPv4
#endif
#ifndef IPPROTO_FIRE
	#define IPPROTO_FIRE              125U                 //FIRE
#endif
#ifndef IPPROTO_CRTP
	#define IPPROTO_CRTP              126U                 //Combat Radio Transport Protocol
#endif
#ifndef IPPROTO_CRUDP
	#define IPPROTO_CRUDP             127U                 //Combat Radio User Datagram
#endif
#ifndef IPPROTO_SSCOPMCE
	#define IPPROTO_SSCOPMCE          128U                 //SSCOPMCE
#endif
#ifndef IPPROTO_IPLT
	#define IPPROTO_IPLT              129U                 //IPLT
#endif
#ifndef IPPROTO_SPS
	#define IPPROTO_SPS               130U                 //Secure Packet Shield
#endif
#ifndef IPPROTO_PIPE
	#define IPPROTO_PIPE              131U                 //Private IP Encapsulation within IP
#endif
#ifndef IPPROTO_SCTP
	#define IPPROTO_SCTP              132U                 //Stream Control Transmission Protocol
#endif
#ifndef IPPROTO_FC
	#define IPPROTO_FC                133U                 //Fibre Channel
#endif
#ifndef IPPROTO_RSVP_E2E
	#define IPPROTO_RSVP_E2E          134U                 //RSVP-E2E-IGNORE
#endif
#ifndef IPPROTO_MOBILITY
	#define IPPROTO_MOBILITY          135U                 //Mobility Header
#endif
#ifndef IPPROTO_UDPLITE
	#define IPPROTO_UDPLITE           136U                 //UDP Lite
#endif
#ifndef IPPROTO_MPLS
	#define IPPROTO_MPLS              137U                 //MPLS in IP
#endif
#ifndef IPPROTO_MANET
	#define IPPROTO_MANET             138U                 //MANET Protocols
#endif
#ifndef IPPROTO_HIP
	#define IPPROTO_HIP               139U                 //Host Identity Protocol
#endif
#ifndef IPPROTO_SHIM6
	#define IPPROTO_SHIM6             140U                 //Shim6 Protocol
#endif
#ifndef IPPROTO_WESP
	#define IPPROTO_WESP              141U                 //Wrapped Encapsulating Security Payload
#endif
#ifndef IPPROTO_ROHC
	#define IPPROTO_ROHC              142U                 //Robust Header Compression
#endif
#ifndef IPPROTO_TEST_1
	#define IPPROTO_TEST_1            253U                 //Use for experimentation and testing
#endif
#ifndef IPPROTO_TEST_2
	#define IPPROTO_TEST_2            254U                 //Use for experimentation and testing
#endif
#ifndef IPPROTO_RESERVED
	#define IPPROTO_RESERVED          255U                 //Reserved
#endif

/* Internet Protocol version 4/IPv4 header
* RFC 791, INTERNET PROTOCOL(https://tools.ietf.org/html/rfc791)
* RFC 2474, Definition of the Differentiated Services Field (DS Field) in the IPv4 and IPv6 Headers(https://tools.ietf.org/html/rfc2474)

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
#define IPV4_IHL_STANDARD            0x05   //Standard IPv4 header length(0x05/20 bytes)
#define IPV4_IHL_BYTES_TIMES         4U     //IHL is number of 32-bit words(4 bytes).
typedef struct _ipv4_hdr_
{
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t                IHL:4;
	uint8_t                Version:4;
#else //BIG_ENDIAN
	uint8_t                Version:4;
	uint8_t                IHL:4;
#endif
	union {
		uint8_t            DSCP_ECN;
		struct {
		#if BYTE_ORDER == LITTLE_ENDIAN
			uint8_t        ECN:2;
			uint8_t        DSCP:6;
		#else //BIG_ENDIAN
			uint8_t        DSCP:6;
			uint8_t        ECN:2;
		#endif
		}DSCP_ECN_Bits;
	};
	uint16_t               Length;
	uint16_t               ID;
	union {
		uint16_t           Flags;
		struct {
		#if BYTE_ORDER == LITTLE_ENDIAN
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
}ipv4_hdr;

/* Internet Protocol version 6/IPv6 header
* RFC 2460, Internet Protocol, Version 6 (IPv6) Specification(https://tools.ietf.org/html/rfc2460)

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
		uint32_t               VersionTrafficFlow;
		struct {
		#if BYTE_ORDER == LITTLE_ENDIAN
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
		}VersionTrafficFlowBits;
	};
	uint16_t                   PayloadLength;
	uint8_t                    NextHeader;
	uint8_t                    HopLimit;
	in6_addr                   Source;
	in6_addr                   Destination;
}ipv6_hdr;

/* Internet Control Message Protocol/ICMP header
* RFC 792, INTERNET CONTROL MESSAGE PROTOCOL(https://tools.ietf.org/html/rfc792)

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
//ICMP Timestamp option is defalut enabled(Linux/macOS).
#if defined(PLATFORM_LINUX)
	uint64_t               Timestamp;
	uint64_t               Nonce;
#elif defined(PLATFORM_MACOS)
	uint64_t               Timestamp;
#endif
}icmp_hdr;

/* Internet Control Message Protocol version 6/ICMPv6 header
* RFC 4443, Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification(https://tools.ietf.org/html/rfc4443)

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
#define ICMPV6_OFFSET_CHECKSUM   2U
#define ICMPV6_TYPE_REQUEST      128U
#define ICMPV6_TYPE_REPLY        129U
#define ICMPV6_CODE_REQUEST      0
#define ICMPV6_CODE_REPLY        0
typedef struct _icmpv6_hdr_
{
	uint8_t                Type;
	uint8_t                Code;
	uint16_t               Checksum;
	uint16_t               ID;
	uint16_t               Sequence;
//ICMPv6 Timestamp option is defalut enabled(Linux/macOS).
#if defined(PLATFORM_LINUX)
	uint64_t               Timestamp;
	uint64_t               Nonce;
#elif defined(PLATFORM_MACOS)
	uint64_t               Timestamp;
#endif
}icmpv6_hdr;

/* Transmission Control Protocol/TCP header
* RFC 675, SPECIFICATION OF INTERNET TRANSMISSION CONTROL PROGRAM(https://tools.ietf.org/html/rfc675)
* RFC 793, TRANSMISSION CONTROL PROTOCOL(https://tools.ietf.org/html/rfc793)
* RFC 1122, Requirements for Internet Hosts -- Communication Layers(https://tools.ietf.org/html/rfc1122)
* RFC 1349, Type of Service in the Internet Protocol Suite(https://tools.ietf.org/html/rfc1349)
* RFC 2401, Security Architecture for the Internet Protocol https://tools.ietf.org/html/rfc2401)
* RFC 2474, Definition of the Differentiated Services Field (DS Field) in the IPv4 and IPv6 Headers https://tools.ietf.org/html/rfc2474)
* RFC 2581, TCP Congestion Control(https://tools.ietf.org/html/rfc2581)
* RFC 3168, The Addition of Explicit Congestion Notification (ECN) to IP https://tools.ietf.org/html/rfc3168)
* RFC 4379, Detecting Multi-Protocol Label Switched (MPLS) Data Plane Failures https://tools.ietf.org/html/rfc4379)
* RFC 5681, TCP Congestion Control(https://tools.ietf.org/html/rfc5681)
* RFC 5884, Bidirectional Forwarding Detection (BFD) for MPLS Label Switched Paths (LSPs) https://tools.ietf.org/html/rfc5884)
* RFC 6093, On the Implementation of the TCP Urgent Mechanism https://tools.ietf.org/html/rfc6093)
* RFC 6298, Computing TCP's Retransmission Timer(https://tools.ietf.org/html/rfc6298)
* RFC 6528, Defending against Sequence Number Attacks https://tools.ietf.org/html/rfc6528)
* RFC 6633, Deprecation of ICMP Source Quench Messages https://tools.ietf.org/html/rfc6633)
* RFC 6864, Updated Specification of the IPv4 ID Field https://tools.ietf.org/html/rfc6864)

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
#define TCP_IHL_STANDARD        5U       //Standard TCP header length
#define TCP_IHL_BYTES_TIMES     4U       //IHL is number of 32-bit words(4 bytes).
#define TCP_FLAG_GET_BIT_IHL    0xF000   //Get data offset in TCP IHL
#define TCP_FLAG_GET_BIT_FLAG   0x0FFF   //Get bits in TCP flag
#define TCP_FLAG_GET_BIT_CWR    0x0080   //Get Congestion Window Reduced bit in TCP flags
#define TCP_FLAG_GET_BIT_ECE    0x0040   //Get ECN-Echo indicates bit in TCP flags
#define TCP_STATUS_RST          0x0004   //TCP status: RST
#define TCP_STATUS_ACK          0x0010   //TCP status: ACK
#define TCP_STATUS_FIN_ACK      0x0011   //TCP status: FIN, ACK
#define TCP_STATUS_SYN_ACK      0x0012   //TCP status: SYN, ACK
#define TCP_STATUS_PSH_ACK      0x0018   //TCP status: PSH, ACK

//Port definitions(1 - 1024, well-known ports)
//About this list, please visit IANA Service Name and Transport Protocol Port Number Registry(https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
#ifndef IPPORT_TCPMUX
	#define IPPORT_TCPMUX               1U
#endif
#ifndef IPPORT_ECHO
	#define IPPORT_ECHO                 7U
#endif
#ifndef IPPORT_DISCARD
	#define IPPORT_DISCARD              9U
#endif
#ifndef IPPORT_SYSTAT
	#define IPPORT_SYSTAT               11U
#endif
#ifndef IPPORT_DAYTIME
	#define IPPORT_DAYTIME              13U
#endif
#ifndef IPPORT_NETSTAT
	#define IPPORT_NETSTAT              15U
#endif
#ifndef IPPORT_QOTD
	#define IPPORT_QOTD                 17U
#endif
#ifndef IPPORT_MSP
	#define IPPORT_MSP                  18U
#endif
#ifndef IPPORT_CHARGEN
	#define IPPORT_CHARGEN              19U
#endif
#ifndef IPPORT_FTP_DATA
	#define IPPORT_FTP_DATA             20U
#endif
#ifndef IPPORT_FTP
	#define IPPORT_FTP                  21U
#endif
#ifndef IPPORT_SSH
	#define IPPORT_SSH                  22U
#endif
#ifndef IPPORT_TELNET
	#define IPPORT_TELNET               23U
#endif
#ifndef IPPORT_SMTP
	#define IPPORT_SMTP                 25U
#endif
#ifndef IPPORT_TIMESERVER
	#define IPPORT_TIMESERVER           37U
#endif
#ifndef IPPORT_RAP
	#define IPPORT_RAP                  38U
#endif
#ifndef IPPORT_RLP
	#define IPPORT_RLP                  39U
#endif
#ifndef IPPORT_NAMESERVER
	#define IPPORT_NAMESERVER           42U
#endif
#ifndef IPPORT_WHOIS
	#define IPPORT_WHOIS                43U
#endif
#ifndef IPPORT_TACACS
	#define IPPORT_TACACS               49U
#endif
#ifndef IPPORT_XNSAUTH
	#define IPPORT_XNSAUTH              56U
#endif
#ifndef IPPORT_MTP
	#define IPPORT_MTP                  57U
#endif
#ifndef IPPORT_BOOTPS
	#define IPPORT_BOOTPS               67U
#endif
#ifndef IPPORT_BOOTPC
	#define IPPORT_BOOTPC               68U
#endif
#ifndef IPPORT_TFTP
	#define IPPORT_TFTP                 69U
#endif
#ifndef IPPORT_RJE
	#define IPPORT_RJE                  77U
#endif
#ifndef IPPORT_FINGER
	#define IPPORT_FINGER               79U
#endif
#ifndef IPPORT_HTTP
	#define IPPORT_HTTP                 80U
#endif
#ifndef IPPORT_HTTPBACKUP
	#define IPPORT_HTTPBACKUP           81U
#endif
#ifndef IPPORT_TTYLINK
	#define IPPORT_TTYLINK              87U
#endif
#ifndef IPPORT_SUPDUP
	#define IPPORT_SUPDUP               95U
#endif
#ifndef IPPORT_POP3
	#define IPPORT_POP3                 110U
#endif
#ifndef IPPORT_SUNRPC
	#define IPPORT_SUNRPC               111U
#endif
#ifndef IPPORT_SQL
	#define IPPORT_SQL                  118U
#endif
#ifndef IPPORT_NTP
	#define IPPORT_NTP                  123U
#endif
#ifndef IPPORT_EPMAP
	#define IPPORT_EPMAP                135U
#endif
#ifndef IPPORT_NETBIOS_NS
	#define IPPORT_NETBIOS_NS           137U
#endif
#ifndef IPPORT_NETBIOS_DGM
	#define IPPORT_NETBIOS_DGM          138U
#endif
#ifndef IPPORT_NETBIOS_SSN
	#define IPPORT_NETBIOS_SSN          139U
#endif
#ifndef IPPORT_IMAP
	#define IPPORT_IMAP                 143U
#endif
#ifndef IPPORT_BFTP
	#define IPPORT_BFTP                 152U
#endif
#ifndef IPPORT_SGMP
	#define IPPORT_SGMP                 153U
#endif
#ifndef IPPORT_SQLSRV
	#define IPPORT_SQLSRV               156U
#endif
#ifndef IPPORT_DMSP
	#define IPPORT_DMSP                 158U
#endif
#ifndef IPPORT_SNMP
	#define IPPORT_SNMP                 161U
#endif
#ifndef IPPORT_SNMP_TRAP
	#define IPPORT_SNMP_TRAP            162U
#endif
#ifndef IPPORT_ATRTMP
	#define IPPORT_ATRTMP               201U
#endif
#ifndef IPPORT_ATHBP
	#define IPPORT_ATHBP                202U
#endif
#ifndef IPPORT_QMTP
	#define IPPORT_QMTP                 209U
#endif
#ifndef IPPORT_IPX
	#define IPPORT_IPX                  213U
#endif
#ifndef IPPORT_IMAP3
	#define IPPORT_IMAP3                220U
#endif
#ifndef IPPORT_BGMP
	#define IPPORT_BGMP                 264U
#endif
#ifndef IPPORT_TSP
	#define IPPORT_TSP                  318U
#endif
#ifndef IPPORT_IMMP
	#define IPPORT_IMMP                 323U
#endif
#ifndef IPPORT_ODMR
	#define IPPORT_ODMR                 366U
#endif
#ifndef IPPORT_RPC2PORTMAP
	#define IPPORT_RPC2PORTMAP          369U
#endif
#ifndef IPPORT_CLEARCASE
	#define IPPORT_CLEARCASE            371U
#endif
#ifndef IPPORT_HPALARMMGR
	#define IPPORT_HPALARMMGR           383U
#endif
#ifndef IPPORT_ARNS
	#define IPPORT_ARNS                 384U
#endif
#ifndef IPPORT_AURP
	#define IPPORT_AURP                 387U
#endif
#ifndef IPPORT_LDAP
	#define IPPORT_LDAP                 389U
#endif
#ifndef IPPORT_UPS
	#define IPPORT_UPS                  401U
#endif
#ifndef IPPORT_SLP
	#define IPPORT_SLP                  427U
#endif
#ifndef IPPORT_HTTPS
	#define IPPORT_HTTPS                443U
#endif
#ifndef IPPORT_SNPP
	#define IPPORT_SNPP                 444U
#endif
#ifndef IPPORT_MICROSOFT_DS
	#define IPPORT_MICROSOFT_DS         445U
#endif
#ifndef IPPORT_KPASSWD
	#define IPPORT_KPASSWD              464U
#endif
#ifndef IPPORT_TCPNETHASPSRV
	#define IPPORT_TCPNETHASPSRV        475U
#endif
#ifndef IPPORT_RETROSPECT
	#define IPPORT_RETROSPECT           497U
#endif
#ifndef IPPORT_ISAKMP
	#define IPPORT_ISAKMP               500U
#endif
#ifndef IPPORT_BIFFUDP
	#define IPPORT_BIFFUDP              512U
#endif
#ifndef IPPORT_WHOSERVER
	#define IPPORT_WHOSERVER			513U
#endif
#ifndef IPPORT_SYSLOG
	#define IPPORT_SYSLOG               514U
#endif
#ifndef IPPORT_ROUTESERVER
	#define IPPORT_ROUTESERVER          520U
#endif
#ifndef IPPORT_NCP
	#define IPPORT_NCP                  524U
#endif
#ifndef IPPORT_COURIER
	#define IPPORT_COURIER              530U
#endif
#ifndef IPPORT_COMMERCE
	#define IPPORT_COMMERCE             542U
#endif
#ifndef IPPORT_RTSP
	#define IPPORT_RTSP                 554U
#endif
#ifndef IPPORT_NNTP
	#define IPPORT_NNTP                 563U
#endif
#ifndef IPPORT_HTTPRPCEPMAP
	#define IPPORT_HTTPRPCEPMAP         593U
#endif
#ifndef IPPORT_IPP
	#define IPPORT_IPP                  631U
#endif
#ifndef IPPORT_LDAPS
	#define IPPORT_LDAPS                636U
#endif
#ifndef IPPORT_MSDP
	#define IPPORT_MSDP                 639U
#endif
#ifndef IPPORT_AODV
	#define IPPORT_AODV                 654U
#endif
#ifndef IPPORT_DNS_TLS
	#define IPPORT_DNS_TLS              853U
#endif
#ifndef IPPORT_FTPSDATA
	#define IPPORT_FTPSDATA             989U
#endif
#ifndef IPPORT_FTPS
	#define IPPORT_FTPS                 990U
#endif
#ifndef IPPORT_NAS
	#define IPPORT_NAS                  991U
#endif
#ifndef IPPORT_TELNETS
	#define IPPORT_TELNETS              992U
#endif
typedef struct _tcp_hdr_
{
	uint16_t               SourcePort;
	uint16_t               DestinationPort;
	uint32_t               Sequence;
	uint32_t               Acknowledge;
	union {
		uint16_t               HeaderLength_Flags;
		struct {
		#if BYTE_ORDER == LITTLE_ENDIAN
			uint8_t                Nonce:1;
			uint8_t                Reserved:3;
			uint8_t                HeaderLength:4;
			uint8_t                FIN:1;
			uint8_t                SYN:1;
			uint8_t                RST:1;
			uint8_t                PSH:1;
			uint8_t                ACK:1;
			uint8_t                URG:1;
			uint8_t                ECE:1;
			uint8_t                CWR:1;
		#else //BIG_ENDIAN
			uint8_t                HeaderLength:4;
			uint8_t                Reserved:3;
			uint8_t                Nonce:1;
			uint8_t                CWR:1;
			uint8_t                ECE:1;
			uint8_t                URG:1;
			uint8_t                ACK:1;
			uint8_t                PSH:1;
			uint8_t                RST:1;
			uint8_t                SYN:1;
			uint8_t                FIN:1;
		#endif
		}HeaderLength_FlagsBits;
	};
	uint16_t               Windows;
	uint16_t               Checksum;
	uint16_t               UrgentPointer;
}tcp_hdr;

/* User Datagram Protocol/UDP header
* RFC 768, User Datagram Protocol(https://tools.ietf.org/html/rfc768)
* RFC 2460, Internet Protocol, Version 6 (IPv6) Specification(https://tools.ietf.org/html/rfc2460)
* RFC 2675, IPv6 Jumbograms(https://tools.ietf.org/html/rfc2675)
* RFC 4113, Management Information Base for the UDP(https://tools.ietf.org/html/rfc4113)
* RFC 5405, Unicast UDP Usage Guidelines for Application Designers(https://tools.ietf.org/html/rfc5405)

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
	uint16_t               SourcePort;
	uint16_t               DestinationPort;
	uint16_t               Length;
	uint16_t               Checksum;
}udp_hdr;

/* Transmission Control Protocol/TCP and User Datagram Protocol/UDP Pseudo header with IPv4

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
}ipv4_psd_hdr;

/* Internet Control Message Protocol version 6/ICMPv6, Transmission Control Protocol/TCP and User Datagram Protocol/UDP Pseudo header with IPv4

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
}ipv6_psd_hdr;


//Domain Name System/DNS part
/* About RFC standards
* RFC 920, Domain Requirements – Specified original top-level domains(https://tools.ietf.org/html/rfc920)
* RFC 1032, Domain Administrators Guide(https://tools.ietf.org/html/rfc1032)
* RFC 1033, Domain Administrators Operations Guide(https://tools.ietf.org/html/rfc1033)
* RFC 1034, Domain Names - Concepts and Facilities(https://tools.ietf.org/html/rfc1034)
* RFC 1035, Domain Names - Implementation and Specification(https://tools.ietf.org/html/rfc1035)
* RFC 1101, DNS Encodings of Network Names and Other Types(https://tools.ietf.org/html/rfc1101)
* RFC 1123, Requirements for Internet Hosts—Application and Support(https://tools.ietf.org/html/rfc1123)
* RFC 1178, Choosing a Name for Your Computer (FYI 5)(https://tools.ietf.org/html/rfc1178)
* RFC 1183, New DNS RR Definitions(https://tools.ietf.org/html/rfc1183)
* RFC 1348, DNS NSAP RRs(https://tools.ietf.org/html/rfc1348)
* RFC 1591, Domain Name System Structure and Delegation (Informational)(https://tools.ietf.org/html/rfc1591)
* RFC 1664, Using the Internet DNS to Distribute RFC1327 Mail Address Mapping Tables(https://tools.ietf.org/html/rfc1664)
* RFC 1706, DNS NSAP Resource Records(https://tools.ietf.org/html/rfc1706)
* RFC 1712, DNS Encoding of Geographical Location(https://tools.ietf.org/html/rfc1712)
* RFC 1876, A Means for Expressing Location Information in the Domain Name System(https://tools.ietf.org/html/rfc1876)
* RFC 1886, DNS Extensions to support IP version 6(https://tools.ietf.org/html/rfc1886)
* RFC 1912, Common DNS Operational and Configuration Errors(https://tools.ietf.org/html/rfc1912)
* RFC 1995, Incremental Zone Transfer in DNS(https://tools.ietf.org/html/rfc1995)
* RFC 1996, A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)(https://tools.ietf.org/html/rfc1996)
* RFC 2052, A DNS RR for specifying the location of services (DNS SRV)(https://tools.ietf.org/html/rfc2052)
* RFC 2100, The Naming of Hosts (Informational)(https://tools.ietf.org/html/rfc2100)
* RFC 2136, Dynamic Updates in the domain name system (DNS UPDATE)(https://tools.ietf.org/html/rfc2136)
* RFC 2181, Clarifications to the DNS Specification(https://tools.ietf.org/html/rfc2181)
* RFC 2182, Selection and Operation of Secondary DNS Servers(https://tools.ietf.org/html/rfc2182)
* RFC 2230, Key Exchange Delegation Record for the DNS(https://tools.ietf.org/html/rfc2230)
* RFC 2308, Negative Caching of DNS Queries (DNS NCACHE)(https://tools.ietf.org/html/rfc2308)
* RFC 2317, Classless IN-ADDR.ARPA delegation (BCP 20)(https://tools.ietf.org/html/rfc2317)
* RFC 2535, Domain Name System Security Extensions(https://tools.ietf.org/html/rfc2535)
* RFC 2536, DSA KEYs and SIGs in the Domain Name System (DNS)(https://tools.ietf.org/html/rfc2536)
* RFC 2537, RSA/MD5 KEYs and SIGs in the Domain Name System (DNS)(https://tools.ietf.org/html/rfc2537)
* RFC 2539, Storage of Diffie-Hellman Keys in the Domain Name System (DNS)(https://tools.ietf.org/html/rfc2539)
* RFC 2671, Extension Mechanisms for DNS (EDNS)(https://tools.ietf.org/html/rfc2671)
* RFC 2672, Non-Terminal DNS Name Redirection(https://tools.ietf.org/html/rfc2672)
* RFC 2845, Secret Key Transaction Authentication for DNS (TSIG)(https://tools.ietf.org/html/rfc2845)
* RFC 2874, DNS Extensions to Support IPv6 Address Aggregation and Renumbering(https://tools.ietf.org/html/rfc2874)
* RFC 2930, Secret Key Establishment for DNS (TKEY RR)(https://tools.ietf.org/html/rfc2930)
* RFC 3110, RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS)(https://tools.ietf.org/html/rfc3110)
* RFC 3123, A DNS RR Type for Lists of Address Prefixes (APL RR)(https://tools.ietf.org/html/rfc3123)
* RFC 3225, Indicating Resolver Support of DNSSEC(https://tools.ietf.org/html/rfc3225)
* RFC 3226, DNSSEC and IPv6 A6 aware server/resolver message size requirements(https://tools.ietf.org/html/rfc3226)
* RFC 3403, Dynamic Delegation Discovery System (DDDS) Part Three: The Domain Name System (DNS Database)(https://tools.ietf.org/html/rfc3403)
* RFC 3597, Handling of Unknown DNS Resource Record (RR Types)(https://tools.ietf.org/html/rfc3597)
* RFC 3696, Application Techniques for Checking and Transformation of Names (Informational)(https://tools.ietf.org/html/rfc3696)
* RFC 4025, A Method for Storing IPsec Keying Material in DNS(https://tools.ietf.org/html/rfc4025)
* RFC 4034, Resource Records for the DNS Security Extensions(https://tools.ietf.org/html/rfc4034)
* RFC 4255, Using DNS to Securely Publish Secure Shell (SSH Key Fingerprints)(https://tools.ietf.org/html/rfc4225)
* RFC 4343, Domain Name System (DNS) Case Insensitivity Clarification(https://tools.ietf.org/html/rfc4343)
* RFC 4398, Storing Certificates in the Domain Name System (DNS)(https://tools.ietf.org/html/rfc4398)
* RFC 4408, Sender Policy Framework (SPF) for Authorizing Use of Domains in E-Mail, Version 1(https://tools.ietf.org/html/rfc4408)
* RFC 4431, The DNSSEC Lookaside Validation (DLV) DNS Resource Record(https://tools.ietf.org/html/rfc4431)
* RFC 4592, The Role of Wildcards in the Domain Name System(https://tools.ietf.org/html/rfc4592)
* RFC 4635, HMAC SHA TSIG Algorithm Identifiers(https://tools.ietf.org/html/rfc4635)
* RFC 4701, A DNS Resource Record (RR) for Encoding Dynamic Host Configuration Protocol (DHCP Information)(DHCID RR)(https://tools.ietf.org/html/rfc4701)
* RFC 4892, Requirements for a Mechanism Identifying a Name Server Instance (Informational)(https://tools.ietf.org/html/rfc4892)
* RFC 5001, DNS Name Server Identifier (NSID) Option(https://tools.ietf.org/html/rfc5001)
* RFC 5155, DNS Security (DNSSEC) Hashed Authenticated Denial of Existence(https://tools.ietf.org/html/rfc5155)
* RFC 5205, Host Identity Protocol (HIP Domain Name System (DNS Extension(https://tools.ietf.org/html/rfc5205)
* RFC 5452, Measures for Making DNS More Resilient against Forged Answers(https://tools.ietf.org/html/rfc5452)
* RFC 5625, DNS Proxy Implementation Guidelines (BCP 152)(https://tools.ietf.org/html/rfc5625)
* RFC 5890, Internationalized Domain Names for Applications (IDNA):Definitions and Document Framework(https://tools.ietf.org/html/rfc5890)
* RFC 5891, Internationalized Domain Names in Applications (IDNA): Protocol(https://tools.ietf.org/html/rfc5891)
* RFC 5892, The Unicode Code Points and Internationalized Domain Names for Applications (IDNA)(https://tools.ietf.org/html/rfc5892)
* RFC 5893, Right-to-Left Scripts for Internationalized Domain Names for Applications (IDNA)(https://tools.ietf.org/html/rfc5893)
* RFC 5894, Internationalized Domain Names for Applications (IDNA):Background, Explanation, and Rationale (Informational)(https://tools.ietf.org/html/rfc594)
* RFC 5895, Mapping Characters for Internationalized Domain Names in Applications (IDNA) 2008 (Informational)(https://tools.ietf.org/html/rfc5895)
* RFC 5936, DNS Zone Transfer Protocol (AXFR)(https://tools.ietf.org/html/rfc5936)
* RFC 5966, DNS Transport over TCP - Implementation Requirements(https://tools.ietf.org/html/rfc5966)
* RFC 6195, Domain Name System (DNS) IANA Considerations (BCP 42)(https://tools.ietf.org/html/rfc6495)
* RFC 6698, The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA(https://tools.ietf.org/html/rfc6698)
* RFC 6742, DNS Resource Records for the Identifier-Locator Network Protocol (ILNP)(https://tools.ietf.org/html/rfc6742)
* RFC 6844, DNS Certification Authority Authorization (CAA) Resource Record(https://tools.ietf.org/html/rfc6844)
* RFC 6975, Signaling Cryptographic Algorithm Understanding in DNS Security Extensions (DNSSEC)(https://tools.ietf.org/html/rfc6975)
* RFC 7043, Resource Records for EUI-48 and EUI-64 Addresses in the DNS(https://tools.ietf.org/html/rfc7043)
* RFC 7314, Extension Mechanisms for DNS (EDNS) EXPIRE Option(https://tools.ietf.org/html/rfc7314)
* RFC 7766, DNS Transport over TCP - Implementation Requirements(https://tools.ietf.org/html/rfc7766)
*/

//About this list, please visit IANA Domain Name System (DNS) Parameters(https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
//Port and Flags definitions
#ifndef IPPORT_DNS
	#define IPPORT_DNS                    53U        //Standard DNS(TCP and UDP) Port
#endif
#ifndef IPPORT_MDNS
	#define IPPORT_MDNS                   5353U      //Multicast Domain Name System/mDNS Port
#endif
#ifndef IPPORT_LLMNR
	#define IPPORT_LLMNR                  5355U      //Link-Local Multicast Name Resolution/LLMNR Port
#endif
#define DNS_FLAG_STANDARD             0x0100     //System Standard query
#define DNS_FLAG_SQR_NE               0x8180     //Standard query response and No Error.
#define DNS_FLAG_SQR_NEA              0x8580     //Standard query response, No Error and Authoritative.
#define DNS_FLAG_SQR_NETC             0x8380     //Standard query response and No Error, but Truncated.
#define DNS_FLAG_SQR_FE               0x8181     //Standard query response, Format Error
#define DNS_FLAG_SQR_SF               0x8182     //Standard query response, Server failure
#define DNS_FLAG_SQR_SNH              0x8183     //Standard query response, No Such Name
#define DNS_FLAG_GET_BIT_RESPONSE     0x8000     //Get Response bit in DNS flags.
#define DNS_FLAG_GET_BIT_OPCODE       0x7800     //Get OPCode in DNS flags.
#define DNS_FLAG_GET_BIT_AA           0x0400     //Get Authoritative bit in DNS flags.
#define DNS_FLAG_GET_BIT_TC           0x0200     //Get Truncated bit in DNS flags.
#define DNS_FLAG_GET_BIT_RD           0x0100     //Get Recursion Desired bit in DNS flags.
#define DNS_FLAG_GET_BIT_Z            0x0040     //Get Reserved bit in DNS flags.
#define DNS_FLAG_GET_BIT_AD           0x0020     //Get Authentic Data bit in DNS flags.
#define DNS_FLAG_GET_BIT_CD           0x0010     //Get Checking Disabled bit in DNS flags.
#define DNS_FLAG_GET_BIT_RCODE        0x000F     //Get RCode in DNS flags.
#define DNS_FLAG_SET_R                0x8000     //Set Response bit in DNS flags.
#define DNS_FLAG_SET_R_TC             0x8200     //Set Response bit and Truncated bit in DNS flags.
#define DNS_FLAG_SET_R_A              0x8580     //Set Response bit and Authoritative bit in DNS flags.
#define DNS_FLAG_SET_R_FE             0x8001     //Set Response bit and Format Error RCode in DNS flags.
#define DNS_FLAG_SET_R_SNH            0x8003     //Set Response bit and No Such Name RCode in DNS flags.
#define DNS_POINTER_8_BITS            0xC0       //DNS compression pointer(11000000)
#define DNS_POINTER_16_BITS           0xC000     //DNS compression pointer(1100000000000000)
#define DNS_POINTER_8_BITS_STRING     ('\xC0')   //DNS compression pointer string
#define DNS_POINTER_BITS_GET_LOCATE   0x3FFF     //Get location of DNS compression pointer(00111111111111111)
#define DNS_POINTER_QUERY             0xC00C     //Pointer of first query

//OPCode definitions
#ifndef DNS_OPCODE_QUERY
	#define DNS_OPCODE_QUERY           0                //OPCode Query is 0.
#endif
#ifndef DNS_OPCODE_IQUERY
	#define DNS_OPCODE_IQUERY          1U               //OPCode Inverse Query(Obsolete) is 1.
#endif
#ifndef DNS_OPCODE_SERVER_STATUS
	#define DNS_OPCODE_SERVER_STATUS   2U               //OPCode Status is 2.
#endif
#ifndef DNS_OPCODE_UNKNOWN
	#define DNS_OPCODE_UNKNOWN         3U               //OPCode Unknown is 3.
#endif
#ifndef DNS_OPCODE_NOTIFY
	#define DNS_OPCODE_NOTIFY          4U               //OPCode Notify is 4.
#endif
#ifndef DNS_OPCODE_UPDATE
	#define DNS_OPCODE_UPDATE          5U               //OPCode Update is 5.
#endif
#ifndef DNS_OPCODE_RESERVED
	#define DNS_OPCODE_RESERVED        0xFFFF           //DNS Reserved OPCode is 65535.
#endif

//Classes definitions
#ifndef DNS_CLASS_INTERNET
	#define DNS_CLASS_INTERNET      0x0001           //DNS INTERNET Classes is 1.
#endif
#ifndef DNS_CLASS_CSNET
	#define DNS_CLASS_CSNET         0x0002           //DNS CSNET Classes is 2.
#endif
#ifndef DNS_CLASS_CHAOS
	#define DNS_CLASS_CHAOS         0x0003           //DNS CHAOS Classes is 3.
#endif
#ifndef DNS_CLASS_HESIOD
	#define DNS_CLASS_HESIOD        0x0004           //DNS HESIOD Classes is 4.
#endif
#ifndef DNS_CLASS_NONE
	#define DNS_CLASS_NONE          0x00FE           //DNS NONE Classes is 254.
#endif
#ifndef DNS_CLASS_ALL
	#define DNS_CLASS_ALL           0x00FF           //DNS ALL Classes is 255.
#endif
#ifndef DNS_CLASS_ANY
	#define DNS_CLASS_ANY           0x00FF           //DNS ANY Classes is 255.
#endif

//RCode definitions
#ifndef DNS_RCODE_NOERROR
	#define DNS_RCODE_NOERROR       0                //RCode No Error is 0.
#endif
#ifndef DNS_RCODE_FORMERR
	#define DNS_RCODE_FORMERR       0x0001           //RCode Format Error is 1.
#endif
#ifndef DNS_RCODE_SERVFAIL
	#define DNS_RCODE_SERVFAIL      0x0002           //RCode Server Failure is 2.
#endif
#ifndef DNS_RCODE_NXDOMAIN
	#define DNS_RCODE_NXDOMAIN      0x0003           //RCode Non-Existent Domain is 3.
#endif
#ifndef DNS_RCODE_NOTIMPL
	#define DNS_RCODE_NOTIMPL       0x0004           //RCode Not Implemented is 4.
#endif
#ifndef DNS_RCODE_REFUSED
	#define DNS_RCODE_REFUSED       0x0005           //RCode Query Refused is 5.
#endif
#ifndef DNS_RCODE_YXDOMAIN
	#define DNS_RCODE_YXDOMAIN      0x0006           //RCode Name Exists when it should not is 6.
#endif
#ifndef DNS_RCODE_YXRRSET
	#define DNS_RCODE_YXRRSET       0x0007           //RCode RR Set Exists when it should not is 7.
#endif
#ifndef DNS_RCODE_NXRRSET
	#define DNS_RCODE_NXRRSET       0x0008           //RCode RR Set that should exist does not is 8.
#endif
#ifndef DNS_RCODE_NOTAUTH
	#define DNS_RCODE_NOTAUTH       0x0009           //RCode Server Not Authoritative for zone/Not Authorized is 9.
#endif
#ifndef DNS_RCODE_NOTZONE
	#define DNS_RCODE_NOTZONE       0x000A           //RCode Name not contained in zone is 10.
#endif
#ifndef DNS_RCODE_BADVERS
	#define DNS_RCODE_BADVERS       0x0010           //RCode Bad OPT Version/TSIG Signature Failure is 16.
#endif
#ifndef DNS_RCODE_BADKEY
	#define DNS_RCODE_BADKEY        0x0011           //RCode Key not recognized is 17.
#endif
#ifndef DNS_RCODE_BADTIME
	#define DNS_RCODE_BADTIME       0x0012           //RCode Signature out of time window is 18.
#endif
#ifndef DNS_RCODE_BADMODE
	#define DNS_RCODE_BADMODE       0x0013           //RCode Bad TKEY Mode is 19.
#endif
#ifndef DNS_RCODE_BADNAME
	#define DNS_RCODE_BADNAME       0x0014           //RCode Duplicate key name is 20.
#endif
#ifndef DNS_RCODE_BADALG
	#define DNS_RCODE_BADALG        0x0015           //RCode Algorithm not supported is 21.
#endif
#ifndef DNS_RCODE_BADTRUNC
	#define DNS_RCODE_BADTRUNC      0x0016           //RCode Bad Truncation is 22.
#endif
#ifndef DNS_RCODE_PRIVATE_A
	#define DNS_RCODE_PRIVATE_A     0xFF00           //DNS Reserved Private use RCode is begin at 3841.
#endif
#ifndef DNS_RCODE_PRIVATE_B
	#define DNS_RCODE_PRIVATE_B     0xFFFE           //DNS Reserved Private use RCode is end at 4095.
#endif

//Record Types definitions
#ifndef DNS_TYPE_A
	#define DNS_TYPE_A            0x0001             //DNS Type A is 1.
#endif
#ifndef DNS_TYPE_NS
	#define DNS_TYPE_NS           0x0002             //DNS Type NS is 2.
#endif
#ifndef DNS_TYPE_MD
	#define DNS_TYPE_MD           0x0003             //DNS Type MD is 3(Obsolete).
#endif
#ifndef DNS_TYPE_MF
	#define DNS_TYPE_MF           0x0004             //DNS Type MF is 4(Obsolete).
#endif
#ifndef DNS_TYPE_CNAME
	#define DNS_TYPE_CNAME        0x0005             //DNS Type CNAME is 5.
#endif
#ifndef DNS_TYPE_SOA
	#define DNS_TYPE_SOA          0x0006             //DNS Type SOA is 6.
#endif
#ifndef DNS_TYPE_MB
	#define DNS_TYPE_MB           0x0007             //DNS Type MB is 7(Experimental).
#endif
#ifndef DNS_TYPE_MG
	#define DNS_TYPE_MG           0x0008             //DNS Type MG is 8(Experimental).
#endif
#ifndef DNS_TYPE_MR
	#define DNS_TYPE_MR           0x0009             //DNS Type MR is 9(Experimental).
#endif
#ifndef DNS_TYPE_NULL
	#define DNS_TYPE_NULL         0x000A             //DNS Type NULL is 10(Experimental).
#endif
#ifndef DNS_TYPE_WKS
	#define DNS_TYPE_WKS          0x000B             //DNS Type WKS is 11.
#endif
#ifndef DNS_TYPE_PTR
	#define DNS_TYPE_PTR          0x000C             //DNS Type PTR is 12.
#endif
#ifndef DNS_TYPE_HINFO
	#define DNS_TYPE_HINFO        0x000D             //DNS Type HINFO is 13.
#endif
#ifndef DNS_TYPE_MINFO
	#define DNS_TYPE_MINFO        0x000E             //DNS Type MINFO is 14.
#endif
#ifndef DNS_TYPE_MX
	#define DNS_TYPE_MX           0x000F             //DNS Type MX is 15.
#endif
#ifndef DNS_TYPE_TEXT
	#define DNS_TYPE_TEXT          0x0010             //DNS Type TXT is 16.
#endif
#ifndef DNS_TYPE_RP
	#define DNS_TYPE_RP           0x0011             //DNS Type RP is 17.
#endif
#ifndef DNS_TYPE_AFSDB
	#define DNS_TYPE_AFSDB        0x0012             //DNS Type AFSDB is 18.
#endif
#ifndef DNS_TYPE_X25
	#define DNS_TYPE_X25          0x0013             //DNS Type X25 is 19.
#endif
#ifndef DNS_TYPE_ISDN
	#define DNS_TYPE_ISDN         0x0014             //DNS Type ISDN is 20.
#endif
#ifndef DNS_TYPE_RT
	#define DNS_TYPE_RT           0x0015             //DNS Type RT is 21.
#endif
#ifndef DNS_TYPE_NSAP
	#define DNS_TYPE_NSAP         0x0016             //DNS Type NSAP is 22.
#endif
#ifndef DNS_TYPE_NSAPPTR
	#define DNS_TYPE_NSAPPTR     0x0017             //DNS Type NSAPPTR is 23(Obsolete).
#endif
#ifndef DNS_TYPE_SIG
	#define DNS_TYPE_SIG          0x0018             //DNS Type SIG is 24.
#endif
#ifndef DNS_TYPE_KEY
	#define DNS_TYPE_KEY          0x0019             //DNS Type KEY is 25.
#endif
#ifndef DNS_TYPE_PX
	#define DNS_TYPE_PX           0x001A             //DNS Type PX is 26.
#endif
#ifndef DNS_TYPE_GPOS
	#define DNS_TYPE_GPOS         0x001B             //DNS Type GPOS is 27.
#endif
#ifndef DNS_TYPE_AAAA
	#define DNS_TYPE_AAAA         0x001C             //DNS Type AAAA is 28.
#endif
#ifndef DNS_TYPE_LOC
	#define DNS_TYPE_LOC          0x001D             //DNS Type LOC is 29.
#endif
#ifndef DNS_TYPE_NXT
	#define DNS_TYPE_NXT          0x001E             //DNS Type NXT is 30.
#endif
#ifndef DNS_TYPE_EID
	#define DNS_TYPE_EID          0x001F             //DNS Type EID is 31.
#endif
#ifndef DNS_TYPE_NIMLOC
	#define DNS_TYPE_NIMLOC       0x0020             //DNS Type NIMLOC is 32.
#endif
#ifndef DNS_TYPE_SRV
	#define DNS_TYPE_SRV          0x0021             //DNS Type SRV is 33.
#endif
#ifndef DNS_TYPE_ATMA
	#define DNS_TYPE_ATMA         0x0022             //DNS Type ATMA is 34.
#endif
#ifndef DNS_TYPE_NAPTR
	#define DNS_TYPE_NAPTR        0x0023             //DNS Type NAPTR is 35.
#endif
#ifndef DNS_TYPE_KX
	#define DNS_TYPE_KX           0x0024             //DNS Type KX is 36.
#endif
#ifndef DNS_TYPE_CERT
	#define DNS_TYPE_CERT         0x0025             //DNS Type CERT is 37.
#endif
#ifndef DNS_TYPE_A6
	#define DNS_TYPE_A6           0x0026             //DNS Type A6 is 38(Obsolete).
#endif
#ifndef DNS_TYPE_DNAME
	#define DNS_TYPE_DNAME        0x0027             //DNS Type DNAME is 39.
#endif
#ifndef DNS_TYPE_SINK
	#define DNS_TYPE_SINK         0x0028             //DNS Type SINK is 40.
#endif
#ifndef DNS_TYPE_OPT
	#define DNS_TYPE_OPT          0x0029             //DNS Type OPT/EDNS is 41.
#endif
#ifndef DNS_TYPE_APL
	#define DNS_TYPE_APL          0x002A             //DNS Type APL is 42.
#endif
#ifndef DNS_TYPE_DS
	#define DNS_TYPE_DS           0x002B             //DNS Type DS is 43.
#endif
#ifndef DNS_TYPE_SSHFP
	#define DNS_TYPE_SSHFP        0x002C             //DNS Type SSHFP is 44.
#endif
#ifndef DNS_TYPE_IPSECKEY
	#define DNS_TYPE_IPSECKEY     0x002D             //DNS Type IPSECKEY is 45.
#endif
#ifndef DNS_TYPE_RRSIG
	#define DNS_TYPE_RRSIG        0x002E             //DNS Type RRSIG is 46.
#endif
#ifndef DNS_TYPE_NSEC
	#define DNS_TYPE_NSEC         0x002F             //DNS Type NSEC is 47.
#endif
#ifndef DNS_TYPE_DNSKEY
	#define DNS_TYPE_DNSKEY       0x0030             //DNS Type DNSKEY is 48.
#endif
#ifndef DNS_TYPE_DHCID
	#define DNS_TYPE_DHCID        0x0031             //DNS Type DHCID is 49.
#endif
#ifndef DNS_TYPE_NSEC3
	#define DNS_TYPE_NSEC3        0x0032             //DNS Type NSEC3 is 50.
#endif
#ifndef DNS_TYPE_NSEC3PARAM
	#define DNS_TYPE_NSEC3PARAM   0x0033             //DNS Type NSEC3PARAM is 51.
#endif
#ifndef DNS_TYPE_TLSA
	#define DNS_TYPE_TLSA         0x0034             //DNS Type Record TLSA is 52.
#endif
#ifndef DNS_TYPE_HIP
	#define DNS_TYPE_HIP          0x0037             //DNS Type HIP is 55.
#endif
#ifndef DNS_TYPE_NINFO
	#define DNS_TYPE_NINFO        0x0038             //DNS Type NINFO is 56.
#endif
#ifndef DNS_TYPE_RKEY
	#define DNS_TYPE_RKEY         0x0039             //DNS Type RKEY is 57.
#endif
#ifndef DNS_TYPE_TALINK
	#define DNS_TYPE_TALINK       0x003A             //DNS Type TALINK is 58.
#endif
#ifndef DNS_TYPE_CDS
	#define DNS_TYPE_CDS          0x003B             //DNS Type CDS is 59.
#endif
#ifndef DNS_TYPE_CDNSKEY
	#define DNS_TYPE_CDNSKEY      0x003C             //DNS Type CDNSKEY is 60.
#endif
#ifndef DNS_TYPE_OPENPGPKEY
	#define DNS_TYPE_OPENPGPKEY   0x003D             //DNS Type OPENPGPKEY is 61.
#endif
#ifndef DNS_TYPE_SPF
	#define DNS_TYPE_SPF          0x0063             //DNS Type SPF is 99.
#endif
#ifndef DNS_TYPE_UINFO
	#define DNS_TYPE_UINFO        0x0064             //DNS Type UINFO is 100.
#endif
#ifndef DNS_TYPE_UID
	#define DNS_TYPE_UID          0x0065             //DNS Type UID is 101.
#endif
#ifndef DNS_TYPE_GID
	#define DNS_TYPE_GID          0x0066             //DNS Type GID is 102.
#endif
#ifndef DNS_TYPE_UNSPEC
	#define DNS_TYPE_UNSPEC       0x0067             //DNS Type UNSPEC is 103.
#endif
#ifndef DNS_TYPE_NID
	#define DNS_TYPE_NID          0x0068             //DNS Type NID is 104.
#endif
#ifndef DNS_TYPE_L32
	#define DNS_TYPE_L32          0x0069             //DNS Type L32 is 105.
#endif
#ifndef DNS_TYPE_L64
	#define DNS_TYPE_L64          0x006A             //DNS Type L64 is 106.
#endif
#ifndef DNS_TYPE_LP
	#define DNS_TYPE_LP           0x006B             //DNS Type LP is 107.
#endif
#ifndef DNS_TYPE_EUI48
	#define DNS_TYPE_EUI48        0x006C             //DNS Type EUI48 is 108.
#endif
#ifndef DNS_TYPE_EUI64
	#define DNS_TYPE_EUI64        0x006D             //DNS Type EUI64 is 109.
#endif
#ifndef DNS_TYPE_ADDRS
	#define DNS_TYPE_ADDRS        0x00F8             //DNS Type TKEY is 248.
#endif
#ifndef DNS_TYPE_TKEY
	#define DNS_TYPE_TKEY         0x00F9             //DNS Type TKEY is 249.
#endif
#ifndef DNS_TYPE_TSIG
	#define DNS_TYPE_TSIG         0x00FA             //DNS Type TSIG is 250.
#endif
#ifndef DNS_TYPE_IXFR
	#define DNS_TYPE_IXFR         0x00FB             //DNS Type IXFR is 251.
#endif
#ifndef DNS_TYPE_AXFR
	#define DNS_TYPE_AXFR         0x00FC             //DNS Type AXFR is 252.
#endif
#ifndef DNS_TYPE_MAILB
	#define DNS_TYPE_MAILB        0x00FD             //DNS Type MAILB is 253.
#endif
#ifndef DNS_TYPE_MAILA
	#define DNS_TYPE_MAILA        0x00FE             //DNS Type MAILA is 254.
#endif
#ifndef DNS_TYPE_ANY
	#define DNS_TYPE_ANY          0x00FF             //DNS Type ANY is 255.
#endif
#ifndef DNS_TYPE_URI
	#define DNS_TYPE_URI          0x0100             //DNS Type URI is 256.
#endif
#ifndef DNS_TYPE_CAA
	#define DNS_TYPE_CAA          0x0101             //DNS Type CAA is 257.
#endif
#ifndef DNS_TYPE_TA
	#define DNS_TYPE_TA           0x8000             //DNS Type TA is 32768.
#endif
#ifndef DNS_TYPE_DLV
	#define DNS_TYPE_DLV          0x8001             //DNS Type DLVS is 32769.
#endif
#ifndef DNS_TYPE_PRIVATE_A
	#define DNS_TYPE_PRIVATE_A    0xFF00             //DNS Reserved Private use records is begin at 65280.
#endif
#ifndef DNS_TYPE_PRIVATE_B
	#define DNS_TYPE_PRIVATE_B    0xFFFE             //DNS Reserved Private use records is end at 65534.
#endif
#ifndef DNS_TYPE_RESERVED
	#define DNS_TYPE_RESERVED     0xFFFF             //DNS Reserved records is 65535.
#endif


/* Domain Name System/DNS header
//With User Datagram Protocol/UDP

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
#define DNS_PACKET_MAXSIZE_TRADITIONAL   512U   //Traditional DNS packet maximum size(512 bytes)
typedef struct _dns_hdr_
{
	uint16_t              ID;
	union {
		uint16_t          Flags;
		struct {
		#if BYTE_ORDER == LITTLE_ENDIAN
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
	uint16_t              Question;
	uint16_t              Answer;
	uint16_t              Authority;
	uint16_t              Additional;
}dns_hdr;

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
		#if BYTE_ORDER == LITTLE_ENDIAN
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
	uint16_t              Question;
	uint16_t              Answer;
	uint16_t              Authority;
	uint16_t              Additional;
}dns_tcp_hdr;

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
//	uint8_t               *Name;
	uint16_t              Type;
	uint16_t              Classes;
}dns_qry;

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
//	uint8_t               *Name;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
//	uint8_t               *Data;
}dns_record_standard;

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
	in_addr               Address;
}dns_record_a;

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
//	uint8_t               *PrimaryName;
}dns_record_cname;

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
//	uint8_t               *PrimaryName;
//	uint8_t               *MailboxName;
	uint32_t              Serial;
	uint32_t              RefreshInterval;
	uint32_t              RetryInterval;
	uint32_t              ExpireLimit;
	uint32_t              MinimumTTL;
}dns_record_soa;

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
	uint16_t              Pointer;
	uint16_t              Type;
	uint16_t              Classes;
	uint32_t              TTL;
	uint16_t              Length;
//	uint8_t               *Name;
}dns_record_ptr;

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
//	uint8_t               MailExchangeName;
}dns_record_mx;

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
//	uint8_t               *TXT;
}dns_record_txt;

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
	in6_addr              Address;
}dns_record_aaaa;

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
//	uint8_t              *Target;
}dns_record_srv;

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
|Extended RCode |EDNS Version |D|           Reserved            |  Extended RCode/Higher bits in extended Return Code, D/DO/DNSSEC OK bit
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |\---------- Z Field -----------/
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define EDNS_VERSION_ZERO           0
#define EDNS_PACKET_MINSIZE         1220U
#define EDNS_FLAG_GET_BIT_DO        0x8000        //Get DO bit in Z field.
typedef struct _dns_record_opt_
{
	uint8_t               Name;
	uint16_t              Type;
	uint16_t              UDP_PayloadSize;
	uint8_t               Extended_RCode;
	uint8_t               Version;
	union {
		uint16_t          Z_Field;
		struct {
		#if BYTE_ORDER == LITTLE_ENDIAN
			uint8_t       Reserved_First:7;
			uint8_t       DO:1;
		#else //BIG_ENDIAN
			uint8_t       DO:1;
			uint8_t       Reserved_First:7;
		#endif
			uint8_t       Reserved_Second;
		}Z_Bits;
	};
	uint16_t              DataLength;
}dns_record_opt, edns_header;

/* Extension Mechanisms for Domain Name System/EDNS Data Option
                    1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Code                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Length                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                             Data                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct _edns_data_option_
{
	uint16_t              Code;
	uint16_t              Length;
//	uint8_t               *Data;
}edns_data_option;

/* Extension Mechanisms for Domain Name System/DNS, Client subnet in EDNS requests
* RFC 7871, Client Subnet in DNS Queries(https://tools.ietf.org/html/rfc7871)

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
#define EDNS_CODE_LLQ                            0x0001   //Long-lived query
#define EDNS_CODE_UL                             0x0002   //Update lease
#define EDNS_CODE_NSID                           0x0003   //Name Server Identifier (RFC 5001)
#define EDNS_CODE_OWNER                          0x0004   //Owner, reserved
#define EDNS_CODE_DAU                            0x0005   //DNSSEC Algorithm Understood (RFC 6975)
#define EDNS_CODE_DHU                            0x0006   //DS Hash Understood (RFC 6975)
#define EDNS_CODE_N3U                            0x0007   //DSEC3 Hash Understood (RFC 6975)
#define EDNS_CODE_CSUBNET                        0x0008   //Client subnet as assigned by IANA
#define EDNS_CODE_EDNS_EXPIRE                    0x0009   //EDNS Expire (RFC 7314)

//About Address Family Numbers, please visit https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml.
#define EDNS_ADDRESS_FAMILY_IPV4                 0x0001
#define EDNS_ADDRESS_FAMILY_IPV6                 0x0002

//Source prefix bits
#define EDNS_CLIENT_SUBNET_SOURCE_PREFIX_IPV6    56U
#define EDNS_CLIENT_SUBNET_SOURCE_PREFIX_IPV4    24U
typedef struct _edns_client_subnet_
{
	uint16_t              Code;
	uint16_t              Length;
	uint16_t              Family;
	uint8_t               Netmask_Source;
	uint8_t               Netmask_Scope;
//	uint8_t               *Address;
}edns_client_subnet;

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
#define DNSSEC_DIGEST_DS_RESERVED              0
#define DNSSEC_DIGEST_DS_SHA1                  1U       //RFC 3658, Delegation Signer (DS) Resource Record (RR)(https://tools.ietf.org/html/rfc3658)
#define DNSSEC_DIGEST_DS_SHA256                2U       //RFC 4509, Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs)(https://tools.ietf.org/html/rfc4509)
#define DNSSEC_DIGEST_DS_GOST                  3U       //RFC 5933, Use of GOST Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC(https://tools.ietf.org/html/rfc5933)
#define DNSSEC_DIGEST_DS_SHA384                4U       //RFC 6605, Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC(https://tools.ietf.org/html/rfc6605)

//About this list, please visit https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
#define DNSSEC_DS_TYPE_RESERVED                0
#define DNSSEC_DS_TYPE_SHA1                    1U
#define DNSSEC_DS_TYPE_SHA256                  2U
#define DNSSEC_DS_TYPE_GOST                    3U
#define DNSSEC_DS_TYPE_SHA384                  4U
#define DNSSEC_LENGTH_SHA1                     20U      //SHA-1 output is 160 bits/20 bytes lentgh
#define DNSSEC_LENGTH_SHA256                   32U      //SHA-256 output is 256 bits/32 bytes lentgh
#define DNSSEC_LENGTH_GOST                     32U      //GOST R 34.11-94 output is 256 bits/32 bytes lentgh
#define DNSSEC_LENGTH_SHA384                   48U      //SHA-384 output is 384 bits/48 bytes lentgh
typedef struct _dns_record_ds_
{
	uint16_t              KeyTag;
	uint8_t               Algorithm;
	uint8_t               Type;
//	uint8_t               *Digest;
}dns_record_ds;

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
#define DNSSEC_AlGORITHM_RESERVED_0            0        //RFC 4034, Reserved(Resource Records for the DNS Security Extensions(https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_RSA_MD5               1U       //RFC 3110, RSA-MD5(RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS)(https://tools.ietf.org/html/rfc3110)
#define DNSSEC_AlGORITHM_DH                    2U       //RFC 2539, Diffie-Hellman(Storage of Diffie-Hellman Keys in the Domain Name System (DNS)(https://tools.ietf.org/html/rfc2539)
#define DNSSEC_AlGORITHM_DSA                   3U       //RFC 3755, DSA-SHA1(Legacy Resolver Compatibility for Delegation Signer (DS)(https://tools.ietf.org/html/rfc3755)
#define DNSSEC_AlGORITHM_RESERVED_4            4U       //RFC 6725, Reserved(DNS Security (DNSSEC) DNSKEY Algorithm IANA Registry Updates(https://tools.ietf.org/html/rfc6725)
#define DNSSEC_AlGORITHM_RSA_SHA1              5U       //RFC 4034, RSA-SHA-1(Resource Records for the DNS Security Extensions(https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_DSA_NSEC3_SHA1        6U       //RFC 5155, DSA-NSEC3-SHA-1(DNS Security (DNSSEC) Hashed Authenticated Denial of Existence(https://tools.ietf.org/html/rfc5155)
#define DNSSEC_AlGORITHM_RSA_SHA1_NSEC3_SHA1   7U       //RFC 5155, RSA-SHA-1-NSEC3-SHA-1(DNS Security (DNSSEC) Hashed Authenticated Denial of Existence(https://tools.ietf.org/html/rfc5155)
#define DNSSEC_AlGORITHM_RSA_SHA256            8U       //RFC 5702, RSA-SHA-256(Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC(https://tools.ietf.org/html/rfc5702)
#define DNSSEC_AlGORITHM_RESERVED_9            9U       //RFC 6725, Reserved(DNS Security (DNSSEC) DNSKEY Algorithm IANA Registry Updates(https://tools.ietf.org/html/rfc6725)
#define DNSSEC_AlGORITHM_RSA_SHA512            10U      //RFC 5702, RSA-SHA-512(Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC(https://tools.ietf.org/html/rfc5702)
#define DNSSEC_AlGORITHM_RESERVED_11           11U      //RFC 6725, Reserved(DNS Security (DNSSEC) DNSKEY Algorithm IANA Registry Updates(https://tools.ietf.org/html/rfc6725)
#define DNSSEC_AlGORITHM_ECC_GOST              12U      //RFC 5933, GOST R 34.10-2001(Use of GOST Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC(https://tools.ietf.org/html/rfc5933)
#define DNSSEC_AlGORITHM_ECDSA_P256_SHA256     13U      //RFC 6605, ECDSA Curve P-256 with SHA-256(Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC(https://tools.ietf.org/html/rfc6605)
#define DNSSEC_AlGORITHM_ECDSA_P386_SHA386     14U      //RFC 6605, ECDSA Curve P-384 with SHA-384(Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC(https://tools.ietf.org/html/rfc6605)
#define DNSSEC_AlGORITHM_RESERVED_123          123U     //RFC 4034, Reserved area between 123 and 251(Resource Records for the DNS Security Extensions(https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_RESERVED_251          251U     //RFC 4034, Reserved area between 123 and 251(Resource Records for the DNS Security Extensions(https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_INDIRECT              252U     //RFC 4034, Reserved for Indirect Keys(Resource Records for the DNS Security Extensions(https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_PRIVATE_DNS           253U     //RFC 4034, Private algorithm(Resource Records for the DNS Security Extensions(https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_PRIVATE_OID           254U     //RFC 4034, Private algorithm(Resource Records for the DNS Security Extensions(https://tools.ietf.org/html/rfc4034)
#define DNSSEC_AlGORITHM_RESERVED_255          255U     //RFC 4034, Reserved(Resource Records for the DNS Security Extensions(https://tools.ietf.org/html/rfc4034)
#define DNSSEC_MINSIZE_RSA                     64U
#define DNSSEC_MINSIZE_DH                      96U
#define DNSSEC_MINSIZE_DSA                     128U
#define DNSSEC_MINSIZE_ECC                     24U
typedef struct _dns_record_rrsig_
{
	uint16_t              TypeCovered;
	uint8_t               Algorithm;
	uint8_t               Labels;
	uint32_t              TTL;
	uint32_t              Expiration;
	uint32_t              Inception;
	uint16_t              KeyTag;
//	uint8_t               *SignerName;
//	uint8_t               *Signature;
}dns_record_rrsig;

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
		#if BYTE_ORDER == LITTLE_ENDIAN
			uint8_t       ZoneKey:1;
			uint8_t       Zero_A:7;
			uint8_t       KeySigningKey:1;
			uint8_t       Zero_B:6;
			uint8_t       KeyRevoked:1;
		#else //BIG_ENDIAN
			uint8_t       Zero_A:7;
			uint8_t       ZoneKey:1;
			uint8_t       KeyRevoked:1;
			uint8_t       Zero_B:6;
			uint8_t       KeySigningKey:1;
		#endif
		}FlagsBits;
	};
	uint8_t               Protocol;
	uint8_t               Algorithm;
//	uint8_t               *PublicKey;
}dns_record_dnskey;

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
//	uint8_t                NextDomainName;
//	uint8_t                TypeBitMap;
}dns_record_nsec;
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
//About this list, please visit IANA Domain Name System Security (DNSSEC) NextSECure3 (NSEC3) Parameters(https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml)
#define DNSSEC_NSEC3_ALGORITHM_SHA1            1U
typedef struct _dns_record_nsec3_
{
	uint8_t               Algorithm;
	union {
		uint8_t           Flags;
		struct {
		#if BYTE_ORDER == LITTLE_ENDIAN
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
//	uint8_t               *Salt;
//	uint8_t               HashLength;
//	uint8_t               *NextHashedOwnerName;
//	uint8_t               *TypeBitMap;
}dns_record_nsec3;

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
//About this list, please visit IANA Domain Name System Security (DNSSEC) NextSECure3 (NSEC3) Parameters(https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml)
typedef struct _dns_record_nsec3param_
{
	uint8_t               Algorithm;
	union {
		uint8_t           Flags;
		struct {
		#if BYTE_ORDER == LITTLE_ENDIAN
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
//	uint8_t               *Salt;
}dns_record_nsec3param;

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
		#if BYTE_ORDER == LITTLE_ENDIAN
			uint8_t       Zero:7;
			uint8_t       IssuerCritical:1;
		#else //BIG_ENDIAN
			uint8_t       IssuerCritical:1;
			uint8_t       Zero:7;
		#endif
		}FlagsBits;
	};
	uint8_t               Length;
//	uint8_t               *Tag;
//	uint8_t               *Value;
}dns_record_caa;


//Domain Name System Curve/DNSCurve part
#if defined(ENABLE_LIBSODIUM)
// About DNSCurve standards: 
// DNSCurve: Usable security for DNS(https://dnscurve.org)
// DNSCrypt, A protocol to improve DNS security(https://dnscrypt.org)
#ifndef IPPORT_DNSCURVE
	#define IPPORT_DNSCURVE                   443U
#endif
#define DNSCURVE_DEFAULT_PORT_STRING      (":443")
#define DNSCURVE_MAGIC_QUERY_LEN          8U
#define DNSCURVE_MAGIC_QUERY_HEX_LEN      16U
#define DNSCURVE_PAYLOAD_MULTIPLE_TIME    64U
#define DNSCRYPT_RECEIVE_MAGIC            ("r6fnvWj8")                   //Receive Magic Number
#define DNSCRYPT_CERT_MAGIC               ("DNSC")                       //Signature Magic Number
#define DNSCRYPT_PADDING_SIGN             0x80
#define DNSCRYPT_PADDING_SIGN_STRING      ('\x80')
// Function definitions
#define crypto_box                        crypto_box_curve25519xsalsa20poly1305
#define crypto_box_HALF_NONCEBYTES        (crypto_box_NONCEBYTES / 2U)
#define crypto_box_open                   crypto_box_curve25519xsalsa20poly1305_open
#define crypto_box_keypair                crypto_box_curve25519xsalsa20poly1305_keypair
#define crypto_box_beforenm               crypto_box_curve25519xsalsa20poly1305_beforenm
#define crypto_box_afternm                crypto_box_curve25519xsalsa20poly1305_afternm
#define crypto_box_open_afternm           crypto_box_curve25519xsalsa20poly1305_open_afternm
#define crypto_sign_open                  crypto_sign_ed25519_open

/* Domain Name System Curve/DNSCurve Test Strings/TXT Data header

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Certificate Magic Number                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Version(Major)         |        Version(Minor)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
#define DNSCURVE_ES_X25519_XSALSA20_POLY1305     0x0001   //DNSCurve es version of X25519-XSalsa20Poly1305
#define DNSCURVE_ES_X25519_XCHACHA20_POLY1305    0x0002   //DNSCurve es version of X25519-XChacha20Poly1305
#define DNSCURVE_VERSION_MINOR                   0        //DNSCurve minor version
typedef struct _dnscurve_txt_hdr_
{
	uint32_t              CertMagicNumber;
	uint16_t              MajorVersion;
	uint16_t              MinorVersion;
}dnscurve_txt_hdr;

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
}dnscurve_txt_signature;
#endif


//SOCKS Protocol part
/* About RFC standards
* RFC 1928, SOCKS Protocol Version 5(https://tools.ietf.org/html/rfc1928)
* RFC 1929, Username/Password Authentication for SOCKS V5(https://tools.ietf.org/html/rfc1929)
* SOCKS(version 4): A protocol for TCP proxy across firewalls(https://www.openssh.com/txt/socks4.protocol)
* SOCKS 4A: A Simple Extension to SOCKS 4 Protocol(https://www.openssh.com/txt/socks4a.protocol)
*/
//Version, Method, Command and Reply definitions
#define SOCKS_VERSION_4                            4U
#define SOCKS_VERSION_4A                           4U
#define SOCKS_VERSION_CONFIG_4A                    0x4A
#define SOCKS_VERSION_5                            5U
#define SOCKS_METHOD_NO_AUTHENTICATION_NUM         1U
#define SOCKS_METHOD_SUPPORT_NUM                   2U
#define SOCKS_METHOD_NO_AUTHENTICATION_REQUIRED    0
#define SOCKS_METHOD_GSSAPI                        1U
#define SOCKS_METHOD_USERNAME_PASSWORD             2U
#define SOCKS_METHOD_IANA_ASSIGNED_A               3U
#define SOCKS_METHOD_IANA_ASSIGNED_B               0x7F
#define SOCKS_METHOD_RESERVED_FOR_PRIVATE_A        0x80
#define SOCKS_METHOD_RESERVED_FOR_PRIVATE_B        0xFE
#define SOCKS_METHOD_NO_ACCEPTABLE_METHODS         0xFF
#define SOCKS_USERNAME_PASSWORD_VERSION            1U
#define SOCKS_USERNAME_PASSWORD_MAXNUM             255U
#define SOCKS_USERNAME_PASSWORD_SUCCESS            0
#define SOCKS_COMMAND_CONNECT                      1U
#define SOCKS_COMMAND_BIND                         2U
#define SOCKS_COMMAND_UDP_ASSOCIATE                3U
#define SOCKS_4_VERSION_BYTES                      0
#define SOCKS_4_ADDRESS_DOMAIN_ADDRESS             0x00000001
#define SOCKS_4_REPLY_GRANTED                      0x5A         //Request granted
#define SOCKS_4_REPLY_REJECTED                     0x5B         //Request rejected or failed
#define SOCKS_4_REPLY_NOT_IDENTD                   0x5C         //Request failed because client is not running identd(or not reachable from the server).
#define SOCKS_4_REPLY_NOT_CONFIRM                  0x5D         //Request failed because client's identd could not confirm the user ID string in the request.
#define SOCKS_5_ADDRESS_IPV4                       1U
#define SOCKS_5_ADDRESS_DOMAIN                     3U
#define SOCKS_5_ADDRESS_IPV6                       4U
#define SOCKS_5_REPLY_SUCCESS                      0
#define SOCKS_5_REPLY_SERVER_FAILURE               1U
#define SOCKS_5_REPLY_NOT_ALLOWED                  2U
#define SOCKS_5_REPLY_NETWORK_UNREACHABLE          3U
#define SOCKS_5_REPLY_HOST_UNREACHABLE             4U
#define SOCKS_5_REPLY_REFUSED                      5U
#define SOCKS_5_REPLY_TTL_EXPORED                  6U
#define SOCKS_5_REPLY_COMMAND_NOT_SUPPORTED        7U
#define SOCKS_5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED   8U
#define SOCKS_5_REPLY_UNASSIGNED_A                 9U
#define SOCKS_5_REPLY_UNASSIGNED_B                 0xFF

//SOCKS client version identifier and method selection message
/*
                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    | Method Number |            Methods            /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _socks_client_selection_message_
{
	uint8_t               Version;
	uint8_t               Methods_Number;
	uint8_t               Methods_1;
	uint8_t               Methods_2;
}socks_client_selection;

//SOCKS server method selection message
/*
                    1 1 1 1 1 1 1
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |    Method     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _socks_server_selection_message_
{
	uint8_t               Version;
	uint8_t               Method;
}socks_server_selection;

//SOCKS client Username/Password authentication message
/*
                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |UserName Length|           User Name           /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Password Length|                   Password                    /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct _socks_client_user_authentication_
{
	uint8_t               Version;
//	uint8_t               UserName_Length;
//	uint8_t               *UserName;
//	uint8_t               Password_Length;
//	uint8_t               *Password;
}socks_client_user_authentication;


//SOCKS server Username/Password authentication message
/*
                    1 1 1 1 1 1 1
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |    Status     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _socks_server_user_authentication_
{
	uint8_t               Version;
	uint8_t               Status;
}socks_server_user_authentication;

//SOCKS version 4 client request message
/*
                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |    Command    |          Remote_Port          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Remote Address                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/           User ID             /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _socks4_client_command_request_
{
	uint8_t               Version;
	uint8_t               Command;
	uint16_t              Remote_Port;
	in_addr               Remote_Address;
	uint8_t               UserID;
}socks4_client_command_request;

//SOCKS version 4 server reply message
/*
                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Reply     |   Reserved    | Address Type  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                         Bind Address                          /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Bind Port           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _socks4_server_command_reply_
{
	uint8_t               Version;
	uint8_t               Command;
	uint16_t              Remote_Port;
	in_addr               Remote_Address;
}socks4_server_command_reply;

//SOCKS version 5 client request message
/*
                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |    Command    |   Reserved    | Address Type  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                        Remote Address                         /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Remote Port           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _socks5_client_command_request_
{
	uint8_t               Version;
	uint8_t               Command;
	uint8_t               Reserved;
	uint8_t               Address_Type;
//	uint8_t               *Remote_Address;
//	uint16_t              Remote_Port;
}socks5_client_command_request;

//SOCKS version 5 server reply message
/*
                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Reply     |   Reserved    | Address Type  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                         Bind Address                          /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Bind Port           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _socks5_server_command_reply_
{
	uint8_t               Version;
	uint8_t               Reply;
	uint8_t               Reserved;
	uint8_t               Bind_Address_Type;
//	uint8_t               *Bind_Address;
//	uint16_t              Bind_Port;
}socks5_server_command_reply;

//SOCKS UDP relay request
/*
                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Reserved            |Fragment Number| Address Type  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                        Remote Address                         /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Remote Port           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
typedef struct _socks_udp_relay_request_
{
	uint16_t              Reserved;
	uint8_t               FragmentNumber;
	uint8_t               Address_Type;
//	uint8_t               *Remote_Address;
//	uint16_t              Remote_Port;
}socks_udp_relay_request;


// Hypertext Transfer Protocol/HTTP part
/* About RFC standards
* RFC 7230, Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing(https://tools.ietf.org/html/rfc7230)
* RFC 7231, Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content(https://tools.ietf.org/html/rfc7231)
* RFC 7235, Hypertext Transfer Protocol (HTTP/1.1): Authentication(https://tools.ietf.org/html/rfc7235)
* RFC 7540, Hypertext Transfer Protocol Version 2 (HTTP/2)(https://tools.ietf.org/html/rfc7540)
* RFC 7541, HPACK: Header Compression for HTTP/2(https://tools.ietf.org/html/rfc7541)
* RFC 7617, The 'Basic' HTTP Authentication Scheme(https://tools.ietf.org/html/rfc7617)
*/
//Size and data definitions
#define HTTP_STATUS_CODE_SIZE                       3U
#if defined(ENABLE_TLS)
#if defined(PLATFORM_WIN)
#if !defined(PLATFORM_WIN_XP)
#define HTTP_1_TLS_ALPN_STRING                      ("http/1.1")
#define HTTP_2_TLS_ALPN_STRING                      ("h2")
#endif
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
#define HTTP_1_TLS_ALPN_STRING                      {8U, 'h', 't', 't', 'p', '/', '1', '.', '1'}
#define HTTP_2_TLS_ALPN_STRING                      {2U, 'h', '2'}
#endif
#endif
/* Hypertext Transfer Protocol Version 2 (HTTP/2) frame header

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Length                     |     Type      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Flags     |R|              Stream Identifier              |   R/Reserved
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Stream ID   |                    Payload                    /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Padload                            /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define HTTP_2_FRAME_TYPE_DATA                      0
#define HTTP_2_FRAME_TYPE_HEADERS                   1U
#define HTTP_2_FRAME_TYPE_PRIORITY                  2U
#define HTTP_2_FRAME_TYPE_RST_STREAM                3U
#define HTTP_2_FRAME_TYPE_SETTINGS                  4U
#define HTTP_2_FRAME_TYPE_PUSH_PROMISE              5U
#define HTTP_2_FRAME_TYPE_PING                      6U
#define HTTP_2_FRAME_TYPE_GOAWAY                    7U
#define HTTP_2_FRAME_TYPE_WINDOW_UPDATE             8U
#define HTTP_2_FRAME_TYPE_CONTINUATION              9U
#define HTTP_2_FRAME_INIT_STREAM_ID                 1U
#define HTTP_2_FREAM_MAXSIZE                        16383U
#define HTTP_2_CONNECTION_CLIENT_PREFACE            ("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
typedef struct _http2_frame_hdr_
{
	uint8_t               Length_High;
	uint16_t              Length_Low;
	uint8_t               Type;
	uint8_t               Flags;
	uint32_t              StreamIdentifier;
//	uint8_t               *Payload;
}http2_frame_hdr;

//No padding at all, so do not need DATA frame header.
/* Hypertext Transfer Protocol Version 2 (HTTP/2) DATA frame header

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/Padding Length /                     Data                      /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                             Data                              /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Padding                            /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define HTTP_2_DATA_FLAGS_END_STREAM                 0x01
/*
typedef struct _http2_data_frame_hdr_
{
//	uint8_t               PaddingLength;
	uint8_t               *Data;
//	uint8_t               *Padding;
}http2_data_frame_hdr;
*/

/* Hypertext Transfer Protocol Version 2 (HTTP/2) HEADERS frame header

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/Padding Length /E|              Stream Dependency              /   E/Explicitly
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/      SD       /    Weight     /     Header Block Fragment     /   SD/Stream Dependency
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                     Header Block Fragment                     /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Padding                            /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define HTTP_2_HEADERS_FLAGS_END_STREAM              0x01
#define HTTP_2_HEADERS_FLAGS_END_HEADERS             0x04
#define HTTP_2_HEADERS_FLAGS_PADDED                  0x08
#define HTTP_2_HEADERS_FLAGS_PRIORITY                0x20
#define HTTP_2_HEADERS_LITERAL_WITHOUT_INDEXED       0
#define HTTP_2_HEADERS_LITERAL_NEVER_INDEXED         0x10
#define HTTP_2_HEADERS_LITERAL_TABLE_SIZE_UPDATE     0x20
#define HTTP_2_HEADERS_LITERAL_INCREMENTAL_INDEXED   0x40
#define HTTP_2_HEADERS_LITERAL_LOW_1_BITS            0x01
#define HTTP_2_HEADERS_LITERAL_LOW_2_BITS            0x03
#define HTTP_2_HEADERS_LITERAL_LOW_3_BITS            0x07
#define HTTP_2_HEADERS_LITERAL_LOW_4_BITS            0x0F
#define HTTP_2_HEADERS_LITERAL_LOW_5_BITS            0x1F
#define HTTP_2_HEADERS_LITERAL_LOW_6_BITS            0x3F
#define HTTP_2_HEADERS_LITERAL_LOW_7_BITS            0x7F
#define HTTP_2_HEADERS_LITERAL_HIGH_1_BITS           0x80
#define HTTP_2_HEADERS_LITERAL_HIGH_2_BITS           0xC0
#define HTTP_2_HEADERS_LITERAL_HIGH_3_BITS           0xE0
#define HTTP_2_HEADERS_LITERAL_HIGH_4_BITS           0xF0
#define HTTP_2_HEADERS_LITERAL_INDEXED_STATUS_200    0x88
#define HTTP_2_HEADERS_INTEGER_LOW_1_BITS            HTTP_2_HEADERS_LITERAL_LOW_1_BITS
#define HTTP_2_HEADERS_INTEGER_LOW_2_BITS            HTTP_2_HEADERS_LITERAL_LOW_2_BITS
#define HTTP_2_HEADERS_INTEGER_LOW_3_BITS            HTTP_2_HEADERS_LITERAL_LOW_3_BITS
#define HTTP_2_HEADERS_INTEGER_LOW_4_BITS            HTTP_2_HEADERS_LITERAL_LOW_4_BITS
#define HTTP_2_HEADERS_INTEGER_LOW_5_BITS            HTTP_2_HEADERS_LITERAL_LOW_5_BITS
#define HTTP_2_HEADERS_INTEGER_LOW_6_BITS            HTTP_2_HEADERS_LITERAL_LOW_6_BITS
#define HTTP_2_HEADERS_INTEGER_LOW_7_BITS            HTTP_2_HEADERS_LITERAL_LOW_7_BITS
#define HTTP_2_HEADERS_INTEGER_HIGH_1_BITS           HTTP_2_HEADERS_LITERAL_HIGH_1_BITS
/*
typedef struct _http2_headers_frame_hdr_
{
//	uint8_t               PaddingLength;
//	uint32_t              StreamDependency;
//	uint8_t               Weight;
	uint8_t               *HeaderBlockFragment;
//	uint8_t               *Padding;
}http2_headers_frame_hdr;
*/

/* Hypertext Transfer Protocol Version 2 (HTTP/2) PRIORITY frame

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|E|                      Stream Dependency                      |   E/Explicitly
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Weigth     |
+-+-+-+-+-+-+-+-+
*/
typedef struct _http2_priority_frame_
{
	uint32_t              StreamDependency;
	uint8_t               Weight;
}http2_priority_frame;

/* Hypertext Transfer Protocol Version 2 (HTTP/2) RST_STREAM frame

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Error Code                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define HTTP_2_ERROR_NO_ERROR                        0
#define HTTP_2_ERROR_PROTOCOL_ERROR                  1U
#define HTTP_2_ERROR_INTERNAL_ERROR                  2U
#define HTTP_2_ERROR_FLOW_CONTROL_ERROR              3U
#define HTTP_2_ERROR_SETTINGS_TIMEOUT                4U
#define HTTP_2_ERROR_STREAM_CLOSED                   5U
#define HTTP_2_ERROR_FRAME_SIZE_ERROR                6U
#define HTTP_2_ERROR_REFUSED_STREAM                  7U
#define HTTP_2_ERROR_CANCEL                          8U
#define HTTP_2_ERROR_COMPRESSION_ERROR               9U
#define HTTP_2_ERROR_CONNECT_ERROR                   10U
#define HTTP_2_ERROR_ENHANCE_YOUR_CALM               11U
#define HTTP_2_ERROR_INADEQUATE_SECURITY             12U
#define HTTP_2_ERROR_HTTP_1_1_REQUIRED               13U
typedef struct _http2_rst_stream_frame_
{
	uint32_t               ErrorCode;
}http2_rst_stream_frame;

/* Hypertext Transfer Protocol Version 2 (HTTP/2) SETTINGS frame

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Identifier           |             Value             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Value             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define HTTP_2_SETTINGS_TYPE_HEADERS_TABLE_SIZE       1U
#define HTTP_2_SETTINGS_TYPE_ENABLE_PUSH              2U
#define HTTP_2_SETTINGS_TYPE_MAX_CONCURRENT_STREAMS   3U
#define HTTP_2_SETTINGS_TYPE_INITIAL_WINDOW_SIZE      4U
#define HTTP_2_SETTINGS_TYPE_MAX_FRAME_SIZE           5U
#define HTTP_2_SETTINGS_TYPE_MAX_HEADERS_LIST_SIZE    6U
#define HTTP_2_SETTINGS_FLAGS_ACK                     0x01
#define HTTP_2_SETTINGS_INIT_HEADERS_TABLE_SIZE       4096U
#define HTTP_2_SETTINGS_INIT_ENABLE_PUSH              1U
#define HTTP_2_SETTINGS_INIT_MAX_CONCURRENT_STREAMS   100U
#define HTTP_2_SETTINGS_INIT_INITIAL_WINDOW_SIZE      65535U
#define HTTP_2_SETTINGS_INIT_MAX_FRAME_SIZE           16384U
typedef struct _http2_settings_frame_
{
	uint16_t               Identifier;
	uint32_t               Value;
}http2_settings_frame;

/* Hypertext Transfer Protocol Version 2 (HTTP/2) PUSH_PROMISE frame header

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/Padding Length /R|             Promised Stream ID              /   R/Reserved
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/      SD       /    Weight     /     Header Block Fragment     /   SD/Stream Dependency
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                     Header Block Fragment                     /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                            Padding                            /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

typedef struct _http2_push_promise_frame_hdr_
{
//	uint8_t               PaddingLength;
//	uint32_t              PromisedStreamID;
	uint8_t               *HeaderBlockFragment;
//	uint8_t               *Padding;
}http2_push_promise_frame_hdr;
*/

/* Hypertext Transfer Protocol Version 2 (HTTP/2) PING frame

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Opaque Data                          |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
#define HTTP_2_PING_FLAGS_ACK                        0x01
typedef struct _http2_ping_frame_
{
	uint64_t               OpaqueData;
}http2_ping_frame;

/* Hypertext Transfer Protocol Version 2 (HTTP/2) GOAWAY frame

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|                       Last-Stream-ID                        |   R/Reserved
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Error Code                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                     Additional Debug Data                     /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct _http2_goaway_frame_
{
	uint32_t               LastStreamID;
	uint32_t               ErrorCode;
}http2_goaway_frame;

/* Hypertext Transfer Protocol Version 2 (HTTP/2) WINDOW_UPDATE frame

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|R|                  Window Size Increment                      |   R/Reserved
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
typedef struct _http2_window_update_frame_
{
	uint32_t               WindowSizeIncrement;
}http2_window_update_frame;

/* Hypertext Transfer Protocol Version 2 (HTTP/2) CONTINUATION frame

                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
/                     Header Block Fragment                     /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

typedef struct _http2_continuation_frame_
{
	uint8_t               *HeaderBlockFragment;
}http2_continuation_frame;
*/


#if defined(ENABLE_TLS)
//TLS Protocol part
//TLS base record
/*
                    1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3 3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Content Type  |            Version            |    Length     /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/    Length     |                    Payload                    /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-++-+-+-+-+-+-+

*/
#define TLS_VERSION_MIN                             0x0301                      //TLS 1.0 = SSL 3.1
typedef struct _tls_base_record_
{
	uint8_t               ContentType;
	uint16_t              Version;
	uint16_t              Length;
}tls_base_record;
#endif

//Memory alignment settings(Part 2)
#pragma pack(pop) //Restore original alignment from stack.
#endif
