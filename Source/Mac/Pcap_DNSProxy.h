// This code is part of Pcap_DNSProxy(Mac)
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


#include "Pcap_DNSProxy_Base.h"

//Code define(Linux/Mac)
#define RETURN_ERROR      -1
#define FALSE             0                         //Microsoft Windows defined
#define TRUE              1                         //Microsoft Windows defined
#define PACKET_MAXSIZE    2048                      //Maximum length of packets(2048 bytes)
#define THREAD_MAXNUM     128                       //Maximum threads number
#define THREAD_PARTNUM    4                         //Parts of threads, also define localhost sockets number: 0 is IPv6/UDP, 1 is IPv4/UDP, 2 is IPv6/TCP, 3 is IPv4/TCP
#define TIME_OUT          1000                      //Timeout in seconds(1000 ms)

//Error Type define, see PrintError.cpp
#define System_Error      1
#define Parameter_Error   2
#define Hosts_Error       3
#define Socket_Error      4
#define LibPcap_Error     5

//Socket Data structure
typedef struct _socket_data_
{
	ssize_t               Socket;
	sockaddr_storage      SockAddr;
	socklen_t             AddrLen;
}SOCKET_Data, SOCKET_DATA;

//Configuration class(Linux/Mac)
class Configuration {
public:
	//Base block(Public)
	bool            PrintError;
	useconds_t      Hosts;
	ssize_t         LocalSocket[THREAD_PARTNUM];
	struct _dns_target_ {
		bool        IPv4;
		in_addr     IPv4Target;
		bool        IPv6;
		in6_addr    IPv6Target;
		bool        Local_IPv4;
		in_addr     Local_IPv4Target;
		bool        Local_IPv6;
		in6_addr    Local_IPv6Target;
	}DNSTarget;
	bool            ServerMode;
	bool            TCPMode;
	//Extend Test block(Public)
	struct _hoplimit_options_ {
		size_t      IPv4TTL;
		size_t      IPv6HopLimit;
		size_t      HopLimitFluctuation;
	}HopLimitOptions;
	bool            IPv4Options;
	struct _icmp_options_ {
		uint16_t    ICMPID;
		uint16_t    ICMPSequence;
		useconds_t  ICMPSpeed;
		uint64_t    ICMPNonce;
	}ICMPOptions;
	bool            TCPOptions;
	bool            DNSOptions;
	bool            Blacklist;
	//Data block(Public)
	struct _domaintest_options_ {
		bool        DomainTestCheck;
		char        *DomainTest;
		uint16_t    DomainTestID;
		useconds_t  DomainTestSpeed;
	}DomainTestOptions;
	struct _paddingdata_options_ {
		char        *PaddingData;
		size_t      PaddingDataLength;
	}PaddingDataOptions;
	struct _localhostserver_options_ {
		char        *LocalhostServer;
		size_t      LocalhostServerLength;
	}LocalhostServerOptions;
	Configuration();
	~Configuration();

	size_t ReadParameter();
	size_t ReadHosts();

private:
	size_t ReadParameterData(const char *Buffer, const size_t Line);
	size_t ReadHostsData(const char *Buffer, const size_t Line, bool &Local);
};

//Hosts list class
class HostsTable {
public:
	bool             Local, White;
	size_t           Protocol;
	char             *Response;
	size_t           ResponseLength, ResponseNum;
	regex_t          Pattern;

	HostsTable();
};

//System&Request port list class
class PortTable {
public:
	SOCKET_DATA      *RecvData;    //System receive sockets/Addresses records
	uint16_t         *SendPort;     //Request ports records
	PortTable();
	~PortTable();

	size_t MatchToSend(const char *Buffer, const size_t Length, const uint16_t RequestPort);
};

//ClassInitialization.cpp
void RegexInitialization();

//Main.cpp
size_t FileInitialization();

//PrintError.cpp
size_t PrintError(const size_t Type, const wchar_t *Message, const ssize_t Code, const size_t Line);

//Protocol.cpp
//uint64_t htonl64(uint64_t Val);
//uint64_t ntohl64(uint64_t Val);
//uint32_t GetFCS(const char *Buffer, const size_t Length);
uint16_t GetChecksum(const uint16_t *Buffer, const size_t Length);
uint16_t ICMPv6Checksum(const char *Buffer, const size_t Length);
bool CheckSpecialAddress(const void *pAddr, const size_t Protocol);
uint16_t UDPChecksum(const char *Buffer, const size_t Length, const size_t Protocol);
size_t CharToDNSQuery(const char *FName, char *TName);
size_t DNSQueryToChar(const char *TName, char *FName);
bool GetLocalAddress(sockaddr_storage &SockAddr, const size_t Protocol);
size_t LocalAddressToPTR(const size_t Protocol);
void RamdomDomain(char *Domain, const size_t Length);

//Configuration.cpp
inline void ReadEncoding(const char *Buffer, const size_t Length, size_t &Encoding, size_t &NextLineType);
inline void CleanupHostsTable();

//Capture.cpp
size_t CaptureInitialization();
size_t Capture(const pcap_if *pDrive);
size_t IPLayer(const char *Recv, const size_t Length, const uint16_t Protocol);
inline bool ICMPCheck(const char *Buffer, const size_t Length, const size_t Protocol);
inline bool TCPCheck(const char *Buffer);
inline bool DTDNSOCheck(const char *Buffer, bool &SignHopLimit);
inline size_t DNSMethod(const char *Recv, const size_t Length, const size_t Protocol, const bool Local);

//Request.cpp
size_t DomainTest(const size_t Protocol);
size_t ICMPEcho();
size_t ICMPv6Echo();
size_t TCPRequest(const char *Send, const size_t SendSize, char *Recv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool Local);
size_t UDPRequest(const char *Send, const size_t Length, const SOCKET_DATA TargetData, const size_t Index, const bool Local);

//Monitor.cpp
size_t MonitorInitialization();
size_t UDPMonitor(const SOCKET_DATA LocalhostData);
size_t TCPMonitor(const SOCKET_DATA LocalhostData);

//Process.cpp
size_t RequestProcess(const char *Send, const size_t Length, const SOCKET_DATA FunctionData, const size_t Protocol, const size_t Index);
inline size_t CheckHosts(const char *Request, const size_t Length, char *Result, bool &Local);
size_t TCPReceiveProcess(const SOCKET_DATA FunctionData, const size_t Index);
