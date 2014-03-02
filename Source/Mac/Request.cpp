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


#include "Pcap_DNSProxy.h"

#define Interval          5           //5s between every sending
#define OnceSend          3

extern Configuration Parameter;
extern PortTable PortList;

//Get TTL(IPv4)/Hop Limits(IPv6) with common DNS request
size_t DomainTest(const size_t Protocol)
{
//Initialization
	char *Buffer = nullptr, *DNSQuery = nullptr;
	try {
		Buffer = new char[PACKET_MAXSIZE]();
		DNSQuery = new char[PACKET_MAXSIZE/4]();
	}
	catch (std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", NULL, NULL);

		delete[] Buffer;
		delete[] DNSQuery;
		return EXIT_FAILURE;
	}
	memset(Buffer, 0, PACKET_MAXSIZE);
	memset(DNSQuery, 0, PACKET_MAXSIZE/4);
	SOCKET_DATA SetProtocol = {0};

//Set request protocol
	if (Protocol == AF_INET6) //IPv6
		SetProtocol.AddrLen = sizeof(sockaddr_in6);
	else //IPv4
		SetProtocol.AddrLen = sizeof(sockaddr_in);
	
//Make a DNS request with Doamin Test packet
	dns_hdr *TestHdr = (dns_hdr *)Buffer;
	TestHdr->ID = Parameter.DomainTestOptions.DomainTestID;
	TestHdr->Flags = htons(0x0100); //System Standard query
	TestHdr->Questions = htons(0x0001);
	size_t TestLength = 0;

//From Parameter
	if (Parameter.DomainTestOptions.DomainTestCheck)
	{
		TestLength = CharToDNSQuery(Parameter.DomainTestOptions.DomainTest, DNSQuery);
		if (TestLength > 0 && TestLength < PACKET_MAXSIZE - sizeof(dns_hdr))
		{
			memcpy(Buffer + sizeof(dns_hdr), DNSQuery, TestLength);
			dns_qry *TestQry = (dns_qry *)(Buffer + sizeof(dns_hdr) + TestLength);
			TestQry->Classes = htons(Class_IN);
			if (Protocol == AF_INET6)
				TestQry->Type = htons(AAAA_Records);
			else
				TestQry->Type = htons(A_Records);
			delete[] DNSQuery;
		}
		else {
			delete[] Buffer;
			delete[] DNSQuery;
			return EXIT_FAILURE;
		}
	}

//Send
	size_t Times = 0;
	while (true)
	{
		if (Times == OnceSend)
		{
			Times = 0;
			if ((Parameter.DNSTarget.IPv4 && Parameter.HopLimitOptions.IPv4TTL == 0) || //IPv4
				(Parameter.DNSTarget.IPv6 && Parameter.HopLimitOptions.IPv6HopLimit == 0)) //IPv6
			{
				sleep(Interval); //5 seconds between every sending.
				continue;
			}

			sleep(Parameter.DomainTestOptions.DomainTestSpeed);
		}
		else {
			//Ramdom domain request
			if (!Parameter.DomainTestOptions.DomainTestCheck)
			{
				RamdomDomain(Parameter.DomainTestOptions.DomainTest, PACKET_MAXSIZE/8);
				TestLength = CharToDNSQuery(Parameter.DomainTestOptions.DomainTest, DNSQuery);
				memcpy(Buffer + sizeof(dns_hdr), DNSQuery, TestLength);

				dns_qry *TestQry = (dns_qry *)(Buffer + sizeof(dns_hdr) + TestLength);
				TestQry->Classes = htons(Class_IN);
				if (Protocol == AF_INET6)
					TestQry->Type = htons(AAAA_Records);
				else
					TestQry->Type = htons(A_Records);
			}

			UDPRequest(Buffer, TestLength + sizeof(dns_hdr) + 4, SetProtocol, THREAD_MAXNUM*THREAD_PARTNUM, false);
			sleep(Interval);
			Times++;
		}
	}

	delete[] Buffer;
	delete[] DNSQuery;
	return EXIT_SUCCESS;
}

//Internet Control Message Protocol/ICMP Echo(Ping) request(Linux/Mac)
size_t ICMPEcho()
{
//Initialization
	char *Buffer = nullptr;
	try {
		Buffer = new char[PACKET_MAXSIZE]();
	}
	catch (std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", NULL, NULL);
		
		return EXIT_FAILURE;
	}
	memset(Buffer, 0, PACKET_MAXSIZE);
	sockaddr_storage SockAddr = {0};
	int Request = 0;

//Make a ICMP request echo packet
	icmp_hdr *icmp = (icmp_hdr *)Buffer;
	icmp->Type = 8; //Echo(Ping) request type
	icmp->ID = htons(Parameter.ICMPOptions.ICMPID);
	icmp->Sequence = htons(Parameter.ICMPOptions.ICMPSequence);
	memcpy(Buffer + sizeof(icmp_hdr), Parameter.PaddingDataOptions.PaddingData, Parameter.PaddingDataOptions.PaddingDataLength - 1);
	
	Request = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	SockAddr.ss_family = AF_INET;
	((sockaddr_in *)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4Target;

//Check socket
	if (Request == RETURN_ERROR)
	{
		PrintError(Socket_Error, L"ICMP Echo(Ping) request error", errno, NULL);
		
		delete[] Buffer;
		close(Request);
		return EXIT_FAILURE;
	}

//Send
	size_t Times = 0;
	while (true)
	{
	//Set TimeStamp and Nonce
		icmp->TimeStamp = time((time_t *)NULL);
	//Formula: [M, N] -> rand()%(N-M+1)+M
		srand((u_int)time((time_t *)NULL));
		Parameter.ICMPOptions.ICMPNonce = rand() % 15728640 + 1048576; //Between 0x100000 and 0xFFFFFF
		icmp->Nonce = Parameter.ICMPOptions.ICMPNonce;
		icmp->Checksum = GetChecksum((uint16_t *)Buffer, sizeof(icmp_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1);
		
	//Send
		sendto(Request, Buffer, sizeof(icmp_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1, NULL, (sockaddr *)&SockAddr,  sizeof(sockaddr_in));

		if (Times == OnceSend)
		{
			Times = 0;
			if (Parameter.HopLimitOptions.IPv4TTL == 0)
			{
				sleep(Interval); //5 seconds between every sending.
				continue;
			}
			
			sleep(Parameter.ICMPOptions.ICMPSpeed);
		}
		else {
			sleep(Interval);
			Times++;
		}
	}

	delete[] Buffer;
	close(Request);
	return EXIT_SUCCESS;
}

//Internet Control Message Protocol Echo version 6/ICMPv6 Echo(Ping) request
size_t ICMPv6Echo()
{
//Initialization
	char *Buffer = nullptr, *ICMPv6Checksum = nullptr;
	try {
		Buffer = new char[PACKET_MAXSIZE]();
		ICMPv6Checksum = new char[PACKET_MAXSIZE]();
	}
	catch (std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", NULL, NULL);

		delete[] Buffer;
		delete[] ICMPv6Checksum;
		return EXIT_FAILURE;
	}
	memset(Buffer, 0, PACKET_MAXSIZE);
	memset(ICMPv6Checksum, 0, PACKET_MAXSIZE);
	sockaddr_storage SockAddr = {0};
	int Request = 0;

//Make a IPv6 ICMPv6 request echo packet
	icmpv6_hdr *icmpv6 = (icmpv6_hdr *)Buffer;
	icmpv6->Type = ICMPV6_REQUEST;
	icmpv6->Code = 0;
	icmpv6->ID = htons(Parameter.ICMPOptions.ICMPID);
	icmpv6->Sequence = htons(Parameter.ICMPOptions.ICMPSequence);

//Validate local IPv6 address
	ipv6_psd_hdr *psd = (ipv6_psd_hdr *)ICMPv6Checksum;
	psd->Dst = Parameter.DNSTarget.IPv6Target;
	if (!GetLocalAddress(SockAddr, AF_INET6))
	{
		PrintError(Socket_Error, L"Get local IPv6 address error", NULL, NULL);
		
		delete[] Buffer;
		delete[] ICMPv6Checksum;
		return EXIT_FAILURE;
	}
//End

	psd->Src = ((sockaddr_in6 *)&SockAddr)->sin6_addr;
	memset(&SockAddr, 0, sizeof(sockaddr_storage));
	psd->Length = htonl((uint32_t)(sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1));
	psd->Next_Header = IPPROTO_ICMPV6;

	memcpy(ICMPv6Checksum + sizeof(ipv6_psd_hdr), icmpv6, sizeof(icmpv6_hdr));
	memcpy(ICMPv6Checksum + sizeof(ipv6_psd_hdr) + sizeof(icmpv6_hdr), &Parameter.PaddingDataOptions.PaddingData, Parameter.PaddingDataOptions.PaddingDataLength - 1);
	icmpv6->Checksum = htons(GetChecksum((uint16_t *)ICMPv6Checksum, sizeof(ipv6_psd_hdr) + sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1));
	delete[] ICMPv6Checksum;

	Request = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	SockAddr.ss_family = AF_INET6;
	((sockaddr_in6 *)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6Target;

//Check socket
	if (Request == RETURN_ERROR)
	{
		PrintError(Socket_Error, L"ICMPv6 Echo(Ping) request error", errno, NULL);
		
		delete[] Buffer;
		close(Request);
		return EXIT_FAILURE;
	}

//Send
	size_t Times = 0;
	while (true)
	{
		sendto(Request, Buffer, sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1, NULL, (sockaddr *)&SockAddr, sizeof(sockaddr_in6));

		if (Times == OnceSend)
		{
			Times = 0;
			if (Parameter.HopLimitOptions.IPv6HopLimit == 0)
			{
				sleep(Interval);
				continue;
			}

			sleep(Parameter.ICMPOptions.ICMPSpeed);
		}
		else {
			Times++;
			sleep(Interval);
		}
	}

	delete[] Buffer;
	close(Request);
	return EXIT_SUCCESS;
}

//Transmission and reception of TCP protocol(Independent)
size_t TCPRequest(const char *Send, const size_t SendSize, char *Recv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool Local)
{
//Initialization
	char *SendBuffer = nullptr, *RecvBuffer = nullptr;
	try {
		SendBuffer = new char[PACKET_MAXSIZE]();
		RecvBuffer = new char[PACKET_MAXSIZE]();
	}
	catch (std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", NULL, NULL);
		
		delete[] SendBuffer;
		delete[] RecvBuffer;
		return EXIT_FAILURE;
	}
	memset(SendBuffer, 0, PACKET_MAXSIZE);
	memset(RecvBuffer, 0, PACKET_MAXSIZE);
	sockaddr_storage SockAddr = {0};
	int TCPSocket = 0;
	memcpy(RecvBuffer, Send, SendSize);

//Add length of request packet(It must be written in header when transpot with TCP protocol)
	uint16_t DataLength = htons((uint16_t)SendSize);
	memcpy(SendBuffer, &DataLength, sizeof(uint16_t));
	memcpy(SendBuffer + sizeof(uint16_t), RecvBuffer, SendSize);
	memset(RecvBuffer, 0, PACKET_MAXSIZE);

//Socket initialization
	if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
	{
		TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (Local && Parameter.DNSTarget.Local_IPv6)
			((sockaddr_in6 *)&SockAddr)->sin6_addr = Parameter.DNSTarget.Local_IPv6Target;
		else
			((sockaddr_in6 *)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6Target;
		SockAddr.ss_family = AF_INET6;
		((sockaddr_in6 *)&SockAddr)->sin6_port = htons(DNS_Port);
	}
	else { //IPv4
		TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (Local && Parameter.DNSTarget.Local_IPv4)
			((sockaddr_in *)&SockAddr)->sin_addr = Parameter.DNSTarget.Local_IPv4Target;
		else
			((sockaddr_in *)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4Target;
		SockAddr.ss_family = AF_INET;
		((sockaddr_in *)&SockAddr)->sin_port = htons(DNS_Port);
	}

	if (TCPSocket == RETURN_ERROR)
	{
		PrintError(Socket_Error, L"TCP request initialization failed", errno, NULL);
		
		delete[] SendBuffer;
		delete[] RecvBuffer;
		close(TCPSocket);
		return EXIT_FAILURE;
	}

//Connect to server
	if (connect(TCPSocket, (sockaddr *)&SockAddr, TargetData.AddrLen) == RETURN_ERROR) //The connection is RESET or other errors when connecting.
	{
		delete[] SendBuffer;
		delete[] RecvBuffer;
		close(TCPSocket);
		return FALSE;
	}

//Send request
	if (send(TCPSocket, SendBuffer, SendSize + sizeof(uint16_t), NULL) == RETURN_ERROR) //The connection is RESET or other errors when sending.
	{
		delete[] SendBuffer;
		delete[] RecvBuffer;
		close(TCPSocket);
		return FALSE;
	}
	delete[] SendBuffer;

//Receive result
	ssize_t RecvLen = recv(TCPSocket, RecvBuffer, RecvSize, NULL) - sizeof(uint16_t);
	if (RecvLen <= FALSE) //The connection is RESET or other errors(including SOCKET_ERROR) when sending.
	{
		delete[] RecvBuffer;
		close(TCPSocket);
		return FALSE;
	}
	memcpy(Recv, RecvBuffer + sizeof(uint16_t), RecvLen);

	delete[] RecvBuffer;
	close(TCPSocket);
	return RecvLen;
}

//Transmission of UDP protocol
size_t UDPRequest(const char *Send, const size_t Length, const SOCKET_DATA TargetData, const size_t Index, const bool Local)
{
	//Initialization
	char *Buffer = nullptr;
	try {
		Buffer = new char[PACKET_MAXSIZE]();
	}
	catch (std::bad_alloc)
	{
		PrintError(System_Error, L"Memory allocation failed", NULL, NULL);
		
		return EXIT_FAILURE;
	}
	memset(Buffer, 0, PACKET_MAXSIZE);
	sockaddr_storage SockAddr = {0};
	int UDPSocket = 0;
	memcpy(Buffer, Send, Length);

//Socket initialization
	if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
	{
		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		if (Local && Parameter.DNSTarget.Local_IPv6)
			((sockaddr_in6 *)&SockAddr)->sin6_addr = Parameter.DNSTarget.Local_IPv6Target;
		else
			((sockaddr_in6 *)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6Target;
		SockAddr.ss_family = AF_INET6;
		((sockaddr_in6 *)&SockAddr)->sin6_port = htons(DNS_Port);
	}
	else { //IPv4
		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (Local && Parameter.DNSTarget.Local_IPv4)
			((sockaddr_in *)&SockAddr)->sin_addr = Parameter.DNSTarget.Local_IPv4Target;
		else
			((sockaddr_in *)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4Target;
		SockAddr.ss_family = AF_INET;
		((sockaddr_in *)&SockAddr)->sin_port = htons(DNS_Port);
	}
	
	if (UDPSocket == RETURN_ERROR)
	{
		PrintError(Socket_Error, L"UDP request initialization failed", errno, NULL);
		
		delete[] Buffer;
		close(UDPSocket);
		return EXIT_FAILURE;
	}
	
//Send request
	if (sendto(UDPSocket, Buffer, Length, NULL, (sockaddr *)&SockAddr, TargetData.AddrLen) == RETURN_ERROR)
	{
		PrintError(Socket_Error, L"UDP request error", errno, NULL);
		
		delete[] Buffer;
		close(UDPSocket);
		return EXIT_FAILURE;
	}

//Mark port(s) to list
	if (Index < THREAD_MAXNUM*THREAD_PARTNUM)
	{
		if (getsockname(UDPSocket, (sockaddr *)&SockAddr, (socklen_t *)&TargetData.AddrLen) != 0)
		{
			delete[] Buffer;
			close(UDPSocket);
			return EXIT_FAILURE;
		}
		if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			PortList.SendPort[Index] = ((sockaddr_in6 *)&SockAddr)->sin6_port;
		else //IPv4
			PortList.SendPort[Index] = ((sockaddr_in *)&SockAddr)->sin_port;
	}

//Receive to disable ICMP report(Linux/Mac)
	socklen_t SockLen = 0;
	recvfrom(UDPSocket, Buffer, PACKET_MAXSIZE, NULL, (sockaddr *)&SockAddr, &SockLen);
	
	delete[] Buffer;
	close(UDPSocket);
	return EXIT_SUCCESS;
}
