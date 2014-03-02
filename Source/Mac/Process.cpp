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

PortTable PortList;
regex_t IPv4PrivateB = {0}, IPv6ULA = {0}, IPv6LUC = {0};

extern Configuration Parameter;
extern std::string LocalhostPTR[2];
extern std::vector<HostsTable> *Using;

//Independent request process
size_t RequestProcess(const char *Send, const size_t Length, const SOCKET_DATA FunctionData, const size_t Protocol, const size_t Index)
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
	dns_hdr *dnshdr = (dns_hdr *)SendBuffer;
	memcpy(SendBuffer, Send, Length);
	bool Local = false;

//Check hosts
	if (dnshdr->Questions == htons(0x0001))
	{
		size_t HostLength = CheckHosts(SendBuffer, Length, RecvBuffer, Local);
		if (HostLength > sizeof(dns_hdr) && HostLength < PACKET_MAXSIZE)
		{
			if (Protocol == IPPROTO_TCP) //TCP
			{
				uint16_t DataLength = htons((uint16_t)HostLength);
				send((int)FunctionData.Socket, (char *)&DataLength, sizeof(uint16_t), NULL);
				send((int)FunctionData.Socket, RecvBuffer, HostLength, NULL);
			}
			else { //UDP
				sendto((int)FunctionData.Socket, RecvBuffer, HostLength, NULL, (sockaddr *)&(FunctionData.SockAddr), FunctionData.AddrLen);
			}
			
			delete[] SendBuffer;
			delete[] RecvBuffer;
			return EXIT_SUCCESS;
		}
	}

	if (Parameter.TCPMode && Length < PACKET_MAXSIZE - sizeof(uint16_t))
	{
		size_t SendLen = TCPRequest(SendBuffer, Length, RecvBuffer, PACKET_MAXSIZE, FunctionData, Local);
		if (SendLen > sizeof(dns_hdr) && SendLen < PACKET_MAXSIZE)
		{
			if (Protocol == IPPROTO_TCP) //TCP
			{
				uint16_t DataLength = htons((uint16_t)SendLen);
				send((int)FunctionData.Socket, (char *)&DataLength, sizeof(uint16_t), NULL);
				send((int)FunctionData.Socket, RecvBuffer, SendLen, NULL);
			}
			else { //UDP
				sendto((int)FunctionData.Socket, RecvBuffer, SendLen, NULL, (sockaddr *)&(FunctionData.SockAddr), FunctionData.AddrLen);
			}
		}
		else { //The connection is RESET or other errors when connecting.
			PortList.RecvData[Index] = FunctionData;
			UDPRequest(SendBuffer, Length, FunctionData, Index, Local);
		}
	}
	else {
		PortList.RecvData[Index] = FunctionData;
		UDPRequest(SendBuffer, Length, FunctionData, Index, Local);
	}

	delete[] SendBuffer;
	delete[] RecvBuffer;
	return EXIT_SUCCESS;
}

//Check hosts from list(Linux/Mac)
inline size_t CheckHosts(const char *Request, const size_t Length, char *Result, bool &Local)
{
//Initilization
	DNSQueryToChar(Request + sizeof(dns_hdr), Result);
	std::string Domain(Result);
	memset(Result, 0, PACKET_MAXSIZE);

//Response
	memcpy(Result, Request, Length);
	dns_hdr *hdr = (dns_hdr *)Result;
	hdr->Flags = htons(0x8180); //Standard query response and no error
	dns_qry *qry = (dns_qry *)(Result + Length - sizeof(dns_qry));

//Class IN
	if (qry->Classes != htons(Class_IN))
	{
		memset(Result, 0, PACKET_MAXSIZE);
		return FALSE;
	}
	
//PTR Records
	if (qry->Type == htons(PTR_Records))
	{
	//IPv4 check
		if (Domain.find(LocalhostPTR[0]) != std::string::npos || //IPv4 Localhost
			Domain.find(".10.in-addr.arpa") != std::string::npos || //Private class A address(10.0.0.0/8, Section 3 in RFC 1918)
			Domain.find(".127.in-addr.arpa") != std::string::npos || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
			Domain.find(".254.169.in-addr.arpa") != std::string::npos || //Link-local address(169.254.0.0/16, RFC 3927)
			regexec(&IPv4PrivateB, Domain.c_str(), 0, 0, 0) == 0 || //Private class B address(172.16.0.0/16, Section 3 in RFC 1918)
			Domain.find(".168.192.in-addr.arpa") != std::string::npos || //Private class C address(192.168.0.0/24, Section 3 in RFC 1918)
		//IPv6 check
			Domain.find("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa") != std::string::npos || //Loopback address(::1, Section 2.5.3 in RFC 4291)
			Domain.find(LocalhostPTR[1]) != std::string::npos || //IPv6 Localhost
			regexec(&IPv6ULA, Domain.c_str(), 0, 0, 0) == 0 || //Unique Local Unicast address/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
			regexec(&IPv6LUC, Domain.c_str(), 0, 0, 0) == 0) //Link-Local Unicast Contrast address(FE80::/10, Section 2.5.6 in RFC 4291)
		{
			hdr->Answer = htons(0x0001);
			dns_ptr_record *rsp = (dns_ptr_record *)(Result + Length);
			rsp->Name = htons(0xC00C); //Pointer of same request
			rsp->Classes = htons(Class_IN); //Class IN
			rsp->TTL = htonl(600); //10 minutes
			rsp->Type = htons(PTR_Records);
			rsp->Length = htons((uint16_t)(Parameter.LocalhostServerOptions.LocalhostServerLength) + 1);
			memcpy(Result + Length + sizeof(dns_ptr_record), Parameter.LocalhostServerOptions.LocalhostServer, Parameter.LocalhostServerOptions.LocalhostServerLength + 1);
			return Length + sizeof(dns_ptr_record) + Parameter.LocalhostServerOptions.LocalhostServerLength + 2;
		}
	}

	if (!Using->empty())
	{
	//AAAA Records
		if (qry->Type == htons(AAAA_Records))
		{
			for (std::vector<HostsTable>::iterator iter = Using->begin();iter != Using->end();iter++)
			{
				if (regexec(&iter->Pattern, Domain.c_str(), 0, 0, 0) == 0)
				{
				//Check white list
					if (iter->White)
					{
						memset(Result, 0, PACKET_MAXSIZE);
						return EXIT_SUCCESS;
					}
				//Check local request
					else if (iter->Local)
					{
						Local = true;
						memset(Result, 0, PACKET_MAXSIZE);
						return EXIT_SUCCESS;
					}
				//Check Hosts
					else if (iter->Protocol == AF_INET6 && iter->ResponseLength > 0)
					{
						hdr->Answer = htons((uint16_t)iter->ResponseNum);
						memcpy(Result + Length, iter->Response, iter->ResponseLength);
						return Length + iter->ResponseLength;
					}
				}
			}
		}

	//A record
		if (qry->Type == htons(A_Records))
		{
			for (std::vector<HostsTable>::iterator iter = Using->begin();iter != Using->end();iter++)
			{
				if (regexec(&iter->Pattern, Domain.c_str(), 0, 0, 0) == 0)
				{
				//Check white list
					if (iter->White)
					{
						memset(Result, 0, PACKET_MAXSIZE);
						return EXIT_SUCCESS;
					}
				//Check local request
					else if (iter->Local)
					{
						Local = true;
						memset(Result, 0, PACKET_MAXSIZE);
						return EXIT_SUCCESS;
					}
				//Check Hosts
					else if (iter->Protocol == AF_INET && iter->ResponseLength > 0)
					{
						hdr->Answer = htons((uint16_t)iter->ResponseNum);
						memcpy(Result + Length, iter->Response, iter->ResponseLength);
						return Length + iter->ResponseLength;
					}
				}
			}
		}
	}

	memset(Result, 0, PACKET_MAXSIZE);
	return EXIT_SUCCESS;
}

//TCP protocol receive process
size_t TCPReceiveProcess(const SOCKET_DATA FunctionData, const size_t Index)
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

//Receive
	bool PUD = false, Sign = false;
	ssize_t RecvLength = 0;
	while (!Sign)
	{
		RecvLength = recv((int)FunctionData.Socket, Buffer, PACKET_MAXSIZE, NULL);
		if (RecvLength == (ssize_t)sizeof(uint16_t)) //TCP segment of a reassembled PDU
		{
			PUD = true;
			continue;
		}
		else if (RecvLength >= (ssize_t)sizeof(dns_hdr))
		{
			Sign = true;
			if (PUD)
			{
				if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
					RequestProcess(Buffer, RecvLength, FunctionData, IPPROTO_TCP, Index + THREAD_MAXNUM*(THREAD_PARTNUM - 2));
				else //IPv4
					RequestProcess(Buffer, RecvLength, FunctionData, IPPROTO_TCP, Index + THREAD_MAXNUM*(THREAD_PARTNUM - 1));
			}
			else {
				if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
					RequestProcess(Buffer + sizeof(uint16_t), RecvLength - sizeof(uint16_t), FunctionData, IPPROTO_TCP, Index + THREAD_MAXNUM*(THREAD_PARTNUM - 2));
				else //IPv4
					RequestProcess(Buffer + sizeof(uint16_t), RecvLength - sizeof(uint16_t), FunctionData, IPPROTO_TCP, Index + THREAD_MAXNUM*(THREAD_PARTNUM - 1));
				
			}
		}

		break;
	}

	delete[] Buffer;
	return EXIT_SUCCESS;
}
