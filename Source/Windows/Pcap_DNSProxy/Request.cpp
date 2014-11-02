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


#include "Pcap_DNSProxy.h"

extern Configuration Parameter;
extern PortTable PortList;
extern AlternateSwapTable AlternateSwapList;
extern std::mutex PortListLock;

//Get TTL(IPv4)/Hop Limits(IPv6) with normal DNS request
size_t __fastcall DomainTestRequest(const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> Buffer(new char[PACKET_MAXSIZE]()), DNSQuery(new char[PACKET_MAXSIZE]());
	SOCKET_DATA TargetData = {0};

//Set request protocol.
	if (Protocol == AF_INET6) //IPv6
		TargetData.AddrLen = sizeof(sockaddr_in6);
	else //IPv4
		TargetData.AddrLen = sizeof(sockaddr_in);

//Make a DNS request with Doamin Test packet.
	auto pdns_hdr = (dns_hdr *)Buffer.get();
	pdns_hdr->ID = Parameter.DomainTestOptions.DomainTestID;
	pdns_hdr->Flags = htons(DNS_STANDARD);
	pdns_hdr->Questions = htons(U16_NUM_1);
	size_t DataLength = 0;

//Fixed domain
	dns_qry *pdns_qry = nullptr;
	if (Parameter.DomainTestOptions.DomainTestData != nullptr)
	{
		DataLength = CharToDNSQuery(Parameter.DomainTestOptions.DomainTestData, DNSQuery.get());
		if (DataLength > 2U && DataLength < PACKET_MAXSIZE - sizeof(dns_hdr))
		{
			memcpy(Buffer.get() + sizeof(dns_hdr), DNSQuery.get(), DataLength);
			pdns_qry = (dns_qry *)(Buffer.get() + sizeof(dns_hdr) + DataLength);
			pdns_qry->Classes = htons(DNS_CLASS_IN);
			if (Protocol == AF_INET6)
				pdns_qry->Type = htons(DNS_AAAA_RECORDS);
			else 
				pdns_qry->Type = htons(DNS_A_RECORDS);
			DNSQuery.reset();
			DataLength += sizeof(dns_hdr) + sizeof(dns_qry);

		//EDNS0 Label
			if (Parameter.EDNS0Label) //No additional
			{
				dns_edns0_label *EDNS0 = (dns_edns0_label *)(Buffer.get() + DataLength);
				pdns_hdr->Additional = htons(U16_NUM_1);
				EDNS0->Type = htons(DNS_EDNS0_RECORDS);
				EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				DataLength += sizeof(dns_edns0_label);
			}
		}
		else {
			return EXIT_FAILURE;
		}
	}

//Send request.
	size_t Times = 0;
	auto ReTest = false;
	dns_edns0_label *EDNS0 = nullptr;
	UDP_REQUEST_MULTITHREAD_PARAMETER UDPRequestParameter = {Buffer.get(), 0, TargetData, QUEUE_MAXLEN * QUEUE_PARTNUM, 3U};

	while (true)
	{
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			ReTest = false;
			if (Protocol == AF_INET6) //IPv6
			{
				if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0 || //IPv6 Main
					Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL && Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0) //IPv6 Alternate
						ReTest = true;

			//Other(Multi)
				if (Parameter.DNSTarget.IPv6_Multi != nullptr)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
						{
							ReTest = true;
							break;
						}
					}
				}
			}
			else { //IPv4
				if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0 || //IPv4 Main
					Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL && Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0) //IPv4 Alternate
						ReTest = true;

			//Other(Multi)
				if (Parameter.DNSTarget.IPv4_Multi != nullptr)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
						{
							ReTest = true;
							break;
						}
					}
				}
			}

			if (ReTest)
			{
				Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND); //5 seconds between every sending.
				continue;
			}

			Sleep((DWORD)Parameter.DomainTestOptions.DomainTestSpeed);
		}
		else {
		//Main
			if (Parameter.DomainTestOptions.DomainTestData == nullptr) //Make ramdom domain request.
			{
				memset(Buffer.get() + sizeof(dns_hdr), 0, PACKET_MAXSIZE - sizeof(dns_hdr));
				MakeRamdomDomain(DNSQuery.get());
				DataLength = CharToDNSQuery(DNSQuery.get(), Buffer.get() + sizeof(dns_hdr));
				memset(DNSQuery.get(), 0, DOMAIN_MAXSIZE);
				
				pdns_qry = (dns_qry *)(Buffer.get() + sizeof(dns_hdr) + DataLength);
				pdns_qry->Classes = htons(DNS_CLASS_IN);
				if (Protocol == AF_INET6)
					pdns_qry->Type = htons(DNS_AAAA_RECORDS);
				else 
					pdns_qry->Type = htons(DNS_A_RECORDS);
				DataLength += sizeof(dns_hdr) + sizeof(dns_qry);

			//EDNS0 Label
				if (Parameter.EDNS0Label) //No additional
				{
					EDNS0 = (dns_edns0_label *)(Buffer.get() + DataLength);
					pdns_hdr->Additional = htons(U16_NUM_1);
					EDNS0->Type = htons(DNS_EDNS0_RECORDS);
					EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					DataLength += sizeof(dns_edns0_label);
				}
			}
			UDPRequest(Buffer.get(), DataLength, TargetData, QUEUE_MAXLEN * QUEUE_PARTNUM, false);

		//Alternate
			if (Parameter.DomainTestOptions.DomainTestData == nullptr) //Make ramdom domain request.
			{
				memset(Buffer.get() + sizeof(dns_hdr), 0, PACKET_MAXSIZE - sizeof(dns_hdr));
				MakeRamdomDomain(DNSQuery.get());
				DataLength = CharToDNSQuery(DNSQuery.get(), Buffer.get() + sizeof(dns_hdr));
				memset(DNSQuery.get(), 0, DOMAIN_MAXSIZE);
				
				pdns_qry = (dns_qry *)(Buffer.get() + sizeof(dns_hdr) + DataLength);
				pdns_qry->Classes = htons(DNS_CLASS_IN);
				if (Protocol == AF_INET6)
					pdns_qry->Type = htons(DNS_AAAA_RECORDS);
				else 
					pdns_qry->Type = htons(DNS_A_RECORDS);
				DataLength += sizeof(dns_hdr) + sizeof(dns_qry);

			//EDNS0 Label
				if (Parameter.EDNS0Label) //No additional
				{
					EDNS0 = (dns_edns0_label *)(Buffer.get() + DataLength);
					pdns_hdr->Additional = htons(U16_NUM_1);
					EDNS0->Type = htons(DNS_EDNS0_RECORDS);
					EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					DataLength += sizeof(dns_edns0_label);
				}
			}
			UDPRequest(Buffer.get(), DataLength, TargetData, QUEUE_MAXLEN * QUEUE_PARTNUM, true);

		//Other(Multi)
			if (Protocol == AF_INET6 && Parameter.DNSTarget.IPv6_Multi != nullptr) //IPv6
			{
				for (size_t Index = 0;Index < Parameter.DNSTarget.IPv6_Multi->size();Index++)
				{
					if (Parameter.DomainTestOptions.DomainTestData == nullptr) //Make ramdom domain request.
					{
						memset(Buffer.get() + sizeof(dns_hdr), 0, PACKET_MAXSIZE - sizeof(dns_hdr));
						MakeRamdomDomain(DNSQuery.get());
						DataLength = CharToDNSQuery(DNSQuery.get(), Buffer.get() + sizeof(dns_hdr));
						memset(DNSQuery.get(), 0, DOMAIN_MAXSIZE);
				
						pdns_qry = (dns_qry *)(Buffer.get() + sizeof(dns_hdr) + DataLength);
						pdns_qry->Classes = htons(DNS_CLASS_IN);
						pdns_qry->Type = htons(DNS_AAAA_RECORDS);
						DataLength += sizeof(dns_hdr) + sizeof(dns_qry);

					//EDNS0 Label
						if (Parameter.EDNS0Label) //No additional
						{
							EDNS0 = (dns_edns0_label *)(Buffer.get() + DataLength);
							pdns_hdr->Additional = htons(U16_NUM_1);
							EDNS0->Type = htons(DNS_EDNS0_RECORDS);
							EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
							DataLength += sizeof(dns_edns0_label);
						}
					}

					UDPRequestParameter.ServerIndex = Index + 3U;
					UDPRequestParameter.Length = DataLength;
					UDPRequestMulti(UDPRequestParameter);
				}
			}
			else if (Parameter.DNSTarget.IPv4_Multi != nullptr) //IPv4
			{
				for (size_t Index = 0;Index < Parameter.DNSTarget.IPv4_Multi->size();Index++)
				{
					if (Parameter.DomainTestOptions.DomainTestData == nullptr) //Make ramdom domain request.
					{
						memset(Buffer.get() + sizeof(dns_hdr), 0, PACKET_MAXSIZE - sizeof(dns_hdr));
						MakeRamdomDomain(DNSQuery.get());
						DataLength = CharToDNSQuery(DNSQuery.get(), Buffer.get() + sizeof(dns_hdr));
						memset(DNSQuery.get(), 0, DOMAIN_MAXSIZE);
				
						pdns_qry = (dns_qry *)(Buffer.get() + sizeof(dns_hdr) + DataLength);
						pdns_qry->Classes = htons(DNS_CLASS_IN);
						pdns_qry->Type = htons(DNS_A_RECORDS);
						DataLength += sizeof(dns_hdr) + sizeof(dns_qry);

					//EDNS0 Label
						if (Parameter.EDNS0Label) //No additional
						{
							EDNS0 = (dns_edns0_label *)(Buffer.get() + DataLength);
							pdns_hdr->Additional = htons(U16_NUM_1);
							EDNS0->Type = htons(DNS_EDNS0_RECORDS);
							EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
							DataLength += sizeof(dns_edns0_label);
						}
					}

					UDPRequestParameter.ServerIndex = Index + 3U;
					UDPRequestParameter.Length = DataLength;
					UDPRequestMulti(UDPRequestParameter);
				}
			}

		//Repeat
			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			Times++;
		}
	}

	return EXIT_SUCCESS;
}

//Internet Control Message Protocol/ICMP Echo(Ping) request
size_t __fastcall ICMPEcho(void)
{
//Initialization
	std::shared_ptr<char> Buffer(new char[sizeof(icmp_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U]());
	std::vector<sockaddr_storage> SockAddr;
	sockaddr_storage SockAddrTemp = {0};

//Make a ICMP request echo packet.
	auto picmp_hdr = (icmp_hdr *)Buffer.get();
	picmp_hdr->Type = 8; //Echo(Ping) request type
	picmp_hdr->ID = Parameter.ICMPOptions.ICMPID;
	picmp_hdr->Sequence = Parameter.ICMPOptions.ICMPSequence;
	memcpy(Buffer.get() + sizeof(icmp_hdr), Parameter.PaddingDataOptions.PaddingData, Parameter.PaddingDataOptions.PaddingDataLength - 1U);
	picmp_hdr->Checksum = GetChecksum((PUINT16)Buffer.get(), sizeof(icmp_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U);
	SYSTEM_SOCKET ICMPSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	//Main and Alternate
	SockAddrTemp.ss_family = AF_INET;
	((PSOCKADDR_IN)&SockAddrTemp)->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
	SockAddr.push_back(SockAddrTemp);
	memset(&SockAddrTemp, 0, sizeof(sockaddr_storage));
	if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
	{
		SockAddrTemp.ss_family = AF_INET;
		((PSOCKADDR_IN)&SockAddrTemp)->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
		SockAddr.push_back(SockAddrTemp);
		memset(&SockAddrTemp, 0, sizeof(sockaddr_storage));
	}

	//Other(Multi)
	if (Parameter.DNSTarget.IPv4_Multi != nullptr)
	{
		for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
		{
			SockAddrTemp.ss_family = AF_INET;
			((PSOCKADDR_IN)&SockAddrTemp)->sin_addr = DNSServerDataIter.AddressData.IPv4.sin_addr;
			SockAddr.push_back(SockAddrTemp);
			memset(&SockAddrTemp, 0, sizeof(sockaddr_storage));
		}
	}

//Check socket.
	if (ICMPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"ICMP Echo(Ping) request error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}

//Set socket timeout.
// Old version(2014-07-22)
//	if (setsockopt(ICMPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
	if (setsockopt(ICMPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set ICMP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(ICMPSocket);

		return EXIT_FAILURE;
	}

//Send request.
	size_t Times = 0;
	auto ReTest = false;
	while (true)
	{
		for (auto SockaddrIter:SockAddr)
		{
			sendto(ICMPSocket, Buffer.get(), (int)(sizeof(icmp_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U), NULL, (PSOCKADDR)&SockaddrIter, sizeof(sockaddr_in));

		//Increase Sequence.
			if (Parameter.ICMPOptions.ICMPSequence == htons(DEFAULT_SEQUENCE))
			{
				if (picmp_hdr->Sequence == U16_MAXNUM)
					picmp_hdr->Sequence = htons(DEFAULT_SEQUENCE);
				else 
					picmp_hdr->Sequence = htons(ntohs(picmp_hdr->Sequence) + 1U);

				picmp_hdr->Checksum = 0;
				picmp_hdr->Checksum = GetChecksum((PUINT16)Buffer.get(), sizeof(icmp_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U);
			}
		}
/*
		sendto(ICMPSocket, Buffer.get(), (int)(sizeof(icmp_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U), NULL, (PSOCKADDR)&(SockAddr[0]), sizeof(sockaddr_in));
		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
			sendto(ICMPSocket, Buffer.get(), (int)(sizeof(icmp_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U), NULL, (PSOCKADDR)&(SockAddr[1U]), sizeof(sockaddr_in));
*/
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Other(Multi)
			ReTest = false;
			if (Parameter.DNSTarget.IPv4_Multi != nullptr)
			{
				for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
				{
					if (DNSServerDataIter.HopLimitData.TTL == 0)
					{
						ReTest = true;
						break;
					}
				}
			}

			if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0 || //IPv4 Main
				Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL && Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0 || //IPv4 Alternate
				ReTest) //Other(Multi)
			{
				Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
				continue;
			}

			Sleep((DWORD)Parameter.ICMPOptions.ICMPSpeed);
		}
		else {
			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			Times++;
		}
	}

	closesocket(ICMPSocket);
	return EXIT_SUCCESS;
}

//Internet Control Message Protocol Echo version 6/ICMPv6 Echo(Ping) request
size_t __fastcall ICMPv6Echo(void)
{
//Initialization
/*
	std::shared_ptr<char> Buffer(new char[sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U]()), Exchange(new char[sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U]());
	sockaddr_storage SockAddr[] = {{0}, {0}};
	memset(&SockAddr, 0, sizeof(sockaddr_storage) * 2U);
*/
	std::vector<std::shared_ptr<char>> Buffer;
	if (Parameter.DNSTarget.IPv6_Multi == nullptr)
	{
		std::vector<std::shared_ptr<char>> BufferTemp(2U);
		BufferTemp.swap(Buffer);
	}
	else {
		std::vector<std::shared_ptr<char>> BufferTemp(Parameter.DNSTarget.IPv6_Multi->size() + 2U);
		BufferTemp.swap(Buffer);
	}

//Make a IPv6 ICMPv6 request echo packet.
	icmpv6_hdr *picmpv6_hdr = nullptr;
	for (auto BufferIter = Buffer.begin();BufferIter != Buffer.end();BufferIter++)
	{
		std::shared_ptr<char> BufferTemp(new char[sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U]());

		picmpv6_hdr = (icmpv6_hdr *)BufferTemp.get();
		picmpv6_hdr->Type = ICMPV6_REQUEST;
		picmpv6_hdr->Code = 0;
		picmpv6_hdr->ID = Parameter.ICMPOptions.ICMPID;
		picmpv6_hdr->Sequence = Parameter.ICMPOptions.ICMPSequence;
		memcpy(BufferTemp.get() + sizeof(icmpv6_hdr), Parameter.PaddingDataOptions.PaddingData, Parameter.PaddingDataOptions.PaddingDataLength - 1U);
		BufferTemp.swap(*BufferIter);
	}

//Get localhost IPv6 address.
	sockaddr_storage SockAddr = {0};
	auto LocalAddressListPTR = GetLocalAddressList(AF_INET6);
	if (LocalAddressListPTR == nullptr)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Get localhost address(es) error", NULL, nullptr, NULL);
		return EXIT_FAILURE;
	}
	else {
		if (LocalAddressListPTR->ai_family == AF_INET6 && LocalAddressListPTR->ai_addrlen == sizeof(sockaddr_in6))
			memcpy(&SockAddr, LocalAddressListPTR->ai_addr, sizeof(sockaddr_in6));
		freeaddrinfo(LocalAddressListPTR);
	}

//ICMP Sequence increase and calculate checksum.
/*
	picmpv6_hdr->Checksum = ICMPv6Checksum((PUINT8)Buffer.get(), sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U, Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)&SockAddr[0])->sin6_addr);
	if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
	{
		memcpy(Exchange.get(), Buffer.get(), sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U);
		picmpv6_hdr->Checksum = ICMPv6Checksum((PUINT8)Buffer.get(), sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U, Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)&SockAddr[0])->sin6_addr);
		SockAddr[1U].ss_family = AF_INET6;
		((PSOCKADDR_IN6)&SockAddr[1U])->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
	}

	SockAddr[0].ss_family = AF_INET6;
	((PSOCKADDR_IN6)&SockAddr[0])->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
*/
	picmpv6_hdr = (icmpv6_hdr *)Buffer.front().get();
	picmpv6_hdr->Checksum = ICMPv6Checksum((PUINT8)Buffer.front().get(), sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U, Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)&SockAddr)->sin6_addr);
	if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family == NULL)
	{
		Buffer.erase(Buffer.begin() + 1U);
	}
	else {
		picmpv6_hdr = (icmpv6_hdr *)Buffer[1U].get();
		if (Parameter.ICMPOptions.ICMPSequence == htons(DEFAULT_SEQUENCE))
			picmpv6_hdr->Sequence = htons(ntohs(Parameter.ICMPOptions.ICMPSequence) + 1U);
		picmpv6_hdr->Checksum = ICMPv6Checksum((PUINT8)Buffer[1U].get(), sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U, Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)&SockAddr)->sin6_addr);
	}

	//Multi requesting part.
	size_t Index = 0;
	for (Index = 2U;(SSIZE_T)Index < (SSIZE_T)(Buffer.size() - 2U);Index++)
	{
		picmpv6_hdr = (icmpv6_hdr *)Buffer[Index].get();
		if (Parameter.ICMPOptions.ICMPSequence == htons(DEFAULT_SEQUENCE))
			picmpv6_hdr->Sequence = htons((uint16_t)(ntohs(Parameter.ICMPOptions.ICMPSequence) + Index));
		picmpv6_hdr->Checksum = ICMPv6Checksum((PUINT8)Buffer[Index].get(), sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U, Parameter.DNSTarget.IPv6_Multi->at(Index).AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)&SockAddr)->sin6_addr);
	}

//Check socket.
	SYSTEM_SOCKET ICMPv6Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (ICMPv6Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"ICMPv6 Echo(Ping) request error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}

//Set socket timeout.
// Old version(2014-07-22)
//	if (setsockopt(ICMPv6Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
	if (setsockopt(ICMPv6Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set ICMPv6 socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(ICMPv6Socket);

		return EXIT_FAILURE;
	}

//Send request.
	size_t Times = 0;
	auto ReTest = false;
	while (true)
	{
	//Main
		sendto(ICMPv6Socket, Buffer.front().get(), (int)(sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U), NULL, (PSOCKADDR)&Parameter.DNSTarget.IPv6.AddressData.IPv6, sizeof(sockaddr_in6));
		if (Parameter.ICMPOptions.ICMPSequence == htons(DEFAULT_SEQUENCE)) //Increase Sequence.
		{
			picmpv6_hdr = (icmpv6_hdr *)Buffer.front().get();
			if (picmpv6_hdr->Sequence == U16_MAXNUM)
				picmpv6_hdr->Sequence = htons(DEFAULT_SEQUENCE);
			else 
				picmpv6_hdr->Sequence = htons(ntohs(picmpv6_hdr->Sequence) + 1U);
			picmpv6_hdr->Checksum = 0;
			picmpv6_hdr->Checksum = ICMPv6Checksum((PUINT8)Buffer.front().get(), sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U, Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)&SockAddr)->sin6_addr);
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
		{
			sendto(ICMPv6Socket, Buffer.at(1U).get(), (int)(sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U), NULL, (PSOCKADDR)&Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6, sizeof(sockaddr_in6));
			if (Parameter.ICMPOptions.ICMPSequence == htons(DEFAULT_SEQUENCE)) //Increase Sequence.
			{
				picmpv6_hdr = (icmpv6_hdr *)Buffer.at(1U).get();
				if (picmpv6_hdr->Sequence == U16_MAXNUM)
					picmpv6_hdr->Sequence = htons(DEFAULT_SEQUENCE);
				else 
					picmpv6_hdr->Sequence = htons(ntohs(picmpv6_hdr->Sequence) + 1U);
				picmpv6_hdr->Checksum = 0;
				picmpv6_hdr->Checksum = ICMPv6Checksum((PUINT8)Buffer.at(1U).get(), sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U, Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)&SockAddr)->sin6_addr);
			}
		}

	//Other(Multi)
		if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			Index = 2U;
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				sendto(ICMPv6Socket, Buffer.at(Index).get(), (int)(sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U), NULL, (PSOCKADDR)&DNSServerDataIter.AddressData.IPv6, sizeof(sockaddr_in6));
				if (Parameter.ICMPOptions.ICMPSequence == htons(DEFAULT_SEQUENCE)) //Increase Sequence.
				{
					picmpv6_hdr = (icmpv6_hdr *)Buffer.at(Index).get();
					if (picmpv6_hdr->Sequence == U16_MAXNUM)
						picmpv6_hdr->Sequence = htons(DEFAULT_SEQUENCE);
					else 
						picmpv6_hdr->Sequence = htons(ntohs(picmpv6_hdr->Sequence) + 1U);
					picmpv6_hdr->Checksum = 0;
					picmpv6_hdr->Checksum = ICMPv6Checksum((PUINT8)Buffer.at(Index).get(), sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U, DNSServerDataIter.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)&SockAddr)->sin6_addr);
				}

				Index++;
			}
		}
/*
		sendto(ICMPv6Socket, Exchange.get(), (int)(sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U), NULL, (PSOCKADDR)&(SockAddr[0]), sizeof(sockaddr_in6));
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
			sendto(ICMPv6Socket, Buffer.get(), (int)(sizeof(icmpv6_hdr) + Parameter.PaddingDataOptions.PaddingDataLength - 1U), NULL, (PSOCKADDR)&(SockAddr[1U]), sizeof(sockaddr_in6));
*/
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Other(Multi)
			ReTest = false;
			if (Parameter.DNSTarget.IPv6_Multi != nullptr)
			{
				for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
				{
					if (DNSServerDataIter.HopLimitData.TTL == 0)
					{
						ReTest = true;
						break;
					}
				}
			}

			if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0 || //IPv6 Main
				Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL && Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0 || //IPv6 Alternate
				ReTest) //Other(Multi)
			{
				Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
				continue;
			}

			Sleep((DWORD)Parameter.ICMPOptions.ICMPSpeed);
		}
		else {
			Times++;
			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
		}
	}

	closesocket(ICMPv6Socket);
	return EXIT_SUCCESS;
}

//Transmission and reception of TCP protocol(Independent)
size_t __fastcall TCPRequest(const PSTR Send, const size_t SendSize, PSTR Recv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool Local, const bool Alternate)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[sizeof(uint16_t) + SendSize]());
	sockaddr_storage SockAddr = {0};
	SYSTEM_SOCKET TCPSocket = 0;
	int AddrLen = 0;
	memcpy(SendBuffer.get(), Send, SendSize);

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	size_t DataLength = AddLengthToTCPDNSHeader(SendBuffer.get(), SendSize, sizeof(uint16_t) + SendSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket initialization
	if ((Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL || Local && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family != NULL) && TargetData.AddrLen == sizeof(sockaddr_in6) ||  //IPv6
		(Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL || !Local && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == NULL) && TargetData.AddrLen == sizeof(sockaddr_in)) //IPv4 is empty.
	{
		if (Alternate)
		{
			if (Local && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port;
			}
			else if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
			else {
				return FALSE;
			}
		}
		else { //Main
			if (Local && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port;
			}
			else if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
			}
			else {
				return FALSE;
			}
		}

		TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		SockAddr.ss_family = AF_INET6;
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL || !Local && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == NULL) //IPv4
	{
		if (Alternate)
		{
			if (Local && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_port;
			}
			else if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
			else {
				return FALSE;
			}
		}
		else { //Main
			if (Local && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port;
			}
			else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}
			else {
				return FALSE;
			}
		}

		TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		SockAddr.ss_family = AF_INET;
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Check socket.
	if (TCPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"TCP request initialization error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}
/*
//TCP KeepAlive Mode
	BOOL bKeepAlive = TRUE;
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_KEEPALIVE, (PSTR)&bKeepAlive, sizeof(bKeepAlive)) == SOCKET_ERROR)
	{
		closesocket(TCPSocket);
		return EXIT_FAILURE;
	}

	tcp_keepalive alive_in = {0};
	tcp_keepalive alive_out = {0};
	alive_in.keepalivetime = STANDARD_TIMEOUT;
	alive_in.keepaliveinterval = RELIABLE_SOCKET_TIMEOUT;
	alive_in.onoff = TRUE;
	ULONG ulBytesReturn = 0;
	if (WSAIoctl(TCPSocket, SIO_KEEPALIVE_VALS, &alive_in, sizeof(alive_in), &alive_out, sizeof(alive_out), &ulBytesReturn, NULL, NULL) == SOCKET_ERROR)
	{
		closesocket(TCPSocket);
		return EXIT_FAILURE;
	}

//Set socket timeout.
// Old version(2014-07-22)
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(TCPSocket);

		return EXIT_FAILURE;
	}

//Connect to server.
	if (connect(TCPSocket, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR) //Connection is RESET or other errors when connecting.
	{
		if (!Alternate && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);
			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}

//Send request.
	if (send(TCPSocket, SendBuffer.get(), (int)DataLength, NULL) == SOCKET_ERROR) //Connection is RESET or other errors when sending.
	{
		if (!Alternate && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);
			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}
	SendBuffer.reset();

//Receive result.
	SSIZE_T RecvLen = recv(TCPSocket, Recv, (int)RecvSize, NULL) - sizeof(uint16_t);
	if (RecvLen <= 0 || (SSIZE_T)htons(((uint16_t *)Recv)[0]) > RecvLen) //Connection is RESET or other errors(including SOCKET_ERROR) when sending or server fin the connection.
	{
		memset(Recv, 0, RecvSize);
		if (!Alternate && RecvLen == RETURN_ERROR - (SSIZE_T)sizeof(uint16_t) && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);
			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}
	else if (RecvLen <= sizeof(dns_hdr) + 1U + sizeof(dns_qry) && htons(((uint16_t *)Recv)[0]) > sizeof(dns_hdr) + 1U + sizeof(dns_qry)) //TCP segment of a reassembled PDU
	{
		size_t PDULen = htons(((uint16_t *)Recv)[0]);
		memset(Recv, 0, RecvSize);
		RecvLen = recv(TCPSocket, Recv, (int)RecvSize, NULL) - sizeof(uint16_t);
		if (RecvLen < (SSIZE_T)PDULen) //Connection is RESET, corrupted packet or sother errors(including SOCKET_ERROR) after sending or finished.
		{
			memset(Recv, 0, RecvSize);
			if (!Alternate && RecvLen == RETURN_ERROR - (SSIZE_T)sizeof(uint16_t) && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(TCPSocket);
				return WSAETIMEDOUT;
			}
			else {
				closesocket(TCPSocket);
				return EXIT_FAILURE;
			}
		}

		closesocket(TCPSocket);
		if (PDULen > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && PDULen <= RecvSize)
		{
		//Responses answer(s) check
			if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv + sizeof(uint16_t), RecvLen))
			{
				memset(Recv, 0, RecvSize);
				return EXIT_FAILURE;
			}

			memmove(Recv, Recv + sizeof(uint16_t), PDULen);
		//Mark DNS Cache
			if (Parameter.CacheType != 0)
				MarkDomainCache(Recv, PDULen);

			return PDULen;
		}
		else {
			closesocket(TCPSocket);
			memset(Recv, 0, RecvSize);

			return EXIT_FAILURE;
		}
	}
	else if (RecvLen > sizeof(dns_hdr) + 1U + sizeof(dns_qry))
	{
		closesocket(TCPSocket);
		RecvLen = ntohs(((uint16_t *)Recv)[0]);
		if (RecvLen > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry)) && RecvLen <= (SSIZE_T)RecvSize)
		{
		//Responses answer(s) check
			if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv + sizeof(uint16_t), RecvLen))
			{
				memset(Recv, 0, RecvSize);
				return EXIT_FAILURE;
			}

			memmove(Recv, Recv + sizeof(uint16_t), RecvLen);
		//Mark DNS Cache
			if (Parameter.CacheType != 0)
				MarkDomainCache(Recv, RecvLen);

			return RecvLen;
		}
		else {
			return EXIT_FAILURE;
		}
	}

	closesocket(TCPSocket);
	memset(Recv, 0, RecvSize);
	return EXIT_FAILURE;
}

//Transmission and reception of TCP protocol(Multithreading)
size_t __fastcall TCPRequestMulti(TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER &TCPRequestParameter, std::mutex &Mutex)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[sizeof(uint16_t) + TCPRequestParameter.SendSize]()), RecvBuffer(new char[TCPRequestParameter.RecvSize]());
	sockaddr_storage SockAddr = {0};
	SYSTEM_SOCKET TCPSocket = 0;
	int AddrLen = 0;
	memcpy(SendBuffer.get(), TCPRequestParameter.Send, TCPRequestParameter.SendSize);

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	size_t DataLength = AddLengthToTCPDNSHeader(SendBuffer.get(), TCPRequestParameter.SendSize, sizeof(uint16_t) + TCPRequestParameter.SendSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket initialization
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL && TCPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in6) || //IPv6
		Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL && TCPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in)) //Non-IPv4
	{
	//All server(including Alternate) Multi Request
		if (TCPRequestParameter.ServerIndex > 0)
		{
		//Main
			if (TCPRequestParameter.ServerIndex == 1U)
			{
				if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL)
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Alternate
			else if (TCPRequestParameter.ServerIndex == 2U)
			{
				if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else if (Parameter.DNSTarget.IPv6_Multi != nullptr && Parameter.DNSTarget.IPv6_Multi->size() > TCPRequestParameter.ServerIndex - 3U)
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6_Multi->at(TCPRequestParameter.ServerIndex - 3U).AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.IPv6_Multi->at(TCPRequestParameter.ServerIndex - 3U).AddressData.IPv6.sin6_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		SockAddr.ss_family = AF_INET6;
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL) //IPv4
	{
	//All server(including Alternate) Multi Request
		if (TCPRequestParameter.ServerIndex > 0)
		{
		//Main
			if (TCPRequestParameter.ServerIndex == 1U)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}
		//Alternate
			else if (TCPRequestParameter.ServerIndex == 2U)
			{
				if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
				{
					((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else if (Parameter.DNSTarget.IPv4_Multi != nullptr && Parameter.DNSTarget.IPv4_Multi->size() > TCPRequestParameter.ServerIndex - 3U)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4_Multi->at(TCPRequestParameter.ServerIndex - 3U).AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.IPv4_Multi->at(TCPRequestParameter.ServerIndex - 3U).AddressData.IPv4.sin_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		SockAddr.ss_family = AF_INET;
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Check socket.
	if (TCPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"TCP request initialization error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}
/*
//TCP KeepAlive Mode
	BOOL bKeepAlive = TRUE;
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_KEEPALIVE, (PSTR)&bKeepAlive, sizeof(bKeepAlive)) == SOCKET_ERROR)
	{
		closesocket(TCPSocket);
		return EXIT_FAILURE;
	}

	tcp_keepalive alive_in = {0};
	tcp_keepalive alive_out = {0};
	alive_in.keepalivetime = STANDARD_TIMEOUT;
	alive_in.keepaliveinterval = RELIABLE_SOCKET_TIMEOUT;
	alive_in.onoff = TRUE;
	ULONG ulBytesReturn = 0;
	if (WSAIoctl(TCPSocket, SIO_KEEPALIVE_VALS, &alive_in, sizeof(alive_in), &alive_out, sizeof(alive_out), &ulBytesReturn, NULL, NULL) == SOCKET_ERROR)
	{
		closesocket(TCPSocket);
		return EXIT_FAILURE;
	}

//Set socket timeout.
// Old version(2014-07-22)
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(TCPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(TCPSocket);

		return EXIT_FAILURE;
	}

//Connect to server.
	if (connect(TCPSocket, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR) //Connection is RESET or other errors when connecting.
	{
		if (TCPRequestParameter.ServerIndex != 2U && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);

			std::unique_lock<std::mutex> TCPMutex(Mutex);
			TCPRequestParameter.ReturnValue = WSAETIMEDOUT;
			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}

//Send request.
	if (send(TCPSocket, SendBuffer.get(), (int)DataLength, NULL) == SOCKET_ERROR) //Connection is RESET or other errors when sending.
	{
		if (TCPRequestParameter.ServerIndex != 2U && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);

			std::unique_lock<std::mutex> TCPMutex(Mutex);
			TCPRequestParameter.ReturnValue = WSAETIMEDOUT;
			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}
	SendBuffer.reset();

//Receive result.
	SSIZE_T RecvLen = recv(TCPSocket, RecvBuffer.get(), (int)TCPRequestParameter.RecvSize, NULL) - sizeof(uint16_t);
	if (RecvLen <= 0 || (SSIZE_T)htons(((uint16_t *)RecvBuffer.get())[0]) > RecvLen) //Connection is RESET or other errors(including SOCKET_ERROR) when sending or server fin the connection.
	{
		RecvBuffer.reset();
		if (TCPRequestParameter.ServerIndex != 2U && RecvLen == RETURN_ERROR - (SSIZE_T)sizeof(uint16_t) && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);

			std::unique_lock<std::mutex> TCPMutex(Mutex);
			TCPRequestParameter.ReturnValue = WSAETIMEDOUT;
			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}
	else if (RecvLen <= sizeof(dns_hdr) + 1U + sizeof(dns_qry) && htons(((uint16_t *)RecvBuffer.get())[0]) > sizeof(dns_hdr) + 1U + sizeof(dns_qry)) //TCP segment of a reassembled PDU
	{
		size_t PDULen = htons(((uint16_t *)RecvBuffer.get())[0]);
		memset(RecvBuffer.get(), 0, TCPRequestParameter.RecvSize);
		RecvLen = recv(TCPSocket, RecvBuffer.get(), (int)TCPRequestParameter.RecvSize, NULL) - sizeof(uint16_t);
		if (RecvLen < (SSIZE_T)PDULen) //Connection is RESET, corrupted packet or sother errors(including SOCKET_ERROR) after sending or finished.
		{
			RecvBuffer.reset();
			if (TCPRequestParameter.ServerIndex != 2U && RecvLen == RETURN_ERROR - (SSIZE_T)sizeof(uint16_t) && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(TCPSocket);

				std::unique_lock<std::mutex> TCPMutex(Mutex);
				TCPRequestParameter.ReturnValue = WSAETIMEDOUT;
				return WSAETIMEDOUT;
			}
			else {
				closesocket(TCPSocket);
				return EXIT_FAILURE;
			}
		}

		closesocket(TCPSocket);
		if (PDULen > sizeof(dns_hdr) + 1U + sizeof(dns_qry) && PDULen <= TCPRequestParameter.RecvSize)
		{
		//Responses answer(s) check
			if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get() + sizeof(uint16_t), RecvLen))
				return EXIT_FAILURE;

			std::unique_lock<std::mutex> TCPMutex(Mutex);
			if (CheckEmptyBuffer(TCPRequestParameter.Recv, TCPRequestParameter.RecvSize) && (TCPRequestParameter.ReturnValue == 0 || TCPRequestParameter.ReturnValue == WSAETIMEDOUT))
			{
				memcpy(TCPRequestParameter.Recv, RecvBuffer.get() + sizeof(uint16_t), PDULen);
				TCPRequestParameter.ReturnValue = PDULen;

			//Mark DNS Cache
				if (Parameter.CacheType != 0)
					MarkDomainCache(TCPRequestParameter.Recv, PDULen);

				return PDULen;
			}
		}
	}
	else if (RecvLen > sizeof(dns_hdr) + 1U + sizeof(dns_qry))
	{
		closesocket(TCPSocket);
		RecvLen = ntohs(((uint16_t *)RecvBuffer.get())[0]);
		if (RecvLen > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry)) && RecvLen <= (SSIZE_T)TCPRequestParameter.RecvSize)
		{
		//Responses answer(s) check
			if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get() + sizeof(uint16_t), RecvLen))
				return EXIT_FAILURE;

			std::unique_lock<std::mutex> TCPMutex(Mutex);
			if (CheckEmptyBuffer(TCPRequestParameter.Recv, TCPRequestParameter.RecvSize) && (TCPRequestParameter.ReturnValue == 0 || TCPRequestParameter.ReturnValue == WSAETIMEDOUT))
			{
				memcpy(TCPRequestParameter.Recv, RecvBuffer.get() + sizeof(uint16_t), RecvLen);
				TCPRequestParameter.ReturnValue = RecvLen;

			//Mark DNS Cache
				if (Parameter.CacheType != 0)
					MarkDomainCache(TCPRequestParameter.Recv, RecvLen);

				return RecvLen;
			}
			else {
				return EXIT_SUCCESS;
			}
		}
	}

	closesocket(TCPSocket);
	return EXIT_FAILURE;
}

//Transmission of UDP protocol
size_t __fastcall UDPRequest(const PSTR Send, const size_t Length, const SOCKET_DATA TargetData, const size_t Index, const bool Alternate)
{
//Initialization
	sockaddr_storage SockAddr = {0};
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if ((Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL) && //IPv6
		TargetData.AddrLen == sizeof(sockaddr_in6) || TargetData.AddrLen == sizeof(sockaddr_in) && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL)
	{
		if (Alternate)
		{
			if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}
		else {
			if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr.ss_family = AF_INET6;
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL) //IPv4
	{
		if (Alternate)
		{
			if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}
		else {
			if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr.ss_family = AF_INET;
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Check socket.
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"UDP request initialization error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}

//Set socket timeout.
// Old version(2014-07-22)
//	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send request.
	if (sendto(UDPSocket, Send, (int)Length, NULL, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"UDP request error", WSAGetLastError(), nullptr, NULL);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Mark port to list.
	if (Index < QUEUE_MAXLEN * QUEUE_PARTNUM)
	{
		if (getsockname(UDPSocket, (PSOCKADDR)&SockAddr, (PINT)&AddrLen) != 0)
		{
			closesocket(UDPSocket);
			return EXIT_FAILURE;
		}

		SOCKET_DATA SockDataTemp = {0};
	//Minimum supported system of GetTickCount64() is Windows Vista.
		if (AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			SockDataTemp.AddrLen = sizeof(sockaddr_in6);
			SockDataTemp.SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&SockDataTemp.SockAddr)->sin6_port = ((PSOCKADDR_IN6)&SockAddr)->sin6_port;

			std::unique_lock<std::mutex> PortListMutex(PortListLock);
			PortList.SendData[Index].push_back(SockDataTemp);
			PortList.SendData[Index].shrink_to_fit();
		}
		else //IPv4
		{
			SockDataTemp.AddrLen = sizeof(sockaddr_in);
			SockDataTemp.SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SockDataTemp.SockAddr)->sin_port = ((PSOCKADDR_IN)&SockAddr)->sin_port;

			std::unique_lock<std::mutex> PortListMutex(PortListLock);
			PortList.SendData[Index].push_back(SockDataTemp);
			PortList.SendData[Index].shrink_to_fit();
		}

	//Mark send time
	#ifdef _WIN64
		AlternateSwapList.PcapAlternateTimeout[Index] = GetTickCount64();
	#else //x86
		AlternateSwapList.PcapAlternateTimeout[Index] = GetTickCount();
	#endif
	}

//Block Port Unreachable messages of system or close the TCP requesting connections.
	if (Index > QUEUE_MAXLEN * QUEUE_PARTNUM / 2U && Index < QUEUE_MAXLEN * QUEUE_PARTNUM) //TCP
		Sleep(RELIABLE_SOCKET_TIMEOUT);
	else //UDP
		Sleep(UNRELIABLE_SOCKET_TIMEOUT);
	closesocket(UDPSocket);
	return EXIT_SUCCESS;
}

//Transmission of UDP protocol(Multithreading)
size_t __fastcall UDPRequestMulti(UDP_REQUEST_MULTITHREAD_PARAMETER UDPRequestParameter)
{
//Initialization
	sockaddr_storage SockAddr = {0};
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL && UDPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in6) || //IPv6
		Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL && UDPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in)) //Non-IPv4
	{
	//All server(including Alternate) Multi Request
		if (UDPRequestParameter.ServerIndex > 0)
		{
		//Main
			if (UDPRequestParameter.ServerIndex == 1U)
			{
				if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL)
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Alternate
			else if (UDPRequestParameter.ServerIndex == 2U)
			{
				if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else if (Parameter.DNSTarget.IPv6_Multi != nullptr && Parameter.DNSTarget.IPv6_Multi->size() > UDPRequestParameter.ServerIndex - 3U)
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.IPv6_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv6.sin6_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr.ss_family = AF_INET6;
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL) //IPv4
	{
	//All server(including Alternate) Multi Request
		if (UDPRequestParameter.ServerIndex > 0)
		{
		//Main
			if (UDPRequestParameter.ServerIndex == 1U)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}
		//Alternate
			else if (UDPRequestParameter.ServerIndex == 2U)
			{
				if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
				{
					((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else if (Parameter.DNSTarget.IPv4_Multi != nullptr && Parameter.DNSTarget.IPv4_Multi->size() > UDPRequestParameter.ServerIndex - 3U)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.IPv4_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv4.sin_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr.ss_family = AF_INET;
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Check socket.
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"UDP request initialization error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}

//Set socket timeout.
// Old version(2014-07-22)
//	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send request.
	if (sendto(UDPSocket, UDPRequestParameter.Send, (int)UDPRequestParameter.Length, NULL, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"UDP request error", WSAGetLastError(), nullptr, NULL);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Mark port to list.
	if (UDPRequestParameter.Index < QUEUE_MAXLEN * QUEUE_PARTNUM)
	{
		if (getsockname(UDPSocket, (PSOCKADDR)&SockAddr, (PINT)&AddrLen) != 0)
		{
			closesocket(UDPSocket);
			return EXIT_FAILURE;
		}

		SOCKET_DATA SockDataTemp = {0};
	//Minimum supported system of GetTickCount64() is Windows Vista.
		if (AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			SockDataTemp.AddrLen = sizeof(sockaddr_in6);
			SockDataTemp.SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&SockDataTemp.SockAddr)->sin6_port = ((PSOCKADDR_IN6)&SockAddr)->sin6_port;

			std::unique_lock<std::mutex> PortListMutex(PortListLock);
			PortList.SendData[UDPRequestParameter.Index].push_back(SockDataTemp);
			PortList.SendData[UDPRequestParameter.Index].shrink_to_fit();
		}
		else //IPv4
		{
			SockDataTemp.AddrLen = sizeof(sockaddr_in);
			SockDataTemp.SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SockDataTemp.SockAddr)->sin_port = ((PSOCKADDR_IN)&SockAddr)->sin_port;

			std::unique_lock<std::mutex> PortListMutex(PortListLock);
			PortList.SendData[UDPRequestParameter.Index].push_back(SockDataTemp);
			PortList.SendData[UDPRequestParameter.Index].shrink_to_fit();
		}

	//Mark send time
	#ifdef _WIN64
		AlternateSwapList.PcapAlternateTimeout[UDPRequestParameter.Index] = GetTickCount64();
	#else //x86
		AlternateSwapList.PcapAlternateTimeout[UDPRequestParameter.Index] = GetTickCount();
	#endif
	}

//Block Port Unreachable messages of system or close the TCP requesting connections.
	if (UDPRequestParameter.Index > QUEUE_MAXLEN * QUEUE_PARTNUM / 2U && UDPRequestParameter.Index < QUEUE_MAXLEN * QUEUE_PARTNUM) //TCP
		Sleep(RELIABLE_SOCKET_TIMEOUT);
	else //UDP
		Sleep(UNRELIABLE_SOCKET_TIMEOUT);
	closesocket(UDPSocket);
	return EXIT_SUCCESS;
}

//Complete transmission of UDP protocol
size_t __fastcall UDPCompleteRequest(const PSTR Send, const size_t SendSize, PSTR Recv, const size_t RecvSize, const SOCKET_DATA TargetData, const bool Local, const bool Alternate)
{
//Initialization
	sockaddr_storage SockAddr = {0};
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if ((Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL || Local && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family != NULL) && TargetData.AddrLen == sizeof(sockaddr_in6) || //IPv6
		(Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL || !Local && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == NULL) && TargetData.AddrLen == sizeof(sockaddr_in)) //IPv4 is empty.
	{
		if (Alternate)
		{
			if (Local && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port;
			}
			else if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL) //Main
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}
		else { //Main
			if (Local && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port;
			}
			else if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL) //Main
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr.ss_family = AF_INET6;
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL || Local && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family != NULL) //IPv4
	{
		if (Alternate)
		{
			if (Local && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_port;
			}
			else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL) //Main
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}
		else { //Main
			if (Local && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family != NULL)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port;
			}
			else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL) //Main
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr.ss_family = AF_INET;
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Check socket.
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}

//Set socket timeout.
/* Old version(2014-07-22)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send request.
	if (sendto(UDPSocket, Send, (int)SendSize, NULL, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request error", WSAGetLastError(), nullptr, NULL);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Receive result.
	SSIZE_T RecvLen = recvfrom(UDPSocket, Recv, (int)RecvSize, NULL, (PSOCKADDR)&SockAddr, (PINT)&AddrLen);
	if (!Alternate && RecvLen == RETURN_ERROR && WSAGetLastError() == WSAETIMEDOUT)
	{
		closesocket(UDPSocket);
		memset(Recv, 0, RecvSize);
		return WSAETIMEDOUT;
	}
	else if (RecvLen > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
	{
	//Hosts Only Extended check
		if (Parameter.DNSDataCheck || Parameter.Blacklist)
		{
			while (RecvLen > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
			{
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(Recv, RecvLen))
				{
					if (Local) //Stop waitting when it is Local requesting.
						RecvLen = EXIT_FAILURE;
					else 
						RecvLen = recvfrom(UDPSocket, Recv, (int)RecvSize, NULL, (PSOCKADDR)&SockAddr, (PINT)&AddrLen);
				}
				else {
					break;
				}
			}
		}

	//Check timeout.
		if (RecvLen <= (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
		{
			memset(Recv, 0, RecvSize);
			if (RecvLen == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(UDPSocket);
				return WSAETIMEDOUT;
			}
			else {
				closesocket(UDPSocket);
				return EXIT_FAILURE;
			}
		}
		else {
			closesocket(UDPSocket);
		}

	//Mark DNS Cache
		if (Parameter.CacheType != 0)
			MarkDomainCache(Recv, RecvLen);

		return RecvLen;
	}
	else {
		closesocket(UDPSocket);
		memset(Recv, 0, RecvSize);
		return EXIT_FAILURE;
	}
}

//Complete transmission of UDP protocol(Multithreading)
size_t __fastcall UDPCompleteRequestMulti(TCPUDP_COMPLETE_REQUEST_MULTITHREAD_PARAMETER &UDPRequestParameter, std::mutex &Mutex)
{
//Initialization
	sockaddr_storage SockAddr = {0};
	SYSTEM_SOCKET UDPSocket = 0;
	int AddrLen = 0;

//Socket initialization
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL && UDPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in6) || //IPv6
		Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == NULL && UDPRequestParameter.TargetData.AddrLen == sizeof(sockaddr_in)) //Non-IPv4
	{
	//All server(including Alternate) Multi Request
		if (UDPRequestParameter.ServerIndex > 0)
		{
		//Main
			if (UDPRequestParameter.ServerIndex == 1U)
			{
				if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL)
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
		//Alternate
			else if (UDPRequestParameter.ServerIndex == 2U)
			{
				if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL)
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else if (Parameter.DNSTarget.IPv6_Multi != nullptr && Parameter.DNSTarget.IPv6_Multi->size() > UDPRequestParameter.ServerIndex - 3U)
			{
				((PSOCKADDR_IN6)&SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockAddr)->sin6_port = Parameter.DNSTarget.IPv6_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv6.sin6_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr.ss_family = AF_INET6;
		AddrLen = sizeof(sockaddr_in6);
	}
	else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL) //IPv4
	{
	//All server(including Alternate) Multi Request
		if (UDPRequestParameter.ServerIndex > 0)
		{
		//Main
			if (UDPRequestParameter.ServerIndex == 1U)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}
		//Alternate
			else if (UDPRequestParameter.ServerIndex == 2U)
			{
				if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
				{
					((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
					((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
				}
				else {
					return EXIT_FAILURE;
				}
			}
			else if (Parameter.DNSTarget.IPv4_Multi != nullptr && Parameter.DNSTarget.IPv4_Multi->size() > UDPRequestParameter.ServerIndex - 3U)
			{
				((PSOCKADDR_IN)&SockAddr)->sin_addr = Parameter.DNSTarget.IPv4_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockAddr)->sin_port = Parameter.DNSTarget.IPv4_Multi->at(UDPRequestParameter.ServerIndex - 3U).AddressData.IPv4.sin_port;
			}
			else {
				return EXIT_FAILURE;
			}
		}

		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		SockAddr.ss_family = AF_INET;
		AddrLen = sizeof(sockaddr_in);
	}
	else {
		return EXIT_FAILURE;
	}

//Check socket.
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, NULL);
		return EXIT_FAILURE;
	}

//Set socket timeout.
/* Old version(2014-07-22)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send request.
	if (sendto(UDPSocket, UDPRequestParameter.Send, (int)UDPRequestParameter.SendSize, NULL, (PSOCKADDR)&SockAddr, AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Complete UDP request error", WSAGetLastError(), nullptr, NULL);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Receive result.
	std::shared_ptr<char> RecvBuffer(new char[UDPRequestParameter.RecvSize]());
	SSIZE_T RecvLen = recvfrom(UDPSocket, RecvBuffer.get(), (int)UDPRequestParameter.RecvSize, NULL, (PSOCKADDR)&SockAddr, (PINT)&AddrLen);
	if (UDPRequestParameter.ServerIndex != 2U && RecvLen == RETURN_ERROR && WSAGetLastError() == WSAETIMEDOUT)
	{
		closesocket(UDPSocket);

		std::unique_lock<std::mutex> UDPMutex(Mutex);
		UDPRequestParameter.ReturnValue = WSAETIMEDOUT;
		return WSAETIMEDOUT;
	}
	else if (RecvLen > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
	{
	//Hosts Only Extended check
		if (Parameter.DNSDataCheck || Parameter.Blacklist)
		{
			while (RecvLen > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
			{
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckDNSLastResult(RecvBuffer.get(), RecvLen))
					RecvLen = recvfrom(UDPSocket, RecvBuffer.get(), (int)UDPRequestParameter.RecvSize, NULL, (PSOCKADDR)&SockAddr, (PINT)&AddrLen);
				else 
					break;
			}
		}

	//Check timeout.
		if (RecvLen <= (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
		{
			if (RecvLen == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT)
			{
				closesocket(UDPSocket);

				std::unique_lock<std::mutex> UDPMutex(Mutex);
				UDPRequestParameter.ReturnValue = WSAETIMEDOUT;
				return WSAETIMEDOUT;
			}
			else {
				closesocket(UDPSocket);
				return EXIT_FAILURE;
			}
		}
		else {
			closesocket(UDPSocket);
		}

		std::unique_lock<std::mutex> TCPMutex(Mutex);
		if (CheckEmptyBuffer(UDPRequestParameter.Recv, UDPRequestParameter.RecvSize) && (UDPRequestParameter.ReturnValue == 0 || UDPRequestParameter.ReturnValue == WSAETIMEDOUT))
		{
			memcpy(UDPRequestParameter.Recv, RecvBuffer.get(), RecvLen);
			UDPRequestParameter.ReturnValue = RecvLen;

		//Mark DNS Cache
			if (Parameter.CacheType != 0)
				MarkDomainCache(UDPRequestParameter.Recv, RecvLen);

			return RecvLen;
		}
		else {
			return EXIT_SUCCESS;
		}
	}
	else {
		closesocket(UDPSocket);
		return EXIT_FAILURE;
	}
}
