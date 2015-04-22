// This code is part of Pcap_DNSProxy
// A local DNS server base on WinPcap and LibPcap.
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


#include "Network.h"

//Get TTL(IPv4)/Hop Limits(IPv6) with normal DNS request
size_t __fastcall DomainTestRequest(const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> Buffer(new char[PACKET_MAXSIZE]()), DNSQuery(new char[PACKET_MAXSIZE]());
	memset(Buffer.get(), 0, PACKET_MAXSIZE);
	memset(DNSQuery.get(), 0, PACKET_MAXSIZE);

//Make a DNS request with Doamin Test packet.
	auto DNS_Header = (pdns_hdr)Buffer.get();
	DNS_Header->ID = Parameter.DomainTestID;
	DNS_Header->Flags = htons(DNS_STANDARD);
	DNS_Header->Questions = htons(U16_NUM_ONE);
	size_t DataLength = 0;

//Convert domain.
	pdns_qry DNS_Query = nullptr;
	if (Parameter.DomainTestData != nullptr)
	{
		DataLength = CharToDNSQuery(Parameter.DomainTestData, DNSQuery.get());
		if (DataLength > 2U && DataLength < PACKET_MAXSIZE - sizeof(dns_hdr))
		{
			memcpy_s(Buffer.get() + sizeof(dns_hdr), PACKET_MAXSIZE - sizeof(dns_hdr), DNSQuery.get(), DataLength);
			DNS_Query = (pdns_qry)(Buffer.get() + sizeof(dns_hdr) + DataLength);
			DNS_Query->Classes = htons(DNS_CLASS_IN);
			if (Protocol == AF_INET6) //IPv6
				DNS_Query->Type = htons(DNS_RECORD_AAAA);
			else //IPv4
				DNS_Query->Type = htons(DNS_RECORD_A);
			DNSQuery.reset();
			DataLength += sizeof(dns_qry);

		//EDNS0 Label
			if (Parameter.EDNS0Label) //No additional
			{
				auto DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + sizeof(dns_hdr) + DataLength);
				DNS_Header->Additional = htons(U16_NUM_ONE);
				DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
				DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				DataLength += sizeof(dns_record_opt);
			}
		}
		else {
			return EXIT_FAILURE;
		}
	}
	DataLength += sizeof(dns_hdr);

//Send requesting.
	size_t Times = 0;
	auto IsReTest = false;
	for (;;)
	{
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			IsReTest = false;
			if (Protocol == AF_INET6) //IPv6
			{
				if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0 || //Main
					Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0) //Alternate
						IsReTest = true;

			//Other(Multi)
				if (Parameter.DNSTarget.IPv6_Multi != nullptr)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
						{
							IsReTest = true;
							break;
						}
					}
				}
			}
			else { //IPv4
				if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0 || //Main
					Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0) //Alternate
						IsReTest = true;

			//Other(Multi)
				if (Parameter.DNSTarget.IPv4_Multi != nullptr)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
						{
							IsReTest = true;
							break;
						}
					}
				}
			}

		//Test again.
			if (IsReTest)
			{
				Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
				continue;
			}
			else {
				Sleep((DWORD)Parameter.DomainTestSpeed);
			}
		}
		else {
		//Make ramdom domain request.
			if (Parameter.DomainTestData == nullptr)
			{
				memset(Buffer.get() + sizeof(dns_hdr), 0, PACKET_MAXSIZE - sizeof(dns_hdr));
				MakeRamdomDomain(DNSQuery.get());
				DataLength = CharToDNSQuery(DNSQuery.get(), Buffer.get() + sizeof(dns_hdr));
				memset(DNSQuery.get(), 0, DOMAIN_MAXSIZE);

				DNS_Query = (pdns_qry)(Buffer.get() + sizeof(dns_hdr) + DataLength);
				DNS_Query->Classes = htons(DNS_CLASS_IN);
				if (Protocol == AF_INET6) //IPv6
					DNS_Query->Type = htons(DNS_RECORD_AAAA);
				else //IPv4
					DNS_Query->Type = htons(DNS_RECORD_A);
				DataLength += sizeof(dns_qry);

			//EDNS0 Label
				if (Parameter.EDNS0Label) //No additional
				{
					auto DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + sizeof(dns_hdr) + DataLength);
					DNS_Header->Additional = htons(U16_NUM_ONE);
					DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
					DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					DataLength += sizeof(dns_record_opt);
				}

				DataLength += sizeof(dns_hdr);
			}

		//Send.
			UDPRequestMulti(Buffer.get(), (int)DataLength, nullptr, 0);

		//Repeat.
			++Times;
			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
		}
	}

	PrintError(LOG_ERROR_SYSTEM, L"Domain Test module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Internet Control Message Protocol/ICMP Echo(Ping) request
size_t __fastcall ICMPEcho(void)
{
//Initialization
	std::shared_ptr<char> Buffer(new char[sizeof(icmp_hdr) + Parameter.ICMPPaddingDataLength - 1U]());
	memset(Buffer.get(), 0, sizeof(icmp_hdr) + Parameter.ICMPPaddingDataLength - 1U);
	std::vector<sockaddr_storage> SockAddr;
	std::shared_ptr<sockaddr_storage> SockAddrTemp(new sockaddr_storage());
	memset(SockAddrTemp.get(), 0, sizeof(sockaddr_storage));

//Make a ICMP request echo packet.
	auto ICMP_Header = (picmp_hdr)Buffer.get();
	ICMP_Header->Type = ICMP_TYPE_REQUEST; //Echo(Ping) request type
	ICMP_Header->ID = Parameter.ICMPID;
	ICMP_Header->Sequence = Parameter.ICMPSequence;
	memcpy_s(Buffer.get() + sizeof(icmp_hdr), Parameter.ICMPPaddingDataLength - 1U, Parameter.ICMPPaddingData, Parameter.ICMPPaddingDataLength - 1U);
	ICMP_Header->Checksum = GetChecksum((PUINT16)Buffer.get(), sizeof(icmp_hdr) + Parameter.ICMPPaddingDataLength - 1U);
	SYSTEM_SOCKET ICMPSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	//Main and Alternate
	SockAddrTemp->ss_family = AF_INET;
	((PSOCKADDR_IN)SockAddrTemp.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
	SockAddr.push_back(*SockAddrTemp);
	memset(SockAddrTemp.get(), 0, sizeof(sockaddr_storage));
	if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
	{
		SockAddrTemp->ss_family = AF_INET;
		((PSOCKADDR_IN)SockAddrTemp.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
		SockAddr.push_back(*SockAddrTemp);
		memset(SockAddrTemp.get(), 0, sizeof(sockaddr_storage));
	}

	//Other(Multi)
	if (Parameter.DNSTarget.IPv4_Multi != nullptr)
	{
		for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
		{
			SockAddrTemp->ss_family = AF_INET;
			((PSOCKADDR_IN)SockAddrTemp.get())->sin_addr = DNSServerDataIter.AddressData.IPv4.sin_addr;
			SockAddr.push_back(*SockAddrTemp);
			memset(SockAddrTemp.get(), 0, sizeof(sockaddr_storage));
		}
	}

//Socket check
	if (ICMPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"ICMP Echo(Ping) request error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(ICMPSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
#elif defined(PLATFORM_LINUX)
	if (setsockopt(ICMPSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		PrintError(LOG_ERROR_NETWORK, L"Set ICMP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(ICMPSocket);

		return EXIT_FAILURE;
	}

//Send requesting.
	size_t Times = 0;
	auto IsReTest = false;
	for (;;)
	{
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			IsReTest = false;
			if (Parameter.DNSTarget.IPv4_Multi != nullptr) //Other(Multi)
			{
				for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
				{
					if (DNSServerDataIter.HopLimitData.TTL == 0)
					{
						IsReTest = true;
						break;
					}
				}
			}

			if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0 || //Main
				Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0 || //Alternate
				IsReTest) //Other(Multi)
			{
				Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
				continue;
			}

			Sleep((DWORD)Parameter.ICMPSpeed);
		}

	//Send.
		for (auto HostsTableIter:SockAddr)
		{
			sendto(ICMPSocket, Buffer.get(), (int)(sizeof(icmp_hdr) + Parameter.ICMPPaddingDataLength - 1U), 0, (PSOCKADDR)&HostsTableIter, sizeof(sockaddr_in));

		//Increase Sequence.
			if (Parameter.ICMPSequence == htons(DEFAULT_SEQUENCE))
			{
				if (ICMP_Header->Sequence == UINT16_MAX)
					ICMP_Header->Sequence = htons(DEFAULT_SEQUENCE);
				else 
					ICMP_Header->Sequence = htons(ntohs(ICMP_Header->Sequence) + 1U);

				ICMP_Header->Checksum = 0;
				ICMP_Header->Checksum = GetChecksum((PUINT16)Buffer.get(), sizeof(icmp_hdr) + Parameter.ICMPPaddingDataLength - 1U);
			}
		}

	//Repeat.
		++Times;
		Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
	}

	shutdown(ICMPSocket, SD_BOTH);
	closesocket(ICMPSocket);
	PrintError(LOG_ERROR_SYSTEM, L"ICMP Test module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Internet Control Message Protocol Echo version 6/ICMPv6 Echo(Ping) request
size_t __fastcall ICMPv6Echo(void)
{
//Initialization
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

//Make a ICMPv6 request echo packet.
	picmpv6_hdr ICMPv6_Header = nullptr;
	for (auto &StringIter:Buffer)
	{
		std::shared_ptr<char> BufferTemp(new char[sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U]());
		memset(BufferTemp.get(), 0, sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U);

		ICMPv6_Header = (picmpv6_hdr)BufferTemp.get();
		ICMPv6_Header->Type = ICMPV6_REQUEST;
		ICMPv6_Header->Code = 0;
		ICMPv6_Header->ID = Parameter.ICMPID;
		ICMPv6_Header->Sequence = Parameter.ICMPSequence;
		memcpy_s(BufferTemp.get() + sizeof(icmpv6_hdr), Parameter.ICMPPaddingDataLength - 1U, Parameter.ICMPPaddingData, Parameter.ICMPPaddingDataLength - 1U);
		BufferTemp.swap(StringIter);
	}

//Get localhost IPv6 address.
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	auto LocalAddressTableIter = GetLocalAddressList(AF_INET6);
	if (LocalAddressTableIter == nullptr)
	{
		PrintError(LOG_ERROR_NETWORK, L"Get localhost addresses", 0, nullptr, 0);
		return EXIT_FAILURE;
	}
	else {
		if (LocalAddressTableIter->ai_family == AF_INET6 && LocalAddressTableIter->ai_addrlen == sizeof(sockaddr_in6))
			memcpy_s(SockAddr.get(), sizeof(sockaddr_storage), LocalAddressTableIter->ai_addr, sizeof(sockaddr_in6));
		freeaddrinfo(LocalAddressTableIter);
	}

//ICMP Sequence increase and calculate checksum.
	ICMPv6_Header = (picmpv6_hdr)Buffer.front().get();
	ICMPv6_Header->Checksum = ICMPv6Checksum((PUINT8)Buffer.front().get(), sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U, Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr);
	if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0)
	{
		Buffer.erase(Buffer.begin() + 1U);
	}
	else {
		ICMPv6_Header = (picmpv6_hdr)Buffer[1U].get();
		if (Parameter.ICMPSequence == htons(DEFAULT_SEQUENCE))
			ICMPv6_Header->Sequence = htons(ntohs(Parameter.ICMPSequence) + 1U);
		ICMPv6_Header->Checksum = ICMPv6Checksum((PUINT8)Buffer[1U].get(), sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U, Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr);
	}

	//Multi requesting part.
	size_t Index = 0;
	for (Index = 2U;(SSIZE_T)Index < (SSIZE_T)(Buffer.size() - 2U);++Index)
	{
		ICMPv6_Header = (picmpv6_hdr)Buffer[Index].get();
		if (Parameter.ICMPSequence == htons(DEFAULT_SEQUENCE))
			ICMPv6_Header->Sequence = htons((uint16_t)(ntohs(Parameter.ICMPSequence) + Index));
		ICMPv6_Header->Checksum = ICMPv6Checksum((PUINT8)Buffer[Index].get(), sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U, Parameter.DNSTarget.IPv6_Multi->at(Index).AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr);
	}

//Socket check
	SYSTEM_SOCKET ICMPv6Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (ICMPv6Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"ICMPv6 Echo(Ping) request error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(ICMPv6Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
#elif defined(PLATFORM_LINUX)
	if (setsockopt(ICMPv6Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		PrintError(LOG_ERROR_NETWORK, L"Set ICMPv6 socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(ICMPv6Socket);

		return EXIT_FAILURE;
	}

//Send requesting.
	size_t Times = 0;
	auto IsReTest = false;
	for (;;)
	{
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			IsReTest = false;
			if (Parameter.DNSTarget.IPv6_Multi != nullptr)
			{
				for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi) //Other(Multi)
				{
					if (DNSServerDataIter.HopLimitData.TTL == 0)
					{
						IsReTest = true;
						break;
					}
				}
			}

			if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0 || //IPv6 Main
				Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0 || //IPv6 Alternate
				IsReTest) //Other(Multi)
			{
				Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
				continue;
			}

			Sleep((DWORD)Parameter.ICMPSpeed);
		}

	//Send.
		//Main
		sendto(ICMPv6Socket, Buffer.front().get(), (int)(sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U), 0, (PSOCKADDR)&Parameter.DNSTarget.IPv6.AddressData.IPv6, sizeof(sockaddr_in6));
		if (Parameter.ICMPSequence == htons(DEFAULT_SEQUENCE)) //Increase Sequence.
		{
			ICMPv6_Header = (picmpv6_hdr)Buffer.front().get();
			if (ICMPv6_Header->Sequence == UINT16_MAX)
				ICMPv6_Header->Sequence = htons(DEFAULT_SEQUENCE);
			else 
				ICMPv6_Header->Sequence = htons(ntohs(ICMPv6_Header->Sequence) + 1U);
			ICMPv6_Header->Checksum = 0;
			ICMPv6_Header->Checksum = ICMPv6Checksum((PUINT8)Buffer.front().get(), sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U, Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr);
		}

		//Alternate
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
			sendto(ICMPv6Socket, Buffer[1U].get(), (int)(sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U), 0, (PSOCKADDR)&Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6, sizeof(sockaddr_in6));
			if (Parameter.ICMPSequence == htons(DEFAULT_SEQUENCE)) //Increase Sequence.
			{
				ICMPv6_Header = (picmpv6_hdr)Buffer[1U].get();
				if (ICMPv6_Header->Sequence == UINT16_MAX)
					ICMPv6_Header->Sequence = htons(DEFAULT_SEQUENCE);
				else 
					ICMPv6_Header->Sequence = htons(ntohs(ICMPv6_Header->Sequence) + 1U);
				ICMPv6_Header->Checksum = 0;
				ICMPv6_Header->Checksum = ICMPv6Checksum((PUINT8)Buffer[1U].get(), sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U, Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr);
			}
		}

		//Other(Multi)
		if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			Index = 2U;
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				sendto(ICMPv6Socket, Buffer[Index].get(), (int)(sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U), 0, (PSOCKADDR)&DNSServerDataIter.AddressData.IPv6, sizeof(sockaddr_in6));
				if (Parameter.ICMPSequence == htons(DEFAULT_SEQUENCE)) //Increase Sequence.
				{
					ICMPv6_Header = (picmpv6_hdr)Buffer[Index].get();
					if (ICMPv6_Header->Sequence == UINT16_MAX)
						ICMPv6_Header->Sequence = htons(DEFAULT_SEQUENCE);
					else 
						ICMPv6_Header->Sequence = htons(ntohs(ICMPv6_Header->Sequence) + 1U);
					ICMPv6_Header->Checksum = 0;
					ICMPv6_Header->Checksum = ICMPv6Checksum((PUINT8)Buffer[Index].get(), sizeof(icmpv6_hdr) + Parameter.ICMPPaddingDataLength - 1U, DNSServerDataIter.AddressData.IPv6.sin6_addr, ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr);
				}

				++Index;
			}
		}

	//Repeat.
		Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
		++Times;
	}

	shutdown(ICMPv6Socket, SD_BOTH);
	closesocket(ICMPv6Socket);
	PrintError(LOG_ERROR_SYSTEM, L"ICMPv6 Test module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Transmission and reception of TCP protocol(Independent)
size_t __fastcall TCPRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const bool IsLocal)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[sizeof(uint16_t) + SendSize]());
	memset(SendBuffer.get(), 0, sizeof(uint16_t) + SendSize);
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SYSTEM_SOCKET TCPSocket = 0;
	socklen_t AddrLen = 0;
	memcpy_s(SendBuffer.get(), SendSize, OriginalSend, SendSize);

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	size_t DataLength = AddLengthToTCPDNSHeader(SendBuffer.get(), SendSize, sizeof(uint16_t) + SendSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	if (Parameter.GatewayAvailable_IPv6) //IPv6
	{
	//Local requesting
		if (IsLocal && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0)
		{
			IsAlternate = &AlternateSwapList.IsSwap[4U];
			AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[4U];
			if (*IsAlternate && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0) //Alternate
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port;
			}
			else { //Main
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port;
			}

			SockAddr->ss_family = AF_INET6;
			TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			AddrLen = sizeof(sockaddr_in6);
		}

	//Main requesting
		if (!IsLocal && SockAddr->ss_family == 0 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0)
		{
			IsAlternate = &AlternateSwapList.IsSwap[0];
			AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[0];
			if (*IsAlternate && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0) //Alternate
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port;
			}
			else { //Main
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port;
			}

			SockAddr->ss_family = AF_INET6;
			TCPSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			AddrLen = sizeof(sockaddr_in6);
		}
	}

	if ((TCPSocket == INVALID_SOCKET || SockAddr->ss_family == 0) && Parameter.GatewayAvailable_IPv4) //IPv4
	{
	//Local requesting
		if (IsLocal && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0)
		{
			IsAlternate = &AlternateSwapList.IsSwap[5U];
			AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[5U];
			if (*IsAlternate && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0) //Alternate
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_port;
			}
			else { //Main
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port;
			}

			SockAddr->ss_family = AF_INET;
			TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			AddrLen = sizeof(sockaddr_in);
		}

	//Main requesting
		if (!IsLocal && SockAddr->ss_family == 0 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0)
		{
			IsAlternate = &AlternateSwapList.IsSwap[1U];
			AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[1U];
			if (*IsAlternate && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0) //Alternate
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
			else { //Main
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}

			SockAddr->ss_family = AF_INET;
			TCPSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			AddrLen = sizeof(sockaddr_in);
		}
	}

//Socket check
	if (TCPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}
	else if (SockAddr->ss_family == 0)
	{
		PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSocket);

		return EXIT_FAILURE;
	}

/* TCP KeepAlive Mode
	BOOL bKeepAlive = TRUE;
	if (setsockopt(TCPSocket, SOL_SOCKET, SO_KEEPALIVE, (const char *)&bKeepAlive, sizeof(bKeepAlive)) == SOCKET_ERROR)
	{
		closesocket(TCPSocket);
		return EXIT_FAILURE;
	}

	tcp_keepalive alive_in = {0};
	tcp_keepalive alive_out = {0};
	alive_in.keepalivetime = STANDARD_TIMEOUT;
	alive_in.keepaliveinterval = Parameter.ReliableSocketTimeout;
	alive_in.onoff = TRUE;
	ULONG ulBytesReturn = 0;
	if (WSAIoctl(TCPSocket, SIO_KEEPALIVE_VALS, &alive_in, sizeof(alive_in), &alive_out, sizeof(alive_out), &ulBytesReturn, nullptr, nullptr) == SOCKET_ERROR)
	{
		closesocket(TCPSocket);
		return EXIT_FAILURE;
	}
*/

//Set Non-blocking Mode
#if defined(PLATFORM_WIN)
	ULONG SocketMode = 1U;
	if (ioctlsocket(TCPSocket, FIONBIO, &SocketMode) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSocket);

		return EXIT_FAILURE;
	}
#elif defined(PLATFORM_LINUX)
	int Flags = fcntl(TCPSocket, F_GETFL, 0);
	fcntl(TCPSocket, F_SETFL, Flags|O_NONBLOCK);
#endif

//Connect to server.
	if (connect(TCPSocket, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
	{
		if (IsAlternate != nullptr && !*IsAlternate && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSocket);
			if (AlternateTimeoutTimes != nullptr)
				++(*AlternateTimeoutTimes);

			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSocket);
			return EXIT_FAILURE;
		}
	}

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	timeval Timeout = {0};
	FD_ZERO(WriteFDS.get());
	FD_SET(TCPSocket, WriteFDS.get());
	SSIZE_T SelectResult = 0, RecvLen = 0;
	uint16_t PDULen = 0;
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
	#if defined(PLATFORM_WIN)
		Timeout.tv_sec = Parameter.ReliableSocketTimeout / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.ReliableSocketTimeout % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif defined(PLATFORM_LINUX)
		Timeout.tv_sec = Parameter.ReliableSocketTimeout.tv_sec;
		Timeout.tv_usec = Parameter.ReliableSocketTimeout.tv_usec;
	#endif
		FD_ZERO(ReadFDS.get());
		FD_SET(TCPSocket, ReadFDS.get());

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
	#elif defined(PLATFORM_LINUX)
		SelectResult = select(TCPSocket + 1U, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
	#endif
		if (SelectResult > 0)
		{
		//Receive.
			if (FD_ISSET(TCPSocket, ReadFDS.get()))
			{
				RecvLen = recv(TCPSocket, OriginalRecv, (int)RecvSize, 0);

			//TCP segment of a reassembled PDU
				if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
				{
					if (RecvLen > 0 && htons(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE)
					{
						PDULen = htons(((uint16_t *)OriginalRecv)[0]);
						memset(OriginalRecv, 0, RecvSize);
						continue;
					}
				//Invalid packet.
					else {
						break;
					}
				}
				else {
				//Length check.
					if (RecvLen < (SSIZE_T)PDULen)
					{
						break;
					}
				//Receive again.
					else if (PDULen > 0)
					{
						shutdown(TCPSocket, SD_BOTH);
						closesocket(TCPSocket);

					//Jump to normal receive process.
						if (PDULen >= DNS_PACKET_MINSIZE)
						{
							RecvLen = PDULen;
							goto JumpFromPDU;
						}

						memset(OriginalRecv, 0, RecvSize);
						return EXIT_FAILURE;
					}
				//First receive.
					else {
					//Length check
						if (RecvLen < (SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]))
						{
							break;
						}
						else {
							shutdown(TCPSocket, SD_BOTH);
							closesocket(TCPSocket);

							RecvLen = ntohs(((uint16_t *)OriginalRecv)[0]);
							if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
							{
								memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(uint16_t), RecvLen);

							//Jump here when TCP segment of a reassembled PDU.
								JumpFromPDU: 

							//Responses question and answers check
								if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, IsLocal, nullptr))
								{
									memset(OriginalRecv, 0, RecvSize);
									return EXIT_FAILURE;
								}

							//Mark DNS Cache.
								if (Parameter.CacheType > 0)
									MarkDomainCache(OriginalRecv, RecvLen);

								return RecvLen;
							}
						//Length check
							else {
								break;
							}
						}
					}
				}
			}

		//Send.
			if (FD_ISSET(TCPSocket, WriteFDS.get()))
			{
				send(TCPSocket, SendBuffer.get(), (int)DataLength, 0);
				FD_ZERO(WriteFDS.get());
			}
		}
	//Timeout
		else if (SelectResult == 0)
		{
			shutdown(TCPSocket, SD_BOTH);
			closesocket(TCPSocket);
			memset(OriginalRecv, 0, RecvSize);
			if (IsAlternate != nullptr && !*IsAlternate)
				++(*AlternateTimeoutTimes);

			return WSAETIMEDOUT;
		}
	//SOCKET_ERROR
		else {
			break;
		}
	}

	shutdown(TCPSocket, SD_BOTH);
	closesocket(TCPSocket);
	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}

//Transmission and reception of TCP protocol(Multithreading)
size_t __fastcall TCPRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[sizeof(uint16_t) + SendSize]());
	memset(SendBuffer.get(), 0, sizeof(uint16_t) + SendSize);
	std::vector<SOCKET_DATA> TCPSocketDataList;
	memcpy_s(SendBuffer.get(), SendSize, OriginalSend, SendSize);

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	size_t DataLength = AddLengthToTCPDNSHeader(SendBuffer.get(), SendSize, sizeof(uint16_t) + SendSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket initialization
	if (Parameter.GatewayAvailable_IPv6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
		std::shared_ptr<SOCKET_DATA> TCPSocketData(new SOCKET_DATA());
		memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
	#if defined(PLATFORM_WIN)
		ULONG SocketMode = 1U;
	#elif defined(PLATFORM_LINUX)
		int Flags = 0;
	#endif
		auto IsAlternate = AlternateSwapList.IsSwap[0];

	//Main
		if (!IsAlternate)
		{
			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				TCPSocketData->SockAddr = Parameter.DNSTarget.IPv6.AddressData.Storage;
				TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			//Socket check
				if (TCPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
			#if defined(PLATFORM_WIN)
				else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					closesocket(TCPSocketData->Socket);

					return EXIT_FAILURE;
				}
			#elif defined(PLATFORM_LINUX)
				Flags = fcntl(TCPSocketData->Socket, F_GETFL, 0);
				fcntl(TCPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
			#endif

				TCPSocketData->AddrLen = sizeof(sockaddr_in6);
				TCPSocketDataList.push_back(*TCPSocketData);
				memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && (IsAlternate || Parameter.AlternateMultiRequest))
		{
			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				TCPSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage;
				TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			//Socket check
				if (TCPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:TCPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
			#if defined(PLATFORM_WIN)
				else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:TCPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}
			#elif defined(PLATFORM_LINUX)
				Flags = fcntl(TCPSocketData->Socket, F_GETFL, 0);
				fcntl(TCPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
			#endif

				TCPSocketData->AddrLen = sizeof(sockaddr_in6);
				TCPSocketDataList.push_back(*TCPSocketData);
				memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Other servers
		if (Parameter.DNSTarget.IPv6_Multi != nullptr && !IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
				{
					TCPSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
					TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
				//Socket check
					if (TCPSocketData->Socket == INVALID_SOCKET)
					{
						PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
						for (auto SocketDataIter:TCPSocketDataList)
							closesocket(SocketDataIter.Socket);

						return EXIT_FAILURE;
					}
				//Set Non-blocking Mode
				#if defined(PLATFORM_WIN)
					else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
					{
						PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
						for (auto SocketDataIter:TCPSocketDataList)
							closesocket(SocketDataIter.Socket);

						return EXIT_FAILURE;
					}
				#elif defined(PLATFORM_LINUX)
					Flags = fcntl(TCPSocketData->Socket, F_GETFL, 0);
					fcntl(TCPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
				#endif

					TCPSocketData->AddrLen = sizeof(sockaddr_in6);
					TCPSocketDataList.push_back(*TCPSocketData);
					memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
				}
			}
		}
	}
	else if (Parameter.GatewayAvailable_IPv4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		std::shared_ptr<SOCKET_DATA> TCPSocketData(new SOCKET_DATA());
		memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
	#if defined(PLATFORM_WIN)
		ULONG SocketMode = 1U;
	#elif defined(PLATFORM_LINUX)
		int Flags = 0;
	#endif
		auto IsAlternate = AlternateSwapList.IsSwap[1U];

	//Main
		if (!IsAlternate)
		{
			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				TCPSocketData->SockAddr = Parameter.DNSTarget.IPv4.AddressData.Storage;
				TCPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			//Socket check
				if (TCPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
			#if defined(PLATFORM_WIN)
				else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					closesocket(TCPSocketData->Socket);

					return EXIT_FAILURE;
				}
			#elif defined(PLATFORM_LINUX)
				Flags = fcntl(TCPSocketData->Socket, F_GETFL, 0);
				fcntl(TCPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
			#endif

				TCPSocketData->AddrLen = sizeof(sockaddr_in);
				TCPSocketDataList.push_back(*TCPSocketData);
				memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && (IsAlternate || Parameter.AlternateMultiRequest))
		{
			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				TCPSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage;
				TCPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			//Socket check
				if (TCPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:TCPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
			#if defined(PLATFORM_WIN)
				else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:TCPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}
			#elif defined(PLATFORM_LINUX)
				Flags = fcntl(TCPSocketData->Socket, F_GETFL, 0);
				fcntl(TCPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
			#endif

				TCPSocketData->AddrLen = sizeof(sockaddr_in);
				TCPSocketDataList.push_back(*TCPSocketData);
				memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Other servers
		if (Parameter.DNSTarget.IPv4_Multi != nullptr && !IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
				{
					TCPSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
					TCPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
				//Socket check
					if (TCPSocketData->Socket == INVALID_SOCKET)
					{
						PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
						for (auto SocketDataIter:TCPSocketDataList)
							closesocket(SocketDataIter.Socket);

						return EXIT_FAILURE;
					}
				//Set Non-blocking Mode
				#if defined(PLATFORM_WIN)
					else if (ioctlsocket(TCPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
					{
						PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
						for (auto SocketDataIter:TCPSocketDataList)
							closesocket(SocketDataIter.Socket);

						return EXIT_FAILURE;
					}
				#elif defined(PLATFORM_LINUX)
					Flags = fcntl(TCPSocketData->Socket, F_GETFL, 0);
					fcntl(TCPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
				#endif

					TCPSocketData->AddrLen = sizeof(sockaddr_in);
					TCPSocketDataList.push_back(*TCPSocketData);
					memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
				}
			}
		}
	}
	else {
		return EXIT_FAILURE;
	}

//Connect to servers.
	for (auto SocketDataIter = TCPSocketDataList.begin();SocketDataIter != TCPSocketDataList.end();)
	{
		if (connect(SocketDataIter->Socket, (PSOCKADDR)&SocketDataIter->SockAddr, SocketDataIter->AddrLen) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
		{
			closesocket(SocketDataIter->Socket);
			SocketDataIter = TCPSocketDataList.erase(SocketDataIter);
			if (SocketDataIter == TCPSocketDataList.end())
				goto StopLoop;
		}
		else {
			++SocketDataIter;
		}
	}
	StopLoop: 
	if (TCPSocketDataList.empty())
		return EXIT_FAILURE;

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	timeval Timeout = {0};
#if defined(PLATFORM_LINUX)
	SOCKET MaxSocket = 0;
#endif
	FD_ZERO(WriteFDS.get());
	for (auto SocketDataIter:TCPSocketDataList)
	{
	#if defined(PLATFORM_LINUX)
		if (SocketDataIter.Socket > MaxSocket)
			MaxSocket = SocketDataIter.Socket;
	#endif
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0, RecvLen = 0;
	std::vector<uint16_t> PDULenList(TCPSocketDataList.size(), 0);
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
	#if defined(PLATFORM_WIN)
		Timeout.tv_sec = Parameter.ReliableSocketTimeout / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.ReliableSocketTimeout % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif defined(PLATFORM_LINUX)
		Timeout.tv_sec = Parameter.ReliableSocketTimeout.tv_sec;
		Timeout.tv_usec = Parameter.ReliableSocketTimeout.tv_usec;
	#endif
		FD_ZERO(ReadFDS.get());
		for (auto SocketDataIter:TCPSocketDataList)
		{
			if (SocketDataIter.Socket > 0)
			{
				FD_SET(SocketDataIter.Socket, ReadFDS.get());
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
	#elif defined(PLATFORM_LINUX)
		SelectResult = select(MaxSocket + 1U, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
	#endif
		if (SelectResult > 0)
		{
		//Receive.
			for (size_t Index = 0;Index < TCPSocketDataList.size();++Index)
			{
				if (FD_ISSET(TCPSocketDataList[Index].Socket, ReadFDS.get()))
				{
					RecvLen = recv(TCPSocketDataList[Index].Socket, OriginalRecv, (int)RecvSize, 0);

				//TCP segment of a reassembled PDU
					if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
					{
						if (RecvLen > 0 && htons(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE)
						{
							PDULenList[Index] = htons(((uint16_t *)OriginalRecv)[0]);
							memset(OriginalRecv, 0, RecvSize);
							continue;
						}
					//Invalid packet.
						else {
							shutdown(TCPSocketDataList[Index].Socket, SD_BOTH);
							closesocket(TCPSocketDataList[Index].Socket);
							TCPSocketDataList[Index].Socket = 0;
							break;
						}
					}
					else {
					//Length check.
						if ((SSIZE_T)PDULenList[Index] > RecvLen)
						{
							shutdown(TCPSocketDataList[Index].Socket, SD_BOTH);
							closesocket(TCPSocketDataList[Index].Socket);
							TCPSocketDataList[Index].Socket = 0;
							break;
						}
					//Receive again.
						else if (PDULenList[Index] > 0)
						{
						//Jump to normal receive process.
							if (PDULenList[Index] >= DNS_PACKET_MINSIZE)
							{
								RecvLen = (SSIZE_T)PDULenList[Index];
								goto JumpFromPDU;
							}

							memset(OriginalRecv, 0, RecvSize);
							continue;
						}
					//First receive.
						else {
						//Length check
							if ((SSIZE_T)ntohs(((uint16_t *)OriginalRecv)[0]) > RecvLen)
							{
								shutdown(TCPSocketDataList[Index].Socket, SD_BOTH);
								closesocket(TCPSocketDataList[Index].Socket);
								TCPSocketDataList[Index].Socket = 0;
								break;
							}
							else {
								RecvLen = ntohs(((uint16_t *)OriginalRecv)[0]);
								if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
								{
									memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(uint16_t), RecvLen);

								//Jump here when TCP segment of a reassembled PDU.
									JumpFromPDU: 

								//Responses question and answers check
									if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, false, nullptr))
									{
										memset(OriginalRecv, 0, RecvSize);
										continue;
									}

								//Close sockets and remove response length of TCP requesting.
									for (auto SocketDataIter:TCPSocketDataList)
									{
										if (SocketDataIter.Socket > 0)
										{
											shutdown(SocketDataIter.Socket, SD_BOTH);
											closesocket(SocketDataIter.Socket);
										}
									}

								//Mark DNS Cache.
									if (Parameter.CacheType > 0)
										MarkDomainCache(OriginalRecv, RecvLen);

									return RecvLen;
								}
							//Length check
								else {
									shutdown(TCPSocketDataList[Index].Socket, SD_BOTH);
									closesocket(TCPSocketDataList[Index].Socket);
									TCPSocketDataList[Index].Socket = 0;
									break;
								}
							}
						}
					}
				}
			}

		//Send.
			for (auto SocketDataIter:TCPSocketDataList)
			{
				if (FD_ISSET(SocketDataIter.Socket, WriteFDS.get()))
					send(SocketDataIter.Socket, SendBuffer.get(), (int)DataLength, 0);
			}

			FD_ZERO(WriteFDS.get());
		}
	//Timeout
		else if (SelectResult == 0)
		{
			memset(OriginalRecv, 0, RecvSize);
			++AlternateSwapList.TimeoutTimes[0];
			++AlternateSwapList.TimeoutTimes[1U];

		//Close all sockets.
			for (auto SocketDataIter:TCPSocketDataList)
			{
				if (SocketDataIter.Socket > 0)
				{
					shutdown(SocketDataIter.Socket, SD_BOTH);
					closesocket(SocketDataIter.Socket);
				}
			}

			return WSAETIMEDOUT;
		}
	//SOCKET_ERROR
		else {
			break;
		}
	}

//Close all sockets.
	for (auto SocketDataIter:TCPSocketDataList)
	{
		if (SocketDataIter.Socket > 0)
		{
			shutdown(SocketDataIter.Socket, SD_BOTH);
			closesocket(SocketDataIter.Socket);
		}
	}

	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}

//Transmission of UDP protocol
size_t __fastcall UDPRequest(const char *OriginalSend, const size_t Length, const SOCKET_DATA *LocalSocketData, const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SYSTEM_SOCKET UDPSocket = 0;
	socklen_t AddrLen = 0;

//Socket initialization
	if (Parameter.GatewayAvailable_IPv6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
		if (AlternateSwapList.IsSwap[2U] && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0) //Alternate
		{
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
		}
		else { //Main
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
			((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
		}

		AddrLen = sizeof(sockaddr_in6);
		SockAddr->ss_family = AF_INET6;
		UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else if (Parameter.GatewayAvailable_IPv4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		if (AlternateSwapList.IsSwap[3U] && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0) //Alternate
		{
			((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
		}
		else { //Main
			((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
			((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
		}

		AddrLen = sizeof(sockaddr_in);
		SockAddr->ss_family = AF_INET;
		UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
#elif defined(PLATFORM_LINUX)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send requesting.
	if (sendto(UDPSocket, OriginalSend, (int)Length, 0, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"UDP request error", WSAGetLastError(), nullptr, 0);
		shutdown(UDPSocket, SD_BOTH);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Mark port to list.
	if (LocalSocketData != nullptr && Protocol > 0)
	{
		if (getsockname(UDPSocket, (PSOCKADDR)SockAddr.get(), &AddrLen) != 0)
		{
			shutdown(UDPSocket, SD_BOTH);
			closesocket(UDPSocket);
			return EXIT_FAILURE;
		}

		std::shared_ptr<PORT_TABLE> PortListTemp(new PORT_TABLE());
		memset(PortListTemp.get(), 0, sizeof(PORT_TABLE));
		std::shared_ptr<SOCKET_DATA> SocketDataTemp(new SOCKET_DATA());
		memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));

	//Mark system connection data.
		PortListTemp->SystemData = *LocalSocketData;

	//Mark sending connection data.
		SocketDataTemp->AddrLen = AddrLen;
		if (AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			SocketDataTemp->SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&SocketDataTemp->SockAddr)->sin6_port = ((PSOCKADDR_IN6)SockAddr.get())->sin6_port;
		}
		else { //IPv4
			SocketDataTemp->SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SocketDataTemp->SockAddr)->sin_port = ((PSOCKADDR_IN)SockAddr.get())->sin_port;
		}

		PortListTemp->RequestData.push_back(*SocketDataTemp);
		PortListTemp->NetworkLayer = SocketDataTemp->SockAddr.ss_family;
		SocketDataTemp.reset();

	//Mark send time.
	//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
		PortListTemp->TransportLayer = Protocol;
		if (Protocol == IPPROTO_TCP) //TCP
		{
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.GetTickCount64PTR != nullptr)
				PortListTemp->ClearPortTime = (size_t)((*Parameter.GetTickCount64PTR)() + Parameter.ReliableSocketTimeout);
			else 
				PortListTemp->ClearPortTime = GetTickCount() + Parameter.ReliableSocketTimeout;
		#elif defined(PLATFORM_WIN)
			PortListTemp->ClearPortTime = GetTickCount64() + Parameter.ReliableSocketTimeout;
		#elif defined(PLATFORM_LINUX)
			PortListTemp->ClearPortTime = GetTickCount64() + Parameter.ReliableSocketTimeout.tv_sec * SECOND_TO_MILLISECOND + Parameter.ReliableSocketTimeout.tv_usec / MICROSECOND_TO_MILLISECOND;
		#endif
		}
		else { //UDP
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.GetTickCount64PTR != nullptr)
				PortListTemp->ClearPortTime = (size_t)((*Parameter.GetTickCount64PTR)() + Parameter.UnreliableSocketTimeout);
			else 
				PortListTemp->ClearPortTime = GetTickCount() + Parameter.UnreliableSocketTimeout;
		#elif defined(PLATFORM_WIN)
			PortListTemp->ClearPortTime = GetTickCount64() + Parameter.UnreliableSocketTimeout;
		#elif defined(PLATFORM_LINUX)
			PortListTemp->ClearPortTime = GetTickCount64() + Parameter.UnreliableSocketTimeout.tv_sec * SECOND_TO_MILLISECOND + Parameter.UnreliableSocketTimeout.tv_usec / MICROSECOND_TO_MILLISECOND;
		#endif
		}

		std::unique_lock<std::mutex> PortListMutex(PortListLock);
		PortList.push_back(*PortListTemp);
	}

//Block Port Unreachable messages of system or close the TCP requesting connections.
	shutdown(UDPSocket, SD_SEND);
#if defined(PLATFORM_WIN)
	if (Protocol == IPPROTO_TCP) //TCP
		Sleep(Parameter.ReliableSocketTimeout);
	else //UDP
		Sleep(Parameter.UnreliableSocketTimeout);
#elif defined(PLATFORM_LINUX)
	if (Protocol == IPPROTO_TCP) //TCP
		usleep(Parameter.ReliableSocketTimeout.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.ReliableSocketTimeout.tv_usec);
	else //UDP
		usleep(Parameter.UnreliableSocketTimeout.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.UnreliableSocketTimeout.tv_usec);
#endif
	shutdown(UDPSocket, SD_BOTH);
	closesocket(UDPSocket);

	return EXIT_SUCCESS;
}

//Transmission of UDP protocol(Multithreading)
size_t __fastcall UDPRequestMulti(const char *OriginalSend, const size_t Length, const SOCKET_DATA *LocalSocketData, const uint16_t Protocol)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;

//Socket initialization
	if (Parameter.GatewayAvailable_IPv6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
		std::shared_ptr<SOCKET_DATA> UDPSocketData(new SOCKET_DATA());
		memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
	#if defined(PLATFORM_WIN)
		ULONG SocketMode = 1U;
	#elif defined(PLATFORM_LINUX)
		int Flags = 0;
	#endif
		auto IsAlternate = AlternateSwapList.IsSwap[0];

	//Main
		if (!IsAlternate)
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.IPv6.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
		#if defined(PLATFORM_WIN)
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(UDPSocketData->Socket);

				return EXIT_FAILURE;
			}
		#elif defined(PLATFORM_LINUX)
			Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
			fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
		#endif

			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && (IsAlternate || LocalSocketData == nullptr || Parameter.AlternateMultiRequest))
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
		#if defined(PLATFORM_WIN)
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}
		#elif defined(PLATFORM_LINUX)
			Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
			fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
		#endif

			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Other servers
		if (Parameter.DNSTarget.IPv6_Multi != nullptr && (!IsAlternate && Parameter.AlternateMultiRequest || LocalSocketData == nullptr))
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				UDPSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
				UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			//Socket check
				if (UDPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
			#if defined(PLATFORM_WIN)
				else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}
			#elif defined(PLATFORM_LINUX)
				Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
				fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
			#endif

				UDPSocketData->AddrLen = sizeof(sockaddr_in6);
				UDPSocketDataList.push_back(*UDPSocketData);
				memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}
	}
	else if (Parameter.GatewayAvailable_IPv4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		std::shared_ptr<SOCKET_DATA> UDPSocketData(new SOCKET_DATA());
		memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
	#if defined(PLATFORM_WIN)
		ULONG SocketMode = 1U;
	#elif defined(PLATFORM_LINUX)
		int Flags = 0;
	#endif
		auto IsAlternate = AlternateSwapList.IsSwap[1U];

	//Main
		if (!IsAlternate)
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.IPv4.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
		#if defined(PLATFORM_WIN)
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(UDPSocketData->Socket);

				return EXIT_FAILURE;
			}
		#elif defined(PLATFORM_LINUX)
			Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
			fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
		#endif

			UDPSocketData->AddrLen = sizeof(sockaddr_in);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && (IsAlternate || LocalSocketData == nullptr || Parameter.AlternateMultiRequest))
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
		#if defined(PLATFORM_WIN)
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}
		#elif defined(PLATFORM_LINUX)
			Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
			fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
		#endif

			UDPSocketData->AddrLen = sizeof(sockaddr_in);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Other servers
		if (Parameter.DNSTarget.IPv4_Multi != nullptr && (!IsAlternate && Parameter.AlternateMultiRequest || LocalSocketData == nullptr))
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				UDPSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
				UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			//Socket check
				if (UDPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
			#if defined(PLATFORM_WIN)
				else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}
			#elif defined(PLATFORM_LINUX)
				Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
				fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
			#endif

				UDPSocketData->AddrLen = sizeof(sockaddr_in);
				UDPSocketDataList.push_back(*UDPSocketData);
				memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}
	}
	else {
		return EXIT_FAILURE;
	}

//Send request and receive result.
	std::shared_ptr<fd_set> WriteFDS(new fd_set());
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	timeval Timeout = {0};
#if defined(PLATFORM_LINUX)
	SOCKET MaxSocket = 0;
#endif
	FD_ZERO(WriteFDS.get());
	for (auto SocketDataIter:UDPSocketDataList)
	{
	#if defined(PLATFORM_LINUX)
		if (SocketDataIter.Socket > MaxSocket)
			MaxSocket = SocketDataIter.Socket;
	#endif
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0;
	for (;;)
	{
	//Reset parameters.
	#if defined(PLATFORM_WIN)
		Timeout.tv_sec = Parameter.UnreliableSocketTimeout / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.UnreliableSocketTimeout % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif defined(PLATFORM_LINUX)
		Timeout.tv_sec = Parameter.UnreliableSocketTimeout.tv_sec;
		Timeout.tv_usec = Parameter.UnreliableSocketTimeout.tv_usec;
	#endif

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, nullptr, WriteFDS.get(), nullptr, &Timeout);
	#elif defined(PLATFORM_LINUX)
		SelectResult = select(MaxSocket + 1U, nullptr, WriteFDS.get(), nullptr, &Timeout);
	#endif
		if (SelectResult > 0)
		{
		//Send.
			for (auto SocketDataIter:UDPSocketDataList)
			{
				if (FD_ISSET(SocketDataIter.Socket, WriteFDS.get()))
				{
					for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;++InnerIndex)
						sendto(SocketDataIter.Socket, OriginalSend, (int)Length, 0, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen);
				}
			}

			break;
		}
	//Timeout or SOCKET_ERROR
		else {
		//Close all sockets.
			for (auto SocketDataIter:UDPSocketDataList)
			{
				shutdown(SocketDataIter.Socket, SD_BOTH);
				closesocket(SocketDataIter.Socket);
			}

			return EXIT_FAILURE;
		}
	}

//Mark port to list.
	if (LocalSocketData != nullptr && Protocol > 0)
	{
		std::shared_ptr<SOCKET_DATA> SocketDataTemp(new SOCKET_DATA());
		std::shared_ptr<PORT_TABLE> PortListTemp(new PORT_TABLE());
		memset(PortListTemp.get(), 0, sizeof(PORT_TABLE));

	//Mark system connection data.
		PortListTemp->SystemData = *LocalSocketData;

	//Mark sending connection data.
		for (auto SocketDataIter:UDPSocketDataList)
		{
			memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));

		//Get socket information.
			if (getsockname(SocketDataIter.Socket, (PSOCKADDR)&SocketDataIter.SockAddr, &SocketDataIter.AddrLen) != 0)
			{
				shutdown(SocketDataIter.Socket, SD_BOTH);
				closesocket(SocketDataIter.Socket);
				continue;
			}

			SocketDataTemp->AddrLen = SocketDataIter.AddrLen;
			if (SocketDataIter.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				SocketDataTemp->SockAddr.ss_family = AF_INET6;
				((PSOCKADDR_IN6)&SocketDataTemp->SockAddr)->sin6_port = ((PSOCKADDR_IN6)&SocketDataIter.SockAddr)->sin6_port;
			}
			else { //IPv4
				SocketDataTemp->SockAddr.ss_family = AF_INET;
				((PSOCKADDR_IN)&SocketDataTemp->SockAddr)->sin_port = ((PSOCKADDR_IN)&SocketDataIter.SockAddr)->sin_port;
			}

			PortListTemp->RequestData.push_back(*SocketDataTemp);
		}

		SocketDataTemp.reset();

	//Mark send time.
	//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
		PortListTemp->NetworkLayer = Protocol;
		if (Protocol == IPPROTO_TCP) //TCP
		{
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.GetTickCount64PTR != nullptr)
				PortListTemp->ClearPortTime = (size_t)((*Parameter.GetTickCount64PTR)() + Parameter.ReliableSocketTimeout);
			else 
				PortListTemp->ClearPortTime = GetTickCount() + Parameter.ReliableSocketTimeout;
		#elif defined(PLATFORM_WIN)
			PortListTemp->ClearPortTime = GetTickCount64() + Parameter.ReliableSocketTimeout;
		#elif defined(PLATFORM_LINUX)
			PortListTemp->ClearPortTime = GetTickCount64() + Parameter.ReliableSocketTimeout.tv_sec * SECOND_TO_MILLISECOND + Parameter.ReliableSocketTimeout.tv_usec / MICROSECOND_TO_MILLISECOND;
		#endif
		}
		else { //UDP
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64)) //Windows(x86)
			if (Parameter.GetTickCount64PTR != nullptr)
				PortListTemp->ClearPortTime = (size_t)((*Parameter.GetTickCount64PTR)() + Parameter.UnreliableSocketTimeout);
			else 
				PortListTemp->ClearPortTime = GetTickCount() + Parameter.UnreliableSocketTimeout;
		#elif defined(PLATFORM_WIN)
			PortListTemp->ClearPortTime = GetTickCount64() + Parameter.UnreliableSocketTimeout;
		#elif defined(PLATFORM_LINUX)
			PortListTemp->ClearPortTime = GetTickCount64() + Parameter.UnreliableSocketTimeout.tv_sec * SECOND_TO_MILLISECOND + Parameter.UnreliableSocketTimeout.tv_usec / MICROSECOND_TO_MILLISECOND;
		#endif
		}

		std::unique_lock<std::mutex> PortListMutex(PortListLock);
		PortList.push_back(*PortListTemp);
	}

//Block Port Unreachable messages of system or close the TCP requesting connections.
	for (auto SocketDataIter:UDPSocketDataList)
		shutdown(SocketDataIter.Socket, SD_SEND);
#if defined(PLATFORM_WIN)
	if (Protocol == IPPROTO_TCP) //TCP
		Sleep(Parameter.ReliableSocketTimeout);
	else //UDP
		Sleep(Parameter.UnreliableSocketTimeout);
#elif defined(PLATFORM_LINUX)
	if (Protocol == IPPROTO_TCP) //TCP
		usleep(Parameter.ReliableSocketTimeout.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.ReliableSocketTimeout.tv_usec);
	else //UDP
		usleep(Parameter.UnreliableSocketTimeout.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.UnreliableSocketTimeout.tv_usec);
#endif
	for (auto SocketDataIter:UDPSocketDataList)
	{
		shutdown(SocketDataIter.Socket, SD_BOTH);
		closesocket(SocketDataIter.Socket);
	}

	return EXIT_SUCCESS;
}

//Complete transmission of UDP protocol
size_t __fastcall UDPCompleteRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const bool IsLocal)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SYSTEM_SOCKET UDPSocket = 0;
	socklen_t AddrLen = 0;

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	if (Parameter.GatewayAvailable_IPv6) //IPv6
	{
	//Local requesting
		if (IsLocal && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0)
		{
			IsAlternate = &AlternateSwapList.IsSwap[6U];
			AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[6U];
			if (*IsAlternate && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0) //Alternate
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port;
			}
			else { //Main
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port;
			}

			SockAddr->ss_family = AF_INET6;
			UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			AddrLen = sizeof(sockaddr_in6);
		}

	//Main requesting
		if (!IsLocal && SockAddr->ss_family == 0 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0)
		{
			IsAlternate = &AlternateSwapList.IsSwap[2U];
			AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[2U];
			if (*IsAlternate && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0) //Alternate
			{
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port;
			}
			else { //Main
				((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)SockAddr.get())->sin6_port = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port;
			}

			SockAddr->ss_family = AF_INET6;
			UDPSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			AddrLen = sizeof(sockaddr_in6);
		}
	}

	if ((UDPSocket == INVALID_SOCKET || SockAddr->ss_family == 0) && Parameter.GatewayAvailable_IPv4) //IPv4
	{
	//Local requesting
		if (IsLocal && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0)
		{
			IsAlternate = &AlternateSwapList.IsSwap[7U];
			AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[7U];
			if (*IsAlternate && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0) //Alternate
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_port;
			}
			else { //Main
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port;
			}

			SockAddr->ss_family = AF_INET;
			UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			AddrLen = sizeof(sockaddr_in);
		}

	//Main requesting
		if (!IsLocal && SockAddr->ss_family == 0 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0)
		{
			IsAlternate = &AlternateSwapList.IsSwap[3U];
			AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[3U];
			if (*IsAlternate && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0) //Alternate
			{
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
			else { //Main
				((PSOCKADDR_IN)SockAddr.get())->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)SockAddr.get())->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}

			SockAddr->ss_family = AF_INET;
			UDPSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			AddrLen = sizeof(sockaddr_in);
		}
	}

//Socket check
	if (UDPSocket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}
	else if (SockAddr->ss_family == 0)
	{
		PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
#elif defined(PLATFORM_LINUX)
	if (setsockopt(UDPSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(UDPSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//UDP connecting
	if (connect(UDPSocket, (PSOCKADDR)SockAddr.get(), AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Send requesting.
	if (send(UDPSocket, OriginalSend, (int)SendSize, 0) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Complete UDP request error", WSAGetLastError(), nullptr, 0);
		shutdown(UDPSocket, SD_BOTH);
		closesocket(UDPSocket);

		return EXIT_FAILURE;
	}

//Receive result.
	SSIZE_T RecvLen = recv(UDPSocket, OriginalRecv, (int)RecvSize, 0);
	if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		if (RecvLen == SOCKET_ERROR)
			RecvLen = WSAGetLastError();
		shutdown(UDPSocket, SD_BOTH);
		closesocket(UDPSocket);
		memset(OriginalRecv, 0, RecvSize);

		if (RecvLen == WSAETIMEDOUT)
		{
			if (IsAlternate != nullptr && !*IsAlternate && AlternateTimeoutTimes != nullptr)
				++(*AlternateTimeoutTimes);
			return WSAETIMEDOUT;
		}
	}
	else {
	//Hosts Only Extended check
		if (Parameter.DNSDataCheck || Parameter.Blacklist)
		{
			for (;;)
			{
				if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, IsLocal, nullptr))
				{
					memset(OriginalRecv, 0, RecvSize);
					if (IsLocal) //Stop waitting when it is Local requesting.
					{
						shutdown(UDPSocket, SD_BOTH);
						closesocket(UDPSocket);
						return EXIT_FAILURE;
					}
					else {
						RecvLen = recv(UDPSocket, OriginalRecv, (int)RecvSize, 0);
						if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
						{
							if (RecvLen == SOCKET_ERROR)
								RecvLen = WSAGetLastError();
							shutdown(UDPSocket, SD_BOTH);
							closesocket(UDPSocket);
							memset(OriginalRecv, 0, RecvSize);
							if (RecvLen == WSAETIMEDOUT)
							{
								if (IsAlternate != nullptr && !*IsAlternate && AlternateTimeoutTimes != nullptr)
									++(*AlternateTimeoutTimes);
								return WSAETIMEDOUT;
							}
							else {
								return EXIT_FAILURE;
							}
						}

						Sleep(LOOP_INTERVAL_TIME);
					}
				}
				else {
					shutdown(UDPSocket, SD_BOTH);
					closesocket(UDPSocket);
					break;
				}
			}
		}

		shutdown(UDPSocket, SD_BOTH);
		closesocket(UDPSocket);

	//Mark DNS Cache.
		if (Parameter.CacheType > 0)
			MarkDomainCache(OriginalRecv, RecvLen);

		return RecvLen;
	}

	return EXIT_FAILURE;
}

//Complete transmission of UDP protocol(Multithreading)
size_t __fastcall UDPCompleteRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;

//Socket initialization
	if (Parameter.GatewayAvailable_IPv6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0) //IPv6
	{
		std::shared_ptr<SOCKET_DATA> UDPSocketData(new SOCKET_DATA());
		memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
	#if defined(PLATFORM_WIN)
		ULONG SocketMode = 1U;
	#elif defined(PLATFORM_LINUX)
		int Flags = 0;
	#endif
		auto IsAlternate = AlternateSwapList.IsSwap[0];

	//Main
		if (!IsAlternate)
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.IPv6.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
		#if defined(PLATFORM_WIN)
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(UDPSocketData->Socket);

				return EXIT_FAILURE;
			}
		#elif defined(PLATFORM_LINUX)
			Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
			fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
		#endif

			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && (IsAlternate || Parameter.AlternateMultiRequest))
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
		#if defined(PLATFORM_WIN)
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}
		#elif defined(PLATFORM_LINUX)
			Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
			fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
		#endif

			UDPSocketData->AddrLen = sizeof(sockaddr_in6);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Other servers
		if (Parameter.DNSTarget.IPv6_Multi != nullptr && !IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				UDPSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
				UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			//Socket check
				if (UDPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
			#if defined(PLATFORM_WIN)
				else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}
			#elif defined(PLATFORM_LINUX)
				Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
				fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
			#endif

				UDPSocketData->AddrLen = sizeof(sockaddr_in6);
				UDPSocketDataList.push_back(*UDPSocketData);
				memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}
	}
	else if (Parameter.GatewayAvailable_IPv4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //IPv4
	{
		std::shared_ptr<SOCKET_DATA> UDPSocketData(new SOCKET_DATA());
		memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
	#if defined(PLATFORM_WIN)
		ULONG SocketMode = 1U;
	#elif defined(PLATFORM_LINUX)
		int Flags = 0;
	#endif
		auto IsAlternate = AlternateSwapList.IsSwap[1U];

	//Main
		if (!IsAlternate)
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.IPv4.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
		#if defined(PLATFORM_WIN)
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				closesocket(UDPSocketData->Socket);

				return EXIT_FAILURE;
			}
		#elif defined(PLATFORM_LINUX)
			Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
			fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
		#endif

			UDPSocketData->AddrLen = sizeof(sockaddr_in);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && (IsAlternate || Parameter.AlternateMultiRequest))
		{
			UDPSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage;
			UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		//Socket check
			if (UDPSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}
		//Set Non-blocking Mode
		#if defined(PLATFORM_WIN)
			else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
				for (auto SocketDataIter:UDPSocketDataList)
					closesocket(SocketDataIter.Socket);

				return EXIT_FAILURE;
			}
		#elif defined(PLATFORM_LINUX)
			Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
			fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
		#endif

			UDPSocketData->AddrLen = sizeof(sockaddr_in);
			UDPSocketDataList.push_back(*UDPSocketData);
			memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Other servers
		if (Parameter.DNSTarget.IPv4_Multi != nullptr && !IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				UDPSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
				UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			//Socket check
				if (UDPSocketData->Socket == INVALID_SOCKET)
				{
					PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode
			#if defined(PLATFORM_WIN)
				else if (ioctlsocket(UDPSocketData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					for (auto SocketDataIter:UDPSocketDataList)
						closesocket(SocketDataIter.Socket);

					return EXIT_FAILURE;
				}
			#elif defined(PLATFORM_LINUX)
				Flags = fcntl(UDPSocketData->Socket, F_GETFL, 0);
				fcntl(UDPSocketData->Socket, F_SETFL, Flags|O_NONBLOCK);
			#endif

				UDPSocketData->AddrLen = sizeof(sockaddr_in);
				UDPSocketDataList.push_back(*UDPSocketData);
				memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}
	}
	else {
		return EXIT_FAILURE;
	}

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	timeval Timeout = {0};
#if defined(PLATFORM_LINUX)
	SOCKET MaxSocket = 0;
#endif
	FD_ZERO(WriteFDS.get());
	for (auto SocketDataIter:UDPSocketDataList)
	{
	#if defined(PLATFORM_LINUX)
		if (SocketDataIter.Socket > MaxSocket)
			MaxSocket = SocketDataIter.Socket;
	#endif
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0, RecvLen = 0;
	size_t Index = 0;
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
	#if defined(PLATFORM_WIN)
		Timeout.tv_sec = Parameter.UnreliableSocketTimeout / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.UnreliableSocketTimeout % SECOND_TO_MILLISECOND * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif defined(PLATFORM_LINUX)
		Timeout.tv_sec = Parameter.UnreliableSocketTimeout.tv_sec;
		Timeout.tv_usec = Parameter.UnreliableSocketTimeout.tv_usec;
	#endif
		FD_ZERO(ReadFDS.get());
		for (auto SocketDataIter:UDPSocketDataList)
		{
			if (SocketDataIter.Socket > 0)
			{
				FD_SET(SocketDataIter.Socket, ReadFDS.get());
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
	#elif defined(PLATFORM_LINUX)
		SelectResult = select(MaxSocket + 1U, ReadFDS.get(), WriteFDS.get(), nullptr, &Timeout);
	#endif
		
		if (SelectResult > 0)
		{
		//Receive.
			for (Index = 0;Index < UDPSocketDataList.size();++Index)
			{
				if (FD_ISSET(UDPSocketDataList[Index].Socket, ReadFDS.get()))
				{
					RecvLen = recvfrom(UDPSocketDataList[Index].Socket, OriginalRecv, (int)RecvSize, 0, (PSOCKADDR)&UDPSocketDataList[Index].SockAddr, &UDPSocketDataList[Index].AddrLen);
					if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
					{
						memset(OriginalRecv, 0, RecvSize);
						shutdown(UDPSocketDataList[Index].Socket, SD_BOTH);
						closesocket(UDPSocketDataList[Index].Socket);
						UDPSocketDataList[Index].Socket = 0;

						continue;
					}
					else {
					//Hosts Only Extended check
						if ((Parameter.DNSDataCheck || Parameter.Blacklist) && !CheckResponseData(OriginalRecv, RecvLen, false, nullptr))
						{
							memset(OriginalRecv, 0, RecvSize);
							shutdown(UDPSocketDataList[Index].Socket, SD_BOTH);
							closesocket(UDPSocketDataList[Index].Socket);
							UDPSocketDataList[Index].Socket = 0;

							continue;
						}

					//Mark DNS Cache.
						if (Parameter.CacheType > 0)
							MarkDomainCache(OriginalRecv, RecvLen);

						for (auto SocketDataIter:UDPSocketDataList)
						{
							if (SocketDataIter.Socket > 0)
							{
								shutdown(SocketDataIter.Socket, SD_BOTH);
								closesocket(SocketDataIter.Socket);
							}
						}

						return RecvLen;
					}
				}
			}

		//Send.
			for (auto SocketDataIter:UDPSocketDataList)
			{
				if (FD_ISSET(SocketDataIter.Socket, WriteFDS.get()))
				{
					for (size_t InnerIndex = 0;InnerIndex < Parameter.MultiRequestTimes;++InnerIndex)
						sendto(SocketDataIter.Socket, OriginalSend, (int)SendSize, 0, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen);
				}
			}

			FD_ZERO(WriteFDS.get());
		}
	//Timeout
		else if (SelectResult == 0)
		{
			memset(OriginalRecv, 0, RecvSize);
			++AlternateSwapList.TimeoutTimes[0];
			++AlternateSwapList.TimeoutTimes[1U];

		//Check global sockets.
			for (auto SocketDataIter:UDPSocketDataList)
			{
				if (SocketDataIter.Socket > 0)
				{
					shutdown(SocketDataIter.Socket, SD_BOTH);
					closesocket(SocketDataIter.Socket);
				}
			}

			return WSAETIMEDOUT;
		}
	//SOCKET_ERROR
		else {
			break;
		}
	}

//Check global sockets.
	for (auto SocketDataIter:UDPSocketDataList)
	{
		if (SocketDataIter.Socket > 0)
		{
			shutdown(SocketDataIter.Socket, SD_BOTH);
			closesocket(SocketDataIter.Socket);
		}
	}

	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}
