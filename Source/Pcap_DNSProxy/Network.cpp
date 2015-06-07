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


#include "Network.h"

#if defined(ENABLE_PCAP)
//Get TTL(IPv4)/Hop Limits(IPv6) with normal DNS request
bool __fastcall DomainTestRequest(const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> Buffer(new char[PACKET_MAXSIZE]()), DNSQuery(new char[PACKET_MAXSIZE]());
	memset(Buffer.get(), 0, PACKET_MAXSIZE);
	memset(DNSQuery.get(), 0, PACKET_MAXSIZE);

//Make a DNS request with Doamin Test packet.
	auto DNS_Header = (pdns_hdr)Buffer.get();
	DNS_Header->ID = Parameter.DomainTest_ID;
	DNS_Header->Flags = htons(DNS_STANDARD);
	DNS_Header->Questions = htons(U16_NUM_ONE);
	size_t DataLength = 0;

//Convert domain.
	pdns_qry DNS_Query = nullptr;
	if (Parameter.DomainTest_Data != nullptr)
	{
		DataLength = CharToDNSQuery(Parameter.DomainTest_Data, DNSQuery.get());
		if (DataLength > DOMAIN_MINSIZE && DataLength < PACKET_MAXSIZE - sizeof(dns_hdr))
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

		//EDNS Label
			if (Parameter.EDNS_Label) //Not any Additional Resource Records
			{
				auto DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + sizeof(dns_hdr) + DataLength);
				DNS_Header->Additional = htons(U16_NUM_ONE);
				DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
				DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNSPayloadSize);
				DataLength += sizeof(dns_record_opt);
			}
		}
		else {
			return false;
		}
	}

	DataLength += sizeof(dns_hdr);

//Send requesting.
	size_t Times = 0;
	for (;;)
	{
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			if (Protocol == AF_INET6) //IPv6
			{
				if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0 || //Main
					Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0) //Alternate
						goto ReTest;

			//Other(Multi)
				if (Parameter.DNSTarget.IPv6_Multi != nullptr)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
							goto ReTest;
					}
				}
			}
			else { //IPv4
				if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0 || //Main
					Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0) //Alternate
						goto ReTest;

			//Other(Multi)
				if (Parameter.DNSTarget.IPv4_Multi != nullptr)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
							goto ReTest;
					}
				}
			}

		//Test again.
			Sleep(Parameter.DomainTest_Speed);
			continue;

		ReTest:
			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			continue;
		}
		else {
		//Make ramdom domain request.
			if (Parameter.DomainTest_Data == nullptr)
			{
				memset(Buffer.get() + sizeof(dns_hdr), 0, PACKET_MAXSIZE - sizeof(dns_hdr));
				MakeRamdomDomain(DNSQuery.get());
				DataLength = CharToDNSQuery(DNSQuery.get(), Buffer.get() + sizeof(dns_hdr)) + sizeof(dns_hdr);
				memset(DNSQuery.get(), 0, DOMAIN_MAXSIZE);

				DNS_Query = (pdns_qry)(Buffer.get() + DataLength);
				DNS_Query->Classes = htons(DNS_CLASS_IN);
				if (Protocol == AF_INET6) //IPv6
					DNS_Query->Type = htons(DNS_RECORD_AAAA);
				else //IPv4
					DNS_Query->Type = htons(DNS_RECORD_A);
				DataLength += sizeof(dns_qry);

			//EDNS Label
				if (Parameter.EDNS_Label) //Not any Additional Resource Records
				{
					auto DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + DataLength);
					DNS_Header->Additional = htons(U16_NUM_ONE);
					DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
					DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNSPayloadSize);
					DataLength += sizeof(dns_record_opt);
				}
			}

		//Send and repeat.
			UDPRequestMulti(Buffer.get(), (int)DataLength, nullptr, 0);
			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			++Times;
		}
	}

	PrintError(LOG_ERROR_SYSTEM, L"Domain Test module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Internet Control Message Protocol(version 6)/ICMP(v6) Echo(Ping) request
bool __fastcall ICMPEcho(const uint16_t Protocol)
{
//Initialization
	size_t Length = 0;

//Socket initialization
	SYSTEM_SOCKET ICMPSocket = 0;
	if (Protocol == AF_INET6) //IPv6
	{
		ICMPSocket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		if (ICMPSocket == INVALID_SOCKET)
		{
			PrintError(LOG_ERROR_NETWORK, L"ICMPv6 Echo(Ping) request error", WSAGetLastError(), nullptr, 0);
			return false;
		}

		Length = sizeof(icmpv6_hdr) + Parameter.ICMP_PaddingLength - 1U;
	}
	else { //IPv4
		ICMPSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (ICMPSocket == INVALID_SOCKET)
		{
			PrintError(LOG_ERROR_NETWORK, L"ICMP Echo(Ping) request error", WSAGetLastError(), nullptr, 0);
			return false;
		}

		Length = sizeof(icmp_hdr) + Parameter.ICMP_PaddingLength - 1U;
	}

//Initialization
	std::shared_ptr<char> Buffer(new char[Length]());
	memset(Buffer.get(), 0, Length);
	std::vector<sockaddr_storage> SockAddr;
	auto ICMP_Header = (picmp_hdr)Buffer.get();
	auto ICMPv6_Header = (picmpv6_hdr)Buffer.get();
	socklen_t AddrLen = 0;
	std::uniform_int_distribution<uint32_t> RamdomDistribution(0, UINT32_MAX);

//ICMPv6
	if (Protocol == AF_INET6)
	{
	//Make a ICMPv6 requesting echo packet.
		ICMPv6_Header->Type = ICMPV6_TYPE_REQUEST;
		ICMPv6_Header->Code = ICMPV6_CODE_REQUEST;
		ICMPv6_Header->ID = Parameter.ICMP_ID;
		ICMPv6_Header->Sequence = Parameter.ICMP_Sequence;
		memcpy_s(Buffer.get() + sizeof(icmpv6_hdr), Parameter.ICMP_PaddingLength - 1U, Parameter.ICMP_PaddingData, Parameter.ICMP_PaddingLength - 1U);
	#if defined(PLATFORM_LINUX)
		ICMPv6_Header->Timestamp = (uint64_t)time(nullptr);
		ICMPv6_Header->Nonce = RamdomDistribution(*Parameter.RamdomEngine);
	#elif defined(PLATFORM_MACX)
		ICMPv6_Header->Timestamp = (uint64_t)time(nullptr);
	#endif

	//Target
		std::shared_ptr<sockaddr_storage> SockAddrTemp(new sockaddr_storage());
		memset(SockAddrTemp.get(), 0, sizeof(sockaddr_storage));
		AddrLen = sizeof(sockaddr_in6);
		
	//Main and Alternate
		SockAddrTemp->ss_family = AF_INET6;
		((PSOCKADDR_IN6)SockAddrTemp.get())->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
		SockAddr.push_back(*SockAddrTemp);
		memset(SockAddrTemp.get(), 0, sizeof(sockaddr_storage));
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
			SockAddrTemp->ss_family = AF_INET6;
			((PSOCKADDR_IN6)SockAddrTemp.get())->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
			SockAddr.push_back(*SockAddrTemp);
			memset(SockAddrTemp.get(), 0, sizeof(sockaddr_storage));
		}

	//Other(Multi)
		if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				SockAddrTemp->ss_family = AF_INET6;
				((PSOCKADDR_IN6)SockAddrTemp.get())->sin6_addr = DNSServerDataIter.AddressData.IPv6.sin6_addr;
				SockAddr.push_back(*SockAddrTemp);
				memset(SockAddrTemp.get(), 0, sizeof(sockaddr_storage));
			}
		}
	}
//ICMP
	else {
	//Make a ICMP requesting echo packet.
		ICMP_Header->Type = ICMP_TYPE_REQUEST;
		ICMP_Header->Code = ICMP_CODE_REQUEST;
		ICMP_Header->ID = Parameter.ICMP_ID;
		ICMP_Header->Sequence = Parameter.ICMP_Sequence;
		memcpy_s(Buffer.get() + sizeof(icmp_hdr), Parameter.ICMP_PaddingLength - 1U, Parameter.ICMP_PaddingData, Parameter.ICMP_PaddingLength - 1U);
	#if defined(PLATFORM_LINUX)
		ICMP_Header->Timestamp = (uint64_t)time(nullptr);
		ICMP_Header->Nonce = RamdomDistribution(*Parameter.RamdomEngine);
	#elif defined(PLATFORM_MACX)
		ICMP_Header->Timestamp = (uint64_t)time(nullptr);
	#endif
		ICMP_Header->Checksum = GetChecksum((PUINT16)Buffer.get(), Length);

	//Target
		std::shared_ptr<sockaddr_storage> SockAddrTemp(new sockaddr_storage());
		memset(SockAddrTemp.get(), 0, sizeof(sockaddr_storage));
		AddrLen = sizeof(sockaddr_in);

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
	}

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(ICMPSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(int)) == SOCKET_ERROR)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (setsockopt(ICMPSocket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		if (Protocol == AF_INET6) //IPv6
			PrintError(LOG_ERROR_NETWORK, L"Set ICMPv6 socket timeout error", WSAGetLastError(), nullptr, 0);
		else //IPv4
			PrintError(LOG_ERROR_NETWORK, L"Set ICMP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(ICMPSocket);

		return false;
	}

//Send requesting.
	size_t Times = 0;
	for (;;)
	{
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			if (Protocol == AF_INET6) //IPv6
			{
				if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0 || //Main
					Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0) //Alternate
					goto ReTest;

				if (Parameter.DNSTarget.IPv6_Multi != nullptr) //Other(Multi)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
					{
						if (DNSServerDataIter.HopLimitData.HopLimit == 0)
							goto ReTest;
					}
				}
			}
			else { //IPv4
				if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0 || //Main
					Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0) //Alternate
					goto ReTest;

				if (Parameter.DNSTarget.IPv4_Multi != nullptr) //Other(Multi)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
							goto ReTest;
					}
				}
			}

			Sleep(Parameter.ICMP_Speed);
			continue;

		ReTest: 
			Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
			continue;
		}

	//Send.
		for (auto HostsTableIter:SockAddr)
		{
			sendto(ICMPSocket, Buffer.get(), (int)Length, 0, (PSOCKADDR)&HostsTableIter, AddrLen);

		//Increase Sequence.
			if (Parameter.ICMP_Sequence == htons(DEFAULT_SEQUENCE))
			{
				if (Protocol == AF_INET6) //IPv6
				{
					if (ICMPv6_Header->Sequence == UINT16_MAX)
						ICMPv6_Header->Sequence = htons(DEFAULT_SEQUENCE);
					else
						ICMPv6_Header->Sequence = htons(ntohs(ICMPv6_Header->Sequence) + 1U);

					//Get UTC time.
				#if defined(PLATFORM_LINUX)
					ICMPv6_Header->Timestamp = (uint64_t)time(nullptr);
					ICMPv6_Header->Nonce = RamdomDistribution(*Parameter.RamdomEngine);
				#elif defined(PLATFORM_MACX)
					ICMPv6_Header->Timestamp = (uint64_t)time(nullptr);
				#endif
				}
				else { //IPv4
					if (ICMP_Header->Sequence == UINT16_MAX)
						ICMP_Header->Sequence = htons(DEFAULT_SEQUENCE);
					else
						ICMP_Header->Sequence = htons(ntohs(ICMP_Header->Sequence) + 1U);

					//Get UTC time.
				#if defined(PLATFORM_LINUX)
					ICMP_Header->Timestamp = (uint64_t)time(nullptr);
					ICMP_Header->Nonce = RamdomDistribution(*Parameter.RamdomEngine);
				#elif defined(PLATFORM_MACX)
					ICMP_Header->Timestamp = (uint64_t)time(nullptr);
				#endif

					ICMP_Header->Checksum = 0;
					ICMP_Header->Checksum = GetChecksum((PUINT16)Buffer.get(), Length);
				}
			}
		}

	//Repeat.
		Sleep(SENDING_INTERVAL_TIME * SECOND_TO_MILLISECOND);
		++Times;
	}

	shutdown(ICMPSocket, SD_BOTH);
	closesocket(ICMPSocket);
	PrintError(LOG_ERROR_SYSTEM, L"ICMP Test module Monitor terminated", 0, nullptr, 0);
	return true;
}
#endif

//Select socket data of DNS target(Independent)
bool __fastcall SelectTargetSocket(SOCKET_DATA *SockData, bool *&IsAlternate, size_t *&AlternateTimeoutTimes, const uint16_t Protocol, const bool IsLocal)
{
//Socket initialization
	uint16_t SocketType = 0;
	if (Protocol == IPPROTO_TCP) //TCP
		SocketType = SOCK_STREAM;
	else //UDP
		SocketType = SOCK_DGRAM;

//Local requesting
	if (IsLocal)
	{
	//IPv6
		if (Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && Parameter.GatewayAvailable_IPv6 || //Auto select
			Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
			Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == 0)) //Non-IPv4
		{
		//TCP
			if (Protocol == IPPROTO_TCP)
			{
				IsAlternate = &AlternateSwapList.IsSwap[4U];
				AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[4U];
			}
		//UDP
			else {
				IsAlternate = &AlternateSwapList.IsSwap[6U];
				AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[6U];
			}
		
		//Alternate
			if (IsAlternate != nullptr && *IsAlternate && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN6)&SockData->SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockData->SockAddr)->sin6_port = Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_port;
			}
		//Main
			else {
				((PSOCKADDR_IN6)&SockData->SockAddr)->sin6_addr = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockData->SockAddr)->sin6_port = Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_port;
			}

			SockData->SockAddr.ss_family = AF_INET6;
			SockData->Socket = socket(AF_INET6, SocketType, Protocol);
			SockData->AddrLen = sizeof(sockaddr_in6);
		}
	//IPv4
		else if (Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && Parameter.GatewayAvailable_IPv4 || //Auto select
			Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
			Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family == 0)) //Non-IPv6
		{
		//TCP
			if (Protocol == IPPROTO_TCP)
			{
				IsAlternate = &AlternateSwapList.IsSwap[5U];
				AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[5U];
			}
		//UDP
			else {
				IsAlternate = &AlternateSwapList.IsSwap[7U];
				AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[7U];
			}

		//Alternate
			if (IsAlternate != nullptr && *IsAlternate && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN)&SockData->SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockData->SockAddr)->sin_port = Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_port;
			}
		//Main
			else {
				((PSOCKADDR_IN)&SockData->SockAddr)->sin_addr = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockData->SockAddr)->sin_port = Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_port;
			}

			SockData->SockAddr.ss_family = AF_INET;
			SockData->Socket = socket(AF_INET, SocketType, Protocol);
			SockData->AddrLen = sizeof(sockaddr_in);
		}
		else {
			return false;
		}
	}
//Main requesting
	else {
	//IPv6
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && Parameter.GatewayAvailable_IPv6 || //Auto select
			Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
			Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0)) //Non-IPv4
		{
		//TCP
			if (Protocol == IPPROTO_TCP)
			{
				IsAlternate = &AlternateSwapList.IsSwap[0];
				AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[0];
			}
		//UDP
			else {
				IsAlternate = &AlternateSwapList.IsSwap[2U];
				AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[2U];
			}
		
		//Alternate
			if (*IsAlternate && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN6)&SockData->SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockData->SockAddr)->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
		//Main
			else {
				((PSOCKADDR_IN6)&SockData->SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&SockData->SockAddr)->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
			}

			SockData->SockAddr.ss_family = AF_INET6;
			SockData->Socket = socket(AF_INET6, SocketType, Protocol);
			SockData->AddrLen = sizeof(sockaddr_in6);
		}
	//IPv4
		else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && Parameter.GatewayAvailable_IPv4 || //Auto select
			Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
			Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0)) //Non-IPv6
		{
		//TCP
			if (Protocol == IPPROTO_TCP)
			{
				IsAlternate = &AlternateSwapList.IsSwap[1U];
				AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[1U];
			}
		//UDP
			else {
				IsAlternate = &AlternateSwapList.IsSwap[3U];
				AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[3U];
			}
			

		//Alternate
			if (*IsAlternate && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN)&SockData->SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockData->SockAddr)->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
		//Main
			else {
				((PSOCKADDR_IN)&SockData->SockAddr)->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&SockData->SockAddr)->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}

			SockData->SockAddr.ss_family = AF_INET;
			SockData->Socket = socket(AF_INET, SocketType, Protocol);
			SockData->AddrLen = sizeof(sockaddr_in);
		}
		else {
			return false;
		}
	}

	return true;
}

//Select socket data of DNS target(Multithreading)
bool __fastcall SelectTargetSocketMulti(std::vector<SOCKET_DATA> &SockDataList, const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<SOCKET_DATA> SockData(new SOCKET_DATA());
	memset(SockData.get(), 0, sizeof(SOCKET_DATA));
	uint16_t SocketType = 0;
	bool *IsAlternate = nullptr;
#if defined(PLATFORM_WIN)
	ULONG SocketMode = 1U;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	int Flags = 0;
#endif
	if (Protocol == IPPROTO_TCP) //TCP
		SocketType = SOCK_STREAM;
	else //UDP
		SocketType = SOCK_DGRAM;

//IPv6
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && 
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && Parameter.GatewayAvailable_IPv6 || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
		Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0)) //Non-IPv4
	{
	//Set Alternate swap list.
		if (Protocol == IPPROTO_TCP) //TCP
			IsAlternate = &AlternateSwapList.IsSwap[0];
		else //UDP
			IsAlternate = &AlternateSwapList.IsSwap[2U];

	//Main
		if (!*IsAlternate)
		{
			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				SockData->SockAddr = Parameter.DNSTarget.IPv6.AddressData.Storage;
				SockData->Socket = socket(AF_INET6, SocketType, Protocol);
			//Socket check
				if (SockData->Socket == INVALID_SOCKET)
				{
					if (Protocol == IPPROTO_TCP) //TCP
						PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
					else //UDP
						PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);

					return false;
				}
			//Set Non-blocking Mode.
			#if defined(PLATFORM_WIN)
				else if (ioctlsocket(SockData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					if (Protocol == IPPROTO_TCP) //TCP
						PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					else //UDP
						PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);

					closesocket(SockData->Socket);
					return false;
				}
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				Flags = fcntl(SockData->Socket, F_GETFL, 0);
				fcntl(SockData->Socket, F_SETFL, Flags|O_NONBLOCK);
			#endif

				SockData->AddrLen = sizeof(sockaddr_in6);
				SockDataList.push_back(*SockData);
				memset(SockData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && (*IsAlternate || Parameter.AlternateMultiRequest))
		{
			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				SockData->SockAddr = Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage;
				SockData->Socket = socket(AF_INET6, SocketType, Protocol);
			//Socket check
				if (SockData->Socket == INVALID_SOCKET)
				{
					if (Protocol == IPPROTO_TCP) //TCP
						PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
					else //UDP
						PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);

					for (auto &SocketDataIter:SockDataList)
						closesocket(SocketDataIter.Socket);
					return false;
				}
			//Set Non-blocking Mode.
			#if defined(PLATFORM_WIN)
				else if (ioctlsocket(SockData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					if (Protocol == IPPROTO_TCP) //TCP
						PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					else //UDP
						PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);

					for (auto &SocketDataIter:SockDataList)
						closesocket(SocketDataIter.Socket);
					return false;
				}
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				Flags = fcntl(SockData->Socket, F_GETFL, 0);
				fcntl(SockData->Socket, F_SETFL, Flags|O_NONBLOCK);
			#endif

				SockData->AddrLen = sizeof(sockaddr_in6);
				SockDataList.push_back(*SockData);
				memset(SockData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Other servers
		if (Parameter.DNSTarget.IPv6_Multi != nullptr && !*IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
				{
					SockData->SockAddr = DNSServerDataIter.AddressData.Storage;
					SockData->Socket = socket(AF_INET6, SocketType, Protocol);
				//Socket check
					if (SockData->Socket == INVALID_SOCKET)
					{
						if (Protocol == IPPROTO_TCP) //TCP
							PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
						else //UDP
							PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);

						for (auto &SocketDataIter:SockDataList)
							closesocket(SocketDataIter.Socket);
						return false;
					}
				//Set Non-blocking Mode.
				#if defined(PLATFORM_WIN)
					else if (ioctlsocket(SockData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
					{
						if (Protocol == IPPROTO_TCP) //TCP
							PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
						else //UDP
							PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);

						for (auto &SocketDataIter:SockDataList)
							closesocket(SocketDataIter.Socket);
						return false;
					}
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					Flags = fcntl(SockData->Socket, F_GETFL, 0);
					fcntl(SockData->Socket, F_SETFL, Flags|O_NONBLOCK);
				#endif

					SockData->AddrLen = sizeof(sockaddr_in6);
					SockDataList.push_back(*SockData);
					memset(SockData.get(), 0, sizeof(SOCKET_DATA));
				}
			}
		}
	}
//IPv4
	else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 &&
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && Parameter.GatewayAvailable_IPv4 || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
		Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0)) //Non-IPv6
	{
	//Set Alternate swap list.
		if (Protocol == IPPROTO_TCP) //TCP
			IsAlternate = &AlternateSwapList.IsSwap[1U];
		else //UDP
			IsAlternate = &AlternateSwapList.IsSwap[3U];

	//Main
		if (!*IsAlternate)
		{
			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				SockData->SockAddr = Parameter.DNSTarget.IPv4.AddressData.Storage;
				SockData->Socket = socket(AF_INET, SocketType, Protocol);
			//Socket check
				if (SockData->Socket == INVALID_SOCKET)
				{
					if (Protocol == IPPROTO_TCP) //TCP
						PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
					else //UDP
						PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);

					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode.
			#if defined(PLATFORM_WIN)
				else if (ioctlsocket(SockData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					if (Protocol == IPPROTO_TCP) //TCP
						PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					else //UDP
						PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);

					closesocket(SockData->Socket);
					return EXIT_FAILURE;
				}
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				Flags = fcntl(SockData->Socket, F_GETFL, 0);
				fcntl(SockData->Socket, F_SETFL, Flags|O_NONBLOCK);
			#endif

				SockData->AddrLen = sizeof(sockaddr_in);
				SockDataList.push_back(*SockData);
				memset(SockData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && (*IsAlternate || Parameter.AlternateMultiRequest))
		{
			for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				SockData->SockAddr = Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage;
				SockData->Socket = socket(AF_INET, SocketType, Protocol);
			//Socket check
				if (SockData->Socket == INVALID_SOCKET)
				{
					if (Protocol == IPPROTO_TCP) //TCP
						PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
					else //UDP
						PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);

					for (auto &SocketDataIter:SockDataList)
						closesocket(SocketDataIter.Socket);
					return EXIT_FAILURE;
				}
			//Set Non-blocking Mode.
			#if defined(PLATFORM_WIN)
				else if (ioctlsocket(SockData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
				{
					if (Protocol == IPPROTO_TCP) //TCP
						PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
					else //UDP
						PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);

					for (auto &SocketDataIter:SockDataList)
						closesocket(SocketDataIter.Socket);
					return EXIT_FAILURE;
				}
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				Flags = fcntl(SockData->Socket, F_GETFL, 0);
				fcntl(SockData->Socket, F_SETFL, Flags|O_NONBLOCK);
			#endif

				SockData->AddrLen = sizeof(sockaddr_in);
				SockDataList.push_back(*SockData);
				memset(SockData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Other servers
		if (Parameter.DNSTarget.IPv4_Multi != nullptr && !*IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				for (size_t Index = 0;Index < Parameter.MultiRequestTimes;++Index)
				{
					SockData->SockAddr = DNSServerDataIter.AddressData.Storage;
					SockData->Socket = socket(AF_INET, SocketType, Protocol);
				//Socket check
					if (SockData->Socket == INVALID_SOCKET)
					{
						if (Protocol == IPPROTO_TCP) //TCP
							PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
						else //UDP
							PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);

						for (auto &SocketDataIter:SockDataList)
							closesocket(SocketDataIter.Socket);

						return EXIT_FAILURE;
					}
				//Set Non-blocking Mode.
				#if defined(PLATFORM_WIN)
					else if (ioctlsocket(SockData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
					{
						if (Protocol == IPPROTO_TCP) //TCP
							PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
						else //UDP
							PrintError(LOG_ERROR_NETWORK, L"Set UDP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);

						for (auto &SocketDataIter:SockDataList)
							closesocket(SocketDataIter.Socket);
						return EXIT_FAILURE;
					}
				#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
					Flags = fcntl(SockData->Socket, F_GETFL, 0);
					fcntl(SockData->Socket, F_SETFL, Flags|O_NONBLOCK);
				#endif

					SockData->AddrLen = sizeof(sockaddr_in);
					SockDataList.push_back(*SockData);
					memset(SockData.get(), 0, sizeof(SOCKET_DATA));
				}
			}
		}
	}
	else {
		return false;
	}

	return true;
}

//Transmission and reception of TCP protocol(Independent)
size_t __fastcall TCPRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const bool IsLocal)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[sizeof(uint16_t) + SendSize]());
	memset(SendBuffer.get(), 0, sizeof(uint16_t) + SendSize);
	std::shared_ptr<SOCKET_DATA> TCPSockData(new SOCKET_DATA());
	memset(TCPSockData.get(), 0, sizeof(SOCKET_DATA));
	memcpy_s(SendBuffer.get(), SendSize, OriginalSend, SendSize);

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	size_t DataLength = AddLengthDataToDNSHeader(SendBuffer.get(), SendSize, sizeof(uint16_t) + SendSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	if (!SelectTargetSocket(TCPSockData.get(), IsAlternate, AlternateTimeoutTimes, IPPROTO_TCP, IsLocal) || TCPSockData->Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"TCP request initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSockData->Socket);

		return EXIT_FAILURE;
	}

/* TCP KeepAlive Mode
	BOOL bKeepAlive = TRUE;
	if (setsockopt(TCPSockData->Socket, SOL_SOCKET, SO_KEEPALIVE, (const char *)&bKeepAlive, sizeof(bKeepAlive)) == SOCKET_ERROR)
	{
		closesocket(TCPSockData->Socket);
		return EXIT_FAILURE;
	}

	tcp_keepalive alive_in = {0};
	tcp_keepalive alive_out = {0};
	alive_in.keepalivetime = STANDARD_TIMEOUT;
	alive_in.keepaliveinterval = Parameter.SocketTimeout_Reliable;
	alive_in.onoff = TRUE;
	ULONG ulBytesReturn = 0;
	if (WSAIoctl(TCPSockData->Socket, SIO_KEEPALIVE_VALS, &alive_in, sizeof(alive_in), &alive_out, sizeof(alive_out), &ulBytesReturn, nullptr, nullptr) == SOCKET_ERROR)
	{
		closesocket(TCPSockData->Socket);
		return EXIT_FAILURE;
	}
*/

//Set Non-blocking Mode.
#if defined(PLATFORM_WIN)
	ULONG SocketMode = 1U;
	if (ioctlsocket(TCPSockData->Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set TCP socket non-blocking mode error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSockData->Socket);

		return EXIT_FAILURE;
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	int Flags = fcntl(TCPSockData->Socket, F_GETFL, 0);
	fcntl(TCPSockData->Socket, F_SETFL, Flags|O_NONBLOCK);
#endif

//Connect to server.
	if (connect(TCPSockData->Socket, (PSOCKADDR)&TCPSockData->SockAddr, TCPSockData->AddrLen) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)
	{
		if (IsAlternate != nullptr && !*IsAlternate && WSAGetLastError() == WSAETIMEDOUT)
		{
			closesocket(TCPSockData->Socket);
			if (AlternateTimeoutTimes != nullptr)
				++(*AlternateTimeoutTimes);

			return WSAETIMEDOUT;
		}
		else {
			closesocket(TCPSockData->Socket);
			return EXIT_FAILURE;
		}
	}

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));
	FD_ZERO(WriteFDS.get());
	FD_SET(TCPSockData->Socket, WriteFDS.get());
	SSIZE_T SelectResult = 0, RecvLen = 0;
	uint16_t PDULen = 0;
	for (size_t LoopLimits = 0;LoopLimits < LOOP_MAX_TIMES;++LoopLimits)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
	#if defined(PLATFORM_WIN)
		Timeout->tv_sec = Parameter.SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
		Timeout->tv_usec = Parameter.SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Timeout->tv_sec = Parameter.SocketTimeout_Reliable.tv_sec;
		Timeout->tv_usec = Parameter.SocketTimeout_Reliable.tv_usec;
	#endif
		FD_ZERO(ReadFDS.get());
		FD_SET(TCPSockData->Socket, ReadFDS.get());

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(TCPSockData->Socket + 1U, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#endif
		if (SelectResult > 0)
		{
		//Receive.
			if (FD_ISSET(TCPSockData->Socket, ReadFDS.get()))
			{
				RecvLen = recv(TCPSockData->Socket, OriginalRecv, (int)RecvSize, 0);

			//TCP segment of a reassembled PDU
				if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
				{
					if (RecvLen > 0 && htons(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE && htons(((uint16_t *)OriginalRecv)[0]) < RecvSize)
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
						shutdown(TCPSockData->Socket, SD_BOTH);
						closesocket(TCPSockData->Socket);

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
							shutdown(TCPSockData->Socket, SD_BOTH);
							closesocket(TCPSockData->Socket);

							RecvLen = ntohs(((uint16_t *)OriginalRecv)[0]);
							if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && RecvLen < (SSIZE_T)RecvSize)
							{
								memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(uint16_t), RecvLen);

							//Jump here when TCP segment of a reassembled PDU.
								JumpFromPDU: 

							//Responses question and answers check
								if ((Parameter.DNSDataCheck || Parameter.BlacklistCheck) && CheckResponseData(OriginalRecv, RecvLen, IsLocal) == EXIT_FAILURE)
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
			if (FD_ISSET(TCPSockData->Socket, WriteFDS.get()))
			{
				send(TCPSockData->Socket, SendBuffer.get(), (int)DataLength, 0);
				FD_ZERO(WriteFDS.get());
			}
		}
	//Timeout
		else if (SelectResult == 0)
		{
			shutdown(TCPSockData->Socket, SD_BOTH);
			closesocket(TCPSockData->Socket);
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

	shutdown(TCPSockData->Socket, SD_BOTH);
	closesocket(TCPSockData->Socket);
	memset(OriginalRecv, 0, RecvSize);
	return EXIT_FAILURE;
}

//Transmission and reception of TCP protocol(Multithreading)
size_t __fastcall TCPRequestMulti(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[sizeof(uint16_t) + SendSize]());
	memset(SendBuffer.get(), 0, sizeof(uint16_t) + SendSize);
	memcpy_s(SendBuffer.get(), SendSize, OriginalSend, SendSize);

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	size_t DataLength = AddLengthDataToDNSHeader(SendBuffer.get(), SendSize, sizeof(uint16_t) + SendSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket initialization
	std::vector<SOCKET_DATA> TCPSocketDataList;
	if (!SelectTargetSocketMulti(TCPSocketDataList, IPPROTO_TCP))
		return EXIT_FAILURE;

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
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	SOCKET MaxSocket = 0;
#endif
	FD_ZERO(WriteFDS.get());
	for (auto &SocketDataIter:TCPSocketDataList)
	{
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (SocketDataIter.Socket > MaxSocket)
			MaxSocket = SocketDataIter.Socket;
	#endif
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0, RecvLen = 0;
	std::vector<uint16_t> PDULenList(TCPSocketDataList.size(), 0);
	for (size_t LoopLimits = 0;LoopLimits < LOOP_MAX_TIMES;++LoopLimits)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
	#if defined(PLATFORM_WIN)
		Timeout->tv_sec = Parameter.SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
		Timeout->tv_usec = Parameter.SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Timeout->tv_sec = Parameter.SocketTimeout_Reliable.tv_sec;
		Timeout->tv_usec = Parameter.SocketTimeout_Reliable.tv_usec;
	#endif
		FD_ZERO(ReadFDS.get());
		for (auto &SocketDataIter:TCPSocketDataList)
		{
			if (SocketDataIter.Socket > 0)
			{
				FD_SET(SocketDataIter.Socket, ReadFDS.get());
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(MaxSocket + 1U, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#endif
		if (SelectResult > 0)
		{
		//Receive.
			for (size_t Index = 0;Index < TCPSocketDataList.size();++Index)
			{
				if (FD_ISSET(TCPSocketDataList.at(Index).Socket, ReadFDS.get()))
				{
					RecvLen = recv(TCPSocketDataList.at(Index).Socket, OriginalRecv, (int)RecvSize, 0);

				//TCP segment of a reassembled PDU
					if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
					{
						if (RecvLen > 0 && htons(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE && htons(((uint16_t *)OriginalRecv)[0]) < RecvSize)
						{
							PDULenList[Index] = htons(((uint16_t *)OriginalRecv)[0]);
							memset(OriginalRecv, 0, RecvSize);
							continue;
						}
					//Invalid packet.
						else {
							shutdown(TCPSocketDataList.at(Index).Socket, SD_BOTH);
							closesocket(TCPSocketDataList.at(Index).Socket);
							TCPSocketDataList.at(Index).Socket = 0;
							break;
						}
					}
					else {
					//Length check.
						if ((SSIZE_T)PDULenList[Index] > RecvLen)
						{
							shutdown(TCPSocketDataList.at(Index).Socket, SD_BOTH);
							closesocket(TCPSocketDataList.at(Index).Socket);
							TCPSocketDataList.at(Index).Socket = 0;
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
								shutdown(TCPSocketDataList.at(Index).Socket, SD_BOTH);
								closesocket(TCPSocketDataList.at(Index).Socket);
								TCPSocketDataList.at(Index).Socket = 0;
								break;
							}
							else {
								RecvLen = ntohs(((uint16_t *)OriginalRecv)[0]);
								if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && RecvLen < (SSIZE_T)RecvSize)
								{
									memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(uint16_t), RecvLen);

								//Jump here when TCP segment of a reassembled PDU.
									JumpFromPDU: 

								//Responses question and answers check
									if ((Parameter.DNSDataCheck || Parameter.BlacklistCheck) && CheckResponseData(OriginalRecv, RecvLen, false) == EXIT_FAILURE)
									{
										memset(OriginalRecv, 0, RecvSize);
										continue;
									}

								//Close sockets and remove response length of TCP requesting.
									for (auto &SocketDataIter:TCPSocketDataList)
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
									shutdown(TCPSocketDataList.at(Index).Socket, SD_BOTH);
									closesocket(TCPSocketDataList.at(Index).Socket);
									TCPSocketDataList.at(Index).Socket = 0;
									break;
								}
							}
						}
					}
				}
			}

		//Send.
			for (auto &SocketDataIter:TCPSocketDataList)
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
			for (auto &SocketDataIter:TCPSocketDataList)
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
	for (auto &SocketDataIter:TCPSocketDataList)
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
#if defined(ENABLE_PCAP)
size_t __fastcall UDPRequest(const char *OriginalSend, const size_t Length, const SOCKET_DATA *LocalSocketData, const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<SOCKET_DATA> UDPSockData(new SOCKET_DATA());
	memset(UDPSockData.get(), 0, sizeof(SOCKET_DATA));
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;

//Socket initialization
	if (!SelectTargetSocket(UDPSockData.get(), IsAlternate, AlternateTimeoutTimes, IPPROTO_UDP, false) || UDPSockData->Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSockData->Socket);

		return EXIT_FAILURE;
	}

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(int)) == SOCKET_ERROR)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSockData->Socket);

		return EXIT_FAILURE;
	}

//Send requesting.
	if (sendto(UDPSockData->Socket, OriginalSend, (int)Length, 0, (PSOCKADDR)&UDPSockData->SockAddr, UDPSockData->AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"UDP request error", WSAGetLastError(), nullptr, 0);
		shutdown(UDPSockData->Socket, SD_BOTH);
		closesocket(UDPSockData->Socket);

		return EXIT_FAILURE;
	}

//Mark port to list.
	if (LocalSocketData != nullptr && Protocol > 0)
	{
		if (getsockname(UDPSockData->Socket, (PSOCKADDR)&UDPSockData->SockAddr, &UDPSockData->AddrLen) != 0)
		{
			shutdown(UDPSockData->Socket, SD_BOTH);
			closesocket(UDPSockData->Socket);
			return EXIT_FAILURE;
		}

		std::shared_ptr<OUTPUT_PACKET_TABLE> OutputPacketListTemp(new OUTPUT_PACKET_TABLE());
		memset(OutputPacketListTemp.get(), 0, sizeof(OUTPUT_PACKET_TABLE));

	//Mark system connection data.
		OutputPacketListTemp->SocketData_Input = *LocalSocketData;
		OutputPacketListTemp->SocketData_Output.push_back(*UDPSockData);
		OutputPacketListTemp->Protocol_Network = UDPSockData->SockAddr.ss_family;

	//Mark send time.
	//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
		OutputPacketListTemp->Protocol_Transport = Protocol;
		if (Protocol == IPPROTO_TCP) //TCP
		{
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (Parameter.GetTickCount64_PTR != nullptr)
				OutputPacketListTemp->ClearPortTime = (size_t)((*Parameter.GetTickCount64_PTR)() + Parameter.SocketTimeout_Reliable);
			else 
				OutputPacketListTemp->ClearPortTime = GetTickCount() + Parameter.SocketTimeout_Reliable;
		#elif defined(PLATFORM_WIN)
			OutputPacketListTemp->ClearPortTime = GetTickCount64() + Parameter.SocketTimeout_Reliable;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			OutputPacketListTemp->ClearPortTime = GetTickCount64() + Parameter.SocketTimeout_Reliable.tv_sec * SECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable.tv_usec / MICROSECOND_TO_MILLISECOND;
		#endif
		}
		else { //UDP
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (Parameter.GetTickCount64_PTR != nullptr)
				OutputPacketListTemp->ClearPortTime = (size_t)((*Parameter.GetTickCount64_PTR)() + Parameter.SocketTimeout_Unreliable);
			else 
				OutputPacketListTemp->ClearPortTime = GetTickCount() + Parameter.SocketTimeout_Unreliable;
		#elif defined(PLATFORM_WIN)
			OutputPacketListTemp->ClearPortTime = GetTickCount64() + Parameter.SocketTimeout_Unreliable;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			OutputPacketListTemp->ClearPortTime = GetTickCount64() + Parameter.SocketTimeout_Unreliable.tv_sec * SECOND_TO_MILLISECOND + Parameter.SocketTimeout_Unreliable.tv_usec / MICROSECOND_TO_MILLISECOND;
		#endif
		}

		std::unique_lock<std::mutex> OutputPacketListMutex(OutputPacketListLock);
		OutputPacketList.push_back(*OutputPacketListTemp);
	}

//Block Port Unreachable messages of system or close the TCP requesting connections.
	shutdown(UDPSockData->Socket, SD_SEND);
#if defined(PLATFORM_WIN)
	if (Protocol == IPPROTO_TCP) //TCP
		Sleep(Parameter.SocketTimeout_Reliable);
	else //UDP
		Sleep(Parameter.SocketTimeout_Unreliable);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (Protocol == IPPROTO_TCP) //TCP
		usleep(Parameter.SocketTimeout_Reliable.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable.tv_usec);
	else //UDP
		usleep(Parameter.SocketTimeout_Unreliable.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Unreliable.tv_usec);
#endif
	shutdown(UDPSockData->Socket, SD_BOTH);
	closesocket(UDPSockData->Socket);

	return EXIT_SUCCESS;
}

//Transmission of UDP protocol(Multithreading)
size_t __fastcall UDPRequestMulti(const char *OriginalSend, const size_t Length, const SOCKET_DATA *LocalSocketData, const uint16_t Protocol)
{
//Socket initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	if (!SelectTargetSocketMulti(UDPSocketDataList, IPPROTO_UDP))
		return EXIT_FAILURE;

//Send request and receive result.
	std::shared_ptr<fd_set> WriteFDS(new fd_set());
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	SOCKET MaxSocket = 0;
#endif
	FD_ZERO(WriteFDS.get());
	for (auto &SocketDataIter:UDPSocketDataList)
	{
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (SocketDataIter.Socket > MaxSocket)
			MaxSocket = SocketDataIter.Socket;
	#endif
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0;
	for (size_t LoopLimits = 0;LoopLimits < LOOP_MAX_TIMES;++LoopLimits)
	{
	//Reset parameters.
	#if defined(PLATFORM_WIN)
		Timeout->tv_sec = Parameter.SocketTimeout_Unreliable / SECOND_TO_MILLISECOND;
		Timeout->tv_usec = Parameter.SocketTimeout_Unreliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Timeout->tv_sec = Parameter.SocketTimeout_Unreliable.tv_sec;
		Timeout->tv_usec = Parameter.SocketTimeout_Unreliable.tv_usec;
	#endif

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, nullptr, WriteFDS.get(), nullptr, Timeout.get());
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(MaxSocket + 1U, nullptr, WriteFDS.get(), nullptr, Timeout.get());
	#endif
		if (SelectResult > 0)
		{
		//Send.
			for (auto &SocketDataIter:UDPSocketDataList)
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
			for (auto &SocketDataIter:UDPSocketDataList)
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
		std::shared_ptr<OUTPUT_PACKET_TABLE> OutputPacketListTemp(new OUTPUT_PACKET_TABLE());
		memset(OutputPacketListTemp.get(), 0, sizeof(OUTPUT_PACKET_TABLE));

	//Mark system connection data.
		OutputPacketListTemp->SocketData_Input = *LocalSocketData;

	//Mark sending connection data.
		for (auto &SocketDataIter:UDPSocketDataList)
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

			OutputPacketListTemp->SocketData_Output.push_back(*SocketDataTemp);
		}

		SocketDataTemp.reset();

	//Mark send time.
	//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
		OutputPacketListTemp->Protocol_Network = Protocol;
		if (Protocol == IPPROTO_TCP) //TCP
		{
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (Parameter.GetTickCount64_PTR != nullptr)
				OutputPacketListTemp->ClearPortTime = (size_t)((*Parameter.GetTickCount64_PTR)() + Parameter.SocketTimeout_Reliable);
			else 
				OutputPacketListTemp->ClearPortTime = GetTickCount() + Parameter.SocketTimeout_Reliable;
		#elif defined(PLATFORM_WIN)
			OutputPacketListTemp->ClearPortTime = GetTickCount64() + Parameter.SocketTimeout_Reliable;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			OutputPacketListTemp->ClearPortTime = GetTickCount64() + Parameter.SocketTimeout_Reliable.tv_sec * SECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable.tv_usec / MICROSECOND_TO_MILLISECOND;
		#endif
		}
		else { //UDP
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (Parameter.GetTickCount64_PTR != nullptr)
				OutputPacketListTemp->ClearPortTime = (size_t)((*Parameter.GetTickCount64_PTR)() + Parameter.SocketTimeout_Unreliable);
			else 
				OutputPacketListTemp->ClearPortTime = GetTickCount() + Parameter.SocketTimeout_Unreliable;
		#elif defined(PLATFORM_WIN)
			OutputPacketListTemp->ClearPortTime = GetTickCount64() + Parameter.SocketTimeout_Unreliable;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			OutputPacketListTemp->ClearPortTime = GetTickCount64() + Parameter.SocketTimeout_Unreliable.tv_sec * SECOND_TO_MILLISECOND + Parameter.SocketTimeout_Unreliable.tv_usec / MICROSECOND_TO_MILLISECOND;
		#endif
		}

		std::unique_lock<std::mutex> OutputPacketListMutex(OutputPacketListLock);
		OutputPacketList.push_back(*OutputPacketListTemp);
	}

//Block Port Unreachable messages of system or close the TCP requesting connections.
	for (auto &SocketDataIter:UDPSocketDataList)
		shutdown(SocketDataIter.Socket, SD_SEND);
#if defined(PLATFORM_WIN)
	if (Protocol == IPPROTO_TCP) //TCP
		Sleep(Parameter.SocketTimeout_Reliable);
	else //UDP
		Sleep(Parameter.SocketTimeout_Unreliable);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (Protocol == IPPROTO_TCP) //TCP
		usleep(Parameter.SocketTimeout_Reliable.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable.tv_usec);
	else //UDP
		usleep(Parameter.SocketTimeout_Unreliable.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Unreliable.tv_usec);
#endif
	for (auto &SocketDataIter:UDPSocketDataList)
	{
		shutdown(SocketDataIter.Socket, SD_BOTH);
		closesocket(SocketDataIter.Socket);
	}

	return EXIT_SUCCESS;
}
#endif

//Complete transmission of UDP protocol
size_t __fastcall UDPCompleteRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize, const bool IsLocal)
{
//Initialization
	std::shared_ptr<SOCKET_DATA> UDPSockData(new SOCKET_DATA());
	memset(UDPSockData.get(), 0, sizeof(SOCKET_DATA));
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;

//Socket initialization
	if (!SelectTargetSocket(UDPSockData.get(), IsAlternate, AlternateTimeoutTimes, IPPROTO_UDP, IsLocal) || UDPSockData->Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSockData->Socket);

		return EXIT_FAILURE;
	}

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(int)) == SOCKET_ERROR)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSockData->Socket);

		return EXIT_FAILURE;
	}

//UDP connecting
	if (connect(UDPSockData->Socket, (PSOCKADDR)&UDPSockData->SockAddr, UDPSockData->AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Complete UDP request initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSockData->Socket);

		return EXIT_FAILURE;
	}

//Send requesting.
	if (send(UDPSockData->Socket, OriginalSend, (int)SendSize, 0) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Complete UDP request error", WSAGetLastError(), nullptr, 0);
		shutdown(UDPSockData->Socket, SD_BOTH);
		closesocket(UDPSockData->Socket);

		return EXIT_FAILURE;
	}

//Receive result.
	SSIZE_T RecvLen = recv(UDPSockData->Socket, OriginalRecv, (int)RecvSize, 0);
	if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		if (RecvLen == SOCKET_ERROR)
			RecvLen = WSAGetLastError();
		shutdown(UDPSockData->Socket, SD_BOTH);
		closesocket(UDPSockData->Socket);
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
		if ((Parameter.DNSDataCheck || Parameter.BlacklistCheck) && CheckResponseData(OriginalRecv, RecvLen, IsLocal) == EXIT_FAILURE)
		{
			memset(OriginalRecv, 0, RecvSize);

		//Set socket timeout.
			if (!IsLocal && Parameter.ReceiveWaiting > 0)
			{
			#if defined(PLATFORM_WIN)
				int SocketTimeoutTemp = (int)Parameter.ReceiveWaiting;
				if (setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&SocketTimeoutTemp, sizeof(int)) == SOCKET_ERROR || 
					setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&SocketTimeoutTemp, sizeof(int)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				timeval SocketTimeoutTemp = {0};
				SocketTimeoutTemp.tv_sec = Parameter.ReceiveWaiting / SECOND_TO_MILLISECOND;
				SocketTimeoutTemp.tv_usec = Parameter.ReceiveWaiting % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
				if (setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&SocketTimeoutTemp, sizeof(timeval)) == SOCKET_ERROR || 
					setsockopt(UDPSockData->Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&SocketTimeoutTemp, sizeof(timeval)) == SOCKET_ERROR)
			#endif
				{
					PrintError(LOG_ERROR_NETWORK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
					closesocket(UDPSockData->Socket);

					return EXIT_FAILURE;
				}
			}
		//Stop waitting when it is Local requesting.
			else {
				shutdown(UDPSockData->Socket, SD_BOTH);
				closesocket(UDPSockData->Socket);
				return EXIT_FAILURE;
			}

		//Try to receive packets.
			for (size_t LoopLimits = 0;LoopLimits < LOOP_MAX_TIMES;++LoopLimits)
			{
				if (CheckResponseData(OriginalRecv, RecvLen, IsLocal) == EXIT_FAILURE)
				{
					memset(OriginalRecv, 0, RecvSize);
					RecvLen = recv(UDPSockData->Socket, OriginalRecv, (int)RecvSize, 0);
					if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
					{
						if (RecvLen == SOCKET_ERROR)
							RecvLen = WSAGetLastError();
						shutdown(UDPSockData->Socket, SD_BOTH);
						closesocket(UDPSockData->Socket);
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
				else {
					shutdown(UDPSockData->Socket, SD_BOTH);
					closesocket(UDPSockData->Socket);
					break;
				}
			}
		}

		shutdown(UDPSockData->Socket, SD_BOTH);
		closesocket(UDPSockData->Socket);

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
//Socket initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	if (!SelectTargetSocketMulti(UDPSocketDataList, IPPROTO_UDP))
		return EXIT_FAILURE;

//Send request and receive result.
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	SOCKET MaxSocket = 0;
#endif
	FD_ZERO(WriteFDS.get());
	for (auto &SocketDataIter:UDPSocketDataList)
	{
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (SocketDataIter.Socket > MaxSocket)
			MaxSocket = SocketDataIter.Socket;
	#endif
		FD_SET(SocketDataIter.Socket, WriteFDS.get());
	}
	SSIZE_T SelectResult = 0, RecvLen = 0;
	size_t Index = 0;
	for (size_t LoopLimits = 0;LoopLimits < LOOP_MAX_TIMES;++LoopLimits)
	{
		Sleep(LOOP_INTERVAL_TIME);

	//Reset parameters.
	#if defined(PLATFORM_WIN)
		Timeout->tv_sec = Parameter.SocketTimeout_Unreliable / SECOND_TO_MILLISECOND;
		Timeout->tv_usec = Parameter.SocketTimeout_Unreliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Timeout->tv_sec = Parameter.SocketTimeout_Unreliable.tv_sec;
		Timeout->tv_usec = Parameter.SocketTimeout_Unreliable.tv_usec;
	#endif
		FD_ZERO(ReadFDS.get());
		for (auto &SocketDataIter:UDPSocketDataList)
		{
			if (SocketDataIter.Socket > 0)
			{
				FD_SET(SocketDataIter.Socket, ReadFDS.get());
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(MaxSocket + 1U, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#endif
		
		if (SelectResult > 0)
		{
		//Receive.
			for (Index = 0;Index < UDPSocketDataList.size();++Index)
			{
				if (FD_ISSET(UDPSocketDataList.at(Index).Socket, ReadFDS.get()))
				{
					RecvLen = recvfrom(UDPSocketDataList.at(Index).Socket, OriginalRecv, (int)RecvSize, 0, (PSOCKADDR)&UDPSocketDataList.at(Index).SockAddr, &UDPSocketDataList.at(Index).AddrLen);
					if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
					{
						memset(OriginalRecv, 0, RecvSize);
						shutdown(UDPSocketDataList.at(Index).Socket, SD_BOTH);
						closesocket(UDPSocketDataList.at(Index).Socket);
						UDPSocketDataList.at(Index).Socket = 0;

						continue;
					}
					else {
					//Hosts Only Extended check
						if ((Parameter.DNSDataCheck || Parameter.BlacklistCheck) && CheckResponseData(OriginalRecv, RecvLen, false) == EXIT_FAILURE)
						{
							memset(OriginalRecv, 0, RecvSize);
							shutdown(UDPSocketDataList.at(Index).Socket, SD_BOTH);
							closesocket(UDPSocketDataList.at(Index).Socket);
							UDPSocketDataList.at(Index).Socket = 0;

							continue;
						}

					//Mark DNS Cache.
						if (Parameter.CacheType > 0)
							MarkDomainCache(OriginalRecv, RecvLen);

						for (auto &SocketDataIter:UDPSocketDataList)
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
			for (auto &SocketDataIter:UDPSocketDataList)
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
			for (auto &SocketDataIter:UDPSocketDataList)
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
	for (auto &SocketDataIter:UDPSocketDataList)
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
