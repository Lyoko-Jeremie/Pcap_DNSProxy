// This code is part of Pcap_DNSProxy
// A local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2016 Chengr28
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


#include "Request.h"

#if defined(ENABLE_PCAP)
//Get TTL(IPv4)/Hop Limits(IPv6) with normal DNS request
bool DomainTestRequest(
	const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<uint8_t> Buffer(new uint8_t[PACKET_MAXSIZE]()), DNSQuery(new uint8_t[PACKET_MAXSIZE]());
	memset(Buffer.get(), 0, PACKET_MAXSIZE);
	memset(DNSQuery.get(), 0, PACKET_MAXSIZE);

//Make a DNS request with Doamin Test packet.
	const auto DNS_Header = (pdns_hdr)Buffer.get();
	DNS_Header->ID = Parameter.DomainTest_ID;
	DNS_Header->Flags = htons(DNS_STANDARD);
	DNS_Header->Question = htons(U16_NUM_ONE);
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
			DNS_Query->Classes = htons(DNS_CLASS_INTERNET);
			if (Protocol == AF_INET6)
				DNS_Query->Type = htons(DNS_TYPE_AAAA);
			else if (Protocol == AF_INET)
				DNS_Query->Type = htons(DNS_TYPE_A);
			else 
				return false;
			DNSQuery.reset();
			DataLength += sizeof(dns_qry);

		//EDNS Label
			if (Parameter.EDNS_Label)
			{
				DataLength = AddEDNSLabelToAdditionalRR(Buffer.get(), DataLength + sizeof(dns_hdr), PACKET_MAXSIZE, nullptr);
				DataLength -= sizeof(dns_hdr);
			}
		}
		else {
			return false;
		}
	}
	DataLength += sizeof(dns_hdr);

//Send request.
	size_t SleepTime_DomainTest = 0, SpeedTime_DomainTest = Parameter.DomainTest_Speed, Times = 0;
	for (;;)
	{
	//Domain Test Disable
		if (Parameter.DomainTest_Speed == 0)
		{
			Sleep(Parameter.FileRefreshTime);
			continue;
		}
	//Sleep time controller
		else if (SleepTime_DomainTest > 0)
		{
			if (SpeedTime_DomainTest != Parameter.DomainTest_Speed)
			{
				SpeedTime_DomainTest = Parameter.DomainTest_Speed;
			}
			else if (SleepTime_DomainTest < SpeedTime_DomainTest)
			{
				SleepTime_DomainTest += Parameter.FileRefreshTime;

				Sleep(Parameter.FileRefreshTime);
				continue;
			}

			SleepTime_DomainTest = 0;
		}

	//Interval time
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			if (Protocol == AF_INET6)
			{
				if ((Parameter.Target_Server_IPv6.HopLimitData_Assign.HopLimit == 0 && Parameter.Target_Server_IPv6.HopLimitData_Mark.HopLimit == 0) || //Main
					(Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0 && //Alternate
					Parameter.Target_Server_Alternate_IPv6.HopLimitData_Assign.HopLimit == 0 && Parameter.Target_Server_Alternate_IPv6.HopLimitData_Mark.HopLimit == 0))
						goto JumpToRetest;

			//Multiple list(IPv6)
				if (Parameter.Target_Server_IPv6_Multiple != nullptr)
				{
					for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multiple)
					{
						if (DNSServerDataIter.HopLimitData_Assign.HopLimit == 0 && DNSServerDataIter.HopLimitData_Mark.HopLimit == 0)
							goto JumpToRetest;
					}
				}
			}
			else if (Protocol == AF_INET)
			{
				if ((Parameter.Target_Server_IPv4.HopLimitData_Assign.TTL == 0 && Parameter.Target_Server_IPv4.HopLimitData_Mark.TTL == 0) || //Main
					(Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0 && //Alternate
					Parameter.Target_Server_Alternate_IPv4.HopLimitData_Assign.TTL == 0 && Parameter.Target_Server_Alternate_IPv4.HopLimitData_Mark.TTL == 0))
						goto JumpToRetest;

			//Multiple list(IPv4)
				if (Parameter.Target_Server_IPv4_Multiple != nullptr)
				{
					for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multiple)
					{
						if (DNSServerDataIter.HopLimitData_Assign.TTL == 0 && DNSServerDataIter.HopLimitData_Mark.TTL == 0)
							goto JumpToRetest;
					}
				}
			}
			else {
				goto JumpToRetest;
			}

		//Wait for testing again.
			SleepTime_DomainTest += Parameter.FileRefreshTime;
			continue;

		//Jump here to start.
		JumpToRetest:
			Sleep(SENDING_INTERVAL_TIME);
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

			//Make DNS query data.
				DNS_Query = (pdns_qry)(Buffer.get() + DataLength);
				DNS_Query->Classes = htons(DNS_CLASS_INTERNET);
				if (Protocol == AF_INET6)
					DNS_Query->Type = htons(DNS_TYPE_AAAA);
				else if (Protocol == AF_INET)
					DNS_Query->Type = htons(DNS_TYPE_A);
				else 
					break;
				DataLength += sizeof(dns_qry);

			//EDNS Label
				if (Parameter.EDNS_Label)
				{
					DNS_Header->Additional = 0;
					DataLength = AddEDNSLabelToAdditionalRR(Buffer.get(), DataLength, PACKET_MAXSIZE, nullptr);
				}
			}

		//Send process
			UDPRequestMultiple(REQUEST_PROCESS_UDP_NO_MARKING, 0, Buffer.get(), DataLength, nullptr);
			Sleep(SENDING_INTERVAL_TIME);
			++Times;
		}
	}

//Monitor terminated
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Domain Test module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Internet Control Message Protocol(version 6)/ICMP(v6) echo(Ping) request
bool ICMPTestRequest(
	const uint16_t Protocol)
{
//Initialization
	size_t Length = 0;
	if (Protocol == AF_INET6)
		Length = sizeof(icmpv6_hdr) + Parameter.ICMP_PaddingLength;
	else if (Protocol == AF_INET)
		Length = sizeof(icmp_hdr) + Parameter.ICMP_PaddingLength;
	else 
		return false;
	std::shared_ptr<uint8_t> SendBuffer(new uint8_t[Length]());
	memset(SendBuffer.get(), 0, Length);
	const auto ICMP_Header = (picmp_hdr)SendBuffer.get();
	const auto ICMPv6_Header = (picmpv6_hdr)SendBuffer.get();
	std::vector<SOCKET_DATA> ICMPSocketData;
#if defined(PLATFORM_LINUX)
	std::uniform_int_distribution<uint32_t> RamdomDistribution(0, UINT32_MAX);
#endif

//ICMPv6
	if (Protocol == AF_INET6)
	{
	//Make a ICMPv6 request echo packet.
		ICMPv6_Header->Type = ICMPV6_TYPE_REQUEST;
		ICMPv6_Header->Code = ICMPV6_CODE_REQUEST;
		ICMPv6_Header->ID = Parameter.ICMP_ID;
		ICMPv6_Header->Sequence = Parameter.ICMP_Sequence;
		memcpy_s(SendBuffer.get() + sizeof(icmpv6_hdr), Parameter.ICMP_PaddingLength, Parameter.ICMP_PaddingData, Parameter.ICMP_PaddingLength);
	#if defined(PLATFORM_LINUX)
		ICMPv6_Header->Timestamp = (uint64_t)time(nullptr);
		ICMPv6_Header->Nonce = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
	#elif defined(PLATFORM_MACX)
		ICMPv6_Header->Timestamp = (uint64_t)time(nullptr);
	#endif

	//Socket initialization
		SOCKET_DATA SocketDataTemp;
		memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));

	//Main
	#if defined(PLATFORM_WIN)
		SocketDataTemp.Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SocketDataTemp.Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
	#endif
		if (!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
			!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr))
		{
			SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			return false;
		}
		else {
			SocketDataTemp.SockAddr.ss_family = Parameter.Target_Server_IPv6.AddressData.Storage.ss_family;
			((PSOCKADDR_IN6)&SocketDataTemp.SockAddr)->sin6_addr = Parameter.Target_Server_IPv6.AddressData.IPv6.sin6_addr;
			SocketDataTemp.AddrLen = sizeof(sockaddr_in6);
			ICMPSocketData.push_back(SocketDataTemp);
			memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
		}

	//Alternate
		if (Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
		#if defined(PLATFORM_WIN)
			SocketDataTemp.Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			SocketDataTemp.Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
		#endif
			if (!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr))
			{
				for (const auto &SocketDataIter:ICMPSocketData)
					SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);

				return false;
			}
			else {
				SocketDataTemp.SockAddr.ss_family = Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family;
				((PSOCKADDR_IN6)&SocketDataTemp.SockAddr)->sin6_addr = Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr;
				SocketDataTemp.AddrLen = sizeof(sockaddr_in6);
				ICMPSocketData.push_back(SocketDataTemp);
				memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
			}
		}

	//Multiple list(IPv6)
		if (Parameter.Target_Server_IPv6_Multiple != nullptr)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multiple)
			{
			#if defined(PLATFORM_WIN)
				SocketDataTemp.Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				SocketDataTemp.Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
			#endif
				if (!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
					!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr))
				{
					for (const auto &SocketDataIter:ICMPSocketData)
						SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);

					return false;
				}
				else {
					SocketDataTemp.SockAddr.ss_family = DNSServerDataIter.AddressData.Storage.ss_family;
					((PSOCKADDR_IN6)&SocketDataTemp.SockAddr)->sin6_addr = DNSServerDataIter.AddressData.IPv6.sin6_addr;
					SocketDataTemp.AddrLen = sizeof(sockaddr_in6);
					ICMPSocketData.push_back(SocketDataTemp);
					memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
				}
			}
		}
	}
//ICMP
	else if (Protocol == AF_INET)
	{
	//Make a ICMP request echo packet.
		ICMP_Header->Type = ICMP_TYPE_REQUEST;
		ICMP_Header->Code = ICMP_CODE_REQUEST;
		ICMP_Header->ID = Parameter.ICMP_ID;
		ICMP_Header->Sequence = Parameter.ICMP_Sequence;
		memcpy_s(SendBuffer.get() + sizeof(icmp_hdr), Parameter.ICMP_PaddingLength, Parameter.ICMP_PaddingData, Parameter.ICMP_PaddingLength);
	#if defined(PLATFORM_LINUX)
		ICMP_Header->Timestamp = (uint64_t)time(nullptr);
		ICMP_Header->Nonce = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
	#elif defined(PLATFORM_MACX)
		ICMP_Header->Timestamp = (uint64_t)time(nullptr);
	#endif
		ICMP_Header->Checksum = GetChecksum((uint16_t *)SendBuffer.get(), Length);

	//Socket initialization
		SOCKET_DATA SocketDataTemp;
		memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));

	//Main
		SocketDataTemp.Socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
			!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
			!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
		{
			SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			return false;
		}
		else {
			SocketDataTemp.SockAddr.ss_family = Parameter.Target_Server_IPv4.AddressData.Storage.ss_family;
			((PSOCKADDR_IN)&SocketDataTemp.SockAddr)->sin_addr = Parameter.Target_Server_IPv4.AddressData.IPv4.sin_addr;
			SocketDataTemp.AddrLen = sizeof(sockaddr_in);
			ICMPSocketData.push_back(SocketDataTemp);
		}

	//Alternate
		if (Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
			memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
			SocketDataTemp.Socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
			if (!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
			{
				for (const auto &SocketDataIter:ICMPSocketData)
					SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);

				return false;
			}
			else {
				SocketDataTemp.SockAddr.ss_family = Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family;
				((PSOCKADDR_IN)&SocketDataTemp.SockAddr)->sin_addr = Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr;
				SocketDataTemp.AddrLen = sizeof(sockaddr_in);
				ICMPSocketData.push_back(SocketDataTemp);
				memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
			}
		}

	//Multiple list(IPv4)
		if (Parameter.Target_Server_IPv4_Multiple != nullptr)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multiple)
			{
				memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
				SocketDataTemp.Socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
				if (!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
					!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
					!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
				{
					for (const auto &SocketDataIter:ICMPSocketData)
						SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);

					return false;
				}
				else {
					SocketDataTemp.SockAddr.ss_family = DNSServerDataIter.AddressData.Storage.ss_family;
					((PSOCKADDR_IN)&SocketDataTemp.SockAddr)->sin_addr = DNSServerDataIter.AddressData.IPv4.sin_addr;
					SocketDataTemp.AddrLen = sizeof(sockaddr_in);
					ICMPSocketData.push_back(SocketDataTemp);
					memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
				}
			}
		}
	}
	else {
		return false;
	}

//Socket attribute setting(Timeout)
	for (auto &SocketDataIter:ICMPSocketData)
	{
		if (!SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TIMEOUT, true, &Parameter.SocketTimeout_Unreliable_Once))
		{
			for (const auto &InnerSocketDataIter:ICMPSocketData)
				SocketSetting(InnerSocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);

			return false;
		}
	}

//Send request.
	std::shared_ptr<uint8_t> RecvBuffer(new uint8_t[PACKET_MAXSIZE]());
	SOCKET_DATA InnerSocketData;
	memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
	memset(&InnerSocketData, 0, sizeof(InnerSocketData));
	size_t SleepTime_ICMP = 0, SpeedTime_ICMP = Parameter.ICMP_Speed, Times = 0, Index = 0;
	auto IsAllSend = false;
	for (;;)
	{
	//ICMP Test Disable
		if (Parameter.ICMP_Speed == 0)
		{
			Sleep(Parameter.FileRefreshTime);
			continue;
		}
	//Sleep time controller
		else if (SleepTime_ICMP > 0)
		{
			if (SpeedTime_ICMP != Parameter.ICMP_Speed)
			{
				SpeedTime_ICMP = Parameter.ICMP_Speed;
			}
			else if (SleepTime_ICMP < SpeedTime_ICMP)
			{
				SleepTime_ICMP += Parameter.FileRefreshTime;
				Sleep(Parameter.FileRefreshTime);

				continue;
			}

			SleepTime_ICMP = 0;
		}

	//Interval time
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			if (Protocol == AF_INET6)
			{
				if ((Parameter.Target_Server_IPv6.HopLimitData_Assign.HopLimit == 0 && Parameter.Target_Server_IPv6.HopLimitData_Mark.HopLimit == 0) || //Main
					(Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0 && //Alternate
					Parameter.Target_Server_Alternate_IPv6.HopLimitData_Assign.HopLimit == 0 && Parameter.Target_Server_Alternate_IPv6.HopLimitData_Mark.HopLimit == 0))
						goto JumpToRetest;

			//Multiple list(IPv6)
				if (Parameter.Target_Server_IPv6_Multiple != nullptr)
				{
					for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multiple)
					{
						if (DNSServerDataIter.HopLimitData_Assign.HopLimit == 0 && DNSServerDataIter.HopLimitData_Mark.HopLimit == 0)
							goto JumpToRetest;
					}
				}
			}
			else if (Protocol == AF_INET)
			{
				if ((Parameter.Target_Server_IPv4.HopLimitData_Assign.TTL == 0 && Parameter.Target_Server_IPv4.HopLimitData_Mark.TTL == 0) || //Main
					(Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0 && //Alternate
					Parameter.Target_Server_Alternate_IPv4.HopLimitData_Assign.TTL == 0 && Parameter.Target_Server_Alternate_IPv4.HopLimitData_Mark.TTL == 0))
						goto JumpToRetest;

			//Multiple list(IPv4)
				if (Parameter.Target_Server_IPv4_Multiple != nullptr)
				{
					for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multiple)
					{
						if (DNSServerDataIter.HopLimitData_Assign.TTL == 0 && DNSServerDataIter.HopLimitData_Mark.TTL == 0)
							goto JumpToRetest;
					}
				}
			}
			else {
				goto JumpToRetest;
			}

		//Wait for testing again.
			SleepTime_ICMP += Parameter.FileRefreshTime;
			continue;

		//Jump here to start.
		JumpToRetest:
			Sleep(SENDING_INTERVAL_TIME);
			continue;
		}

	//Send and receive process
		for (const auto &SocketDataIter:ICMPSocketData)
		{
			IsAllSend = false;
			for (Index = 0;Index < Parameter.MultipleRequestTimes;++Index)
			{
				if (!IsAllSend)
				{
					sendto(SocketDataIter.Socket, (const char *)SendBuffer.get(), (int)Length, 0, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen);
					if (Index + 1U == Parameter.MultipleRequestTimes)
					{
						IsAllSend = true;
						Index = 0;
					}
				}
				else {
					memcpy_s(&InnerSocketData, sizeof(InnerSocketData), &SocketDataIter, sizeof(InnerSocketData));
					recvfrom(SocketDataIter.Socket, (char *)RecvBuffer.get(), PACKET_MAXSIZE, 0, (PSOCKADDR)&InnerSocketData.SockAddr, &InnerSocketData.AddrLen);
					memset(RecvBuffer.get(), 0, PACKET_MAXSIZE);
					memset(&InnerSocketData, 0, sizeof(InnerSocketData));
				}
			}

		//Increase Sequence.
			if (ntohs(Parameter.ICMP_Sequence) == DEFAULT_SEQUENCE)
			{
				if (Protocol == AF_INET6)
				{
					if (ICMPv6_Header->Sequence == UINT16_MAX)
						ICMPv6_Header->Sequence = htons(DEFAULT_SEQUENCE);
					else 
						ICMPv6_Header->Sequence = htons(ntohs(ICMPv6_Header->Sequence) + 1U);

				//Get UTC time.
				#if defined(PLATFORM_LINUX)
					ICMPv6_Header->Timestamp = (uint64_t)time(nullptr);
					ICMPv6_Header->Nonce = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
				#elif defined(PLATFORM_MACX)
					ICMPv6_Header->Timestamp = (uint64_t)time(nullptr);
				#endif
				}
				else if (Protocol == AF_INET)
				{
					if (ICMP_Header->Sequence == UINT16_MAX)
						ICMP_Header->Sequence = htons(DEFAULT_SEQUENCE);
					else 
						ICMP_Header->Sequence = htons(ntohs(ICMP_Header->Sequence) + 1U);

				//Get UTC time.
				#if defined(PLATFORM_LINUX)
					ICMP_Header->Timestamp = (uint64_t)time(nullptr);
					ICMP_Header->Nonce = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
				#elif defined(PLATFORM_MACX)
					ICMP_Header->Timestamp = (uint64_t)time(nullptr);
				#endif

					ICMP_Header->Checksum = 0;
					ICMP_Header->Checksum = GetChecksum((uint16_t *)SendBuffer.get(), Length);
				}
			}
		}

	//Repeat.
		Sleep(SENDING_INTERVAL_TIME);
		++Times;
	}

//Monitor terminated
	for (const auto &SocketDataIter:ICMPSocketData)
		SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"ICMP Test module Monitor terminated", 0, nullptr, 0);

	return true;
}
#endif

//Transmission and reception of TCP protocol
size_t TCPRequestSingle(
	const size_t RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const ADDRESS_UNION_DATA * const SpecifieTargetData)
{
//Initialization
	std::vector<SOCKET_DATA> TCPSocketDataList(1U);
	memset(&TCPSocketDataList.front(), 0, sizeof(TCPSocketDataList.front()));
	memset(OriginalRecv, 0, RecvSize);
	const auto SendBuffer = OriginalRecv;
	memcpy_s(SendBuffer, RecvSize, OriginalSend, SendSize);

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	if (SelectTargetSocketSingle(RequestType, IPPROTO_TCP, &TCPSocketDataList.front(), nullptr, &IsAlternate, &AlternateTimeoutTimes, SpecifieTargetData) == EXIT_FAILURE)
	{
		PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"TCP socket initialization error", 0, nullptr, 0);
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Socket attribute setting(Non-blocking mode)
	if (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr))
	{
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Add length of request packet(It must be written in header when transport with TCP protocol).
	size_t DataLength = AddLengthDataToHeader(SendBuffer, SendSize, RecvSize);
	if (DataLength == EXIT_FAILURE)
	{
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Socket selecting
	ssize_t ErrorCode = 0;
	const ssize_t RecvLen = SocketSelectingOnce(RequestType, IPPROTO_TCP, TCPSocketDataList, nullptr, SendBuffer, DataLength, OriginalRecv, RecvSize, &ErrorCode);
	if (ErrorCode == WSAETIMEDOUT && IsAlternate != nullptr && !*IsAlternate && //Mark timeout.
		(!Parameter.AlternateMultipleRequest || RequestType == REQUEST_PROCESS_LOCAL))
			++(*AlternateTimeoutTimes);

	return RecvLen;
}

//Transmission and reception of TCP protocol(Multiple threading)
size_t TCPRequestMultiple(
	const size_t RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize)
{
//Initialization
	memset(OriginalRecv, 0, RecvSize);
	const auto SendBuffer = OriginalRecv;
	memcpy_s(SendBuffer, RecvSize, OriginalSend, SendSize);

//Socket initialization
	std::vector<SOCKET_DATA> TCPSocketDataList;
	if (!SelectTargetSocketMultiple(IPPROTO_TCP, TCPSocketDataList))
		return EXIT_FAILURE;

//Add length of request packet(It must be written in header when transport with TCP protocol).
	size_t DataLength = AddLengthDataToHeader(SendBuffer, SendSize, RecvSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket selecting
	ssize_t ErrorCode = 0;
	const ssize_t RecvLen = SocketSelectingOnce(RequestType, IPPROTO_TCP, TCPSocketDataList, nullptr, SendBuffer, DataLength, OriginalRecv, RecvSize, &ErrorCode);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in6)) //IPv6
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV6];
		else if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in)) //IPv4
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV4];
	}

	return RecvLen;
}

//Transmission of UDP protocol
#if defined(ENABLE_PCAP)
size_t UDPRequestSingle(
	const size_t RequestType, 
	const uint16_t Protocol, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA * const LocalSocketData)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	memset(&UDPSocketDataList.front(), 0, sizeof(UDPSocketDataList.front()));
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;

//Socket initialization
	if (SelectTargetSocketSingle(RequestType, IPPROTO_UDP, &UDPSocketDataList.front(), nullptr, &IsAlternate, &AlternateTimeoutTimes, nullptr) == EXIT_FAILURE)
	{
		PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"UDP socket initialization error", 0, nullptr, 0);
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Socket attribute setting(Non-blocking mode)
	if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr))
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Socket selecting
	ssize_t RecvLen = SocketSelectingOnce(RequestType, IPPROTO_UDP, UDPSocketDataList, nullptr, OriginalSend, SendSize, nullptr, 0, nullptr);
	if (RecvLen != EXIT_SUCCESS)
	{
		for (auto &SocketDataIter:UDPSocketDataList)
			SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Mark port to list.
	MarkPortToList(Protocol, LocalSocketData, UDPSocketDataList);
	return EXIT_SUCCESS;
}

//Transmission of UDP protocol(Multiple threading)
size_t UDPRequestMultiple(
	const size_t RequestType, 
	const uint16_t Protocol, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA * const LocalSocketData)
{
//Socket initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	if (!SelectTargetSocketMultiple(IPPROTO_UDP, UDPSocketDataList))
		return EXIT_FAILURE;

//Socket selecting
	ssize_t RecvLen = SocketSelectingOnce(RequestType, IPPROTO_UDP, UDPSocketDataList, nullptr, OriginalSend, SendSize, nullptr, 0, nullptr);
	if (RecvLen != EXIT_SUCCESS)
	{
		for (auto &SocketDataIter:UDPSocketDataList)
			SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Mark port to list.
	MarkPortToList(Protocol, LocalSocketData, UDPSocketDataList);
	return EXIT_SUCCESS;
}
#endif

//Complete transmission of UDP protocol
size_t UDPCompleteRequestSingle(
	const size_t RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const ADDRESS_UNION_DATA * const SpecifieTargetData)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	memset(&UDPSocketDataList.front(), 0, sizeof(UDPSocketDataList.front()));
	memset(OriginalRecv, 0, RecvSize);

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	if (SelectTargetSocketSingle(RequestType, IPPROTO_UDP, &UDPSocketDataList.front(), nullptr, &IsAlternate, &AlternateTimeoutTimes, SpecifieTargetData) == EXIT_FAILURE)
	{
		PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Complete UDP socket initialization error", 0, nullptr, 0);
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Socket attribute setting(Non-blocking mode)
	if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr))
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Socket selecting
	ssize_t ErrorCode = 0;
	const ssize_t RecvLen = SocketSelectingOnce(RequestType, IPPROTO_UDP, UDPSocketDataList, nullptr, OriginalSend, SendSize, OriginalRecv, RecvSize, &ErrorCode);
	if (ErrorCode == WSAETIMEDOUT && IsAlternate != nullptr && !*IsAlternate && //Mark timeout.
		(!Parameter.AlternateMultipleRequest || RequestType == REQUEST_PROCESS_LOCAL))
			++(*AlternateTimeoutTimes);

	return RecvLen;
}

//Complete transmission of UDP protocol(Multiple threading)
size_t UDPCompleteRequestMultiple(
	const size_t RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	memset(OriginalRecv, 0, RecvSize);

//Socket initialization
	if (!SelectTargetSocketMultiple(IPPROTO_UDP, UDPSocketDataList))
		return EXIT_FAILURE;

//Socket selecting
	ssize_t ErrorCode = 0;
	const ssize_t RecvLen = SocketSelectingOnce(RequestType, IPPROTO_UDP, UDPSocketDataList, nullptr, OriginalSend, SendSize, OriginalRecv, RecvSize, &ErrorCode);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in6)) //IPv6
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV6];
		else if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in)) //IPv4
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV4];
	}

	return RecvLen;
}
