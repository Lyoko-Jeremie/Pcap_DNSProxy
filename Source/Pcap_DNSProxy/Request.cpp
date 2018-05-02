// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2018 Chengr28
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
//Get Hop Limits(IPv6) and TTL(IPv4) with normal DNS request
bool DomainTestRequest(
	const uint16_t Protocol)
{
//Initialization
	const auto SendBuffer = std::make_unique<uint8_t[]>(PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
	const auto RecvBuffer = std::make_unique<uint8_t[]>(Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);
	memset(SendBuffer.get(), 0, PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
	memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);

//Make a DNS request with Doamin Test packet.
	const auto DNS_Header = reinterpret_cast<dns_hdr *>(SendBuffer.get());
	DNS_Header->ID = Parameter.DomainTest_ID;
	DNS_Header->Flags = htons(DNS_FLAG_REQUEST_STANDARD);
	DNS_Header->Question = htons(UINT16_NUM_ONE);
	size_t DataLength = 0;

//Convert domain.
	dns_qry *DNS_Query = nullptr;
	if (Parameter.DomainTest_Data != nullptr)
	{
		DataLength = StringToPacketQuery(Parameter.DomainTest_Data, RecvBuffer.get());
		if (DataLength > DOMAIN_MINSIZE && DataLength + sizeof(dns_hdr) < PACKET_NORMAL_MAXSIZE)
		{
			memcpy_s(SendBuffer.get() + sizeof(dns_hdr), Parameter.LargeBufferSize - sizeof(dns_hdr), RecvBuffer.get(), DataLength);
			memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);
			DNS_Query = reinterpret_cast<dns_qry *>(SendBuffer.get() + sizeof(dns_hdr) + DataLength);
			DNS_Query->Classes = htons(DNS_CLASS_INTERNET);
			if (Protocol == AF_INET6)
				DNS_Query->Type = htons(DNS_TYPE_AAAA);
			else if (Protocol == AF_INET)
				DNS_Query->Type = htons(DNS_TYPE_A);
			else 
				return false;

			DataLength += sizeof(dns_qry);

		//EDNS Label
			if (Parameter.EDNS_Label)
			{
				DataLength = Add_EDNS_LabelToPacket(SendBuffer.get(), DataLength + sizeof(dns_hdr), PACKET_NORMAL_MAXSIZE, nullptr);
				DataLength -= sizeof(dns_hdr);
			}
		}
		else {
			return false;
		}
	}

	DataLength += sizeof(dns_hdr);

//Send request.
	size_t TotalSleepTime = 0, Times = 0;
	auto FileModifiedTime = GlobalRunningStatus.ConfigFileModifiedTime;
	for (;;)
	{
	//Domain Test disable
		if (Parameter.DomainTest_Speed == 0)
		{
			Sleep(Parameter.FileRefreshTime);
			continue;
		}
	//Sleep time controller
		else if (TotalSleepTime > 0)
		{
		//Configuration files have been changed.
			if (FileModifiedTime != GlobalRunningStatus.ConfigFileModifiedTime)
			{
				FileModifiedTime = GlobalRunningStatus.ConfigFileModifiedTime;
				TotalSleepTime = 0;
			}
		//Interval time is not enough.
			else if (TotalSleepTime < Parameter.DomainTest_Speed)
			{
				TotalSleepTime += Parameter.FileRefreshTime;

				Sleep(Parameter.FileRefreshTime);
				continue;
			}
		//Interval time is enough, next recheck time.
			else {
				TotalSleepTime = 0;
			}
		}

	//Interval time
		if (Times == SENDING_ONCE_INTERVAL_TIMES)
		{
			Times = 0;

		//Test again check.
			if (Protocol == AF_INET6)
			{
				if (
				//Main
					(Parameter.Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad == 0 && 
					Parameter.Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark == 0) || 
					!Parameter.Target_Server_Main_IPv6.ServerPacketStatus.IsMarkDetail || 
				//Alternate
					(Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
					((Parameter.Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad == 0 && 
					Parameter.Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark == 0) || 
					!Parameter.Target_Server_Alternate_IPv6.ServerPacketStatus.IsMarkDetail)))
						goto JumpToRetest;

			//Multiple list(IPv6)
				if (Parameter.Target_Server_IPv6_Multiple != nullptr)
				{
					for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multiple)
					{
						if ((DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad == 0 && 
							DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark == 0) || 
							!DNSServerDataIter.ServerPacketStatus.IsMarkDetail)
								goto JumpToRetest;
					}
				}
			}
			else if (Protocol == AF_INET)
			{
				if (
				//Main
					(Parameter.Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad == 0 && 
					Parameter.Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark == 0) || 
					!Parameter.Target_Server_Main_IPv4.ServerPacketStatus.IsMarkDetail || 
				//Alternate
					(Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
					((Parameter.Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad == 0 && 
					Parameter.Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark == 0) || 
					!Parameter.Target_Server_Alternate_IPv4.ServerPacketStatus.IsMarkDetail)))
						goto JumpToRetest;

			//Multiple list(IPv4)
				if (Parameter.Target_Server_IPv4_Multiple != nullptr)
				{
					for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multiple)
					{
						if ((DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad == 0 && 
							DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark == 0) || 
							!DNSServerDataIter.ServerPacketStatus.IsMarkDetail)
								goto JumpToRetest;
					}
				}
			}
			else {
				goto JumpToRetest;
			}

		//Wait for testing again.
			TotalSleepTime += Parameter.FileRefreshTime;
			continue;

		//Jump here to restart.
		JumpToRetest:
			Sleep(SENDING_INTERVAL_TIME);
		}
		else {
		//Make random domain request.
			if (Parameter.DomainTest_Data == nullptr)
			{
				memset(SendBuffer.get() + sizeof(dns_hdr), 0, PACKET_NORMAL_MAXSIZE - sizeof(dns_hdr));
				memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);
				MakeRandomDomain(RecvBuffer.get());
				DataLength = StringToPacketQuery(RecvBuffer.get(), SendBuffer.get() + sizeof(dns_hdr)) + sizeof(dns_hdr);

			//Make DNS query data.
				DNS_Query = reinterpret_cast<dns_qry *>(SendBuffer.get() + DataLength);
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
					DataLength = Add_EDNS_LabelToPacket(SendBuffer.get(), DataLength, PACKET_NORMAL_MAXSIZE, nullptr);
				}
			}

		//Send process, both TCP and UDP protocol
			memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);
			if (Parameter.DomainTest_Protocol == REQUEST_MODE_TEST::BOTH)
			{
				UDP_RequestMultiple(REQUEST_PROCESS_TYPE::UDP_WITHOUT_REGISTER, 0, SendBuffer.get(), DataLength, nullptr, nullptr);
				TCP_RequestMultiple(REQUEST_PROCESS_TYPE::TCP_WITHOUT_REGISTER, SendBuffer.get(), DataLength, RecvBuffer.get(), Parameter.LargeBufferSize, nullptr);
			}
			else if (Parameter.DomainTest_Protocol == REQUEST_MODE_TEST::TCP)
			{
				TCP_RequestMultiple(REQUEST_PROCESS_TYPE::TCP_WITHOUT_REGISTER, SendBuffer.get(), DataLength, RecvBuffer.get(), Parameter.LargeBufferSize, nullptr);
			}
			else if (Parameter.DomainTest_Protocol == REQUEST_MODE_TEST::UDP)
			{
				UDP_RequestMultiple(REQUEST_PROCESS_TYPE::UDP_WITHOUT_REGISTER, 0, SendBuffer.get(), DataLength, nullptr, nullptr);
			}

		//Interval time
			Sleep(SENDING_INTERVAL_TIME);
			++Times;
		}
	}

//Monitor terminated
	PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Domain Test module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Internet Control Message Protocol/ICMP echo request(Ping) read callback
void ICMP_TestReadCallback(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument)
{
//ICMP Test Disable or no response from server.
	if ((EventType & EV_TIMEOUT) != 0)
		return;

//Mark arguments.
	const auto CallbackArgument = reinterpret_cast<ICMP_EVENT_ARGUMENT *>(Argument);

//Match active socket in the list.
	SOCKET_DATA SocketDataTemp;
	memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
	for (const auto &SocketDataItem:*CallbackArgument->SocketData)
	{
		if (static_cast<evutil_socket_t>(SocketDataItem.Socket) == Socket)
		{
			SocketDataTemp = SocketDataItem;
			break;
		}
	}

//Socket data check
	if (SocketDataTemp.Socket == 0)
		return;

//Drop all responses.
	recvfrom(Socket, reinterpret_cast<char *>(CallbackArgument->RecvBuffer), static_cast<int>(CallbackArgument->RecvSize), 0, reinterpret_cast<sockaddr *>(&SocketDataTemp.SockAddr), &SocketDataTemp.AddrLen);
	memset(CallbackArgument->RecvBuffer, 0, CallbackArgument->RecvSize);

	return;
}

//Internet Control Message Protocol/ICMP echo request(Ping) write callback
void ICMP_TestWriteCallback(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument)
{
//Mark arguments.
	const auto CallbackArgument = reinterpret_cast<ICMP_EVENT_ARGUMENT *>(Argument);

//Match active socket in the list.
	SOCKET_DATA SocketDataTemp;
	memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
	for (const auto &SocketDataItem:*CallbackArgument->SocketData)
	{
		if (static_cast<evutil_socket_t>(SocketDataItem.Socket) == Socket)
		{
			SocketDataTemp = SocketDataItem;
			break;
		}
	}

//Socket data check
	if (SocketDataTemp.Socket == 0)
		return;

//Send request to all servers.
	const auto ICMPv6_Header = reinterpret_cast<icmpv6_hdr *>(CallbackArgument->SendBuffer);
	const auto ICMP_Header = reinterpret_cast<icmp_hdr *>(CallbackArgument->SendBuffer);
#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	time_t Timestamp = 0;
#endif
	for (size_t Index = 0;Index < Parameter.MultipleRequestTimes;++Index)
	{
	//Socket settings
		if (CallbackArgument->Protocol == AF_INET6)
			SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr);
		else if (CallbackArgument->Protocol == AF_INET)
			SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr);

	//Get current time.
	//Timestamp must be generated when sending, not before.
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		Timestamp = time(nullptr);
		if (Timestamp < 0)
			Timestamp = 0;

	//Set header data(Part 1).
		if (CallbackArgument->Protocol == AF_INET6)
		{
		//Timestamp and Nonce
			ICMPv6_Header->Timestamp = static_cast<uint64_t>(Timestamp);
		#if defined(PLATFORM_LINUX)
		#if defined(ENABLE_LIBSODIUM)
			ICMPv6_Header->Nonce = randombytes_random();
		#else
			ICMPv6_Header->Nonce = CallbackArgument->RandomDistribution(*GlobalRunningStatus.RandomEngine);
		#endif
		#endif
		}
		else if (CallbackArgument->Protocol == AF_INET)
		{
		//Timestamp and Nonce
			ICMP_Header->Timestamp = static_cast<uint64_t>(Timestamp);
		#if defined(PLATFORM_LINUX)
		#if defined(ENABLE_LIBSODIUM)
			ICMP_Header->Nonce = randombytes_random();
		#else
			ICMP_Header->Nonce = CallbackArgument->RandomDistribution(*GlobalRunningStatus.RandomEngine);
		#endif
		#endif

		//Checksum calculating
			ICMP_Header->Checksum = 0;
			ICMP_Header->Checksum = GetChecksum(reinterpret_cast<uint16_t *>(CallbackArgument->SendBuffer), CallbackArgument->SendSize);
		}
	#endif

	//Send request.
		sendto(Socket, reinterpret_cast<const char *>(CallbackArgument->SendBuffer), static_cast<int>(CallbackArgument->SendSize), 0, reinterpret_cast<sockaddr *>(const_cast<sockaddr_storage *>(&SocketDataTemp.SockAddr)), SocketDataTemp.AddrLen);

	//Set header data(Part 2).
		if (CallbackArgument->Protocol == AF_INET6)
		{
		//Increase sequence.
			if (ntohs(Parameter.ICMP_Sequence) == DEFAULT_SEQUENCE)
			{
				if (ICMPv6_Header->Sequence == UINT16_MAX)
					ICMPv6_Header->Sequence = htons(DEFAULT_SEQUENCE);
				else 
					ICMPv6_Header->Sequence = htons(ntohs(ICMPv6_Header->Sequence) + 1U);
			}
		}
		else if (CallbackArgument->Protocol == AF_INET)
		{
		//Increase sequence.
			if (ntohs(Parameter.ICMP_Sequence) == DEFAULT_SEQUENCE)
			{
				if (ICMP_Header->Sequence == UINT16_MAX)
					ICMP_Header->Sequence = htons(DEFAULT_SEQUENCE);
				else 
					ICMP_Header->Sequence = htons(ntohs(ICMP_Header->Sequence) + 1U);
			}

		//Checksum calculating
			ICMP_Header->Checksum = 0;
			ICMP_Header->Checksum = GetChecksum(reinterpret_cast<uint16_t *>(CallbackArgument->SendBuffer), CallbackArgument->SendSize);
		}
	}

	return;
}

//Internet Control Message Protocol/ICMP echo request(Ping) timer callback
void ICMP_TestTimerCallback(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument)
{
//Mark arguments.
	const auto CallbackArgument = reinterpret_cast<ICMP_EVENT_ARGUMENT *>(Argument);

//Interval time controller
	if (Parameter.ICMP_Speed == 0) //ICMP Test Disable
	{
	#if defined(PLATFORM_WIN)
		CallbackArgument->IntervalTimeout.tv_sec = static_cast<DWORD>(Parameter.FileRefreshTime) / SECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		CallbackArgument->IntervalTimeout.tv_sec = Parameter.FileRefreshTime / SECOND_TO_MILLISECOND;
	#endif

	//Add timer event again.
		if (event_add(CallbackArgument->EventList->front(), &CallbackArgument->IntervalTimeout) == RETURN_ERROR)
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event error", 0, nullptr, 0);

		return;
	}
//Not enough once check times
	else if (CallbackArgument->OnceTimes < SENDING_ONCE_INTERVAL_TIMES)
	{
		++CallbackArgument->OnceTimes;
	}
	else {
	//Check if Hop Limit/TTL exist.
		auto IsHopLimitExist = true;
		if (CallbackArgument->Protocol == AF_INET6) //IPv6
		{
		//Main and Alternate
			if ((Parameter.Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad == 0 && 
				Parameter.Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark == 0) || 
				(Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
				Parameter.Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad == 0 && 
				Parameter.Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark == 0))
					IsHopLimitExist = false;

		//Multiple list(IPv6)
			if (IsHopLimitExist && Parameter.Target_Server_IPv6_Multiple != nullptr)
			{
				for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multiple)
				{
					if (DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad == 0 && 
						DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark == 0)
					{
						IsHopLimitExist = false;
						break;
					}
				}
			}
		}
		else if (CallbackArgument->Protocol == AF_INET) //IPv4
		{
		//Main and Alternate
			if ((Parameter.Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad == 0 && 
				Parameter.Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark == 0) || 
				(Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
				Parameter.Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad == 0 && 
				Parameter.Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark == 0))
					IsHopLimitExist = false;

		//Multiple list(IPv4)
			if (IsHopLimitExist && Parameter.Target_Server_IPv4_Multiple != nullptr)
			{
				for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multiple)
				{
					if (DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad == 0 && DNSServerDataIter.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark == 0)
					{
						IsHopLimitExist = false;
						break;
					}
				}
			}
		}

	//Retest if Hop Limits/TTLs are not exist.
		if (IsHopLimitExist)
		{
		//Mark total sleep time.
			size_t LoopInterval = 0;
			if (Parameter.ICMP_Speed < Parameter.FileRefreshTime)
				LoopInterval = Parameter.ICMP_Speed;
			else 
				LoopInterval = Parameter.FileRefreshTime;
			CallbackArgument->TotalSleepTime += LoopInterval;
		
		//Interval time is not enough.
			if (CallbackArgument->TotalSleepTime < Parameter.ICMP_Speed)
			{
			#if defined(PLATFORM_WIN)
				CallbackArgument->IntervalTimeout.tv_sec = static_cast<DWORD>(LoopInterval) / SECOND_TO_MILLISECOND;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				CallbackArgument->IntervalTimeout.tv_sec = LoopInterval / SECOND_TO_MILLISECOND;
			#endif

			//Add timer event again.
				if (event_add(CallbackArgument->EventList->front(), &CallbackArgument->IntervalTimeout) == RETURN_ERROR)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event error", 0, nullptr, 0);

				return;
			}
		}
		
	//Interval time is enough, next recheck time.
		CallbackArgument->TotalSleepTime = 0;
		CallbackArgument->OnceTimes = 0;
	}

//Repeat events.
	auto IsTimerEvent = true, IsWriteEvent = true;
	for (const auto &EventItem:*CallbackArgument->EventList)
	{
	//Event list: Timer, Read, Write, Read, Write..
		if (IsWriteEvent)
		{
			if (IsTimerEvent)
			{
				CallbackArgument->IntervalTimeout.tv_sec = SENDING_INTERVAL_TIME / SECOND_TO_MILLISECOND;
				IsTimerEvent = false;

			//Add timer event again.
				if (event_add(EventItem, &CallbackArgument->IntervalTimeout) == RETURN_ERROR)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event error", 0, nullptr, 0);
			}
			else {
			//Add write event again.
				if (event_add(EventItem, &CallbackArgument->SocketTimeout) == RETURN_ERROR)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event error", 0, nullptr, 0);
			}

			IsWriteEvent = false;
		}
		else {
			IsWriteEvent = true;
		}
	}

	return;
}

//Internet Control Message Protocol/ICMP echo request(Ping)
bool ICMP_TestRequest(
	const uint16_t Protocol)
{
//Protocol check
	size_t DataLength = 0;
	if (Protocol == AF_INET6)
		DataLength = sizeof(icmpv6_hdr) + Parameter.ICMP_PaddingLength;
	else if (Protocol == AF_INET)
		DataLength = sizeof(icmp_hdr) + Parameter.ICMP_PaddingLength;
	else 
		return false;

//Initialization
	const auto SendBuffer = std::make_unique<uint8_t[]>(DataLength + MEMORY_RESERVED_BYTES);
	memset(SendBuffer.get(), 0, DataLength + MEMORY_RESERVED_BYTES);
	std::vector<SOCKET_DATA> ICMP_SocketData;
#if defined(PLATFORM_LINUX)
#if !defined(ENABLE_LIBSODIUM)
	std::uniform_int_distribution<uint32_t> RandomDistribution(0, UINT32_MAX);
#endif
#endif

//Make a new ICMPv6 request packet.
	if (Protocol == AF_INET6)
	{
	//Make a ICMPv6 request echo packet.
	//ICMPv6 protocol checksum will always be calculated by network stack in all platforms.
		const auto ICMPv6_Header = reinterpret_cast<icmpv6_hdr *>(SendBuffer.get());
		ICMPv6_Header->Type = ICMPV6_TYPE_REQUEST;
		ICMPv6_Header->Code = ICMPV6_CODE_REQUEST;
		ICMPv6_Header->ID = Parameter.ICMP_ID;
		ICMPv6_Header->Sequence = Parameter.ICMP_Sequence;
		memcpy_s(SendBuffer.get() + sizeof(icmpv6_hdr), Parameter.ICMP_PaddingLength, Parameter.ICMP_PaddingData, Parameter.ICMP_PaddingLength);

	//Socket initialization
	//Windows: Use SOCK_RAW type with IPPROTO_ICMPV6.
	//Linux: Use SOCK_RAW type with IPPROTO_ICMPV6, also support SOCK_DGRAM type but default disabled.
	//macOS: Use SOCK_DGRAM type with IPPROTO_ICMPV6.
		SOCKET_DATA SocketDataTemp;
		memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
		SocketDataTemp.Socket = INVALID_SOCKET;
//		int OptionValue = ICMPV6_OFFSET_CHECKSUM;

	//Main
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		SocketDataTemp.Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	#elif defined(PLATFORM_MACOS)
		SocketDataTemp.Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
	#endif
		if (!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) // || 
//			!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr) || 
//			!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::CHECKSUM_IPV6, true, &OptionValue) //ICMPv6 protocol checksum will always be calculated by network stack in all platforms.
			)
		{
			SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			return false;
		}
		else {
			SocketDataTemp.SockAddr.ss_family = Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family;
			reinterpret_cast<sockaddr_in6 *>(&SocketDataTemp.SockAddr)->sin6_addr = Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr;
			SocketDataTemp.AddrLen = sizeof(sockaddr_in6);
			ICMP_SocketData.push_back(SocketDataTemp);
			memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
			SocketDataTemp.Socket = INVALID_SOCKET;
		}

	//Alternate
		if (Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
		{
//			OptionValue = ICMPV6_OFFSET_CHECKSUM;

		#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
			SocketDataTemp.Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		#elif defined(PLATFORM_MACOS)
			SocketDataTemp.Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
		#endif
			if (!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) // || 
//				!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr) || 
//				!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::CHECKSUM_IPV6, true, &OptionValue) //ICMPv6 protocol checksum will always be calculated by network stack in all platforms.
				)
			{
				for (auto &SocketDataIter:ICMP_SocketData)
					SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

				return false;
			}
			else {
				SocketDataTemp.SockAddr.ss_family = Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family;
				reinterpret_cast<sockaddr_in6 *>(&SocketDataTemp.SockAddr)->sin6_addr = Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr;
				SocketDataTemp.AddrLen = sizeof(sockaddr_in6);
				ICMP_SocketData.push_back(SocketDataTemp);
				memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
				SocketDataTemp.Socket = INVALID_SOCKET;
			}
		}

	//Multiple list(IPv6)
		if (Parameter.Target_Server_IPv6_Multiple != nullptr)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multiple)
			{
//				OptionValue = ICMPV6_OFFSET_CHECKSUM;

			#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
				SocketDataTemp.Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
			#elif defined(PLATFORM_MACOS)
				SocketDataTemp.Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
			#endif
				if (!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) // || 
//					!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr) || 
//					!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::CHECKSUM_IPV6, true, &OptionValue) //ICMPv6 protocol checksum will always be calculated by network stack in all platforms.
					)
				{
					for (auto &SocketDataIter:ICMP_SocketData)
						SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

					return false;
				}
				else {
					SocketDataTemp.SockAddr.ss_family = DNSServerDataIter.AddressData.Storage.ss_family;
					reinterpret_cast<sockaddr_in6 *>(&SocketDataTemp.SockAddr)->sin6_addr = DNSServerDataIter.AddressData.IPv6.sin6_addr;
					SocketDataTemp.AddrLen = sizeof(sockaddr_in6);
					ICMP_SocketData.push_back(SocketDataTemp);
					memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
					SocketDataTemp.Socket = INVALID_SOCKET;
				}
			}
		}
	}
//Make a new ICMP request packet.
	else if (Protocol == AF_INET)
	{
	//Make a ICMP request echo packet, calculate checksum to make sure that is correct.
	//Windows: It seems that it's not calculating by network stack.
	//Linux: Calculate by network stack.
	//macOS: It seems that it's not calculating by network stack.
		const auto ICMP_Header = reinterpret_cast<icmp_hdr *>(SendBuffer.get());
		ICMP_Header->Type = ICMP_TYPE_REQUEST;
		ICMP_Header->Code = ICMP_CODE_REQUEST;
		ICMP_Header->ID = Parameter.ICMP_ID;
		ICMP_Header->Sequence = Parameter.ICMP_Sequence;
		memcpy_s(SendBuffer.get() + sizeof(icmp_hdr), Parameter.ICMP_PaddingLength, Parameter.ICMP_PaddingData, Parameter.ICMP_PaddingLength);
//		ICMP_Header->Checksum = 0;
		ICMP_Header->Checksum = GetChecksum(reinterpret_cast<uint16_t *>(SendBuffer.get()), DataLength);

	//Socket initialization
	//Windows: Use SOCK_RAW type with IPPROTO_ICMP.
	//Linux: Use SOCK_RAW type with IPPROTO_ICMP, also support SOCK_DGRAM type but default disabled and need to set <net.ipv4.ping_group_range='0 10'>.
	//macOS: Use SOCK_DGRAM type with IPPROTO_ICMP.
		SOCKET_DATA SocketDataTemp;
		memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
		SocketDataTemp.Socket = INVALID_SOCKET;

	//Main
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		SocketDataTemp.Socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	#elif defined(PLATFORM_MACOS)
		SocketDataTemp.Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	#endif
		if (!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
//			!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
			!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))
		{
			SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			return false;
		}
		else {
			SocketDataTemp.SockAddr.ss_family = Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family;
			reinterpret_cast<sockaddr_in *>(&SocketDataTemp.SockAddr)->sin_addr = Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_addr;
			SocketDataTemp.AddrLen = sizeof(sockaddr_in);
			ICMP_SocketData.push_back(SocketDataTemp);
			memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
			SocketDataTemp.Socket = INVALID_SOCKET;
		}

	//Alternate
		if (Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0)
		{
		#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
			SocketDataTemp.Socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		#elif defined(PLATFORM_MACOS)
			SocketDataTemp.Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
		#endif
			if (!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
//				!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))
			{
				for (auto &SocketDataIter:ICMP_SocketData)
					SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

				return false;
			}
			else {
				SocketDataTemp.SockAddr.ss_family = Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family;
				reinterpret_cast<sockaddr_in *>(&SocketDataTemp.SockAddr)->sin_addr = Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr;
				SocketDataTemp.AddrLen = sizeof(sockaddr_in);
				ICMP_SocketData.push_back(SocketDataTemp);
				memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
				SocketDataTemp.Socket = INVALID_SOCKET;
			}
		}

	//Multiple list(IPv4)
		if (Parameter.Target_Server_IPv4_Multiple != nullptr)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multiple)
			{
			#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
				SocketDataTemp.Socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
			#elif defined(PLATFORM_MACOS)
				SocketDataTemp.Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
			#endif
				if (!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
//					!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
					!SocketSetting(SocketDataTemp.Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))
				{
					for (auto &SocketDataIter:ICMP_SocketData)
						SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

					return false;
				}
				else {
					SocketDataTemp.SockAddr.ss_family = DNSServerDataIter.AddressData.Storage.ss_family;
					reinterpret_cast<sockaddr_in *>(&SocketDataTemp.SockAddr)->sin_addr = DNSServerDataIter.AddressData.IPv4.sin_addr;
					SocketDataTemp.AddrLen = sizeof(sockaddr_in);
					ICMP_SocketData.push_back(SocketDataTemp);
					memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
					SocketDataTemp.Socket = INVALID_SOCKET;
				}
			}
		}
	}
	else {
		return false;
	}

//Event initialization
	const auto RecvBuffer = std::make_unique<uint8_t[]>(PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
	memset(RecvBuffer.get(), 0, PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
	event *TimerEvent = nullptr;
	std::vector<event *> EventList;
	ICMP_EVENT_ARGUMENT ICMP_EventArg;
	memset(&ICMP_EventArg, 0, sizeof(ICMP_EventArg));
	ICMP_EventArg.Protocol = Protocol;
	ICMP_EventArg.EventBase = event_base_new();
	if (ICMP_EventArg.EventBase == nullptr)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", 0, nullptr, 0);
		goto StopLoop;
	}
	ICMP_EventArg.EventList = &EventList;
	ICMP_EventArg.SocketData = &ICMP_SocketData;
#if defined(PLATFORM_WIN)
	ICMP_EventArg.SocketTimeout.tv_sec = Parameter.SocketTimeout_Unreliable_Once / SECOND_TO_MILLISECOND;
	ICMP_EventArg.SocketTimeout.tv_usec = Parameter.SocketTimeout_Unreliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	ICMP_EventArg.SocketTimeout = Parameter.SocketTimeout_Unreliable_Once;
#endif
	ICMP_EventArg.IntervalTimeout.tv_sec = SENDING_INTERVAL_TIME / SECOND_TO_MILLISECOND;
	ICMP_EventArg.SendBuffer = SendBuffer.get();
	ICMP_EventArg.RecvBuffer = RecvBuffer.get();
	ICMP_EventArg.SendSize = DataLength;
	ICMP_EventArg.RecvSize = PACKET_NORMAL_MAXSIZE;
	ICMP_EventArg.FileModifiedTime = GlobalRunningStatus.ConfigFileModifiedTime;
#if defined(PLATFORM_LINUX)
#if !defined(ENABLE_LIBSODIUM)
	ICMP_EventArg.RandomDistribution = &RandomDistribution;
#endif
#endif

//Set timer event.
	TimerEvent = evtimer_new(ICMP_EventArg.EventBase, ICMP_TestTimerCallback, &ICMP_EventArg);
	if (TimerEvent == nullptr || event_add(TimerEvent, &ICMP_EventArg.IntervalTimeout) == RETURN_ERROR)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", 0, nullptr, 0);
		goto StopLoop;
	}
	else {
		ICMP_EventArg.EventList->push_back(TimerEvent);
	}

//Set read and write events.
	for (const auto &SocketDataIter:ICMP_SocketData)
	{
	//Socket settings
		if (evutil_make_socket_nonblocking(SocketDataIter.Socket) == RETURN_ERROR)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", 0, nullptr, 0);
			goto StopLoop;
		}

	//Make events.
		const auto ReadEvent = event_new(ICMP_EventArg.EventBase, SocketDataIter.Socket, EV_READ|EV_PERSIST, ICMP_TestReadCallback, &ICMP_EventArg);
		const auto WriteEvent = event_new(ICMP_EventArg.EventBase, SocketDataIter.Socket, EV_WRITE, ICMP_TestWriteCallback, &ICMP_EventArg);

	//Add events to event base.
		if (ReadEvent == nullptr || WriteEvent == nullptr || 
			event_add(ReadEvent, &ICMP_EventArg.IntervalTimeout) == RETURN_ERROR || //No need to read any data from socket, set socket timeout to interval timeout.
			event_add(WriteEvent, &ICMP_EventArg.SocketTimeout) == RETURN_ERROR)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", 0, nullptr, 0);
			goto StopLoop;
		}

	//Mark events which need timer to loop.
		ICMP_EventArg.EventList->push_back(ReadEvent);
		ICMP_EventArg.EventList->push_back(WriteEvent);
	}

//Event loop.
	event_base_dispatch(ICMP_EventArg.EventBase);

//Jump here to stop loop.
StopLoop:

//Free all events and sockets.
	for (const auto &EventItem:*ICMP_EventArg.EventList)
	{
		if (EventItem != nullptr)
			event_free(EventItem);
	}
	if (ICMP_EventArg.EventBase != nullptr)
		event_base_free(ICMP_EventArg.EventBase);
	for (auto &SocketDataIter:ICMP_SocketData)
		SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

//Monitor terminated
	PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"ICMP Test module Monitor terminated", 0, nullptr, 0);
	return true;
}
#endif

//Transmission and reception of TCP protocol
size_t TCP_RequestSingle(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const ADDRESS_UNION_DATA * const SpecifieTargetData, 
	const SOCKET_DATA * const LocalSocketData)
{
//Initialization
	std::vector<SOCKET_DATA> TCPSocketDataList(1U);
	memset(&TCPSocketDataList.front(), 0, sizeof(TCPSocketDataList.front()));
	TCPSocketDataList.front().Socket = INVALID_SOCKET;
	memset(OriginalRecv, 0, RecvSize);
	const auto SendBuffer = OriginalRecv;
	memcpy_s(SendBuffer, RecvSize, OriginalSend, SendSize);

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	if (SelectTargetSocketSingle(RequestType, IPPROTO_TCP, &TCPSocketDataList.front(), &IsAlternate, &AlternateTimeoutTimes, SpecifieTargetData, nullptr, nullptr) == EXIT_FAILURE)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"TCP socket initialization error", 0, nullptr, 0);
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Socket attribute setting(Non-blocking mode)
	if (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr))
	{
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Add length of request packet.
	const auto DataLength = AddLengthDataToHeader(SendBuffer, SendSize, RecvSize);
	if (DataLength == EXIT_FAILURE)
	{
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Socket selecting
	ssize_t ErrorCode = 0;
	const auto RecvLen = SocketSelectingOnce(RequestType, IPPROTO_TCP, TCPSocketDataList, nullptr, SendBuffer, DataLength, OriginalRecv, RecvSize, &ErrorCode, LocalSocketData);
	if (ErrorCode == WSAETIMEDOUT && IsAlternate != nullptr && !*IsAlternate && //Mark timeout.
		(!Parameter.AlternateMultipleRequest || RequestType == REQUEST_PROCESS_TYPE::LOCAL_NORMAL || RequestType == REQUEST_PROCESS_TYPE::LOCAL_IN_WHITE))
			++(*AlternateTimeoutTimes);

//Close all sockets.
	if (SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

	return RecvLen;
}

//Transmission and reception of TCP protocol(Multiple threading)
size_t TCP_RequestMultiple(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const SOCKET_DATA * const LocalSocketData)
{
//Initialization
	memset(OriginalRecv, 0, RecvSize);
	const auto SendBuffer = OriginalRecv;
	memcpy_s(SendBuffer, RecvSize, OriginalSend, SendSize);

//Socket initialization
	std::vector<SOCKET_DATA> TCPSocketDataList;
	if (!SelectTargetSocketMultiple(IPPROTO_TCP, TCPSocketDataList))
		return EXIT_FAILURE;

//Add length of request packet.
	const auto DataLength = AddLengthDataToHeader(SendBuffer, SendSize, RecvSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket selecting
	ssize_t ErrorCode = 0;
	const auto RecvLen = SocketSelectingOnce(RequestType, IPPROTO_TCP, TCPSocketDataList, nullptr, SendBuffer, DataLength, OriginalRecv, RecvSize, &ErrorCode, LocalSocketData);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in6)) //IPv6
			++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6];
		else if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in)) //IPv4
			++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4];
	}

//Close all sockets.
	for (auto &SocketIter:TCPSocketDataList)
	{
		if (SocketSetting(SocketIter.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			SocketSetting(SocketIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	}

	return RecvLen;
}

//Transmission of UDP protocol
#if defined(ENABLE_PCAP)
size_t UDP_RequestSingle(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA * const LocalSocketData, 
	size_t *EDNS_Length)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	memset(&UDPSocketDataList.front(), 0, sizeof(UDPSocketDataList.front()));
	UDPSocketDataList.front().Socket = INVALID_SOCKET;
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;

//Socket initialization
	if (SelectTargetSocketSingle(RequestType, IPPROTO_UDP, &UDPSocketDataList.front(), &IsAlternate, &AlternateTimeoutTimes, nullptr, nullptr, nullptr) == EXIT_FAILURE)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"UDP socket initialization error", 0, nullptr, 0);
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Socket attribute setting(Non-blocking mode)
	if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr))
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Socket selecting
	const auto RecvLen = SocketSelectingOnce(RequestType, IPPROTO_UDP, UDPSocketDataList, nullptr, OriginalSend, SendSize, nullptr, 0, nullptr, LocalSocketData);
	if (RecvLen != EXIT_SUCCESS)
	{
		for (auto &SocketDataIter:UDPSocketDataList)
			SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Mark port to list.
	RegisterPortToList(Protocol, LocalSocketData, UDPSocketDataList, EDNS_Length);
	return EXIT_SUCCESS;
}

//Transmission of UDP protocol(Multiple threading)
size_t UDP_RequestMultiple(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA * const LocalSocketData, 
	size_t *EDNS_Length)
{
//Socket initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	if (!SelectTargetSocketMultiple(IPPROTO_UDP, UDPSocketDataList))
		return EXIT_FAILURE;

//Socket selecting
	const auto RecvLen = SocketSelectingOnce(RequestType, IPPROTO_UDP, UDPSocketDataList, nullptr, OriginalSend, SendSize, nullptr, 0, nullptr, LocalSocketData);
	if (RecvLen != EXIT_SUCCESS)
	{
		for (auto &SocketDataIter:UDPSocketDataList)
			SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Mark port to list.
	RegisterPortToList(Protocol, LocalSocketData, UDPSocketDataList, EDNS_Length);
	return EXIT_SUCCESS;
}
#endif

//Complete transmission of UDP protocol
size_t UDP_CompleteRequestSingle(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const ADDRESS_UNION_DATA * const SpecifieTargetData, 
	const SOCKET_DATA * const LocalSocketData)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	memset(&UDPSocketDataList.front(), 0, sizeof(UDPSocketDataList.front()));
	UDPSocketDataList.front().Socket = INVALID_SOCKET;
	memset(OriginalRecv, 0, RecvSize);

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	if (SelectTargetSocketSingle(RequestType, IPPROTO_UDP, &UDPSocketDataList.front(), &IsAlternate, &AlternateTimeoutTimes, SpecifieTargetData, nullptr, nullptr) == EXIT_FAILURE)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Complete UDP socket initialization error", 0, nullptr, 0);
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Socket attribute setting(Non-blocking mode)
	if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr))
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Socket selecting
	ssize_t ErrorCode = 0;
	const auto RecvLen = SocketSelectingOnce(RequestType, IPPROTO_UDP, UDPSocketDataList, nullptr, OriginalSend, SendSize, OriginalRecv, RecvSize, &ErrorCode, LocalSocketData);
	if (ErrorCode == WSAETIMEDOUT && IsAlternate != nullptr && !*IsAlternate && //Mark timeout.
		(!Parameter.AlternateMultipleRequest || RequestType == REQUEST_PROCESS_TYPE::LOCAL_NORMAL || RequestType == REQUEST_PROCESS_TYPE::LOCAL_IN_WHITE))
			++(*AlternateTimeoutTimes);

//Close all sockets.
	if (SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

	return RecvLen;
}

//Complete transmission of UDP protocol(Multiple threading)
size_t UDP_CompleteRequestMultiple(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const SOCKET_DATA * const LocalSocketData)
{
//Initialization
	memset(OriginalRecv, 0, RecvSize);

//Socket initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	if (!SelectTargetSocketMultiple(IPPROTO_UDP, UDPSocketDataList))
		return EXIT_FAILURE;

//Socket selecting
	ssize_t ErrorCode = 0;
	const auto RecvLen = SocketSelectingOnce(RequestType, IPPROTO_UDP, UDPSocketDataList, nullptr, OriginalSend, SendSize, OriginalRecv, RecvSize, &ErrorCode, LocalSocketData);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in6)) //IPv6
			++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6];
		else if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in)) //IPv4
			++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4];
	}

//Close all sockets.
	for (auto &SocketIter:UDPSocketDataList)
	{
		if (SocketSetting(SocketIter.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			SocketSetting(SocketIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	}

	return RecvLen;
}
