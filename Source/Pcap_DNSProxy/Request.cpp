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

#if defined(PLATFORM_WIN)
//Firewall Test
bool FirewallTest(
	const uint16_t Protocol, 
	ssize_t &ErrorCode)
{
//Initialization
	std::uniform_int_distribution<uint16_t> RandomDistribution(0, 0);
	SOCKET_VALUE_TABLE SocketValue_FirewallTest;
	size_t Index = 0;
	ErrorCode = 0;

//IPv6
	if (Protocol == AF_INET6)
	{
	//Socket value initialization
		if (!SocketValue_FirewallTest.SocketValueInit(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, 0, nullptr, &ErrorCode))
			return false;
		reinterpret_cast<sockaddr_in6 *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin6_addr = in6addr_any;
		GenerateRandomBuffer(&reinterpret_cast<sockaddr_in6 *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin6_port, sizeof(reinterpret_cast<sockaddr_in6 *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin6_port), &RandomDistribution, 0, 0);

	//Bind local socket.
		while (bind(SocketValue_FirewallTest.ValueSet.front().Socket, reinterpret_cast<const sockaddr *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr), SocketValue_FirewallTest.ValueSet.front().AddrLen) == SOCKET_ERROR)
		{
			if (Index < LOOP_MAX_LARGE_TIMES && WSAGetLastError() == WSAEADDRINUSE)
			{
				GenerateRandomBuffer(&reinterpret_cast<sockaddr_in6 *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin6_port, sizeof(reinterpret_cast<sockaddr_in6 *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin6_port), &RandomDistribution, 0, 0);
				++Index;
			}
			else {
				ErrorCode = WSAGetLastError();
				return false;
			}
		}
	}
//IPv4
	else if (Protocol == AF_INET)
	{
	//Socket value initialization
		if (!SocketValue_FirewallTest.SocketValueInit(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, nullptr, &ErrorCode))
			return false;
		reinterpret_cast<sockaddr_in *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin_addr.s_addr = INADDR_ANY;
		GenerateRandomBuffer(&reinterpret_cast<sockaddr_in *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin_port, sizeof(reinterpret_cast<sockaddr_in *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin_port), &RandomDistribution, 0, 0);

	//Bind local socket.
		while (bind(SocketValue_FirewallTest.ValueSet.front().Socket, reinterpret_cast<const sockaddr *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr), SocketValue_FirewallTest.ValueSet.front().AddrLen) == SOCKET_ERROR)
		{
			if (Index < LOOP_MAX_LARGE_TIMES && WSAGetLastError() == WSAEADDRINUSE)
			{
				GenerateRandomBuffer(&reinterpret_cast<sockaddr_in *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin_port, sizeof(reinterpret_cast<sockaddr_in *>(&SocketValue_FirewallTest.ValueSet.front().SockAddr)->sin_port), &RandomDistribution, 0, 0);
				++Index;
			}
			else {
				ErrorCode = WSAGetLastError();
				return false;
			}
		}
	}
	else {
		return false;
	}

	return true;
}
#endif

#if defined(ENABLE_PCAP)
//Domain Test request load bufferevent
bool LoadBufferEvent_DomainTest(
	EVENT_TABLE_TRANSMISSION_ONCE *EventArgument_Domain)
{
//Mark arguments and check first load.
	auto IsFirstLoad = false;
	if (EventArgument_Domain == nullptr)
		return false;
	else if (EventArgument_Domain->Protocol_Transport->empty())
		IsFirstLoad = true;

//Socket initialization
	ssize_t ErrorCode = 0;
	if (EventArgument_Domain->Protocol_Network == AF_INET6) //IPv6
	{
	//TCP
		ErrorCode = 0;
		if (Parameter.DomainTest_Protocol == REQUEST_MODE_TEST::BOTH || Parameter.DomainTest_Protocol == REQUEST_MODE_TEST::TCP)
		{
		//Socket settings
			if (
			//Main
				!EventArgument_Domain->SocketValue->SocketValueInit(AF_INET6, SOCK_STREAM, IPPROTO_TCP, ntohs(Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_port), &Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr, &ErrorCode) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr) || 
			//Alternate
				(Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
				(!EventArgument_Domain->SocketValue->SocketValueInit(AF_INET6, SOCK_STREAM, IPPROTO_TCP, ntohs(Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_port), &Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr, &ErrorCode) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event initialization error", ErrorCode, nullptr, 0);
				return false;
			}
			else if (IsFirstLoad)
			{
			//Socket timeout settings
				timeval SocketTimeout;
				memset(&SocketTimeout, 0, sizeof(SocketTimeout));
			#if defined(PLATFORM_WIN)
				SocketTimeout.tv_sec = Parameter.SocketTimeout_Reliable_Once / SECOND_TO_MILLISECOND;
				SocketTimeout.tv_usec = Parameter.SocketTimeout_Reliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				SocketTimeout = Parameter.SocketTimeout_Reliable_Once;
			#endif

			//Main
				EventArgument_Domain->Protocol_Transport->push_back(IPPROTO_TCP);
				EventArgument_Domain->SocketTimeout->push_back(SocketTimeout);
				EventArgument_Domain->SendBuffer->push_back(std::move(std::make_unique<uint8_t[]>(EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES)));
				memset(EventArgument_Domain->SendBuffer->back().get(), 0, EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES);
				EventArgument_Domain->SendLen->push_back(0);
				EventArgument_Domain->SendTimes->push_back(0);

			//Alternate
				if (Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
				{
					EventArgument_Domain->Protocol_Transport->push_back(IPPROTO_TCP);
					EventArgument_Domain->SocketTimeout->push_back(SocketTimeout);
					EventArgument_Domain->SendBuffer->push_back(std::move(std::make_unique<uint8_t[]>(EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES)));
					memset(EventArgument_Domain->SendBuffer->back().get(), 0, EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES);
					EventArgument_Domain->SendLen->push_back(0);
					EventArgument_Domain->SendTimes->push_back(0);
				}
			}

		//Multiple list(IPv6)
			if (Parameter.Target_Server_IPv6_Multiple != nullptr)
			{
				for (const auto &DNS_ServerDataItem:*Parameter.Target_Server_IPv6_Multiple)
				{
					ErrorCode = 0;
					if (!EventArgument_Domain->SocketValue->SocketValueInit(AF_INET6, SOCK_STREAM, IPPROTO_TCP, ntohs(DNS_ServerDataItem.AddressData.IPv6.sin6_port), &DNS_ServerDataItem.AddressData.IPv6.sin6_addr, &ErrorCode) || 
						!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
						!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr) || 
						!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
					{
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event initialization error", ErrorCode, nullptr, 0);
						return false;
					}
					else if (IsFirstLoad)
					{
					//Socket timeout settings
						timeval SocketTimeout;
						memset(&SocketTimeout, 0, sizeof(SocketTimeout));
					#if defined(PLATFORM_WIN)
						SocketTimeout.tv_sec = Parameter.SocketTimeout_Reliable_Once / SECOND_TO_MILLISECOND;
						SocketTimeout.tv_usec = Parameter.SocketTimeout_Reliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
					#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
						SocketTimeout = Parameter.SocketTimeout_Reliable_Once;
					#endif

					//Multiple
						EventArgument_Domain->Protocol_Transport->push_back(IPPROTO_TCP);
						EventArgument_Domain->SocketTimeout->push_back(SocketTimeout);
						EventArgument_Domain->SendBuffer->push_back(std::move(std::make_unique<uint8_t[]>(EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES)));
						memset(EventArgument_Domain->SendBuffer->back().get(), 0, EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES);
						EventArgument_Domain->SendLen->push_back(0);
						EventArgument_Domain->SendTimes->push_back(0);
					}
				}
			}
		}

	//UDP
		if (Parameter.DomainTest_Protocol == REQUEST_MODE_TEST::BOTH || Parameter.DomainTest_Protocol == REQUEST_MODE_TEST::UDP)
		{
		//Socket settings
			ErrorCode = 0;
			if (
			//Main
				!EventArgument_Domain->SocketValue->SocketValueInit(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, ntohs(Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_port), &Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr, &ErrorCode) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr) || 
			//Alternate
				(Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
				(!EventArgument_Domain->SocketValue->SocketValueInit(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, ntohs(Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_port), &Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr, &ErrorCode) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event initialization error", ErrorCode, nullptr, 0);
				return false;
			}
			else if (IsFirstLoad)
			{
			//Socket timeout settings
				timeval SocketTimeout;
				memset(&SocketTimeout, 0, sizeof(SocketTimeout));
			#if defined(PLATFORM_WIN)
				SocketTimeout.tv_sec = Parameter.SocketTimeout_Unreliable_Once / SECOND_TO_MILLISECOND;
				SocketTimeout.tv_usec = Parameter.SocketTimeout_Unreliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				SocketTimeout = Parameter.SocketTimeout_Unreliable_Once;
			#endif

			//Main
				EventArgument_Domain->Protocol_Transport->push_back(IPPROTO_UDP);
				EventArgument_Domain->SocketTimeout->push_back(SocketTimeout);
				EventArgument_Domain->SendBuffer->push_back(std::move(std::make_unique<uint8_t[]>(EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES)));
				memset(EventArgument_Domain->SendBuffer->back().get(), 0, EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES);
				EventArgument_Domain->SendLen->push_back(0);
				EventArgument_Domain->SendTimes->push_back(0);

			//Alternate
				if (Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
				{
					EventArgument_Domain->Protocol_Transport->push_back(IPPROTO_UDP);
					EventArgument_Domain->SocketTimeout->push_back(SocketTimeout);
					EventArgument_Domain->SendBuffer->push_back(std::move(std::make_unique<uint8_t[]>(EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES)));
					memset(EventArgument_Domain->SendBuffer->back().get(), 0, EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES);
					EventArgument_Domain->SendLen->push_back(0);
					EventArgument_Domain->SendTimes->push_back(0);
				}
			}

		//Multiple list(IPv6)
			if (Parameter.Target_Server_IPv6_Multiple != nullptr)
			{
				for (const auto &DNS_ServerDataItem:*Parameter.Target_Server_IPv6_Multiple)
				{
					ErrorCode = 0;
					if (!EventArgument_Domain->SocketValue->SocketValueInit(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, ntohs(DNS_ServerDataItem.AddressData.IPv6.sin6_port), &DNS_ServerDataItem.AddressData.IPv6.sin6_addr, &ErrorCode) || 
						!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
						!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
					{
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event initialization error", ErrorCode, nullptr, 0);
						return false;
					}
					else if (IsFirstLoad)
					{
					//Socket timeout settings
						timeval SocketTimeout;
						memset(&SocketTimeout, 0, sizeof(SocketTimeout));
					#if defined(PLATFORM_WIN)
						SocketTimeout.tv_sec = Parameter.SocketTimeout_Unreliable_Once / SECOND_TO_MILLISECOND;
						SocketTimeout.tv_usec = Parameter.SocketTimeout_Unreliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
					#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
						SocketTimeout = Parameter.SocketTimeout_Unreliable_Once;
					#endif

					//Multiple
						EventArgument_Domain->Protocol_Transport->push_back(IPPROTO_UDP);
						EventArgument_Domain->SocketTimeout->push_back(SocketTimeout);
						EventArgument_Domain->SendBuffer->push_back(std::move(std::make_unique<uint8_t[]>(EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES)));
						memset(EventArgument_Domain->SendBuffer->back().get(), 0, EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES);
						EventArgument_Domain->SendLen->push_back(0);
						EventArgument_Domain->SendTimes->push_back(0);
					}
				}
			}
		}
	}
	else if (EventArgument_Domain->Protocol_Network == AF_INET) //IPv4
	{
	//TCP
		if (Parameter.DomainTest_Protocol == REQUEST_MODE_TEST::BOTH || Parameter.DomainTest_Protocol == REQUEST_MODE_TEST::TCP)
		{
		//Socket settings
			ErrorCode = 0;
			if (
			//Main
				!EventArgument_Domain->SocketValue->SocketValueInit(AF_INET, SOCK_STREAM, IPPROTO_TCP, ntohs(Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_port), &Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_addr, &ErrorCode) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
			//Alternate
				(Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
				(!EventArgument_Domain->SocketValue->SocketValueInit(AF_INET, SOCK_STREAM, IPPROTO_TCP, ntohs(Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_port), &Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr, &ErrorCode) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr))))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event initialization error", ErrorCode, nullptr, 0);
				return false;
			}
			else if (IsFirstLoad)
			{
			//Socket timeout settings
				timeval SocketTimeout;
				memset(&SocketTimeout, 0, sizeof(SocketTimeout));
			#if defined(PLATFORM_WIN)
				SocketTimeout.tv_sec = Parameter.SocketTimeout_Reliable_Once / SECOND_TO_MILLISECOND;
				SocketTimeout.tv_usec = Parameter.SocketTimeout_Reliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				SocketTimeout = Parameter.SocketTimeout_Reliable_Once;
			#endif

			//Main
				EventArgument_Domain->Protocol_Transport->push_back(IPPROTO_TCP);
				EventArgument_Domain->SocketTimeout->push_back(SocketTimeout);
				EventArgument_Domain->SendBuffer->push_back(std::move(std::make_unique<uint8_t[]>(EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES)));
				memset(EventArgument_Domain->SendBuffer->back().get(), 0, EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES);
				EventArgument_Domain->SendLen->push_back(0);
				EventArgument_Domain->SendTimes->push_back(0);

			//Alternate
				if (Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
				{
					EventArgument_Domain->Protocol_Transport->push_back(IPPROTO_TCP);
					EventArgument_Domain->SocketTimeout->push_back(SocketTimeout);
					EventArgument_Domain->SendBuffer->push_back(std::move(std::make_unique<uint8_t[]>(EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES)));
					memset(EventArgument_Domain->SendBuffer->back().get(), 0, EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES);
					EventArgument_Domain->SendLen->push_back(0);
					EventArgument_Domain->SendTimes->push_back(0);
				}
			}

		//Multiple list(IPv4)
			if (Parameter.Target_Server_IPv4_Multiple != nullptr)
			{
				for (const auto &DNS_ServerDataItem:*Parameter.Target_Server_IPv4_Multiple)
				{
					ErrorCode = 0;
					if (!EventArgument_Domain->SocketValue->SocketValueInit(AF_INET, SOCK_STREAM, IPPROTO_TCP, ntohs(DNS_ServerDataItem.AddressData.IPv4.sin_port), &DNS_ServerDataItem.AddressData.IPv4.sin_addr, &ErrorCode) || 
						!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
						!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr) || 
						!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr))
					{
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event initialization error", ErrorCode, nullptr, 0);
						return false;
					}
					else if (IsFirstLoad)
					{
					//Socket timeout settings
						timeval SocketTimeout;
						memset(&SocketTimeout, 0, sizeof(SocketTimeout));
					#if defined(PLATFORM_WIN)
						SocketTimeout.tv_sec = Parameter.SocketTimeout_Reliable_Once / SECOND_TO_MILLISECOND;
						SocketTimeout.tv_usec = Parameter.SocketTimeout_Reliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
					#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
						SocketTimeout = Parameter.SocketTimeout_Reliable_Once;
					#endif

					//Multiple
						EventArgument_Domain->Protocol_Transport->push_back(IPPROTO_TCP);
						EventArgument_Domain->SocketTimeout->push_back(SocketTimeout);
						EventArgument_Domain->SendBuffer->push_back(std::move(std::make_unique<uint8_t[]>(EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES)));
						memset(EventArgument_Domain->SendBuffer->back().get(), 0, EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES);
						EventArgument_Domain->SendLen->push_back(0);
						EventArgument_Domain->SendTimes->push_back(0);
					}
				}
			}
		}

	//UDP
		if (Parameter.DomainTest_Protocol == REQUEST_MODE_TEST::BOTH || Parameter.DomainTest_Protocol == REQUEST_MODE_TEST::UDP)
		{
		//Socket settings
			ErrorCode = 0;
			if (
			//Main
				!EventArgument_Domain->SocketValue->SocketValueInit(AF_INET, SOCK_DGRAM, IPPROTO_UDP, ntohs(Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_port), &Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_addr, &ErrorCode) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr) || 
			//Alternate
				(Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
				(!EventArgument_Domain->SocketValue->SocketValueInit(AF_INET, SOCK_DGRAM, IPPROTO_UDP, ntohs(Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_port), &Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr, &ErrorCode) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))))
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event initialization error", ErrorCode, nullptr, 0);
				return false;
			}
			else if (IsFirstLoad)
			{
			//Socket timeout settings
				timeval SocketTimeout;
				memset(&SocketTimeout, 0, sizeof(SocketTimeout));
			#if defined(PLATFORM_WIN)
				SocketTimeout.tv_sec = Parameter.SocketTimeout_Unreliable_Once / SECOND_TO_MILLISECOND;
				SocketTimeout.tv_usec = Parameter.SocketTimeout_Unreliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				SocketTimeout = Parameter.SocketTimeout_Unreliable_Once;
			#endif

			//Main
				EventArgument_Domain->Protocol_Transport->push_back(IPPROTO_UDP);
				EventArgument_Domain->SocketTimeout->push_back(SocketTimeout);
				EventArgument_Domain->SendBuffer->push_back(std::move(std::make_unique<uint8_t[]>(EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES)));
				memset(EventArgument_Domain->SendBuffer->back().get(), 0, EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES);
				EventArgument_Domain->SendLen->push_back(0);
				EventArgument_Domain->SendTimes->push_back(0);

			//Alternate
				if (Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
				{
					EventArgument_Domain->Protocol_Transport->push_back(IPPROTO_UDP);
					EventArgument_Domain->SocketTimeout->push_back(SocketTimeout);
					EventArgument_Domain->SendBuffer->push_back(std::move(std::make_unique<uint8_t[]>(EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES)));
					memset(EventArgument_Domain->SendBuffer->back().get(), 0, EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES);
					EventArgument_Domain->SendLen->push_back(0);
					EventArgument_Domain->SendTimes->push_back(0);
				}
			}

		//Multiple list(IPv4)
			if (Parameter.Target_Server_IPv4_Multiple != nullptr)
			{
				for (const auto &DNS_ServerDataItem:*Parameter.Target_Server_IPv4_Multiple)
				{
					ErrorCode = 0;
					if (!EventArgument_Domain->SocketValue->SocketValueInit(AF_INET, SOCK_DGRAM, IPPROTO_UDP, ntohs(DNS_ServerDataItem.AddressData.IPv4.sin_port), &DNS_ServerDataItem.AddressData.IPv4.sin_addr, &ErrorCode) || 
						!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
						!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
						!SocketSetting(EventArgument_Domain->SocketValue->ValueSet.back().Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))
					{
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event initialization error", ErrorCode, nullptr, 0);
						return false;
					}
					else if (IsFirstLoad)
					{
					//Socket timeout settings
						timeval SocketTimeout;
						memset(&SocketTimeout, 0, sizeof(SocketTimeout));
					#if defined(PLATFORM_WIN)
						SocketTimeout.tv_sec = Parameter.SocketTimeout_Unreliable_Once / SECOND_TO_MILLISECOND;
						SocketTimeout.tv_usec = Parameter.SocketTimeout_Unreliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
					#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
						SocketTimeout = Parameter.SocketTimeout_Unreliable_Once;
					#endif

					//Multiple
						EventArgument_Domain->Protocol_Transport->push_back(IPPROTO_UDP);
						EventArgument_Domain->SocketTimeout->push_back(SocketTimeout);
						EventArgument_Domain->SendBuffer->push_back(std::move(std::make_unique<uint8_t[]>(EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES)));
						memset(EventArgument_Domain->SendBuffer->back().get(), 0, EventArgument_Domain->SendSize + MEMORY_RESERVED_BYTES);
						EventArgument_Domain->SendLen->push_back(0);
						EventArgument_Domain->SendTimes->push_back(0);
					}
				}
			}
		}
	}
	else {
		return false;
	}

//Make domain test request and connect to server.
	dns_hdr *DNS_Header = nullptr;
	dns_qry *DNS_Query = nullptr;
	bufferevent *BufferEvent = nullptr;
	size_t Result = 0, Index = 0;
	for (Index = 0;Index < EventArgument_Domain->SocketValue->ValueSet.size();++Index)
	{
	//Transport layer check and match DNS header location.
		if (EventArgument_Domain->Protocol_Transport->at(Index) == IPPROTO_TCP)
		{
			DNS_Header = reinterpret_cast<dns_hdr *>(EventArgument_Domain->SendBuffer->at(Index).get() + sizeof(uint16_t));
		}
		else if (EventArgument_Domain->Protocol_Transport->at(Index) == IPPROTO_UDP)
		{
			DNS_Header = reinterpret_cast<dns_hdr *>(EventArgument_Domain->SendBuffer->at(Index).get());
		}
		else {
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event error", 0, nullptr, 0);
			return false;
		}

	//Make fixed part of packet.
		if (EventArgument_Domain->SendLen->at(Index) == 0)
		{
		//TCP DNS header(Part 1)
			if (EventArgument_Domain->Protocol_Transport->at(Index) == IPPROTO_TCP)
				EventArgument_Domain->SendLen->at(Index) += sizeof(uint16_t);

		//DNS header
			DNS_Header->ID = Parameter.DomainTest_ID;
			DNS_Header->Flags = htons(DNS_FLAG_REQUEST_STANDARD);
			DNS_Header->Question = htons(UINT16_NUM_ONE);
			EventArgument_Domain->SendLen->at(Index) += sizeof(dns_hdr);

		//Make fixed domain to test.
			if (Parameter.DomainTest_Data != nullptr)
			{
				memset(EventArgument_Domain->RecvBuffer, 0, EventArgument_Domain->RecvSize);
				const auto DomainLength = StringToPacketQuery(Parameter.DomainTest_Data, EventArgument_Domain->RecvBuffer);
				if (DomainLength > DOMAIN_MINSIZE && DomainLength + sizeof(uint16_t) + sizeof(dns_hdr) < EventArgument_Domain->SendSize)
				{
				//Copy test domain.
					memcpy_s(EventArgument_Domain->SendBuffer->at(Index).get() + EventArgument_Domain->SendLen->at(Index), EventArgument_Domain->SendSize - EventArgument_Domain->SendLen->at(Index), EventArgument_Domain->RecvBuffer, DomainLength);
					memset(EventArgument_Domain->RecvBuffer, 0, EventArgument_Domain->RecvSize);
					EventArgument_Domain->SendLen->at(Index) += DomainLength;
					DNS_Query = reinterpret_cast<dns_qry *>(EventArgument_Domain->SendBuffer->at(Index).get() + EventArgument_Domain->SendLen->at(Index));
					DNS_Query->Classes = htons(DNS_CLASS_INTERNET);
					if (EventArgument_Domain->Protocol_Network == AF_INET6)
					{
						DNS_Query->Type = htons(DNS_TYPE_AAAA);
						EventArgument_Domain->SendLen->at(Index) += sizeof(dns_qry);
					}
					else if (EventArgument_Domain->Protocol_Network == AF_INET)
					{
						DNS_Query->Type = htons(DNS_TYPE_A);
						EventArgument_Domain->SendLen->at(Index) += sizeof(dns_qry);
					}

				//EDNS Label
					if (Parameter.EDNS_Label)
						EventArgument_Domain->SendLen->at(Index) = Add_EDNS_LabelToPacket(EventArgument_Domain->SendBuffer->at(Index).get(), EventArgument_Domain->SendLen->at(Index), EventArgument_Domain->SendSize - EventArgument_Domain->SendLen->at(Index), nullptr);

				//TCP DNS header(Part 2)
					if (EventArgument_Domain->Protocol_Transport->at(Index) == IPPROTO_TCP)
						*reinterpret_cast<uint16_t *>(EventArgument_Domain->SendBuffer->at(Index).get()) = htons(static_cast<uint16_t>(EventArgument_Domain->SendLen->at(Index) - sizeof(uint16_t)));
				}
				else {
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event error", 0, nullptr, 0);
					return false;
				}
			}
		}

	//Generate random domain request everytime.
		if (Parameter.DomainTest_Data == nullptr)
		{
		//Clear data except fixed part.
			memset(EventArgument_Domain->RecvBuffer, 0, EventArgument_Domain->RecvSize);
			GenerateRandomDomain(EventArgument_Domain->RecvBuffer);
			if (EventArgument_Domain->Protocol_Transport->at(Index) == IPPROTO_TCP)
			{
				memset(EventArgument_Domain->SendBuffer->at(Index).get() + sizeof(uint16_t) + sizeof(dns_hdr), 0, EventArgument_Domain->SendSize - sizeof(uint16_t) - sizeof(dns_hdr));
				EventArgument_Domain->SendLen->at(Index) = sizeof(uint16_t) +  sizeof(dns_hdr) + StringToPacketQuery(EventArgument_Domain->RecvBuffer, EventArgument_Domain->SendBuffer->at(Index).get() + sizeof(uint16_t) + sizeof(dns_hdr));
				memset(EventArgument_Domain->RecvBuffer, 0, EventArgument_Domain->RecvSize);
			}
			else if (EventArgument_Domain->Protocol_Transport->at(Index) == IPPROTO_UDP)
			{
				memset(EventArgument_Domain->SendBuffer->at(Index).get() + sizeof(dns_hdr), 0, EventArgument_Domain->SendSize - sizeof(dns_hdr));
				EventArgument_Domain->SendLen->at(Index) = sizeof(dns_hdr) + StringToPacketQuery(EventArgument_Domain->RecvBuffer, EventArgument_Domain->SendBuffer->at(Index).get() + sizeof(dns_hdr));
				memset(EventArgument_Domain->RecvBuffer, 0, EventArgument_Domain->RecvSize);
			}

		//Make DNS query data.
			DNS_Query = reinterpret_cast<dns_qry *>(EventArgument_Domain->SendBuffer->at(Index).get() + EventArgument_Domain->SendLen->at(Index));
			DNS_Query->Classes = htons(DNS_CLASS_INTERNET);
			if (EventArgument_Domain->Protocol_Network == AF_INET6)
			{
				DNS_Query->Type = htons(DNS_TYPE_AAAA);
				EventArgument_Domain->SendLen->at(Index) += sizeof(dns_qry);
			}
			else if (EventArgument_Domain->Protocol_Network == AF_INET)
			{
				DNS_Query->Type = htons(DNS_TYPE_A);
				EventArgument_Domain->SendLen->at(Index) += sizeof(dns_qry);
			}

		//EDNS Label
			if (Parameter.EDNS_Label)
			{
				DNS_Header->Additional = 0;
				EventArgument_Domain->SendLen->at(Index) = Add_EDNS_LabelToPacket(EventArgument_Domain->SendBuffer->at(Index).get(), EventArgument_Domain->SendLen->at(Index), EventArgument_Domain->SendSize, nullptr);
			}

		//TCP DNS header(Part 2)
			if (EventArgument_Domain->Protocol_Transport->at(Index) == IPPROTO_TCP)
				*reinterpret_cast<uint16_t *>(EventArgument_Domain->SendBuffer->at(Index).get()) = htons(static_cast<uint16_t>(EventArgument_Domain->SendLen->at(Index) - sizeof(uint16_t)));
		}

	//Bufferevent initialization
		BufferEvent = bufferevent_socket_new(EventArgument_Domain->EventBase, EventArgument_Domain->SocketValue->ValueSet.at(Index).Socket, 0);
		if (BufferEvent == nullptr)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event error", 0, nullptr, 0);
			return false;
		}
		else {
			EventArgument_Domain->EventBufferList->push_back(BufferEvent);
		}
	
	//Set callback function.
		bufferevent_setcb(EventArgument_Domain->EventBufferList->back(), ReadCallback_TransmissionOnce, WriteCallback_TransmissionOnce, EventCallback_TransmissionOnce, EventArgument_Domain);

	//Set timeouts and water mark.
		if (EventArgument_Domain->Protocol_Transport->at(Index) == IPPROTO_TCP)
		{
		//Set socket timeout.
		#if defined(PLATFORM_WIN)
			EventArgument_Domain->SocketTimeout->at(Index).tv_sec = Parameter.SocketTimeout_Reliable_Once / SECOND_TO_MILLISECOND;
			EventArgument_Domain->SocketTimeout->at(Index).tv_usec = Parameter.SocketTimeout_Reliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			EventArgument_Domain->SocketTimeout->at(Index) = Parameter.SocketTimeout_Reliable_Once;
		#endif

		//Set interval timeout.
		//No need to read any data from bufferevent, set read socket timeout to interval timeout.
			bufferevent_set_timeouts(EventArgument_Domain->EventBufferList->back(), &EventArgument_Domain->IntervalTimeout, &EventArgument_Domain->SocketTimeout->at(Index));
	
		//Set bufferevent water mark.
			bufferevent_setwatermark(EventArgument_Domain->EventBufferList->back(), EV_READ, DNS_PACKET_MINSIZE, 0);
		}
		else if (EventArgument_Domain->Protocol_Transport->at(Index) == IPPROTO_UDP)
		{
		#if defined(PLATFORM_WIN)
			EventArgument_Domain->SocketTimeout->at(Index).tv_sec = Parameter.SocketTimeout_Unreliable_Once / SECOND_TO_MILLISECOND;
			EventArgument_Domain->SocketTimeout->at(Index).tv_usec = Parameter.SocketTimeout_Unreliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			EventArgument_Domain->SocketTimeout->at(Index) = Parameter.SocketTimeout_Unreliable_Once;
		#endif

		//Set interval timeout.
		//No need to read any data from bufferevent, set read socket timeout to interval timeout.
			bufferevent_set_timeouts(EventArgument_Domain->EventBufferList->back(), &EventArgument_Domain->IntervalTimeout, &EventArgument_Domain->SocketTimeout->at(Index));

		//No need to set bufferevent water mark for UDP, because UDP is datagram-oriented protocol.
//			bufferevent_setwatermark(EventArgument_Domain->EventBufferList->back(), EV_READ, DNS_PACKET_MINSIZE, 0);
		}

	//Set highest priority for bufferevents.
		bufferevent_priority_set(EventArgument_Domain->EventBufferList->back(), 0);

	//Enable bufferevent read and write operations.
		if (bufferevent_enable(EventArgument_Domain->EventBufferList->back(), EV_READ | EV_WRITE) == RETURN_ERROR)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event error", 0, nullptr, 0);
			return false;
		}

	//Connect to server and reset send times.
		Result = SocketConnecting(EventArgument_Domain->Protocol_Transport->at(Index), EventArgument_Domain->SocketValue->ValueSet.at(Index).Socket, reinterpret_cast<const sockaddr *>(&EventArgument_Domain->SocketValue->ValueSet.at(Index).SockAddr), EventArgument_Domain->SocketValue->ValueSet.at(Index).AddrLen, EventArgument_Domain->SendBuffer->at(Index).get(), EventArgument_Domain->SendLen->at(Index));
		if (Result >= DNS_PACKET_MINSIZE)
			EventArgument_Domain->SendTimes->at(Index) = 1U;
		else 
			EventArgument_Domain->SendTimes->at(Index) = 0;
	}

	return true;
}

//Get Hop Limits(IPv6) and TTL(IPv4) via normal DNS request
bool TestRequest_Domain(
	const uint16_t Protocol)
{
//Event support initialization
	std::vector<uint16_t> Protocol_Transport;
	std::vector<timeval> SocketTimeout;
	event *TimerEvent = nullptr;
	std::vector<event *> EventList;
	std::vector<bufferevent *> EventBufferList;
	SOCKET_VALUE_TABLE SocketValue_Domain;
	std::vector<std::unique_ptr<uint8_t[]>> SendBufferList;
	const auto RecvBuffer = std::make_unique<uint8_t[]>(Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);
	memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);
	std::vector<size_t> SendLenList;
	std::vector<size_t> SendTimesList;

//Event initialization
	EVENT_TABLE_TRANSMISSION_ONCE EventArgument_Domain;
	EventArgument_Domain.Protocol_Network = Protocol;
	EventArgument_Domain.Protocol_Transport = &Protocol_Transport;
	EventArgument_Domain.SocketTimeout = &SocketTimeout;
	EventArgument_Domain.IntervalTimeout.tv_sec = SENDING_INTERVAL_TIME / SECOND_TO_MILLISECOND;
	EventArgument_Domain.EventBase = event_base_new();
	if (EventArgument_Domain.EventBase == nullptr)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event initialization error", 0, nullptr, 0);
		return false;
	}
	EventArgument_Domain.EventList = &EventList;
	EventArgument_Domain.EventBufferList = &EventBufferList;
	EventArgument_Domain.SocketValue = &SocketValue_Domain;
	EventArgument_Domain.SendBuffer = &SendBufferList;
	EventArgument_Domain.RecvBuffer = RecvBuffer.get();
	EventArgument_Domain.SendSize = Parameter.LargeBufferSize;
	EventArgument_Domain.SendLen = &SendLenList;
	EventArgument_Domain.SendTimes = &SendTimesList;
	EventArgument_Domain.RecvSize = Parameter.LargeBufferSize;
	EventArgument_Domain.FileModifiedTime = GlobalRunningStatus.ConfigFileModifiedTime;

//Set priority to event base, but no need to make sure working.
//Write + Read (Main + Alternate + Multiple servers) > Timer
	event_base_priority_init(EventArgument_Domain.EventBase, 2U);

//Set timer event.
	TimerEvent = evtimer_new(EventArgument_Domain.EventBase, TimerCallback_TransmissionOnce, &EventArgument_Domain);
	if (TimerEvent == nullptr)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event initialization error", 0, nullptr, 0);
		return false;
	}
	else {
		EventArgument_Domain.EventList->push_back(TimerEvent);
	}

//Set lowest priority for timer event.
//	event_priority_set(TimerEvent, 1U);

//Add timer event to event base.
	if (event_add(TimerEvent, &EventArgument_Domain.IntervalTimeout) == RETURN_ERROR)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event initialization error", 0, nullptr, 0);
		return false;
	}

//Load bufferevent.
	if (Parameter.DomainTest_Speed > 0)
	{
		LoadBufferEvent_DomainTest(&EventArgument_Domain);
		++EventArgument_Domain.OnceTimes;
	}

//Event loop.
	event_base_dispatch(EventArgument_Domain.EventBase);

//Monitor terminated
	PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Domain Test module Monitor terminated", 0, nullptr, 0);
	return false;
}

//Internet Control Message Protocol/ICMP echo request(Ping)
bool TestRequest_ICMP(
	const uint16_t Protocol)
{
//Protocol check
	size_t DataLength = 0;
	if (Protocol == AF_INET6)
	{
		DataLength = sizeof(icmpv6_hdr) + Parameter.ICMP_PaddingLength;
	}
	else if (Protocol == AF_INET)
	{
		DataLength = sizeof(icmp_hdr) + Parameter.ICMP_PaddingLength;
	}
	else {
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", 0, nullptr, 0);
		return false;
	}

//Initialization
	const auto SendBuffer = std::make_unique<uint8_t[]>(DataLength + MEMORY_RESERVED_BYTES);
	memset(SendBuffer.get(), 0, DataLength + MEMORY_RESERVED_BYTES);
	SOCKET_VALUE_TABLE SocketValue_ICMP;
	ssize_t ErrorCode = 0;

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
//		ICMPv6_Header->Checksum = 0;

	//Socket initialization
	//Windows: Use SOCK_RAW type with IPPROTO_ICMPV6.
	//Linux: Use SOCK_RAW type with IPPROTO_ICMPV6, also support SOCK_DGRAM type but default disabled.
	//macOS: Use SOCK_DGRAM type with IPPROTO_ICMPV6.
		ErrorCode = 0;
		if (
		//Main
		#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
			!SocketValue_ICMP.SocketValueInit(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, 0, &Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr, &ErrorCode) || 
		#elif defined(PLATFORM_MACOS)
			!SocketValue_ICMP.SocketValueInit(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6, 0, &Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr, &ErrorCode) || 
		#endif
			!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
			!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr) || 
//			!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::CHECKSUM_IPV6, true, &OptionValue) //ICMPv6 protocol checksum will always be calculated by network stack in all platforms.
		//Alternate
			(Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
		#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
			(!SocketValue_ICMP.SocketValueInit(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, 0, &Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr, &ErrorCode) || 
		#elif defined(PLATFORM_MACOS)
			(!SocketValue_ICMP.SocketValueInit(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6, 0, &Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr, &ErrorCode) || 
		#endif
			!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
			!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr) // || 
//			!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::CHECKSUM_IPV6, true, &OptionValue) //ICMPv6 protocol checksum will always be calculated by network stack in all platforms.
			)))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", ErrorCode, nullptr, 0);
			return false;
		}

	//Multiple list(IPv6)
		if (Parameter.Target_Server_IPv6_Multiple != nullptr)
		{
			for (const auto &DNS_ServerDataItem:*Parameter.Target_Server_IPv6_Multiple)
			{
				ErrorCode = 0;
				if (
				#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
					!SocketValue_ICMP.SocketValueInit(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6, 0, &DNS_ServerDataItem.AddressData.IPv6.sin6_addr, &ErrorCode) || 
				#elif defined(PLATFORM_MACOS)
					!SocketValue_ICMP.SocketValueInit(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6, 0, &DNS_ServerDataItem.AddressData.IPv6.sin6_addr, &ErrorCode) || 
				#endif
					!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr) // || 
//					!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::CHECKSUM_IPV6, true, &OptionValue) //ICMPv6 protocol checksum will always be calculated by network stack in all platforms.
					)
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", ErrorCode, nullptr, 0);
					return false;
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
		ICMP_Header->Checksum = GetChecksum_Internet(reinterpret_cast<uint16_t *>(SendBuffer.get()), DataLength);

	//Socket initialization
	//Windows: Use SOCK_RAW type with IPPROTO_ICMP.
	//Linux: Use SOCK_RAW type with IPPROTO_ICMP, also support SOCK_DGRAM type but default disabled and need to set <net.ipv4.ping_group_range='0 10'>.
	//macOS: Use SOCK_DGRAM type with IPPROTO_ICMP.
		ErrorCode = 0;
		if (
		//Main
		#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
			!SocketValue_ICMP.SocketValueInit(AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, &Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_addr, &ErrorCode) || 
		#elif defined(PLATFORM_MACOS)
			!SocketValue_ICMP.SocketValueInit(AF_INET, SOCK_DGRAM, IPPROTO_ICMP, 0, &Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_addr, &ErrorCode) || 
		#endif
			!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
			!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
			!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr) || 
		//Alternate
			(Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
		#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
			(!SocketValue_ICMP.SocketValueInit(AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, &Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr, &ErrorCode) || 
		#elif defined(PLATFORM_MACOS)
			(!SocketValue_ICMP.SocketValueInit(AF_INET, SOCK_DGRAM, IPPROTO_ICMP, 0, &Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr, &ErrorCode) || 
		#endif
			!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
			!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
			!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", ErrorCode, nullptr, 0);
			return false;
		}

	//Multiple list(IPv4)
		if (Parameter.Target_Server_IPv4_Multiple != nullptr)
		{
			for (const auto &DNS_ServerDataItem:*Parameter.Target_Server_IPv4_Multiple)
			{
				ErrorCode = 0;
				if (
				#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
					!SocketValue_ICMP.SocketValueInit(AF_INET, SOCK_RAW, IPPROTO_ICMP, 0, &DNS_ServerDataItem.AddressData.IPv4.sin_addr, &ErrorCode) || 
				#elif defined(PLATFORM_MACOS)
					!SocketValue_ICMP.SocketValueInit(AF_INET, SOCK_DGRAM, IPPROTO_ICMP, 0, &DNS_ServerDataItem.AddressData.IPv4.sin_addr, &ErrorCode) || 
				#endif
					!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
					!SocketSetting(SocketValue_ICMP.ValueSet.back().Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", ErrorCode, nullptr, 0);
					return false;
				}
			}
		}
	}
	else {
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", 0, nullptr, 0);
		return false;
	}

//Event support initialization
	const auto RecvBuffer = std::make_unique<uint8_t[]>(Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);
	memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);
	event *TimerEvent = nullptr;
	std::vector<event *> EventList;
	size_t Priority = 0;

//Event initialization
	EVENT_TABLE_SOCKET_SEND EventArgument_ICMP;
	EventArgument_ICMP.Protocol = Protocol;
#if defined(PLATFORM_WIN)
	EventArgument_ICMP.SocketTimeout.tv_sec = Parameter.SocketTimeout_Unreliable_Once / SECOND_TO_MILLISECOND;
	EventArgument_ICMP.SocketTimeout.tv_usec = Parameter.SocketTimeout_Unreliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	EventArgument_ICMP.SocketTimeout = Parameter.SocketTimeout_Unreliable_Once;
#endif
	EventArgument_ICMP.IntervalTimeout.tv_sec = SENDING_INTERVAL_TIME / SECOND_TO_MILLISECOND;
	EventArgument_ICMP.EventBase = event_base_new();
	if (EventArgument_ICMP.EventBase == nullptr)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", 0, nullptr, 0);
		goto StopLoop;
	}
	EventArgument_ICMP.EventList = &EventList;
	EventArgument_ICMP.SocketValue = &SocketValue_ICMP;
	EventArgument_ICMP.SendBuffer = SendBuffer.get();
	EventArgument_ICMP.RecvBuffer = RecvBuffer.get();
	EventArgument_ICMP.SendSize = DataLength;
	EventArgument_ICMP.RecvSize = Parameter.LargeBufferSize;
	EventArgument_ICMP.FileModifiedTime = GlobalRunningStatus.ConfigFileModifiedTime;

//Set priority level to event base.
//Write (Main > Alternate > Multiple servers) > Read > Timer
	if (SocketValue_ICMP.ValueSet.size() + 2U < EVENT_MAX_PRIORITIES)
		event_base_priority_init(EventArgument_ICMP.EventBase, static_cast<int>(SocketValue_ICMP.ValueSet.size() + 2U));

//Set timer event.
	TimerEvent = evtimer_new(EventArgument_ICMP.EventBase, TimerCallback_SocketSend, &EventArgument_ICMP);
	if (TimerEvent == nullptr)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", 0, nullptr, 0);
		goto StopLoop;
	}
	else {
		EventArgument_ICMP.EventList->push_back(TimerEvent);
	}

//Set lowest priority level for timer event.
	event_priority_set(EventArgument_ICMP.EventList->back(), static_cast<int>(SocketValue_ICMP.ValueSet.size() + 1U));

//Add timer event to event base.
	if (event_add(EventArgument_ICMP.EventList->back(), &EventArgument_ICMP.IntervalTimeout) == RETURN_ERROR)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event initialization error", 0, nullptr, 0);
		goto StopLoop;
	}

//Set read and write events.
	for (auto &SocketDataItem:EventArgument_ICMP.SocketValue->ValueSet)
	{
	//Make read events.
		const auto ReadEvent = event_new(EventArgument_ICMP.EventBase, SocketDataItem.Socket, EV_READ | EV_PERSIST, ReadCallback_SocketSend, &EventArgument_ICMP);
		if (ReadEvent == nullptr)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event error", 0, nullptr, 0);
			goto StopLoop;
		}
		else {
			EventArgument_ICMP.EventList->push_back(ReadEvent);
		}

	//Make write events.
		const auto WriteEvent = event_new(EventArgument_ICMP.EventBase, SocketDataItem.Socket, EV_WRITE, WriteCallback_SocketSend, &EventArgument_ICMP);
		if (WriteEvent == nullptr)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event error", 0, nullptr, 0);
			goto StopLoop;
		}
		else {
			EventArgument_ICMP.EventList->push_back(WriteEvent);
		}

	//Set second lowest priority level for read events and decrement priority level for write events.
		event_priority_set(ReadEvent, static_cast<int>(SocketValue_ICMP.ValueSet.size()));
		event_priority_set(WriteEvent, static_cast<int>(Priority));
		++Priority;

	//Add events to event base.
		if (event_add(ReadEvent, &EventArgument_ICMP.IntervalTimeout) == RETURN_ERROR || //No need to read any data from socket, set socket timeout to interval timeout.
			(Parameter.ICMP_Speed > 0 && event_add(WriteEvent, &EventArgument_ICMP.SocketTimeout) == RETURN_ERROR))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event error", 0, nullptr, 0);
			goto StopLoop;
		}
	}

//Event loop.
	++EventArgument_ICMP.OnceTimes;
	event_base_dispatch(EventArgument_ICMP.EventBase);

//Jump here to stop loop.
StopLoop:

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
	const uint16_t QueryType, 
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
	if (SelectTargetSocketSingle(RequestType, IPPROTO_TCP, QueryType, LocalSocketData, &TCPSocketDataList.front(), &IsAlternate, &AlternateTimeoutTimes, SpecifieTargetData, nullptr, nullptr) == EXIT_FAILURE)
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
	const uint16_t Protocol_Network, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA * const LocalSocketData)
{
//Initialization
	memset(OriginalRecv, 0, RecvSize);
	const auto SendBuffer = OriginalRecv;
	memcpy_s(SendBuffer, RecvSize, OriginalSend, SendSize);

//Socket initialization
	std::vector<SOCKET_DATA> TCPSocketDataList;
	if (!SelectTargetSocketMultiple(Protocol_Network, IPPROTO_TCP, QueryType, LocalSocketData, TCPSocketDataList))
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
			++AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6);
		else if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in)) //IPv4
			++AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4);
	}

//Close all sockets.
	for (auto &SocketItem:TCPSocketDataList)
	{
		if (SocketSetting(SocketItem.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			SocketSetting(SocketItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
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
	const uint16_t QueryType, 
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
	if (SelectTargetSocketSingle(RequestType, IPPROTO_UDP, QueryType, LocalSocketData, &UDPSocketDataList.front(), &IsAlternate, &AlternateTimeoutTimes, nullptr, nullptr, nullptr) == EXIT_FAILURE)
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
		for (auto &SocketDataItem:UDPSocketDataList)
			SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Mark port to list.
	RegisterPortToList(Protocol, LocalSocketData, UDPSocketDataList, EDNS_Length);
	return EXIT_SUCCESS;
}

//Transmission of UDP protocol(Multiple threading)
size_t UDP_RequestMultiple(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol_Network, 
	const uint16_t Protocol_Transport, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	const uint16_t QueryType, 
	const SOCKET_DATA * const LocalSocketData, 
	size_t *EDNS_Length)
{
//Socket initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	if (!SelectTargetSocketMultiple(Protocol_Network, IPPROTO_UDP, QueryType, LocalSocketData, UDPSocketDataList))
		return EXIT_FAILURE;

//Socket selecting
	const auto RecvLen = SocketSelectingOnce(RequestType, IPPROTO_UDP, UDPSocketDataList, nullptr, OriginalSend, SendSize, nullptr, 0, nullptr, LocalSocketData);
	if (RecvLen != EXIT_SUCCESS)
	{
		for (auto &SocketDataItem:UDPSocketDataList)
			SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Mark port to list.
	RegisterPortToList(Protocol_Transport, LocalSocketData, UDPSocketDataList, EDNS_Length);
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
	const uint16_t QueryType, 
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
	if (SelectTargetSocketSingle(RequestType, IPPROTO_UDP, QueryType, LocalSocketData, &UDPSocketDataList.front(), &IsAlternate, &AlternateTimeoutTimes, SpecifieTargetData, nullptr, nullptr) == EXIT_FAILURE)
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
	const uint16_t QueryType, 
	const SOCKET_DATA * const LocalSocketData)
{
//Initialization
	memset(OriginalRecv, 0, RecvSize);

//Socket initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	if (!SelectTargetSocketMultiple(0, IPPROTO_UDP, QueryType, LocalSocketData, UDPSocketDataList))
		return EXIT_FAILURE;

//Socket selecting
	ssize_t ErrorCode = 0;
	const auto RecvLen = SocketSelectingOnce(RequestType, IPPROTO_UDP, UDPSocketDataList, nullptr, OriginalSend, SendSize, OriginalRecv, RecvSize, &ErrorCode, LocalSocketData);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultipleRequest) //Mark timeout.
	{
		if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in6)) //IPv6
			++AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6);
		else if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in)) //IPv4
			++AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4);
	}

//Close all sockets.
	for (auto &SocketItem:UDPSocketDataList)
	{
		if (SocketSetting(SocketItem.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			SocketSetting(SocketItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	}

	return RecvLen;
}
