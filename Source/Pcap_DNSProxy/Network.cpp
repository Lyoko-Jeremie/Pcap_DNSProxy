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


#include "Network.h"

//Socket option settings
bool SocketSetting(
	SYSTEM_SOCKET &Socket, 
	const SOCKET_SETTING_TYPE SettingType, 
	const bool IsPrintError, 
	void * const DataPointer)
{
	switch (SettingType)
	{
/* ICMPv6 protocol checksum will always be calculated by network stack in all platforms.
	//Socket checksum offset setting
		case SOCKET_SETTING_TYPE::CHECKSUM_IPV6:
		{
		//Pointer check
			if (DataPointer == nullptr)
				return false;

		//Socket timeout options
			if (setsockopt(Socket, IPPROTO_IPV6, IPV6_CHECKSUM, reinterpret_cast<const char *>(DataPointer), sizeof(int)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket IPv6 checksum settings error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
				Socket = INVALID_SOCKET;

				return false;
			}
		}break;
*/
	//Socket closing process
		case SOCKET_SETTING_TYPE::CLOSE:
		{
		#if defined(PLATFORM_WIN)
			if (Socket != INVALID_SOCKET && Socket != SOCKET_ERROR)
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (Socket != INVALID_SOCKET)
		#endif
			{
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
				Socket = INVALID_SOCKET;
			}
		}break;
	//Socket attribute setting(IPv4 header Do Not Fragment flag)
		case SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT:
		{
		#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_WIN))
			if (Parameter.DoNotFragment_IPv4)
			{
			#if defined(PLATFORM_WIN)
				const DWORD OptionValue = 1U;
				if (setsockopt(Socket, IPPROTO_IP, IP_DONTFRAGMENT, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#elif defined(PLATFORM_FREEBSD)
				const int OptionValue = 1;
				if (setsockopt(Socket, IPPROTO_IP, IP_DONTFRAG, &OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#elif defined(PLATFORM_LINUX)
				const int OptionValue = IP_PMTUDISC_DO;
				if (setsockopt(Socket, IPPROTO_IP, IP_MTU_DISCOVER, &OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket Do Not Fragment flag settings error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);
					Socket = INVALID_SOCKET;

					return false;
				}
			}
		#endif
		}break;
	//Socket attribute setting(IPv6 header Hop Limts)
		case SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6:
		{
		//Range
			if (Parameter.PacketHopLimits_IPv6_End > 0)
			{
			//Socket attribute settings process
			#if defined(PLATFORM_WIN)
				DWORD OptionValue = 0;
				GenerateRandomBuffer(&OptionValue, sizeof(OptionValue), nullptr, Parameter.PacketHopLimits_IPv6_Begin, Parameter.PacketHopLimits_IPv6_End);
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				int OptionValue = 0;
				GenerateRandomBuffer(&OptionValue, sizeof(OptionValue), nullptr, Parameter.PacketHopLimits_IPv6_Begin, Parameter.PacketHopLimits_IPv6_End);
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket Hop Limits settings error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);
					Socket = INVALID_SOCKET;

					return false;
				}
			}
		//Value
			else if (Parameter.PacketHopLimits_IPv6_Begin > 0)
			{
			#if defined(PLATFORM_WIN)
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, reinterpret_cast<const char *>(&Parameter.PacketHopLimits_IPv6_Begin), sizeof(Parameter.PacketHopLimits_IPv6_Begin)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &Parameter.PacketHopLimits_IPv6_Begin, sizeof(Parameter.PacketHopLimits_IPv6_Begin)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket Hop Limits settings error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);
					Socket = INVALID_SOCKET;

					return false;
				}
			}
		}break;
	//Socket attribute setting(IPv4 header TTL)
		case SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4:
		{
		//Range
			if (Parameter.PacketHopLimits_IPv4_End > 0)
			{
			//Socket attribute settings process
			#if defined(PLATFORM_WIN)
				DWORD OptionValue = 0;
				GenerateRandomBuffer(&OptionValue, sizeof(OptionValue), nullptr, Parameter.PacketHopLimits_IPv4_Begin, Parameter.PacketHopLimits_IPv4_End);
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				int OptionValue = 0;
				GenerateRandomBuffer(&OptionValue, sizeof(OptionValue), nullptr, Parameter.PacketHopLimits_IPv4_Begin, Parameter.PacketHopLimits_IPv4_End);
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, &OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket Hop Limits settings error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);
					Socket = INVALID_SOCKET;

					return false;
				}
			}
		//Value
			else if (Parameter.PacketHopLimits_IPv4_Begin > 0)
			{
			#if defined(PLATFORM_WIN)
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, reinterpret_cast<const char *>(&Parameter.PacketHopLimits_IPv4_Begin), sizeof(Parameter.PacketHopLimits_IPv4_Begin)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, &Parameter.PacketHopLimits_IPv4_Begin, sizeof(Parameter.PacketHopLimits_IPv4_Begin)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket Hop Limits settings error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);
					Socket = INVALID_SOCKET;

					return false;
				}
			}
		}break;
	//Socket invalid check
		case SOCKET_SETTING_TYPE::INVALID_CHECK:
		{
		#if defined(PLATFORM_WIN)
			if (Socket == 0 || Socket == INVALID_SOCKET || Socket == SOCKET_ERROR)
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (Socket == 0 || Socket == INVALID_SOCKET)
		#endif
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket initialization error", WSAGetLastError(), nullptr, 0);

				return false;
			}
		}break;
	//Socket attribute setting(Non-blocking mode)
		case SOCKET_SETTING_TYPE::NON_BLOCKING_MODE:
		{
		#if defined(PLATFORM_WIN)
			unsigned long SocketMode = 1U;
			if (ioctlsocket(Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			const auto SocketMode = fcntl(Socket, F_GETFL, 0);
			if (SocketMode == RETURN_ERROR || fcntl(Socket, F_SETFL, SocketMode | O_NONBLOCK) == RETURN_ERROR)
		#endif
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket non-blocking mode settings error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
				Socket = INVALID_SOCKET;

				return false;
			}
		}break;
	//Socket attribute setting(Reusing)
		case SOCKET_SETTING_TYPE::REUSE:
		{
		#if defined(PLATFORM_WIN)
		//Windows: Preventing other sockets from being forcibly bound to the same address and port.
			const DWORD OptionValue = 1U;
			if (setsockopt(Socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket reusing disabled settings error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
				Socket = INVALID_SOCKET;

				return false;
			}
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			const int OptionValue = 1;

		//Linux and macOS: Set TIME_WAIT resuing.
/*			errno = 0;
			if (setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket reusing enabled settings error", errno, nullptr, 0);
				shutdown(Socket, SHUT_RDWR);
				close(Socket);
				Socket = INVALID_SOCKET;

				return false;
			}
*/
		//Linux and macOS: Set an IPv6 server socket that must not accept IPv4 connections.
			errno = 0;
			if (setsockopt(Socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket treating wildcard binding settings error", errno, nullptr, 0);
				shutdown(Socket, SHUT_RDWR);
				close(Socket);
				Socket = INVALID_SOCKET;

				return false;
			}
		#endif
		}break;
	//Socket attribute setting(TCP No Delay)
		case SOCKET_SETTING_TYPE::TCP_NO_DELAY:
		{
		#if defined(PLATFORM_WIN)
			const BOOL OptionValue = TRUE;
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			const int OptionValue = 1;
		#endif
			if (setsockopt(Socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket no delay mode settings error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
				Socket = INVALID_SOCKET;

				return false;
			}
		}break;
	//Socket attribute setting(TFO/TCP Fast Open)
		case SOCKET_SETTING_TYPE::TCP_FAST_OPEN:
		{
		//Socket attribute settings process
			if (Parameter.TCP_FastOpen > 0)
			{
			//Windows: Server side is completed, client side is only support overlapped I/O. Waiting Microsoft extends it to normal socket(2018-09-30).
			//Linux: Server side and client side are both completed, also support queue length.
			//macOS: Server side and client side are both completed.
			#if defined(PLATFORM_WIN)
			#if !defined(PLATFORM_WIN_XP)
				const DWORD OptionValue = 1U;
				if (setsockopt(Socket, IPPROTO_TCP, TCP_FASTOPEN, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket TCP Fast Open settings error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);
					Socket = INVALID_SOCKET;

					return false;
				}
			#endif
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				errno = 0;
			#if defined(PLATFORM_FREEBSD)
				const int OptionValue = Parameter.TCP_FastOpen;
				if (setsockopt(Socket, IPPROTO_TCP, TCP_FASTOPEN, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#elif defined(PLATFORM_LINUX)
				const int OptionValue = Parameter.TCP_FastOpen;
				if (setsockopt(Socket, SOL_TCP, TCP_FASTOPEN, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#elif defined(PLATFORM_MACOS)
				const int OptionValue = 1;
				if (setsockopt(Socket, IPPROTO_TCP, TCP_FASTOPEN, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket TCP Fast Open settings error", errno, nullptr, 0);
					shutdown(Socket, SHUT_RDWR);
					close(Socket);
					Socket = INVALID_SOCKET;

					return false;
				}
			#endif
			}
		}break;
	//Socket attribute setting(TCP keep alive mode)
		case SOCKET_SETTING_TYPE::TCP_KEEP_ALIVE:
		{
		#if defined(PLATFORM_WIN)
			const DWORD OptionValue = 1U;
			if (setsockopt(Socket, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			{
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
				Socket = INVALID_SOCKET;

				return false;
			}

		//TCP keepalive settings
			tcp_keepalive AliveTransport_IN;
			tcp_keepalive AliveTransport_OUT;
			memset(&AliveTransport_IN, 0, sizeof(tcp_keepalive));
			memset(&AliveTransport_OUT, 0, sizeof(tcp_keepalive));
			AliveTransport_IN.onoff = 1U;
			AliveTransport_IN.keepalivetime = Parameter.SocketTimeout_Reliable_Once;
			AliveTransport_IN.keepaliveinterval = STANDARD_TIMEOUT;
			ULONG ulBytesReturn = 0;
			if (WSAIoctl(Socket, SIO_KEEPALIVE_VALS, &AliveTransport_IN, sizeof(tcp_keepalive), &AliveTransport_OUT, sizeof(tcp_keepalive), &ulBytesReturn, nullptr, nullptr) == SOCKET_ERROR)
			{
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
				Socket = INVALID_SOCKET;

				return false;
			}
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			const int OptionValue = 1;
			if (setsockopt(Socket, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			{
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
				Socket = INVALID_SOCKET;

				return false;
			}
		#endif
		}break;
	//Socket attribute setting(Timeout)
		case SOCKET_SETTING_TYPE::TIMEOUT:
		{
		//Pointer check
			if (DataPointer == nullptr)
				return false;

		//Socket timeout options
		#if defined(PLATFORM_WIN)
			const auto OptionValue = *reinterpret_cast<const DWORD *>(DataPointer);
			if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR || 
				setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(DataPointer), sizeof(timeval)) == SOCKET_ERROR || 
				setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(DataPointer), sizeof(timeval)) == SOCKET_ERROR)
		#endif
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket timeout settings error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
				Socket = INVALID_SOCKET;

				return false;
			}
		}break;
	//Socket attribute setting(Block UDP RESET message)
		case SOCKET_SETTING_TYPE::UDP_BLOCK_RESET:
		{
		#if defined(PLATFORM_WIN)
			BOOL NewBehavior = FALSE;
			DWORD BytesReturned = 0;
			if (WSAIoctl(Socket, SIO_UDP_CONNRESET, &NewBehavior, sizeof(BOOL), nullptr, 0, &BytesReturned, nullptr, nullptr) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket UDP block RESET message settings error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
				Socket = INVALID_SOCKET;

				return false;
			}
		#endif
		}break;
	}

	return true;
}

#if defined(ENABLE_PCAP)
//Original socket send only read callback
void ReadCallback_SocketSend(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument)
{
//Mark arguments.
	if (Argument == nullptr)
		return;
	const auto CallbackArgument = reinterpret_cast<EVENT_TABLE_SOCKET_SEND *>(Argument);

//Match active socket in the list.
	SOCKET_DATA SocketDataTemp;
	memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
	for (const auto &SocketDataItem:CallbackArgument->SocketValue->ValueSet)
	{
		if (static_cast<const evutil_socket_t>(SocketDataItem.Socket) == Socket)
		{
			SocketDataTemp = SocketDataItem;
			break;
		}
	}

//Socket data check
	if (SocketDataTemp.Socket == 0)
		return;

//Drop all responses.
	while (recvfrom(Socket, reinterpret_cast<char *>(CallbackArgument->RecvBuffer), static_cast<const int>(CallbackArgument->RecvSize), 0, reinterpret_cast<sockaddr *>(&SocketDataTemp.SockAddr), &SocketDataTemp.AddrLen) > 0)
		memset(CallbackArgument->RecvBuffer, 0, CallbackArgument->RecvSize);

	return;
}

//Original socket send only write callback
void WriteCallback_SocketSend(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument)
{
//Mark arguments.
	if (Argument == nullptr)
		return;
	const auto CallbackArgument = reinterpret_cast<EVENT_TABLE_SOCKET_SEND *>(Argument);

//Match active socket in the list.
	SOCKET_DATA SocketDataTemp;
	memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
	for (const auto &SocketDataItem:CallbackArgument->SocketValue->ValueSet)
	{
		if (static_cast<const evutil_socket_t>(SocketDataItem.Socket) == Socket)
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
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
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
	#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		Timestamp = time(nullptr);
		if (Timestamp < 0)
			Timestamp = 0;
	#endif

	//Set header data.
		if (CallbackArgument->Protocol == AF_INET6)
		{
		//Sequence
			if (Parameter.ICMP_Sequence == 0)
			{
				if (CallbackArgument->PacketSequence == 0)
					CallbackArgument->PacketSequence = hton16(ntoh16(CallbackArgument->PacketSequence) + 1U);
				ICMPv6_Header->Sequence = CallbackArgument->PacketSequence;
			}

		//Timestamp and Nonce
		#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			ICMPv6_Header->Timestamp = static_cast<const uint64_t>(Timestamp);
		#if defined(PLATFORM_LINUX)
			GenerateRandomBuffer(&ICMPv6_Header->Nonce, sizeof(ICMPv6_Header->Nonce), nullptr, 0, 0);
		#endif
		#endif
		}
		else if (CallbackArgument->Protocol == AF_INET)
		{
		//Sequence
			if (Parameter.ICMP_Sequence == 0)
			{
				if (CallbackArgument->PacketSequence == 0)
					CallbackArgument->PacketSequence = hton16(ntoh16(CallbackArgument->PacketSequence) + 1U);
				ICMP_Header->Sequence = CallbackArgument->PacketSequence;
			}

		//Timestamp and Nonce
		#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			ICMP_Header->Timestamp = static_cast<const uint64_t>(Timestamp);
		#if defined(PLATFORM_LINUX)
			GenerateRandomBuffer(&ICMP_Header->Nonce, sizeof(ICMP_Header->Nonce), nullptr, 0, 0);
		#endif
		#endif

		//Checksum calculating
			ICMP_Header->Checksum = 0;
			ICMP_Header->Checksum = GetChecksum_Internet(reinterpret_cast<const uint16_t *>(CallbackArgument->SendBuffer), CallbackArgument->SendSize);
		}

	//Send request.
		sendto(Socket, reinterpret_cast<const char *>(CallbackArgument->SendBuffer), static_cast<const int>(CallbackArgument->SendSize), 0, reinterpret_cast<const sockaddr *>(&SocketDataTemp.SockAddr), SocketDataTemp.AddrLen);
	}

	return;
}

//Original socket send only timer callback
void TimerCallback_SocketSend(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument)
{
//Mark arguments.
	if (Argument == nullptr)
		return;
	const auto CallbackArgument = reinterpret_cast<EVENT_TABLE_SOCKET_SEND *>(Argument);

//Interval time controller
	if (Parameter.ICMP_Speed == 0 || //ICMP Test disable
		event_base_get_num_events(CallbackArgument->EventBase, EVENT_BASE_COUNT_ACTIVE) > 0) //Waiting all callback finished.
	{
	//Set interval timeout.
	#if defined(PLATFORM_WIN)
		CallbackArgument->IntervalTimeout.tv_sec = static_cast<const DWORD>(Parameter.FileRefreshTime) / SECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		CallbackArgument->IntervalTimeout.tv_sec = Parameter.FileRefreshTime / SECOND_TO_MILLISECOND;
	#endif

	//Reset next recheck process.
		if (Parameter.ICMP_Speed == 0)
		{
			CallbackArgument->TotalSleepTime = 0;
			CallbackArgument->OnceTimes = 0;
			CallbackArgument->RetestTimes = 0;
		}

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

		//Multiple list
			if (IsHopLimitExist && Parameter.Target_Server_IPv6_Multiple != nullptr)
			{
				for (const auto &DNS_ServerDataItem:*Parameter.Target_Server_IPv6_Multiple)
				{
					if (DNS_ServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad == 0 && 
						DNS_ServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark == 0)
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

		//Multiple list
			if (IsHopLimitExist && Parameter.Target_Server_IPv4_Multiple != nullptr)
			{
				for (const auto &DNS_ServerDataItem:*Parameter.Target_Server_IPv4_Multiple)
				{
					if (DNS_ServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad == 0 && DNS_ServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark == 0)
					{
						IsHopLimitExist = false;
						break;
					}
				}
			}
		}

	//Keep to retest if no any available gateways.
		if (!GlobalRunningStatus.GatewayAvailable_IPv6 && !GlobalRunningStatus.GatewayAvailable_IPv4)
			CallbackArgument->RetestTimes = 0;

	//Retest if Hop Limits/TTLs are not exist or retest not more than a value times.
		if (IsHopLimitExist || CallbackArgument->RetestTimes + 1U >= SENDING_MAX_INTERVAL_TIMES)
		{
		//Mark total sleep time.
			size_t LoopInterval = 0;
			if (Parameter.ICMP_Speed < Parameter.FileRefreshTime)
				LoopInterval = Parameter.ICMP_Speed;
			else 
				LoopInterval = Parameter.FileRefreshTime;
			CallbackArgument->TotalSleepTime += LoopInterval;

		//Interval time is enough or configuration file modified, reset retest times.
			if (CallbackArgument->TotalSleepTime >= Parameter.ICMP_Speed || 
				CallbackArgument->FileModifiedTime != GlobalRunningStatus.ConfigFileModifiedTime)
			{
				CallbackArgument->RetestTimes = 0;
				CallbackArgument->FileModifiedTime = GlobalRunningStatus.ConfigFileModifiedTime;
			}
		//Interval time is not enough.
			else {
			#if defined(PLATFORM_WIN)
				CallbackArgument->IntervalTimeout.tv_sec = static_cast<const DWORD>(LoopInterval) / SECOND_TO_MILLISECOND;
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				CallbackArgument->IntervalTimeout.tv_sec = LoopInterval / SECOND_TO_MILLISECOND;
			#endif

			//Add timer event again.
				if (event_add(CallbackArgument->EventList->front(), &CallbackArgument->IntervalTimeout) == RETURN_ERROR)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"ICMP Test event error", 0, nullptr, 0);

				return;
			}
		}
	//Mark retest times.
		else if (GlobalRunningStatus.GatewayAvailable_IPv6 || GlobalRunningStatus.GatewayAvailable_IPv4)
		{
			++CallbackArgument->RetestTimes;
		}

	//Interval time is enough, next recheck process.
		CallbackArgument->TotalSleepTime = 0;
		CallbackArgument->OnceTimes = 1U;
	}

//Increase sequence.
	if (Parameter.ICMP_Sequence == 0)
	{
		if (CallbackArgument->PacketSequence == UINT16_MAX)
			CallbackArgument->PacketSequence = hton16(UINT16_NUM_ONE);
		else 
			CallbackArgument->PacketSequence = hton16(ntoh16(CallbackArgument->PacketSequence) + 1U);
	}

//Reset socket timeout.
#if defined(PLATFORM_WIN)
	CallbackArgument->SocketTimeout.tv_sec = Parameter.SocketTimeout_Unreliable_Once / SECOND_TO_MILLISECOND;
	CallbackArgument->SocketTimeout.tv_usec = Parameter.SocketTimeout_Unreliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	CallbackArgument->SocketTimeout = Parameter.SocketTimeout_Unreliable_Once;
#endif

//Repeat events.
	auto IsTimerEvent = true, IsWriteEvent = true;
	for (const auto &EventItem:*CallbackArgument->EventList)
	{
	//Timer, Socket 1 Read, Socket 1 Write, Socket 2 Read, Socket 2 Write..
		if (IsWriteEvent)
		{
			if (IsTimerEvent)
			{
			//Reset interval timeout.
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

//Bufferevent transmission once event callback
void EventCallback_TransmissionOnce(
	bufferevent *BufferEvent, 
	short EventType, 
	void *Argument)
{
//Mark arguments.
	if (Argument == nullptr)
		return;
	const auto CallbackArgument = reinterpret_cast<EVENT_TABLE_TRANSMISSION_ONCE *>(Argument);

//Match active bufferevent in the list.
	size_t Index = 0;
	for (Index = 0;Index < CallbackArgument->EventBufferList->size();++Index)
	{
		if (CallbackArgument->EventBufferList->at(Index) == BufferEvent)
			break;
		else if (Index + 1U == CallbackArgument->EventBufferList->size())
			return;
	}

//Connection finished, error or timeout
	if ((EventType & BEV_EVENT_EOF) > 0 || (EventType & BEV_EVENT_ERROR) > 0 || (EventType & BEV_EVENT_TIMEOUT) > 0)
	{
		if (CallbackArgument->EventBufferList->at(Index) != nullptr)
		{
			bufferevent_free(CallbackArgument->EventBufferList->at(Index));
			CallbackArgument->EventBufferList->at(Index) = nullptr;
		}

		SocketSetting(CallbackArgument->SocketValue->ValueSet.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	}

	return;
}

//Bufferevent transmission once read callback
void ReadCallback_TransmissionOnce(
	bufferevent *BufferEvent, 
	void *Argument)
{
//Mark arguments.
	if (Argument == nullptr)
		return;
	const auto CallbackArgument = reinterpret_cast<EVENT_TABLE_TRANSMISSION_ONCE *>(Argument);

//Drop all responses.
	while (evbuffer_get_length(bufferevent_get_input(BufferEvent)) > 0)
	{
		bufferevent_read(BufferEvent, CallbackArgument->RecvBuffer, CallbackArgument->RecvSize);
		memset(CallbackArgument->RecvBuffer, 0, CallbackArgument->RecvSize);
	}

//Match active bufferevent in the list.
	size_t Index = 0;
	for (Index = 0;Index < CallbackArgument->EventBufferList->size();++Index)
	{
		if (CallbackArgument->EventBufferList->at(Index) == BufferEvent)
			break;
		else if (Index + 1U == CallbackArgument->EventBufferList->size())
			return;
	}

//Free bufferevent and close socket once completed.
	if (CallbackArgument->EventBufferList->at(Index) != nullptr)
	{
		bufferevent_free(CallbackArgument->EventBufferList->at(Index));
		CallbackArgument->EventBufferList->at(Index) = nullptr;
	}

	SocketSetting(CallbackArgument->SocketValue->ValueSet.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	return;
}

//Bufferevent transmission once write callback
void WriteCallback_TransmissionOnce(
	bufferevent *BufferEvent, 
	void *Argument)
{
//Mark arguments.
	if (Argument == nullptr)
		return;
	const auto CallbackArgument = reinterpret_cast<EVENT_TABLE_TRANSMISSION_ONCE *>(Argument);

//Match active bufferevent in the list.
	size_t Index = 0;
	for (Index = 0;Index < CallbackArgument->EventBufferList->size();++Index)
	{
		if (CallbackArgument->EventBufferList->at(Index) == BufferEvent)
			break;
		else if (Index + 1U == CallbackArgument->EventBufferList->size())
			return;
	}

//Send request.
	if (CallbackArgument->SendTimes->at(Index) > 0)
	{
		bufferevent_disable(BufferEvent, EV_WRITE);
	}
	else {
		bufferevent_write(BufferEvent, CallbackArgument->SendBuffer->at(Index).get(), CallbackArgument->SendLen->at(Index));
		++CallbackArgument->SendTimes->at(Index);
	}

	return;
}

//Bufferevent transmission once timer callback
void TimerCallback_TransmissionOnce(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument)
{
//Mark arguments.
	if (Argument == nullptr)
		return;
	const auto CallbackArgument = reinterpret_cast<EVENT_TABLE_TRANSMISSION_ONCE *>(Argument);

//Free all bufferevent everytime.
	if (!CallbackArgument->EventBufferList->empty())
	{
		for (auto &EventBufferItem:*CallbackArgument->EventBufferList)
		{
			if (EventBufferItem != nullptr)
			{
				bufferevent_free(EventBufferItem);
				EventBufferItem = nullptr;
			}
		}

		CallbackArgument->EventBufferList->clear();
		CallbackArgument->EventBufferList->shrink_to_fit();
	}

//Close all sockets everytime.
	CallbackArgument->SocketValue->ClearAllSocket(false);

//Interval time controller
	if (Parameter.DomainTest_Speed == 0 || //Domain Test disable
		event_base_get_num_events(CallbackArgument->EventBase, EVENT_BASE_COUNT_ACTIVE) > 0) //Waiting all callback finished.
	{
	//Set interval timeout.
	#if defined(PLATFORM_WIN)
		CallbackArgument->IntervalTimeout.tv_sec = static_cast<const DWORD>(Parameter.FileRefreshTime) / SECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		CallbackArgument->IntervalTimeout.tv_sec = Parameter.FileRefreshTime / SECOND_TO_MILLISECOND;
	#endif

	//Reset next recheck process.
		if (Parameter.DomainTest_Speed == 0)
		{
			CallbackArgument->TotalSleepTime = 0;
			CallbackArgument->OnceTimes = 0;
			CallbackArgument->RetestTimes = 0;
		}

	//Add timer event again.
		if (event_add(CallbackArgument->EventList->front(), &CallbackArgument->IntervalTimeout) == RETURN_ERROR)
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event error", 0, nullptr, 0);

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
		if (CallbackArgument->Protocol_Network == AF_INET6) //IPv6
		{
		//Main and Alternate
			if ((Parameter.Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad == 0 && 
				Parameter.Target_Server_Main_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark == 0) || 
				(Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && 
				Parameter.Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad == 0 && 
				Parameter.Target_Server_Alternate_IPv6.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark == 0))
					IsHopLimitExist = false;

		//Multiple list
			if (IsHopLimitExist && Parameter.Target_Server_IPv6_Multiple != nullptr)
			{
				for (const auto &DNS_ServerDataItem:*Parameter.Target_Server_IPv6_Multiple)
				{
					if (DNS_ServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_StaticLoad == 0 && 
						DNS_ServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv6_HeaderStatus.HopLimit_DynamicMark == 0)
					{
						IsHopLimitExist = false;
						break;
					}
				}
			}
		}
		else if (CallbackArgument->Protocol_Network == AF_INET) //IPv4
		{
		//Main and Alternate
			if ((Parameter.Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad == 0 && 
				Parameter.Target_Server_Main_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark == 0) || 
				(Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && 
				Parameter.Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad == 0 && 
				Parameter.Target_Server_Alternate_IPv4.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark == 0))
					IsHopLimitExist = false;

		//Multiple list
			if (IsHopLimitExist && Parameter.Target_Server_IPv4_Multiple != nullptr)
			{
				for (const auto &DNS_ServerDataItem:*Parameter.Target_Server_IPv4_Multiple)
				{
					if (DNS_ServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_StaticLoad == 0 && DNS_ServerDataItem.ServerPacketStatus.NetworkLayerStatus.IPv4_HeaderStatus.TTL_DynamicMark == 0)
					{
						IsHopLimitExist = false;
						break;
					}
				}
			}
		}

	//Keep to retest if no any available gateways.
		if (!GlobalRunningStatus.GatewayAvailable_IPv6 && !GlobalRunningStatus.GatewayAvailable_IPv4)
			CallbackArgument->RetestTimes = 0;

	//Retest if Hop Limits/TTLs are not exist or retest not more than a value times.
		if (IsHopLimitExist || CallbackArgument->RetestTimes + 1U >= SENDING_MAX_INTERVAL_TIMES)
		{
		//Mark total sleep time.
			size_t LoopInterval = 0;
			if (Parameter.DomainTest_Speed < Parameter.FileRefreshTime)
				LoopInterval = Parameter.DomainTest_Speed;
			else 
				LoopInterval = Parameter.FileRefreshTime;
			CallbackArgument->TotalSleepTime += LoopInterval;

		//Interval time is enough or configuration file modified, reset retest times.
			if (CallbackArgument->TotalSleepTime >= Parameter.DomainTest_Speed || 
				CallbackArgument->FileModifiedTime != GlobalRunningStatus.ConfigFileModifiedTime)
			{
				CallbackArgument->RetestTimes = 0;
				CallbackArgument->FileModifiedTime = GlobalRunningStatus.ConfigFileModifiedTime;
			}
		//Interval time is not enough.
			else {
			#if defined(PLATFORM_WIN)
				CallbackArgument->IntervalTimeout.tv_sec = static_cast<const DWORD>(LoopInterval) / SECOND_TO_MILLISECOND;
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				CallbackArgument->IntervalTimeout.tv_sec = LoopInterval / SECOND_TO_MILLISECOND;
			#endif

			//Add timer event again.
				if (event_add(CallbackArgument->EventList->front(), &CallbackArgument->IntervalTimeout) == RETURN_ERROR)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event error", 0, nullptr, 0);

				return;
			}
		}
	//Mark retest times.
		else if (GlobalRunningStatus.GatewayAvailable_IPv6 && GlobalRunningStatus.GatewayAvailable_IPv4)
		{
			++CallbackArgument->RetestTimes;
		}

	//Interval time is enough, next recheck process.
		CallbackArgument->TotalSleepTime = 0;
		CallbackArgument->OnceTimes = 1U;
	}

//Set interval timeout and repeat events.
	CallbackArgument->IntervalTimeout.tv_sec = SENDING_INTERVAL_TIME / SECOND_TO_MILLISECOND;
	if (event_add(CallbackArgument->EventList->front(), &CallbackArgument->IntervalTimeout) == RETURN_ERROR)
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Domain Test event error", 0, nullptr, 0);

//Repeat bufferevents.
	LoadBufferEvent_DomainTest(CallbackArgument);
	return;
}
#endif

//Select network layer protocol for all request
uint16_t SelectProtocol_Network(
	const REQUEST_MODE_NETWORK GlobalSpecific, 
	const uint16_t TargetSpecific_IPv6, 
	const uint16_t TargetSpecific_IPv4, 
	const bool IsAccordingType, 
	const uint16_t TypeSpecific, 
	const SOCKET_DATA * const LocalSocketSpecific)
{
//Only one of IPv6 and IPv4 protocol is available.
	if (TargetSpecific_IPv4 == 0)
		return AF_INET6;
	else if (TargetSpecific_IPv6 == 0)
		return AF_INET;

//Auto select
	if (GlobalSpecific == REQUEST_MODE_NETWORK::BOTH)
	{
	//According type specific
		if (IsAccordingType)
		{
			if (ntoh16(TypeSpecific) == DNS_TYPE_AAAA)
				return AF_INET6;
			else if (ntoh16(TypeSpecific) == DNS_TYPE_A)
				return AF_INET;
		}

	//Local socket specific
		if (LocalSocketSpecific != nullptr)
		{
			if (LocalSocketSpecific->SockAddr.ss_family == AF_INET6 && GlobalRunningStatus.GatewayAvailable_IPv6)
				return AF_INET6;
			else if (LocalSocketSpecific->SockAddr.ss_family == AF_INET && GlobalRunningStatus.GatewayAvailable_IPv4)
				return AF_INET;
		}

	//Network status specific
		if (GlobalRunningStatus.GatewayAvailable_IPv6)
		{
			return AF_INET6;
		}
		else if (GlobalRunningStatus.GatewayAvailable_IPv4)
		{
			return AF_INET;
		}
		else { //Both IPv6 and IPv4 are not available, set default to IPv6.
			return AF_INET6;
		}
	}
//IPv6
	else if (GlobalSpecific == REQUEST_MODE_NETWORK::IPV6)
	{
		if (GlobalRunningStatus.GatewayAvailable_IPv6)
			return AF_INET6;
		else 
			return AF_INET;
	}
//IPv4
	else if (GlobalSpecific == REQUEST_MODE_NETWORK::IPV4)
	{
		if (GlobalRunningStatus.GatewayAvailable_IPv4)
			return AF_INET;
		else 
			return AF_INET6;
	}

	return 0;
}

//Select socket data of DNS target
size_t SelectTargetSocketSingle(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
	const uint16_t QueryType, 
	const SOCKET_DATA * const LocalSocketData, 
	SOCKET_DATA * const TargetSocketData, 
	bool ** const IsAlternate, 
	size_t ** const AlternateTimeoutTimes, 
	const ADDRESS_UNION_DATA * const SpecifieTargetData, 
	void * DNSCurvePacketServerType, 
	void ** const DNSCurvePacketTarget)
{
//Socket type and request type check
	uint16_t SocketType = 0;
	if (Protocol == IPPROTO_TCP)
		SocketType = SOCK_STREAM;
	else if (Protocol == IPPROTO_UDP)
		SocketType = SOCK_DGRAM;
	else 
		return EXIT_FAILURE;

//Select DNSCurve target socket
#if defined(ENABLE_LIBSODIUM)
	if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
	{
	//Pointer check
		auto PacketTarget = reinterpret_cast<DNSCURVE_SERVER_DATA **>(DNSCurvePacketTarget);
		if (PacketTarget == nullptr || DNSCurvePacketServerType == nullptr)
			return EXIT_FAILURE;
		const auto NetworkSpecific = SelectProtocol_Network(DNSCurveParameter.DNSCurveProtocol_Network, DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family, DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family, DNSCurveParameter.DNSCurveProtocol_IsAccordingType, QueryType, LocalSocketData);

	//IPv6
		if (NetworkSpecific == AF_INET6)
		{
		//Timeout settings
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV6);
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV6);
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV6);
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV6);
			}
			else {
				return EXIT_FAILURE;
			}

		//Encryption mode check
			if (DNSCurveParameter.IsEncryption)
			{
				if ((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
						**IsAlternate = true;
				if (**IsAlternate && 
					((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
						**IsAlternate = false;
			}

		//Alternate
			if (**IsAlternate && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
			{
				reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_addr = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr;
				reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_port = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_port;
				*PacketTarget = &DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6;
				*reinterpret_cast<DNSCURVE_SERVER_TYPE *>(DNSCurvePacketServerType) = DNSCURVE_SERVER_TYPE::ALTERNATE_IPV6;
			}
		//Main
			else {
			//Encryption mode check
				if (DNSCurveParameter.IsEncryption && 
					((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
						return EXIT_FAILURE;

				reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_addr = DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr;
				reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_port = DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.IPv6.sin6_port;
				*PacketTarget = &DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6;
				*reinterpret_cast<DNSCURVE_SERVER_TYPE *>(DNSCurvePacketServerType) = DNSCURVE_SERVER_TYPE::MAIN_IPV6;
			}

		//Socket attribute settings
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				return EXIT_FAILURE;
			}
		}
	//IPv4
		else if (NetworkSpecific == AF_INET)
		{
		//Timeout settings
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV4);
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV4);
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV4);
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV4);
			}
			else {
				return EXIT_FAILURE;
			}

		//Encryption mode check
			if (DNSCurveParameter.IsEncryption)
			{
				if ((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
						**IsAlternate = true;
				if (**IsAlternate && 
					((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
						**IsAlternate = false;
			}

		//Alternate
			if (**IsAlternate && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0)
			{
				reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_addr = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr;
				reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_port = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.IPv4.sin_port;
				*PacketTarget = &DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4;
				*reinterpret_cast<DNSCURVE_SERVER_TYPE *>(DNSCurvePacketServerType) = DNSCURVE_SERVER_TYPE::ALTERNATE_IPV4;
			}
		//Main
			else {
			//Encryption mode check
				if (DNSCurveParameter.IsEncryption && 
					((!DNSCurveParameter.IsClientEphemeralKey && sodium_is_zero(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES) != 0) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
						return EXIT_FAILURE;

				reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_addr = DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.IPv4.sin_addr;
				reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_port = DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.IPv4.sin_port;
				*PacketTarget = &DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4;
				*reinterpret_cast<DNSCURVE_SERVER_TYPE *>(DNSCurvePacketServerType) = DNSCURVE_SERVER_TYPE::MAIN_IPV4;
			}

		//Socket attribute settings
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
				(Protocol == IPPROTO_UDP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr)))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				return EXIT_FAILURE;
			}
		}

		return EXIT_SUCCESS;
	}
#endif

//Specifie target request
	if (SpecifieTargetData != nullptr && SpecifieTargetData->Storage.ss_family != 0)
	{
		if (SpecifieTargetData->Storage.ss_family == AF_INET6)
		{
			reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_addr = SpecifieTargetData->IPv6.sin6_addr;
			reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_port = SpecifieTargetData->IPv6.sin6_port;
			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				return EXIT_FAILURE;
			}
		}
		else if (SpecifieTargetData->Storage.ss_family == AF_INET)
		{
			reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_addr = SpecifieTargetData->IPv4.sin_addr;
			reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_port = SpecifieTargetData->IPv4.sin_port;
			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
				(Protocol == IPPROTO_UDP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr)))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				return EXIT_FAILURE;
			}
		}
		else {
			return EXIT_FAILURE;
		}
	}
//Local request
	else if (RequestType == REQUEST_PROCESS_TYPE::LOCAL_NORMAL || RequestType == REQUEST_PROCESS_TYPE::LOCAL_IN_WHITE)
	{
		const auto NetworkSpecific = SelectProtocol_Network(Parameter.LocalProtocol_Network, Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family, Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family, Parameter.LocalProtocol_IsAccordingType, QueryType, LocalSocketData);

	//IPv6
		if (NetworkSpecific == AF_INET6)
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_LOCAL_TCP_IPV6);
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_LOCAL_TCP_IPV6);
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_LOCAL_UDP_IPV6);
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_LOCAL_UDP_IPV6);
			}
			else {
				return EXIT_FAILURE;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Local_Alternate_IPv6.Storage.ss_family != 0)
			{
				reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_addr = Parameter.Target_Server_Local_Alternate_IPv6.IPv6.sin6_addr;
				reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_port = Parameter.Target_Server_Local_Alternate_IPv6.IPv6.sin6_port;
			}
		//Main
			else {
				reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_addr = Parameter.Target_Server_Local_Main_IPv6.IPv6.sin6_addr;
				reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_port = Parameter.Target_Server_Local_Main_IPv6.IPv6.sin6_port;
			}

		//Socket initialization
			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				return EXIT_FAILURE;
			}
		}
	//IPv4
		else if (NetworkSpecific == AF_INET)
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_LOCAL_TCP_IPV4);
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_LOCAL_TCP_IPV4);
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_LOCAL_UDP_IPV4);
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_LOCAL_UDP_IPV4);
			}
			else {
				return EXIT_FAILURE;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Local_Alternate_IPv4.Storage.ss_family != 0)
			{
				reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_addr = Parameter.Target_Server_Local_Alternate_IPv4.IPv4.sin_addr;
				reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_port = Parameter.Target_Server_Local_Alternate_IPv4.IPv4.sin_port;
			}
		//Main
			else {
				reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_addr = Parameter.Target_Server_Local_Main_IPv4.IPv4.sin_addr;
				reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_port = Parameter.Target_Server_Local_Main_IPv4.IPv4.sin_port;
			}

		//Socket initialization
			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
				(Protocol == IPPROTO_UDP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr)))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				return EXIT_FAILURE;
			}
		}
		else {
			return EXIT_FAILURE;
		}
	}
//Main request
	else {
		const auto NetworkSpecific = SelectProtocol_Network(Parameter.RequestMode_Network, Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family, Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family, Parameter.RequestMode_IsAccordingType, QueryType, LocalSocketData);

	//IPv6
		if (NetworkSpecific == AF_INET6)
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6);
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6);
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV6);
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV6);
			}
			else {
				return EXIT_FAILURE;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
			{
				reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_addr = Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr;
				reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_port = Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
		//Main
			else {
				reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_addr = Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr;
				reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr)->sin6_port = Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_port;
			}

		//Socket initialization
			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				return EXIT_FAILURE;
			}
		}
	//IPv4
		if (NetworkSpecific == AF_INET)
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4);
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4);
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV4);
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV4);
			}
			else {
				return EXIT_FAILURE;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0)
			{
				reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_addr = Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr;
				reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_port = Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_port;
			}
		//Main
			else {
				reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_addr = Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_addr;
				reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr)->sin_port = Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_port;
			}

		//Socket initialization
			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
				(Protocol == IPPROTO_UDP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr)))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				return EXIT_FAILURE;
			}
		}
		else {
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

//Select socket data of DNS target(Multiple threading)
bool SelectTargetSocketMultiple(
	const uint16_t Protocol_Network, 
	const uint16_t Protocol_Transport, 
	const uint16_t QueryType, 
	const SOCKET_DATA * const LocalSocketData, 
	std::vector<SOCKET_DATA> &TargetSocketDataList)
{
//Initialization
	uint16_t SocketType = 0;
	if (Protocol_Transport == IPPROTO_TCP)
		SocketType = SOCK_STREAM;
	else if (Protocol_Transport == IPPROTO_UDP)
		SocketType = SOCK_DGRAM;
	else 
		return false;
	SOCKET_DATA TargetSocketData;
	memset(&TargetSocketData, 0, sizeof(TargetSocketData));
	TargetSocketData.Socket = INVALID_SOCKET;
	size_t Index = 0;
	bool *IsAlternate = nullptr;

//Select network protocol.
	auto NetworkSpecific = Protocol_Network;
	if (NetworkSpecific == 0)
		NetworkSpecific = SelectProtocol_Network(Parameter.RequestMode_Network, Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family, Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family, Parameter.RequestMode_IsAccordingType, QueryType, LocalSocketData);

//IPv6
	if (NetworkSpecific == AF_INET6)
	{
	//Set Alternate swap list.
		if (Protocol_Transport == IPPROTO_TCP)
			IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6);
		else if (Protocol_Transport == IPPROTO_UDP)
			IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV6);
		else 
			return false;

	//Main
		if (!*IsAlternate)
		{
			for (Index = 0;Index < Parameter.MultipleRequestTimes;++Index)
			{
				memset(&TargetSocketData, 0, sizeof(TargetSocketData));
				TargetSocketData.SockAddr = Parameter.Target_Server_Main_IPv6.AddressData.Storage;
				TargetSocketData.Socket = socket(AF_INET6, SocketType, Protocol_Transport);

			//Socket attribute settings
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
					(Protocol_Transport == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
				{
					for (auto &SocketDataItem:TargetSocketDataList)
						SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

					return false;
				}

			//Socket initialization
				TargetSocketData.AddrLen = sizeof(sockaddr_in6);
				TargetSocketDataList.push_back(TargetSocketData);
			}
		}

	//Alternate
		if (Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0 && (*IsAlternate || Parameter.AlternateMultipleRequest))
		{
			for (Index = 0;Index < Parameter.MultipleRequestTimes;++Index)
			{
				memset(&TargetSocketData, 0, sizeof(TargetSocketData));
				TargetSocketData.SockAddr = Parameter.Target_Server_Alternate_IPv6.AddressData.Storage;
				TargetSocketData.Socket = socket(AF_INET6, SocketType, Protocol_Transport);

			//Socket attribute settings
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
					(Protocol_Transport == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
				{
					for (auto &SocketDataItem:TargetSocketDataList)
						SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

					return false;
				}

			//Socket initialization
				TargetSocketData.AddrLen = sizeof(sockaddr_in6);
				TargetSocketDataList.push_back(TargetSocketData);
			}
		}

	//Other servers
		if (Parameter.Target_Server_IPv6_Multiple != nullptr && !*IsAlternate && Parameter.AlternateMultipleRequest)
		{
			for (const auto &DNS_ServerDataItem:*Parameter.Target_Server_IPv6_Multiple)
			{
				for (Index = 0;Index < Parameter.MultipleRequestTimes;++Index)
				{
					memset(&TargetSocketData, 0, sizeof(TargetSocketData));
					TargetSocketData.SockAddr = DNS_ServerDataItem.AddressData.Storage;
					TargetSocketData.Socket = socket(AF_INET6, SocketType, Protocol_Transport);

				//Socket attribute settings
					if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
						(Protocol_Transport == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
					{
						for (auto &SocketDataItem:TargetSocketDataList)
							SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

						return false;
					}

				//Socket initialization
					TargetSocketData.AddrLen = sizeof(sockaddr_in6);
					TargetSocketDataList.push_back(TargetSocketData);
				}
			}
		}
	}
//IPv4
	else if (NetworkSpecific == AF_INET)
	{
	//Set Alternate swap list.
		if (Protocol_Transport == IPPROTO_TCP)
			IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4);
		else if (Protocol_Transport == IPPROTO_UDP)
			IsAlternate = &AlternateSwapList.IsSwapped.at(ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV4);
		else 
			return false;

	//Main
		if (!*IsAlternate)
		{
			for (Index = 0;Index < Parameter.MultipleRequestTimes;++Index)
			{
				memset(&TargetSocketData, 0, sizeof(TargetSocketData));
				TargetSocketData.SockAddr = Parameter.Target_Server_Main_IPv4.AddressData.Storage;
				TargetSocketData.Socket = socket(AF_INET, SocketType, Protocol_Transport);

			//Socket attribute settings
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
					(Protocol_Transport == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
					(Protocol_Transport == IPPROTO_UDP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr)))
				{
					for (auto &SocketDataItem:TargetSocketDataList)
						SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

					return false;
				}

			//Socket initialization
				TargetSocketData.AddrLen = sizeof(sockaddr_in);
				TargetSocketDataList.push_back(TargetSocketData);
			}
		}

	//Alternate
		if (Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0 && (*IsAlternate || Parameter.AlternateMultipleRequest))
		{
			for (Index = 0;Index < Parameter.MultipleRequestTimes;++Index)
			{
				memset(&TargetSocketData, 0, sizeof(TargetSocketData));
				TargetSocketData.SockAddr = Parameter.Target_Server_Alternate_IPv4.AddressData.Storage;
				TargetSocketData.Socket = socket(AF_INET, SocketType, Protocol_Transport);

			//Socket attribute settings
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
					(Protocol_Transport == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
					(Protocol_Transport == IPPROTO_UDP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr)))
				{
					for (auto &SocketDataItem:TargetSocketDataList)
						SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

					return false;
				}

			//Socket initialization
				TargetSocketData.AddrLen = sizeof(sockaddr_in);
				TargetSocketDataList.push_back(TargetSocketData);
			}
		}

	//Other servers
		if (Parameter.Target_Server_IPv4_Multiple != nullptr && !*IsAlternate && Parameter.AlternateMultipleRequest)
		{
			for (const auto &DNS_ServerDataItem:*Parameter.Target_Server_IPv4_Multiple)
			{
				for (Index = 0;Index < Parameter.MultipleRequestTimes;++Index)
				{
					memset(&TargetSocketData, 0, sizeof(TargetSocketData));
					TargetSocketData.SockAddr = DNS_ServerDataItem.AddressData.Storage;
					TargetSocketData.Socket = socket(AF_INET, SocketType, Protocol_Transport);

				//Socket attribute settings
					if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
						(Protocol_Transport == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
						(Protocol_Transport == IPPROTO_UDP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr)))
					{
						for (auto &SocketDataItem:TargetSocketDataList)
							SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

						return false;
					}

				//Socket initialization
					TargetSocketData.AddrLen = sizeof(sockaddr_in);
					TargetSocketDataList.push_back(TargetSocketData);
				}
			}
		}
	}
	else {
		return false;
	}

	return true;
}

//Connect to server(TCP) or socket connecting(UDP)
size_t SocketConnecting(
	const uint16_t Protocol, 
	SYSTEM_SOCKET &Socket, 
	const sockaddr * const SockAddr, 
	const socklen_t AddrLen, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize)
{
//Socket check
	if (!SocketSetting(Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr))
	{
		SocketSetting(Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//TCP connecting
	if (Protocol == IPPROTO_TCP)
	{
	#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (Parameter.TCP_FastOpen > 0 && OriginalSend != nullptr && SendSize > 0)
		{
			errno = 0;

		#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX))
		//Send request and network stack will connect to server first.
		#if defined(PLATFORM_FREEBSD)
			ssize_t RecvLen = sendto(Socket, OriginalSend, SendSize, 0, SockAddr, AddrLen);
		#elif defined(PLATFORM_LINUX)
			ssize_t RecvLen = sendto(Socket, OriginalSend, SendSize, MSG_FASTOPEN, SockAddr, AddrLen);
		#endif
			if (RecvLen == SOCKET_ERROR && errno != EAGAIN && errno != EINPROGRESS)
				return EXIT_FAILURE;
			else if (RecvLen < static_cast<const ssize_t>(DNS_PACKET_MINSIZE))
				return EXIT_SUCCESS;
			else 
				return RecvLen;
		#elif defined(PLATFORM_MACOS)
		//Socket initialization
			sa_endpoints_t EndPoints;
			memset(&EndPoints, 0, sizeof(EndPoints));
			EndPoints.sae_srcif = 0;
			EndPoints.sae_srcaddr = nullptr;
			EndPoints.sae_srcaddrlen = 0;
			EndPoints.sae_dstaddr = SockAddr;
			EndPoints.sae_dstaddrlen = AddrLen;

		//Socket length initialization
			if (AddrLen == sizeof(sockaddr_in6))
				reinterpret_cast<sockaddr_in6 *>(const_cast<sockaddr *>(EndPoints.sae_dstaddr))->sin6_len = sizeof(sockaddr_in6);
			else if (AddrLen == sizeof(sockaddr_in))
				reinterpret_cast<sockaddr_in *>(const_cast<sockaddr *>(EndPoints.sae_dstaddr))->sin_len = sizeof(sockaddr_in);
			else 
				return EXIT_FAILURE;

		//Hold connecting to server.
			ssize_t RecvLen = connectx(Socket, &EndPoints, SAE_ASSOCID_ANY, CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT, nullptr, 0, nullptr, nullptr);
			if (RecvLen == SOCKET_ERROR && errno != EAGAIN && errno != EINPROGRESS)
				return EXIT_FAILURE;

		//Send request and network stack will connect to server first.
			RecvLen = send(Socket, OriginalSend, SendSize, 0);
			if (RecvLen == SOCKET_ERROR && errno != EAGAIN && errno != EINPROGRESS)
				return EXIT_FAILURE;
			else if (RecvLen < static_cast<const ssize_t>(DNS_PACKET_MINSIZE))
				return EXIT_SUCCESS;
			else 
				return RecvLen;
		#endif
		}
		else {
	#endif
			if (connect(Socket, SockAddr, AddrLen) == SOCKET_ERROR)
			{
				ssize_t ErrorCode = WSAGetLastError();

			#if defined(PLATFORM_WIN)
				if (ErrorCode != WSAEWOULDBLOCK)
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (ErrorCode != EAGAIN && ErrorCode != EINPROGRESS)
			#endif
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"TCP connection initialization error", ErrorCode, nullptr, 0);
					SocketSetting(Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

					return EXIT_FAILURE;
				}
			}
	#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		}
	#endif
	}
//UDP connecting
	else if (Protocol == IPPROTO_UDP)
	{
		if (connect(Socket, SockAddr, AddrLen) == SOCKET_ERROR)
		{
			ssize_t ErrorCode = WSAGetLastError();

		#if defined(PLATFORM_WIN)
			if (ErrorCode != WSAEWOULDBLOCK)
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (ErrorCode != EAGAIN && ErrorCode != EINPROGRESS)
		#endif
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"UDP connection initialization error", ErrorCode, nullptr, 0);
				SocketSetting(Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

				return EXIT_FAILURE;
			}
		}
	}
	else {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

//Non-blocking mode selecting(Once)
ssize_t SocketSelectingOnce(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	void * const OriginalDNSCurveSocketSelectingDataList, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	ssize_t * const ErrorCode, 
	const SOCKET_DATA * const LocalSocketData)
{
//Socket data check, select file descriptor set size and maximum socket index check(Part 1)
//Windows: The variable FD_SETSIZE determines the maximum number of descriptors in a set.
//Windows: The default value of FD_SETSIZE is 64, which can be modified by defining FD_SETSIZE to another value before including Winsock2.h.
//Windows: Internally, socket handles in an fd_set structure are not represented as bit flags as in Berkeley Unix.
//Linux and macOS: Select nfds is the highest-numbered file descriptor in any of the three sets, plus 1.
//Linux and macOS: An fd_set is a fixed size buffer.
//Linux and macOS: Executing FD_CLR() or FD_SET() with a value of fd that is negative or is equal to or larger than FD_SETSIZE will result in undefined behavior.
	if (SocketDataList.empty())
	{
		return EXIT_FAILURE;
	}
#if defined(PLATFORM_WIN)
	else if (SocketDataList.size() >= FD_SETSIZE)
	{
	//Close all sockets.
		for (auto &SocketDataItem:SocketDataList)
			SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}
#endif

//Initialization(Part 1)
	std::vector<SOCKET_SELECTING_ONCE_TABLE> SocketSelectingDataList(SocketDataList.size());
	size_t Index = 0;
	ssize_t RecvLen = 0;
	if (ErrorCode != nullptr)
		*ErrorCode = 0;
#if defined(ENABLE_LIBSODIUM)
	auto DNSCurveSocketSelectingDataList = reinterpret_cast<std::vector<DNSCURVE_SOCKET_SELECTING_TABLE> *>(OriginalDNSCurveSocketSelectingDataList);
	if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
	{
		if (DNSCurveSocketSelectingDataList == nullptr)
		{
		//Close all sockets.
			for (auto &SocketDataItem:SocketDataList)
				SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

			return EXIT_FAILURE;
		}
	}
#endif

//TCP or UDP connecting
	for (Index = 0;Index < SocketDataList.size();++Index)
	{
	//Set send buffer(DNSCurve).
	#if defined(ENABLE_LIBSODIUM)
		if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
			RecvLen = SocketConnecting(Protocol, SocketDataList.at(Index).Socket, reinterpret_cast<const sockaddr *>(&SocketDataList.at(Index).SockAddr), SocketDataList.at(Index).AddrLen, DNSCurveSocketSelectingDataList->at(Index).SendBuffer, DNSCurveSocketSelectingDataList->at(Index).SendSize);
		else 
	#endif
			RecvLen = SocketConnecting(Protocol, SocketDataList.at(Index).Socket, reinterpret_cast<const sockaddr *>(&SocketDataList.at(Index).SockAddr), SocketDataList.at(Index).AddrLen, OriginalSend, SendSize);
		if (RecvLen == EXIT_FAILURE)
		{
			SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		}
		else if (Protocol == IPPROTO_TCP && Parameter.TCP_FastOpen > 0 && RecvLen >= static_cast<const ssize_t>(DNS_PACKET_MINSIZE))
		{
		#if defined(ENABLE_LIBSODIUM)
			if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
				DNSCurveSocketSelectingDataList->at(Index).IsPacketDone = true;
			else 
		#endif
				SocketSelectingDataList.at(Index).IsPacketDone = true;
		}
	}

//Socket check(Part 1)
	for (auto SocketDataItem = SocketDataList.begin();SocketDataItem != SocketDataList.end();++SocketDataItem)
	{
		if (SocketSetting(SocketDataItem->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			break;
		else if (SocketDataItem + 1U == SocketDataList.end())
			return EXIT_FAILURE;
	}

//Initialization(Part 2)
	std::unique_ptr<uint8_t[]> RecvBufferTemp(nullptr);
	fd_set ReadFDS, WriteFDS;
	timeval Timeout;
	memset(&ReadFDS, 0, sizeof(ReadFDS));
	memset(&WriteFDS, 0, sizeof(WriteFDS));
	memset(&Timeout, 0, sizeof(Timeout));
	size_t LastReceiveIndex = 0;
	auto IsReadReady = false, IsWriteReady = false;
	if (OriginalRecv == nullptr
	#if defined(ENABLE_LIBSODIUM)
		&& RequestType != REQUEST_PROCESS_TYPE::DNSCURVE_MAIN
	#endif
		)
	{
		auto RecvBufferSwap = std::make_unique<uint8_t[]>(PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
		memset(RecvBufferSwap.get(), 0, PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
		std::swap(RecvBufferTemp, RecvBufferSwap);
	}

//Socket attribute setting(Timeout)
#if defined(ENABLE_LIBSODIUM)
	if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
	{
		if (Protocol == IPPROTO_TCP)
		{
		#if defined(PLATFORM_WIN)
			Timeout.tv_sec = DNSCurveParameter.DNSCurve_SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
			Timeout.tv_usec = DNSCurveParameter.DNSCurve_SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			Timeout = DNSCurveParameter.DNSCurve_SocketTimeout_Reliable;
		#endif
		}
		else if (Protocol == IPPROTO_UDP)
		{
		#if defined(PLATFORM_WIN)
			Timeout.tv_sec = DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable / SECOND_TO_MILLISECOND;
			Timeout.tv_usec = DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			Timeout = DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable;
		#endif
		}
		else {
			return EXIT_FAILURE;
		}
	}
	else {
#endif
		if (Protocol == IPPROTO_TCP)
		{
		#if defined(PLATFORM_WIN)
			Timeout.tv_sec = Parameter.SocketTimeout_Reliable_Once / SECOND_TO_MILLISECOND;
			Timeout.tv_usec = Parameter.SocketTimeout_Reliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			Timeout = Parameter.SocketTimeout_Reliable_Once;
		#endif
		}
		else if (Protocol == IPPROTO_UDP)
		{
		#if defined(PLATFORM_WIN)
			Timeout.tv_sec = Parameter.SocketTimeout_Unreliable_Once / SECOND_TO_MILLISECOND;
			Timeout.tv_usec = Parameter.SocketTimeout_Unreliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			Timeout = Parameter.SocketTimeout_Unreliable_Once;
		#endif
		}
		else {
			return EXIT_FAILURE;
		}
#if defined(ENABLE_LIBSODIUM)
	}
#endif

//Selecting send and receive process
	for (;;)
	{
		auto IsAllSocketShutdown = false;

	//Socket check(Part 2)
		for (auto SocketDataItem = SocketDataList.begin();SocketDataItem != SocketDataList.end();++SocketDataItem)
		{
			if (SocketSetting(SocketDataItem->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
				break;
			else if (SocketDataItem + 1U == SocketDataList.end())
				IsAllSocketShutdown = true;
		}

	//Buffer list check(Part 1)
		if (OriginalRecv != nullptr && (IsAllSocketShutdown || Parameter.ReceiveWaiting == 0 || SocketDataList.size() == 1U))
		{
		//Scan all result.
		#if defined(ENABLE_LIBSODIUM)
			if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
				RecvLen = SelectingResultOnce(RequestType, Protocol, SocketDataList, nullptr, DNSCurveSocketSelectingDataList, OriginalRecv, RecvSize, LocalSocketData);
			else 
		#endif
				RecvLen = SelectingResultOnce(RequestType, Protocol, SocketDataList, &SocketSelectingDataList, nullptr, OriginalRecv, RecvSize, LocalSocketData);

		//Get result or all socket cloesed
			if (RecvLen >= static_cast<const ssize_t>(DNS_PACKET_MINSIZE))
				return RecvLen;
			else if (IsAllSocketShutdown)
				return EXIT_FAILURE;
		}

	//Reset parameters.
		FD_ZERO(&ReadFDS);
		FD_ZERO(&WriteFDS);
		SYSTEM_SOCKET MaxSocket = INVALID_SOCKET;

	//Socket check and non-blocking process
		for (Index = 0;Index < SocketDataList.size();++Index)
		{
		//Non-blocking process
		//Socket data check, select file descriptor set size and maximum socket index check(Part 2)
			if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			{
			#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (SocketDataList.at(Index).Socket + 1U >= FD_SETSIZE)
				{
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
					continue;
				}
			#endif

			//Select structure initialization
				if (SocketDataList.at(Index).Socket > MaxSocket)
					MaxSocket = SocketDataList.at(Index).Socket;

			//Receive and send process
				FD_SET(SocketDataList.at(Index).Socket, &ReadFDS);
				if (
				#if defined(ENABLE_LIBSODIUM)
					(RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN && !DNSCurveSocketSelectingDataList->at(Index).IsPacketDone) || 
				#endif
					(
				#if defined(ENABLE_LIBSODIUM)
					RequestType != REQUEST_PROCESS_TYPE::DNSCURVE_MAIN && 
				#endif
					!SocketSelectingDataList.at(Index).IsPacketDone))
						FD_SET(SocketDataList.at(Index).Socket, &WriteFDS);
			}
			else if (MaxSocket == INVALID_SOCKET && Index + 1U == SocketDataList.size())
			{
				return EXIT_FAILURE;
			}
		}

	//Send request only.
		if (OriginalRecv == nullptr
		#if defined(ENABLE_LIBSODIUM)
			&& RequestType != REQUEST_PROCESS_TYPE::DNSCURVE_MAIN
		#endif
			)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
				if (!SocketSelectingDataList.at(Index).IsPacketDone)
					break;
				else if (Index + 1U == SocketDataList.size())
					return EXIT_SUCCESS;
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		ssize_t SelectResult = select(0, &ReadFDS, &WriteFDS, nullptr, &Timeout);
	#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		ssize_t SelectResult = select(MaxSocket + 1U, &ReadFDS, &WriteFDS, nullptr, &Timeout);
	#endif
		if (SelectResult > 0)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
			//File set available check
				if (!SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
				{
					continue;
				}
				else {
					IsReadReady = false;
					IsWriteReady = false;
					if (FD_ISSET(SocketDataList.at(Index).Socket, &ReadFDS) != 0)
						IsReadReady = true;
					if (FD_ISSET(SocketDataList.at(Index).Socket, &WriteFDS) != 0)
						IsWriteReady = true;
				}

			//Socket option check
			//Select will set both reading and writing sets and set SO_ERROR to error code when connection was failed.
				if (IsReadReady && IsWriteReady)
				{
					int OptionValue = 0;
					socklen_t OptionSize = sizeof(OptionValue);
					if (getsockopt(SocketDataList.at(Index).Socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&OptionValue), &OptionSize) == SOCKET_ERROR)
					{
						if (Protocol == IPPROTO_TCP)
							PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"TCP socket connecting error", WSAGetLastError(), nullptr, 0);
						else if (Protocol == IPPROTO_UDP)
							PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"UDP socket connecting error", WSAGetLastError(), nullptr, 0);
						if (ErrorCode != nullptr)
							*ErrorCode = WSAGetLastError();
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

						continue;
					}
					else if (OptionValue > 0)
					{
						if (Protocol == IPPROTO_TCP)
							PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"TCP socket connecting error", OptionValue, nullptr, 0);
						else if (Protocol == IPPROTO_UDP)
							PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"UDP socket connecting error", OptionValue, nullptr, 0);
						if (ErrorCode != nullptr)
							*ErrorCode = OptionValue;
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

						continue;
					}
				}

			#if defined(ENABLE_LIBSODIUM)
			//DNSCurve
				if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
				{
				//Receive process
					if (IsReadReady)
					{
					//Buffer initialization
						if (!DNSCurveSocketSelectingDataList->at(Index).RecvBuffer)
						{
							auto DNSCurveRecvBuffer = std::make_unique<uint8_t[]>(RecvSize + MEMORY_RESERVED_BYTES);
							memset(DNSCurveRecvBuffer.get(), 0, RecvSize);
							std::swap(DNSCurveSocketSelectingDataList->at(Index).RecvBuffer, DNSCurveRecvBuffer);
						}

					//Receive from selecting.
						RecvLen = recv(SocketDataList.at(Index).Socket, reinterpret_cast<char *>(DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.get() + DNSCurveSocketSelectingDataList->at(Index).RecvLen), static_cast<const int>(RecvSize - DNSCurveSocketSelectingDataList->at(Index).RecvLen), 0);

					//Connection closed or SOCKET_ERROR
						if (RecvLen <= 0)
						{
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
							DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.reset();
							DNSCurveSocketSelectingDataList->at(Index).RecvLen = 0;

							continue;
						}
						else if (Protocol == IPPROTO_UDP && RecvLen >= static_cast<const ssize_t>(DNS_PACKET_MINSIZE) && DNSCurveSocketSelectingDataList->at(Index).RecvLen > 0)
						{
							memset(DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.get(), 0, DNSCurveSocketSelectingDataList->at(Index).RecvLen);
							memmove_s(DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.get(), RecvSize, DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.get() + DNSCurveSocketSelectingDataList->at(Index).RecvLen, RecvLen);
							DNSCurveSocketSelectingDataList->at(Index).RecvLen = 0;
						}

					//Mark whole packet length and last packet.
						DNSCurveSocketSelectingDataList->at(Index).RecvLen += RecvLen;
						LastReceiveIndex = Index;
					}

				//Send process
					if (IsWriteReady && 
						!DNSCurveSocketSelectingDataList->at(Index).IsPacketDone)
					{
						if (send(SocketDataList.at(Index).Socket, reinterpret_cast<const char *>(DNSCurveSocketSelectingDataList->at(Index).SendBuffer), static_cast<const int>(DNSCurveSocketSelectingDataList->at(Index).SendSize), 0) == SOCKET_ERROR)
						{
							ssize_t InnerErrorCode = WSAGetLastError();
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

						#if defined(PLATFORM_WIN)
							if (InnerErrorCode == WSAEWOULDBLOCK)
						#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							if (InnerErrorCode == EAGAIN || InnerErrorCode == EINPROGRESS)
						#endif
							{
								DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.reset();
								DNSCurveSocketSelectingDataList->at(Index).RecvLen = 0;
							}
						}
						else {
							DNSCurveSocketSelectingDataList->at(Index).IsPacketDone = true;
						}
					}
				}
			//Normal
				else {
			#endif
				//Receive process
					if (IsReadReady)
					{
						if (OriginalRecv != nullptr)
						{
						//Buffer initialization
							if (!SocketSelectingDataList.at(Index).RecvBuffer)
							{
								auto RecvBufferSwap = std::make_unique<uint8_t[]>(RecvSize + MEMORY_RESERVED_BYTES);
								memset(RecvBufferSwap.get(), 0, RecvSize);
								std::swap(SocketSelectingDataList.at(Index).RecvBuffer, RecvBufferSwap);
							}

						//Receive from selecting.
							RecvLen = recv(SocketDataList.at(Index).Socket, reinterpret_cast<char *>(SocketSelectingDataList.at(Index).RecvBuffer.get() + SocketSelectingDataList.at(Index).RecvLen), static_cast<const int>(RecvSize - SocketSelectingDataList.at(Index).RecvLen), 0);

						//Connection closed or SOCKET_ERROR
							if (RecvLen <= 0)
							{
								SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
								SocketSelectingDataList.at(Index).RecvBuffer.reset();
								SocketSelectingDataList.at(Index).RecvLen = 0;

								continue;
							}
							else if (Protocol == IPPROTO_UDP && RecvLen >= static_cast<const ssize_t>(DNS_PACKET_MINSIZE) && SocketSelectingDataList.at(Index).RecvLen > 0)
							{
								memset(SocketSelectingDataList.at(Index).RecvBuffer.get(), 0, SocketSelectingDataList.at(Index).RecvLen);
								memmove_s(SocketSelectingDataList.at(Index).RecvBuffer.get(), RecvSize, SocketSelectingDataList.at(Index).RecvBuffer.get() + SocketSelectingDataList.at(Index).RecvLen, RecvLen);
								SocketSelectingDataList.at(Index).RecvLen = 0;
							}

						//Mark whole packet length and last packet.
							SocketSelectingDataList.at(Index).RecvLen += RecvLen;
							LastReceiveIndex = Index;
						}
						else {
						//Receive, drop all data and close sockets.
							recv(SocketDataList.at(Index).Socket, reinterpret_cast<char *>(RecvBufferTemp.get()), PACKET_NORMAL_MAXSIZE, 0);
							memset(RecvBufferTemp.get(), 0, PACKET_NORMAL_MAXSIZE + MEMORY_RESERVED_BYTES);
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

							continue;
						}
					}

				//Send process
					if (IsWriteReady && 
						!SocketSelectingDataList.at(Index).IsPacketDone)
					{
						if (send(SocketDataList.at(Index).Socket, reinterpret_cast<const char *>(OriginalSend), static_cast<const int>(SendSize), 0) == SOCKET_ERROR)
						{
							ssize_t InnerErrorCode = WSAGetLastError();
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

						#if defined(PLATFORM_WIN)
							if (InnerErrorCode == WSAEWOULDBLOCK)
						#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							if (InnerErrorCode == EAGAIN || InnerErrorCode == EINPROGRESS)
						#endif
							{
								SocketSelectingDataList.at(Index).RecvBuffer.reset();
								SocketSelectingDataList.at(Index).RecvLen = 0;
							}
						}
						else {
							SocketSelectingDataList.at(Index).IsPacketDone = true;
						}
					}
			#if defined(ENABLE_LIBSODIUM)
				}
			#endif
			}
		}
	//Timeout
		else if (SelectResult == 0)
		{
			if (OriginalRecv != nullptr)
			{
				Index = 0;

			//Swap to last receive packet when Receive Waiting is ON.
				MaxSocket = SocketDataList.at(LastReceiveIndex).Socket;
				SocketDataList.at(LastReceiveIndex).Socket = SocketDataList.at(Index).Socket;
				SocketDataList.at(Index).Socket = MaxSocket;
			#if defined(ENABLE_LIBSODIUM)
				if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
				{
					const auto PrecomputationKeyTemp = DNSCurveSocketSelectingDataList->at(Index).PrecomputationKey;
					DNSCurveSocketSelectingDataList->at(Index).PrecomputationKey = DNSCurveSocketSelectingDataList->at(LastReceiveIndex).PrecomputationKey;
					DNSCurveSocketSelectingDataList->at(LastReceiveIndex).PrecomputationKey = PrecomputationKeyTemp;
					const auto ReceiveMagicNumberTemp = DNSCurveSocketSelectingDataList->at(Index).ReceiveMagicNumber;
					DNSCurveSocketSelectingDataList->at(Index).ReceiveMagicNumber = DNSCurveSocketSelectingDataList->at(LastReceiveIndex).ReceiveMagicNumber;
					DNSCurveSocketSelectingDataList->at(LastReceiveIndex).ReceiveMagicNumber = ReceiveMagicNumberTemp;
					std::swap(DNSCurveSocketSelectingDataList->at(LastReceiveIndex).RecvBuffer, DNSCurveSocketSelectingDataList->at(Index).RecvBuffer);
					RecvLen = DNSCurveSocketSelectingDataList->at(LastReceiveIndex).RecvLen;
					DNSCurveSocketSelectingDataList->at(LastReceiveIndex).RecvLen = DNSCurveSocketSelectingDataList->at(Index).RecvLen;
					DNSCurveSocketSelectingDataList->at(Index).RecvLen = RecvLen;
					RecvLen = SelectingResultOnce(RequestType, Protocol, SocketDataList, nullptr, DNSCurveSocketSelectingDataList, OriginalRecv, RecvSize, LocalSocketData);
				}
				else {
			#endif
					std::swap(SocketSelectingDataList.at(LastReceiveIndex).RecvBuffer, SocketSelectingDataList.at(Index).RecvBuffer);
					RecvLen = SocketSelectingDataList.at(LastReceiveIndex).RecvLen;
					SocketSelectingDataList.at(LastReceiveIndex).RecvLen = SocketSelectingDataList.at(Index).RecvLen;
					SocketSelectingDataList.at(Index).RecvLen = RecvLen;
					RecvLen = SelectingResultOnce(RequestType, Protocol, SocketDataList, &SocketSelectingDataList, nullptr, OriginalRecv, RecvSize, LocalSocketData);
			#if defined(ENABLE_LIBSODIUM)
				}
			#endif

			//Buffer list check(Part 2)
				if (RecvLen >= static_cast<const ssize_t>(DNS_PACKET_MINSIZE))
					return RecvLen;
			}

			if (ErrorCode != nullptr)
				*ErrorCode = WSAETIMEDOUT;

			break;
		}
	//SOCKET_ERROR
		else {
			if (ErrorCode != nullptr)
				*ErrorCode = WSAGetLastError();

			break;
		}
	}

//Close all sockets.
	for (auto &SocketDataItem:SocketDataList)
		SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

	return EXIT_FAILURE;
}

//Socket selecting result(Once)
ssize_t SelectingResultOnce(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_ONCE_TABLE> *SocketSelectingDataList, 
	void * const OriginalDNSCurveSocketSelectingDataList, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const SOCKET_DATA * const LocalSocketData)
{
//Socket data check
	if (SocketDataList.empty())
		return EXIT_FAILURE;

//Initialization
#if defined(ENABLE_LIBSODIUM)
	auto DNSCurveSocketSelectingDataList = reinterpret_cast<std::vector<DNSCURVE_SOCKET_SELECTING_TABLE> *>(OriginalDNSCurveSocketSelectingDataList);
	if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
	{
		if (DNSCurveSocketSelectingDataList == nullptr)
			return EXIT_FAILURE;
	}
	else {
#endif
		if (SocketSelectingDataList == nullptr)
			return EXIT_FAILURE;
#if defined(ENABLE_LIBSODIUM)
	}
#endif
	ssize_t RecvLen = 0;

//Scan all buffer.
	for (size_t Index = 0;Index < SocketDataList.size();++Index)
	{
	#if defined(ENABLE_LIBSODIUM)
	//DNSCurve
		if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
		{
			if (DNSCurveSocketSelectingDataList->at(Index).RecvBuffer && DNSCurveSocketSelectingDataList->at(Index).RecvLen >= DNS_PACKET_MINSIZE)
			{
			//TCP header length check
				if (Protocol == IPPROTO_TCP)
				{
					RecvLen = ntoh16(reinterpret_cast<const uint16_t *>(DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.get())[0]);
					if (RecvLen < static_cast<const ssize_t>(DNS_PACKET_MINSIZE) || RecvLen >= static_cast<const ssize_t>(RecvSize) || RecvLen > static_cast<const ssize_t>(DNSCurveSocketSelectingDataList->at(Index).RecvLen))
					{
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
						DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.reset();
						DNSCurveSocketSelectingDataList->at(Index).RecvLen = 0;

						continue;
					}
					else {
						memmove_s(DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.get(), RecvSize, DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.get() + sizeof(uint16_t), RecvLen);
						memset(DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.get() + RecvLen, 0, static_cast<const ssize_t>(RecvSize) - RecvLen);
					}
				}
			//UDP length
				else if (Protocol == IPPROTO_UDP)
				{
					RecvLen = DNSCurveSocketSelectingDataList->at(Index).RecvLen;
				}
				else {
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
					DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.reset();
					DNSCurveSocketSelectingDataList->at(Index).RecvLen = 0;

					continue;
				}

			//Decrypt or get packet data(DNSCurve).
				if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
				{
					RecvLen = DNSCurve_PacketDecryption(DNSCurveSocketSelectingDataList->at(Index).ReceiveMagicNumber, DNSCurveSocketSelectingDataList->at(Index).PrecomputationKey, DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.get(), RecvSize, RecvLen);
					if (RecvLen < static_cast<const ssize_t>(DNS_PACKET_MINSIZE))
					{
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
						DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.reset();
						DNSCurveSocketSelectingDataList->at(Index).RecvLen = 0;

						continue;
					}
					else {
						memset(OriginalRecv, 0, RecvSize);
						memcpy_s(OriginalRecv, RecvSize, DNSCurveSocketSelectingDataList->at(Index).RecvBuffer.get(), RecvLen);
					}
				}

			//Register to global list.
				std::unique_lock<std::mutex> SocketRegisterMutex(SocketRegisterLock);
				for (auto &SocketDataItem:SocketDataList)
				{
					if (SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
					{
						SOCKET_REGISTER_DATA SocketRegisterDataTemp;
						SocketRegisterDataTemp.first = SocketDataItem.Socket;
						SocketRegisterDataTemp.second = 0;
						if (Protocol == IPPROTO_TCP)
						{
						#if defined(PLATFORM_WIN)
							SocketRegisterDataTemp.second = GetCurrentSystemTime() + DNSCurveParameter.DNSCurve_SocketTimeout_Reliable;
						#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							SocketRegisterDataTemp.second = IncreaseMillisecondTime(GetCurrentSystemTime(), DNSCurveParameter.DNSCurve_SocketTimeout_Reliable);
						#endif
						}
						else if (Protocol == IPPROTO_UDP)
						{
						#if defined(PLATFORM_WIN)
							SocketRegisterDataTemp.second = GetCurrentSystemTime() + DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable;
						#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							SocketRegisterDataTemp.second = IncreaseMillisecondTime(GetCurrentSystemTime(), DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable);
						#endif
						}
						else {
							continue;
						}

						SocketRegisterList.push_back(SocketRegisterDataTemp);
						SocketDataItem.Socket = INVALID_SOCKET;
					}
				}

				SocketRegisterMutex.unlock();

			//Mark domain cache.
				if (Parameter.DNS_CacheType != DNS_CACHE_TYPE::NONE)
					MarkDomainCache(OriginalRecv, RecvLen, LocalSocketData);

				return RecvLen;
			}
		}
	//Normal
		else {
	#endif
			if (SocketSelectingDataList->at(Index).RecvBuffer && SocketSelectingDataList->at(Index).RecvLen >= DNS_PACKET_MINSIZE)
			{
			//TCP header length check
				if (Protocol == IPPROTO_TCP)
				{
					RecvLen = ntoh16(reinterpret_cast<const uint16_t *>(SocketSelectingDataList->at(Index).RecvBuffer.get())[0]);
					if (RecvLen < static_cast<const ssize_t>(DNS_PACKET_MINSIZE) || RecvLen >= static_cast<const ssize_t>(RecvSize) || RecvLen > static_cast<const ssize_t>(SocketSelectingDataList->at(Index).RecvLen))
					{
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
						SocketSelectingDataList->at(Index).RecvBuffer.reset();
						SocketSelectingDataList->at(Index).RecvLen = 0;

						continue;
					}
					else {
						memmove_s(SocketSelectingDataList->at(Index).RecvBuffer.get(), RecvSize, SocketSelectingDataList->at(Index).RecvBuffer.get() + sizeof(uint16_t), RecvLen);
						memset(SocketSelectingDataList->at(Index).RecvBuffer.get() + RecvLen, 0, RecvSize - static_cast<const ssize_t>(RecvLen));
					}
				}
			//UDP length
				else if (Protocol == IPPROTO_UDP)
				{
					RecvLen = SocketSelectingDataList->at(Index).RecvLen;
				}
				else {
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
					SocketSelectingDataList->at(Index).RecvBuffer.reset();
					SocketSelectingDataList->at(Index).RecvLen = 0;

					continue;
				}

			//Receive from buffer list.
				RecvLen = CheckResponseData(
					RequestType, 
					SocketSelectingDataList->at(Index).RecvBuffer.get(), 
					RecvLen, 
					RecvSize, 
					nullptr, 
					nullptr);
				if (RecvLen < static_cast<const ssize_t>(DNS_PACKET_MINSIZE))
				{
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
					SocketSelectingDataList->at(Index).RecvBuffer.reset();
					SocketSelectingDataList->at(Index).RecvLen = 0;

					continue;
				}
				else {
					memset(OriginalRecv, 0, RecvSize);
					memcpy_s(OriginalRecv, RecvSize, SocketSelectingDataList->at(Index).RecvBuffer.get(), RecvLen);
				}

			//Register to global list.
				std::unique_lock<std::mutex> SocketRegisterMutex(SocketRegisterLock);
				for (auto &SocketDataItem:SocketDataList)
				{
					if (SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
					{
						SOCKET_REGISTER_DATA SocketRegisterDataTemp;
						SocketRegisterDataTemp.first = SocketDataItem.Socket;
						SocketRegisterDataTemp.second = 0;
						if (Protocol == IPPROTO_TCP)
						{
						#if defined(PLATFORM_WIN)
							SocketRegisterDataTemp.second = GetCurrentSystemTime() + Parameter.SocketTimeout_Reliable_Once;
						#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							SocketRegisterDataTemp.second = IncreaseMillisecondTime(GetCurrentSystemTime(), Parameter.SocketTimeout_Reliable_Once);
						#endif
						}
						else if (Protocol == IPPROTO_UDP)
						{
						#if defined(PLATFORM_WIN)
							SocketRegisterDataTemp.second = GetCurrentSystemTime() + Parameter.SocketTimeout_Unreliable_Once;
						#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							SocketRegisterDataTemp.second = IncreaseMillisecondTime(GetCurrentSystemTime(), Parameter.SocketTimeout_Unreliable_Once);
						#endif
						}
						else {
							continue;
						}

						SocketRegisterList.push_back(SocketRegisterDataTemp);
						SocketDataItem.Socket = INVALID_SOCKET;
					}
				}

				SocketRegisterMutex.unlock();

			//Mark domain cache.
				if (Parameter.DNS_CacheType != DNS_CACHE_TYPE::NONE)
					MarkDomainCache(OriginalRecv, RecvLen, LocalSocketData);

				return RecvLen;
			}
	#if defined(ENABLE_LIBSODIUM)
		}
	#endif
	}

	return EXIT_FAILURE;
}

//Non-blocking mode selecting(Serial)
size_t SocketSelectingSerial(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList)
{
//Socket data check, select file descriptor set size and maximum socket index check(Part 1)
//Windows: The variable FD_SETSIZE determines the maximum number of descriptors in a set.
//Windows: The default value of FD_SETSIZE is 64, which can be modified by defining FD_SETSIZE to another value before including Winsock2.h.
//Windows: Internally, socket handles in an fd_set structure are not represented as bit flags as in Berkeley Unix.
//Linux and macOS: Select nfds is the highest-numbered file descriptor in any of the three sets, plus 1.
//Linux and macOS: An fd_set is a fixed size buffer.
//Linux and macOS: Executing FD_CLR() or FD_SET() with a value of fd that is negative or is equal to or larger than FD_SETSIZE will result in undefined behavior.
	if (SocketDataList.empty())
	{
		return EXIT_FAILURE;
	}
	else if (
		SocketSelectingDataList.empty() || ErrorCodeList.empty()
	#if defined(PLATFORM_WIN)
		|| SocketDataList.size() >= FD_SETSIZE
	#endif
		)
	{
	//Close all sockets.
		for (auto &SocketDataItem:SocketDataList)
			SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Initialization
	fd_set ReadFDS, WriteFDS;
	timeval Timeout;
	memset(&ReadFDS, 0, sizeof(ReadFDS));
	memset(&WriteFDS, 0, sizeof(WriteFDS));
	memset(&Timeout, 0, sizeof(Timeout));
	ssize_t SelectResult = 0, RecvLen = 0;
	SYSTEM_SOCKET MaxSocket = INVALID_SOCKET;
	size_t Index = 0;

//Socket check(Send process)
	for (auto SocketDataItem = SocketDataList.begin();SocketDataItem != SocketDataList.end();++SocketDataItem)
	{
		if (SocketSetting(SocketDataItem->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			break;
		else if (SocketDataItem + 1U == SocketDataList.end())
			return EXIT_FAILURE;
	}

//Socket attribute setting
	if (Protocol == IPPROTO_TCP)
	{
	#if defined(PLATFORM_WIN)
		Timeout.tv_sec = Parameter.SocketTimeout_Reliable_Serial / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.SocketTimeout_Reliable_Serial % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		Timeout = Parameter.SocketTimeout_Reliable_Serial;
	#endif
	}
	else if (Protocol == IPPROTO_UDP)
	{
	#if defined(PLATFORM_WIN)
		Timeout.tv_sec = Parameter.SocketTimeout_Unreliable_Serial / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.SocketTimeout_Unreliable_Serial % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		Timeout = Parameter.SocketTimeout_Unreliable_Serial;
	#endif
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check and attribute setting
	for (Index = 0;Index < SocketSelectingDataList.size();++Index)
	{
		SocketSelectingDataList.at(Index).IsPacketDone = false;
		if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			ErrorCodeList.at(Index) = 0;
	}

//Selecting send process
	for (;;)
	{
	//Reset parameters.
		FD_ZERO(&WriteFDS);
		MaxSocket = INVALID_SOCKET;

	//Socket check and non-blocking process
		for (Index = 0;Index < SocketDataList.size();++Index)
		{
		//Select file descriptor set size and maximum socket index check(Part 2)
			if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr) && 
				SocketSelectingDataList.at(Index).SendBuffer && SocketSelectingDataList.at(Index).SendLen > 0 && 
				!SocketSelectingDataList.at(Index).IsPacketDone && ErrorCodeList.at(Index) == 0)
			{
			#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (SocketDataList.at(Index).Socket + 1U >= FD_SETSIZE)
				{
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
					continue;
				}
			#endif

			//Select structure initialization
				FD_SET(SocketDataList.at(Index).Socket, &WriteFDS);
				if (SocketDataList.at(Index).Socket > MaxSocket)
					MaxSocket = SocketDataList.at(Index).Socket;
			}
			else if (MaxSocket == INVALID_SOCKET && Index + 1U == SocketDataList.size())
			{
				goto StopLoop;
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, nullptr, &WriteFDS, nullptr, &Timeout);
	#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		SelectResult = select(MaxSocket + 1U, nullptr, &WriteFDS, nullptr, &Timeout);
	#endif
		if (SelectResult > 0)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
				if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr) && 
					!SocketSelectingDataList.at(Index).IsPacketDone && 
					FD_ISSET(SocketDataList.at(Index).Socket, &WriteFDS) != 0)
				{
				//Socket option check
				//Select will set both reading and writing sets and set SO_ERROR to error code when connection was failed.
					int OptionValue = 0;
					socklen_t OptionSize = sizeof(OptionValue);
					if (getsockopt(SocketDataList.at(Index).Socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&OptionValue), &OptionSize) == SOCKET_ERROR)
					{
						if (Protocol == IPPROTO_TCP)
							PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"TCP socket connecting error", WSAGetLastError(), nullptr, 0);
						else if (Protocol == IPPROTO_UDP)
							PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"UDP socket connecting error", WSAGetLastError(), nullptr, 0);
						ErrorCodeList.at(Index) = WSAGetLastError();
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

						continue;
					}
					else if (OptionValue > 0)
					{
						if (Protocol == IPPROTO_TCP)
							PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"TCP socket connecting error", OptionValue, nullptr, 0);
						else if (Protocol == IPPROTO_UDP)
							PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"UDP socket connecting error", OptionValue, nullptr, 0);
						ErrorCodeList.at(Index) = OptionValue;
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

						continue;
					}

				//Send data.
					if (send(SocketDataList.at(Index).Socket, reinterpret_cast<const char *>(SocketSelectingDataList.at(Index).SendBuffer.get()), static_cast<const int>(SocketSelectingDataList.at(Index).SendLen), 0) == SOCKET_ERROR)
					{
						ErrorCodeList.at(Index) = WSAGetLastError();

					//Send in progress.
					#if defined(PLATFORM_WIN)
						if (ErrorCodeList.at(Index) == WSAEWOULDBLOCK)
					#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
						if (ErrorCodeList.at(Index) == EAGAIN || ErrorCodeList.at(Index) == EINPROGRESS)
					#endif
						{
							ErrorCodeList.at(Index) = 0;
						}
					//SOCKET_ERROR
						else {
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
						}
					}
					else {
						SocketSelectingDataList.at(Index).IsPacketDone = true;
					}
				}
			}
		}
	//Timeout
		else if (SelectResult == 0)
		{
			for (Index = 0;Index < ErrorCodeList.size();++Index)
			{
				if (!SocketSelectingDataList.at(Index).IsPacketDone)
				{
					ErrorCodeList.at(Index) = WSAETIMEDOUT;
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				}
			}

			break;
		}
	//SOCKET_ERROR
		else {
			for (Index = 0;Index < ErrorCodeList.size();++Index)
			{
				ErrorCodeList.at(Index) = WSAGetLastError();
				SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			}

			return EXIT_FAILURE;
		}
	}

//Jump here to stop loop.
StopLoop:

//HTTP CONNECT shutdown connection is no need to receive anything.
	if (RequestType == REQUEST_PROCESS_TYPE::HTTP_CONNECT_SHUTDOWN)
		return EXIT_SUCCESS;

//Socket check(Receive process)
	for (auto SocketDataItem = SocketDataList.begin();SocketDataItem != SocketDataList.end();++SocketDataItem)
	{
		if (SocketSetting(SocketDataItem->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			break;
		else if (SocketDataItem + 1U == SocketDataList.end())
			return EXIT_FAILURE;
	}

//Socket check and attribute setting
	for (Index = 0;Index < SocketSelectingDataList.size();++Index)
	{
		SocketSelectingDataList.at(Index).IsPacketDone = false;
		if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			ErrorCodeList.at(Index) = 0;
	}

//Selecting receive process
	for (;;)
	{
	//Reset parameters.
		FD_ZERO(&ReadFDS);
		MaxSocket = INVALID_SOCKET;

	//Socket check and non-blocking process
		for (Index = 0;Index < SocketDataList.size();++Index)
		{
		//Select file descriptor set size and maximum socket index check(Part 3)
			if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr) && 
				!SocketSelectingDataList.at(Index).IsPacketDone && !SocketSelectingDataList.at(Index).IsSendOnly && 
				ErrorCodeList.at(Index) == 0)
			{
			#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (SocketDataList.at(Index).Socket + 1U >= FD_SETSIZE)
				{
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
					continue;
				}
			#endif

			//Select structure initialization
				FD_SET(SocketDataList.at(Index).Socket, &ReadFDS);
				if (SocketDataList.at(Index).Socket > MaxSocket)
					MaxSocket = SocketDataList.at(Index).Socket;
			}
			else if (MaxSocket == INVALID_SOCKET && Index + 1U == SocketDataList.size())
			{
				return EXIT_SUCCESS;
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, &ReadFDS, nullptr, nullptr, &Timeout);
	#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		SelectResult = select(MaxSocket + 1U, &ReadFDS, nullptr, nullptr, &Timeout);
	#endif
		if (SelectResult > 0)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
				if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr) && 
					!SocketSelectingDataList.at(Index).IsPacketDone && !SocketSelectingDataList.at(Index).IsSendOnly && 
					FD_ISSET(SocketDataList.at(Index).Socket, &ReadFDS) != 0)
				{
				//Socket option check
				//Select will set both reading and writing sets and set SO_ERROR to error code when connection was failed.
					int OptionValue = 0;
					socklen_t OptionSize = sizeof(OptionValue);
					if (getsockopt(SocketDataList.at(Index).Socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&OptionValue), &OptionSize) == SOCKET_ERROR)
					{
						if (Protocol == IPPROTO_TCP)
							PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"TCP socket connecting error", WSAGetLastError(), nullptr, 0);
						else if (Protocol == IPPROTO_UDP)
							PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"UDP socket connecting error", WSAGetLastError(), nullptr, 0);
						ErrorCodeList.at(Index) = WSAGetLastError();
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

						continue;
					}
					else if (OptionValue > 0)
					{
						if (Protocol == IPPROTO_TCP)
							PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"TCP socket connecting error", OptionValue, nullptr, 0);
						else if (Protocol == IPPROTO_UDP)
							PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"UDP socket connecting error", OptionValue, nullptr, 0);
						ErrorCodeList.at(Index) = OptionValue;
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

						continue;
					}

				//Receive data.
					for (;;)
					{
					//Prepare buffer.
						if (!SocketSelectingDataList.at(Index).RecvBuffer)
						{
							auto RecvBuffer = std::make_unique<uint8_t[]>(Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);
							memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize + MEMORY_RESERVED_BYTES);
							std::swap(SocketSelectingDataList.at(Index).RecvBuffer, RecvBuffer);
							SocketSelectingDataList.at(Index).RecvSize = Parameter.LargeBufferSize;
							SocketSelectingDataList.at(Index).RecvLen = 0;
						}
						else if (SocketSelectingDataList.at(Index).RecvSize <= SocketSelectingDataList.at(Index).RecvLen + Parameter.LargeBufferSize)
						{
							auto RecvBuffer = std::make_unique<uint8_t[]>(SocketSelectingDataList.at(Index).RecvSize + Parameter.LargeBufferSize);
							memset(RecvBuffer.get(), 0, SocketSelectingDataList.at(Index).RecvSize + Parameter.LargeBufferSize);
							memcpy_s(RecvBuffer.get(), SocketSelectingDataList.at(Index).RecvSize + Parameter.LargeBufferSize, SocketSelectingDataList.at(Index).RecvBuffer.get(), SocketSelectingDataList.at(Index).RecvLen);
							std::swap(SocketSelectingDataList.at(Index).RecvBuffer, RecvBuffer);
							SocketSelectingDataList.at(Index).RecvSize += Parameter.LargeBufferSize;
						}

					//Receive process
						RecvLen = recv(SocketDataList.at(Index).Socket, reinterpret_cast<char *>(SocketSelectingDataList.at(Index).RecvBuffer.get() + SocketSelectingDataList.at(Index).RecvLen), static_cast<const int>(SocketSelectingDataList.at(Index).RecvSize - SocketSelectingDataList.at(Index).RecvLen), 0);
						if (RecvLen == SOCKET_ERROR)
						{
							ErrorCodeList.at(Index) = WSAGetLastError();

						//Receive in progress.
						#if defined(PLATFORM_WIN)
							if (ErrorCodeList.at(Index) == WSAEWOULDBLOCK)
						#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							if (ErrorCodeList.at(Index) == EAGAIN || ErrorCodeList.at(Index) == EINPROGRESS)
						#endif
							{
								ErrorCodeList.at(Index) = 0;

							//Connection stream finished check
								if (Protocol == IPPROTO_UDP || CheckConnectionStreamFin(RequestType, SocketSelectingDataList.at(Index).RecvBuffer.get(), SocketSelectingDataList.at(Index).RecvLen))
									SocketSelectingDataList.at(Index).IsPacketDone = true;
							}
						//SOCKET_ERROR
							else {
								SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
							}

							break;
						}
						else if (RecvLen == 0) //Connection closed
						{
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
							break;
						}
						else {
							SocketSelectingDataList.at(Index).RecvLen += static_cast<const size_t>(RecvLen);
						}
					}
				}
			}
		}
	//Timeout
		else if (SelectResult == 0)
		{
			break; //Receive finished.
		}
	//SOCKET_ERROR
		else {
			for (Index = 0;Index < ErrorCodeList.size();++Index)
			{
				ErrorCodeList.at(Index) = WSAGetLastError();
				SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			}

			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

#if defined(ENABLE_PCAP)
//Register socket information to global list
void RegisterPortToList(
	const uint16_t Protocol, 
	const SOCKET_DATA * const LocalSocketData, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	const std::string * const DomainString_Original, 
	const std::string * const DomainString_Request
//	size_t *EDNS_Length
)
{
//Socket data check
	if (SocketDataList.empty())
		return;

//Register port.
	if (LocalSocketData != nullptr && Protocol > 0)
	{
		SOCKET_DATA SocketDataTemp;
		OUTPUT_PACKET_TABLE OutputPacketListTemp;
		memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
		SocketDataTemp.Socket = INVALID_SOCKET;

	//Register system connection data.
		OutputPacketListTemp.SocketData_Input = *LocalSocketData;
/* EDNS Label operations are different between DNS servers.
		if (Parameter.PacketCheck_DNS && EDNS_Length != nullptr)
			OutputPacketListTemp.EDNS_Length = *EDNS_Length;
*/

	//Register sending connection data.
		for (auto &SocketDataItem:SocketDataList)
		{
			if (!SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			{
				continue;
			}
			else {
				memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
				SocketDataTemp.Socket = INVALID_SOCKET;
			}

		//Get socket information(Socket).
			if (getsockname(SocketDataItem.Socket, reinterpret_cast<sockaddr *>(&SocketDataItem.SockAddr), &SocketDataItem.AddrLen) != 0)
			{
				SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				continue;
			}

		//Get socket information(Attributes).
			SocketDataTemp.AddrLen = SocketDataItem.AddrLen;
			if (SocketDataItem.AddrLen == sizeof(sockaddr_in6))
			{
				SocketDataTemp.SockAddr.ss_family = AF_INET6;
				reinterpret_cast<sockaddr_in6 *>(&SocketDataTemp.SockAddr)->sin6_port = reinterpret_cast<const sockaddr_in6 *>(&SocketDataItem.SockAddr)->sin6_port;
			}
			else if (SocketDataItem.AddrLen == sizeof(sockaddr_in))
			{
				SocketDataTemp.SockAddr.ss_family = AF_INET;
				reinterpret_cast<sockaddr_in *>(&SocketDataTemp.SockAddr)->sin_port = reinterpret_cast<const sockaddr_in *>(&SocketDataItem.SockAddr)->sin_port;
			}
			else {
				SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				continue;
			}

			OutputPacketListTemp.SocketData_Output.push_back(SocketDataTemp);
		}

	//Register send time.
		OutputPacketListTemp.Protocol_Network = Protocol;
		if (Protocol == IPPROTO_TCP)
		{
		#if defined(PLATFORM_WIN)
			OutputPacketListTemp.ClearPortTime = GetCurrentSystemTime() + Parameter.SocketTimeout_Reliable_Once;
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			OutputPacketListTemp.ClearPortTime = IncreaseMillisecondTime(GetCurrentSystemTime(), Parameter.SocketTimeout_Reliable_Once);
		#endif
		}
		else if (Protocol == IPPROTO_UDP)
		{
		#if defined(PLATFORM_WIN)
			OutputPacketListTemp.ClearPortTime = GetCurrentSystemTime() + Parameter.SocketTimeout_Unreliable_Once;
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			OutputPacketListTemp.ClearPortTime = IncreaseMillisecondTime(GetCurrentSystemTime(), Parameter.SocketTimeout_Unreliable_Once);
		#endif
		}
		else {
			return;
		}

	//Clear expired data.
		std::lock_guard<std::mutex> OutputPacketListMutex(OutputPacketListLock);
		while (!OutputPacketList.empty() && OutputPacketList.front().ClearPortTime <= GetCurrentSystemTime())
		{
		//Register timeout.
			if (OutputPacketList.front().ClearPortTime > 0)
			{
				if (OutputPacketList.front().Protocol_Network == AF_INET6)
				{
					if (OutputPacketList.front().Protocol_Transport == IPPROTO_TCP)
						++AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6);
					else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP)
						++AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV6);
				}
				else if (OutputPacketList.front().Protocol_Network == AF_INET)
				{
					if (OutputPacketList.front().Protocol_Transport == IPPROTO_TCP)
						++AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4);
					else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP)
						++AlternateSwapList.TimeoutTimes.at(ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV4);
				}
			}

			OutputPacketList.pop_front();
		}

	//Register to global list.
		if (DomainString_Original != nullptr)
			OutputPacketListTemp.DomainString_Original = *DomainString_Original;
		if (DomainString_Request != nullptr)
			OutputPacketListTemp.DomainString_Request = *DomainString_Request;
		OutputPacketList.push_back(OutputPacketListTemp);
	}

//Block Port Unreachable messages of system or close the TCP request connections.
	for (auto &SocketDataItem:SocketDataList)
	{
		if (SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			shutdown(SocketDataItem.Socket, SD_SEND);
	}
#if defined(PLATFORM_WIN)
	if (Protocol == IPPROTO_TCP)
		Sleep(Parameter.SocketTimeout_Reliable_Once);
//	else if (Protocol == IPPROTO_UDP)
	else 
		Sleep(Parameter.SocketTimeout_Unreliable_Once);
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (Protocol == IPPROTO_TCP)
		usleep(Parameter.SocketTimeout_Reliable_Once.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable_Once.tv_usec);
//	else if (Protocol == IPPROTO_UDP)
	else 
		usleep(Parameter.SocketTimeout_Unreliable_Once.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Unreliable_Once.tv_usec);
#endif
	for (auto &SocketDataItem:SocketDataList)
		SocketSetting(SocketDataItem.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

	return;
}
#endif
