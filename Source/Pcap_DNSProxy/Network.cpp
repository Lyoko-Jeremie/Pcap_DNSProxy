// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2017 Chengr28
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

#if defined(PLATFORM_WIN)
//Windows Firewall Test
bool FirewallTest(
	const uint16_t Protocol, 
	ssize_t &ErrorCode)
{
//Ramdom number distribution initialization
	std::uniform_int_distribution<uint16_t> RamdomDistribution(DYNAMIC_MIN_PORT, UINT16_MAX - 1U);
	sockaddr_storage SockAddr;
	memset(&SockAddr, 0, sizeof(SockAddr));
	SYSTEM_SOCKET FirewallSocket = 0;
	size_t Index = 0;
	ErrorCode = 0;

//IPv6
	if (Protocol == AF_INET6)
	{
		(reinterpret_cast<sockaddr_in6 *>(&SockAddr))->sin6_addr = in6addr_any;
		(reinterpret_cast<sockaddr_in6 *>(&SockAddr))->sin6_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
		SockAddr.ss_family = AF_INET6;
		FirewallSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	//Bind local socket.
		if (!SocketSetting(FirewallSocket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr))
		{
			ErrorCode = WSAGetLastError();
			return false;
		}
		else if (bind(FirewallSocket, reinterpret_cast<sockaddr *>(&SockAddr), sizeof(sockaddr_in6)) == SOCKET_ERROR)
		{
			(reinterpret_cast<sockaddr_in6 *>(&SockAddr))->sin6_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
			while (bind(FirewallSocket, reinterpret_cast<sockaddr *>(&SockAddr), sizeof(sockaddr_in6)) == SOCKET_ERROR)
			{
				if (Index < LOOP_MAX_TIMES && WSAGetLastError() == WSAEADDRINUSE)
				{
					(reinterpret_cast<sockaddr_in6 *>(&SockAddr))->sin6_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
					++Index;
				}
				else {
					ErrorCode = WSAGetLastError();
					SocketSetting(FirewallSocket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

					return false;
				}
			}
		}
	}
//IPv4
	else if (Protocol == AF_INET)
	{
		(reinterpret_cast<sockaddr_in *>(&SockAddr))->sin_addr.s_addr = INADDR_ANY;
		(reinterpret_cast<sockaddr_in *>(&SockAddr))->sin_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
		SockAddr.ss_family = AF_INET;
		FirewallSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	//Bind local socket.
		if (!SocketSetting(FirewallSocket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr))
		{
			ErrorCode = WSAGetLastError();
			return false;
		}
		else if (bind(FirewallSocket, reinterpret_cast<sockaddr *>(&SockAddr), sizeof(sockaddr_in)) == SOCKET_ERROR)
		{
			(reinterpret_cast<sockaddr_in *>(&SockAddr))->sin_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
			while (bind(FirewallSocket, reinterpret_cast<sockaddr *>(&SockAddr), sizeof(sockaddr_in)) == SOCKET_ERROR)
			{
				if (Index < LOOP_MAX_TIMES && WSAGetLastError() == WSAEADDRINUSE)
				{
					(reinterpret_cast<sockaddr_in *>(&SockAddr))->sin_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
					++Index;
				}
				else {
					ErrorCode = WSAGetLastError();
					SocketSetting(FirewallSocket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

					return false;
				}
			}
		}
	}
	else {
		return false;
	}

//Close socket.
	SocketSetting(FirewallSocket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	return true;
}
#endif

//Socket option settings
bool SocketSetting(
	const SYSTEM_SOCKET Socket, 
	const SOCKET_SETTING_TYPE SettingType, 
	const bool IsPrintError, 
	void * const DataPointer)
{
	switch (SettingType)
	{
	//Socket closing process
		case SOCKET_SETTING_TYPE::CLOSE:
		{
		#if defined(PLATFORM_WIN)
			if (Socket != 0 && Socket != INVALID_SOCKET && Socket != SOCKET_ERROR)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (Socket != 0 && Socket != INVALID_SOCKET)
		#endif
			{
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
			}
		}break;
	//Socket attribute setting(IPv4 header Do Not Fragment flag)
		case SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT:
		{
		#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
			if (Parameter.DoNotFragment)
			{
			#if defined(PLATFORM_WIN)
				const DWORD OptionValue = TRUE;
				if (setsockopt(Socket, IPPROTO_IP, IP_DONTFRAGMENT, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				const int OptionValue = IP_PMTUDISC_DO;
				if (setsockopt(Socket, IPPROTO_IP, IP_MTU_DISCOVER, &OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket Do Not Fragment flag setting error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);

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
			//Socket attribute setting process
			#if defined(PLATFORM_WIN)
				std::uniform_int_distribution<DWORD> RamdomDistribution(Parameter.PacketHopLimits_IPv6_Begin, Parameter.PacketHopLimits_IPv6_End);
				const auto OptionValue = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				std::uniform_int_distribution<int> RamdomDistribution(Parameter.PacketHopLimits_IPv6_Begin, Parameter.PacketHopLimits_IPv6_End);
				const auto OptionValue = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket Hop Limits setting error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);

					return false;
				}
			}
		//Value
			else if (Parameter.PacketHopLimits_IPv6_Begin > 0)
			{
			#if defined(PLATFORM_WIN)
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, reinterpret_cast<const char *>(&Parameter.PacketHopLimits_IPv6_Begin), sizeof(Parameter.PacketHopLimits_IPv6_Begin)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &Parameter.PacketHopLimits_IPv6_Begin, sizeof(Parameter.PacketHopLimits_IPv6_Begin)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket Hop Limits setting error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);

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
			//Socket attribute setting process
			#if defined(PLATFORM_WIN)
				std::uniform_int_distribution<DWORD> RamdomDistribution(Parameter.PacketHopLimits_IPv4_Begin, Parameter.PacketHopLimits_IPv4_End);
				const auto OptionValue = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				std::uniform_int_distribution<int> RamdomDistribution(Parameter.PacketHopLimits_IPv4_Begin, Parameter.PacketHopLimits_IPv4_End);
				const auto OptionValue = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, &OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket Hop Limits setting error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);

					return false;
				}
			}
		//Value
			else if (Parameter.PacketHopLimits_IPv4_Begin > 0)
			{
			#if defined(PLATFORM_WIN)
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, reinterpret_cast<const char *>(&Parameter.PacketHopLimits_IPv4_Begin), sizeof(Parameter.PacketHopLimits_IPv4_Begin)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, &Parameter.PacketHopLimits_IPv4_Begin, sizeof(Parameter.PacketHopLimits_IPv4_Begin)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket Hop Limits setting error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);

					return false;
				}
			}
		}break;
	//Socket invalid check
		case SOCKET_SETTING_TYPE::INVALID_CHECK:
		{
		#if defined(PLATFORM_WIN)
			if (Socket == 0 || Socket == INVALID_SOCKET || Socket == SOCKET_ERROR)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
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
			unsigned long SocketMode = TRUE;
			if (ioctlsocket(Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			const auto SocketMode = fcntl(Socket, F_GETFL, 0);
			if (SocketMode == RETURN_ERROR || fcntl(Socket, F_SETFL, SocketMode | O_NONBLOCK) == RETURN_ERROR)
		#endif
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket non-blocking mode setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		}break;
	//Socket attribute setting(Reusing)
		case SOCKET_SETTING_TYPE::REUSE:
		{
		#if defined(PLATFORM_WIN)
		//Preventing other sockets from being forcibly bound to the same address and port(Windows).
			const DWORD OptionValue = TRUE;
			if (setsockopt(Socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket reusing disable setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			const int OptionValue = TRUE;

		//Set TIME_WAIT resuing(Linux/macOS).
/*			errno = 0;
			if (setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket reusing enable setting error", errno, nullptr, 0);
				shutdown(Socket, SHUT_RDWR);
				close(Socket);

				return false;
			}
*/
		//Set an IPv6 server socket that must not accept IPv4 connections(Linux/macOS).
			errno = 0;
			if (setsockopt(Socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket treating wildcard bind setting error", errno, nullptr, 0);
				shutdown(Socket, SHUT_RDWR);
				close(Socket);

				return false;
			}
		#endif
		}break;
	//Socket attribute setting(TFO/TCP Fast Open)
		case SOCKET_SETTING_TYPE::TCP_FAST_OPEN:
		{
		//Socket attribute setting process
			if (Parameter.TCP_FastOpen > 0)
			{
			//Windows: Server side is completed but need to confirm in the new SDK, client side is only support overlapped I/O so waiting Microsoft to extend it to normal socket(2017-04-02).
			//Linux: Server side and client side is both completed, also support queue length.
			//macOS: Server side and client side is both completed.
			#if defined(PLATFORM_WIN)
				const DWORD OptionValue = TRUE;
				if (setsockopt(Socket, IPPROTO_TCP, TCP_FASTOPEN, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket TCP Fast Open setting error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);

					return false;
				}
			#elif (defined(PLATFORM_LINUX) || defined(PLATFOEM_MACOS))
				errno = 0;
			#if defined(PLATFORM_LINUX)
				const int OptionValue = Parameter.TCP_FastOpen;
				if (setsockopt(Socket, SOL_TCP, TCP_FASTOPEN, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#elif defined(PLATFOEM_MACOS)
				const int OptionValue = TRUE;
				if (setsockopt(Socket, IPPROTO_TCP, TCP_FASTOPEN, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket TCP Fast Open setting error", errno, nullptr, 0);
					shutdown(Socket, SHUT_RDWR);
					close(Socket);

					return false;
				}
			#endif
			}
		}break;
/* TCP keep alive mode
	//Socket attribute setting(TCP keep alive mode)
		case SOCKET_SETTING_TYPE::TCP_KEEP_ALIVE:
		{
		#if defined(PLATFORM_WIN)
			const DWORD OptionValue = TRUE;
			if (setsockopt(Socket, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			{
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}

			tcp_keepalive Alive_IN;
			tcp_keepalive Alive_OUT;
			memset(&Alive_IN, 0, sizeof(tcp_keepalive));
			memset(&Alive_OUT, 0, sizeof(tcp_keepalive));
			Alive_IN.keepalivetime = STANDARD_TIMEOUT;
			Alive_IN.keepaliveinterval = Parameter.SocketTimeout_Reliable_Once;
			Alive_IN.onoff = TRUE;
			ULONG ulBytesReturn = 0;
			if (WSAIoctl(Socket, SIO_KEEPALIVE_VALS, &Alive_IN, sizeof(tcp_keepalive), &Alive_OUT, sizeof(tcp_keepalive), &ulBytesReturn, nullptr, nullptr) == SOCKET_ERROR)
			{
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			const int OptionValue = TRUE;
			if (setsockopt(Socket, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			{
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		#endif
		}break;
*/
	//Socket attribute setting(Timeout)
		case SOCKET_SETTING_TYPE::TIMEOUT:
		{
		//Pointer check
			if (DataPointer == nullptr)
				return false;

		//Socket timeout options
		#if defined(PLATFORM_WIN)
			const auto OptionValue = *reinterpret_cast<DWORD *>(DataPointer);
			if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR || 
				setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(DataPointer), sizeof(timeval)) == SOCKET_ERROR || 
				setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(DataPointer), sizeof(timeval)) == SOCKET_ERROR)
		#endif
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket timeout setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

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
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket UDP block RESET message setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		#endif
		}break;
	}

	return true;
}

//Select socket data of DNS target
size_t SelectTargetSocketSingle(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
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

	//IPv6
		if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0 && 
			((DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
			DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV6 || //IPv6
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV4 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0))) //Non-IPv4
		{
		//Timeout settings
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV6];
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV6];
			}
			else {
				return EXIT_FAILURE;
			}

		//Encryption mode check
			if (DNSCurveParameter.IsEncryption)
			{
				if ((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
						**IsAlternate = true;
				if (**IsAlternate && 
					((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
						**IsAlternate = false;
			}

		//Alternate
			if (**IsAlternate && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
			{
				(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_addr = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr;
				(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_port = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_port;
				*PacketTarget = &DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6;
				*reinterpret_cast<DNSCURVE_SERVER_TYPE *>(DNSCurvePacketServerType) = DNSCURVE_SERVER_TYPE::ALTERNATE_IPV6;
			}
		//Main
			else {
			//Encryption mode check
				if (DNSCurveParameter.IsEncryption && 
					((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
						return EXIT_FAILURE;

				(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_addr = DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr;
				(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_port = DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.IPv6.sin6_port;
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
				TargetSocketData->Socket = 0;

				return EXIT_FAILURE;
			}
		}
	//IPv4
		else if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
			((DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
			DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV4 || //IPv4
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_NETWORK::IPV6 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0))) //Non-IPv6
		{
		//Timeout settings
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_TCP_IPV4];
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_DNSCURVE_UDP_IPV4];
			}
			else {
				return EXIT_FAILURE;
			}

		//Encryption mode check
			if (DNSCurveParameter.IsEncryption)
			{
				if ((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN))
						**IsAlternate = true;
				if (**IsAlternate && 
					((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
						**IsAlternate = false;
			}

		//Alternate
			if (**IsAlternate && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0)
			{
				(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_addr = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr;
				(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_port = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.IPv4.sin_port;
				*PacketTarget = &DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4;
				*reinterpret_cast<DNSCURVE_SERVER_TYPE *>(DNSCurvePacketServerType) = DNSCURVE_SERVER_TYPE::ALTERNATE_IPV4;
			}
		//Main
			else {
			//Encryption mode check
				if (DNSCurveParameter.IsEncryption && 
					((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
						return EXIT_FAILURE;

				(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_addr = DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.IPv4.sin_addr;
				(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_port = DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.IPv4.sin_port;
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
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

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
			(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_addr = SpecifieTargetData->IPv6.sin6_addr;
			(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_port = SpecifieTargetData->IPv6.sin6_port;
			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return EXIT_FAILURE;
			}
		}
		else if (SpecifieTargetData->Storage.ss_family == AF_INET)
		{
			(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_addr = SpecifieTargetData->IPv4.sin_addr;
			(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_port = SpecifieTargetData->IPv4.sin_port;
			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return EXIT_FAILURE;
			}
		}
		else {
			return EXIT_FAILURE;
		}
	}
//Local request
	else if (RequestType == REQUEST_PROCESS_TYPE::LOCAL)
	{
	//IPv6
		if (Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family != 0 && 
			((Parameter.LocalProtocol_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
			Parameter.LocalProtocol_Network == REQUEST_MODE_NETWORK::IPV6 || //IPv6
			(Parameter.LocalProtocol_Network == REQUEST_MODE_NETWORK::IPV4 && Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family == 0))) //Non-IPv4
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_LOCAL_TCP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_LOCAL_TCP_IPV6];
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_LOCAL_UDP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_LOCAL_UDP_IPV6];
			}
			else {
				return EXIT_FAILURE;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Local_Alternate_IPv6.Storage.ss_family != 0)
			{
				(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_addr = Parameter.Target_Server_Local_Alternate_IPv6.IPv6.sin6_addr;
				(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_port = Parameter.Target_Server_Local_Alternate_IPv6.IPv6.sin6_port;
			}
		//Main
			else {
				(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_addr = Parameter.Target_Server_Local_Main_IPv6.IPv6.sin6_addr;
				(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_port = Parameter.Target_Server_Local_Main_IPv6.IPv6.sin6_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return EXIT_FAILURE;
			}
		}
	//IPv4
		else if (Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family != 0 && 
			((Parameter.LocalProtocol_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
			Parameter.LocalProtocol_Network == REQUEST_MODE_NETWORK::IPV4 || //IPv4
			(Parameter.LocalProtocol_Network == REQUEST_MODE_NETWORK::IPV6 && Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family == 0))) //Non-IPv6
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_LOCAL_TCP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_LOCAL_TCP_IPV4];
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_LOCAL_UDP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_LOCAL_UDP_IPV4];
			}
			else {
				return EXIT_FAILURE;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Local_Alternate_IPv4.Storage.ss_family != 0)
			{
				(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_addr = Parameter.Target_Server_Local_Alternate_IPv4.IPv4.sin_addr;
				(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_port = Parameter.Target_Server_Local_Alternate_IPv4.IPv4.sin_port;
			}
		//Main
			else {
				(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_addr = Parameter.Target_Server_Local_Main_IPv4.IPv4.sin_addr;
				(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_port = Parameter.Target_Server_Local_Main_IPv4.IPv4.sin_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return EXIT_FAILURE;
			}
		}
		else {
			return EXIT_FAILURE;
		}
	}
//Main request
	else {
	//IPv6
		if (Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0 && 
			((Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
			Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV6 || //IPv6
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV4 && Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0))) //Non-IPv4
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6];
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV6];
			}
			else {
				return EXIT_FAILURE;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
			{
				(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_addr = Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr;
				(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_port = Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
		//Main
			else {
				(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_addr = Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr;
				(reinterpret_cast<sockaddr_in6 *>(&TargetSocketData->SockAddr))->sin6_port = Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return EXIT_FAILURE;
			}
		}
	//IPv4
		else if (Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
			((Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
			Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV4 || //IPv4
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV6 && Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0))) //Non-IPv6
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4];
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV4];
			}
			else {
				return EXIT_FAILURE;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0)
			{
				(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_addr = Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr;
				(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_port = Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_port;
			}
		//Main
			else {
				(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_addr = Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_addr;
				(reinterpret_cast<sockaddr_in *>(&TargetSocketData->SockAddr))->sin_port = Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

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
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &TargetSocketDataList)
{
//Initialization
	SOCKET_DATA TargetSocketData;
	memset(&TargetSocketData, 0, sizeof(TargetSocketData));
	uint16_t SocketType = 0;
	size_t Index = 0;
	bool *IsAlternate = nullptr;
	if (Protocol == IPPROTO_TCP)
		SocketType = SOCK_STREAM;
	else if (Protocol == IPPROTO_UDP)
		SocketType = SOCK_DGRAM;
	else 
		return false;

//IPv6
	if (Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0 && 
		((Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV6 || //IPv6
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV4 && Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0))) //Non-IPv4
	{
	//Set Alternate swap list.
		if (Protocol == IPPROTO_TCP)
			IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6];
		else if (Protocol == IPPROTO_UDP)
			IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV6];
		else 
			return false;

	//Main
		if (!*IsAlternate)
		{
			for (Index = 0;Index < Parameter.MultipleRequestTimes;++Index)
			{
				memset(&TargetSocketData, 0, sizeof(TargetSocketData));
				TargetSocketData.SockAddr = Parameter.Target_Server_Main_IPv6.AddressData.Storage;
				TargetSocketData.Socket = socket(AF_INET6, SocketType, Protocol);

			//Socket attribute settings
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
					(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
				{
					for (auto &SocketDataIter:TargetSocketDataList)
					{
						SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
						SocketDataIter.Socket = 0;
					}

					return false;
				}

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
				TargetSocketData.Socket = socket(AF_INET6, SocketType, Protocol);

			//Socket attribute settings
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
					(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
				{
					for (auto &SocketDataIter:TargetSocketDataList)
					{
						SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
						SocketDataIter.Socket = 0;
					}

					return false;
				}

				TargetSocketData.AddrLen = sizeof(sockaddr_in6);
				TargetSocketDataList.push_back(TargetSocketData);
			}
		}

	//Other servers
		if (Parameter.Target_Server_IPv6_Multiple != nullptr && !*IsAlternate && Parameter.AlternateMultipleRequest)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multiple)
			{
				for (Index = 0;Index < Parameter.MultipleRequestTimes;++Index)
				{
					memset(&TargetSocketData, 0, sizeof(TargetSocketData));
					TargetSocketData.SockAddr = DNSServerDataIter.AddressData.Storage;
					TargetSocketData.Socket = socket(AF_INET6, SocketType, Protocol);

				//Socket attribute settings
					if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
						(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr))
					{
						for (auto &SocketDataIter:TargetSocketDataList)
						{
							SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
							SocketDataIter.Socket = 0;
						}

						return false;
					}

					TargetSocketData.AddrLen = sizeof(sockaddr_in6);
					TargetSocketDataList.push_back(TargetSocketData);
				}
			}
		}
	}
//IPv4
	else if (Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
		((Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV4 || //IPv4
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK::IPV6 && Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0))) //Non-IPv6
	{
	//Set Alternate swap list.
		if (Protocol == IPPROTO_TCP)
			IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4];
		else if (Protocol == IPPROTO_UDP)
			IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV4];
		else 
			return false;

	//Main
		if (!*IsAlternate)
		{
			for (Index = 0;Index < Parameter.MultipleRequestTimes;++Index)
			{
				memset(&TargetSocketData, 0, sizeof(TargetSocketData));
				TargetSocketData.SockAddr = Parameter.Target_Server_Main_IPv4.AddressData.Storage;
				TargetSocketData.Socket = socket(AF_INET, SocketType, Protocol);

			//Socket attribute settings
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
					(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))
				{
					for (auto &SocketDataIter:TargetSocketDataList)
					{
						SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
						SocketDataIter.Socket = 0;
					}

					return false;
				}

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
				TargetSocketData.Socket = socket(AF_INET, SocketType, Protocol);

			//Socket attribute settings
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
					(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))
				{
					for (auto &SocketDataIter:TargetSocketDataList)
					{
						SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
						SocketDataIter.Socket = 0;
					}

					return false;
				}

				TargetSocketData.AddrLen = sizeof(sockaddr_in);
				TargetSocketDataList.push_back(TargetSocketData);
			}
		}

	//Other servers
		if (Parameter.Target_Server_IPv4_Multiple != nullptr && !*IsAlternate && Parameter.AlternateMultipleRequest)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multiple)
			{
				for (Index = 0;Index < Parameter.MultipleRequestTimes;++Index)
				{
					memset(&TargetSocketData, 0, sizeof(TargetSocketData));
					TargetSocketData.SockAddr = DNSServerDataIter.AddressData.Storage;
					TargetSocketData.Socket = socket(AF_INET, SocketType, Protocol);

				//Socket attribute settings
					if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
						(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr)) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))
					{
						for (auto &SocketDataIter:TargetSocketDataList)
						{
							SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
							SocketDataIter.Socket = 0;
						}

						return false;
					}

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
	const SYSTEM_SOCKET Socket, 
	const sockaddr * const SockAddr, 
	const socklen_t AddrLen, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize)
{
//TCP connecting
	if (Protocol == IPPROTO_TCP)
	{
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (Parameter.TCP_FastOpen > 0 && OriginalSend != nullptr && SendSize > 0)
		{
			errno = 0;
			
		#if defined(PLATFORM_LINUX)
		//Send request and it will automatic connect to server.
			ssize_t RecvLen = sendto(Socket, OriginalSend, SendSize, MSG_FASTOPEN, SockAddr, AddrLen);
			if (RecvLen == SOCKET_ERROR && errno != EAGAIN && errno != EINPROGRESS)
				return EXIT_FAILURE;
			else if (RecvLen < static_cast<ssize_t>(DNS_PACKET_MINSIZE))
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
				(reinterpret_cast<sockaddr_in6 *>(const_cast<sockaddr *>(EndPoints.sae_dstaddr)))->sin6_len = sizeof(sockaddr_in6);
			else if (AddrLen == sizeof(sockaddr_in))
				(reinterpret_cast<sockaddr_in *>(const_cast<sockaddr *>(EndPoints.sae_dstaddr)))->sin_len = sizeof(sockaddr_in);
			else 
				return EXIT_FAILURE;
			
		//Hold connecting to server.
			ssize_t RecvLen = connectx(Socket, &EndPoints, SAE_ASSOCID_ANY, CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT, nullptr, 0, nullptr, nullptr);
			if (RecvLen == SOCKET_ERROR && errno != EAGAIN && errno != EINPROGRESS)
				return EXIT_FAILURE;
			
		//Send request and it will automatic connect to server.
			RecvLen = send(Socket, OriginalSend, SendSize, 0);
			if (RecvLen == SOCKET_ERROR && errno != EAGAIN && errno != EINPROGRESS)
				return EXIT_FAILURE;
			else if (RecvLen < static_cast<ssize_t>(DNS_PACKET_MINSIZE))
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
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (ErrorCode != EAGAIN && ErrorCode != EINPROGRESS)
			#endif
					return EXIT_FAILURE;
			}
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		}
	#endif
	}
//UDP connecting
	else if (Protocol == IPPROTO_UDP)
	{
		if (connect(Socket, SockAddr, AddrLen) == SOCKET_ERROR)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"Socket connecting error", WSAGetLastError(), nullptr, 0);
			SocketSetting(Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

			return EXIT_FAILURE;
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
	void * const OriginalDNSCurveSocketSelectingList, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	ssize_t * const ErrorCode)
{
//Socket data check
	if (SocketDataList.empty())
		return EXIT_FAILURE;

//Initialization(Part 1)
	std::vector<SOCKET_SELECTING_ONCE_TABLE> SocketSelectingList(SocketDataList.size());
	size_t Index = 0;
	ssize_t RecvLen = 0;
	if (ErrorCode != nullptr)
		*ErrorCode = 0;
#if defined(ENABLE_LIBSODIUM)
	auto DNSCurveSocketSelectingList = reinterpret_cast<std::vector<DNSCURVE_SOCKET_SELECTING_TABLE> *>(OriginalDNSCurveSocketSelectingList);
	if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
	{
		if (DNSCurveSocketSelectingList == nullptr)
			return EXIT_FAILURE;
	}
#endif

//TCP or UDP connecting
	for (Index = 0;Index < SocketDataList.size();++Index)
	{
	//Set send buffer(DNSCurve).
	#if defined(ENABLE_LIBSODIUM)
		if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
			RecvLen = SocketConnecting(Protocol, SocketDataList.at(Index).Socket, reinterpret_cast<sockaddr *>(&SocketDataList.at(Index).SockAddr), SocketDataList.at(Index).AddrLen, DNSCurveSocketSelectingList->at(Index).SendBuffer, DNSCurveSocketSelectingList->at(Index).SendSize);
		else 
	#endif
			RecvLen = SocketConnecting(Protocol, SocketDataList.at(Index).Socket, reinterpret_cast<sockaddr *>(&SocketDataList.at(Index).SockAddr), SocketDataList.at(Index).AddrLen, OriginalSend, SendSize);
		if (RecvLen == EXIT_FAILURE)
		{
			SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			SocketDataList.at(Index).Socket = 0;
		}
		else if (Protocol == IPPROTO_TCP && Parameter.TCP_FastOpen > 0 && RecvLen >= static_cast<ssize_t>(DNS_PACKET_MINSIZE))
		{
		#if defined(ENABLE_LIBSODIUM)
			if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
				DNSCurveSocketSelectingList->at(Index).IsPacketDone = true;
			else 
		#endif
				SocketSelectingList.at(Index).IsPacketDone = true;
		}
	}

//Socket check(Part 1)
	for (auto SocketDataIter = SocketDataList.begin();SocketDataIter != SocketDataList.end();++SocketDataIter)
	{
		if (SocketSetting(SocketDataIter->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			break;
		else if (SocketDataIter + 1U == SocketDataList.end())
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
	if (OriginalRecv == nullptr
	#if defined(ENABLE_LIBSODIUM)
		&& RequestType != REQUEST_PROCESS_TYPE::DNSCURVE_MAIN
	#endif
		)
	{
		std::unique_ptr<uint8_t[]> RecvBufferSwap(new uint8_t[PACKET_MAXSIZE]());
		memset(RecvBufferSwap.get(), 0, PACKET_MAXSIZE);
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
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			Timeout = DNSCurveParameter.DNSCurve_SocketTimeout_Reliable;
		#endif
		}
		else { //UDP
		#if defined(PLATFORM_WIN)
			Timeout.tv_sec = DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable / SECOND_TO_MILLISECOND;
			Timeout.tv_usec = DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			Timeout = DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable;
		#endif
		}
	}
	else {
#endif
		if (Protocol == IPPROTO_TCP)
		{
		#if defined(PLATFORM_WIN)
			Timeout.tv_sec = Parameter.SocketTimeout_Reliable_Once / SECOND_TO_MILLISECOND;
			Timeout.tv_usec = Parameter.SocketTimeout_Reliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			Timeout = Parameter.SocketTimeout_Reliable_Once;
		#endif
		}
		else { //UDP
		#if defined(PLATFORM_WIN)
			Timeout.tv_sec = Parameter.SocketTimeout_Unreliable_Once / SECOND_TO_MILLISECOND;
			Timeout.tv_usec = Parameter.SocketTimeout_Unreliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			Timeout = Parameter.SocketTimeout_Unreliable_Once;
		#endif
		}
#if defined(ENABLE_LIBSODIUM)
	}
#endif

//Selecting process
	for (;;)
	{
		auto IsAllSocketShutdown = false;

	//Socket check(Part 2)
		for (auto SocketDataIter = SocketDataList.begin();SocketDataIter != SocketDataList.end();++SocketDataIter)
		{
			if (SocketSetting(SocketDataIter->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			{
				break;
			}
			else if (SocketDataIter + 1U == SocketDataList.end())
			{
				if (RequestType == REQUEST_PROCESS_TYPE::UDP_WITHOUT_MARKING)
					return EXIT_SUCCESS;
				else 
					IsAllSocketShutdown = true;
			}
		}

	//Buffer list check(Part 1)
		if (OriginalRecv != nullptr && (IsAllSocketShutdown || Parameter.ReceiveWaiting == 0 || SocketDataList.size() == 1U))
		{
		//Scan all result.
		#if defined(ENABLE_LIBSODIUM)
			if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
				RecvLen = SelectingResultOnce(RequestType, Protocol, SocketDataList, nullptr, DNSCurveSocketSelectingList, OriginalRecv, RecvSize);
			else 
		#endif
				RecvLen = SelectingResultOnce(RequestType, Protocol, SocketDataList, &SocketSelectingList, nullptr, OriginalRecv, RecvSize);

		//Get result or all socket cloesed
			if (RecvLen >= static_cast<ssize_t>(DNS_PACKET_MINSIZE))
				return RecvLen;
			else if (IsAllSocketShutdown)
				return EXIT_FAILURE;
		}

	//Reset parameters.
		FD_ZERO(&ReadFDS);
		FD_ZERO(&WriteFDS);
		SYSTEM_SOCKET MaxSocket = 0;
			
	//Socket check and non-blocking process
		for (Index = 0;Index < SocketDataList.size();++Index)
		{
		//Non-blocking process
			if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			{
			//Select structure initialization
				if (SocketDataList.at(Index).Socket > MaxSocket)
					MaxSocket = SocketDataList.at(Index).Socket;

			//Receive and send process
				FD_SET(SocketDataList.at(Index).Socket, &ReadFDS);
				if (
				#if defined(ENABLE_LIBSODIUM)
					(RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN && !DNSCurveSocketSelectingList->at(Index).IsPacketDone) || 
				#endif
					(
				#if defined(ENABLE_LIBSODIUM)
					RequestType != REQUEST_PROCESS_TYPE::DNSCURVE_MAIN && 
				#endif
					!SocketSelectingList.at(Index).IsPacketDone))
						FD_SET(SocketDataList.at(Index).Socket, &WriteFDS);
			}
			else if (MaxSocket == 0 && Index + 1U == SocketDataList.size())
			{
				return EXIT_FAILURE;
			}
		}

	//Send request only.
		if (OriginalRecv == nullptr && 
			RequestType != REQUEST_PROCESS_TYPE::UDP_WITHOUT_MARKING
		#if defined(ENABLE_LIBSODIUM)
			&& RequestType != REQUEST_PROCESS_TYPE::DNSCURVE_MAIN
		#endif
			)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
				if (!SocketSelectingList.at(Index).IsPacketDone)
					break;
				else if (Index + 1U == SocketDataList.size())
					return EXIT_SUCCESS;
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		ssize_t SelectResult = select(0, &ReadFDS, &WriteFDS, nullptr, &Timeout);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		ssize_t SelectResult = select(MaxSocket + 1U, &ReadFDS, &WriteFDS, nullptr, &Timeout);
	#endif
		if (SelectResult > 0)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
			#if defined(ENABLE_LIBSODIUM)
			//DNSCurve
				if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
				{
				//Receive process
					if (FD_ISSET(SocketDataList.at(Index).Socket, &ReadFDS))
					{
					//Buffer initialization
						if (!DNSCurveSocketSelectingList->at(Index).RecvBuffer)
						{
							std::unique_ptr<uint8_t[]> DNSCurveRecvBuffer(new uint8_t[RecvSize]());
							sodium_memzero(DNSCurveRecvBuffer.get(), RecvSize);
							std::swap(DNSCurveSocketSelectingList->at(Index).RecvBuffer, DNSCurveRecvBuffer);
						}

					//Receive from selecting.
						RecvLen = recv(SocketDataList.at(Index).Socket, reinterpret_cast<char *>(DNSCurveSocketSelectingList->at(Index).RecvBuffer.get() + DNSCurveSocketSelectingList->at(Index).RecvLen), static_cast<int>(RecvSize - DNSCurveSocketSelectingList->at(Index).RecvLen), 0);

					//Connection closed or SOCKET_ERROR
						if (RecvLen <= 0)
						{
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
							SocketDataList.at(Index).Socket = 0;
							DNSCurveSocketSelectingList->at(Index).RecvBuffer.reset();
							DNSCurveSocketSelectingList->at(Index).RecvLen = 0;
							continue;
						}
						else if (Protocol == IPPROTO_UDP && RecvLen >= static_cast<ssize_t>(DNS_PACKET_MINSIZE) && DNSCurveSocketSelectingList->at(Index).RecvLen > 0)
						{
							sodium_memzero(DNSCurveSocketSelectingList->at(Index).RecvBuffer.get(), DNSCurveSocketSelectingList->at(Index).RecvLen);
							memmove_s(DNSCurveSocketSelectingList->at(Index).RecvBuffer.get(), RecvSize, DNSCurveSocketSelectingList->at(Index).RecvBuffer.get() + DNSCurveSocketSelectingList->at(Index).RecvLen, RecvLen);
							DNSCurveSocketSelectingList->at(Index).RecvLen = 0;
						}

					//Mark whole packet length and last packet.
						DNSCurveSocketSelectingList->at(Index).RecvLen += RecvLen;
						LastReceiveIndex = Index;
					}

				//Send process
					if (FD_ISSET(SocketDataList.at(Index).Socket, &WriteFDS) && !DNSCurveSocketSelectingList->at(Index).IsPacketDone)
					{
						if (send(SocketDataList.at(Index).Socket, reinterpret_cast<const char *>(DNSCurveSocketSelectingList->at(Index).SendBuffer), static_cast<int>(DNSCurveSocketSelectingList->at(Index).SendSize), 0) == SOCKET_ERROR)
						{
							ssize_t InnerErrorCode = WSAGetLastError();
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
							SocketDataList.at(Index).Socket = 0;

						#if defined(PLATFORM_WIN)
							if (InnerErrorCode == WSAEWOULDBLOCK)
						#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							if (InnerErrorCode == EAGAIN || InnerErrorCode == EINPROGRESS)
						#endif
							{
								DNSCurveSocketSelectingList->at(Index).RecvBuffer.reset();
								DNSCurveSocketSelectingList->at(Index).RecvLen = 0;
							}
						}
						else {
							DNSCurveSocketSelectingList->at(Index).IsPacketDone = true;
						}
					}
				}
			//Normal
				else {
			#endif
				//Receive process
					if (FD_ISSET(SocketDataList.at(Index).Socket, &ReadFDS))
					{
						if (OriginalRecv != nullptr)
						{
						//Buffer initialization
							if (!SocketSelectingList.at(Index).RecvBuffer)
							{
								std::unique_ptr<uint8_t[]> RecvBufferSwap(new uint8_t[RecvSize]());
								memset(RecvBufferSwap.get(), 0, RecvSize);
								std::swap(SocketSelectingList.at(Index).RecvBuffer, RecvBufferSwap);
							}

						//Receive from selecting.
							RecvLen = recv(SocketDataList.at(Index).Socket, reinterpret_cast<char *>(SocketSelectingList.at(Index).RecvBuffer.get() + SocketSelectingList.at(Index).RecvLen), static_cast<int>(RecvSize - SocketSelectingList.at(Index).RecvLen), 0);

						//Connection closed or SOCKET_ERROR
							if (RecvLen <= 0)
							{
								SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
								SocketDataList.at(Index).Socket = 0;
								SocketSelectingList.at(Index).RecvBuffer.reset();
								SocketSelectingList.at(Index).RecvLen = 0;
								continue;
							}
							else if (Protocol == IPPROTO_UDP && RecvLen >= static_cast<ssize_t>(DNS_PACKET_MINSIZE) && SocketSelectingList.at(Index).RecvLen > 0)
							{
								memset(SocketSelectingList.at(Index).RecvBuffer.get(), 0, SocketSelectingList.at(Index).RecvLen);
								memmove_s(SocketSelectingList.at(Index).RecvBuffer.get(), RecvSize, SocketSelectingList.at(Index).RecvBuffer.get() + SocketSelectingList.at(Index).RecvLen, RecvLen);
								SocketSelectingList.at(Index).RecvLen = 0;
							}

						//Mark whole packet length and last packet.
							SocketSelectingList.at(Index).RecvLen += RecvLen;
							LastReceiveIndex = Index;
						}
						else {
						//Receive, drop all data and close sockets.
							recv(SocketDataList.at(Index).Socket, reinterpret_cast<char *>(RecvBufferTemp.get()), PACKET_MAXSIZE, 0);
							memset(RecvBufferTemp.get(), 0, PACKET_MAXSIZE);
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
							SocketDataList.at(Index).Socket = 0;
						}
					}

				//Send process
					if (FD_ISSET(SocketDataList.at(Index).Socket, &WriteFDS) && !SocketSelectingList.at(Index).IsPacketDone)
					{
						if (send(SocketDataList.at(Index).Socket, reinterpret_cast<const char *>(OriginalSend), static_cast<int>(SendSize), 0) == SOCKET_ERROR)
						{
							ssize_t InnerErrorCode = WSAGetLastError();
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
							SocketDataList.at(Index).Socket = 0;

						#if defined(PLATFORM_WIN)
							if (InnerErrorCode == WSAEWOULDBLOCK)
						#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							if (InnerErrorCode == EAGAIN || InnerErrorCode == EINPROGRESS)
						#endif
							{
								SocketSelectingList.at(Index).RecvBuffer.reset();
								SocketSelectingList.at(Index).RecvLen = 0;
							}
						}
						else {
							SocketSelectingList.at(Index).IsPacketDone = true;
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
					const auto PrecomputationKeyTemp = DNSCurveSocketSelectingList->at(Index).PrecomputationKey;
					DNSCurveSocketSelectingList->at(Index).PrecomputationKey = DNSCurveSocketSelectingList->at(LastReceiveIndex).PrecomputationKey;
					DNSCurveSocketSelectingList->at(LastReceiveIndex).PrecomputationKey = PrecomputationKeyTemp;
					const auto ReceiveMagicNumberTemp = DNSCurveSocketSelectingList->at(Index).ReceiveMagicNumber;
					DNSCurveSocketSelectingList->at(Index).ReceiveMagicNumber = DNSCurveSocketSelectingList->at(LastReceiveIndex).ReceiveMagicNumber;
					DNSCurveSocketSelectingList->at(LastReceiveIndex).ReceiveMagicNumber = ReceiveMagicNumberTemp;
					std::swap(DNSCurveSocketSelectingList->at(LastReceiveIndex).RecvBuffer, DNSCurveSocketSelectingList->at(Index).RecvBuffer);
					RecvLen = DNSCurveSocketSelectingList->at(LastReceiveIndex).RecvLen;
					DNSCurveSocketSelectingList->at(LastReceiveIndex).RecvLen = DNSCurveSocketSelectingList->at(Index).RecvLen;
					DNSCurveSocketSelectingList->at(Index).RecvLen = RecvLen;
					RecvLen = SelectingResultOnce(RequestType, Protocol, SocketDataList, nullptr, DNSCurveSocketSelectingList, OriginalRecv, RecvSize);
				}
				else {
			#endif
					std::swap(SocketSelectingList.at(LastReceiveIndex).RecvBuffer, SocketSelectingList.at(Index).RecvBuffer);
					RecvLen = SocketSelectingList.at(LastReceiveIndex).RecvLen;
					SocketSelectingList.at(LastReceiveIndex).RecvLen = SocketSelectingList.at(Index).RecvLen;
					SocketSelectingList.at(Index).RecvLen = RecvLen;
					RecvLen = SelectingResultOnce(RequestType, Protocol, SocketDataList, &SocketSelectingList, nullptr, OriginalRecv, RecvSize);
			#if defined(ENABLE_LIBSODIUM)
				}
			#endif

			//Buffer list check(Part 2)
				if (RecvLen >= static_cast<ssize_t>(DNS_PACKET_MINSIZE))
					return RecvLen;
			}
			else if (RequestType == REQUEST_PROCESS_TYPE::UDP_WITHOUT_MARKING)
			{
			//Close all sockets.
				for (auto &SocketDataIter:SocketDataList)
				{
					SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
					SocketDataIter.Socket = 0;
				}

				return EXIT_SUCCESS;
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
	for (auto &SocketDataIter:SocketDataList)
	{
		SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		SocketDataIter.Socket = 0;
	}

	return EXIT_FAILURE;
}

//Socket selecting result(Once)
ssize_t SelectingResultOnce(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_ONCE_TABLE> *SocketSelectingList, 
	void * const OriginalDNSCurveSocketSelectingList, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize)
{
//Socket data check
	if (SocketDataList.empty())
		return EXIT_FAILURE;

//Initialization
#if defined(ENABLE_LIBSODIUM)
	auto DNSCurveSocketSelectingList = reinterpret_cast<std::vector<DNSCURVE_SOCKET_SELECTING_TABLE> *>(OriginalDNSCurveSocketSelectingList);
	if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
	{
		if (DNSCurveSocketSelectingList == nullptr)
			return EXIT_FAILURE;
	}
	else {
#endif
		if (SocketSelectingList == nullptr)
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
			if (DNSCurveSocketSelectingList->at(Index).RecvBuffer && DNSCurveSocketSelectingList->at(Index).RecvLen >= DNS_PACKET_MINSIZE)
			{
			//TCP header length check
				if (Protocol == IPPROTO_TCP)
				{
					RecvLen = ntohs(reinterpret_cast<uint16_t *>(DNSCurveSocketSelectingList->at(Index).RecvBuffer.get())[0]);
					if (RecvLen < static_cast<ssize_t>(DNS_PACKET_MINSIZE) || RecvLen >= static_cast<ssize_t>(RecvSize) || RecvLen > static_cast<ssize_t>(DNSCurveSocketSelectingList->at(Index).RecvLen))
					{
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
						SocketDataList.at(Index).Socket = 0;
						DNSCurveSocketSelectingList->at(Index).RecvBuffer.reset();
						DNSCurveSocketSelectingList->at(Index).RecvLen = 0;
						continue;
					}
					else {
						memmove_s(DNSCurveSocketSelectingList->at(Index).RecvBuffer.get(), RecvSize, DNSCurveSocketSelectingList->at(Index).RecvBuffer.get() + sizeof(uint16_t), RecvLen);
						sodium_memzero(DNSCurveSocketSelectingList->at(Index).RecvBuffer.get() + RecvLen, static_cast<ssize_t>(RecvSize) - RecvLen);
					}
				}
			//UDP length
				else if (Protocol == IPPROTO_UDP)
				{
					RecvLen = DNSCurveSocketSelectingList->at(Index).RecvLen;
				}
				else {
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
					SocketDataList.at(Index).Socket = 0;
					DNSCurveSocketSelectingList->at(Index).RecvBuffer.reset();
					DNSCurveSocketSelectingList->at(Index).RecvLen = 0;
					continue;
				}

			//Decrypt or get packet data(DNSCurve).
				if (RequestType == REQUEST_PROCESS_TYPE::DNSCURVE_MAIN)
				{
					RecvLen = DNSCurvePacketDecryption(DNSCurveSocketSelectingList->at(Index).ReceiveMagicNumber, DNSCurveSocketSelectingList->at(Index).PrecomputationKey, DNSCurveSocketSelectingList->at(Index).RecvBuffer.get(), RecvSize, RecvLen);
					if (RecvLen < static_cast<ssize_t>(DNS_PACKET_MINSIZE))
					{
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
						SocketDataList.at(Index).Socket = 0;
						DNSCurveSocketSelectingList->at(Index).RecvBuffer.reset();
						DNSCurveSocketSelectingList->at(Index).RecvLen = 0;
						continue;
					}
					else {
						sodium_memzero(OriginalRecv, RecvSize);
						memcpy_s(OriginalRecv, RecvSize, DNSCurveSocketSelectingList->at(Index).RecvBuffer.get(), RecvLen);
					}
				}

			//Mark sockets to global list.
				std::unique_lock<std::mutex> SocketMarkingMutex(SocketMarkingLock);
				for (auto &SocketDataIter:SocketDataList)
				{
					if (SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
					{
						SOCKET_MARKING_DATA SocketMarkingDataTemp;
						SocketMarkingDataTemp.first = SocketDataIter.Socket;
						if (Protocol == IPPROTO_TCP)
						{
						#if defined(PLATFORM_WIN)
							SocketMarkingDataTemp.second = GetCurrentSystemTime() + DNSCurveParameter.DNSCurve_SocketTimeout_Reliable;
						#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							SocketMarkingDataTemp.second = IncreaseMillisecondTime(GetCurrentSystemTime(), DNSCurveParameter.DNSCurve_SocketTimeout_Reliable);
						#endif
						}
						else if (Protocol == IPPROTO_UDP)
						{
						#if defined(PLATFORM_WIN)
							SocketMarkingDataTemp.second = GetCurrentSystemTime() + DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable;
						#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							SocketMarkingDataTemp.second = IncreaseMillisecondTime(GetCurrentSystemTime(), DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable);
						#endif
						}
						else {
							continue;
						}

						SocketMarkingList.push_back(SocketMarkingDataTemp);
						SocketDataIter.Socket = 0;
					}
				}

				SocketMarkingMutex.unlock();

			//Mark DNS cache.
				if (Parameter.DNS_CacheType != DNS_CACHE_TYPE::NONE)
					MarkDomainCache(OriginalRecv, RecvLen);

				return RecvLen;
			}
		}
	//Normal
		else {
	#endif
			if (SocketSelectingList->at(Index).RecvBuffer && SocketSelectingList->at(Index).RecvLen >= DNS_PACKET_MINSIZE)
			{
			//TCP header length check
				if (Protocol == IPPROTO_TCP)
				{
					RecvLen = ntohs(reinterpret_cast<uint16_t *>(SocketSelectingList->at(Index).RecvBuffer.get())[0]);
					if (RecvLen < static_cast<ssize_t>(DNS_PACKET_MINSIZE) || RecvLen >= static_cast<ssize_t>(RecvSize) || RecvLen > static_cast<ssize_t>(SocketSelectingList->at(Index).RecvLen))
					{
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
						SocketDataList.at(Index).Socket = 0;
						SocketSelectingList->at(Index).RecvBuffer.reset();
						SocketSelectingList->at(Index).RecvLen = 0;
						continue;
					}
					else {
						memmove_s(SocketSelectingList->at(Index).RecvBuffer.get(), RecvSize, SocketSelectingList->at(Index).RecvBuffer.get() + sizeof(uint16_t), RecvLen);
						memset(SocketSelectingList->at(Index).RecvBuffer.get() + RecvLen, 0, RecvSize - static_cast<ssize_t>(RecvLen));
					}
				}
			//UDP length
				else if (Protocol == IPPROTO_UDP)
				{
					RecvLen = SocketSelectingList->at(Index).RecvLen;
				}
				else {
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
					SocketDataList.at(Index).Socket = 0;
					SocketSelectingList->at(Index).RecvBuffer.reset();
					SocketSelectingList->at(Index).RecvLen = 0;
					continue;
				}

			//Receive from buffer list.
				RecvLen = CheckResponseData(
					RequestType, 
					SocketSelectingList->at(Index).RecvBuffer.get(), 
					RecvLen, 
					RecvSize, 
					nullptr);
				if (RecvLen < static_cast<ssize_t>(DNS_PACKET_MINSIZE))
				{
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
					SocketDataList.at(Index).Socket = 0;
					SocketSelectingList->at(Index).RecvBuffer.reset();
					SocketSelectingList->at(Index).RecvLen = 0;
					continue;
				}
				else {
					memset(OriginalRecv, 0, RecvSize);
					memcpy_s(OriginalRecv, RecvSize, SocketSelectingList->at(Index).RecvBuffer.get(), RecvLen);
				}

			//Mark sockets to global list.
				std::unique_lock<std::mutex> SocketMarkingMutex(SocketMarkingLock);
				for (auto &SocketDataIter:SocketDataList)
				{
					if (SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
					{
						SOCKET_MARKING_DATA SocketMarkingDataTemp;
						SocketMarkingDataTemp.first = SocketDataIter.Socket;
						if (Protocol == IPPROTO_TCP)
						{
						#if defined(PLATFORM_WIN)
							SocketMarkingDataTemp.second = GetCurrentSystemTime() + Parameter.SocketTimeout_Reliable_Once;
						#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							SocketMarkingDataTemp.second = IncreaseMillisecondTime(GetCurrentSystemTime(), Parameter.SocketTimeout_Reliable_Once);
						#endif
						}
						else if (Protocol == IPPROTO_UDP)
						{
						#if defined(PLATFORM_WIN)
							SocketMarkingDataTemp.second = GetCurrentSystemTime() + Parameter.SocketTimeout_Unreliable_Once;
						#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							SocketMarkingDataTemp.second = IncreaseMillisecondTime(GetCurrentSystemTime(), Parameter.SocketTimeout_Unreliable_Once);
						#endif
						}
						else {
							continue;
						}

						SocketMarkingList.push_back(SocketMarkingDataTemp);
						SocketDataIter.Socket = 0;
					}
				}

				SocketMarkingMutex.unlock();

			//Mark DNS cache.
				if (Parameter.DNS_CacheType != DNS_CACHE_TYPE::NONE)
					MarkDomainCache(OriginalRecv, RecvLen);

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
//Socket data check
	if (SocketDataList.empty() || SocketSelectingDataList.empty() || ErrorCodeList.empty())
		return EXIT_FAILURE;

//Initialization
	fd_set ReadFDS, WriteFDS;
	timeval Timeout;
	memset(&ReadFDS, 0, sizeof(ReadFDS));
	memset(&WriteFDS, 0, sizeof(WriteFDS));
	memset(&Timeout, 0, sizeof(Timeout));
	ssize_t SelectResult = 0, RecvLen = 0;
	SYSTEM_SOCKET MaxSocket = 0;
	size_t Index = 0;

//Socket check(Send process)
	for (auto SocketDataIter = SocketDataList.begin();SocketDataIter != SocketDataList.end();++SocketDataIter)
	{
		if (SocketSetting(SocketDataIter->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			break;
		else if (SocketDataIter + 1U == SocketDataList.end())
			return EXIT_FAILURE;
	}

//Socket attribute setting
	if (Protocol == IPPROTO_TCP)
	{
	#if defined(PLATFORM_WIN)
		Timeout.tv_sec = Parameter.SocketTimeout_Reliable_Serial / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.SocketTimeout_Reliable_Serial % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		Timeout = Parameter.SocketTimeout_Reliable_Serial;
	#endif
	}
	else if (Protocol == IPPROTO_UDP)
	{
	#if defined(PLATFORM_WIN)
		Timeout.tv_sec = Parameter.SocketTimeout_Unreliable_Serial / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.SocketTimeout_Unreliable_Serial % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
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
		MaxSocket = 0;

	//Socket check and non-blocking process
		for (Index = 0;Index < SocketDataList.size();++Index)
		{
			if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr) && 
				SocketSelectingDataList.at(Index).SendBuffer && SocketSelectingDataList.at(Index).SendLen > 0 && 
				!SocketSelectingDataList.at(Index).IsPacketDone && ErrorCodeList.at(Index) == 0)
			{
			//Select structure initialization
				FD_SET(SocketDataList.at(Index).Socket, &WriteFDS);
				if (SocketDataList.at(Index).Socket > MaxSocket)
					MaxSocket = SocketDataList.at(Index).Socket;
			}
			else if (MaxSocket == 0 && Index + 1U == SocketDataList.size())
			{
				goto StopLoop;
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, nullptr, &WriteFDS, nullptr, &Timeout);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		SelectResult = select(MaxSocket + 1U, nullptr, &WriteFDS, nullptr, &Timeout);
	#endif
		if (SelectResult > 0)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
				if (FD_ISSET(SocketDataList.at(Index).Socket, &WriteFDS) && !SocketSelectingDataList.at(Index).IsPacketDone)
				{
					if (send(SocketDataList.at(Index).Socket, reinterpret_cast<const char *>(SocketSelectingDataList.at(Index).SendBuffer.get()), static_cast<int>(SocketSelectingDataList.at(Index).SendLen), 0) == SOCKET_ERROR)
					{
						ErrorCodeList.at(Index) = WSAGetLastError();
				
					//Send in progress.
					#if defined(PLATFORM_WIN)
						if (ErrorCodeList.at(Index) == WSAEWOULDBLOCK)
					#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
						if (ErrorCodeList.at(Index) == EAGAIN || ErrorCodeList.at(Index) == EINPROGRESS)
					#endif
						{
							ErrorCodeList.at(Index) = 0;
						}
					//SOCKET_ERROR
						else {
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
							SocketDataList.at(Index).Socket = 0;
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
					SocketDataList.at(Index).Socket = 0;
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
				SocketDataList.at(Index).Socket = 0;
			}

			return EXIT_FAILURE;
		}
	}

//Jump here to stop loop.
StopLoop:

//Socket check(Receive process)
	for (auto SocketDataIter = SocketDataList.begin();SocketDataIter != SocketDataList.end();++SocketDataIter)
	{
		if (SocketSetting(SocketDataIter->Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			break;
		else if (SocketDataIter + 1U == SocketDataList.end())
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
		MaxSocket = 0;

	//Socket check and non-blocking process
		for (Index = 0;Index < SocketDataList.size();++Index)
		{
			if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr) && 
				!SocketSelectingDataList.at(Index).IsPacketDone && !SocketSelectingDataList.at(Index).IsSendOnly && 
				ErrorCodeList.at(Index) == 0)
			{
			//Select structure initialization
				FD_SET(SocketDataList.at(Index).Socket, &ReadFDS);
				if (SocketDataList.at(Index).Socket > MaxSocket)
					MaxSocket = SocketDataList.at(Index).Socket;
			}
			else if (MaxSocket == 0 && Index + 1U == SocketDataList.size())
			{
				return EXIT_SUCCESS;
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, &ReadFDS, nullptr, nullptr, &Timeout);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		SelectResult = select(MaxSocket + 1U, &ReadFDS, nullptr, nullptr, &Timeout);
	#endif
		if (SelectResult > 0)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
				if (FD_ISSET(SocketDataList.at(Index).Socket, &ReadFDS) && 
					!SocketSelectingDataList.at(Index).IsPacketDone && !SocketSelectingDataList.at(Index).IsSendOnly)
				{
				//Receive all packets from socket.
					for (;;)
					{
					//Prepare buffer.
						if (!SocketSelectingDataList.at(Index).RecvBuffer)
						{
							std::unique_ptr<uint8_t[]> RecvBuffer(new uint8_t[Parameter.LargeBufferSize]);
							memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize);
							std::swap(SocketSelectingDataList.at(Index).RecvBuffer, RecvBuffer);
							SocketSelectingDataList.at(Index).RecvSize = Parameter.LargeBufferSize;
							SocketSelectingDataList.at(Index).RecvLen = 0;
						}
						else if (SocketSelectingDataList.at(Index).RecvSize < SocketSelectingDataList.at(Index).RecvLen + Parameter.LargeBufferSize)
						{
							std::unique_ptr<uint8_t[]> RecvBuffer(new uint8_t[SocketSelectingDataList.at(Index).RecvSize + Parameter.LargeBufferSize]);
							memset(RecvBuffer.get(), 0, SocketSelectingDataList.at(Index).RecvSize + Parameter.LargeBufferSize);
							memcpy_s(RecvBuffer.get(), SocketSelectingDataList.at(Index).RecvSize + Parameter.LargeBufferSize, SocketSelectingDataList.at(Index).RecvBuffer.get(), SocketSelectingDataList.at(Index).RecvLen);
							std::swap(SocketSelectingDataList.at(Index).RecvBuffer, RecvBuffer);
							SocketSelectingDataList.at(Index).RecvSize += Parameter.LargeBufferSize;
						}

					//Receive process
						RecvLen = recv(SocketDataList.at(Index).Socket, reinterpret_cast<char *>(SocketSelectingDataList.at(Index).RecvBuffer.get() + SocketSelectingDataList.at(Index).RecvLen), static_cast<int>(SocketSelectingDataList.at(Index).RecvSize - SocketSelectingDataList.at(Index).RecvLen), 0);
						if (RecvLen == SOCKET_ERROR)
						{
							ErrorCodeList.at(Index) = WSAGetLastError();

						//Receive in progress.
						#if defined(PLATFORM_WIN)
							if (ErrorCodeList.at(Index) == WSAEWOULDBLOCK)
						#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
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
								SocketDataList.at(Index).Socket = 0;
							}

							break;
						}
						else if (RecvLen == 0) //Connection closed
						{
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
							SocketDataList.at(Index).Socket = 0;

							break;
						}
						else {
							SocketSelectingDataList.at(Index).RecvLen += static_cast<size_t>(RecvLen);
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
				SocketDataList.at(Index).Socket = 0;
			}

			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

#if defined(ENABLE_PCAP)
//Mark socket information to global list
void MarkPortToList(
	const uint16_t Protocol, 
	const SOCKET_DATA * const LocalSocketData, 
	std::vector<SOCKET_DATA> &SocketDataList)
{
//Socket data check
	if (SocketDataList.empty())
		return;

//Mark port.
	if (LocalSocketData != nullptr && Protocol > 0)
	{
		SOCKET_DATA SocketDataTemp;
		OUTPUT_PACKET_TABLE OutputPacketListTemp;
		memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));

	//Mark system connection data.
		OutputPacketListTemp.SocketData_Input = *LocalSocketData;

	//Mark sending connection data.
		for (auto &SocketDataIter:SocketDataList)
		{
			if (!SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
				continue;
			else 
				memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));

		//Get socket information(Socket).
			if (getsockname(SocketDataIter.Socket, reinterpret_cast<sockaddr *>(&SocketDataIter.SockAddr), &SocketDataIter.AddrLen) != 0)
			{
				SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				SocketDataIter.Socket = 0;

				continue;
			}

		//Get socket information(Attributes).
			SocketDataTemp.AddrLen = SocketDataIter.AddrLen;
			if (SocketDataIter.AddrLen == sizeof(sockaddr_in6))
			{
				SocketDataTemp.SockAddr.ss_family = AF_INET6;
				(reinterpret_cast<sockaddr_in6 *>(&SocketDataTemp.SockAddr))->sin6_port = (reinterpret_cast<sockaddr_in6 *>(&SocketDataIter.SockAddr))->sin6_port;
			}
			else if (SocketDataIter.AddrLen == sizeof(sockaddr_in))
			{
				SocketDataTemp.SockAddr.ss_family = AF_INET;
				(reinterpret_cast<sockaddr_in *>(&SocketDataTemp.SockAddr))->sin_port = (reinterpret_cast<sockaddr_in *>(&SocketDataIter.SockAddr))->sin_port;
			}
			else {
				SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
				SocketDataIter.Socket = 0;

				continue;
			}

			OutputPacketListTemp.SocketData_Output.push_back(SocketDataTemp);
		}

	//Mark send time.
		OutputPacketListTemp.Protocol_Network = Protocol;
		if (Protocol == IPPROTO_TCP)
		{
		#if defined(PLATFORM_WIN)
			OutputPacketListTemp.ClearPortTime = GetCurrentSystemTime() + Parameter.SocketTimeout_Reliable_Once;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			OutputPacketListTemp.ClearPortTime = IncreaseMillisecondTime(GetCurrentSystemTime(), Parameter.SocketTimeout_Reliable_Once);
		#endif
		}
		else if (Protocol == IPPROTO_UDP)
		{
		#if defined(PLATFORM_WIN)
			OutputPacketListTemp.ClearPortTime = GetCurrentSystemTime() + Parameter.SocketTimeout_Unreliable_Once;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
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
		//Mark timeout.
			if (OutputPacketList.front().ClearPortTime > 0)
			{
				if (OutputPacketList.front().Protocol_Network == AF_INET6)
				{
					if (OutputPacketList.front().Protocol_Transport == IPPROTO_TCP)
						++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV6];
					else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP)
						++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV6];
				}
				else if (OutputPacketList.front().Protocol_Network == AF_INET)
				{
					if (OutputPacketList.front().Protocol_Transport == IPPROTO_TCP)
						++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_TCP_IPV4];
					else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP)
						++AlternateSwapList.TimeoutTimes[ALTERNATE_SWAP_TYPE_MAIN_UDP_IPV4];
				}
			}

			OutputPacketList.pop_front();
		}

		OutputPacketList.push_back(OutputPacketListTemp);
	}

//Block Port Unreachable messages of system or close the TCP request connections.
	for (auto &SocketDataIter:SocketDataList)
	{
		if (SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
			shutdown(SocketDataIter.Socket, SD_SEND);
	}
#if defined(PLATFORM_WIN)
	if (Protocol == IPPROTO_TCP)
		Sleep(Parameter.SocketTimeout_Reliable_Once);
	else if (Protocol == IPPROTO_UDP)
		Sleep(Parameter.SocketTimeout_Unreliable_Once);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (Protocol == IPPROTO_TCP)
		usleep(Parameter.SocketTimeout_Reliable_Once.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable_Once.tv_usec);
	else if (Protocol == IPPROTO_UDP)
		usleep(Parameter.SocketTimeout_Unreliable_Once.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Unreliable_Once.tv_usec);
#endif
	for (auto &SocketDataIter:SocketDataList)
	{
		SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		SocketDataIter.Socket = 0;
	}

	return;
}
#endif
