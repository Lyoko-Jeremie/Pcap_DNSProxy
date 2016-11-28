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
		((PSOCKADDR_IN6)&SockAddr)->sin6_addr = in6addr_any;
		((PSOCKADDR_IN6)&SockAddr)->sin6_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
		SockAddr.ss_family = AF_INET6;
		FirewallSocket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	//Bind local socket.
		if (!SocketSetting(FirewallSocket, SOCKET_SETTING_INVALID_CHECK, true, nullptr))
		{
			ErrorCode = WSAGetLastError();
			return false;
		}
		else if (bind(FirewallSocket, (PSOCKADDR)&SockAddr, sizeof(sockaddr_in6)) == SOCKET_ERROR)
		{
			((PSOCKADDR_IN6)&SockAddr)->sin6_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
			while (bind(FirewallSocket, (PSOCKADDR)&SockAddr, sizeof(sockaddr_in6)) == SOCKET_ERROR)
			{
				if (Index < LOOP_MAX_TIMES && WSAGetLastError() == WSAEADDRINUSE)
				{
					((PSOCKADDR_IN6)&SockAddr)->sin6_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
					++Index;
				}
				else {
					ErrorCode = WSAGetLastError();
					SocketSetting(FirewallSocket, SOCKET_SETTING_CLOSE, false, nullptr);

					return false;
				}
			}
		}
	}
//IPv4
	else if (Protocol == AF_INET)
	{
		((PSOCKADDR_IN)&SockAddr)->sin_addr.s_addr = INADDR_ANY;
		((PSOCKADDR_IN)&SockAddr)->sin_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
		SockAddr.ss_family = AF_INET;
		FirewallSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	//Bind local socket.
		if (!SocketSetting(FirewallSocket, SOCKET_SETTING_INVALID_CHECK, true, nullptr))
		{
			ErrorCode = WSAGetLastError();
			return false;
		}
		else if (bind(FirewallSocket, (PSOCKADDR)&SockAddr, sizeof(sockaddr_in)) == SOCKET_ERROR)
		{
			((PSOCKADDR_IN)&SockAddr)->sin_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
			while (bind(FirewallSocket, (PSOCKADDR)&SockAddr, sizeof(sockaddr_in)) == SOCKET_ERROR)
			{
				if (Index < LOOP_MAX_TIMES && WSAGetLastError() == WSAEADDRINUSE)
				{
					((PSOCKADDR_IN)&SockAddr)->sin_port = htons(RamdomDistribution(*GlobalRunningStatus.RamdomEngine));
					++Index;
				}
				else {
					ErrorCode = WSAGetLastError();
					SocketSetting(FirewallSocket, SOCKET_SETTING_CLOSE, false, nullptr);

					return false;
				}
			}
		}
	}
	else {
		return false;
	}

//Close socket.
	SocketSetting(FirewallSocket, SOCKET_SETTING_CLOSE, false, nullptr);
	return true;
}
#endif

//Socket option settings
bool SocketSetting(
	const SYSTEM_SOCKET Socket, 
	const size_t SettingType, 
	const bool IsPrintError, 
	void * const DataPointer)
{
	switch (SettingType)
	{
	//Socket invalid check
		case SOCKET_SETTING_INVALID_CHECK:
		{
		#if defined(PLATFORM_WIN)
			if (Socket == 0 || Socket == INVALID_SOCKET || Socket == SOCKET_ERROR)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (Socket == 0 || Socket == INVALID_SOCKET)
		#endif
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket initialization error", WSAGetLastError(), nullptr, 0);

				return false;
			}
		}break;
	//Socket closing process
		case SOCKET_SETTING_CLOSE:
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
	//Socket attribute setting(Timeout)
		case SOCKET_SETTING_TIMEOUT:
		{
		//Pointer check
			if (DataPointer == nullptr)
				return false;

		//Socket timeout options
		#if defined(PLATFORM_WIN)
			const DWORD OptionValue = *(DWORD *)DataPointer;
			if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&OptionValue, sizeof(OptionValue)) == SOCKET_ERROR || 
				setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)DataPointer, sizeof(timeval)) == SOCKET_ERROR || 
				setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)DataPointer, sizeof(timeval)) == SOCKET_ERROR)
		#endif
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket timeout setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		}break;
	//Socket attribute setting(Reusing)
		case SOCKET_SETTING_REUSE:
		{
		#if defined(PLATFORM_WIN)
		//Preventing other sockets from being forcibly bound to the same address and port(Windows).
			const DWORD OptionValue = TRUE;
			if (setsockopt(Socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket reusing disable setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			const int OptionValue = TRUE;

		//Set TIME_WAIT resuing(Linux/macOS).
/*			errno = 0;
			if (setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket reusing enable setting error", errno, nullptr, 0);
				shutdown(Socket, SHUT_RDWR);
				close(Socket);

				return false;
			}
*/
		//Set an IPv6 server socket that must not accept IPv4 connections in Linux.
			errno = 0;
			if (setsockopt(Socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket treating wildcard bind setting error", errno, nullptr, 0);
				shutdown(Socket, SHUT_RDWR);
				close(Socket);

				return false;
			}
		#endif
		}break;
	//Socket attribute setting(TFO/TCP Fast Open)
	//It seems that TCP Fast Open option is not ready in Windows and macOS(2016-11-28).
		case SOCKET_SETTING_TCP_FAST_OPEN:
		{
		//Global parameter check
			if (!Parameter.TCP_FastOpen)
				return true;

		//Socket attribute setting process
		#if defined(PLATFORM_WIN)
			const DWORD OptionValue = TRUE;
			if (setsockopt(Socket, IPPROTO_TCP, TCP_FASTOPEN, (const char *)&OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket TCP Fast Open setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		#elif defined(PLATFORM_LINUX)
			const int OptionValue = TCP_FASTOPEN_HINT;
			errno = 0;
			if (setsockopt(Socket, SOL_TCP, TCP_FASTOPEN, (const char *)&OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket TCP Fast Open setting error", errno, nullptr, 0);
				shutdown(Socket, SHUT_RDWR);
				close(Socket);

				return false;
			}
		#endif
		}break;
	//Socket attribute setting(Non-blocking mode)
		case SOCKET_SETTING_NON_BLOCKING_MODE:
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
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket non-blocking mode setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		}break;
/* TCP keep alive mode
	//Socket attribute setting(TCP keep alive mode)
		case SOCKET_SETTING_TCP_KEEPALIVE:
		{
		#if defined(PLATFORM_WIN)
			const DWORD OptionValue = TRUE;
			if (setsockopt(Socket, SOL_SOCKET, SO_KEEPALIVE, (const char *)&OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
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
			if (setsockopt(Socket, SOL_SOCKET, SO_KEEPALIVE, (const char *)&OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			{
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		#endif
		}break;
*/
	//Socket attribute setting(UDP RESET message blocking)
	#if defined(PLATFORM_WIN)
		case SOCKET_SETTING_UDP_BLOCK_RESET:
		{
			BOOL NewBehavior = FALSE;
			DWORD BytesReturned = 0;
			if (WSAIoctl(Socket, SIO_UDP_CONNRESET, &NewBehavior, sizeof(BOOL), nullptr, 0, &BytesReturned, nullptr, nullptr) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket UDP block RESET message setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		}break;
	#endif
	//Socket attribute setting(IPv4 header TTL)
		case SOCKET_SETTING_HOP_LIMITS_IPV4:
		{
		//Range
			if (Parameter.PacketHopLimits_IPv4_End > 0)
			{
			//Socket attribute setting process
			#if defined(PLATFORM_WIN)
				std::uniform_int_distribution<DWORD> RamdomDistribution(Parameter.PacketHopLimits_IPv4_Begin, Parameter.PacketHopLimits_IPv4_End);
				const DWORD OptionValue = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, (const char *)&OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				std::uniform_int_distribution<int> RamdomDistribution(Parameter.PacketHopLimits_IPv4_Begin, Parameter.PacketHopLimits_IPv4_End);
				const int OptionValue = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, &OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket Hop Limits setting error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);

					return false;
				}
			}
		//Value
			else if (Parameter.PacketHopLimits_IPv4_Begin > 0)
			{
			#if defined(PLATFORM_WIN)
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, (const char *)&Parameter.PacketHopLimits_IPv4_Begin, sizeof(Parameter.PacketHopLimits_IPv4_Begin)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, &Parameter.PacketHopLimits_IPv4_Begin, sizeof(Parameter.PacketHopLimits_IPv4_Begin)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket Hop Limits setting error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);

					return false;
				}
			}
		}break;
	//Socket attribute setting(IPv6 header Hop Limts)
		case SOCKET_SETTING_HOP_LIMITS_IPV6:
		{
		//Range
			if (Parameter.PacketHopLimits_IPv6_End > 0)
			{
			//Socket attribute setting process
			#if defined(PLATFORM_WIN)
				std::uniform_int_distribution<DWORD> RamdomDistribution(Parameter.PacketHopLimits_IPv6_Begin, Parameter.PacketHopLimits_IPv6_End);
				const DWORD OptionValue = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (const char *)&OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				std::uniform_int_distribution<int> RamdomDistribution(Parameter.PacketHopLimits_IPv6_Begin, Parameter.PacketHopLimits_IPv6_End);
				const int OptionValue = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket Hop Limits setting error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);

					return false;
				}
			}
		//Value
			else if (Parameter.PacketHopLimits_IPv6_Begin > 0)
			{
			#if defined(PLATFORM_WIN)
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (const char *)&Parameter.PacketHopLimits_IPv6_Begin, sizeof(Parameter.PacketHopLimits_IPv6_Begin)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &Parameter.PacketHopLimits_IPv6_Begin, sizeof(Parameter.PacketHopLimits_IPv6_Begin)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket Hop Limits setting error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);

					return false;
				}
			}
		}break;
	//Socket attribute setting(IPv4 header Do Not Fragment flag)
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		case SOCKET_SETTING_DO_NOT_FRAGMENT:
		{
			if (Parameter.DoNotFragment)
			{
			#if defined(PLATFORM_WIN)
				const DWORD OptionValue = TRUE;
				if (setsockopt(Socket, IPPROTO_IP, IP_DONTFRAGMENT, (const char *)&OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				const int OptionValue = IP_PMTUDISC_DO;
				if (setsockopt(Socket, IPPROTO_IP, IP_MTU_DISCOVER, &OptionValue, sizeof(OptionValue)) == SOCKET_ERROR)
			#endif
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket Do Not Fragment flag setting error", WSAGetLastError(), nullptr, 0);
					shutdown(Socket, SD_BOTH);
					closesocket(Socket);

					return EXIT_FAILURE;
				}
			}
		}break;
	#endif
	}

	return true;
}

//Select socket data of DNS target
size_t SelectTargetSocketSingle(
	const size_t RequestType, 
	const uint16_t Protocol, 
	SOCKET_DATA * const TargetSocketData, 
	void ** const DNSCurvePacketTarget, 
	bool ** const IsAlternate, 
	size_t ** const AlternateTimeoutTimes, 
	const ADDRESS_UNION_DATA * const SpecifieTargetData)
{
//Socket type and request type check
	uint16_t SocketType = 0;
	if (Protocol == IPPROTO_TCP)
		SocketType = SOCK_STREAM;
	else if (Protocol == IPPROTO_UDP)
		SocketType = SOCK_DGRAM;
	else 
		return EXIT_FAILURE;
#if defined(ENABLE_LIBSODIUM)
	auto PacketTarget = (DNSCURVE_SERVER_DATA **)DNSCurvePacketTarget;
	size_t ServerType = 0;

//Select DNSCurve target socket
	if (RequestType == REQUEST_PROCESS_DNSCURVE_MAIN)
	{
		if (PacketTarget == nullptr)
			return EXIT_FAILURE;

	//IPv6
		if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family != 0 && 
			((DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
			DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 || //IPv6
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0))) //Non-IPv4
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_DNSCURVE_TCP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_TCP_IPV6];
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_DNSCURVE_UDP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_UDP_IPV6];
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

			if (**IsAlternate && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
			{
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_port;
				*PacketTarget = &DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv6;
				ServerType = DNSCURVE_ALTERNATE_IPV6;
			}
			else { //Main
			//Encryption mode check
				if (DNSCurveParameter.IsEncryption && 
					((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
						return EXIT_FAILURE;

				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.IPv6.sin6_port;
				*PacketTarget = &DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6;
				ServerType = DNSCURVE_MAIN_IPV6;
			}

			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return EXIT_FAILURE;
			}
			else {
				return ServerType;
			}
		}
	//IPv4
		else if (DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
			((DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
			DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV4 || //IPv4
			(DNSCurveParameter.DNSCurveProtocol_Network == REQUEST_MODE_IPV6 && DNSCurveParameter.DNSCurve_Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0))) //Non-IPv6
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_DNSCURVE_TCP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_TCP_IPV4];
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_DNSCURVE_UDP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_DNSCURVE_UDP_IPV4];
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

			if (**IsAlternate && DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0)
			{
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4.AddressData.IPv4.sin_port;
				*PacketTarget = &DNSCurveParameter.DNSCurve_Target_Server_Alternate_IPv4;
				ServerType = DNSCURVE_ALTERNATE_IPV4;
			}
			else { //Main
			//Encryption mode check
				if (DNSCurveParameter.IsEncryption && 
					((!DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.PrecomputationKey, crypto_box_BEFORENMBYTES)) || 
					(DNSCurveParameter.IsClientEphemeralKey && CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.ServerFingerprint, crypto_box_PUBLICKEYBYTES)) || 
					CheckEmptyBuffer(DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.SendMagicNumber, DNSCURVE_MAGIC_QUERY_LEN)))
						return EXIT_FAILURE;

				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4.AddressData.IPv4.sin_port;
				*PacketTarget = &DNSCurveParameter.DNSCurve_Target_Server_Main_IPv4;
				ServerType = DNSCURVE_MAIN_IPV4;
			}

			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return EXIT_FAILURE;
			}
			else {
				return ServerType;
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
			((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = SpecifieTargetData->IPv6.sin6_addr;
			((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = SpecifieTargetData->IPv6.sin6_port;
			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return EXIT_FAILURE;
			}
		}
		else if (SpecifieTargetData->Storage.ss_family == AF_INET)
		{
			((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = SpecifieTargetData->IPv4.sin_addr;
			((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = SpecifieTargetData->IPv4.sin_port;
			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return EXIT_FAILURE;
			}
		}
		else {
			return EXIT_FAILURE;
		}
	}
//Local request
	else if (RequestType == REQUEST_PROCESS_LOCAL)
	{
	//IPv6
		if (Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family != 0 && 
			((Parameter.LocalProtocol_Network == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
			Parameter.LocalProtocol_Network == REQUEST_MODE_IPV6 || //IPv6
			(Parameter.LocalProtocol_Network == REQUEST_MODE_IPV4 && Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family == 0))) //Non-IPv4
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_LOCAL_TCP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_LOCAL_TCP_IPV6];
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_LOCAL_UDP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_LOCAL_UDP_IPV6];
			}
			else {
				return EXIT_FAILURE;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Local_Alternate_IPv6.Storage.ss_family != 0)
			{
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = Parameter.Target_Server_Local_Alternate_IPv6.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = Parameter.Target_Server_Local_Alternate_IPv6.IPv6.sin6_port;
			}
		//Main
			else {
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = Parameter.Target_Server_Local_Main_IPv6.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = Parameter.Target_Server_Local_Main_IPv6.IPv6.sin6_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return EXIT_FAILURE;
			}
		}
	//IPv4
		else if (Parameter.Target_Server_Local_Main_IPv4.Storage.ss_family != 0 && 
			((Parameter.LocalProtocol_Network == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
			Parameter.LocalProtocol_Network == REQUEST_MODE_IPV4 || //IPv4
			(Parameter.LocalProtocol_Network == REQUEST_MODE_IPV6 && Parameter.Target_Server_Local_Main_IPv6.Storage.ss_family == 0))) //Non-IPv6
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_LOCAL_TCP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_LOCAL_TCP_IPV4];
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_LOCAL_UDP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_LOCAL_UDP_IPV4];
			}
			else {
				return EXIT_FAILURE;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Local_Alternate_IPv4.Storage.ss_family != 0)
			{
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = Parameter.Target_Server_Local_Alternate_IPv4.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = Parameter.Target_Server_Local_Alternate_IPv4.IPv4.sin_port;
			}
		//Main
			else {
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = Parameter.Target_Server_Local_Main_IPv4.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = Parameter.Target_Server_Local_Main_IPv4.IPv4.sin_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
			((Parameter.RequestMode_Network == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
			Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
			(Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0))) //Non-IPv4
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_TCP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV6];
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_UDP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_UDP_IPV6];
			}
			else {
				return false;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family != 0)
			{
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
		//Main
			else {
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = Parameter.Target_Server_Main_IPv6.AddressData.IPv6.sin6_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return EXIT_FAILURE;
			}
		}
	//IPv4
		else if (Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family != 0 && 
			((Parameter.RequestMode_Network == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
			Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
			(Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0))) //Non-IPv6
		{
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_TCP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV4];
			}
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_UDP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_UDP_IPV4];
			}
			else {
				return EXIT_FAILURE;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family != 0)
			{
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_port;
			}
		//Main
			else {
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = Parameter.Target_Server_Main_IPv4.AddressData.IPv4.sin_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
		((Parameter.RequestMode_Network == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
		(Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.Target_Server_Main_IPv4.AddressData.Storage.ss_family == 0))) //Non-IPv4
	{
	//Set Alternate swap list.
		if (Protocol == IPPROTO_TCP)
			IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_TCP_IPV6];
		else if (Protocol == IPPROTO_UDP)
			IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_UDP_IPV6];
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
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
					(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr))
				{
					for (auto &SocketDataIter:TargetSocketDataList)
					{
						SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
					(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr))
				{
					for (auto &SocketDataIter:TargetSocketDataList)
					{
						SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
					if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
						(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr))
					{
						for (auto &SocketDataIter:TargetSocketDataList)
						{
							SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
		((Parameter.RequestMode_Network == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
		(Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.Target_Server_Main_IPv6.AddressData.Storage.ss_family == 0))) //Non-IPv6
	{
	//Set Alternate swap list.
		if (Protocol == IPPROTO_TCP)
			IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_TCP_IPV4];
		else if (Protocol == IPPROTO_UDP)
			IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_UDP_IPV4];
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
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
					(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
				{
					for (auto &SocketDataIter:TargetSocketDataList)
					{
						SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
					(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
					!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
				{
					for (auto &SocketDataIter:TargetSocketDataList)
					{
						SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
					if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
						(Protocol == IPPROTO_TCP && !SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr)) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
						!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
					{
						for (auto &SocketDataIter:TargetSocketDataList)
						{
							SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
		ssize_t ErrorCode = 0;

	#if defined(PLATFORM_LINUX)
		if (Parameter.TCP_FastOpen && OriginalSend != nullptr && SendSize >= DNS_PACKET_MINSIZE)
		{
			errno = 0;
			ssize_t RecvLen = sendto(Socket, OriginalSend, (int)SendSize, MSG_FASTOPEN, SockAddr, AddrLen);
			if (RecvLen == SOCKET_ERROR && errno != EAGAIN && errno != EINPROGRESS)
				return EXIT_FAILURE;
			else if (RecvLen < (ssize_t)DNS_PACKET_MINSIZE)
				return EXIT_SUCCESS;
			else 
				return RecvLen;
		}
		else {
	#endif
			if (connect(Socket, SockAddr, AddrLen) == SOCKET_ERROR)
			{
				ErrorCode = WSAGetLastError();

			#if defined(PLATFORM_WIN)
				if (ErrorCode != WSAEWOULDBLOCK)
			#elif defined(PLATFORM_LINUX)
				if (ErrorCode != EAGAIN && ErrorCode != EINPROGRESS)
			#elif defined(PLATFORM_MACOS)
				if (ErrorCode != EWOULDBLOCK && ErrorCode != EAGAIN && ErrorCode != EINPROGRESS)
			#endif
					return EXIT_FAILURE;
			}
	#if defined(PLATFORM_LINUX)
		}
	#endif
	}
//UDP connecting
	else if (Protocol == IPPROTO_UDP)
	{
		if (connect(Socket, SockAddr, AddrLen) == SOCKET_ERROR)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"Socket connecting error", WSAGetLastError(), nullptr, 0);
			SocketSetting(Socket, SOCKET_SETTING_CLOSE, false, nullptr);

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
	const size_t RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	void * const OriginalDNSCurveSocketSelectingList, 
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	ssize_t * const ErrorCode)
{
//Initialization(Part 1)
	std::vector<SOCKET_SELECTING_ONCE_DATA> SocketSelectingList;
	size_t Index = 0;
	ssize_t RecvLen = 0;
	if (ErrorCode != nullptr)
		*ErrorCode = 0;
#if defined(ENABLE_LIBSODIUM)
	auto DNSCurveSocketSelectingList = (std::vector<DNSCURVE_SOCKET_SELECTING_DATA> *)OriginalDNSCurveSocketSelectingList;
	if (RequestType == REQUEST_PROCESS_DNSCURVE_MAIN)
	{
		if (DNSCurveSocketSelectingList == nullptr)
			return EXIT_FAILURE;
	}
	else {
#endif
		SOCKET_SELECTING_ONCE_DATA InnerSocketData;
		memset(&InnerSocketData, 0, sizeof(InnerSocketData));
		for (Index = 0;Index < SocketDataList.size();++Index)
			SocketSelectingList.push_back(InnerSocketData);
#if defined(ENABLE_LIBSODIUM)
	}
#endif

//TCP or UDP connecting
	for (Index = 0;Index < SocketDataList.size();++Index)
	{
	//Set send buffer(DNSCurve).
	#if defined(ENABLE_LIBSODIUM)
		if (RequestType == REQUEST_PROCESS_DNSCURVE_MAIN)
			RecvLen = SocketConnecting(Protocol, SocketDataList.at(Index).Socket, (PSOCKADDR)&SocketDataList.at(Index).SockAddr, SocketDataList.at(Index).AddrLen, DNSCurveSocketSelectingList->at(Index).SendBuffer, DNSCurveSocketSelectingList->at(Index).SendSize);
		else 
	#endif
			RecvLen = SocketConnecting(Protocol, SocketDataList.at(Index).Socket, (PSOCKADDR)&SocketDataList.at(Index).SockAddr, SocketDataList.at(Index).AddrLen, OriginalSend, SendSize);
		if (RecvLen == EXIT_FAILURE)
		{
			SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			SocketDataList.at(Index).Socket = 0;
		}
		else if (Protocol == IPPROTO_TCP && Parameter.TCP_FastOpen && RecvLen >= (ssize_t)DNS_PACKET_MINSIZE)
		{
		#if defined(ENABLE_LIBSODIUM)
			if (RequestType == REQUEST_PROCESS_DNSCURVE_MAIN)
				DNSCurveSocketSelectingList->at(Index).IsPacketDone = true;
			else 
		#endif
				SocketSelectingList.at(Index).IsPacketDone = true;

			++Index;
		}
	}

//Socket check(Part 1)
	for (auto SocketDataIter = SocketDataList.begin();SocketDataIter != SocketDataList.end();++SocketDataIter)
	{
		if (SocketSetting(SocketDataIter->Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
			break;
		else if (SocketDataIter + 1U == SocketDataList.end())
			return EXIT_FAILURE;
	}

//Initialization(Part 2)
	std::shared_ptr<uint8_t> RecvBufferTemp;
	fd_set ReadFDS, WriteFDS;
	timeval Timeout;
	memset(&ReadFDS, 0, sizeof(ReadFDS));
	memset(&WriteFDS, 0, sizeof(WriteFDS));
	memset(&Timeout, 0, sizeof(Timeout));
	ssize_t SelectResult = 0;
	size_t LastReceiveIndex = 0;
	SYSTEM_SOCKET MaxSocket = 0;
	auto IsAllSocketShutdown = false;
	if (OriginalRecv == nullptr && RequestType != REQUEST_PROCESS_DNSCURVE_MAIN)
	{
		std::shared_ptr<uint8_t> RecvBufferSwap(new uint8_t[PACKET_MAXSIZE]());
		memset(RecvBufferSwap.get(), 0, PACKET_MAXSIZE);
		RecvBufferTemp.swap(RecvBufferSwap);
	}

//Socket attribute setting(Timeout)
#if defined(ENABLE_LIBSODIUM)
	if (RequestType == REQUEST_PROCESS_DNSCURVE_MAIN)
	{
		if (Protocol == IPPROTO_TCP)
		{
		#if defined(PLATFORM_WIN)
			Timeout.tv_sec = DNSCurveParameter.DNSCurve_SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
			Timeout.tv_usec = DNSCurveParameter.DNSCurve_SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			Timeout.tv_sec = DNSCurveParameter.DNSCurve_SocketTimeout_Reliable.tv_sec;
			Timeout.tv_usec = DNSCurveParameter.DNSCurve_SocketTimeout_Reliable.tv_usec;
		#endif
		}
		else { //UDP
		#if defined(PLATFORM_WIN)
			Timeout.tv_sec = DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable / SECOND_TO_MILLISECOND;
			Timeout.tv_usec = DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			Timeout.tv_sec = DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable.tv_sec;
			Timeout.tv_usec = DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable.tv_usec;
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
			Timeout.tv_sec = Parameter.SocketTimeout_Reliable_Once.tv_sec;
			Timeout.tv_usec = Parameter.SocketTimeout_Reliable_Once.tv_usec;
		#endif
		}
		else { //UDP
		#if defined(PLATFORM_WIN)
			Timeout.tv_sec = Parameter.SocketTimeout_Unreliable_Once / SECOND_TO_MILLISECOND;
			Timeout.tv_usec = Parameter.SocketTimeout_Unreliable_Once % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			Timeout.tv_sec = Parameter.SocketTimeout_Unreliable_Once.tv_sec;
			Timeout.tv_usec = Parameter.SocketTimeout_Unreliable_Once.tv_usec;
		#endif
		}
#if defined(ENABLE_LIBSODIUM)
	}
#endif

//Selecting process
	for (;;)
	{
	//Socket check(Part 2)
		for (auto SocketDataIter = SocketDataList.begin();SocketDataIter != SocketDataList.end();++SocketDataIter)
		{
			if (SocketSetting(SocketDataIter->Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
			{
				break;
			}
			else if (SocketDataIter + 1U == SocketDataList.end())
			{
				if (RequestType == REQUEST_PROCESS_UDP_NO_MARKING)
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
			if (RequestType == REQUEST_PROCESS_DNSCURVE_MAIN)
				RecvLen = SelectingResultOnce(RequestType, Protocol, SocketDataList, nullptr, DNSCurveSocketSelectingList, OriginalRecv, RecvSize);
			else 
		#endif
				RecvLen = SelectingResultOnce(RequestType, Protocol, SocketDataList, &SocketSelectingList, nullptr, OriginalRecv, RecvSize);

		//Get result or all socket cloesed
			if (RecvLen >= (ssize_t)DNS_PACKET_MINSIZE)
				return RecvLen;
			else if (IsAllSocketShutdown)
				return EXIT_FAILURE;
		}

	//Reset parameters.
		FD_ZERO(&ReadFDS);
		FD_ZERO(&WriteFDS);
		MaxSocket = 0;

	//Socket check and non-blocking process
		for (Index = 0;Index < SocketDataList.size();++Index)
		{
		//Non-blocking process
			if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
			{
			//Select structure initialization
				if (SocketDataList.at(Index).Socket > MaxSocket)
					MaxSocket = SocketDataList.at(Index).Socket;

			//Receive and send process
				FD_SET(SocketDataList.at(Index).Socket, &ReadFDS);
				if (
				#if defined(ENABLE_LIBSODIUM)
					(RequestType == REQUEST_PROCESS_DNSCURVE_MAIN && !DNSCurveSocketSelectingList->at(Index).IsPacketDone) || 
				#endif
					(RequestType != REQUEST_PROCESS_DNSCURVE_MAIN && !SocketSelectingList.at(Index).IsPacketDone))
						FD_SET(SocketDataList.at(Index).Socket, &WriteFDS);
			}
			else if (MaxSocket == 0 && Index + 1U == SocketDataList.size())
			{
				return EXIT_FAILURE;
			}
		}

	//Send request only
		if (OriginalRecv == nullptr && 
			RequestType != REQUEST_PROCESS_UDP_NO_MARKING && RequestType != REQUEST_PROCESS_DNSCURVE_MAIN)
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
		SelectResult = select(0, &ReadFDS, &WriteFDS, nullptr, &Timeout);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		SelectResult = select(MaxSocket + 1U, &ReadFDS, &WriteFDS, nullptr, &Timeout);
	#endif
		if (SelectResult > 0)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
			#if defined(ENABLE_LIBSODIUM)
			//DNSCurve
				if (RequestType == REQUEST_PROCESS_DNSCURVE_MAIN)
				{
				//Receive process
					if (FD_ISSET(SocketDataList.at(Index).Socket, &ReadFDS))
					{
					//Buffer initialization
						if (!DNSCurveSocketSelectingList->at(Index).RecvBuffer)
						{
							std::shared_ptr<uint8_t> DNSCurveRecvBuffer(new uint8_t[RecvSize]());
							sodium_memzero(DNSCurveRecvBuffer.get(), RecvSize);
							DNSCurveSocketSelectingList->at(Index).RecvBuffer.swap(DNSCurveRecvBuffer);
						}

					//Receive from selecting.
						RecvLen = recv(SocketDataList.at(Index).Socket, (char *)DNSCurveSocketSelectingList->at(Index).RecvBuffer.get() + DNSCurveSocketSelectingList->at(Index).RecvLen, (int)(RecvSize - DNSCurveSocketSelectingList->at(Index).RecvLen), 0);

					//Connection closed or SOCKET_ERROR
						if (RecvLen <= 0)
						{
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
							SocketDataList.at(Index).Socket = 0;
							DNSCurveSocketSelectingList->at(Index).RecvBuffer.reset();
							DNSCurveSocketSelectingList->at(Index).RecvLen = 0;
							continue;
						}
						else if (Protocol == IPPROTO_UDP && RecvLen >= (ssize_t)DNS_PACKET_MINSIZE && DNSCurveSocketSelectingList->at(Index).RecvLen > 0)
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
						if (send(SocketDataList.at(Index).Socket, (const char *)DNSCurveSocketSelectingList->at(Index).SendBuffer, (int)DNSCurveSocketSelectingList->at(Index).SendSize, 0) == SOCKET_ERROR)
						{
							ssize_t InnerErrorCode = WSAGetLastError();
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
							SocketDataList.at(Index).Socket = 0;

						#if defined(PLATFORM_WIN)
							if (InnerErrorCode == WSAEWOULDBLOCK)
						#elif defined(PLATFORM_LINUX)
							if (InnerErrorCode == EAGAIN || InnerErrorCode == EINPROGRESS)
						#elif defined(PLATFORM_MACOS)
							if (InnerErrorCode == EWOULDBLOCK || InnerErrorCode == EAGAIN || InnerErrorCode == EINPROGRESS)
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
								std::shared_ptr<uint8_t> RecvBufferSwap(new uint8_t[RecvSize]());
								memset(RecvBufferSwap.get(), 0, RecvSize);
								SocketSelectingList.at(Index).RecvBuffer.swap(RecvBufferSwap);
							}

						//Receive from selecting.
							RecvLen = recv(SocketDataList.at(Index).Socket, (char *)SocketSelectingList.at(Index).RecvBuffer.get() + SocketSelectingList.at(Index).RecvLen, (int)(RecvSize - SocketSelectingList.at(Index).RecvLen), 0);

						//Connection closed or SOCKET_ERROR
							if (RecvLen <= 0)
							{
								SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
								SocketDataList.at(Index).Socket = 0;
								SocketSelectingList.at(Index).RecvBuffer.reset();
								SocketSelectingList.at(Index).RecvLen = 0;
								continue;
							}
							else if (Protocol == IPPROTO_UDP && RecvLen >= (ssize_t)DNS_PACKET_MINSIZE && SocketSelectingList.at(Index).RecvLen > 0)
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
							RecvLen = recv(SocketDataList.at(Index).Socket, (char *)RecvBufferTemp.get(), PACKET_MAXSIZE, 0);
							memset(RecvBufferTemp.get(), 0, PACKET_MAXSIZE);
							RecvLen = 0;
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
							SocketDataList.at(Index).Socket = 0;
						}
					}

				//Send process
					if (FD_ISSET(SocketDataList.at(Index).Socket, &WriteFDS) && !SocketSelectingList.at(Index).IsPacketDone)
					{
						if (send(SocketDataList.at(Index).Socket, (const char *)OriginalSend, (int)SendSize, 0) == SOCKET_ERROR)
						{
							ssize_t InnerErrorCode = WSAGetLastError();
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
							SocketDataList.at(Index).Socket = 0;

						#if defined(PLATFORM_WIN)
							if (InnerErrorCode == WSAEWOULDBLOCK)
						#elif defined(PLATFORM_LINUX)
							if (InnerErrorCode == EAGAIN || InnerErrorCode == EINPROGRESS)
						#elif defined(PLATFORM_MACOS)
							if (InnerErrorCode == EWOULDBLOCK || InnerErrorCode == EAGAIN || InnerErrorCode == EINPROGRESS)
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
				if (RequestType == REQUEST_PROCESS_DNSCURVE_MAIN)
				{
					auto PrecomputationKeyTemp = DNSCurveSocketSelectingList->at(Index).PrecomputationKey;
					DNSCurveSocketSelectingList->at(Index).PrecomputationKey = DNSCurveSocketSelectingList->at(LastReceiveIndex).PrecomputationKey;
					DNSCurveSocketSelectingList->at(LastReceiveIndex).PrecomputationKey = PrecomputationKeyTemp;
					auto ReceiveMagicNumberTemp = DNSCurveSocketSelectingList->at(Index).ReceiveMagicNumber;
					DNSCurveSocketSelectingList->at(Index).ReceiveMagicNumber = DNSCurveSocketSelectingList->at(LastReceiveIndex).ReceiveMagicNumber;
					DNSCurveSocketSelectingList->at(LastReceiveIndex).ReceiveMagicNumber = ReceiveMagicNumberTemp;
					DNSCurveSocketSelectingList->at(LastReceiveIndex).RecvBuffer.swap(DNSCurveSocketSelectingList->at(Index).RecvBuffer);
					RecvLen = DNSCurveSocketSelectingList->at(LastReceiveIndex).RecvLen;
					DNSCurveSocketSelectingList->at(LastReceiveIndex).RecvLen = DNSCurveSocketSelectingList->at(Index).RecvLen;
					DNSCurveSocketSelectingList->at(Index).RecvLen = RecvLen;
					RecvLen = SelectingResultOnce(RequestType, Protocol, SocketDataList, nullptr, DNSCurveSocketSelectingList, OriginalRecv, RecvSize);
				}
				else {
			#endif
					SocketSelectingList.at(LastReceiveIndex).RecvBuffer.swap(SocketSelectingList.at(Index).RecvBuffer);
					RecvLen = SocketSelectingList.at(LastReceiveIndex).RecvLen;
					SocketSelectingList.at(LastReceiveIndex).RecvLen = SocketSelectingList.at(Index).RecvLen;
					SocketSelectingList.at(Index).RecvLen = RecvLen;
					RecvLen = SelectingResultOnce(RequestType, Protocol, SocketDataList, &SocketSelectingList, nullptr, OriginalRecv, RecvSize);
			#if defined(ENABLE_LIBSODIUM)
				}
			#endif

			//Buffer list check(Part 2)
				if (RecvLen >= (ssize_t)DNS_PACKET_MINSIZE)
					return RecvLen;
			}
			else if (RequestType == REQUEST_PROCESS_UDP_NO_MARKING)
			{
			//Close all sockets.
				for (auto &SocketDataIter:SocketDataList)
				{
					SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
		SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		SocketDataIter.Socket = 0;
	}

	return EXIT_FAILURE;
}

//Socket selecting result(Once)
ssize_t SelectingResultOnce(
	const size_t RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_ONCE_DATA> *SocketSelectingList, 
	void * const OriginalDNSCurveSocketSelectingList, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize)
{
#if defined(ENABLE_LIBSODIUM)
	auto DNSCurveSocketSelectingList = (std::vector<DNSCURVE_SOCKET_SELECTING_DATA> *)OriginalDNSCurveSocketSelectingList;
	if (RequestType == REQUEST_PROCESS_DNSCURVE_MAIN)
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
		if (RequestType == REQUEST_PROCESS_DNSCURVE_MAIN)
		{
			if (DNSCurveSocketSelectingList->at(Index).RecvBuffer && DNSCurveSocketSelectingList->at(Index).RecvLen >= DNS_PACKET_MINSIZE)
			{
			//TCP header length check
				if (Protocol == IPPROTO_TCP)
				{
					RecvLen = ntohs(((uint16_t *)DNSCurveSocketSelectingList->at(Index).RecvBuffer.get())[0]);
					if (RecvLen < (ssize_t)DNS_PACKET_MINSIZE || RecvLen >= (ssize_t)RecvSize || RecvLen > (ssize_t)DNSCurveSocketSelectingList->at(Index).RecvLen)
					{
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
						SocketDataList.at(Index).Socket = 0;
						DNSCurveSocketSelectingList->at(Index).RecvBuffer.reset();
						DNSCurveSocketSelectingList->at(Index).RecvLen = 0;
						continue;
					}
					else {
						memmove_s(DNSCurveSocketSelectingList->at(Index).RecvBuffer.get(), RecvSize, DNSCurveSocketSelectingList->at(Index).RecvBuffer.get() + sizeof(uint16_t), RecvLen);
						sodium_memzero(DNSCurveSocketSelectingList->at(Index).RecvBuffer.get() + RecvLen, (ssize_t)RecvSize - RecvLen);
					}
				}
			//UDP length
				else if (Protocol == IPPROTO_UDP)
				{
					RecvLen = DNSCurveSocketSelectingList->at(Index).RecvLen;
				}
				else {
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
					SocketDataList.at(Index).Socket = 0;
					DNSCurveSocketSelectingList->at(Index).RecvBuffer.reset();
					DNSCurveSocketSelectingList->at(Index).RecvLen = 0;
					continue;
				}

			//Decrypt or get packet data(DNSCurve).
				if (RequestType == REQUEST_PROCESS_DNSCURVE_MAIN)
				{
					RecvLen = DNSCurvePacketDecryption(DNSCurveSocketSelectingList->at(Index).ReceiveMagicNumber, DNSCurveSocketSelectingList->at(Index).PrecomputationKey, DNSCurveSocketSelectingList->at(Index).RecvBuffer.get(), RecvSize, RecvLen);
					if (RecvLen < (ssize_t)DNS_PACKET_MINSIZE)
					{
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
					if (SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
					{
						SOCKET_MARKING_DATA SocketMarkingDataTemp;
						SocketMarkingDataTemp.first = SocketDataIter.Socket;
						if (Protocol == IPPROTO_TCP)
						#if defined(PLATFORM_WIN)
							SocketMarkingDataTemp.second = GetCurrentSystemTime() + DNSCurveParameter.DNSCurve_SocketTimeout_Reliable;
						#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							SocketMarkingDataTemp.second = IncreaseMillisecondTime(GetCurrentSystemTime(), DNSCurveParameter.DNSCurve_SocketTimeout_Reliable);
						#endif
						else if (Protocol == IPPROTO_UDP)
						#if defined(PLATFORM_WIN)
							SocketMarkingDataTemp.second = GetCurrentSystemTime() + DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable;
						#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
							SocketMarkingDataTemp.second = IncreaseMillisecondTime(GetCurrentSystemTime(), DNSCurveParameter.DNSCurve_SocketTimeout_Unreliable);
						#endif
						else 
							continue;

						SocketMarkingList.push_back(SocketMarkingDataTemp);
						SocketDataIter.Socket = 0;
					}
				}
				SocketMarkingMutex.unlock();

			//Mark DNS cache.
				if (Parameter.CacheType != CACHE_TYPE_NONE)
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
					RecvLen = ntohs(((uint16_t *)SocketSelectingList->at(Index).RecvBuffer.get())[0]);
					if (RecvLen < (ssize_t)DNS_PACKET_MINSIZE || RecvLen >= (ssize_t)RecvSize || RecvLen > (ssize_t)SocketSelectingList->at(Index).RecvLen)
					{
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
						SocketDataList.at(Index).Socket = 0;
						SocketSelectingList->at(Index).RecvBuffer.reset();
						SocketSelectingList->at(Index).RecvLen = 0;
						continue;
					}
					else {
						memmove_s(SocketSelectingList->at(Index).RecvBuffer.get(), RecvSize, SocketSelectingList->at(Index).RecvBuffer.get() + sizeof(uint16_t), RecvLen);
						memset(SocketSelectingList->at(Index).RecvBuffer.get() + RecvLen, 0, RecvSize - (size_t)RecvLen);
					}
				}
			//UDP length
				else if (Protocol == IPPROTO_UDP)
				{
					RecvLen = SocketSelectingList->at(Index).RecvLen;
				}
				else {
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
				if (RecvLen < (ssize_t)DNS_PACKET_MINSIZE)
				{
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
					if (SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
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
				if (Parameter.CacheType != CACHE_TYPE_NONE)
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
	const size_t RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList)
{
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
		if (SocketSetting(SocketDataIter->Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
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
		Timeout.tv_sec = Parameter.SocketTimeout_Reliable_Serial.tv_sec;
		Timeout.tv_usec = Parameter.SocketTimeout_Reliable_Serial.tv_usec;
	#endif
	}
	else if (Protocol == IPPROTO_UDP)
	{
	#if defined(PLATFORM_WIN)
		Timeout.tv_sec = Parameter.SocketTimeout_Unreliable_Serial / SECOND_TO_MILLISECOND;
		Timeout.tv_usec = Parameter.SocketTimeout_Unreliable_Serial % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		Timeout.tv_sec = Parameter.SocketTimeout_Unreliable_Serial.tv_sec;
		Timeout.tv_usec = Parameter.SocketTimeout_Unreliable_Serial.tv_usec;
	#endif
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check and attribute setting
	for (Index = 0;Index < SocketSelectingDataList.size();++Index)
	{
		SocketSelectingDataList.at(Index).IsPacketDone = false;
		if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
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
			if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr) && 
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
					if (send(SocketDataList.at(Index).Socket, (const char *)SocketSelectingDataList.at(Index).SendBuffer.get(), (int)SocketSelectingDataList.at(Index).SendLen, 0) == SOCKET_ERROR)
					{
						ErrorCodeList.at(Index) = WSAGetLastError();
				
					//Send in progress.
					#if defined(PLATFORM_WIN)
						if (ErrorCodeList.at(Index) == WSAEWOULDBLOCK)
					#elif defined(PLATFORM_LINUX)
						if (ErrorCodeList.at(Index) == EAGAIN || ErrorCodeList.at(Index) == EINPROGRESS)
					#elif defined(PLATFORM_MACOS)
						if (ErrorCodeList.at(Index) == EWOULDBLOCK || ErrorCodeList.at(Index) == EAGAIN || ErrorCodeList.at(Index) == EINPROGRESS)
					#endif
						{
							ErrorCodeList.at(Index) = 0;
						}
					//SOCKET_ERROR
						else {
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
				SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
		if (SocketSetting(SocketDataIter->Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
			break;
		else if (SocketDataIter + 1U == SocketDataList.end())
			return EXIT_FAILURE;
	}

//Socket check and attribute setting
	for (Index = 0;Index < SocketSelectingDataList.size();++Index)
	{
		SocketSelectingDataList.at(Index).IsPacketDone = false;
		if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
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
			if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr) && 
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
							std::shared_ptr<uint8_t> RecvBuffer(new uint8_t[Parameter.LargeBufferSize]);
							memset(RecvBuffer.get(), 0, Parameter.LargeBufferSize);
							SocketSelectingDataList.at(Index).RecvBuffer.swap(RecvBuffer);
							SocketSelectingDataList.at(Index).RecvSize = Parameter.LargeBufferSize;
							SocketSelectingDataList.at(Index).RecvLen = 0;
						}
						else if (SocketSelectingDataList.at(Index).RecvSize < SocketSelectingDataList.at(Index).RecvLen + Parameter.LargeBufferSize)
						{
							std::shared_ptr<uint8_t> RecvBuffer(new uint8_t[SocketSelectingDataList.at(Index).RecvSize + Parameter.LargeBufferSize]);
							memset(RecvBuffer.get(), 0, SocketSelectingDataList.at(Index).RecvSize + Parameter.LargeBufferSize);
							memcpy_s(RecvBuffer.get(), SocketSelectingDataList.at(Index).RecvSize + Parameter.LargeBufferSize, SocketSelectingDataList.at(Index).RecvBuffer.get(), SocketSelectingDataList.at(Index).RecvLen);
							SocketSelectingDataList.at(Index).RecvBuffer.swap(RecvBuffer);
							SocketSelectingDataList.at(Index).RecvSize += Parameter.LargeBufferSize;
						}

					//Receive process
						RecvLen = recv(SocketDataList.at(Index).Socket, (char *)(SocketSelectingDataList.at(Index).RecvBuffer.get() + SocketSelectingDataList.at(Index).RecvLen), (int)(SocketSelectingDataList.at(Index).RecvSize - SocketSelectingDataList.at(Index).RecvLen), 0);
						if (RecvLen == SOCKET_ERROR)
						{
							ErrorCodeList.at(Index) = WSAGetLastError();

						//Receive in progress.
						#if defined(PLATFORM_WIN)
							if (ErrorCodeList.at(Index) == WSAEWOULDBLOCK)
						#elif defined(PLATFORM_LINUX)
							if (ErrorCodeList.at(Index) == EAGAIN || ErrorCodeList.at(Index) == EINPROGRESS)
						#elif defined(PLATFORM_MACOS)
							if (ErrorCodeList.at(Index) == EWOULDBLOCK || ErrorCodeList.at(Index) == EAGAIN || ErrorCodeList.at(Index) == EINPROGRESS)
						#endif
							{
								ErrorCodeList.at(Index) = 0;

							//Connection stream finished check
								if (Protocol == IPPROTO_UDP || CheckConnectionStreamFin(RequestType, SocketSelectingDataList.at(Index).RecvBuffer.get(), SocketSelectingDataList.at(Index).RecvLen))
									SocketSelectingDataList.at(Index).IsPacketDone = true;
							}
						//SOCKET_ERROR
							else {
								SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
								SocketDataList.at(Index).Socket = 0;
							}

							break;
						}
						else if (RecvLen == 0) //Connection closed
						{
							SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
							SocketDataList.at(Index).Socket = 0;

							break;
						}
						else {
							SocketSelectingDataList.at(Index).RecvLen += (size_t)RecvLen;
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
				SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
	if (LocalSocketData != nullptr && Protocol > 0)
	{
		SOCKET_DATA SocketDataTemp;
		OUTPUT_PACKET_TABLE OutputPacketListTemp;
		memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));
		memset(&OutputPacketListTemp, 0, sizeof(OutputPacketListTemp));

	//Mark system connection data.
		OutputPacketListTemp.SocketData_Input = *LocalSocketData;

	//Mark sending connection data.
		for (auto &SocketDataIter:SocketDataList)
		{
			if (!SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
				continue;
			else 
				memset(&SocketDataTemp, 0, sizeof(SocketDataTemp));

		//Get socket information.
			if (getsockname(SocketDataIter.Socket, (PSOCKADDR)&SocketDataIter.SockAddr, &SocketDataIter.AddrLen) != 0)
			{
				SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				SocketDataIter.Socket = 0;

				continue;
			}

			SocketDataTemp.AddrLen = SocketDataIter.AddrLen;
			if (SocketDataIter.AddrLen == sizeof(sockaddr_in6))
			{
				SocketDataTemp.SockAddr.ss_family = AF_INET6;
				((PSOCKADDR_IN6)&SocketDataTemp.SockAddr)->sin6_port = ((PSOCKADDR_IN6)&SocketDataIter.SockAddr)->sin6_port;
			}
			else if (SocketDataIter.AddrLen == sizeof(sockaddr_in))
			{
				SocketDataTemp.SockAddr.ss_family = AF_INET;
				((PSOCKADDR_IN)&SocketDataTemp.SockAddr)->sin_port = ((PSOCKADDR_IN)&SocketDataIter.SockAddr)->sin_port;
			}
			else {
				SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
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
						++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV6];
					else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP)
						++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_UDP_IPV6];
				}
				else if (OutputPacketList.front().Protocol_Network == AF_INET)
				{
					if (OutputPacketList.front().Protocol_Transport == IPPROTO_TCP)
						++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV4];
					else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP)
						++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_UDP_IPV4];
				}
			}

			OutputPacketList.pop_front();
		}

		OutputPacketList.push_back(OutputPacketListTemp);
	}

//Block Port Unreachable messages of system or close the TCP request connections.
	for (auto &SocketDataIter:SocketDataList)
	{
		if (SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
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
		SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		SocketDataIter.Socket = 0;
	}

	return;
}
#endif
