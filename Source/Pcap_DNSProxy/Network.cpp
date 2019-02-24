// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on packet capturing
// Copyright (C) 2012-2019 Chengr28
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

//Set socket attribute
bool SetSocketAttribute(
	SYSTEM_SOCKET &Socket, 
	const SOCKET_SETTING_TYPE SettingType, 
	const bool IsPrintError, 
	void * const DataPointer)
{
	switch (SettingType)
	{
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
			if (GlobalConfiguration.DoNotFragment_IPv4)
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
			if (GlobalConfiguration.PacketHopLimits_IPv6_End > 0)
			{
			#if defined(PLATFORM_WIN)
				DWORD OptionValue = 0;
				GenerateRandomBuffer(&OptionValue, sizeof(OptionValue), nullptr, GlobalConfiguration.PacketHopLimits_IPv6_Begin, GlobalConfiguration.PacketHopLimits_IPv6_End);
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				int OptionValue = 0;
				GenerateRandomBuffer(&OptionValue, sizeof(OptionValue), nullptr, GlobalConfiguration.PacketHopLimits_IPv6_Begin, GlobalConfiguration.PacketHopLimits_IPv6_End);
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
			else if (GlobalConfiguration.PacketHopLimits_IPv6_Begin > 0)
			{
			#if defined(PLATFORM_WIN)
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, reinterpret_cast<const char *>(&GlobalConfiguration.PacketHopLimits_IPv6_Begin), sizeof(GlobalConfiguration.PacketHopLimits_IPv6_Begin)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (setsockopt(Socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &GlobalConfiguration.PacketHopLimits_IPv6_Begin, sizeof(GlobalConfiguration.PacketHopLimits_IPv6_Begin)) == SOCKET_ERROR)
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
			if (GlobalConfiguration.PacketHopLimits_IPv4_End > 0)
			{
			#if defined(PLATFORM_WIN)
				DWORD OptionValue = 0;
				GenerateRandomBuffer(&OptionValue, sizeof(OptionValue), nullptr, GlobalConfiguration.PacketHopLimits_IPv4_Begin, GlobalConfiguration.PacketHopLimits_IPv4_End);
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				int OptionValue = 0;
				GenerateRandomBuffer(&OptionValue, sizeof(OptionValue), nullptr, GlobalConfiguration.PacketHopLimits_IPv4_Begin, GlobalConfiguration.PacketHopLimits_IPv4_End);
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
			else if (GlobalConfiguration.PacketHopLimits_IPv4_Begin > 0)
			{
			#if defined(PLATFORM_WIN)
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, reinterpret_cast<const char *>(&GlobalConfiguration.PacketHopLimits_IPv4_Begin), sizeof(GlobalConfiguration.PacketHopLimits_IPv4_Begin)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, &GlobalConfiguration.PacketHopLimits_IPv4_Begin, sizeof(GlobalConfiguration.PacketHopLimits_IPv4_Begin)) == SOCKET_ERROR)
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
/* No need to set TIME_WAIT resuing.
			errno = 0;
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
	//Socket attribute setting(TFO/TCP Fast Open, normal version)
		case SOCKET_SETTING_TYPE::TCP_FAST_OPEN_NORMAL:
		{
			if (GlobalConfiguration.TCP_FastOpen > 0)
			{
			//Windows: Server side is completed, client side is only support overlapped I/O. Waiting Microsoft extends it to normal socket.
			//Linux: Server side and client side are both completed, also support queue length.
			//macOS: Server side and client side are both completed.
			#if defined(PLATFORM_WIN)
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
			#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
				errno = 0;
			#if defined(PLATFORM_FREEBSD)
				const int OptionValue = GlobalConfiguration.TCP_FastOpen;
				if (setsockopt(Socket, IPPROTO_TCP, TCP_FASTOPEN, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
			#elif defined(PLATFORM_LINUX)
				const int OptionValue = GlobalConfiguration.TCP_FastOpen;
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
	//Socket attribute setting(TFO/TCP Fast Open, client version)
	#if defined(PLATFORM_LINUX)
		case SOCKET_SETTING_TYPE::TCP_FAST_OPEN_CONNECT:
		{
		//Linux: Client side is completed, also support queue length.
			if (GlobalConfiguration.TCP_FastOpen > 0)
			{
				errno = 0;
				const int OptionValue = GlobalConfiguration.TCP_FastOpen;
				if (setsockopt(Socket, SOL_TCP, TCP_FASTOPEN_CONNECT, reinterpret_cast<const char *>(&OptionValue), sizeof(OptionValue)) == SOCKET_ERROR)
				{
					if (IsPrintError)
						PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"Socket TCP Fast Open settings error", errno, nullptr, 0);
					shutdown(Socket, SHUT_RDWR);
					close(Socket);
					Socket = INVALID_SOCKET;

					return false;
				}
			}
		}break;
	#endif
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
/* No need to set interval keepalive packet and timeout, use system default. 
			tcp_keepalive AliveTransport_IN;
			tcp_keepalive AliveTransport_OUT;
			memset(&AliveTransport_IN, 0, sizeof(tcp_keepalive));
			memset(&AliveTransport_OUT, 0, sizeof(tcp_keepalive));
			AliveTransport_IN.onoff = 1U;
			AliveTransport_IN.keepalivetime = GlobalConfiguration.SocketTimeout_Reliable_Once;
			AliveTransport_IN.keepaliveinterval = STANDARD_TIMEOUT;
			ULONG ulBytesReturn = 0;
			if (WSAIoctl(
				Socket, 
				SIO_KEEPALIVE_VALS, 
				&AliveTransport_IN, 
				sizeof(tcp_keepalive), 
				&AliveTransport_OUT, 
				sizeof(tcp_keepalive), 
				&ulBytesReturn, 
				nullptr, 
				nullptr) == SOCKET_ERROR)
			{
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
				Socket = INVALID_SOCKET;

				return false;
			}
*/
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
			if (WSAIoctl(
				Socket, 
				SIO_UDP_CONNRESET, 
				&NewBehavior, 
				sizeof(BOOL), 
				nullptr, 
				0, 
				&BytesReturned, 
				nullptr, 
				nullptr) == SOCKET_ERROR)
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
