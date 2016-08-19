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

//Socket option settings
bool SocketSetting(
	const SYSTEM_SOCKET Socket, 
	const size_t SettingType, 
	const bool IsPrintError, 
	void *DataPointer)
{
	switch (SettingType)
	{
	//Socket check
		case SOCKET_SETTING_INVALID_CHECK:
		{
		#if defined(PLATFORM_WIN)
			if (Socket == 0 || Socket == INVALID_SOCKET || Socket == SOCKET_ERROR)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (Socket == 0 || Socket == INVALID_SOCKET)
		#endif
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket initialization error", WSAGetLastError(), nullptr, 0);

				return false;
			}
		}break;
	//Socket closing
		case SOCKET_SETTING_CLOSE:
		{
		#if defined(PLATFORM_WIN)
			if (Socket != 0 && Socket != INVALID_SOCKET || Socket != SOCKET_ERROR)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (Socket != 0 && Socket != INVALID_SOCKET)
		#endif
			{
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);
			}
		}break;
	//Socket timeout setting
		case SOCKET_SETTING_TIMEOUT:
		{
		//Pointer check
			if (DataPointer == nullptr)
				return false;

		//Socket timeout options
		#if defined(PLATFORM_WIN)
			if (setsockopt(Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)DataPointer, sizeof(int)) == SOCKET_ERROR || 
				setsockopt(Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)DataPointer, sizeof(int)) == SOCKET_ERROR)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
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
	//Socket reusing setting
		case SOCKET_SETTING_REUSE:
		{
			int SetVal = 1;
			
		#if defined(PLATFORM_WIN)
		//Preventing other sockets from being forcibly bound to the same address and port(Windows).
			if (setsockopt(Socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket reusing disable setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		//Set TIME_WAIT resuing(Linux/Mac).
/*			errno = 0;
			if (setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket reusing enable setting error", errno, nullptr, 0);
				shutdown(Socket, SHUT_RDWR);
				close(Socket);

				return false;
			}
*/
		//Set an IPv6 server socket that cannot accept IPv4 connections in Linux.
			SetVal = 1;
			errno = 0;
			if (setsockopt(Socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket treating wildcard bind setting error", errno, nullptr, 0);
				shutdown(Socket, SHUT_RDWR);
				close(Socket);

				return false;
			}
		#endif
		}break;
	//Socket TCP Fast Open setting
	#if defined(PLATFORM_LINUX)
		case SOCKET_SETTING_TCP_FAST_OPEN:
		{
			int SetVal = TCP_FASTOPEN_HINT;
			errno = 0;
			if (setsockopt(Socket, SOL_TCP, TCP_FASTOPEN, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket TCP Fast Open setting error", errno, nullptr, 0);
				shutdown(Socket, SHUT_RDWR);
				close(Socket);

				return false;
			}
		}break;
	#endif
	//Socket Non-blocking Mode setting
		case SOCKET_SETTING_NON_BLOCKING_MODE:
		{
		#if defined(PLATFORM_WIN)
			unsigned long SocketMode = 1U;
			if (ioctlsocket(Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			auto SocketMode = fcntl(Socket, F_GETFL, 0);
			if (SocketMode == RETURN_ERROR || fcntl(Socket, F_SETFL, SocketMode|O_NONBLOCK) == RETURN_ERROR)
		#endif
			{
				if (IsPrintError)
					PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Socket non-blocking mode setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		}break;
/* Socket TCP keepalive mode setting
	#if defined(PLATFORM_WIN)
		case SOCKET_SETTING_TCP_KEEPALIVE:
		{
			BOOL SetVal = TRUE;
			if (setsockopt(Socket, SOL_SOCKET, SO_KEEPALIVE, (const char *)&SetVal, sizeof(BOOL)) == SOCKET_ERROR)
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
			Alive_IN.keepaliveinterval = Parameter.SocketTimeout_Reliable;
			Alive_IN.onoff = TRUE;
			ULONG ulBytesReturn = 0;
			if (WSAIoctl(Socket, SIO_KEEPALIVE_VALS, &Alive_IN, sizeof(tcp_keepalive), &Alive_OUT, sizeof(tcp_keepalive), &ulBytesReturn, nullptr, nullptr) == SOCKET_ERROR)
			{
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		}break;
	#endif
*/
	//Socket UDP block RESET message setting
	#if defined(PLATFORM_WIN)
		case SOCKET_SETTING_UDP_BLOCK_RESET:
		{
			DWORD BytesReturned = 0;
			BOOL NewBehavior = FALSE;
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
	//Socket IPv4 header TTL setting
		case SOCKET_SETTING_HOP_LIMITS_IPV4:
		{
		//Range
			if (Parameter.PacketHopLimits_IPv4_End > 0)
			{
			//Ramdom number distribution initialization
				std::uniform_int_distribution<int> RamdomDistribution(Parameter.PacketHopLimits_IPv4_Begin, Parameter.PacketHopLimits_IPv4_End);
				int HopLimitsValue = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);

			//Hop Limits setting
			#if defined(PLATFORM_WIN)
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, (const char *)&HopLimitsValue, sizeof(int)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, &HopLimitsValue, sizeof(int)) == SOCKET_ERROR)
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
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, (const char *)&Parameter.PacketHopLimits_IPv4_Begin, sizeof(int)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (setsockopt(Socket, IPPROTO_IP, IP_TTL, &Parameter.PacketHopLimits_IPv4_Begin, sizeof(int)) == SOCKET_ERROR)
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
	//Socket IPv6 header Hop Limts setting
		case SOCKET_SETTING_HOP_LIMITS_IPV6:
		{
		//Range
			if (Parameter.PacketHopLimits_IPv6_End > 0)
			{
			//Ramdom number distribution initialization
				std::uniform_int_distribution<int> RamdomDistribution(Parameter.PacketHopLimits_IPv6_Begin, Parameter.PacketHopLimits_IPv6_End);
				int HopLimitsValue = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);

			//Hop Limits setting
			#if defined(PLATFORM_WIN)
				if (setsockopt(Socket, IPPROTO_IP, IPV6_UNICAST_HOPS, (const char *)&HopLimitsValue, sizeof(int)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (setsockopt(Socket, IPPROTO_IP, IPV6_UNICAST_HOPS, &HopLimitsValue, sizeof(int)) == SOCKET_ERROR)
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
				if (setsockopt(Socket, IPPROTO_IP, IPV6_UNICAST_HOPS, (const char *)&Parameter.PacketHopLimits_IPv6_Begin, sizeof(int)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				if (setsockopt(Socket, IPPROTO_IP, IPV6_UNICAST_HOPS, &Parameter.PacketHopLimits_IPv6_Begin, sizeof(int)) == SOCKET_ERROR)
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
	//Socket IPv4 header Do Not Fragment flag setting
	#if (defined(PLATFORM_WIN) || defined(PLATFORM_LINUX))
		case SOCKET_SETTING_DO_NOT_FRAGMENT:
		{
			if (Parameter.DoNotFragment)
			{
			#if defined(PLATFORM_WIN)
				int DoNotFragment = 1;
				if (setsockopt(Socket, IPPROTO_IP, IP_DONTFRAGMENT, (const char *)&DoNotFragment, sizeof(int)) == SOCKET_ERROR)
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				int DoNotFragment = IP_PMTUDISC_DO;
				if (setsockopt(Socket, IPPROTO_IP, IP_MTU_DISCOVER, &DoNotFragment, sizeof(int)) == SOCKET_ERROR)
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

//Connect to server(TCP) or socket connecting(UDP)
size_t SocketConnecting(
	const uint16_t Protocol, 
	const SYSTEM_SOCKET Socket, 
	const sockaddr *SockAddr, 
	const socklen_t AddrLen, 
	const uint8_t *OriginalSend, 
	const size_t SendSize)
{
//Disable warning message.
#if (defined(PLATFORM_WIN) || defined(PLATFORM_MACX))
	SendSize;
	OriginalSend;
#endif

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
			#elif defined(PLATFORM_MACX)
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

//Non-blocking mode selecting
ssize_t SocketSelecting(
	const size_t RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	const uint8_t *OriginalSend, 
	const size_t SendSize, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize, 
	ssize_t *ErrorCode)
{
//Initialization(Part 1)
	std::vector<SOCKET_SELECTING_DATA> SocketSelectingList(SocketDataList.size());
	for (auto &SocketSelectingIter:SocketSelectingList)
	{
		SocketSelectingIter.Length = 0;
		SocketSelectingIter.IsPacketSend = false;
	}
	size_t Index = 0;
	ssize_t RecvLen = 0;
	if (ErrorCode != nullptr)
		*ErrorCode = 0;

//TCP or UDP connecting
	for (auto &SocketDataIter:SocketDataList)
	{
		RecvLen = SocketConnecting(Protocol, SocketDataIter.Socket, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen, OriginalSend, SendSize);
		if (RecvLen == EXIT_FAILURE)
		{
			SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			SocketDataIter.Socket = 0;
		}
	#if defined(PLATFORM_LINUX)
		else if (Protocol == IPPROTO_TCP && Parameter.TCP_FastOpen && RecvLen > (ssize_t)DNS_PACKET_MINSIZE)
		{
			SocketSelectingList.at(Index).IsPacketSend = true;
			++Index;
		}
	#endif
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
	fd_set ReadFDS, WriteFDS;
	timeval Timeout;
	memset(&ReadFDS, 0, sizeof(ReadFDS));
	memset(&WriteFDS, 0, sizeof(WriteFDS));
	memset(&Timeout, 0, sizeof(Timeout));
	ssize_t SelectResult = 0;
	size_t LastReceiveIndex = 0;
	SYSTEM_SOCKET MaxSocket = 0;
	auto IsAllSocketClosed = false;

//Socket timeout setting
#if defined(PLATFORM_WIN)
	Timeout.tv_sec = Parameter.SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
	Timeout.tv_usec = Parameter.SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Timeout.tv_sec = Parameter.SocketTimeout_Reliable.tv_sec;
	Timeout.tv_usec = Parameter.SocketTimeout_Reliable.tv_usec;
#endif

//Selecting process
	for (;;)
	{
	//Socket check(Part 2)
		for (auto SocketDataIter = SocketDataList.begin();SocketDataIter != SocketDataList.end();++SocketDataIter)
		{
			if (SocketSetting(SocketDataIter->Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
				break;
			else if (SocketDataIter + 1U == SocketDataList.end())
				IsAllSocketClosed = true;
		}

	//Buffer list check(Part 1)
		if (OriginalRecv != nullptr && (IsAllSocketClosed || Parameter.ReceiveWaiting == 0 || SocketDataList.size() == 1U))
		{
		//Scan all result.
			RecvLen = SelectingResult(RequestType, Protocol, SocketDataList, SocketSelectingList, OriginalRecv, RecvSize);
			if (RecvLen >= (ssize_t)DNS_PACKET_MINSIZE)
				return RecvLen;
		//All socket cloesed. 
			else if (IsAllSocketClosed)
				return EXIT_FAILURE;
		}

	//Reset parameters.
		FD_ZERO(&ReadFDS);
		FD_ZERO(&WriteFDS);
		MaxSocket = 0;

	//Socket check and non-blocking process setting
		for (Index = 0;Index < SocketDataList.size();++Index)
		{
		//Non-blocking process setting
			if (SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
			{
			//Select structure setting
				if (SocketDataList.at(Index).Socket > MaxSocket)
					MaxSocket = SocketDataList.at(Index).Socket;

			//Receive process
				if (OriginalRecv != nullptr)
					FD_SET(SocketDataList.at(Index).Socket, &ReadFDS);

			//Send process
				if (!SocketSelectingList.at(Index).IsPacketSend)
					FD_SET(SocketDataList.at(Index).Socket, &WriteFDS);
			}
			else if (MaxSocket == 0 && Index + 1U == SocketDataList.size())
			{
				return EXIT_FAILURE;
			}
		}

	//Send request only
		if (OriginalRecv == nullptr)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
				if (!SocketSelectingList.at(Index).IsPacketSend)
					break;
				else if (Index + 1U == SocketDataList.size())
					return EXIT_SUCCESS;
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, &ReadFDS, &WriteFDS, nullptr, &Timeout);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(MaxSocket + 1U, &ReadFDS, &WriteFDS, nullptr, &Timeout);
	#endif
		if (SelectResult > 0)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
			//Receive process
				if (FD_ISSET(SocketDataList.at(Index).Socket, &ReadFDS) && OriginalRecv != nullptr)
				{
				//Buffer initialization
					if (!SocketSelectingList.at(Index).RecvBuffer)
					{
						std::shared_ptr<uint8_t> RecvBufferTemp(new uint8_t[RecvSize]());
						memset(RecvBufferTemp.get(), 0, RecvSize);
						SocketSelectingList.at(Index).RecvBuffer.swap(RecvBufferTemp);
					}

				//Receive from selecting.
					RecvLen = recv(SocketDataList.at(Index).Socket, (char *)SocketSelectingList.at(Index).RecvBuffer.get() + SocketSelectingList.at(Index).Length, (int)(RecvSize - SocketSelectingList.at(Index).Length), 0);

				//Connection closed or SOCKET_ERROR
					if (RecvLen <= 0)
					{
						SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
						SocketDataList.at(Index).Socket = 0;
						SocketSelectingList.at(Index).RecvBuffer.reset();
						SocketSelectingList.at(Index).Length = 0;
						continue;
					}
					else if (Protocol == IPPROTO_UDP && RecvLen > (ssize_t)DNS_PACKET_MINSIZE && SocketSelectingList.at(Index).Length > 0)
					{
						memset(SocketSelectingList.at(Index).RecvBuffer.get(), 0, SocketSelectingList.at(Index).Length);
						memmove_s(SocketSelectingList.at(Index).RecvBuffer.get(), RecvSize, SocketSelectingList.at(Index).RecvBuffer.get() + SocketSelectingList.at(Index).Length, RecvLen);
						SocketSelectingList.at(Index).Length = 0;
					}

				//Mark whole packet length and last packet.
					SocketSelectingList.at(Index).Length += RecvLen;
					LastReceiveIndex = Index;
				}

			//Send process
				if (FD_ISSET(SocketDataList.at(Index).Socket, &WriteFDS) && !SocketSelectingList.at(Index).IsPacketSend)
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
					#elif defined(PLATFORM_MACX)
						if (InnerErrorCode == EWOULDBLOCK || InnerErrorCode == EAGAIN || InnerErrorCode == EINPROGRESS)
					#endif
						{
							SocketSelectingList.at(Index).RecvBuffer.reset();
							SocketSelectingList.at(Index).Length = 0;
						}
					}
					else {
						SocketSelectingList.at(Index).IsPacketSend = true;
					}
				}
			}
		}
	//Timeout
		else if (SelectResult == 0)
		{
			if (OriginalRecv != nullptr)
			{
			//Swap to last receive packet when Receive Waiting is ON.
				Index = 0;
				MaxSocket = SocketDataList.at(LastReceiveIndex).Socket;
				SocketDataList.at(LastReceiveIndex).Socket = SocketDataList.at(Index).Socket;
				SocketDataList.at(Index).Socket = MaxSocket;
				SocketSelectingList.at(LastReceiveIndex).RecvBuffer.swap(SocketSelectingList.at(Index).RecvBuffer);
				RecvLen = SocketSelectingList.at(LastReceiveIndex).Length;
				SocketSelectingList.at(LastReceiveIndex).Length = SocketSelectingList.at(Index).Length;
				SocketSelectingList.at(Index).Length = RecvLen;

			//Buffer list check(Part 2)
				RecvLen = SelectingResult(RequestType, Protocol, SocketDataList, SocketSelectingList, OriginalRecv, RecvSize);
				if (RecvLen >= (ssize_t)DNS_PACKET_MINSIZE)
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
	for (auto &SocketDataIter:SocketDataList)
	{
		SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		SocketDataIter.Socket = 0;
	}

	return EXIT_FAILURE;
}

//Socket selecting result
ssize_t SelectingResult(
	const size_t RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_DATA> &SocketSelectingList, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize)
{
	ssize_t RecvLen = 0;

//Scan all buffer.
	for (size_t Index = 0;Index < SocketDataList.size();++Index)
	{
		if (SocketSelectingList.at(Index).RecvBuffer && SocketSelectingList.at(Index).Length >= DNS_PACKET_MINSIZE)
		{
		//TCP header length check
			if (Protocol == IPPROTO_TCP)
			{
				RecvLen = ntohs(((uint16_t *)SocketSelectingList.at(Index).RecvBuffer.get())[0]);
				if (RecvLen < (ssize_t)DNS_PACKET_MINSIZE || RecvLen > (ssize_t)SocketSelectingList.at(Index).Length || 
					RecvLen >= (ssize_t)RecvSize)
				{
					SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
					SocketDataList.at(Index).Socket = 0;
					SocketSelectingList.at(Index).RecvBuffer.reset();
					SocketSelectingList.at(Index).Length = 0;
					continue;
				}
				else {
					memmove_s(SocketSelectingList.at(Index).RecvBuffer.get(), RecvSize, SocketSelectingList.at(Index).RecvBuffer.get() + sizeof(uint16_t), RecvLen);
					memset(SocketSelectingList.at(Index).RecvBuffer.get() + RecvLen, 0, RecvSize - (size_t)RecvLen);
				}
			}
		//UDP length
			else if (Protocol == IPPROTO_UDP)
			{
				RecvLen = SocketSelectingList.at(Index).Length;
			}
			else {
				SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				SocketDataList.at(Index).Socket = 0;
				SocketSelectingList.at(Index).RecvBuffer.reset();
				SocketSelectingList.at(Index).Length = 0;
				continue;
			}

		//Receive from buffer list.
			RecvLen = CheckResponseData(
				RequestType, 
				SocketSelectingList.at(Index).RecvBuffer.get(), 
				RecvLen, 
				RecvSize, 
				nullptr);
			if (RecvLen < (ssize_t)DNS_PACKET_MINSIZE)
			{
				SocketSetting(SocketDataList.at(Index).Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				SocketDataList.at(Index).Socket = 0;
				SocketSelectingList.at(Index).RecvBuffer.reset();
				SocketSelectingList.at(Index).Length = 0;
				continue;
			}
			else {
				memset(OriginalRecv, 0, RecvSize);
				memcpy_s(OriginalRecv, RecvSize, SocketSelectingList.at(Index).RecvBuffer.get(), RecvLen);
			}

		//Close all sockets.
			for (auto &SocketDataIter:SocketDataList)
			{
				SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				SocketDataIter.Socket = 0;
			}

		//Mark DNS cache.
			if (Parameter.CacheType > 0)
				MarkDomainCache(OriginalRecv, RecvLen);

			return RecvLen;
		}
	}

	return EXIT_FAILURE;
}

#if defined(ENABLE_PCAP)
//Mark socket information to global list
void MarkPortToList(
	const uint16_t Protocol, 
	const SOCKET_DATA *LocalSocketData, 
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
			if (SocketDataIter.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				SocketDataTemp.SockAddr.ss_family = AF_INET6;
				((PSOCKADDR_IN6)&SocketDataTemp.SockAddr)->sin6_port = ((PSOCKADDR_IN6)&SocketDataIter.SockAddr)->sin6_port;
			}
			else if (SocketDataIter.AddrLen == sizeof(sockaddr_in)) //IPv4
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
		if (Protocol == IPPROTO_TCP) //TCP
		{
		#if defined(PLATFORM_WIN_XP)
			OutputPacketListTemp.ClearPortTime = GetTickCount() + Parameter.SocketTimeout_Reliable;
		#elif defined(PLATFORM_WIN)
			OutputPacketListTemp.ClearPortTime = GetTickCount64() + Parameter.SocketTimeout_Reliable;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			OutputPacketListTemp.ClearPortTime = GetCurrentSystemTime() + Parameter.SocketTimeout_Reliable.tv_sec * SECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable.tv_usec / MICROSECOND_TO_MILLISECOND;
		#endif
		}
		else if (Protocol == IPPROTO_UDP) //UDP
		{
		#if defined(PLATFORM_WIN_XP)
			OutputPacketListTemp.ClearPortTime = GetTickCount() + Parameter.SocketTimeout_Unreliable;
		#elif defined(PLATFORM_WIN)
			OutputPacketListTemp.ClearPortTime = GetTickCount64() + Parameter.SocketTimeout_Unreliable;
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			OutputPacketListTemp.ClearPortTime = GetCurrentSystemTime() + Parameter.SocketTimeout_Unreliable.tv_sec * SECOND_TO_MILLISECOND + Parameter.SocketTimeout_Unreliable.tv_usec / MICROSECOND_TO_MILLISECOND;
		#endif
		}
		else {
			return;
		}

	//Clear timeout data.
		std::lock_guard<std::mutex> OutputPacketListMutex(OutputPacketListLock);
	#if defined(PLATFORM_WIN_XP)
		while (!OutputPacketList.empty() && OutputPacketList.front().ClearPortTime <= GetTickCount())
		{
		//Mark timeout.
			if (OutputPacketList.front().ClearPortTime > 0)
			{
				if (OutputPacketList.front().Protocol_Network == AF_INET6) //IPv6
				{
					if (OutputPacketList.front().Protocol_Transport == IPPROTO_TCP) //TCP
						++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV6];
					else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP) //UDP
						++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_UDP_IPV6];
					}
				else if (OutputPacketList.front().Protocol_Network == AF_INET) //IPv4
				{
					if (OutputPacketList.front().Protocol_Transport == IPPROTO_TCP) //TCP
						++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV4];
					else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP) //UDP
						++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_UDP_IPV4];
				}
			}

			OutputPacketList.pop_front();
		}
	#else
		while (!OutputPacketList.empty() && OutputPacketList.front().ClearPortTime <= GetTickCount64())
		{
		//Mark timeout.
			if (OutputPacketList.front().ClearPortTime > 0)
			{
				if (OutputPacketList.front().Protocol_Network == AF_INET6) //IPv6
				{
					if (OutputPacketList.front().Protocol_Transport == IPPROTO_TCP) //TCP
						++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV6];
					else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP) //UDP
						++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_UDP_IPV6];
				}
				else if (OutputPacketList.front().Protocol_Network == AF_INET) //IPv4
				{
					if (OutputPacketList.front().Protocol_Transport == IPPROTO_TCP) //TCP
						++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV4];
					else if (OutputPacketList.front().Protocol_Transport == IPPROTO_UDP) //UDP
						++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_UDP_IPV4];
				}
			}

			OutputPacketList.pop_front();
		}
	#endif

		OutputPacketList.push_back(OutputPacketListTemp);
	}

//Block Port Unreachable messages of system or close the TCP request connections.
	for (auto &SocketDataIter:SocketDataList)
	{
		if (SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
			shutdown(SocketDataIter.Socket, SD_SEND);
	}
#if defined(PLATFORM_WIN)
	if (Protocol == IPPROTO_TCP) //TCP
		Sleep(Parameter.SocketTimeout_Reliable);
	else if (Protocol == IPPROTO_UDP) //UDP
		Sleep(Parameter.SocketTimeout_Unreliable);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (Protocol == IPPROTO_TCP) //TCP
		usleep(Parameter.SocketTimeout_Reliable.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable.tv_usec);
	else if (Protocol == IPPROTO_UDP) //UDP
		usleep(Parameter.SocketTimeout_Unreliable.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Unreliable.tv_usec);
#endif
	for (auto &SocketDataIter:SocketDataList)
	{
		SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		SocketDataIter.Socket = 0;
	}

	return;
}
#endif

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
	auto DNS_Header = (pdns_hdr)Buffer.get();
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
			DNS_Query->Classes = htons(DNS_CLASS_IN);
			if (Protocol == AF_INET6) //IPv6
				DNS_Query->Type = htons(DNS_RECORD_AAAA);
			else if (Protocol == AF_INET) //IPv4
				DNS_Query->Type = htons(DNS_RECORD_A);
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
			if (Protocol == AF_INET6) //IPv6
			{
				if (Parameter.Target_Server_IPv6.HopLimitData.HopLimit == 0 || //Main
					(Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0 && Parameter.Target_Server_Alternate_IPv6.HopLimitData.HopLimit == 0)) //Alternate
						goto JumpToRetest;

			//Other(Multi)
				if (Parameter.Target_Server_IPv6_Multi != nullptr)
				{
					for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
							goto JumpToRetest;
					}
				}
			}
			else if (Protocol == AF_INET) //IPv4
			{
				if (Parameter.Target_Server_IPv4.HopLimitData.TTL == 0 || //Main
					(Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0 && Parameter.Target_Server_Alternate_IPv4.HopLimitData.TTL == 0)) //Alternate
						goto JumpToRetest;

			//Other(Multi)
				if (Parameter.Target_Server_IPv4_Multi != nullptr)
				{
					for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
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

				DNS_Query = (pdns_qry)(Buffer.get() + DataLength);
				DNS_Query->Classes = htons(DNS_CLASS_IN);
				if (Protocol == AF_INET6) //IPv6
					DNS_Query->Type = htons(DNS_RECORD_AAAA);
				else if (Protocol == AF_INET) //IPv4
					DNS_Query->Type = htons(DNS_RECORD_A);
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
			UDPRequestMulti(Buffer.get(), (int)DataLength, nullptr, 0);
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
	if (Protocol == AF_INET6) //IPv6
		Length = sizeof(icmpv6_hdr) + Parameter.ICMP_PaddingLength;
	else if (Protocol == AF_INET) //IPv4
		Length = sizeof(icmp_hdr) + Parameter.ICMP_PaddingLength;
	else 
		return false;
	std::shared_ptr<uint8_t> Buffer(new uint8_t[Length]());
	memset(Buffer.get(), 0, Length);
	auto ICMP_Header = (picmp_hdr)Buffer.get();
	auto ICMPv6_Header = (picmpv6_hdr)Buffer.get();
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
		memcpy_s(Buffer.get() + sizeof(icmpv6_hdr), Parameter.ICMP_PaddingLength, Parameter.ICMP_PaddingData, Parameter.ICMP_PaddingLength);
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

	//Other(Multi)
		if (Parameter.Target_Server_IPv6_Multi != nullptr)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multi)
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
		memcpy_s(Buffer.get() + sizeof(icmp_hdr), Parameter.ICMP_PaddingLength, Parameter.ICMP_PaddingData, Parameter.ICMP_PaddingLength);
	#if defined(PLATFORM_LINUX)
		ICMP_Header->Timestamp = (uint64_t)time(nullptr);
		ICMP_Header->Nonce = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
	#elif defined(PLATFORM_MACX)
		ICMP_Header->Timestamp = (uint64_t)time(nullptr);
	#endif
		ICMP_Header->Checksum = GetChecksum((uint16_t *)Buffer.get(), Length);

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

	//Other(Multi)
		if (Parameter.Target_Server_IPv4_Multi != nullptr)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multi)
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

//Socket timeout setting
	for (auto &SocketDataIter:ICMPSocketData)
	{
		if (!SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TIMEOUT, true, &Parameter.SocketTimeout_Unreliable))
		{
			for (const auto &InnerSocketDataIter:ICMPSocketData)
				SocketSetting(InnerSocketDataIter.Socket, SOCKET_SETTING_CLOSE, false, nullptr);

			return false;
		}
	}

//Send request.
	size_t SleepTime_ICMP = 0, SpeedTime_ICMP = Parameter.ICMP_Speed, Times = 0, Index = 0;
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
			if (Protocol == AF_INET6) //IPv6
			{
				if (Parameter.Target_Server_IPv6.HopLimitData.HopLimit == 0 || //Main
					(Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0 && Parameter.Target_Server_Alternate_IPv6.HopLimitData.HopLimit == 0)) //Alternate
						goto JumpToRetest;

				if (Parameter.Target_Server_IPv6_Multi != nullptr) //Other(Multi)
				{
					for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multi)
					{
						if (DNSServerDataIter.HopLimitData.HopLimit == 0)
							goto JumpToRetest;
					}
				}
			}
			else if (Protocol == AF_INET) //IPv4
			{
				if (Parameter.Target_Server_IPv4.HopLimitData.TTL == 0 || //Main
					(Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0 && Parameter.Target_Server_Alternate_IPv4.HopLimitData.TTL == 0)) //Alternate
						goto JumpToRetest;

				if (Parameter.Target_Server_IPv4_Multi != nullptr) //Other(Multi)
				{
					for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
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

	//Send process
		for (const auto &SocketDataIter:ICMPSocketData)
		{
			for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
				sendto(SocketDataIter.Socket, (const char *)Buffer.get(), (int)Length, 0, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen);

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
					ICMPv6_Header->Nonce = RamdomDistribution(*GlobalRunningStatus.RamdomEngine);
				#elif defined(PLATFORM_MACX)
					ICMPv6_Header->Timestamp = (uint64_t)time(nullptr);
				#endif
				}
				else if (Protocol == AF_INET) //IPv4
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
					ICMP_Header->Checksum = GetChecksum((uint16_t *)Buffer.get(), Length);
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

//Select socket data of DNS target(Independent)
bool SelectTargetSocket(
	const size_t RequestType, 
	SOCKET_DATA *TargetSocketData, 
	bool **IsAlternate, 
	size_t **AlternateTimeoutTimes, 
	const uint16_t Protocol)
{
//Socket initialization
	uint16_t SocketType = 0;
	memset(TargetSocketData, 0, sizeof(SOCKET_DATA));
	if (Protocol == IPPROTO_TCP) //TCP
		SocketType = SOCK_STREAM;
	else if (Protocol == IPPROTO_UDP) //UDP
		SocketType = SOCK_DGRAM;
	else 
		return false;

//Local request
	if (RequestType == REQUEST_PROCESS_LOCAL)
	{
	//IPv6
		if (Parameter.Target_Server_Local_IPv6.Storage.ss_family > 0 && 
			((Parameter.LocalProtocol_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
			Parameter.LocalProtocol_Network == REQUEST_MODE_IPV6 || //IPv6
			(Parameter.LocalProtocol_Network == REQUEST_MODE_IPV4 && Parameter.Target_Server_Local_IPv4.Storage.ss_family == 0))) //Non-IPv4
		{
		//TCP
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_LOCAL_TCP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_LOCAL_TCP_IPV6];
			}
		//UDP
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_LOCAL_UDP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_LOCAL_UDP_IPV6];
			}
			else {
				return false;
			}
		
		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Alternate_Local_IPv6.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = Parameter.Target_Server_Alternate_Local_IPv6.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = Parameter.Target_Server_Alternate_Local_IPv6.IPv6.sin6_port;
			}
		//Main
			else {
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = Parameter.Target_Server_Local_IPv6.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = Parameter.Target_Server_Local_IPv6.IPv6.sin6_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return false;
			}
		}
	//IPv4
		else if (Parameter.Target_Server_Local_IPv4.Storage.ss_family > 0 && 
			((Parameter.LocalProtocol_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
			Parameter.LocalProtocol_Network == REQUEST_MODE_IPV4 || //IPv4
			(Parameter.LocalProtocol_Network == REQUEST_MODE_IPV6 && Parameter.Target_Server_Local_IPv6.Storage.ss_family == 0))) //Non-IPv6
		{
		//TCP
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_LOCAL_TCP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_LOCAL_TCP_IPV4];
			}
		//UDP
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_LOCAL_UDP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_LOCAL_UDP_IPV4];
			}
			else {
				return false;
			}

		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Alternate_Local_IPv4.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = Parameter.Target_Server_Alternate_Local_IPv4.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = Parameter.Target_Server_Alternate_Local_IPv4.IPv4.sin_port;
			}
		//Main
			else {
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = Parameter.Target_Server_Local_IPv4.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = Parameter.Target_Server_Local_IPv4.IPv4.sin_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return false;
			}
		}
		else {
			return false;
		}
	}
//Main request
	else {
	//IPv6
		if (Parameter.Target_Server_IPv6.AddressData.Storage.ss_family > 0 && 
			((Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
			Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
			(Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.Target_Server_IPv4.AddressData.Storage.ss_family == 0))) //Non-IPv4
		{
		//TCP
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_TCP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV6];
			}
		//UDP
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_UDP_IPV6];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_UDP_IPV6];
			}
			else {
				return false;
			}
		
		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = Parameter.Target_Server_Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
		//Main
			else {
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = Parameter.Target_Server_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = Parameter.Target_Server_IPv6.AddressData.IPv6.sin6_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return false;
			}
		}
	//IPv4
		else if (Parameter.Target_Server_IPv4.AddressData.Storage.ss_family > 0 && 
			((Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
			Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
			(Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.Target_Server_IPv6.AddressData.Storage.ss_family == 0))) //Non-IPv6
		{
		//TCP
			if (Protocol == IPPROTO_TCP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_TCP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV4];
			}
		//UDP
			else if (Protocol == IPPROTO_UDP)
			{
				*IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_UDP_IPV4];
				*AlternateTimeoutTimes = &AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_UDP_IPV4];
			}
			else {
				return false;
			}
			
		//Alternate
			if (**IsAlternate && Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = Parameter.Target_Server_Alternate_IPv4.AddressData.IPv4.sin_port;
			}
		//Main
			else {
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = Parameter.Target_Server_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = Parameter.Target_Server_IPv4.AddressData.IPv4.sin_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr) || 
				!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
			{
				SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_CLOSE, false, nullptr);
				TargetSocketData->Socket = 0;

				return false;
			}
		}
		else {
			return false;
		}
	}

	return true;
}

//Select socket data of DNS target(Multithreading)
bool SelectTargetSocketMulti(
	std::vector<SOCKET_DATA> &TargetSocketDataList, 
	const uint16_t Protocol)
{
//Initialization
	SOCKET_DATA TargetSocketData;
	memset(&TargetSocketData, 0, sizeof(TargetSocketData));
	uint16_t SocketType = 0;
	size_t Index = 0;
	bool *IsAlternate = nullptr;
	if (Protocol == IPPROTO_TCP) //TCP
		SocketType = SOCK_STREAM;
	else if (Protocol == IPPROTO_UDP) //UDP
		SocketType = SOCK_DGRAM;
	else 
		return false;

//IPv6
	if (Parameter.Target_Server_IPv6.AddressData.Storage.ss_family > 0 && 
		((Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
		(Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.Target_Server_IPv4.AddressData.Storage.ss_family == 0))) //Non-IPv4
	{
	//Set Alternate swap list.
		if (Protocol == IPPROTO_TCP) //TCP
			IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_TCP_IPV6];
		else if (Protocol == IPPROTO_UDP) //UDP
			IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_UDP_IPV6];
		else 
			return false;

	//Main
		if (!*IsAlternate)
		{
			for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				memset(&TargetSocketData, 0, sizeof(TargetSocketData));
				TargetSocketData.SockAddr = Parameter.Target_Server_IPv6.AddressData.Storage;
				TargetSocketData.Socket = socket(AF_INET6, SocketType, Protocol);

			//Socket check, non-blocking mode setting and Hop Limits setting
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
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
		if (Parameter.Target_Server_Alternate_IPv6.AddressData.Storage.ss_family > 0 && (*IsAlternate || Parameter.AlternateMultiRequest))
		{
			for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				memset(&TargetSocketData, 0, sizeof(TargetSocketData));
				TargetSocketData.SockAddr = Parameter.Target_Server_Alternate_IPv6.AddressData.Storage;
				TargetSocketData.Socket = socket(AF_INET6, SocketType, Protocol);

			//Socket check, non-blocking mode setting and Hop Limits setting
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
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
		if (Parameter.Target_Server_IPv6_Multi != nullptr && !*IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv6_Multi)
			{
				for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
				{
					memset(&TargetSocketData, 0, sizeof(TargetSocketData));
					TargetSocketData.SockAddr = DNSServerDataIter.AddressData.Storage;
					TargetSocketData.Socket = socket(AF_INET6, SocketType, Protocol);

				//Socket check, non-blocking mode setting and Hop Limits setting
					if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
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
	else if (Parameter.Target_Server_IPv4.AddressData.Storage.ss_family > 0 && 
		((Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
		Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
		(Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.Target_Server_IPv6.AddressData.Storage.ss_family == 0))) //Non-IPv6
	{
	//Set Alternate swap list.
		if (Protocol == IPPROTO_TCP) //TCP
			IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_TCP_IPV4];
		else if (Protocol == IPPROTO_UDP) //UDP
			IsAlternate = &AlternateSwapList.IsSwap[ALTERNATE_TYPE_MAIN_UDP_IPV4];
		else 
			return false;

	//Main
		if (!*IsAlternate)
		{
			for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				memset(&TargetSocketData, 0, sizeof(TargetSocketData));
				TargetSocketData.SockAddr = Parameter.Target_Server_IPv4.AddressData.Storage;
				TargetSocketData.Socket = socket(AF_INET, SocketType, Protocol);

			//Socket check, non-blocking mode setting, Hop Limits setting and Do Not Fragment setting
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
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
		if (Parameter.Target_Server_Alternate_IPv4.AddressData.Storage.ss_family > 0 && (*IsAlternate || Parameter.AlternateMultiRequest))
		{
			for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				memset(&TargetSocketData, 0, sizeof(TargetSocketData));
				TargetSocketData.SockAddr = Parameter.Target_Server_Alternate_IPv4.AddressData.Storage;
				TargetSocketData.Socket = socket(AF_INET, SocketType, Protocol);

			//Socket check, non-blocking mode setting, Hop Limits setting and Do Not Fragment setting
				if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
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
		if (Parameter.Target_Server_IPv4_Multi != nullptr && !*IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (const auto &DNSServerDataIter:*Parameter.Target_Server_IPv4_Multi)
			{
				for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
				{
					memset(&TargetSocketData, 0, sizeof(TargetSocketData));
					TargetSocketData.SockAddr = DNSServerDataIter.AddressData.Storage;
					TargetSocketData.Socket = socket(AF_INET, SocketType, Protocol);

				//Socket check, non-blocking mode setting, Hop Limits setting and Do Not Fragment setting
					if (!SocketSetting(TargetSocketData.Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
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

//Transmission and reception of TCP protocol(Independent)
size_t TCPRequest(
	const size_t RequestType, 
	const uint8_t *OriginalSend, 
	const size_t SendSize, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> TCPSocketDataList(1U);
	memset(&TCPSocketDataList.front(), 0, sizeof(TCPSocketDataList.front()));
	memset(OriginalRecv, 0, RecvSize);
	auto SendBuffer = OriginalRecv;
	memcpy_s(SendBuffer, RecvSize, OriginalSend, SendSize);

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	if (!SelectTargetSocket(RequestType, &TCPSocketDataList.front(), &IsAlternate, &AlternateTimeoutTimes, IPPROTO_TCP))
	{
		PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"TCP socket initialization error", 0, nullptr, 0);
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Socket non-blocking mode setting
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
	ssize_t ErrorCode = 0, RecvLen = SocketSelecting(RequestType, IPPROTO_TCP, TCPSocketDataList, SendBuffer, DataLength, OriginalRecv, RecvSize, &ErrorCode);
	if (ErrorCode == WSAETIMEDOUT && IsAlternate != nullptr && !*IsAlternate && //Mark timeout.
		(!Parameter.AlternateMultiRequest || RequestType == REQUEST_PROCESS_LOCAL))
			++(*AlternateTimeoutTimes);
	
	return RecvLen;
}

//Transmission and reception of TCP protocol(Multithreading)
size_t TCPRequestMulti(
	const size_t RequestType, 
	const uint8_t *OriginalSend, 
	const size_t SendSize, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize)
{
//Initialization
	memset(OriginalRecv, 0, RecvSize);
	auto SendBuffer = OriginalRecv;
	memcpy_s(SendBuffer, RecvSize, OriginalSend, SendSize);

//Socket initialization
	std::vector<SOCKET_DATA> TCPSocketDataList;
	if (!SelectTargetSocketMulti(TCPSocketDataList, IPPROTO_TCP))
		return EXIT_FAILURE;

//Add length of request packet(It must be written in header when transport with TCP protocol).
	size_t DataLength = AddLengthDataToHeader(SendBuffer, SendSize, RecvSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket selecting
	ssize_t ErrorCode = 0, RecvLen = SocketSelecting(RequestType, IPPROTO_TCP, TCPSocketDataList, SendBuffer, DataLength, OriginalRecv, RecvSize, &ErrorCode);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultiRequest) //Mark timeout.
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
size_t UDPRequest(
	const uint8_t *OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA *LocalSocketData, 
	const uint16_t Protocol)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	memset(&UDPSocketDataList.front(), 0, sizeof(UDPSocketDataList.front()));
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;

//Socket initialization
	if (!SelectTargetSocket(REQUEST_PROCESS_UDP, &UDPSocketDataList.front(), &IsAlternate, &AlternateTimeoutTimes, IPPROTO_UDP))
	{
		PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"UDP socket initialization error", 0, nullptr, 0);
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Socket non-blocking mode setting
	if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr))
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Socket selecting
	ssize_t RecvLen = SocketSelecting(REQUEST_PROCESS_UDP, IPPROTO_UDP, UDPSocketDataList, OriginalSend, SendSize, nullptr, 0, nullptr);
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

//Transmission of UDP protocol(Multithreading)
size_t UDPRequestMulti(
	const uint8_t *OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA *LocalSocketData, 
	const uint16_t Protocol)
{
//Socket initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	if (!SelectTargetSocketMulti(UDPSocketDataList, IPPROTO_UDP))
		return EXIT_FAILURE;

//Socket selecting
	ssize_t RecvLen = SocketSelecting(REQUEST_PROCESS_UDP, IPPROTO_UDP, UDPSocketDataList, OriginalSend, SendSize, nullptr, 0, nullptr);
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
size_t UDPCompleteRequest(
	const size_t RequestType, 
	const uint8_t *OriginalSend, 
	const size_t SendSize, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	memset(&UDPSocketDataList.front(), 0, sizeof(UDPSocketDataList.front()));
	memset(OriginalRecv, 0, RecvSize);

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	if (!SelectTargetSocket(RequestType, &UDPSocketDataList.front(), &IsAlternate, &AlternateTimeoutTimes, IPPROTO_UDP))
	{
		PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"Complete UDP socket initialization error", 0, nullptr, 0);
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Socket non-blocking mode setting
	if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr))
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Socket selecting
	ssize_t ErrorCode = 0, RecvLen = SocketSelecting(RequestType, IPPROTO_UDP, UDPSocketDataList, OriginalSend, SendSize, OriginalRecv, RecvSize, &ErrorCode);
	if (ErrorCode == WSAETIMEDOUT && IsAlternate != nullptr && !*IsAlternate && //Mark timeout.
		(!Parameter.AlternateMultiRequest || RequestType == REQUEST_PROCESS_LOCAL))
			++(*AlternateTimeoutTimes);

	return RecvLen;
}

//Complete transmission of UDP protocol(Multithreading)
size_t UDPCompleteRequestMulti(
	const size_t RequestType, 
	const uint8_t *OriginalSend, 
	const size_t SendSize, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	memset(OriginalRecv, 0, RecvSize);

//Socket initialization
	if (!SelectTargetSocketMulti(UDPSocketDataList, IPPROTO_UDP))
		return EXIT_FAILURE;

//Socket selecting
	ssize_t ErrorCode = 0, RecvLen = SocketSelecting(RequestType, IPPROTO_UDP, UDPSocketDataList, OriginalSend, SendSize, OriginalRecv, RecvSize, &ErrorCode);
	if (ErrorCode == WSAETIMEDOUT && !Parameter.AlternateMultiRequest) //Mark timeout.
	{
		if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in6)) //IPv6
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV6];
		else if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in)) //IPv4
			++AlternateSwapList.TimeoutTimes[ALTERNATE_TYPE_MAIN_TCP_IPV4];
	}

	return RecvLen;
}
