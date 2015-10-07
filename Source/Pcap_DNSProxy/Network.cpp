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

//Socket option settings
bool __fastcall SocketSetting(
	const SYSTEM_SOCKET Socket, 
	const size_t SettingType, 
	void *DataPointer)
{
	switch (SettingType)
	{
	//Socket check
		case SOCKET_SETTING_INVALID_CHECK:
		{
			if (Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"Socket initialization error", WSAGetLastError(), nullptr, 0);
				return false;
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
				PrintError(LOG_ERROR_NETWORK, L"Socket timeout setting error", WSAGetLastError(), nullptr, 0);
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
				PrintError(LOG_ERROR_NETWORK, L"Socket reusing disable setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		//Set TIME_WAIT resuing(Linux/Mac).
/*			if (setsockopt(Socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Socket reusing enable setting error", errno, nullptr, 0);
				shutdown(Socket, SHUT_RDWR);
				close(Socket);

				return false;
			}
*/
		//Set an IPv6 server socket that cannot accept IPv4 connections on Linux.
			SetVal = 1;
			if (setsockopt(Socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Socket treating wildcard bind setting error", errno, nullptr, 0);
				shutdown(Socket, SHUT_RDWR);
				close(Socket);

				return false;
			}
		#endif
		}break;
	#if defined(PLATFORM_LINUX)
	//Socket TCP Fast Open setting
		case SOCKET_SETTING_TCP_FAST_OPEN:
		{
			int SetVal = TCP_FASTOPEN_HINT;
			if (setsockopt(Socket, SOL_TCP, TCP_FASTOPEN, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Socket TCP Fast Open setting error", errno, nullptr, 0);
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
			ULONG SocketMode = 1U;
			if (ioctlsocket(Socket, FIONBIO, &SocketMode) == SOCKET_ERROR)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			auto SocketMode = fcntl(Socket, F_GETFL, 0);
			if (SocketMode == RETURN_ERROR || fcntl(Socket, F_SETFL, SocketMode|O_NONBLOCK) == RETURN_ERROR)
		#endif
			{
				PrintError(LOG_ERROR_NETWORK, L"Socket non-blocking mode setting error", WSAGetLastError(), nullptr, 0);
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

			tcp_keepalive Alive_IN = {0};
			tcp_keepalive Alive_OUT = {0};
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
	#if defined(PLATFORM_WIN)
	//Socket UDP block RESET message setting
		case SOCKET_SETTING_UDP_BLOCK_RESET:
		{
			DWORD BytesReturned = 0;
			BOOL NewBehavior = FALSE;
			if (WSAIoctl(Socket, SIO_UDP_CONNRESET, &NewBehavior, sizeof(BOOL), nullptr, 0, &BytesReturned, nullptr, nullptr) == SOCKET_ERROR)
			{
				PrintError(LOG_ERROR_NETWORK, L"Socket UDP block RESET message setting error", WSAGetLastError(), nullptr, 0);
				shutdown(Socket, SD_BOTH);
				closesocket(Socket);

				return false;
			}
		}break;
	#endif
	}

	return true;
}

//Connect to server(TCP) or socket connecting(UDP)
size_t __fastcall SocketConnecting(
	const uint16_t Protocol, 
	const SYSTEM_SOCKET Socket, 
	const PSOCKADDR SockAddr, 
	const socklen_t AddrLen, 
	const char *OriginalSend, 
	const size_t SendSize)
{
//TCP connecting
	if (Protocol == IPPROTO_TCP)
	{
		SSIZE_T ErrorCode = 0;

	#if defined(PLATFORM_LINUX)
		if (Parameter.TCP_FastOpen && OriginalSend != nullptr && SendSize >= DNS_PACKET_MINSIZE)
		{
			SSIZE_T RecvLen = sendto(Socket, OriginalSend, (int)SendSize, MSG_FASTOPEN, SockAddr, AddrLen);
			if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
			{
				ErrorCode = WSAGetLastError();
				if (ErrorCode != EAGAIN && ErrorCode != EINPROGRESS)
					return EXIT_FAILURE;
				else 
					return EXIT_SUCCESS;
			}
			else {
				return RecvLen;
			}
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
			PrintError(LOG_ERROR_NETWORK, L"Socket connecting error", WSAGetLastError(), nullptr, 0);
			shutdown(Socket, SD_BOTH);
			closesocket(Socket);

			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}

//Non-blocking mode selecting
SSIZE_T __fastcall SocketSelecting(
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const bool IsLocal, 
	const bool NoCheck)
{
//Initialization(Part 1)
	std::vector<SOCKET_SELECTING_DATA> SocketSelectingList(SocketDataList.size());
	for (auto &SocketSelectingIter:SocketSelectingList)
	{
		SocketSelectingIter.Length = 0;
		SocketSelectingIter.PacketIsSend = false;
	}
	size_t Index = 0;
	SSIZE_T RecvLen = 0;

//TCP or UDP connecting
	for (auto &SocketDataIter:SocketDataList)
	{
		RecvLen = SocketConnecting(Protocol, SocketDataIter.Socket, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen, OriginalSend, SendSize);
		if (RecvLen == EXIT_FAILURE)
		{
			shutdown(SocketDataIter.Socket, SD_BOTH);
			closesocket(SocketDataIter.Socket);
			SocketDataIter.Socket = 0;
		}
	#if defined(PLATFORM_LINUX)
		else if (Protocol == IPPROTO_TCP && Parameter.TCP_FastOpen && RecvLen > (SSIZE_T)DNS_PACKET_MINSIZE)
		{
			SocketSelectingList.at(Index).PacketIsSend = true;
			++Index;
		}
	#endif
	}

//Socket check(Part 1)
	for (auto SocketDataIter = SocketDataList.begin();SocketDataIter != SocketDataList.end();++SocketDataIter)
	{
		if (SocketDataIter->Socket > 0)
			break;
		else if (SocketDataIter + 1U == SocketDataList.end())
			return EXIT_FAILURE;
	}

//Initialization(Part 2)
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));
	SSIZE_T SelectResult = 0;
	size_t LastReceiveIndex = 0;
	SYSTEM_SOCKET MaxSocket = 0;
	auto IsAllSocketClosed = false;

//Socket timeout setting
#if defined(PLATFORM_WIN)
	Timeout->tv_sec = Parameter.SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
	Timeout->tv_usec = Parameter.SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Timeout->tv_sec = Parameter.SocketTimeout_Reliable.tv_sec;
	Timeout->tv_usec = Parameter.SocketTimeout_Reliable.tv_usec;
#endif

//Selecting process
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME_NO_DELAY);

	//Socket check(Part 2)
		for (auto SocketDataIter = SocketDataList.begin();SocketDataIter != SocketDataList.end();++SocketDataIter)
		{
			if (SocketDataIter->Socket > 0)
				break;
			else if (SocketDataIter + 1U == SocketDataList.end())
				IsAllSocketClosed = true;
		}

	//Buffer list check(Part 1)
		if (OriginalRecv != nullptr && (IsAllSocketClosed || Parameter.ReceiveWaiting == 0 || SocketDataList.size() == 1U))
		{
		//Sacn all result.
			RecvLen = SelectingResult(Protocol, SocketDataList, SocketSelectingList, OriginalRecv, RecvSize, IsLocal, NoCheck);
			if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
				return RecvLen;
		//All socket cloesed. 
			else if (IsAllSocketClosed)
				return EXIT_FAILURE;
		}

	//Reset parameters.
		FD_ZERO(ReadFDS.get());
		FD_ZERO(WriteFDS.get());
		MaxSocket = 0;

	//Socket check and non-blocking process setting
		for (Index = 0;Index < SocketDataList.size();++Index)
		{
		//Non-blocking process setting
			if (SocketDataList.at(Index).Socket > 0)
			{
			//Select structure setting
				if (SocketDataList.at(Index).Socket > MaxSocket)
					MaxSocket = SocketDataList.at(Index).Socket;

			//Receive process
				if (OriginalRecv != nullptr)
					FD_SET(SocketDataList.at(Index).Socket, ReadFDS.get());

			//Send process
				if (!SocketSelectingList.at(Index).PacketIsSend)
					FD_SET(SocketDataList.at(Index).Socket, WriteFDS.get());
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
				if (!SocketSelectingList.at(Index).PacketIsSend)
					break;
				else if (Index + 1U == SocketDataList.size())
					return EXIT_SUCCESS;
			}
		}

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(MaxSocket + 1U, ReadFDS.get(), WriteFDS.get(), nullptr, Timeout.get());
	#endif
		if (SelectResult > EXIT_SUCCESS)
		{
			for (Index = 0;Index < SocketDataList.size();++Index)
			{
			//Receive process
				if (FD_ISSET(SocketDataList.at(Index).Socket, ReadFDS.get()) && OriginalRecv != nullptr)
				{
				//Buffer initialization
					if (!SocketSelectingList.at(Index).RecvBuffer)
					{
						std::shared_ptr<char> RecvBufferTemp(new char[RecvSize]());
						memset(RecvBufferTemp.get(), 0, RecvSize);
						SocketSelectingList.at(Index).RecvBuffer.swap(RecvBufferTemp);
					}

				//Receive from selecting.
					RecvLen = recv(SocketDataList.at(Index).Socket, SocketSelectingList.at(Index).RecvBuffer.get() + SocketSelectingList.at(Index).Length, (int)(RecvSize - SocketSelectingList.at(Index).Length), 0);

				//Connection closed or SOCKET_ERROR
					if (RecvLen <= 0)
					{
						shutdown(SocketDataList.at(Index).Socket, SD_BOTH);
						closesocket(SocketDataList.at(Index).Socket);
						SocketDataList.at(Index).Socket = 0;
						SocketSelectingList.at(Index).RecvBuffer.reset();
						SocketSelectingList.at(Index).Length = 0;
						continue;
					}
					else if (Protocol == IPPROTO_UDP && RecvLen > (SSIZE_T)DNS_PACKET_MINSIZE && SocketSelectingList.at(Index).Length > 0)
					{
						memset(SocketSelectingList.at(Index).RecvBuffer.get(), 0, SocketSelectingList.at(Index).Length);
						memmove_s(SocketSelectingList.at(Index).RecvBuffer.get(), RecvSize, SocketSelectingList.at(Index).RecvBuffer.get() + SocketSelectingList.at(Index).Length, RecvLen);
						SocketSelectingList.at(Index).Length = 0;
					}

				//Whole packet length
					SocketSelectingList.at(Index).Length += RecvLen;

				//Mark last packet.
					LastReceiveIndex = Index;
				}

			//Send process
				if (FD_ISSET(SocketDataList.at(Index).Socket, WriteFDS.get()) && !SocketSelectingList.at(Index).PacketIsSend)
				{
					if (send(SocketDataList.at(Index).Socket, OriginalSend, (int)SendSize, 0) <= EXIT_SUCCESS)
					{
						shutdown(SocketDataList.at(Index).Socket, SD_BOTH);
						closesocket(SocketDataList.at(Index).Socket);
						SocketDataList.at(Index).Socket = 0;
						SocketSelectingList.at(Index).RecvBuffer.reset();
						SocketSelectingList.at(Index).Length = 0;
					}
					else {
						SocketSelectingList.at(Index).PacketIsSend = true;
					}
				}
			}
		}
	//Timeout
		else if (SelectResult == EXIT_SUCCESS)
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
				RecvLen = SelectingResult(Protocol, SocketDataList, SocketSelectingList, OriginalRecv, RecvSize, IsLocal, NoCheck);
				if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
					return RecvLen;
			}

		//Close all sockets.
			for (auto &SocketDataIter:SocketDataList)
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
	for (auto &SocketDataIter:SocketDataList)
	{
		if (SocketDataIter.Socket > 0)
		{
			shutdown(SocketDataIter.Socket, SD_BOTH);
			closesocket(SocketDataIter.Socket);
		}
	}

	return EXIT_FAILURE;
}

//Socket selecting result
SSIZE_T __fastcall SelectingResult(
	uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_DATA> &SocketSelectingList, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const bool IsLocal, 
	const bool NoCheck)
{
	SSIZE_T RecvLen = 0;

//Scan all buffer.
	for (size_t Index = 0;Index < SocketDataList.size();++Index)
	{
		if (SocketSelectingList.at(Index).RecvBuffer && SocketSelectingList.at(Index).Length >= DNS_PACKET_MINSIZE)
		{
		//TCP header length check
			if (Protocol == IPPROTO_TCP)
			{
				RecvLen = ntohs(((PUINT16)SocketSelectingList.at(Index).RecvBuffer.get())[0]);
				if (RecvLen >(SSIZE_T)SocketSelectingList.at(Index).Length)
				{
					shutdown(SocketDataList.at(Index).Socket, SD_BOTH);
					closesocket(SocketDataList.at(Index).Socket);
					SocketDataList.at(Index).Socket = 0;
					SocketSelectingList.at(Index).RecvBuffer.reset();
					SocketSelectingList.at(Index).Length = 0;
					continue;
				}
				else {
					memmove_s(SocketSelectingList.at(Index).RecvBuffer.get(), RecvSize, SocketSelectingList.at(Index).RecvBuffer.get() + sizeof(uint16_t), RecvLen);
					memset(SocketSelectingList.at(Index).RecvBuffer.get() + RecvLen, 0, (size_t)((RecvSize - RecvLen)));
				}
			}
		//UDP length
			else {
				RecvLen = SocketSelectingList.at(Index).Length;
			}

		//Receive from buffer list.
			if (!NoCheck && (Parameter.HeaderCheck_DNS || Parameter.DataCheck_Blacklist))
				RecvLen = CheckResponseData(SocketSelectingList.at(Index).RecvBuffer.get(), RecvLen, IsLocal, nullptr);
			if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
			{
				shutdown(SocketDataList.at(Index).Socket, SD_BOTH);
				closesocket(SocketDataList.at(Index).Socket);
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
	}

	return EXIT_FAILURE;
}

#if defined(ENABLE_PCAP)
//Mark socket information to global list
void __fastcall MarkPortToList(
	const uint16_t Protocol, 
	const SOCKET_DATA *LocalSocketData, 
	std::vector<SOCKET_DATA> &SocketDataList)
{
	if (LocalSocketData != nullptr && Protocol > 0)
	{
		std::shared_ptr<SOCKET_DATA> SocketDataTemp(new SOCKET_DATA());
		std::shared_ptr<OUTPUT_PACKET_TABLE> OutputPacketListTemp(new OUTPUT_PACKET_TABLE());
		memset(OutputPacketListTemp.get(), 0, sizeof(OUTPUT_PACKET_TABLE));

	//Mark system connection data.
		OutputPacketListTemp->SocketData_Input = *LocalSocketData;

	//Mark sending connection data.
		for (auto &SocketDataIter:SocketDataList)
		{
			if (SocketDataIter.Socket == 0)
				continue;
			memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));

		//Get socket information.
			if (getsockname(SocketDataIter.Socket, (PSOCKADDR)&SocketDataIter.SockAddr, &SocketDataIter.AddrLen) != EXIT_SUCCESS)
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
			if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr)
				OutputPacketListTemp->ClearPortTime = (size_t)((*GlobalRunningStatus.FunctionPTR_GetTickCount64)() + Parameter.SocketTimeout_Reliable);
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
			if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr)
				OutputPacketListTemp->ClearPortTime = (size_t)((*GlobalRunningStatus.FunctionPTR_GetTickCount64)() + Parameter.SocketTimeout_Unreliable);
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

//Block Port Unreachable messages of system or close the TCP request connections.
	for (auto &SocketDataIter:SocketDataList)
	{
		if (SocketDataIter.Socket > 0)
			shutdown(SocketDataIter.Socket, SD_SEND);
	}
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
	for (auto &SocketDataIter:SocketDataList)
	{
		if (SocketDataIter.Socket > 0)
		{
			shutdown(SocketDataIter.Socket, SD_BOTH);
			closesocket(SocketDataIter.Socket);
		}
	}

	return;
}
#endif

#if defined(ENABLE_PCAP)
//Get TTL(IPv4)/Hop Limits(IPv6) with normal DNS request
bool __fastcall DomainTestRequest(
	const uint16_t Protocol)
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
			if (Parameter.EDNS_Label)
			{
				DataLength = AddEDNSLabelToAdditionalRR(Buffer.get(), DataLength + sizeof(dns_hdr), PACKET_MAXSIZE, false);
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
	//Sleep time controller
		if (SleepTime_DomainTest > 0)
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
				if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0 || //Main
					Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0) //Alternate
						goto JumpToRetest;

			//Other(Multi)
				if (Parameter.DNSTarget.IPv6_Multi != nullptr)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
							goto JumpToRetest;
					}
				}
			}
			else { //IPv4
				if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0 || //Main
					Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0) //Alternate
						goto JumpToRetest;

			//Other(Multi)
				if (Parameter.DNSTarget.IPv4_Multi != nullptr)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
							goto JumpToRetest;
					}
				}
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
				else //IPv4
					DNS_Query->Type = htons(DNS_RECORD_A);
				DataLength += sizeof(dns_qry);

			//EDNS Label
				if (Parameter.EDNS_Label)
				{
					DNS_Header->Additional = 0;
					DataLength = AddEDNSLabelToAdditionalRR(Buffer.get(), DataLength, PACKET_MAXSIZE, false);
				}
			}

		//Send process
			UDPRequestMulti(Buffer.get(), (int)DataLength, nullptr, 0);
			Sleep(SENDING_INTERVAL_TIME);
			++Times;
		}
	}

//Monitor terminated
	PrintError(LOG_ERROR_SYSTEM, L"Domain Test module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Internet Control Message Protocol(version 6)/ICMP(v6) Echo(Ping) request
bool __fastcall ICMPTestRequest(
	const uint16_t Protocol)
{
//Initialization
	size_t Length = 0;
	if (Protocol == AF_INET6) //IPv6
		Length = sizeof(icmpv6_hdr) + Parameter.ICMP_PaddingLength;
	else 
		Length = sizeof(icmp_hdr) + Parameter.ICMP_PaddingLength;
	std::shared_ptr<char> Buffer(new char[Length]());
	memset(Buffer.get(), 0, Length);
	auto ICMP_Header = (picmp_hdr)Buffer.get();
	auto ICMPv6_Header = (picmpv6_hdr)Buffer.get();
	std::vector<SOCKET_DATA> ICMPSocketData;
	std::uniform_int_distribution<uint32_t> RamdomDistribution(0, UINT32_MAX);

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
		std::shared_ptr<SOCKET_DATA> SocketDataTemp(new SOCKET_DATA());
		memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));
		
	//Main
	#if defined(PLATFORM_WIN)
		SocketDataTemp->Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SocketDataTemp->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
	#endif
		if (!SocketSetting(SocketDataTemp->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
		{
			return false;
		}
		else {
			SocketDataTemp->SockAddr.ss_family = Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family;
			((PSOCKADDR_IN6)&SocketDataTemp->SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
			SocketDataTemp->AddrLen = sizeof(sockaddr_in6);
			ICMPSocketData.push_back(*SocketDataTemp);
			memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0)
		{
		#if defined(PLATFORM_WIN)
			SocketDataTemp->Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			SocketDataTemp->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
		#endif
			if (!SocketSetting(SocketDataTemp->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
			{
				for (auto SocketDataIter:ICMPSocketData)
					closesocket(SocketDataIter.Socket);

				return false;
			}
			else {
				SocketDataTemp->SockAddr.ss_family = Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family;
				((PSOCKADDR_IN6)&SocketDataTemp->SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				SocketDataTemp->AddrLen = sizeof(sockaddr_in6);
				ICMPSocketData.push_back(*SocketDataTemp);
				memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Other(Multi)
		if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
			#if defined(PLATFORM_WIN)
				SocketDataTemp->Socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				SocketDataTemp->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
			#endif
				if (!SocketSetting(SocketDataTemp->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
				{
					for (auto SocketDataIter:ICMPSocketData)
						closesocket(SocketDataIter.Socket);

					return false;
				}
				else {
					SocketDataTemp->SockAddr.ss_family = DNSServerDataIter.AddressData.Storage.ss_family;
					((PSOCKADDR_IN6)&SocketDataTemp->SockAddr)->sin6_addr = DNSServerDataIter.AddressData.IPv6.sin6_addr;
					SocketDataTemp->AddrLen = sizeof(sockaddr_in6);
					ICMPSocketData.push_back(*SocketDataTemp);
					memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));
				}
			}
		}
	}
//ICMP
	else {
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
		ICMP_Header->Checksum = GetChecksum((PUINT16)Buffer.get(), Length);

	//Socket initialization
		std::shared_ptr<SOCKET_DATA> SocketDataTemp(new SOCKET_DATA());
		memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));

	//Main
		SocketDataTemp->Socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (!SocketSetting(SocketDataTemp->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
		{
			return false;
		}
		else {
			SocketDataTemp->SockAddr.ss_family = Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family;
			((PSOCKADDR_IN)&SocketDataTemp->SockAddr)->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
			SocketDataTemp->AddrLen = sizeof(sockaddr_in);
			ICMPSocketData.push_back(*SocketDataTemp);
			memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
		{
			SocketDataTemp->Socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
			if (!SocketSetting(SocketDataTemp->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
			{
				for (auto SocketDataIter:ICMPSocketData)
					closesocket(SocketDataIter.Socket);

				return false;
			}
			else {
				SocketDataTemp->SockAddr.ss_family = Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family;
				((PSOCKADDR_IN)&SocketDataTemp->SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				SocketDataTemp->AddrLen = sizeof(sockaddr_in);
				ICMPSocketData.push_back(*SocketDataTemp);
				memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Other(Multi)
		if (Parameter.DNSTarget.IPv4_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				SocketDataTemp->Socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
				if (!SocketSetting(SocketDataTemp->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
				{
					for (auto SocketDataIter:ICMPSocketData)
						closesocket(SocketDataIter.Socket);

					return false;
				}
				else {
					SocketDataTemp->SockAddr.ss_family = DNSServerDataIter.AddressData.Storage.ss_family;
					((PSOCKADDR_IN)&SocketDataTemp->SockAddr)->sin_addr = DNSServerDataIter.AddressData.IPv4.sin_addr;
					SocketDataTemp->AddrLen = sizeof(sockaddr_in);
					ICMPSocketData.push_back(*SocketDataTemp);
					memset(SocketDataTemp.get(), 0, sizeof(SOCKET_DATA));
				}
			}
		}
	}

//Socket timeout setting
	for (auto SocketDataIter:ICMPSocketData)
	{
		if (!SocketSetting(SocketDataIter.Socket, SOCKET_SETTING_TIMEOUT, &Parameter.SocketTimeout_Unreliable))
		{
			for (auto InnerSocketDataIter:ICMPSocketData)
				closesocket(InnerSocketDataIter.Socket);

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
				if (Parameter.DNSTarget.IPv6.HopLimitData.HopLimit == 0 || //Main
					Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv6.HopLimitData.HopLimit == 0) //Alternate
						goto JumpToRetest;

				if (Parameter.DNSTarget.IPv6_Multi != nullptr) //Other(Multi)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
					{
						if (DNSServerDataIter.HopLimitData.HopLimit == 0)
							goto JumpToRetest;
					}
				}
			}
			else { //IPv4
				if (Parameter.DNSTarget.IPv4.HopLimitData.TTL == 0 || //Main
					Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && Parameter.DNSTarget.Alternate_IPv4.HopLimitData.TTL == 0) //Alternate
						goto JumpToRetest;

				if (Parameter.DNSTarget.IPv4_Multi != nullptr) //Other(Multi)
				{
					for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
					{
						if (DNSServerDataIter.HopLimitData.TTL == 0)
							goto JumpToRetest;
					}
				}
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
		for (auto SocketDataIter:ICMPSocketData)
		{
			for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
				sendto(SocketDataIter.Socket, Buffer.get(), (int)Length, 0, (PSOCKADDR)&SocketDataIter.SockAddr, SocketDataIter.AddrLen);

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
				else { //IPv4
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
					ICMP_Header->Checksum = GetChecksum((PUINT16)Buffer.get(), Length);
				}
			}
		}

	//Repeat.
		Sleep(SENDING_INTERVAL_TIME);
		++Times;
	}

//Monitor terminated
	for (auto SocketDataIter:ICMPSocketData)
	{
		shutdown(SocketDataIter.Socket, SD_BOTH);
		closesocket(SocketDataIter.Socket);
	}

	PrintError(LOG_ERROR_SYSTEM, L"ICMP Test module Monitor terminated", 0, nullptr, 0);
	return true;
}
#endif

//Select socket data of DNS target(Independent)
bool __fastcall SelectTargetSocket(
	SOCKET_DATA *TargetSocketData, 
	bool *&IsAlternate, 
	size_t *&AlternateTimeoutTimes, 
	const uint16_t Protocol, 
	const bool IsLocal)
{
//Socket initialization
	uint16_t SocketType = 0;
	if (Protocol == IPPROTO_TCP) //TCP
		SocketType = SOCK_STREAM;
	else //UDP
		SocketType = SOCK_DGRAM;

//Local request
	if (IsLocal)
	{
	//IPv6
		if (Parameter.DNSTarget.Local_IPv6.Storage.ss_family > 0 && 
			(Parameter.LocalProtocol_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6 || //Auto select
			Parameter.LocalProtocol_Network == REQUEST_MODE_IPV6 || //IPv6
			Parameter.LocalProtocol_Network == REQUEST_MODE_IPV4 && Parameter.DNSTarget.Local_IPv4.Storage.ss_family == 0)) //Non-IPv4
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
			if (IsAlternate != nullptr && *IsAlternate && Parameter.DNSTarget.Alternate_Local_IPv6.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_Local_IPv6.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = Parameter.DNSTarget.Alternate_Local_IPv6.IPv6.sin6_port;
			}
		//Main
			else {
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = Parameter.DNSTarget.Local_IPv6.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = Parameter.DNSTarget.Local_IPv6.IPv6.sin6_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
		}
	//IPv4
		else if (Parameter.DNSTarget.Local_IPv4.Storage.ss_family > 0 && 
			(Parameter.LocalProtocol_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4 || //Auto select
			Parameter.LocalProtocol_Network == REQUEST_MODE_IPV4 || //IPv4
			Parameter.LocalProtocol_Network == REQUEST_MODE_IPV6 && Parameter.DNSTarget.Local_IPv6.Storage.ss_family == 0)) //Non-IPv6
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
			if (IsAlternate != nullptr && *IsAlternate && Parameter.DNSTarget.Alternate_Local_IPv4.Storage.ss_family > 0)
			{
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_Local_IPv4.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = Parameter.DNSTarget.Alternate_Local_IPv4.IPv4.sin_port;
			}
		//Main
			else {
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = Parameter.DNSTarget.Local_IPv4.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = Parameter.DNSTarget.Local_IPv4.IPv4.sin_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
		}
		else {
			return false;
		}
	}
//Main request
	else {
	//IPv6
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6 || //Auto select
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
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_port;
			}
		//Main
			else {
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_addr = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr;
				((PSOCKADDR_IN6)&TargetSocketData->SockAddr)->sin6_port = Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET6;
			TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);
			TargetSocketData->AddrLen = sizeof(sockaddr_in6);
		}
	//IPv4
		else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4 || //Auto select
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
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_port;
			}
		//Main
			else {
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_addr = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr;
				((PSOCKADDR_IN)&TargetSocketData->SockAddr)->sin_port = Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_port;
			}

			TargetSocketData->SockAddr.ss_family = AF_INET;
			TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);
			TargetSocketData->AddrLen = sizeof(sockaddr_in);
		}
		else {
			return false;
		}
	}

	return true;
}

//Select socket data of DNS target(Multithreading)
bool __fastcall SelectTargetSocketMulti(
	std::vector<SOCKET_DATA> &TargetSocketDataList, 
	const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<SOCKET_DATA> TargetSocketData(new SOCKET_DATA());
	memset(TargetSocketData.get(), 0, sizeof(SOCKET_DATA));
	uint16_t SocketType = 0;
	size_t Index = 0;
	bool *IsAlternate = nullptr;
	if (Protocol == IPPROTO_TCP) //TCP
		SocketType = SOCK_STREAM;
	else //UDP
		SocketType = SOCK_DGRAM;

//IPv6
	if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && 
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6 || //Auto select
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
			for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				TargetSocketData->SockAddr = Parameter.DNSTarget.IPv6.AddressData.Storage;
				TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);

			//Socket check and non-blocking mode setting
				if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr) || 
					!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
				{
					for (auto &SocketDataIter:TargetSocketDataList)
						closesocket(SocketDataIter.Socket);

					return false;
				}

				TargetSocketData->AddrLen = sizeof(sockaddr_in6);
				TargetSocketDataList.push_back(*TargetSocketData);
				memset(TargetSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && (*IsAlternate || Parameter.AlternateMultiRequest))
		{
			for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				TargetSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage;
				TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);

			//Socket check and non-blocking mode setting
				if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr) || 
					!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
				{
					for (auto &SocketDataIter:TargetSocketDataList)
						closesocket(SocketDataIter.Socket);

					return false;
				}

				TargetSocketData->AddrLen = sizeof(sockaddr_in6);
				TargetSocketDataList.push_back(*TargetSocketData);
				memset(TargetSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Other servers
		if (Parameter.DNSTarget.IPv6_Multi != nullptr && !*IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
				{
					TargetSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
					TargetSocketData->Socket = socket(AF_INET6, SocketType, Protocol);

				//Socket check and non-blocking mode setting
					if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr) || 
						!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
					{
						for (auto &SocketDataIter:TargetSocketDataList)
							closesocket(SocketDataIter.Socket);

						return false;
					}

					TargetSocketData->AddrLen = sizeof(sockaddr_in6);
					TargetSocketDataList.push_back(*TargetSocketData);
					memset(TargetSocketData.get(), 0, sizeof(SOCKET_DATA));
				}
			}
		}
	}
//IPv4
	else if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && 
		(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4 || //Auto select
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
			for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				TargetSocketData->SockAddr = Parameter.DNSTarget.IPv4.AddressData.Storage;
				TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);

			//Socket check and non-blocking mode setting
				if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr) || 
					!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
				{
					for (auto &SocketDataIter:TargetSocketDataList)
						closesocket(SocketDataIter.Socket);

					return false;
				}

				TargetSocketData->AddrLen = sizeof(sockaddr_in);
				TargetSocketDataList.push_back(*TargetSocketData);
				memset(TargetSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Alternate
		if (Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && (*IsAlternate || Parameter.AlternateMultiRequest))
		{
			for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
			{
				TargetSocketData->SockAddr = Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage;
				TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);

			//Socket check and non-blocking mode setting
				if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr) || 
					!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
				{
					for (auto &SocketDataIter:TargetSocketDataList)
						closesocket(SocketDataIter.Socket);

					return false;
				}

				TargetSocketData->AddrLen = sizeof(sockaddr_in);
				TargetSocketDataList.push_back(*TargetSocketData);
				memset(TargetSocketData.get(), 0, sizeof(SOCKET_DATA));
			}
		}

	//Other servers
		if (Parameter.DNSTarget.IPv4_Multi != nullptr && !*IsAlternate && Parameter.AlternateMultiRequest)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				for (Index = 0;Index < Parameter.MultiRequestTimes;++Index)
				{
					TargetSocketData->SockAddr = DNSServerDataIter.AddressData.Storage;
					TargetSocketData->Socket = socket(AF_INET, SocketType, Protocol);

				//Socket check and non-blocking mode setting
					if (!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr) || 
						!SocketSetting(TargetSocketData->Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
					{
						for (auto &SocketDataIter:TargetSocketDataList)
							closesocket(SocketDataIter.Socket);

						return false;
					}

					TargetSocketData->AddrLen = sizeof(sockaddr_in);
					TargetSocketDataList.push_back(*TargetSocketData);
					memset(TargetSocketData.get(), 0, sizeof(SOCKET_DATA));
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
size_t __fastcall TCPRequest(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const bool IsLocal)
{
//Initialization
	std::vector<SOCKET_DATA> TCPSocketDataList(1U);
	memset(&TCPSocketDataList.front(), 0, sizeof(SOCKET_DATA));
	memset(OriginalRecv, 0, RecvSize);
	auto SendBuffer = OriginalRecv;
	memcpy_s(SendBuffer, RecvSize, OriginalSend, SendSize);

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	if (!SelectTargetSocket(&TCPSocketDataList.front(), IsAlternate, AlternateTimeoutTimes, IPPROTO_TCP, IsLocal) || TCPSocketDataList.front().Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"TCP socket initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(TCPSocketDataList.front().Socket);

		return EXIT_FAILURE;
	}

//Socket non-blocking mode setting
	if (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
		return EXIT_FAILURE;

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	size_t DataLength = AddLengthDataToHeader(SendBuffer, SendSize, RecvSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket selecting
	SSIZE_T RecvLen = SocketSelecting(IPPROTO_TCP, TCPSocketDataList, SendBuffer, DataLength, OriginalRecv, RecvSize, IsLocal, false);
	if (RecvLen == WSAETIMEDOUT && !Parameter.AlternateMultiRequest && IsAlternate != nullptr && !*IsAlternate) //Mark timeout.
		++(*AlternateTimeoutTimes);
	
	return RecvLen;
}

//Transmission and reception of TCP protocol(Multithreading)
size_t __fastcall TCPRequestMulti(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
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

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	size_t DataLength = AddLengthDataToHeader(SendBuffer, SendSize, RecvSize);
	if (DataLength == EXIT_FAILURE)
		return EXIT_FAILURE;

//Socket selecting
	SSIZE_T RecvLen = SocketSelecting(IPPROTO_TCP, TCPSocketDataList, SendBuffer, DataLength, OriginalRecv, RecvSize, false, false);
	if (RecvLen == WSAETIMEDOUT && !Parameter.AlternateMultiRequest) //Mark timeout.
	{
		if (TCPSocketDataList.front().AddrLen == sizeof(sockaddr_in6)) //IPv6
			++AlternateSwapList.TimeoutTimes[0];
		else //IPv4
			++AlternateSwapList.TimeoutTimes[1U];
	}

	return RecvLen;
}

//Transmission of UDP protocol
#if defined(ENABLE_PCAP)
size_t __fastcall UDPRequest(
	const char *OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA *LocalSocketData, 
	const uint16_t Protocol)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	memset(&UDPSocketDataList.front(), 0, sizeof(SOCKET_DATA));
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;

//Socket initialization
	if (!SelectTargetSocket(&UDPSocketDataList.front(), IsAlternate, AlternateTimeoutTimes, IPPROTO_UDP, false) || UDPSocketDataList.front().Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"UDP socket initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocketDataList.front().Socket);

		return EXIT_FAILURE;
	}

//Socket non-blocking mode setting
	if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
		return EXIT_FAILURE;

//Socket selecting
	SSIZE_T RecvLen = SocketSelecting(IPPROTO_UDP, UDPSocketDataList, OriginalSend, SendSize, nullptr, 0, false, false);
	if (RecvLen != EXIT_SUCCESS)
	{
		for (auto &SocketDataIter:UDPSocketDataList)
		{
			shutdown(SocketDataIter.Socket, SD_BOTH);
			closesocket(SocketDataIter.Socket);
		}

		return EXIT_FAILURE;
	}

//Mark port to list.
	MarkPortToList(Protocol, LocalSocketData, UDPSocketDataList);
	return EXIT_SUCCESS;
}

//Transmission of UDP protocol(Multithreading)
size_t __fastcall UDPRequestMulti(
	const char *OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA *LocalSocketData, 
	const uint16_t Protocol)
{
//Socket initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	if (!SelectTargetSocketMulti(UDPSocketDataList, IPPROTO_UDP))
		return EXIT_FAILURE;

//Socket selecting
	SSIZE_T RecvLen = SocketSelecting(IPPROTO_UDP, UDPSocketDataList, OriginalSend, SendSize, nullptr, 0, false, false);
	if (RecvLen != EXIT_SUCCESS)
	{
		for (auto &SocketDataIter:UDPSocketDataList)
		{
			shutdown(SocketDataIter.Socket, SD_BOTH);
			closesocket(SocketDataIter.Socket);
		}

		return EXIT_FAILURE;
	}

//Mark port to list.
	MarkPortToList(Protocol, LocalSocketData, UDPSocketDataList);
	return EXIT_SUCCESS;
}
#endif

//Complete transmission of UDP protocol
size_t __fastcall UDPCompleteRequest(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const bool IsLocal)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList(1U);
	memset(&UDPSocketDataList.front(), 0, sizeof(SOCKET_DATA));
	memset(OriginalRecv, 0, RecvSize);

//Socket initialization
	bool *IsAlternate = nullptr;
	size_t *AlternateTimeoutTimes = nullptr;
	if (!SelectTargetSocket(&UDPSocketDataList.front(), IsAlternate, AlternateTimeoutTimes, IPPROTO_UDP, IsLocal) || UDPSocketDataList.front().Socket == INVALID_SOCKET)
	{
		PrintError(LOG_ERROR_NETWORK, L"Complete UDP socket initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(UDPSocketDataList.front().Socket);

		return EXIT_FAILURE;
	}

//Socket non-blocking mode setting
	if (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
		return EXIT_FAILURE;

//Socket selecting
	SSIZE_T RecvLen = SocketSelecting(IPPROTO_UDP, UDPSocketDataList, OriginalSend, SendSize, OriginalRecv, RecvSize, IsLocal, false);
	if (RecvLen == WSAETIMEDOUT && !Parameter.AlternateMultiRequest && IsAlternate != nullptr && !*IsAlternate) //Mark timeout.
		++(*AlternateTimeoutTimes);

	return RecvLen;
}

//Complete transmission of UDP protocol(Multithreading)
size_t __fastcall UDPCompleteRequestMulti(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> UDPSocketDataList;
	memset(OriginalRecv, 0, RecvSize);

//Socket initialization
	if (!SelectTargetSocketMulti(UDPSocketDataList, IPPROTO_UDP))
		return EXIT_FAILURE;

//Socket selecting
	SSIZE_T RecvLen = SocketSelecting(IPPROTO_UDP, UDPSocketDataList, OriginalSend, SendSize, OriginalRecv, RecvSize, false, false);
	if (RecvLen == WSAETIMEDOUT && !Parameter.AlternateMultiRequest) //Mark timeout.
	{
		if (UDPSocketDataList.front().AddrLen == sizeof(sockaddr_in6)) //IPv6
			++AlternateSwapList.TimeoutTimes[0];
		else //IPv4
			++AlternateSwapList.TimeoutTimes[1U];
	}

	return RecvLen;
}
