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


#include "Monitor.h"

//Local DNS server initialization
bool __fastcall MonitorInit(
	void)
{
//Capture initialization
#if defined(ENABLE_PCAP)
	if (Parameter.PcapCapture && 
	//Direct Request mode
		!(Parameter.DirectRequest == DIRECT_REQUEST_MODE_BOTH || 
		Parameter.DirectRequest == DIRECT_REQUEST_MODE_IPV6 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0 && 
		Parameter.DirectRequest == DIRECT_REQUEST_MODE_IPV4 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0) && 
	//SOCKS request only mode
		!(Parameter.SOCKS && Parameter.SOCKS_Only)
	//DNSCurve request only mode
	#if defined(ENABLE_LIBSODIUM)
		&& !(Parameter.DNSCurve && DNSCurveParameter.IsEncryptionOnly)
	#endif
		)
	{
	#if defined(ENABLE_PCAP)
		std::thread CaptureInitializationThread(CaptureInit);
		CaptureInitializationThread.detach();
	#endif

	//Get Hop Limits/TTL with normal DNS request.
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
			Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0)) //Non-IPv4
		{
			std::thread IPv6TestDoaminThread(DomainTestRequest, AF_INET6);
			IPv6TestDoaminThread.detach();
		}

		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
			Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0)) //Non-IPv6
		{
			std::thread IPv4TestDoaminThread(DomainTestRequest, AF_INET);
			IPv4TestDoaminThread.detach();
		}

	//Get Hop Limits/TTL with ICMP Echo.
	//ICMPv6
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
			Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0)) //Non-IPv4
		{
			std::thread ICMPv6Thread(ICMPTestRequest, AF_INET6);
			ICMPv6Thread.detach();
		}

	//ICMP
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
			Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0)) //Non-IPv6
		{
			std::thread ICMPThread(ICMPTestRequest, AF_INET);
			ICMPThread.detach();
		}
	}
#endif

//Set Preferred DNS servers switcher.
	if (!Parameter.AlternateMultiRequest && 
		(Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0
	#if defined(ENABLE_LIBSODIUM)
		|| DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 || DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0
	#endif
		) || Parameter.DNSTarget.Alternate_Local_IPv6.Storage.ss_family > 0 || Parameter.DNSTarget.Alternate_Local_IPv4.Storage.ss_family > 0)
	{
		std::thread AlternateServerMonitorThread(AlternateServerMonitor);
		AlternateServerMonitorThread.detach();
	}

//Initialization
	std::shared_ptr<SOCKET_DATA> LocalSocketData(new SOCKET_DATA());
	memset(LocalSocketData.get(), 0, sizeof(SOCKET_DATA));
	std::vector<std::thread> MonitorThread((Parameter.ListenPort->size() + 1U) * TRANSPORT_LAYER_PARTNUM);
	size_t MonitorThreadIndex = 0;

//Set localhost Monitor sockets(IPv6/UDP).
	if (Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_NETWORK_BOTH || Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_IPV6)
	{
		if (Parameter.ListenProtocol_Transport == LISTEN_PROTOCOL_TRANSPORT_BOTH || Parameter.ListenProtocol_Transport == LISTEN_PROTOCOL_UDP)
		{
			LocalSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			if (LocalSocketData->Socket == INVALID_SOCKET)
			{
				if (WSAGetLastError() != 0 && WSAGetLastError() != WSAEAFNOSUPPORT)
					PrintError(LOG_ERROR_NETWORK, L"IPv6 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
			}
			else {
				GlobalRunningStatus.LocalListeningSocket->push_back(LocalSocketData->Socket);
				LocalSocketData->SockAddr.ss_family = AF_INET6;
				LocalSocketData->AddrLen = sizeof(sockaddr_in6);

			//Listen Address available(IPv6)
				if (Parameter.ListenAddress_IPv6 != nullptr)
				{
					for (auto ListenAddressIter:*Parameter.ListenAddress_IPv6)
					{
						if (LocalSocketData->Socket == 0)
						{
							LocalSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
							if (!SocketSetting(LocalSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
								break;

							GlobalRunningStatus.LocalListeningSocket->push_back(LocalSocketData->Socket);
						}

						((PSOCKADDR_IN6)&LocalSocketData->SockAddr)->sin6_addr = ((PSOCKADDR_IN6)&ListenAddressIter)->sin6_addr;
						((PSOCKADDR_IN6)&LocalSocketData->SockAddr)->sin6_port = ((PSOCKADDR_IN6)&ListenAddressIter)->sin6_port;

					//Add to global thread list.
						std::thread MonitorThreadTemp(UDPMonitor, *LocalSocketData);
						MonitorThread.at(MonitorThreadIndex).swap(MonitorThreadTemp);
						++MonitorThreadIndex;
						LocalSocketData->Socket = 0;
					}
				}
				else {
				//Proxy Mode
					if (Parameter.OperationMode == LISTEN_MODE_PROXY)
						((PSOCKADDR_IN6)&LocalSocketData->SockAddr)->sin6_addr = in6addr_loopback;
				//Server Mode, Priavte Mode and Custom Mode
					else 
						((PSOCKADDR_IN6)&LocalSocketData->SockAddr)->sin6_addr = in6addr_any;

				//Set ports.
					if (Parameter.ListenPort != nullptr)
					{
						for (auto ListenPortIter:*Parameter.ListenPort)
						{
							if (LocalSocketData->Socket == 0)
							{
								LocalSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
								if (!SocketSetting(LocalSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
									break;

								GlobalRunningStatus.LocalListeningSocket->push_back(LocalSocketData->Socket);
							}

							((PSOCKADDR_IN6)&LocalSocketData->SockAddr)->sin6_port = ListenPortIter;

						//Add to global thread list.
							std::thread MonitorThreadTemp(UDPMonitor, *LocalSocketData);
							MonitorThread.at(MonitorThreadIndex).swap(MonitorThreadTemp);
							++MonitorThreadIndex;
							LocalSocketData->Socket = 0;
						}
					}
				}
			}

			memset(LocalSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Set localhost socket(IPv6/TCP).
		if (Parameter.ListenProtocol_Transport == LISTEN_PROTOCOL_TRANSPORT_BOTH || Parameter.ListenProtocol_Transport == LISTEN_PROTOCOL_TCP)
		{
			LocalSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			if (LocalSocketData->Socket == INVALID_SOCKET)
			{
				if (WSAGetLastError() != 0 && WSAGetLastError() != WSAEAFNOSUPPORT)
					PrintError(LOG_ERROR_NETWORK, L"IPv6 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
			}
			else {
				GlobalRunningStatus.LocalListeningSocket->push_back(LocalSocketData->Socket);
				LocalSocketData->SockAddr.ss_family = AF_INET6;
				LocalSocketData->AddrLen = sizeof(sockaddr_in6);

			//Listen Address available(IPv6)
				if (Parameter.ListenAddress_IPv6 != nullptr)
				{
					for (auto ListenAddressIter:*Parameter.ListenAddress_IPv6)
					{
						if (LocalSocketData->Socket == 0)
						{
							LocalSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
							if (!SocketSetting(LocalSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
								break;

							GlobalRunningStatus.LocalListeningSocket->push_back(LocalSocketData->Socket);
						}

						((PSOCKADDR_IN6)&LocalSocketData->SockAddr)->sin6_addr = ((PSOCKADDR_IN6)&ListenAddressIter)->sin6_addr;
						((PSOCKADDR_IN6)&LocalSocketData->SockAddr)->sin6_port = ((PSOCKADDR_IN6)&ListenAddressIter)->sin6_port;

					//Add to global thread list.
						std::thread MonitorThreadTemp(TCPMonitor, *LocalSocketData);
						MonitorThread.at(MonitorThreadIndex).swap(MonitorThreadTemp);
						++MonitorThreadIndex;
						LocalSocketData->Socket = 0;
					}
				}
				else {
				//Proxy Mode
					if (Parameter.OperationMode == LISTEN_MODE_PROXY)
						((PSOCKADDR_IN6)&LocalSocketData->SockAddr)->sin6_addr = in6addr_loopback;
				//Server Mode, Priavte Mode and Custom Mode
					else 
						((PSOCKADDR_IN6)&LocalSocketData->SockAddr)->sin6_addr = in6addr_any;

				//Set ports.
					if (Parameter.ListenPort != nullptr)
					{
						for (auto ListenPortIter:*Parameter.ListenPort)
						{
							if (LocalSocketData->Socket == 0)
							{
								LocalSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
								if (!SocketSetting(LocalSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
									break;

								GlobalRunningStatus.LocalListeningSocket->push_back(LocalSocketData->Socket);
							}

							((PSOCKADDR_IN6)&LocalSocketData->SockAddr)->sin6_port = ListenPortIter;

						//Add to global thread list.
							std::thread MonitorThreadTemp(TCPMonitor, *LocalSocketData);
							MonitorThread.at(MonitorThreadIndex).swap(MonitorThreadTemp);
							++MonitorThreadIndex;
							LocalSocketData->Socket = 0;
						}
					}
				}
			}

			memset(LocalSocketData.get(), 0, sizeof(SOCKET_DATA));
		}
	}

//Set localhost socket(IPv4/UDP).
	if (Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_NETWORK_BOTH || Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_IPV4)
	{
		if (Parameter.ListenProtocol_Transport == LISTEN_PROTOCOL_TRANSPORT_BOTH || Parameter.ListenProtocol_Transport == LISTEN_PROTOCOL_UDP)
		{
			LocalSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (SocketSetting(LocalSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
			{
				GlobalRunningStatus.LocalListeningSocket->push_back(LocalSocketData->Socket);
				LocalSocketData->SockAddr.ss_family = AF_INET;
				LocalSocketData->AddrLen = sizeof(sockaddr_in);

			//Listen Address available(IPv4)
				if (Parameter.ListenAddress_IPv4 != nullptr)
				{
					for (auto ListenAddressIter:*Parameter.ListenAddress_IPv4)
					{
						if (LocalSocketData->Socket == 0)
						{
							LocalSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
							if (!SocketSetting(LocalSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
								break;

							GlobalRunningStatus.LocalListeningSocket->push_back(LocalSocketData->Socket);
						}

						((PSOCKADDR_IN)&LocalSocketData->SockAddr)->sin_addr = ((PSOCKADDR_IN)&ListenAddressIter)->sin_addr;
						((PSOCKADDR_IN)&LocalSocketData->SockAddr)->sin_port = ((PSOCKADDR_IN)&ListenAddressIter)->sin_port;

					//Add to global thread list.
						std::thread MonitorThreadTemp(UDPMonitor, *LocalSocketData);
						MonitorThread.at(MonitorThreadIndex).swap(MonitorThreadTemp);
						++MonitorThreadIndex;
						LocalSocketData->Socket = 0;
					}
				}
				else {
				//Proxy Mode
					if (Parameter.OperationMode == LISTEN_MODE_PROXY)
						((PSOCKADDR_IN)&LocalSocketData->SockAddr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
				//Server Mode, Priavte Mode and Custom Mode
					else 
						((PSOCKADDR_IN)&LocalSocketData->SockAddr)->sin_addr.s_addr = INADDR_ANY;

				//Set ports.
					if (Parameter.ListenPort != nullptr)
					{
						for (auto ListenPortIter:*Parameter.ListenPort)
						{
							if (LocalSocketData->Socket == 0)
							{
								LocalSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
								if (!SocketSetting(LocalSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
									break;

								GlobalRunningStatus.LocalListeningSocket->push_back(LocalSocketData->Socket);
							}

							((PSOCKADDR_IN)&LocalSocketData->SockAddr)->sin_port = ListenPortIter;

						//Add to global thread list.
							std::thread MonitorThreadTemp(UDPMonitor, *LocalSocketData);
							MonitorThread.at(MonitorThreadIndex).swap(MonitorThreadTemp);
							++MonitorThreadIndex;
							LocalSocketData->Socket = 0;
						}
					}
				}
			}

			memset(LocalSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Set localhost socket(IPv4/TCP).
		if (Parameter.ListenProtocol_Transport == LISTEN_PROTOCOL_TRANSPORT_BOTH || Parameter.ListenProtocol_Transport == LISTEN_PROTOCOL_TCP)
		{
			LocalSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (SocketSetting(LocalSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
			{
				GlobalRunningStatus.LocalListeningSocket->push_back(LocalSocketData->Socket);
				LocalSocketData->SockAddr.ss_family = AF_INET;
				LocalSocketData->AddrLen = sizeof(sockaddr_in);

			//Listen Address available(IPv4)
				if (Parameter.ListenAddress_IPv4 != nullptr)
				{
					for (auto ListenAddressIter:*Parameter.ListenAddress_IPv4)
					{
						if (LocalSocketData->Socket == 0)
						{
							LocalSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
							if (!SocketSetting(LocalSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
								break;

							GlobalRunningStatus.LocalListeningSocket->push_back(LocalSocketData->Socket);
						}

						((PSOCKADDR_IN)&LocalSocketData->SockAddr)->sin_addr = ((PSOCKADDR_IN)&ListenAddressIter)->sin_addr;
						((PSOCKADDR_IN)&LocalSocketData->SockAddr)->sin_port = ((PSOCKADDR_IN)&ListenAddressIter)->sin_port;

					//Add to global thread list.
						std::thread MonitorThreadTemp(TCPMonitor, *LocalSocketData);
						MonitorThread.at(MonitorThreadIndex).swap(MonitorThreadTemp);
						++MonitorThreadIndex;
						LocalSocketData->Socket = 0;
					}
				}
				else {
				//Proxy Mode
					if (Parameter.OperationMode == LISTEN_MODE_PROXY)
						((PSOCKADDR_IN)&LocalSocketData->SockAddr)->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
				//Server Mode, Priavte Mode and Custom Mode
					else 
						((PSOCKADDR_IN)&LocalSocketData->SockAddr)->sin_addr.s_addr = INADDR_ANY;

				//Set ports.
					if (Parameter.ListenPort != nullptr)
					{
						for (auto ListenPortIter:*Parameter.ListenPort)
						{
							if (LocalSocketData->Socket == 0)
							{
								LocalSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
								if (!SocketSetting(LocalSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
									break;

								GlobalRunningStatus.LocalListeningSocket->push_back(LocalSocketData->Socket);
							}

							((PSOCKADDR_IN)&LocalSocketData->SockAddr)->sin_port = ListenPortIter;

						//Add to global thread list.
							std::thread InnerMonitorThreadTemp(TCPMonitor, *LocalSocketData);
							MonitorThread.at(MonitorThreadIndex).swap(InnerMonitorThreadTemp);
							++MonitorThreadIndex;
							LocalSocketData->Socket = 0;
						}
					}
				}
			}
		}
	}

	LocalSocketData.reset();

#if defined(PLATFORM_WIN)
//Set MailSlot Monitor.
	std::thread FlushDNSMailSlotMonitorThread(FlushDNSMailSlotMonitor);
	FlushDNSMailSlotMonitorThread.detach();
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Set FIFO Monitor.
	std::thread FlushDNSFIFOMonitorThread(FlushDNSFIFOMonitor);
	FlushDNSFIFOMonitorThread.detach();
#endif

//Join threads.
	for (auto &ThreadIter:MonitorThread)
	{
		if (ThreadIter.joinable())
			ThreadIter.join();
	}

	return true;
}

//Local DNS server with UDP protocol
bool __fastcall UDPMonitor(
	const SOCKET_DATA LocalSocketData)
{
//Block UDP RESET message, socket timeout, reusing and non-blocking mode setting 
	if (!SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_TIMEOUT, &Parameter.SocketTimeout_Unreliable)
	#if defined(PLATFORM_WIN)
		|| !SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_UDP_BLOCK_RESET, nullptr)
		|| !SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_REUSE, nullptr)
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		|| LocalSocketData.SockAddr.ss_family == AF_INET6 && !SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_REUSE, nullptr)
	#endif
		|| !SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
			return false;

//Bind socket to port.
	if (bind(LocalSocketData.Socket, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Bind UDP Monitor socket error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return false;
	}

//Initialization
	std::shared_ptr<SOCKET_DATA> ClientData(new SOCKET_DATA());
	std::shared_ptr<char> RecvBuffer(new char[PACKET_MAXSIZE * Parameter.BufferQueueSize]());
	std::shared_ptr<char> SendBuffer(new char[PACKET_MAXSIZE]());
	std::shared_ptr<fd_set> ReadFDS(new fd_set());
	std::shared_ptr<timeval> OriginalTimeout(new timeval()), Timeout(new timeval());
	memset(ClientData.get(), 0, sizeof(SOCKET_DATA));
	memset(RecvBuffer.get(), 0, PACKET_MAXSIZE * Parameter.BufferQueueSize);
	memset(SendBuffer.get(), 0, PACKET_MAXSIZE);
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(OriginalTimeout.get(), 0, sizeof(timeval));
	memset(Timeout.get(), 0, sizeof(timeval));
#if defined(PLATFORM_WIN)
	OriginalTimeout->tv_sec = Parameter.SocketTimeout_Unreliable / SECOND_TO_MILLISECOND;
	OriginalTimeout->tv_usec = Parameter.SocketTimeout_Unreliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	OriginalTimeout->tv_sec = Parameter.SocketTimeout_Unreliable.tv_sec;
	OriginalTimeout->tv_usec = Parameter.SocketTimeout_Unreliable.tv_usec;
#endif
	SSIZE_T SelectResult = 0;
	uint64_t LastMarkTime = 0, NowTime = 0;
	if (Parameter.QueueResetTime > 0)
	{
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr)
			LastMarkTime = (*GlobalRunningStatus.FunctionPTR_GetTickCount64)();
		else 
			LastMarkTime = GetTickCount();
	#else
		LastMarkTime = GetTickCount64();
	#endif
	}
	size_t Index = 0;
	SSIZE_T RecvLen = 0;
	auto IsLocal = false;

//Listening module
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME_NO_DELAY);

	//Interval time between receive
		if (Parameter.QueueResetTime > 0 && Index + 1U == Parameter.BufferQueueSize)
		{
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr)
				NowTime = (*GlobalRunningStatus.FunctionPTR_GetTickCount64)();
			else 
				NowTime = GetTickCount();
		#else
			NowTime = GetTickCount64();
		#endif
			if (LastMarkTime + Parameter.QueueResetTime > NowTime)
				Sleep(LastMarkTime + Parameter.QueueResetTime - NowTime);

		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr)
				LastMarkTime = (*GlobalRunningStatus.FunctionPTR_GetTickCount64)();
			else 
				LastMarkTime = GetTickCount();
		#else
			LastMarkTime = GetTickCount64();
		#endif
		}

	//Reset parameters.
		memset(RecvBuffer.get() + PACKET_MAXSIZE * Index, 0, PACKET_MAXSIZE);
		memcpy_s(Timeout.get(), sizeof(timeval), OriginalTimeout.get(), sizeof(timeval));
		memcpy_s(ClientData.get(), sizeof(SOCKET_DATA), &LocalSocketData, sizeof(SOCKET_DATA));
		FD_ZERO(ReadFDS.get());
		FD_SET(ClientData->Socket, ReadFDS.get());
		IsLocal = false;

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), nullptr, nullptr, Timeout.get());
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(ClientData->Socket + 1U, ReadFDS.get(), nullptr, nullptr, Timeout.get());
	#endif
		if (SelectResult > EXIT_SUCCESS)
		{
			if (FD_ISSET(ClientData->Socket, ReadFDS.get()))
			{
			//Receive response and check DNS query data.
				if (Parameter.EDNS_Label) //EDNS Label
					RecvLen = recvfrom(ClientData->Socket, RecvBuffer.get() + PACKET_MAXSIZE * Index, PACKET_MAXSIZE - EDNS_ADDITIONAL_MAXSIZE, 0, (PSOCKADDR)&ClientData->SockAddr, (socklen_t *)&ClientData->AddrLen);
				else 
					RecvLen = recvfrom(ClientData->Socket, RecvBuffer.get() + PACKET_MAXSIZE * Index, PACKET_MAXSIZE, 0, (PSOCKADDR)&ClientData->SockAddr, (socklen_t *)&ClientData->AddrLen);
				if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
				{
					continue;
				}
				else {
					RecvLen = CheckQueryData(RecvBuffer.get() + PACKET_MAXSIZE * Index, SendBuffer.get(), RecvLen, *ClientData, IPPROTO_UDP, &IsLocal);
					if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
						continue;
				}

			//Request process
				if (ClientData->AddrLen == sizeof(sockaddr_in6)) //IPv6
				{
					std::thread RequestProcessThread(EnterRequestProcess, RecvBuffer.get() + PACKET_MAXSIZE * Index, RecvLen, *ClientData, IPPROTO_UDP, IsLocal);
					RequestProcessThread.detach();
				}
				else { //IPv4
					std::thread RequestProcessThread(EnterRequestProcess, RecvBuffer.get() + PACKET_MAXSIZE * Index, RecvLen, *ClientData, IPPROTO_UDP, IsLocal);
					RequestProcessThread.detach();
				}

				Index = (Index + 1U) % Parameter.BufferQueueSize;
			}
		}
	//Timeout
		else if (SelectResult == EXIT_SUCCESS)
		{
			continue;
		}
	//SOCKET_ERROR
		else {
			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				PrintError(LOG_ERROR_NETWORK, L"IPv6 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
			else //IPv4
				PrintError(LOG_ERROR_NETWORK, L"IPv4 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);

			Sleep(LOOP_INTERVAL_TIME_MONITOR);
			continue;
		}
	}

//Monitor terminated
	shutdown(LocalSocketData.Socket, SD_BOTH);
	closesocket(LocalSocketData.Socket);
	PrintError(LOG_ERROR_SYSTEM, L"UDP listening module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Local DNS server with TCP protocol
bool __fastcall TCPMonitor(
	const SOCKET_DATA LocalSocketData)
{
//Socket timeout, reusing, TCP Fast Open and non-blocking mode setting
	if (!SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_TIMEOUT, &Parameter.SocketTimeout_Reliable)
	#if defined(PLATFORM_WIN)
		|| !SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_REUSE, nullptr)
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		|| LocalSocketData.SockAddr.ss_family == AF_INET6 && !SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_REUSE, nullptr)
		#if defined(PLATFORM_LINUX)
			|| Parameter.TCP_FastOpen && !SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_TCP_FAST_OPEN, nullptr)
		#endif
	#endif	
		|| !SocketSetting(LocalSocketData.Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
			return false;

//Bind socket to port.
	if (bind(LocalSocketData.Socket, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Bind TCP Monitor socket error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return false;
	}

//Listen request from socket.
	if (listen(LocalSocketData.Socket, SOMAXCONN) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"TCP Monitor socket listening initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return false;
	}

//Initialization
	std::shared_ptr<SOCKET_DATA> ClientData(new SOCKET_DATA());
	std::shared_ptr<fd_set> ReadFDS(new fd_set());
	std::shared_ptr<timeval> OriginalTimeout(new timeval()), Timeout(new timeval());
	memset(ClientData.get(), 0, sizeof(SOCKET_DATA));
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(OriginalTimeout.get(), 0, sizeof(timeval));
	memset(Timeout.get(), 0, sizeof(timeval));
#if defined(PLATFORM_WIN)
	OriginalTimeout->tv_sec = Parameter.SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
	OriginalTimeout->tv_usec = Parameter.SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	OriginalTimeout->tv_sec = Parameter.SocketTimeout_Reliable.tv_sec;
	OriginalTimeout->tv_usec = Parameter.SocketTimeout_Reliable.tv_usec;
#endif
	SSIZE_T SelectResult = 0;
	uint64_t LastMarkTime = 0, NowTime = 0;
	if (Parameter.QueueResetTime > 0)
	{
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr)
			LastMarkTime = (*GlobalRunningStatus.FunctionPTR_GetTickCount64)();
		else 
			LastMarkTime = GetTickCount();
	#else
		LastMarkTime = GetTickCount64();
	#endif
	}
	size_t Index = 0;

//Start Monitor.
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME_NO_DELAY);

	//Interval time between receive
		if (Parameter.QueueResetTime > 0 && Index + 1U == Parameter.BufferQueueSize)
		{
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr)
				NowTime = (*GlobalRunningStatus.FunctionPTR_GetTickCount64)();
			else 
				NowTime = GetTickCount();
		#else
			NowTime = GetTickCount64();
		#endif
			if (LastMarkTime + Parameter.QueueResetTime > NowTime)
				Sleep(LastMarkTime + Parameter.QueueResetTime - NowTime);

		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr)
				LastMarkTime = (*GlobalRunningStatus.FunctionPTR_GetTickCount64)();
			else 
				LastMarkTime = GetTickCount();
		#else
			LastMarkTime = GetTickCount64();
		#endif
		}

	//Reset parameters.
		memset(&ClientData->SockAddr, 0, sizeof(sockaddr_storage));
		ClientData->AddrLen = LocalSocketData.AddrLen;
		ClientData->SockAddr.ss_family = LocalSocketData.SockAddr.ss_family;
		memcpy_s(Timeout.get(), sizeof(timeval), OriginalTimeout.get(), sizeof(timeval));
		FD_ZERO(ReadFDS.get());
		FD_SET(LocalSocketData.Socket, ReadFDS.get());

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS.get(), nullptr, nullptr, Timeout.get());
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(LocalSocketData.Socket + 1U, ReadFDS.get(), nullptr, nullptr, Timeout.get());
	#endif
		if (SelectResult > EXIT_SUCCESS)
		{
			if (FD_ISSET(LocalSocketData.Socket, ReadFDS.get()))
			{
			//Accept connection and check address.
				ClientData->Socket = accept(LocalSocketData.Socket, (PSOCKADDR)&ClientData->SockAddr, &ClientData->AddrLen);
				if (ClientData->Socket == INVALID_SOCKET)
					continue;
				if (CheckQueryData(nullptr, nullptr, 0, *ClientData, 0, nullptr) != EXIT_SUCCESS)
				{
					shutdown(ClientData->Socket, SD_BOTH);
					closesocket(ClientData->Socket);
					continue;
				}

			//Accept process.
				std::thread TCPReceiveThread(TCPReceiveProcess, *ClientData);
				TCPReceiveThread.detach();
				Index = (Index + 1U) % Parameter.BufferQueueSize;
			}
		}
	//Timeout
		else if (SelectResult == EXIT_SUCCESS)
		{
			continue;
		}
	//SOCKET_ERROR
		else {
			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				PrintError(LOG_ERROR_NETWORK, L"IPv6 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
			else //IPv4
				PrintError(LOG_ERROR_NETWORK, L"IPv4 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);

			Sleep(LOOP_INTERVAL_TIME_MONITOR);
			continue;
		}
	}

//Monitor terminated
	shutdown(LocalSocketData.Socket, SD_BOTH);
	closesocket(LocalSocketData.Socket);
	PrintError(LOG_ERROR_SYSTEM, L"TCP listening module Monitor terminated", 0, nullptr, 0);
	return true;
}

//TCP Monitor receive process
bool __fastcall TCPReceiveProcess(
	const SOCKET_DATA LocalSocketData)
{
//Initialization(Part 1)
	std::shared_ptr<char> RecvBuffer(new char[LARGE_PACKET_MAXSIZE]());
	std::shared_ptr<fd_set> ReadFDS(new fd_set());
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(RecvBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));
	SSIZE_T RecvLen = 0;
	auto IsLocal = false;

//Receive process
#if defined(PLATFORM_WIN)
	Timeout->tv_sec = Parameter.SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
	Timeout->tv_usec = Parameter.SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Timeout->tv_sec = Parameter.SocketTimeout_Reliable.tv_sec;
	Timeout->tv_usec = Parameter.SocketTimeout_Reliable.tv_usec;
#endif
	FD_ZERO(ReadFDS.get());
	FD_SET(LocalSocketData.Socket, ReadFDS.get());

#if defined(PLATFORM_WIN)
	RecvLen = select(0, ReadFDS.get(), nullptr, nullptr, Timeout.get());
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	RecvLen = select(LocalSocketData.Socket + 1U, ReadFDS.get(), nullptr, nullptr, Timeout.get());
#endif
	if (RecvLen > 0 && FD_ISSET(LocalSocketData.Socket, ReadFDS.get()))
	{
		if (Parameter.EDNS_Label) //EDNS Label
			RecvLen = recv(LocalSocketData.Socket, RecvBuffer.get(), LARGE_PACKET_MAXSIZE - EDNS_ADDITIONAL_MAXSIZE, 0);
		else 
			RecvLen = recv(LocalSocketData.Socket, RecvBuffer.get(), LARGE_PACKET_MAXSIZE, 0);
	}
//Timeout or SOCKET_ERROR
	else {
		shutdown(LocalSocketData.Socket, SD_BOTH);
		closesocket(LocalSocketData.Socket);
		return false;
	}

//Connection closed or SOCKET_ERROR
	size_t Length = 0;
	if (RecvLen <= 0)
	{
		shutdown(LocalSocketData.Socket, SD_BOTH);
		closesocket(LocalSocketData.Socket);
		return false;
	}
	else if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		Length = RecvLen;

	//Socket selecting structure setting
		memset(ReadFDS.get(), 0, sizeof(fd_set));
		memset(Timeout.get(), 0, sizeof(timeval));
	#if defined(PLATFORM_WIN)
		Timeout->tv_sec = Parameter.SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
		Timeout->tv_usec = Parameter.SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Timeout->tv_sec = Parameter.SocketTimeout_Reliable.tv_sec;
		Timeout->tv_usec = Parameter.SocketTimeout_Reliable.tv_usec;
	#endif
		FD_ZERO(ReadFDS.get());
		FD_SET(LocalSocketData.Socket, ReadFDS.get());

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		RecvLen = select(0, ReadFDS.get(), nullptr, nullptr, Timeout.get());
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		RecvLen = select(LocalSocketData.Socket + 1U, ReadFDS.get(), nullptr, nullptr, Timeout.get());
	#endif
		if (RecvLen > 0 && FD_ISSET(LocalSocketData.Socket, ReadFDS.get()))
		{
			if (Parameter.EDNS_Label) //EDNS Label
				RecvLen = recv(LocalSocketData.Socket, RecvBuffer.get() + Length, (int)(LARGE_PACKET_MAXSIZE - EDNS_ADDITIONAL_MAXSIZE - Length), 0);
			else 
				RecvLen = recv(LocalSocketData.Socket, RecvBuffer.get() + Length, (int)(LARGE_PACKET_MAXSIZE - Length), 0);

		//Packet length check
			if (RecvLen > 0)
			{
				RecvLen += Length;
			}
		//Connection closed or SOCKET_ERROR
			else {
				shutdown(LocalSocketData.Socket, SD_BOTH);
				closesocket(LocalSocketData.Socket);
				return false;
			}
		}
	//Timeout or SOCKET_ERROR
		else {
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
			return false;
		}
	}

//Packet length check
	Length = ntohs(((PUINT16)RecvBuffer.get())[0]);
	if (RecvLen >= (SSIZE_T)Length && Length >= DNS_PACKET_MINSIZE)
	{
	//Check DNS query data.
		std::shared_ptr<char> SendBuffer(new char[LARGE_PACKET_MAXSIZE]());
		Length = CheckQueryData(RecvBuffer.get() + sizeof(uint16_t), SendBuffer.get(), Length, LocalSocketData, IPPROTO_TCP, &IsLocal);
		if (Length < (SSIZE_T)DNS_PACKET_MINSIZE)
		{
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
			return false;
		}
		SendBuffer.reset();

	//Main request process
		if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			EnterRequestProcess(RecvBuffer.get() + sizeof(uint16_t), Length, LocalSocketData, IPPROTO_TCP, IsLocal);
		else //IPv4
			EnterRequestProcess(RecvBuffer.get() + sizeof(uint16_t), Length, LocalSocketData, IPPROTO_TCP, IsLocal);
	}
	else {
		shutdown(LocalSocketData.Socket, SD_BOTH);
		closesocket(LocalSocketData.Socket);
		return false;
	}

//Block Port Unreachable messages of system.
	shutdown(LocalSocketData.Socket, SD_SEND);
#if defined(PLATFORM_WIN)
	Sleep(Parameter.SocketTimeout_Reliable);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	usleep(Parameter.SocketTimeout_Reliable.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable.tv_usec);
#endif
	shutdown(LocalSocketData.Socket, SD_BOTH);
	closesocket(LocalSocketData.Socket);

	return true;
}

//Alternate DNS servers switcher
void __fastcall AlternateServerMonitor(
	void)
{
	size_t Index = 0, RangeTimer[ALTERNATE_SERVERNUM]{0}, SwapTimer[ALTERNATE_SERVERNUM]{0};

//Switcher
//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
	for (;;)
	{
	//Complete request process check
		for (Index = 0;Index < ALTERNATE_SERVERNUM;++Index)
		{
		//Reset TimeoutTimes out of alternate time range.
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr && (*GlobalRunningStatus.FunctionPTR_GetTickCount64)() >= RangeTimer[Index] || GetTickCount() >= RangeTimer[Index])
			{
				if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr)
					RangeTimer[Index] = (size_t)((*GlobalRunningStatus.FunctionPTR_GetTickCount64)() + Parameter.AlternateTimeRange);
				else 
					RangeTimer[Index] = GetTickCount() + Parameter.AlternateTimeRange;
		#else
			if (GetTickCount64() >= RangeTimer[Index])
			{
				RangeTimer[Index] = GetTickCount64() + Parameter.AlternateTimeRange;
		#endif
				AlternateSwapList.TimeoutTimes[Index] = 0;
				continue;
			}

		//Reset alternate switching.
			if (AlternateSwapList.IsSwap[Index])
			{
			#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
				if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr && (*GlobalRunningStatus.FunctionPTR_GetTickCount64)() >= SwapTimer[Index] || GetTickCount() >= SwapTimer[Index])
			#else
				if (GetTickCount64() >= SwapTimer[Index])
			#endif
				{
					AlternateSwapList.IsSwap[Index] = false;
					AlternateSwapList.TimeoutTimes[Index] = 0;
					SwapTimer[Index] = 0;
				}
			}
			else {
			//Mark alternate switching.
				if (AlternateSwapList.TimeoutTimes[Index] >= Parameter.AlternateTimes)
				{
					AlternateSwapList.IsSwap[Index] = true;
					AlternateSwapList.TimeoutTimes[Index] = 0;
				#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
					if (GlobalRunningStatus.FunctionPTR_GetTickCount64 != nullptr)
						SwapTimer[Index] = (size_t)((*GlobalRunningStatus.FunctionPTR_GetTickCount64)() + Parameter.AlternateResetTime);
					else 
						SwapTimer[Index] = GetTickCount() + Parameter.AlternateResetTime;
				#else
					SwapTimer[Index] = GetTickCount64() + Parameter.AlternateResetTime;
				#endif
				}
			}
		}

		Sleep(LOOP_INTERVAL_TIME_MONITOR);
	}

//Monitor terminated
	PrintError(LOG_ERROR_SYSTEM, L"Alternate Server module Monitor terminated", 0, nullptr, 0);
	return;
}

//Get local address list
#if defined(PLATFORM_WIN)
PADDRINFOA __fastcall GetLocalAddressList(
	const uint16_t Protocol, 
	PSTR HostName)
{
//Initialization
	std::shared_ptr<addrinfo> Hints(new addrinfo());
	memset(Hints.get(), 0, sizeof(addrinfo));
	PADDRINFOA Result = nullptr;

	if (Protocol == AF_INET6) //IPv6
		Hints->ai_family = AF_INET6;
	else //IPv4
		Hints->ai_family = AF_INET;
	Hints->ai_socktype = SOCK_DGRAM;
	Hints->ai_protocol = IPPROTO_UDP;

//Get localhost name.
	if (gethostname(HostName, DOMAIN_MAXSIZE) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Get localhost name error", WSAGetLastError(), nullptr, 0);
		return nullptr;
	}

//Get localhost data.
	int ResultGetaddrinfo = getaddrinfo(HostName, nullptr, Hints.get(), &Result);
	if (ResultGetaddrinfo != EXIT_SUCCESS)
	{
		PrintError(LOG_ERROR_NETWORK, L"Get localhost address error", ResultGetaddrinfo, nullptr, 0);

		freeaddrinfo(Result);
		return nullptr;
	}

	return Result;
}
#endif

#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Get address from best network interface
bool GetBestInterfaceAddress(
	const uint16_t Protocol, 
	const sockaddr_storage *OriginalSockAddr)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SockAddr->ss_family = Protocol;
	SOCKET InterfaceSocket = socket(Protocol, SOCK_DGRAM, IPPROTO_UDP);
	socklen_t AddrLen = 0;

//Check socket.
	if (!SocketSetting(InterfaceSocket, SOCKET_SETTING_INVALID_CHECK, nullptr))
	{
		if (Protocol == AF_INET6) //IPv6
			GlobalRunningStatus.GatewayAvailable_IPv6 = false;
		else //IPv4
			GlobalRunningStatus.GatewayAvailable_IPv4 = false;

		return false;
	}

//Check parameter.
	if (Protocol == AF_INET6)
	{
		((PSOCKADDR_IN6)SockAddr.get())->sin6_addr = ((PSOCKADDR_IN6)OriginalSockAddr)->sin6_addr;
		((PSOCKADDR_IN6)SockAddr.get())->sin6_port = ((PSOCKADDR_IN6)OriginalSockAddr)->sin6_port;
		AddrLen = sizeof(sockaddr_in6);

	//UDP connecting
		if (connect(InterfaceSocket, (PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in6)) == SOCKET_ERROR || 
			getsockname(InterfaceSocket, (PSOCKADDR)SockAddr.get(), &AddrLen) == SOCKET_ERROR || SockAddr->ss_family != AF_INET6 || 
			AddrLen != sizeof(sockaddr_in6) || CheckEmptyBuffer(&((PSOCKADDR_IN6)SockAddr.get())->sin6_addr, sizeof(in6_addr)))
		{
			GlobalRunningStatus.GatewayAvailable_IPv6 = false;

			close(InterfaceSocket);
			return false;
		}
	}
	else { //IPv4
		((PSOCKADDR_IN)SockAddr.get())->sin_addr = ((PSOCKADDR_IN)OriginalSockAddr)->sin_addr;
		((PSOCKADDR_IN)SockAddr.get())->sin_port = ((PSOCKADDR_IN)OriginalSockAddr)->sin_port;
		AddrLen = sizeof(sockaddr_in);

	//UDP connecting
		if (connect(InterfaceSocket, (PSOCKADDR)SockAddr.get(), sizeof(sockaddr_in)) == SOCKET_ERROR || 
			getsockname(InterfaceSocket, (PSOCKADDR)SockAddr.get(), &AddrLen) == SOCKET_ERROR || SockAddr->ss_family != AF_INET || 
			AddrLen != sizeof(sockaddr_in) || CheckEmptyBuffer(&((PSOCKADDR_IN)SockAddr.get())->sin_addr, sizeof(in_addr)))
		{
			GlobalRunningStatus.GatewayAvailable_IPv4 = false;

			close(InterfaceSocket);
			return false;
		}
	}

	close(InterfaceSocket);
	return true;
}
#endif

//Get gateway information
void __fastcall GetGatewayInformation(
	const uint16_t Protocol)
{
//IPv6
	if (Protocol == AF_INET6)
	{
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0 && 
			Parameter.DNSTarget.Local_IPv6.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_Local_IPv6.Storage.ss_family == 0
		#if defined(ENABLE_LIBSODIUM)
			&& DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0
		#endif
			)
		{
			GlobalRunningStatus.GatewayAvailable_IPv6 = false;
			return;
		}
	#if defined(PLATFORM_WIN)
		DWORD AdaptersIndex = 0;
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Local_IPv6.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Local_IPv6.IPv6, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_Local_IPv6.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_Local_IPv6.IPv6, &AdaptersIndex) != NO_ERROR
		#if defined(ENABLE_LIBSODIUM)
			|| DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR
		#endif
			)
		{
			GlobalRunningStatus.GatewayAvailable_IPv6 = false;
			return;
		}

	//IPv6 Multi
		if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				if (GetBestInterfaceEx((PSOCKADDR)&DNSServerDataIter.AddressData.IPv6, &AdaptersIndex) != NO_ERROR)
				{
					GlobalRunningStatus.GatewayAvailable_IPv6 = false;
					return;
				}
			}
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET6, &Parameter.DNSTarget.IPv6.AddressData.Storage) || 
			Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET6, &Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage) || 
			Parameter.DNSTarget.Local_IPv6.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET6, &Parameter.DNSTarget.Local_IPv6.Storage) || 
			Parameter.DNSTarget.Alternate_Local_IPv6.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET6, &Parameter.DNSTarget.Alternate_Local_IPv6.Storage)
		#if defined(ENABLE_LIBSODIUM)
			|| DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET6, &DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage) || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET6, &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage)
		#endif
			)
		{
			GlobalRunningStatus.GatewayAvailable_IPv6 = false;
			return;
		}

	//IPv6 Multi
		if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				if (!GetBestInterfaceAddress(AF_INET6, &DNSServerDataIter.AddressData.Storage))
				{
					GlobalRunningStatus.GatewayAvailable_IPv6 = false;
					return;
				}
			}
		}
	#endif

		GlobalRunningStatus.GatewayAvailable_IPv6 = true;
	}
//IPv4
	else {
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family == 0 && 
			Parameter.DNSTarget.Local_IPv4.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_Local_IPv4.Storage.ss_family == 0
		#if defined(ENABLE_LIBSODIUM)
			&& DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family == 0
		#endif
			)
		{
			GlobalRunningStatus.GatewayAvailable_IPv4 = false;
			return;
		}
	#if defined(PLATFORM_WIN)
		DWORD AdaptersIndex = 0;
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Local_IPv4.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Local_IPv4.IPv4, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_Local_IPv4.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_Local_IPv4.IPv4, &AdaptersIndex) != NO_ERROR
		#if defined(ENABLE_LIBSODIUM)
			|| DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR
		#endif
			)
		{
			GlobalRunningStatus.GatewayAvailable_IPv4 = false;
			return;
		}

	//IPv4 Multi
		if (Parameter.DNSTarget.IPv4_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				if (GetBestInterfaceEx((PSOCKADDR)&DNSServerDataIter.AddressData.IPv4, &AdaptersIndex) != NO_ERROR)
				{
					GlobalRunningStatus.GatewayAvailable_IPv4 = false;
					return;
				}
			}
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET, &Parameter.DNSTarget.IPv4.AddressData.Storage) || 
			Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET, &Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage) || 
			Parameter.DNSTarget.Local_IPv4.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET, &Parameter.DNSTarget.Local_IPv4.Storage) || 
			Parameter.DNSTarget.Alternate_Local_IPv4.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET, &Parameter.DNSTarget.Alternate_Local_IPv4.Storage)
		#if defined(ENABLE_LIBSODIUM)
			|| DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET, &DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage) || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET, &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage)
		#endif
			)
		{
			GlobalRunningStatus.GatewayAvailable_IPv4 = false;
			return;
		}

	//IPv4 Multi
		if (Parameter.DNSTarget.IPv4_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				if (!GetBestInterfaceAddress(AF_INET, &DNSServerDataIter.AddressData.Storage))
				{
					GlobalRunningStatus.GatewayAvailable_IPv4 = false;
					return;
				}
			}
		}
	#endif

		GlobalRunningStatus.GatewayAvailable_IPv4 = true;
	}

	return;
}

//Local network information monitor
void __fastcall NetworkInformationMonitor(
	void)
{
//Initialization
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	std::shared_ptr<char> HostName(new char[DOMAIN_MAXSIZE]());
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
	memset(HostName.get(), 0, DOMAIN_MAXSIZE);
#if !defined(PLATFORM_MACX)
	std::string Result;
	SSIZE_T Index = 0;
#endif
#if defined(PLATFORM_WIN)
	PADDRINFOA LocalAddressList = nullptr, LocalAddressTableIter = nullptr;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	ifaddrs *InterfaceAddressList = nullptr, *InterfaceAddressIter = nullptr;
	auto IsErrorFirstPrint = true;
#endif
	pdns_hdr DNS_Header = nullptr;
	pdns_qry DNS_Query = nullptr;
	void *DNS_Record = nullptr;
	auto IsSubnetMark = false;
	std::unique_lock<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[0]), LocalAddressMutexIPv4(LocalAddressLock[1U]);
	LocalAddressMutexIPv6.unlock();
	LocalAddressMutexIPv4.unlock();

//Monitor
	for (;;)
	{
		IsSubnetMark = false;

	//Get localhost addresses(IPv6)
		if (Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_NETWORK_BOTH || Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_IPV6)
		{
		#if defined(PLATFORM_WIN)
			memset(HostName.get(), 0, DOMAIN_MAXSIZE);
			LocalAddressList = GetLocalAddressList(AF_INET6, HostName.get());
			if (LocalAddressList == nullptr)
			{
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (getifaddrs(&InterfaceAddressList) != EXIT_SUCCESS || InterfaceAddressList == nullptr)
			{
				if (InterfaceAddressList != nullptr)
					freeifaddrs(InterfaceAddressList);
				InterfaceAddressList = nullptr;
				PrintError(LOG_ERROR_NETWORK, L"Get localhost address error", errno, nullptr, 0);
		#endif

				Sleep(Parameter.FileRefreshTime);
				continue;
			}
			else {
				LocalAddressMutexIPv6.lock();
				memset(GlobalRunningStatus.LocalAddress_Response[0], 0, PACKET_MAXSIZE);
				GlobalRunningStatus.LocalAddress_Length[0] = 0;
			#if !defined(PLATFORM_MACX)
				std::string DNSPTRString;
				GlobalRunningStatus.LocalAddress_ResponsePTR[0]->clear();
				GlobalRunningStatus.LocalAddress_ResponsePTR[0]->shrink_to_fit();
			#endif

			//Mark local addresses(A part).
				DNS_Header = (pdns_hdr)GlobalRunningStatus.LocalAddress_Response[0];
				DNS_Header->Flags = htons(DNS_SQR_NEA);
				DNS_Header->Questions = htons(U16_NUM_ONE);
				GlobalRunningStatus.LocalAddress_Length[0] += sizeof(dns_hdr);
				memcpy_s(GlobalRunningStatus.LocalAddress_Response[0] + GlobalRunningStatus.LocalAddress_Length[0], PACKET_MAXSIZE - GlobalRunningStatus.LocalAddress_Length[0], Parameter.LocalFQDN_Response, Parameter.LocalFQDN_Length);
				GlobalRunningStatus.LocalAddress_Length[0] += Parameter.LocalFQDN_Length;
				DNS_Query = (pdns_qry)(GlobalRunningStatus.LocalAddress_Response[0] + GlobalRunningStatus.LocalAddress_Length[0]);
				DNS_Query->Type = htons(DNS_RECORD_AAAA);
				DNS_Query->Classes = htons(DNS_CLASS_IN);
				GlobalRunningStatus.LocalAddress_Length[0] += sizeof(dns_qry);

			//Read addresses list and convert to Fully Qualified Domain Name/FQDN PTR.
			#if defined(PLATFORM_WIN)
				for (LocalAddressTableIter = LocalAddressList;LocalAddressTableIter != nullptr;LocalAddressTableIter = LocalAddressTableIter->ai_next)
				{
					if (LocalAddressTableIter->ai_family == AF_INET6 && LocalAddressTableIter->ai_addrlen == sizeof(sockaddr_in6) && 
						LocalAddressTableIter->ai_addr->sa_family == AF_INET6)
					{
					//Mark localhost subnet(IPv6).
						if (Parameter.EDNS_ClientSubnet && !IsSubnetMark && !Parameter.LocalhostSubnet.Setting_IPv6 && 
							Parameter.LocalhostSubnet.IPv6 != nullptr && Parameter.LocalhostSubnet.IPv6->Address.ss_family == 0 && 
							!CheckSpecialAddress(&((PSOCKADDR_IN6)LocalAddressTableIter->ai_addr)->sin6_addr, AF_INET6, true, nullptr))
						{
							Parameter.LocalhostSubnet.IPv6->Address.ss_family = AF_INET6;
							((PSOCKADDR_IN6)&Parameter.LocalhostSubnet.IPv6->Address)->sin6_addr = ((PSOCKADDR_IN6)LocalAddressTableIter->ai_addr)->sin6_addr;
							Parameter.LocalhostSubnet.IPv6->Prefix = sizeof(in6_addr) * BYTES_TO_BITS; //No recommendation is provided for IPv6 at this time so keep all bits, see https://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02.

							IsSubnetMark = true;
						}

					//Mark local addresses(B part).
						if (GlobalRunningStatus.LocalAddress_Length[0] <= PACKET_MAXSIZE - sizeof(dns_record_aaaa))
						{
							DNS_Record = (pdns_record_aaaa)(GlobalRunningStatus.LocalAddress_Response[0] + GlobalRunningStatus.LocalAddress_Length[0]);
							((pdns_record_aaaa)DNS_Record)->Name = htons(DNS_POINTER_QUERY);
							((pdns_record_aaaa)DNS_Record)->Classes = htons(DNS_CLASS_IN);
							((pdns_record_aaaa)DNS_Record)->TTL = htonl(Parameter.HostsDefaultTTL);
							((pdns_record_aaaa)DNS_Record)->Type = htons(DNS_RECORD_AAAA);
							((pdns_record_aaaa)DNS_Record)->Length = htons(sizeof(in6_addr));
							((pdns_record_aaaa)DNS_Record)->Addr = ((PSOCKADDR_IN6)LocalAddressTableIter->ai_addr)->sin6_addr;
							GlobalRunningStatus.LocalAddress_Length[0] += sizeof(dns_record_aaaa);
							++DNS_Header->Answer;
						}

					#if !defined(PLATFORM_MACX)
					//Initialization
						DNSPTRString.clear();
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

					//Convert from in6_addr to string.
						size_t AddrStringLen = 0;
						for (Index = 0;Index < (SSIZE_T)(sizeof(in6_addr) / sizeof(uint16_t));++Index)
						{
							sprintf_s(Addr.get(), ADDR_STRING_MAXSIZE, "%x", ntohs(((PSOCKADDR_IN6)LocalAddressTableIter->ai_addr)->sin6_addr.s6_words[Index]));

						//Add zeros to beginning of string.
							if (strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE) < 4U)
							{
								AddrStringLen = strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE);
								memmove_s(Addr.get() + 4U - strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE), ADDR_STRING_MAXSIZE, Addr.get(), strnlen_s(Addr.get(), ADDR_STRING_MAXSIZE));
								memset(Addr.get(), ASCII_ZERO, 4U - AddrStringLen);
							}
							DNSPTRString.append(Addr.get());
							memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

						//Last data
							if (Index < (SSIZE_T)(sizeof(in6_addr) / sizeof(uint16_t) - 1U))
								DNSPTRString.append(":");
						}

					//Convert to standard IPv6 address format(":0:" -> ":0000:").
						Index = 0;
						while (DNSPTRString.find(":0:", Index) != std::string::npos)
							DNSPTRString.replace(DNSPTRString.find(":0:", Index), 3U, ":0000:");

					//Delete all colons
						while (DNSPTRString.find(":") != std::string::npos)
							DNSPTRString.erase(DNSPTRString.find(":"), strlen(":"));

					//Convert standard IPv6 address string to DNS PTR.
						for (Index = DNSPTRString.length() - 1U;Index >= 0;--Index)
						{
							Result.append(DNSPTRString, Index, 1U);
							Result.append(".");
						}
						Result.append("ip6.arpa");

					//Add to global list.
						GlobalRunningStatus.LocalAddress_ResponsePTR[0]->push_back(Result);
						Result.clear();
						Result.shrink_to_fit();
					#endif
					}
				}
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				for (InterfaceAddressIter = InterfaceAddressList;InterfaceAddressIter != nullptr;InterfaceAddressIter = InterfaceAddressIter->ifa_next)
				{
					if (InterfaceAddressIter->ifa_addr != nullptr && InterfaceAddressIter->ifa_addr->sa_family == AF_INET6)
					{
					//Mark localhost subnet(IPv6).
						if (Parameter.EDNS_ClientSubnet && !IsSubnetMark && !Parameter.LocalhostSubnet.Setting_IPv6 && 
							Parameter.LocalhostSubnet.IPv6 != nullptr && Parameter.LocalhostSubnet.IPv6->Address.ss_family == 0 && 
							!CheckSpecialAddress(&((PSOCKADDR_IN6)InterfaceAddressIter->ifa_addr)->sin6_addr, AF_INET6, true, nullptr))
						{
							Parameter.LocalhostSubnet.IPv6->Address.ss_family = AF_INET6;
							((PSOCKADDR_IN6)&Parameter.LocalhostSubnet.IPv6->Address)->sin6_addr = ((PSOCKADDR_IN6)InterfaceAddressIter->ifa_addr)->sin6_addr;
							Parameter.LocalhostSubnet.IPv6->Prefix = sizeof(in6_addr) * BYTES_TO_BITS; //No recommendation is provided for IPv6 at this time so keep all bits, see https://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02.

							IsSubnetMark = true;
						}

					//Mark local addresses(B part).
						if (GlobalRunningStatus.LocalAddress_Length[0] <= PACKET_MAXSIZE - sizeof(dns_record_aaaa))
						{
							DNS_Record = (pdns_record_aaaa)(GlobalRunningStatus.LocalAddress_Response[0] + GlobalRunningStatus.LocalAddress_Length[0]);
							((pdns_record_aaaa)DNS_Record)->Name = htons(DNS_POINTER_QUERY);
							((pdns_record_aaaa)DNS_Record)->Classes = htons(DNS_CLASS_IN);
							((pdns_record_aaaa)DNS_Record)->TTL = htonl(Parameter.HostsDefaultTTL);
							((pdns_record_aaaa)DNS_Record)->Type = htons(DNS_RECORD_AAAA);
							((pdns_record_aaaa)DNS_Record)->Length = htons(sizeof(in6_addr));
							((pdns_record_aaaa)DNS_Record)->Addr = ((PSOCKADDR_IN6)InterfaceAddressIter->ifa_addr)->sin6_addr;
							GlobalRunningStatus.LocalAddress_Length[0] += sizeof(dns_record_aaaa);
							++DNS_Header->Answer;
						}

					#if !defined(PLATFORM_MACX)
					//Initialization
						DNSPTRString.clear();
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

					//Convert from in6_addr to string.
						size_t AddrStringLen = 0;
						for (Index = 0;Index < (SSIZE_T)(sizeof(in6_addr) / sizeof(uint16_t));++Index)
						{
							snprintf(Addr.get(), ADDR_STRING_MAXSIZE, "%x", ntohs(((PSOCKADDR_IN6)InterfaceAddressIter->ifa_addr)->sin6_addr.s6_words[Index]));

						//Add zeros to beginning of string.
							if (strnlen(Addr.get(), ADDR_STRING_MAXSIZE) < 4U)
							{
								AddrStringLen = strnlen(Addr.get(), ADDR_STRING_MAXSIZE);
								memmove_s(Addr.get() + 4U - strnlen(Addr.get(), ADDR_STRING_MAXSIZE), ADDR_STRING_MAXSIZE, Addr.get(), strnlen(Addr.get(), ADDR_STRING_MAXSIZE));
								memset(Addr.get(), ASCII_ZERO, 4U - AddrStringLen);
							}
							DNSPTRString.append(Addr.get());
							memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

						//Last data
							if (Index < (SSIZE_T)(sizeof(in6_addr) / sizeof(uint16_t) - 1U))
								DNSPTRString.append(":");
						}

					//Convert to standard IPv6 address format(":0:" -> ":0000:").
						Index = 0;
						while (DNSPTRString.find(":0:", Index) != std::string::npos)
							DNSPTRString.replace(DNSPTRString.find(":0:", Index), 3U, ":0000:");

					//Delete all colons
						while (DNSPTRString.find(":") != std::string::npos)
							DNSPTRString.erase(DNSPTRString.find(":"), strlen(":"));

					//Convert standard IPv6 address string to DNS PTR.
						for (Index = DNSPTRString.length() - 1U;Index >= 0;--Index)
						{
							Result.append(DNSPTRString, Index, 1U);
							Result.append(".");
						}
						Result.append("ip6.arpa");

					//Add to global list.
						GlobalRunningStatus.LocalAddress_ResponsePTR[0]->push_back(Result);
						Result.clear();
						Result.shrink_to_fit();
					#endif
					}
				}
			#endif

			//Mark local addresses(C part).
				if (DNS_Header->Answer == 0)
				{
					memset(GlobalRunningStatus.LocalAddress_Response[0], 0, PACKET_MAXSIZE);
					GlobalRunningStatus.LocalAddress_Length[0] = 0;
				}
				else {
					DNS_Header->Answer = htons(DNS_Header->Answer);
				}

			//Free all lists.
				LocalAddressMutexIPv6.unlock();
			#if defined(PLATFORM_WIN)
				freeaddrinfo(LocalAddressList);
				LocalAddressList = nullptr;
			#endif

			//Reset localhost subnet settings if there no any addresses which can be marked.
				if (Parameter.EDNS_ClientSubnet && Parameter.LocalhostSubnet.IPv6 != nullptr && !IsSubnetMark && !Parameter.LocalhostSubnet.Setting_IPv6)
				{
					Parameter.LocalhostSubnet.IPv6->Prefix = 0;
					memset(&Parameter.LocalhostSubnet.IPv6->Address, 0, sizeof(sockaddr_storage));
				}
			}
		}

	//Get localhost addresses(IPv4)
		if (Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_NETWORK_BOTH || Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_IPV4)
		{
		#if defined(PLATFORM_WIN)
			memset(HostName.get(), 0, DOMAIN_MAXSIZE);
			LocalAddressList = GetLocalAddressList(AF_INET, HostName.get());
			if (LocalAddressList == nullptr)
			{
				Sleep(Parameter.FileRefreshTime);
				continue;
			}
			else {
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			{
		#endif
				LocalAddressMutexIPv4.lock();
				memset(GlobalRunningStatus.LocalAddress_Response[1U], 0, PACKET_MAXSIZE);
				GlobalRunningStatus.LocalAddress_Length[1U] = 0;
			#if !defined(PLATFORM_MACX)
				std::string DNSPTRString;
				GlobalRunningStatus.LocalAddress_ResponsePTR[1U]->clear();
				GlobalRunningStatus.LocalAddress_ResponsePTR[1U]->shrink_to_fit();
			#endif

			//Mark local addresses(A part).
				DNS_Header = (pdns_hdr)GlobalRunningStatus.LocalAddress_Response[1U];
				DNS_Header->Flags = htons(DNS_SQR_NEA);
				DNS_Header->Questions = htons(U16_NUM_ONE);
				GlobalRunningStatus.LocalAddress_Length[1U] += sizeof(dns_hdr);
				memcpy_s(GlobalRunningStatus.LocalAddress_Response[1U] + GlobalRunningStatus.LocalAddress_Length[1U], PACKET_MAXSIZE - GlobalRunningStatus.LocalAddress_Length[1U], Parameter.LocalFQDN_Response, Parameter.LocalFQDN_Length);
				GlobalRunningStatus.LocalAddress_Length[1U] += Parameter.LocalFQDN_Length;
				DNS_Query = (pdns_qry)(GlobalRunningStatus.LocalAddress_Response[1U] + GlobalRunningStatus.LocalAddress_Length[1U]);
				DNS_Query->Type = htons(DNS_RECORD_AAAA);
				DNS_Query->Classes = htons(DNS_CLASS_IN);
				GlobalRunningStatus.LocalAddress_Length[1U] += sizeof(dns_qry);

			//Read addresses list and convert to Fully Qualified Domain Name/FQDN PTR.
			#if defined(PLATFORM_WIN)
				for (LocalAddressTableIter = LocalAddressList;LocalAddressTableIter != nullptr;LocalAddressTableIter = LocalAddressTableIter->ai_next)
				{
					if (LocalAddressTableIter->ai_family == AF_INET && LocalAddressTableIter->ai_addrlen == sizeof(sockaddr_in) && 
						LocalAddressTableIter->ai_addr->sa_family == AF_INET)
					{
					//Mark localhost subnet(IPv4).
						if (Parameter.EDNS_ClientSubnet && !IsSubnetMark && !Parameter.LocalhostSubnet.Setting_IPv4 && 
							Parameter.LocalhostSubnet.IPv4 != nullptr && Parameter.LocalhostSubnet.IPv4->Address.ss_family == 0 && 
							!CheckSpecialAddress(&((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr, AF_INET, true, nullptr))
						{
							Parameter.LocalhostSubnet.IPv4->Address.ss_family = AF_INET;
							((PSOCKADDR_IN)&Parameter.LocalhostSubnet.IPv4->Address)->sin_addr = ((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr;
							((PSOCKADDR_IN)&Parameter.LocalhostSubnet.IPv4->Address)->sin_addr.s_impno = 0;
							Parameter.LocalhostSubnet.IPv4->Prefix = (sizeof(in_addr) - 1U) * BYTES_TO_BITS; //Keep 24 bits of IPv4 address, see https://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02.

							IsSubnetMark = true;
						}

					//Mark local addresses(B part).
						if (GlobalRunningStatus.LocalAddress_Length[1U] <= PACKET_MAXSIZE - sizeof(dns_record_a))
						{
							DNS_Record = (pdns_record_a)(GlobalRunningStatus.LocalAddress_Response[1U] + GlobalRunningStatus.LocalAddress_Length[1U]);
							((pdns_record_a)DNS_Record)->Name = htons(DNS_POINTER_QUERY);
							((pdns_record_a)DNS_Record)->Classes = htons(DNS_CLASS_IN);
							((pdns_record_a)DNS_Record)->TTL = htonl(Parameter.HostsDefaultTTL);
							((pdns_record_a)DNS_Record)->Type = htons(DNS_RECORD_A);
							((pdns_record_a)DNS_Record)->Length = htons(sizeof(in_addr));
							((pdns_record_a)DNS_Record)->Addr = ((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr;
							GlobalRunningStatus.LocalAddress_Length[1U] += sizeof(dns_record_a);
							++DNS_Header->Answer;
						}

					#if !defined(PLATFORM_MACX)
					//Initialization
						DNSPTRString.clear();
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

					//Convert from in_addr to DNS PTR.
						sprintf_s(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr.s_impno);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						sprintf_s(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr.s_lh);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						sprintf_s(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr.s_host);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						sprintf_s(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr.s_net);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						Result.append("in-addr.arpa");

					//Add to global list.
						GlobalRunningStatus.LocalAddress_ResponsePTR[1U]->push_back(Result);
						Result.clear();
						Result.shrink_to_fit();
					#endif
					}
				}
			#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
				for (InterfaceAddressIter = InterfaceAddressList;InterfaceAddressIter != nullptr;InterfaceAddressIter = InterfaceAddressIter->ifa_next)
				{
					if (InterfaceAddressIter->ifa_addr != nullptr && InterfaceAddressIter->ifa_addr->sa_family == AF_INET)
					{
					//Mark localhost subnet(IPv4).
						if (Parameter.EDNS_ClientSubnet && !IsSubnetMark && !Parameter.LocalhostSubnet.Setting_IPv4 && 
							Parameter.LocalhostSubnet.IPv4 != nullptr && Parameter.LocalhostSubnet.IPv4->Address.ss_family == 0 && 
							!CheckSpecialAddress(&((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr, AF_INET, true, nullptr))
						{
							Parameter.LocalhostSubnet.IPv4->Address.ss_family = AF_INET;
							((PSOCKADDR_IN)&Parameter.LocalhostSubnet.IPv4->Address)->sin_addr = ((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr;
							((PSOCKADDR_IN)&Parameter.LocalhostSubnet.IPv4->Address)->sin_addr.s_impno = 0;
							Parameter.LocalhostSubnet.IPv4->Prefix = (sizeof(in_addr) - 1U) * BYTES_TO_BITS; //Keep 24 bits of IPv4 address, see https://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02.

							IsSubnetMark = true;
						}

					//Mark local addresses(B part).
						if (GlobalRunningStatus.LocalAddress_Length[1U] <= PACKET_MAXSIZE - sizeof(dns_record_a))
						{
							DNS_Record = (pdns_record_a)(GlobalRunningStatus.LocalAddress_Response[1U] + GlobalRunningStatus.LocalAddress_Length[1U]);
							((pdns_record_a)DNS_Record)->Name = htons(DNS_POINTER_QUERY);
							((pdns_record_a)DNS_Record)->Classes = htons(DNS_CLASS_IN);
							((pdns_record_a)DNS_Record)->TTL = htonl(Parameter.HostsDefaultTTL);
							((pdns_record_a)DNS_Record)->Type = htons(DNS_RECORD_A);
							((pdns_record_a)DNS_Record)->Length = htons(sizeof(in_addr));
							((pdns_record_a)DNS_Record)->Addr = ((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr;
							GlobalRunningStatus.LocalAddress_Length[1U] += sizeof(dns_record_a);
							++DNS_Header->Answer;
						}

					#if !defined(PLATFORM_MACX)
					//Initialization
						DNSPTRString.clear();
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);

					//Convert from in_addr to DNS PTR.
						snprintf(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr.s_impno);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						snprintf(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr.s_lh);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						snprintf(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr.s_host);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						snprintf(Addr.get(), ADDR_STRING_MAXSIZE, "%u", ((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr.s_net);
						Result.append(Addr.get());
						memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
						Result.append(".");
						Result.append("in-addr.arpa");

					//Add to global list.
						GlobalRunningStatus.LocalAddress_ResponsePTR[1U]->push_back(Result);
						Result.clear();
						Result.shrink_to_fit();
					#endif
					}
				}
			#endif

			//Mark local addresses(C part).
				if (DNS_Header->Answer == 0)
				{
					memset(GlobalRunningStatus.LocalAddress_Response[1U], 0, PACKET_MAXSIZE);
					GlobalRunningStatus.LocalAddress_Length[1U] = 0;
				}
				else {
					DNS_Header->Answer = htons(DNS_Header->Answer);
				}

			//Free all lists.
				LocalAddressMutexIPv4.unlock();
			#if defined(PLATFORM_WIN)
				freeaddrinfo(LocalAddressList);
				LocalAddressList = nullptr;
			#endif

			//Reset localhost subnet settings if there no any addresses which can be marked.
				if (Parameter.EDNS_ClientSubnet && Parameter.LocalhostSubnet.IPv4 != nullptr && !IsSubnetMark && !Parameter.LocalhostSubnet.Setting_IPv4)
				{
					Parameter.LocalhostSubnet.IPv4->Prefix = 0;
					memset(&Parameter.LocalhostSubnet.IPv4->Address, 0, sizeof(sockaddr_storage));
				}
			}
		}

	//Free all lists.
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (InterfaceAddressList != nullptr)
			freeifaddrs(InterfaceAddressList);
		InterfaceAddressList = nullptr;
	#endif

	//Get gateway information and check.
		GetGatewayInformation(AF_INET6);
		GetGatewayInformation(AF_INET);
		if (!GlobalRunningStatus.GatewayAvailable_IPv4)
		{
		#if defined(PLATFORM_WIN)
			if (!GlobalRunningStatus.GatewayAvailable_IPv6)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (!IsErrorFirstPrint && !GlobalRunningStatus.GatewayAvailable_IPv6)
		#endif
				PrintError(LOG_ERROR_NETWORK, L"Not any available gateways to public network", 0, nullptr, 0);

		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			IsErrorFirstPrint = false;
		#endif
		}

	//Auto-refresh
		Sleep(Parameter.FileRefreshTime);
	}

//Monitor terminated
	PrintError(LOG_ERROR_SYSTEM, L"Get Local Address Information module Monitor terminated", 0, nullptr, 0);
	return;
}
