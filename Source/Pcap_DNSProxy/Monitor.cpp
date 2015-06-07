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
bool __fastcall MonitorInit(void)
{
//Capture initialization
#if defined(ENABLE_PCAP)
	#if defined(ENABLE_LIBSODIUM)
		if (Parameter.PcapCapture && !Parameter.HostsOnly && !(Parameter.DNSCurve && DNSCurveParameter.IsEncryption && DNSCurveParameter.IsEncryptionOnly))
	#else
		if (Parameter.PcapCapture && !Parameter.HostsOnly)
	#endif
	{
	#if defined(ENABLE_PCAP)
		std::thread CaptureInitializationThread(CaptureInit);
		CaptureInitializationThread.detach();
	#endif

	//Get Hop Limits/TTL with normal DNS request.
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && 
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
			Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0)) //Non-IPv4
		{
			std::thread IPv6TestDoaminThread(DomainTestRequest, AF_INET6);
			IPv6TestDoaminThread.detach();
		}

		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 &&
			(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
			Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0)) //Non-IPv6
		{
			std::thread IPv4TestDoaminThread(DomainTestRequest, AF_INET);
			IPv4TestDoaminThread.detach();
		}

	//Get Hop Limits/TTL with ICMP Echo.
		if (Parameter.ICMP_Speed > 0)
		{
		//ICMPv6
			if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 &&
				(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV6 || //IPv6
				Parameter.RequestMode_Network == REQUEST_MODE_IPV4 && Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0)) //Non-IPv4
			{
				std::thread ICMPv6Thread(ICMPEcho, AF_INET6);
				ICMPv6Thread.detach();
			}

		//ICMP
			if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 &&
				(Parameter.RequestMode_Network == REQUEST_MODE_NETWORK_BOTH || Parameter.RequestMode_Network == REQUEST_MODE_IPV4 || //IPv4
				Parameter.RequestMode_Network == REQUEST_MODE_IPV6 && Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0)) //Non-IPv6
			{
				std::thread ICMPThread(ICMPEcho, AF_INET);
				ICMPThread.detach();
			}
		}
	}
#endif

//Set Preferred DNS servers switcher.
	if (!Parameter.AlternateMultiRequest && 
		(Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0
	#if defined(ENABLE_LIBSODIUM)
		|| DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 || DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0
	#endif
		) || Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0)
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
				Parameter.LocalSocket->push_back(LocalSocketData->Socket);
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
							if (LocalSocketData->Socket == INVALID_SOCKET)
							{
								PrintError(LOG_ERROR_NETWORK, L"IPv6 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
								break;
							}

							Parameter.LocalSocket->push_back(LocalSocketData->Socket);
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
								if (LocalSocketData->Socket == INVALID_SOCKET)
								{
									PrintError(LOG_ERROR_NETWORK, L"IPv6 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
									break;
								}

								Parameter.LocalSocket->push_back(LocalSocketData->Socket);
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
				Parameter.LocalSocket->push_back(LocalSocketData->Socket);
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
							if (LocalSocketData->Socket == INVALID_SOCKET)
							{
								PrintError(LOG_ERROR_NETWORK, L"IPv6 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
								break;
							}

							Parameter.LocalSocket->push_back(LocalSocketData->Socket);
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
								if (LocalSocketData->Socket == INVALID_SOCKET)
								{
									PrintError(LOG_ERROR_NETWORK, L"IPv6 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
									break;
								}

								Parameter.LocalSocket->push_back(LocalSocketData->Socket);
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
			if (LocalSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"IPv4 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
			}
			else {
				Parameter.LocalSocket->push_back(LocalSocketData->Socket);
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
							if (LocalSocketData->Socket == INVALID_SOCKET)
							{
								PrintError(LOG_ERROR_NETWORK, L"IPv4 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
								break;
							}

							Parameter.LocalSocket->push_back(LocalSocketData->Socket);
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
								if (LocalSocketData->Socket == INVALID_SOCKET)
								{
									PrintError(LOG_ERROR_NETWORK, L"IPv4 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
									break;
								}

								Parameter.LocalSocket->push_back(LocalSocketData->Socket);
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
			if (LocalSocketData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_NETWORK, L"IPv4 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
			}
			else {
				Parameter.LocalSocket->push_back(LocalSocketData->Socket);
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
							if (LocalSocketData->Socket == INVALID_SOCKET)
							{
								PrintError(LOG_ERROR_NETWORK, L"IPv4 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
								break;
							}

							Parameter.LocalSocket->push_back(LocalSocketData->Socket);
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
								if (LocalSocketData->Socket == INVALID_SOCKET)
								{
									PrintError(LOG_ERROR_NETWORK, L"IPv4 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
									break;
								}

								Parameter.LocalSocket->push_back(LocalSocketData->Socket);
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
	for (size_t Index = 0;Index < MonitorThread.size();++Index)
	{
		if (MonitorThread.at(Index).joinable())
			MonitorThread.at(Index).join();
	}

	return true;
}

//Local DNS server with UDP protocol
bool __fastcall UDPMonitor(const SOCKET_DATA LocalSocketData)
{
	SSIZE_T RecvLen = 0;

#if defined(PLATFORM_WIN)
//Block WSAECONNRESET error of UDP Monitor.
	DWORD BytesReturned = 0;
	BOOL NewBehavior = FALSE;
	RecvLen = WSAIoctl(LocalSocketData.Socket, SIO_UDP_CONNRESET, &NewBehavior, sizeof(BOOL), nullptr, 0, &BytesReturned, nullptr, nullptr);
	if (RecvLen == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket SIO_UDP_CONNRESET error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return false;
	}
#endif

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(int)) == SOCKET_ERROR ||
		setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(int)) == SOCKET_ERROR)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.SocketTimeout_Unreliable, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return false;
	}

//Preventing other sockets from being forcibly bound to the same address and port(Windows).
//Set TIME_WAIT resuing(Linux).
#if defined(PLATFORM_WIN)
//Socket reuse setting
	int SetVal = 1;
	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket disable reusing error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return false;
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Socket reuse setting
	int SetVal = 1;
	/*	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
		{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket enable reusing error", errno, nullptr, 0);
		close(LocalSocketData.Socket);

		return false;
		}
		*/
//Set an IPv6 server socket that cannot accept IPv4 connections on Linux.
//	SetVal = 1;
	if (LocalSocketData.SockAddr.ss_family == AF_INET6 && Parameter.OperationMode != LISTEN_MODE_PROXY && 
		setsockopt(LocalSocketData.Socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket treating wildcard bind error", errno, nullptr, 0);
		close(LocalSocketData.Socket);

		return false;
	}
#endif

//Bind socket to port.
	if (bind(LocalSocketData.Socket, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Bind UDP Monitor socket error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return false;
	}

//Initialization
	std::shared_ptr<char> Buffer(new char[PACKET_MAXSIZE * Parameter.BufferQueueSize]());
	memset(Buffer.get(), 0, PACKET_MAXSIZE * Parameter.BufferQueueSize);
	uint64_t LastMarkTime = 0, NowTime = 0;
	if (Parameter.QueueResetTime > 0)
	{
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		if (Parameter.GetTickCount64_PTR != nullptr)
			LastMarkTime = (*Parameter.GetTickCount64_PTR)();
		else 
			LastMarkTime = GetTickCount();
	#else
		LastMarkTime = GetTickCount64();
	#endif
	}
	void *Addr = nullptr;
	pdns_hdr DNS_Header = nullptr;
	size_t Index[] = {0, 0};

//Start Monitor.
	for (;;)
	{
		memset(Buffer.get() + PACKET_MAXSIZE * Index[0], 0, PACKET_MAXSIZE);
		Sleep(LOOP_INTERVAL_TIME);
	
	//Interval time between receive
		if (Parameter.QueueResetTime > 0 && Index[0] + 1U == Parameter.BufferQueueSize)
		{
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (Parameter.GetTickCount64_PTR != nullptr)
				NowTime = (*Parameter.GetTickCount64_PTR)();
			else 
				NowTime = GetTickCount();
		#else
			NowTime = GetTickCount64();
		#endif
			if (LastMarkTime + Parameter.QueueResetTime > NowTime)
				Sleep(LastMarkTime + Parameter.QueueResetTime - NowTime);

		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (Parameter.GetTickCount64_PTR != nullptr)
				LastMarkTime = (*Parameter.GetTickCount64_PTR)();
			else
				LastMarkTime = GetTickCount();
		#else
			LastMarkTime = GetTickCount64();
		#endif
		}

	//Receive
		if (Parameter.EDNS_Label) //EDNS Label
			RecvLen = recvfrom(LocalSocketData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], PACKET_MAXSIZE - EDNS_ADDITIONAL_MAXSIZE, 0, (PSOCKADDR)&LocalSocketData.SockAddr, (socklen_t *)&LocalSocketData.AddrLen);
		else 
			RecvLen = recvfrom(LocalSocketData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], PACKET_MAXSIZE, 0, (PSOCKADDR)&LocalSocketData.SockAddr, (socklen_t *)&LocalSocketData.AddrLen);

	//Check address.
		if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			Addr = &((PSOCKADDR_IN6)&LocalSocketData.SockAddr)->sin6_addr;
			if (CheckEmptyBuffer(Addr, sizeof(in6_addr)) || //Empty address
			//Check Private Mode(IPv6).
				Parameter.OperationMode == LISTEN_MODE_PRIVATE && 
				!(((in6_addr *)Addr)->s6_bytes[0] >= 0xFC && ((in6_addr *)Addr)->s6_bytes[0] <= 0xFD || //Unique Local Unicast address/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
				((in6_addr *)Addr)->s6_bytes[0] == 0xFE && ((in6_addr *)Addr)->s6_bytes[1U] >= 0x80 && ((in6_addr *)Addr)->s6_bytes[1U] <= 0xBF || //Link-Local Unicast Contrast address(FE80::/10, Section 2.5.6 in RFC 4291)
				((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x0001)) || //Loopback address(::1, Section 2.5.3 in RFC 4291)
			//Check Custom Mode(IPv6).
				Parameter.OperationMode == LISTEN_MODE_CUSTOM && !CheckCustomModeFilter(Addr, AF_INET6))
					continue;
		}
		else { //IPv4
			Addr = &((PSOCKADDR_IN)&LocalSocketData.SockAddr)->sin_addr;
			if ((*(in_addr *)Addr).s_addr == 0 || //Empty address
			//Check Private Mode(IPv4).
				Parameter.OperationMode == LISTEN_MODE_PRIVATE && 
				!(((in_addr *)Addr)->s_net == 0x0A || //Private class A address(10.0.0.0/8, Section 3 in RFC 1918)
				((in_addr *)Addr)->s_net == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
				((in_addr *)Addr)->s_net == 0xAC && ((in_addr *)Addr)->s_host >= 0x10 && ((in_addr *)Addr)->s_host <= 0x1F || //Private class B address(172.16.0.0/16, Section 3 in RFC 1918)
				((in_addr *)Addr)->s_net == 0xC0 && ((in_addr *)Addr)->s_host == 0xA8) || //Private class C address(192.168.0.0/24, Section 3 in RFC 1918)
			//Check Custom Mode(IPv4).
				Parameter.OperationMode == LISTEN_MODE_CUSTOM && !CheckCustomModeFilter(Addr, AF_INET))
					continue;
		}

	//UDP Truncated check
		if (RecvLen > (SSIZE_T)(Parameter.EDNSPayloadSize - EDNS_ADDITIONAL_MAXSIZE) && 
			(Parameter.EDNS_Label || RecvLen > (SSIZE_T)Parameter.EDNSPayloadSize))
		{
		//Make packets with EDNS Lebal.
			DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_RTC);
			pdns_record_opt DNS_Record_OPT = nullptr;
			if (DNS_Header->Additional == 0)
			{
				DNS_Header->Additional = htons(U16_NUM_ONE);
				DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen);
				DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
				DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNSPayloadSize);
				RecvLen += sizeof(dns_record_opt);
			}
			else if (DNS_Header->Additional == htons(U16_NUM_ONE))
			{
				DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen - sizeof(dns_record_opt));
				if (DNS_Record_OPT->Type == htons(DNS_RECORD_OPT))
					DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNSPayloadSize);
			}
			else {
				continue;
			}

		//Send requesting.
			sendto(LocalSocketData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], (int)RecvLen, 0, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen);
			continue;
		}

	//Receive process.
		if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
		{
		//Check requesting.
			DNS_Header = (pdns_hdr)(Buffer.get() + PACKET_MAXSIZE * Index[0]);
			if (DNS_Header->Questions != htons(U16_NUM_ONE) || DNS_Header->Answer > 0 || ntohs(DNS_Header->Additional) > U16_NUM_ONE || DNS_Header->Authority > 0)
				continue;
			for (Index[1U] = sizeof(dns_hdr);Index[1U] < DNS_PACKET_QUERY_LOCATE(Buffer.get() + PACKET_MAXSIZE * Index[0]);++Index[1U])
			{
				if (*(Buffer.get() + PACKET_MAXSIZE * Index[0] + Index[1U]) == DNS_POINTER_BITS_STRING)
					continue;
			}
			if (Index[1U] != DNS_PACKET_QUERY_LOCATE(Buffer.get() + PACKET_MAXSIZE * Index[0]))
			{
				DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R_FE);
				sendto(LocalSocketData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], (int)RecvLen, 0, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen);
				continue;
			}

		//EDNS Label
			if (Parameter.EDNS_Label)
				RecvLen = AddEDNS_LabelToAdditionalRR(Buffer.get() + PACKET_MAXSIZE * Index[0], (size_t)RecvLen);

		//Request process
			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				std::thread RequestProcessThread(EnterRequestProcess, Buffer.get() + PACKET_MAXSIZE * Index[0], RecvLen, LocalSocketData, IPPROTO_UDP);
				RequestProcessThread.detach();
			}
			else { //IPv4
				std::thread RequestProcessThread(EnterRequestProcess, Buffer.get() + PACKET_MAXSIZE * Index[0], RecvLen, LocalSocketData, IPPROTO_UDP);
				RequestProcessThread.detach();
			}

			Index[0] = (Index[0] + 1U) % Parameter.BufferQueueSize;
		}
		else { //Incorrect packets
			continue;
		}
	}

	shutdown(LocalSocketData.Socket, SD_BOTH);
	closesocket(LocalSocketData.Socket);
	PrintError(LOG_ERROR_SYSTEM, L"UDP listening module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Local DNS server with TCP protocol
bool __fastcall TCPMonitor(const SOCKET_DATA LocalSocketData)
{
//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Reliable, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.SocketTimeout_Reliable, sizeof(int)) == SOCKET_ERROR)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.SocketTimeout_Reliable, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.SocketTimeout_Reliable, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		PrintError(LOG_ERROR_NETWORK, L"Set TCP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return false;
	}

//Preventing other sockets from being forcibly bound to the same address and port(Windows).
//Set TIME_WAIT resuing(Linux).
#if defined(PLATFORM_WIN)
//Socket reuse setting
	int SetVal = 1;
	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set TCP socket disable reusing error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return false;
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Socket reuse setting
	int SetVal = 1;
/*	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set TCP socket enable reusing error", errno, nullptr, 0);
		close(LocalSocketData.Socket);

		return false;
	}
*/
//Create an IPv6 server socket that can also accept IPv4 connections on Linux.
//	SetVal = 1;
	if (LocalSocketData.SockAddr.ss_family == AF_INET6 && Parameter.OperationMode != LISTEN_MODE_PROXY && 
		setsockopt(LocalSocketData.Socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set TCP socket treating wildcard bind error", errno, nullptr, 0);
		close(LocalSocketData.Socket);

		return false;
	}
#endif

//Bind socket to port.
	if (bind(LocalSocketData.Socket, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Bind TCP Monitor socket error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return false;
	}

//Listen requesting from socket.
	if (listen(LocalSocketData.Socket, SOMAXCONN) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"TCP Monitor socket listening initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return false;
	}

//Initialization
	std::shared_ptr<SOCKET_DATA> ClientData(new SOCKET_DATA());
	ClientData->AddrLen = LocalSocketData.AddrLen;
	uint64_t LastMarkTime = 0, NowTime = 0;
	if (Parameter.QueueResetTime > 0)
	{
	#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
		if (Parameter.GetTickCount64_PTR != nullptr)
			LastMarkTime = (*Parameter.GetTickCount64_PTR)();
		else
			LastMarkTime = GetTickCount();
	#else
		LastMarkTime = GetTickCount64();
	#endif
	}
	void *Addr = nullptr;
	size_t Index = 0;

//Start Monitor.
	for (;;)
	{
		memset(&ClientData->SockAddr, 0, sizeof(sockaddr_storage));
		Sleep(LOOP_INTERVAL_TIME);

	//Interval time between receive
		if (Parameter.QueueResetTime > 0 && Index + 1U == Parameter.BufferQueueSize)
		{
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (Parameter.GetTickCount64_PTR != nullptr)
				NowTime = (*Parameter.GetTickCount64_PTR)();
			else 
				NowTime = GetTickCount();
		#else
			NowTime = GetTickCount64();
		#endif
			if (LastMarkTime + Parameter.QueueResetTime > NowTime)
				Sleep(LastMarkTime + Parameter.QueueResetTime - NowTime);

		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (Parameter.GetTickCount64_PTR != nullptr)
				LastMarkTime = (*Parameter.GetTickCount64_PTR)();
			else
				LastMarkTime = GetTickCount();
		#else
			LastMarkTime = GetTickCount64();
		#endif
		}

	//Accept connection.
		ClientData->Socket = accept(LocalSocketData.Socket, (PSOCKADDR)&ClientData->SockAddr, &ClientData->AddrLen);
		if (ClientData->Socket == INVALID_SOCKET)
			continue;

	//Check address.
		if (ClientData->AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			Addr = &((PSOCKADDR_IN6)&ClientData->SockAddr)->sin6_addr;
			if (CheckEmptyBuffer(Addr, sizeof(in6_addr)) || //Empty address
			//Check Private Mode(IPv6).
				(Parameter.OperationMode == LISTEN_MODE_PRIVATE && 
				!(((in6_addr *)Addr)->s6_bytes[0] >= 0xFC && ((in6_addr *)Addr)->s6_bytes[0] <= 0xFD || //Unique Local Unicast address/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
				((in6_addr *)Addr)->s6_bytes[0] == 0xFE && ((in6_addr *)Addr)->s6_bytes[1U] >= 0x80 && ((in6_addr *)Addr)->s6_bytes[1U] <= 0xBF || //Link-Local Unicast Contrast address(FE80::/10, Section 2.5.6 in RFC 4291)
				((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x0001))) || //Loopback address(::1, Section 2.5.3 in RFC 4291)
			//Check Custom Mode(IPv6).
				(Parameter.OperationMode == LISTEN_MODE_CUSTOM && !CheckCustomModeFilter(Addr, AF_INET6)))
			{
				shutdown(LocalSocketData.Socket, SD_BOTH);
				closesocket(ClientData->Socket);
				continue;
			}
		}
		else { //IPv4
			Addr = &((PSOCKADDR_IN)&ClientData->SockAddr)->sin_addr;
			if ((*(in_addr *)Addr).s_addr == 0 || //Empty address
			//Check Private Mode(IPv4).
				(Parameter.OperationMode == LISTEN_MODE_PRIVATE && 
				!(((in_addr *)Addr)->s_net == 0x0A || //Private class A address(10.0.0.0/8, Section 3 in RFC 1918)
				((in_addr *)Addr)->s_net == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
				((in_addr *)Addr)->s_net == 0xAC && ((in_addr *)Addr)->s_host >= 0x10 && ((in_addr *)Addr)->s_host <= 0x1F || //Private class B address(172.16.0.0/16, Section 3 in RFC 1918)
				((in_addr *)Addr)->s_net == 0xC0 && ((in_addr *)Addr)->s_host == 0xA8)) || //Private class C address(192.168.0.0/24, Section 3 in RFC 1918)
			//Check Custom Mode(IPv4).
				(Parameter.OperationMode == LISTEN_MODE_CUSTOM && !CheckCustomModeFilter(Addr, AF_INET)))
			{
				shutdown(LocalSocketData.Socket, SD_BOTH);
				closesocket(ClientData->Socket);
				continue;
			}
		}

	//Accept process.
		std::thread TCPReceiveThread(TCPReceiveProcess, *ClientData);
		TCPReceiveThread.detach();
		Index = (Index + 1U) % Parameter.BufferQueueSize;
	}

	shutdown(LocalSocketData.Socket, SD_BOTH);
	closesocket(LocalSocketData.Socket);
	PrintError(LOG_ERROR_SYSTEM, L"TCP listening module Monitor terminated", 0, nullptr, 0);
	return true;
}

//TCP protocol receive process
bool __fastcall TCPReceiveProcess(const SOCKET_DATA LocalSocketData)
{
	std::shared_ptr<char> Buffer(new char[LARGE_PACKET_MAXSIZE]());
	memset(Buffer.get(), 0, LARGE_PACKET_MAXSIZE);
	size_t InnerIndex = 0;
	SSIZE_T RecvLen = 0;

//Receive
	if (Parameter.EDNS_Label) //EDNS Label
		RecvLen = recv(LocalSocketData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE - EDNS_ADDITIONAL_MAXSIZE, 0);
	else 
		RecvLen = recv(LocalSocketData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE, 0);
	if (RecvLen == (SSIZE_T)sizeof(uint16_t)) //TCP segment of a reassembled PDU
	{
	//Receive without PDU.
		uint16_t PDU_Len = ntohs(((uint16_t *)Buffer.get())[0]);
		if (PDU_Len > LARGE_PACKET_MAXSIZE)
		{
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
			return false;
		}
		memset(Buffer.get(), 0, RecvLen);
		if (Parameter.EDNS_Label) //EDNS Label
			RecvLen = recv(LocalSocketData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE - EDNS_ADDITIONAL_MAXSIZE, 0);
		else 
			RecvLen = recv(LocalSocketData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE, 0);

	//Receive packet.
		if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && RecvLen >= (SSIZE_T)PDU_Len)
		{
		//Check requesting.
			auto DNS_Header = (pdns_hdr)Buffer.get();
			if (DNS_Header->Questions != htons(U16_NUM_ONE) || (ntohs(DNS_Header->Flags) & DNS_GET_BIT_RESPONSE) > 0 || 
				DNS_Header->Answer > 0 || ntohs(DNS_Header->Additional) > U16_NUM_ONE || DNS_Header->Authority > 0)
			{
				shutdown(LocalSocketData.Socket, SD_BOTH);
				closesocket(LocalSocketData.Socket);
				return false;
			}
			for (InnerIndex = sizeof(dns_hdr);InnerIndex < DNS_PACKET_QUERY_LOCATE(Buffer.get());++InnerIndex)
			{
				if (*(Buffer.get() + InnerIndex) == DNS_POINTER_BITS_STRING)
					break;
			}
			if (InnerIndex != DNS_PACKET_QUERY_LOCATE(Buffer.get()))
			{
				DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R_FE);
				send(LocalSocketData.Socket, Buffer.get(), (int)RecvLen, 0);

				shutdown(LocalSocketData.Socket, SD_BOTH);
				closesocket(LocalSocketData.Socket);
				return false;
			}

		//EDNS Label
			if (Parameter.EDNS_Label)
				RecvLen = AddEDNS_LabelToAdditionalRR(Buffer.get(), (size_t)RecvLen);

		//Requesting process
			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				EnterRequestProcess(Buffer.get(), PDU_Len, LocalSocketData, IPPROTO_TCP);
			else //IPv4
				EnterRequestProcess(Buffer.get(), PDU_Len, LocalSocketData, IPPROTO_TCP);
		}
		else {
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
			return false;
		}
	}
	else if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && RecvLen >= (SSIZE_T)htons(((uint16_t *)Buffer.get())[0]) && htons(((uint16_t *)Buffer.get())[0]) < LARGE_PACKET_MAXSIZE)
	{
		RecvLen = htons(((uint16_t *)Buffer.get())[0]);

	//Check requesting.
		auto DNS_Header = (pdns_hdr)(Buffer.get() + sizeof(uint16_t));
		if (DNS_Header->Questions != htons(U16_NUM_ONE) || (ntohs(DNS_Header->Flags) & DNS_GET_BIT_RESPONSE) > 0 ||
			DNS_Header->Answer > 0 || ntohs(DNS_Header->Additional) > U16_NUM_ONE || DNS_Header->Authority > 0)
		{
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
			return false;
		}
		for (InnerIndex = sizeof(dns_tcp_hdr);InnerIndex < DNS_TCP_PACKET_QUERY_LOCATE(Buffer.get());++InnerIndex)
		{
			if (*(Buffer.get() + InnerIndex) == DNS_POINTER_BITS_STRING)
				break;
		}
		if (InnerIndex != DNS_TCP_PACKET_QUERY_LOCATE(Buffer.get()))
		{
			DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R_FE);
			send(LocalSocketData.Socket, Buffer.get(), (int)RecvLen + sizeof(uint16_t), 0);

			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
			return false;
		}

	//EDNS Label
		if (Parameter.EDNS_Label)
			RecvLen = AddEDNS_LabelToAdditionalRR(Buffer.get() + sizeof(uint16_t), (size_t)RecvLen);

	//Requesting process
		if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			EnterRequestProcess(Buffer.get() + sizeof(uint16_t), RecvLen, LocalSocketData, IPPROTO_TCP);
		else //IPv4
			EnterRequestProcess(Buffer.get() + sizeof(uint16_t), RecvLen, LocalSocketData, IPPROTO_TCP);
	}
	else {
		shutdown(LocalSocketData.Socket, SD_BOTH);
		closesocket(LocalSocketData.Socket);
		return false;
	}

//Block Port Unreachable messages of system.
	shutdown(LocalSocketData.Socket, SD_BOTH);
#if defined(PLATFORM_WIN)
	Sleep(Parameter.SocketTimeout_Reliable);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	usleep(Parameter.SocketTimeout_Reliable.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.SocketTimeout_Reliable.tv_usec);
#endif
	closesocket(LocalSocketData.Socket);
	return true;
}

//Alternate DNS servers switcher
void __fastcall AlternateServerMonitor(void)
{
	size_t Index = 0, RangeTimer[ALTERNATE_SERVERNUM] = {0}, SwapTimer[ALTERNATE_SERVERNUM] = {0};

//Switcher
//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
	for (;;)
	{
	//Complete Requesting check
		for (Index = 0;Index < ALTERNATE_SERVERNUM;++Index)
		{
		//Reset TimeoutTimes out of alternate time range.
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (Parameter.GetTickCount64_PTR != nullptr && (*Parameter.GetTickCount64_PTR)() >= RangeTimer[Index] || GetTickCount() >= RangeTimer[Index])
			{
				if (Parameter.GetTickCount64_PTR != nullptr)
					RangeTimer[Index] = (size_t)((*Parameter.GetTickCount64_PTR)() + Parameter.AlternateTimeRange);
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
				if (Parameter.GetTickCount64_PTR != nullptr && (*Parameter.GetTickCount64_PTR)() >= SwapTimer[Index] || GetTickCount() >= SwapTimer[Index])
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
					if (Parameter.GetTickCount64_PTR != nullptr)
						SwapTimer[Index] = (size_t)((*Parameter.GetTickCount64_PTR)() + Parameter.AlternateResetTime);
					else 
						SwapTimer[Index] = GetTickCount() + Parameter.AlternateResetTime;
				#else
					SwapTimer[Index] = GetTickCount64() + Parameter.AlternateResetTime;
				#endif
				}
			}
		}

		Sleep(MONITOR_LOOP_INTERVAL_TIME);
	}

	PrintError(LOG_ERROR_SYSTEM, L"Alternate Server module Monitor terminated", 0, nullptr, 0);
	return;
}

//Get local address list
#if defined(PLATFORM_WIN)
PADDRINFOA __fastcall GetLocalAddressList(const uint16_t Protocol)
{
//Initialization
	std::shared_ptr<char> HostName(new char[DOMAIN_MAXSIZE]());
	memset(HostName.get(), 0, DOMAIN_MAXSIZE);
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
	if (gethostname(HostName.get(), DOMAIN_MAXSIZE) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Get localhost name error", WSAGetLastError(), nullptr, 0);
		return nullptr;
	}

//Get localhost data.
	int ResultGetaddrinfo = getaddrinfo(HostName.get(), nullptr, Hints.get(), &Result);
	if (ResultGetaddrinfo != 0)
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
bool GetBestInterfaceAddress(const uint16_t Protocol, const sockaddr_storage *OriginalSockAddr)
{
//Initialization
	std::shared_ptr<sockaddr_storage> SockAddr(new sockaddr_storage());
	memset(SockAddr.get(), 0, sizeof(sockaddr_storage));
	SockAddr->ss_family = Protocol;
	SOCKET InterfaceSocket = socket(Protocol, SOCK_DGRAM, IPPROTO_UDP);
	socklen_t AddrLen = 0;

//Check socket.
	if (InterfaceSocket == INVALID_SOCKET)
	{
		Parameter.TunnelAvailable_IPv6 = false;
		if (Protocol == AF_INET6)
			Parameter.GatewayAvailable_IPv6 = false;
		else //IPv4
			Parameter.GatewayAvailable_IPv4 = false;

		PrintError(LOG_ERROR_NETWORK, L"UDP request initialization error", WSAGetLastError(), nullptr, 0);
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
			Parameter.GatewayAvailable_IPv6 = false;
			Parameter.TunnelAvailable_IPv6 = false;

			close(InterfaceSocket);
			return false;
		}

	//Address check(IPv6 tunnels support: 6to4, ISATAP and Teredo)
		if (((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[0] == htons(0x2001) && ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[1U] == 0 || //Teredo relay/tunnel Addresses(2001::/32, RFC 4380)
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[0] == htons(0x2002) || //6to4 relay/tunnel Addresses(2002::/16, Section 2 in RFC 3056)
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[0] >= 0x80 && ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[1U] <= 0xBF && //Link-Local Unicast Contrast Addresses/LUC(FE80::/10, Section 2.5.6 in RFC 4291)
			((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[4U] == 0 && ((PSOCKADDR_IN6)SockAddr.get())->sin6_addr.__u6_addr16[5U] == htons(0x5EFE)) //ISATAP Interface Identifiers Addresses(Prefix:0:5EFE:0:0:0:0/64, which also in Link-Local Unicast Contrast Addresses/LUC, Section 6.1 in RFC 5214)
				Parameter.TunnelAvailable_IPv6 = true;
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
			Parameter.GatewayAvailable_IPv4 = false;
			Parameter.TunnelAvailable_IPv6 = false;

			close(InterfaceSocket);
			return false;
		}
	}

	close(InterfaceSocket);
	return true;
}
#endif

//Get gateway information
void __fastcall GetGatewayInformation(const uint16_t Protocol)
{
//IPv6
	if (Protocol == AF_INET6)
	{
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0 && 
			Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family == 0
		#if defined(ENABLE_LIBSODIUM)
			&& DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family == 0
		#endif
			)
		{
			Parameter.GatewayAvailable_IPv6 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}
	#if defined(PLATFORM_WIN)
		DWORD AdaptersIndex = 0;
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Local_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR
		#if defined(ENABLE_LIBSODIUM)
			|| DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.IPv6, &AdaptersIndex) != NO_ERROR
		#endif
			)
		{
			Parameter.GatewayAvailable_IPv6 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}

	//IPv6 Multi
		if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				if (GetBestInterfaceEx((PSOCKADDR)&DNSServerDataIter.AddressData.IPv6, &AdaptersIndex) != NO_ERROR)
				{
					Parameter.GatewayAvailable_IPv6 = false;
					Parameter.TunnelAvailable_IPv6 = false;
					return;
				}
			}
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET6, &Parameter.DNSTarget.IPv6.AddressData.Storage) || 
			Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET6, &Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage) || 
			Parameter.DNSTarget.Local_IPv6.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET6, &Parameter.DNSTarget.Local_IPv6.AddressData.Storage) || 
			Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET6, &Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage)
		#if defined(ENABLE_LIBSODIUM)
			|| DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET6, &DNSCurveParameter.DNSCurveTarget.IPv6.AddressData.Storage) || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET6, &DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage)
		#endif
			)
		{
			Parameter.GatewayAvailable_IPv6 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}

	//IPv6 Multi
		if (Parameter.DNSTarget.IPv6_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv6_Multi)
			{
				if (!GetBestInterfaceAddress(AF_INET6, &DNSServerDataIter.AddressData.Storage))
				{
					Parameter.GatewayAvailable_IPv6 = false;
					Parameter.TunnelAvailable_IPv6 = false;
					return;
				}
			}
		}
	#endif

		Parameter.GatewayAvailable_IPv6 = true;
		Parameter.TunnelAvailable_IPv6 = true;
	}
//IPv4
	else {
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family == 0 && 
			Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family == 0 && Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family == 0
		#if defined(ENABLE_LIBSODIUM)
			&& DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family == 0 && DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family == 0
		#endif
			)
		{
			Parameter.GatewayAvailable_IPv4 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}
	#if defined(PLATFORM_WIN)
		DWORD AdaptersIndex = 0;
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Local_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR
		#if defined(ENABLE_LIBSODIUM)
			|| DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && GetBestInterfaceEx((PSOCKADDR)&DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.IPv4, &AdaptersIndex) != NO_ERROR
		#endif
			)
		{
			Parameter.GatewayAvailable_IPv4 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}

	//IPv4 Multi
		if (Parameter.DNSTarget.IPv4_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				if (GetBestInterfaceEx((PSOCKADDR)&DNSServerDataIter.AddressData.IPv4, &AdaptersIndex) != NO_ERROR)
				{
					Parameter.GatewayAvailable_IPv4 = false;
					Parameter.TunnelAvailable_IPv6 = false;
					return;
				}
			}
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET, &Parameter.DNSTarget.IPv4.AddressData.Storage) || 
			Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET, &Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage) || 
			Parameter.DNSTarget.Local_IPv4.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET, &Parameter.DNSTarget.Local_IPv4.AddressData.Storage) || 
			Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET, &Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage)
		#if defined(ENABLE_LIBSODIUM)
			|| DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET, &DNSCurveParameter.DNSCurveTarget.IPv4.AddressData.Storage) || 
			DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 && !GetBestInterfaceAddress(AF_INET, &DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage)
		#endif
			)
		{
			Parameter.GatewayAvailable_IPv4 = false;
			Parameter.TunnelAvailable_IPv6 = false;
			return;
		}

	//IPv4 Multi
		if (Parameter.DNSTarget.IPv4_Multi != nullptr)
		{
			for (auto DNSServerDataIter:*Parameter.DNSTarget.IPv4_Multi)
			{
				if (!GetBestInterfaceAddress(AF_INET, &DNSServerDataIter.AddressData.Storage))
				{
					Parameter.GatewayAvailable_IPv4 = false;
					Parameter.TunnelAvailable_IPv6 = false;
					return;
				}
			}
		}
	#endif

		Parameter.GatewayAvailable_IPv4 = true;
	}

	return;
}

//Local network information monitor
void __fastcall NetworkInformationMonitor(void)
{
//Initialization
	std::shared_ptr<char> Addr(new char[ADDR_STRING_MAXSIZE]());
	memset(Addr.get(), 0, ADDR_STRING_MAXSIZE);
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
	pdns_record_aaaa DNS_Record_AAAA = nullptr;
	pdns_record_a DNS_Record_A = nullptr;
	auto IsSubnetMark = false;

//Monitor
	for (;;)
	{
		IsSubnetMark = false;

	//Get localhost addresses(IPv6)
		if (Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_NETWORK_BOTH || Parameter.ListenProtocol_Network == LISTEN_PROTOCOL_IPV6)
		{
		#if defined(PLATFORM_WIN)
			LocalAddressList = GetLocalAddressList(AF_INET6);
			if (LocalAddressList == nullptr)
			{
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (getifaddrs(&InterfaceAddressList) != 0 || InterfaceAddressList == nullptr)
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
				std::unique_lock<std::mutex> LocalAddressMutexIPv6(LocalAddressLock[0]);
				memset(Parameter.LocalAddress_Response[0], 0, PACKET_MAXSIZE);
				Parameter.LocalAddress_Length[0] = 0;
			#if !defined(PLATFORM_MACX)
				std::string DNSPTRString;
				Parameter.LocalAddress_ResponsePTR[0]->clear();
				Parameter.LocalAddress_ResponsePTR[0]->shrink_to_fit();
			#endif

			//Mark local addresses(A part).
				DNS_Header = (pdns_hdr)Parameter.LocalAddress_Response[0];
				DNS_Header->Flags = htons(DNS_SQR_NEA);
				DNS_Header->Questions = htons(U16_NUM_ONE);
				Parameter.LocalAddress_Length[0] += sizeof(dns_hdr);
				memcpy_s(Parameter.LocalAddress_Response[0] + Parameter.LocalAddress_Length[0], PACKET_MAXSIZE - Parameter.LocalAddress_Length[0], Parameter.LocalFQDN_Response, Parameter.LocalFQDN_Length);
				Parameter.LocalAddress_Length[0] += Parameter.LocalFQDN_Length;
				DNS_Query = (pdns_qry)(Parameter.LocalAddress_Response[0] + Parameter.LocalAddress_Length[0]);
				DNS_Query->Type = htons(DNS_RECORD_AAAA);
				DNS_Query->Classes = htons(DNS_CLASS_IN);
				Parameter.LocalAddress_Length[0] += sizeof(dns_qry);

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
						if (Parameter.LocalAddress_Length[0] <= PACKET_MAXSIZE - sizeof(dns_record_aaaa))
						{
							DNS_Record_AAAA = (pdns_record_aaaa)(Parameter.LocalAddress_Response[0] + Parameter.LocalAddress_Length[0]);
							DNS_Record_AAAA->Name = htons(DNS_POINTER_QUERY);
							DNS_Record_AAAA->Classes = htons(DNS_CLASS_IN);
							DNS_Record_AAAA->TTL = htonl(Parameter.HostsDefaultTTL);
							DNS_Record_AAAA->Type = htons(DNS_RECORD_AAAA);
							DNS_Record_AAAA->Length = htons(sizeof(in6_addr));
							DNS_Record_AAAA->Addr = ((PSOCKADDR_IN6)LocalAddressTableIter->ai_addr)->sin6_addr;
							Parameter.LocalAddress_Length[0] += sizeof(dns_record_aaaa);
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

						//Last
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
						Parameter.LocalAddress_ResponsePTR[0]->push_back(Result);
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
						if (Parameter.LocalAddress_Length[0] <= PACKET_MAXSIZE - sizeof(dns_record_aaaa))
						{
							DNS_Record_AAAA = (pdns_record_aaaa)(Parameter.LocalAddress_Response[0] + Parameter.LocalAddress_Length[0]);
							DNS_Record_AAAA->Name = htons(DNS_POINTER_QUERY);
							DNS_Record_AAAA->Classes = htons(DNS_CLASS_IN);
							DNS_Record_AAAA->TTL = htonl(Parameter.HostsDefaultTTL);
							DNS_Record_AAAA->Type = htons(DNS_RECORD_AAAA);
							DNS_Record_AAAA->Length = htons(sizeof(in6_addr));
							DNS_Record_AAAA->Addr = ((PSOCKADDR_IN6)InterfaceAddressIter->ifa_addr)->sin6_addr;
							Parameter.LocalAddress_Length[0] += sizeof(dns_record_aaaa);
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

						//Last
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
						Parameter.LocalAddress_ResponsePTR[0]->push_back(Result);
						Result.clear();
						Result.shrink_to_fit();
					#endif
					}
				}
			#endif

			//Mark local addresses(C part).
				if (DNS_Header->Answer == 0)
				{
					memset(Parameter.LocalAddress_Response[0], 0, PACKET_MAXSIZE);
					Parameter.LocalAddress_Length[0] = 0;
				}
				else {
					DNS_Header->Answer = htons(DNS_Header->Answer);
				}

			//Add to global list.
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
			LocalAddressList = GetLocalAddressList(AF_INET);
			if (LocalAddressList == nullptr)
			{
				Sleep(Parameter.FileRefreshTime);
				continue;
			}
			else {
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			{
		#endif
				std::unique_lock<std::mutex> LocalAddressMutexIPv4(LocalAddressLock[1U]);
				memset(Parameter.LocalAddress_Response[1U], 0, PACKET_MAXSIZE);
				Parameter.LocalAddress_Length[1U] = 0;
			#if !defined(PLATFORM_MACX)
				std::string DNSPTRString;
				Parameter.LocalAddress_ResponsePTR[1U]->clear();
				Parameter.LocalAddress_ResponsePTR[1U]->shrink_to_fit();
			#endif

			//Mark local addresses(A part).
				DNS_Header = (pdns_hdr)Parameter.LocalAddress_Response[1U];
				DNS_Header->Flags = htons(DNS_SQR_NEA);
				DNS_Header->Questions = htons(U16_NUM_ONE);
				Parameter.LocalAddress_Length[1U] += sizeof(dns_hdr);
				memcpy_s(Parameter.LocalAddress_Response[1U] + Parameter.LocalAddress_Length[1U], PACKET_MAXSIZE - Parameter.LocalAddress_Length[1U], Parameter.LocalFQDN_Response, Parameter.LocalFQDN_Length);
				Parameter.LocalAddress_Length[1U] += Parameter.LocalFQDN_Length;
				DNS_Query = (pdns_qry)(Parameter.LocalAddress_Response[1U] + Parameter.LocalAddress_Length[1U]);
				DNS_Query->Type = htons(DNS_RECORD_AAAA);
				DNS_Query->Classes = htons(DNS_CLASS_IN);
				Parameter.LocalAddress_Length[1U] += sizeof(dns_qry);

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
						if (Parameter.LocalAddress_Length[1U] <= PACKET_MAXSIZE - sizeof(dns_record_a))
						{
							DNS_Record_A = (pdns_record_a)(Parameter.LocalAddress_Response[1U] + Parameter.LocalAddress_Length[1U]);
							DNS_Record_A->Name = htons(DNS_POINTER_QUERY);
							DNS_Record_A->Classes = htons(DNS_CLASS_IN);
							DNS_Record_A->TTL = htonl(Parameter.HostsDefaultTTL);
							DNS_Record_A->Type = htons(DNS_RECORD_A);
							DNS_Record_A->Length = htons(sizeof(in_addr));
							DNS_Record_A->Addr = ((PSOCKADDR_IN)LocalAddressTableIter->ai_addr)->sin_addr;
							Parameter.LocalAddress_Length[1U] += sizeof(dns_record_a);
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
						Parameter.LocalAddress_ResponsePTR[1U]->push_back(Result);
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
						if (Parameter.LocalAddress_Length[1U] <= PACKET_MAXSIZE - sizeof(dns_record_a))
						{
							DNS_Record_A = (pdns_record_a)(Parameter.LocalAddress_Response[1U] + Parameter.LocalAddress_Length[1U]);
							DNS_Record_A->Name = htons(DNS_POINTER_QUERY);
							DNS_Record_A->Classes = htons(DNS_CLASS_IN);
							DNS_Record_A->TTL = htonl(Parameter.HostsDefaultTTL);
							DNS_Record_A->Type = htons(DNS_RECORD_A);
							DNS_Record_A->Length = htons(sizeof(in_addr));
							DNS_Record_A->Addr = ((PSOCKADDR_IN)InterfaceAddressIter->ifa_addr)->sin_addr;
							Parameter.LocalAddress_Length[1U] += sizeof(dns_record_a);
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
						Parameter.LocalAddress_ResponsePTR[1U]->push_back(Result);
						Result.clear();
						Result.shrink_to_fit();
					#endif
					}
				}
			#endif

			//Mark local addresses(C part).
				if (DNS_Header->Answer == 0)
				{
					memset(Parameter.LocalAddress_Response[1U], 0, PACKET_MAXSIZE);
					Parameter.LocalAddress_Length[1U] = 0;
				}
				else {
					DNS_Header->Answer = htons(DNS_Header->Answer);
				}

			//Add to global list.
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

	//Free list.
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		if (InterfaceAddressList != nullptr)
			freeifaddrs(InterfaceAddressList);
		InterfaceAddressList = nullptr;
	#endif

	//Get gateway information and check.
		GetGatewayInformation(AF_INET6);
		GetGatewayInformation(AF_INET);
		if (!Parameter.GatewayAvailable_IPv4)
		{
		#if defined(PLATFORM_WIN)
			if (!Parameter.GatewayAvailable_IPv6)
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			if (!IsErrorFirstPrint && !Parameter.GatewayAvailable_IPv6)
		#endif
				PrintError(LOG_ERROR_NETWORK, L"Not any available gateways to public network", 0, nullptr, 0);

			Parameter.TunnelAvailable_IPv6 = false;
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
			IsErrorFirstPrint = false;
		#endif
		}

	//Auto-refresh
		Sleep(Parameter.FileRefreshTime);
	}

	PrintError(LOG_ERROR_SYSTEM, L"Get Local Address Information module Monitor terminated", 0, nullptr, 0);
	return;
}
