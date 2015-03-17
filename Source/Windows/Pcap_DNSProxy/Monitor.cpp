// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
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

//Running Log writing Monitor
size_t __fastcall RunningLogWriteMonitor(void)
{
//Initialization
	FILE *Output = nullptr;
	std::shared_ptr<tm> TimeStructure(new tm());
	memset(TimeStructure.get(), 0, sizeof(tm));
	HANDLE RunningFileHandle = nullptr;
	std::shared_ptr<LARGE_INTEGER> RunningFileSize(new LARGE_INTEGER());
	memset(RunningFileSize.get(), 0, sizeof(LARGE_INTEGER));
	std::unique_lock<std::mutex> RunningLogMutex(RunningLogLock);
	RunningLogMutex.unlock();

//Write messages into file.
	for (;;)
	{
		RunningLogMutex.lock();

	//Check whole file size.
		RunningFileHandle = CreateFileW(Parameter.RunningLogPath->c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (RunningFileHandle != INVALID_HANDLE_VALUE)
		{
			memset(RunningFileSize.get(), 0, sizeof(LARGE_INTEGER));
			if (GetFileSizeEx(RunningFileHandle, RunningFileSize.get()) == 0)
			{
				CloseHandle(RunningFileHandle);
			}
			else {
				CloseHandle(RunningFileHandle);
				if (RunningFileSize->QuadPart > 0 && (size_t)RunningFileSize->QuadPart >= Parameter.LogMaxSize && 
					DeleteFileW(Parameter.RunningLogPath->c_str()) != 0)
						PrintError(LOG_ERROR_SYSTEM, L"Old Running Log file was deleted", 0, nullptr, 0);
			}
		}

	//Write all messages to file.
		_wfopen_s(&Output, Parameter.RunningLogPath->c_str(), L"a,ccs=UTF-8");
		if (Output != nullptr && Parameter.RunningLogWriteQueue != nullptr)
		{
			for (auto RunningLogDataIter:*Parameter.RunningLogWriteQueue)
			{
				memset(TimeStructure.get(), 0, sizeof(tm));
				localtime_s(TimeStructure.get(), &RunningLogDataIter.TimeValues);

			//Print to screen.
				if (Parameter.Console)
					wprintf_s(L"%d-%02d-%02d %02d:%02d:%02d -> %ls\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, RunningLogDataIter.Message.c_str());

			//Print Running Log.
				fwprintf_s(Output, L"%d-%02d-%02d %02d:%02d:%02d -> %ls\n", TimeStructure->tm_year + 1900, TimeStructure->tm_mon + 1, TimeStructure->tm_mday, TimeStructure->tm_hour, TimeStructure->tm_min, TimeStructure->tm_sec, RunningLogDataIter.Message.c_str());
			}

		//Clear list.
			Parameter.RunningLogWriteQueue->clear();
			Parameter.RunningLogWriteQueue->shrink_to_fit();

		//Close file.
			fclose(Output);
		}

		RunningLogMutex.unlock();
		Sleep((DWORD)Parameter.RunningLogRefreshTime); //Time between writing.
	}

	return EXIT_SUCCESS;
}

//Local DNS server initialization
size_t __fastcall MonitorInit(void)
{
//Capture initialization
	if (Parameter.PcapCapture && !Parameter.HostsOnly && !(Parameter.DNSCurve && DNSCurveParameter.IsEncryption && DNSCurveParameter.IsEncryptionOnly))
	{
		std::thread CaptureInitializationThread(CaptureInit);
		CaptureInitializationThread.detach();

	//Get Hop Limits/TTL with normal DNS request.
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0)
		{
			std::thread IPv6TestDoaminThread(DomainTestRequest, AF_INET6); //Get Hop Limits.
			IPv6TestDoaminThread.detach();
		}

		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0) //Get TTL.
		{
			std::thread IPv4TestDoaminThread(DomainTestRequest, AF_INET);
			IPv4TestDoaminThread.detach();
		}

		//Get Hop Limits/TTL with ICMP Echo.
		if (Parameter.ICMPSpeed > 0)
		{
			//ICMPv6
			if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family > 0)
			{
				std::thread ICMPv6Thread(ICMPv6Echo);
				ICMPv6Thread.detach();
			}

			//ICMP
			if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0)
			{
				std::thread ICMPThread(ICMPEcho);
				ICMPThread.detach();
			}
		}
	}

//Set Preferred DNS servers switcher.
	if (!Parameter.AlternateMultiRequest && 
		Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 || 
		Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0 || 
		DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 || DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0)
	{
		std::thread AlternateServerMonitorThread(AlternateServerMonitor);
		AlternateServerMonitorThread.detach();
	}

//Initialization
	std::shared_ptr<SOCKET_DATA> LocalhostData(new SOCKET_DATA());
	memset(LocalhostData.get(), 0, sizeof(SOCKET_DATA));
//	std::thread IPv6UDPMonitorThread, IPv4UDPMonitorThread, IPv6TCPMonitorThread, IPv4TCPMonitorThread;
	std::vector<std::thread> MonitorThread((Parameter.ListenPort->size() + 1U) * QUEUE_PARTNUM);
	size_t MonitorThreadIndex = 0;

//Set localhost monitor sockets(IPv6/UDP).
	if (Parameter.ListenProtocol_NetworkLayer == LISTEN_IPV6_IPV4 || Parameter.ListenProtocol_NetworkLayer == LISTEN_IPV6)
	{
		if (Parameter.ListenProtocol_TransportLayer == LISTEN_TCP_UDP || Parameter.ListenProtocol_TransportLayer == LISTEN_UDP)
		{
			LocalhostData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			if (LocalhostData->Socket == INVALID_SOCKET)
			{
				if ( /* IsWindowsVistaOrGreater() || */ WSAGetLastError() != 0 && WSAGetLastError() != WSAEAFNOSUPPORT)
					PrintError(LOG_ERROR_WINSOCK, L"IPv6 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
			}
			else {
//				Parameter.LocalSocket[0] = LocalhostData->Socket;
				Parameter.LocalSocket->push_back(LocalhostData->Socket);
				LocalhostData->SockAddr.ss_family = AF_INET6;
				LocalhostData->AddrLen = sizeof(sockaddr_in6);

			//Listen Address available(IPv6)
				if (Parameter.ListenAddress_IPv6 != nullptr)
				{
					for (size_t Index = 0;Index < Parameter.ListenAddress_IPv6->size();Index++)
					{
						if (Index > 0)
						{
							LocalhostData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
							if (LocalhostData->Socket == INVALID_SOCKET)
							{
								PrintError(LOG_ERROR_WINSOCK, L"IPv6 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
								break;
							}
						}

						((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_addr = ((PSOCKADDR_IN6)&Parameter.ListenAddress_IPv6->at(Index))->sin6_addr;
						((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_port = ((PSOCKADDR_IN6)&Parameter.ListenAddress_IPv6->at(Index))->sin6_port;

					//Add to global thread list.
						std::thread MonitorThreadTemp(UDPMonitor, *LocalhostData);
						MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
						MonitorThreadIndex++;
					}
				}
				else {
				//Proxy Mode
					if (Parameter.OperationMode == LISTEN_PROXYMODE)
						((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_addr = in6addr_loopback;
				//Server Mode, Priavte Mode and Custom Mode
					else
						((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_addr = in6addr_any;

				//Set ports.
//					((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_port = Parameter.ListenPort;
					if (Parameter.ListenPort != nullptr)
					{
						for (auto ListenPortIter:*Parameter.ListenPort)
						{
							LocalhostData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
							if (LocalhostData->Socket == INVALID_SOCKET)
							{
								PrintError(LOG_ERROR_WINSOCK, L"IPv6 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
								break;
							}

							((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_port = ListenPortIter;
							Parameter.LocalSocket->push_back(LocalhostData->Socket);

						//Add to global thread list.
							std::thread MonitorThreadTemp(UDPMonitor, *LocalhostData);
							MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
							MonitorThreadIndex++;
						}
					}
				}
			}

			memset(LocalhostData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Set localhost socket(IPv6/TCP).
		if (Parameter.ListenProtocol_TransportLayer == LISTEN_TCP_UDP || Parameter.ListenProtocol_TransportLayer == LISTEN_TCP)
		{
			LocalhostData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
			if (LocalhostData->Socket == INVALID_SOCKET)
			{
				if ( /* IsWindowsVistaOrGreater() || */ WSAGetLastError() != 0 && WSAGetLastError() != WSAEAFNOSUPPORT)
					PrintError(LOG_ERROR_WINSOCK, L"IPv6 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
			}
			else {
//				Parameter.LocalSocket[2U] = LocalhostData->Socket;
				Parameter.LocalSocket->push_back(LocalhostData->Socket);
				LocalhostData->SockAddr.ss_family = AF_INET6;
				LocalhostData->AddrLen = sizeof(sockaddr_in6);

			//Listen Address available(IPv6)
				if (Parameter.ListenAddress_IPv6 != nullptr)
				{
					for (size_t Index = 0;Index < Parameter.ListenAddress_IPv6->size();Index++)
					{
						if (Index > 0)
						{
							LocalhostData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
							if (LocalhostData->Socket == INVALID_SOCKET)
							{
								PrintError(LOG_ERROR_WINSOCK, L"IPv6 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
								break;
							}
						}

						((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_addr = ((PSOCKADDR_IN6)&Parameter.ListenAddress_IPv6->at(Index))->sin6_addr;
						((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_port = ((PSOCKADDR_IN6)&Parameter.ListenAddress_IPv6->at(Index))->sin6_port;

					//Add to global thread list.
						std::thread MonitorThreadTemp(TCPMonitor, *LocalhostData);
						MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
						MonitorThreadIndex++;
					}
				}
				else {
				//Proxy Mode
					if (Parameter.OperationMode == LISTEN_PROXYMODE)
						((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_addr = in6addr_loopback;
				//Server Mode, Priavte Mode and Custom Mode
					else
						((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_addr = in6addr_any;

				//Set ports.
//					((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_port = Parameter.ListenPort;
					if (Parameter.ListenPort != nullptr)
					{
						for (auto ListenPortIter:*Parameter.ListenPort)
						{
							LocalhostData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
							if (LocalhostData->Socket == INVALID_SOCKET)
							{
								PrintError(LOG_ERROR_WINSOCK, L"IPv6 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
								break;
							}

							((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_port = ListenPortIter;
							Parameter.LocalSocket->push_back(LocalhostData->Socket);

						//Add to global thread list.
							std::thread MonitorThreadTemp(TCPMonitor, *LocalhostData);
							MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
							MonitorThreadIndex++;
						}
					}
				}
			}

			memset(LocalhostData.get(), 0, sizeof(SOCKET_DATA));
		}
	}

//Set localhost socket(IPv4/UDP).
	if (Parameter.ListenProtocol_NetworkLayer == LISTEN_IPV6_IPV4 || Parameter.ListenProtocol_NetworkLayer == LISTEN_IPV4)
	{
		if (Parameter.ListenProtocol_TransportLayer == LISTEN_TCP_UDP || Parameter.ListenProtocol_TransportLayer == LISTEN_UDP)
		{
			LocalhostData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (LocalhostData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"IPv4 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
			}
			else {
//				Parameter.LocalSocket[1U] = LocalhostData->Socket;
				Parameter.LocalSocket->push_back(LocalhostData->Socket);
				LocalhostData->SockAddr.ss_family = AF_INET;
				LocalhostData->AddrLen = sizeof(sockaddr_in);

			//Listen Address available(IPv6)
				if (Parameter.ListenAddress_IPv4 != nullptr)
				{
					for (size_t Index = 0;Index < Parameter.ListenAddress_IPv4->size();Index++)
					{
						if (Index > 0)
						{
							LocalhostData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
							if (LocalhostData->Socket == INVALID_SOCKET)
							{
								PrintError(LOG_ERROR_WINSOCK, L"IPv4 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
								break;
							}
						}

						((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_addr = ((PSOCKADDR_IN)&Parameter.ListenAddress_IPv4->at(Index))->sin_addr;
						((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_port = ((PSOCKADDR_IN)&Parameter.ListenAddress_IPv4->at(Index))->sin_port;

					//Add to global thread list.
						std::thread MonitorThreadTemp(UDPMonitor, *LocalhostData);
						MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
						MonitorThreadIndex++;
					}
				}
				else {
				//Proxy Mode
					if (Parameter.OperationMode == LISTEN_PROXYMODE)
						((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
				//Server Mode, Priavte Mode and Custom Mode
					else
						((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_addr.S_un.S_addr = INADDR_ANY;

				//Set ports.
//					((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_port = Parameter.ListenPort;
					if (Parameter.ListenPort != nullptr)
					{
						for (auto ListenPortIter:*Parameter.ListenPort)
						{
							LocalhostData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
							if (LocalhostData->Socket == INVALID_SOCKET)
							{
								PrintError(LOG_ERROR_WINSOCK, L"IPv4 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
								break;
							}

							((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_port = ListenPortIter;
							Parameter.LocalSocket->push_back(LocalhostData->Socket);

						//Add to global thread list.
							std::thread MonitorThreadTemp(UDPMonitor, *LocalhostData);
							MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
							MonitorThreadIndex++;
						}
					}
				}
			}

			memset(LocalhostData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Set localhost socket(IPv4/TCP).
		if (Parameter.ListenProtocol_TransportLayer == LISTEN_TCP_UDP || Parameter.ListenProtocol_TransportLayer == LISTEN_TCP)
		{
			LocalhostData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (LocalhostData->Socket == INVALID_SOCKET)
			{
				PrintError(LOG_ERROR_WINSOCK, L"IPv4 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
			}
			else {
//				Parameter.LocalSocket[3U] = LocalhostData->Socket;
				Parameter.LocalSocket->push_back(LocalhostData->Socket);
				LocalhostData->SockAddr.ss_family = AF_INET;
				LocalhostData->AddrLen = sizeof(sockaddr_in);

			//Listen Address available(IPv6)
				if (Parameter.ListenAddress_IPv4 != nullptr)
				{
					for (size_t Index = 0;Index < Parameter.ListenAddress_IPv4->size();Index++)
					{
						if (Index > 0)
						{
							LocalhostData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
							if (LocalhostData->Socket == INVALID_SOCKET)
							{
								PrintError(LOG_ERROR_WINSOCK, L"IPv4 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
								break;
							}
						}

						((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_addr = ((PSOCKADDR_IN)&Parameter.ListenAddress_IPv4->at(Index))->sin_addr;
						((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_port = ((PSOCKADDR_IN)&Parameter.ListenAddress_IPv4->at(Index))->sin_port;

					//Add to global thread list.
						std::thread MonitorThreadTemp(TCPMonitor, *LocalhostData);
						MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
						MonitorThreadIndex++;
					}
				}
				else {
				//Proxy Mode
					if (Parameter.OperationMode == LISTEN_PROXYMODE)
						((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
				//Server Mode, Priavte Mode and Custom Mode
					else
						((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_addr.S_un.S_addr = INADDR_ANY;

				//Set ports.
//					((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_port = Parameter.ListenPort;
					if (Parameter.ListenPort != nullptr)
					{
						for (auto ListenPortIter:*Parameter.ListenPort)
						{
							LocalhostData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
							if (LocalhostData->Socket == INVALID_SOCKET)
							{
								PrintError(LOG_ERROR_WINSOCK, L"IPv4 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, 0);
								break;
							}

							((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_port = ListenPortIter;
							Parameter.LocalSocket->push_back(LocalhostData->Socket);

						//Add to global thread list.
							std::thread InnerMonitorThreadTemp(TCPMonitor, *LocalhostData);
							MonitorThread[MonitorThreadIndex].swap(InnerMonitorThreadTemp);
							MonitorThreadIndex++;
						}
					}
				}
			}
		}
	}

	LocalhostData.reset();

//Join threads.
/* Old version(2015-03-14)
	if (IPv6UDPMonitorThread.joinable())
		IPv6UDPMonitorThread.join();
	if (IPv4UDPMonitorThread.joinable())
		IPv4UDPMonitorThread.join();
	if (IPv6TCPMonitorThread.joinable())
		IPv6TCPMonitorThread.join();
	if (IPv4TCPMonitorThread.joinable())
		IPv4TCPMonitorThread.join();
*/
	for (size_t Index = 0;Index < MonitorThreadIndex;Index++)
	{
		if (MonitorThread[Index].joinable())
			MonitorThread[Index].join();
	}

	return EXIT_SUCCESS;
}

//Local DNS server with UDP protocol
size_t __fastcall UDPMonitor(const SOCKET_DATA LocalhostData)
{
//Block WSAECONNRESET error of UDP Monitor.
	DWORD BytesReturned = 0;
	BOOL NewBehavior = FALSE;
	SSIZE_T RecvLen = WSAIoctl(LocalhostData.Socket, SIO_UDP_CONNRESET, &NewBehavior, sizeof(BOOL), nullptr, 0, &BytesReturned, nullptr, nullptr);
	if (RecvLen == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket SIO_UDP_CONNRESET error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalhostData.Socket);

		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalhostData.Socket);

		return EXIT_FAILURE;
	}
/*
//Set Non-blocking Mode
	ULONG SocketMode = 1U;
	if (ioctlsocket(Parameter.LocalhostSocket ,FIONBIO, &SocketMode) == SOCKET_ERROR)
		return EXIT_FAILURE;

//Preventing other sockets from being forcibly bound to the same address and port.
	int Val = 1;
	if (setsockopt(Parameter.LocalhostSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (PSTR)&Val, sizeof(int)) == SOCKET_ERROR)
		return EXIT_FAILURE;
*/
//Bind socket to port.
	if (bind(LocalhostData.Socket, (PSOCKADDR)&LocalhostData.SockAddr, LocalhostData.AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Bind UDP Monitor socket error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalhostData.Socket);

		return EXIT_FAILURE;
	}

//Start Monitor.
	std::shared_ptr<char> Buffer(new char[PACKET_MAXSIZE * BUFFER_RING_MAXNUM]());
	memset(Buffer.get(), 0, PACKET_MAXSIZE * BUFFER_RING_MAXNUM);
	void *Addr = nullptr;
	pdns_hdr DNS_Header = nullptr;
	std::unique_lock<std::mutex> UDPMonitorIndexMutex(UDPMonitorIndexLock);
	UDPMonitorIndexMutex.unlock();
	size_t Index[] = {0, 0};

	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);
		memset(Buffer.get() + PACKET_MAXSIZE * Index[0], 0, PACKET_MAXSIZE);
		if (Parameter.EDNS0Label) //EDNS0 Label
			RecvLen = recvfrom(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], PACKET_MAXSIZE - sizeof(dns_record_opt), 0, (PSOCKADDR)&LocalhostData.SockAddr, (PINT)&LocalhostData.AddrLen);
		else 
			RecvLen = recvfrom(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], PACKET_MAXSIZE, 0, (PSOCKADDR)&LocalhostData.SockAddr, (PINT)&LocalhostData.AddrLen);

	//Check address(es).
		if (LocalhostData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			Addr = &((PSOCKADDR_IN6)&LocalhostData.SockAddr)->sin6_addr;
			if (CheckEmptyBuffer(Addr, sizeof(in6_addr)) || //Empty address
			//Check Private Mode(IPv6).
				(Parameter.OperationMode == LISTEN_PRIVATEMODE && 
				!(((in6_addr *)Addr)->u.Byte[0] >= 0xFC && ((in6_addr *)Addr)->u.Byte[0] <= 0xFD || //Unique Local Unicast address/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
				((in6_addr *)Addr)->u.Byte[0] == 0xFE && ((in6_addr *)Addr)->u.Byte[1U] >= 0x80 && ((in6_addr *)Addr)->u.Byte[1U] <= 0xBF || //Link-Local Unicast Contrast address(FE80::/10, Section 2.5.6 in RFC 4291)
				((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x0001))) || //Loopback address(::1, Section 2.5.3 in RFC 4291)
			//Check Custom Mode(IPv6).
				Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET6))
/* Old version(2015-03-13)
			//Check Server Mode(IPv6).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.OperationMode == LISTEN_SERVERMODE) && 
				CheckSpecialAddress(Addr, AF_INET6, nullptr)
*/
					continue;
		}
		else { //IPv4
			Addr = &((PSOCKADDR_IN)&LocalhostData.SockAddr)->sin_addr;
			if ((*(in_addr *)Addr).S_un.S_addr == 0 || //Empty address
			//Check Private Mode(IPv4).
				(Parameter.OperationMode == LISTEN_PRIVATEMODE &&
				!(((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0x0A || //Private class A address(10.0.0.0/8, Section 3 in RFC 1918)
				((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
				((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xAC && ((in_addr *)Addr)->S_un.S_un_b.s_b2 >= 0x10 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 <= 0x1F || //Private class B address(172.16.0.0/16, Section 3 in RFC 1918)
				((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xC0 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 == 0xA8)) || //Private class C address(192.168.0.0/24, Section 3 in RFC 1918)
			//Check Custom Mode(IPv4).
				Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET))
/* Old version(2015-03-13)
			//Check Server Mode(IPv4).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.OperationMode == LISTEN_SERVERMODE) &&
				CheckSpecialAddress(Addr, AF_INET, nullptr))
*/
					continue;
		}

	//UDP Truncated check
		if (RecvLen > (SSIZE_T)(Parameter.EDNS0PayloadSize - sizeof(dns_record_opt)))
		{
			if (Parameter.EDNS0Label || //EDNS0 Lebal
				RecvLen > (SSIZE_T)Parameter.EDNS0PayloadSize)
			{
			//Make packets with EDNS0 Lebal.
				DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8200); //Set 1000001000000000, DNS_SQR_NETC
				pdns_record_opt DNS_Record_OPT = nullptr;
				if (DNS_Header->Additional == 0)
				{
					DNS_Header->Additional = htons(U16_NUM_ONE);
					DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen);
					DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
					DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					RecvLen += sizeof(dns_record_opt);
				}
				else if (DNS_Header->Additional == htons(U16_NUM_ONE))
				{
					DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen - sizeof(dns_record_opt));
					if (DNS_Record_OPT->Type == htons(DNS_RECORD_OPT))
						DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				}
				else {
					continue;
				}

			//Send requesting.
				sendto(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], (int)RecvLen, 0, (PSOCKADDR)&LocalhostData.SockAddr, LocalhostData.AddrLen);
				continue;
			}
		}

	//Receive process.
		if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
		{
		//Check requesting.
			DNS_Header = (pdns_hdr)(Buffer.get() + PACKET_MAXSIZE * Index[0]);
			if (DNS_Header->Questions != htons(U16_NUM_ONE) || DNS_Header->Answer > 0 || ntohs(DNS_Header->Additional) > U16_NUM_ONE || DNS_Header->Authority > 0)
				continue;
			for (Index[1U] = sizeof(dns_hdr);Index[1U] < DNS_PACKET_QUERY_LOCATE(Buffer.get() + PACKET_MAXSIZE * Index[0]);Index[1U]++)
			{
				if (*(Buffer.get() + PACKET_MAXSIZE * Index[0] + Index[1U]) == '\xC0')
					continue;
			}
			if (Index[1U] != DNS_PACKET_QUERY_LOCATE(Buffer.get() + PACKET_MAXSIZE * Index[0]))
			{
				DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8001); //Set 10000000000000001, DNS_SQR_FE
				sendto(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], (int)RecvLen, 0, (PSOCKADDR)&LocalhostData.SockAddr, LocalhostData.AddrLen);
				continue;
			}

		//EDNS0 Label
			if (Parameter.EDNS0Label)
			{
				pdns_record_opt DNS_Record_OPT = nullptr;

			//No additional
				if (DNS_Header->Additional == 0)
				{
					DNS_Header->Additional = htons(U16_NUM_ONE);
					DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen);
					DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
					DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					RecvLen += sizeof(dns_record_opt);
				}
			//Already have Additional Resource Records
				else {
					DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen - sizeof(dns_record_opt));
					if (DNS_Record_OPT->Type == htons(DNS_RECORD_OPT))
						DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				}

			//DNSSEC
				if (Parameter.DNSSECRequest && DNS_Record_OPT->Type == htons(DNS_RECORD_OPT))
				{
					DNS_Header->FlagsBits.AD = ~DNS_Header->FlagsBits.AD; //Local DNSSEC Server validate
					DNS_Header->FlagsBits.CD = ~DNS_Header->FlagsBits.CD; //Client validate
					DNS_Record_OPT->Z_Bits.DO = ~DNS_Record_OPT->Z_Bits.DO; //Accepts DNSSEC security Resource Records
				}
			}

		//Request process
			UDPMonitorIndexMutex.lock();
			if (LocalhostData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				std::thread RequestProcessThread(EnterRequestProcess, Buffer.get() + PACKET_MAXSIZE * Index[0], RecvLen, LocalhostData, IPPROTO_UDP, UDPMonitorIndex);
				RequestProcessThread.detach();
			}
			else { //IPv4
				std::thread RequestProcessThread(EnterRequestProcess, Buffer.get() + PACKET_MAXSIZE * Index[0], RecvLen, LocalhostData, IPPROTO_UDP, UDPMonitorIndex + QUEUE_MAXLEN);
				RequestProcessThread.detach();
			}
			UDPMonitorIndex = (UDPMonitorIndex + 1U) % QUEUE_MAXLEN;
			UDPMonitorIndexMutex.unlock();

			Index[0] = (Index[0] + 1U) % BUFFER_RING_MAXNUM;
//			Index[1U] = (Index[1U] + 1U) % QUEUE_MAXLEN;
		}
/*		else if (RecvLen == 0)
		{
			continue;
		}
		else if (RecvLen < 0) //SOCKET_ERROR
		{
			if (WSAGetLastError() != 0 && WSAGetLastError() != WSAETIMEDOUT)
			{
				PrintError(LOG_ERROR_WINSOCK, L"UDP Monitor socket listening error", WSAGetLastError(), nullptr, 0);
				closesocket(LocalhostData.Socket);

				return EXIT_FAILURE;
			}
			else {
				continue;
			}
		}
*/
		else { //Incorrect packets
//			DNS_Header->Flags = htons(DNS_SQR_FE);
//			sendto(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], (int)RecvLen, 0, (PSOCKADDR)&LocalhostData.SockAddr, LocalhostData.AddrLen);
			continue;
		}
	}

	shutdown(LocalhostData.Socket, SD_BOTH);
	closesocket(LocalhostData.Socket);
	PrintError(LOG_ERROR_SYSTEM, L"UDP listening module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Local DNS server with TCP protocol
size_t __fastcall TCPMonitor(const SOCKET_DATA LocalhostData)
{
//Set socket timeout.
	if (setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalhostData.Socket);

		return EXIT_FAILURE;
	}
/*
//Set Non-blocking Mode
	ULONG SocketMode = 1U;
	if (ioctlsocket(Parameter.LocalhostSocket ,FIONBIO, &SocketMode) == SOCKET_ERROR)
		return EXIT_FAILURE;

//Preventing other sockets from being forcibly bound to the same address and port.
	int Val = 1;
	if (setsockopt(Parameter.LocalhostSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (PSTR)&Val, sizeof(int)) == SOCKET_ERROR)
		return EXIT_FAILURE;
*/
//Bind socket to port.
	if (bind(LocalhostData.Socket, (PSOCKADDR)&LocalhostData.SockAddr, LocalhostData.AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Bind TCP Monitor socket error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalhostData.Socket);

		return EXIT_FAILURE;
	}

//Listen request from socket.
	if (listen(LocalhostData.Socket, SOMAXCONN) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"TCP Monitor socket listening initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalhostData.Socket);

		return EXIT_FAILURE;
	}

//Start Monitor.
	std::shared_ptr<SOCKET_DATA> ClientData(new SOCKET_DATA());
	void *Addr = nullptr;
//	size_t Index = 0;
	std::unique_lock<std::mutex> TCPMonitorIndexMutex(TCPMonitorIndexLock);
	TCPMonitorIndexMutex.unlock();
	ClientData->AddrLen = LocalhostData.AddrLen;

	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);
//		memset(ClientData.get(), 0, sizeof(SOCKET_DATA) - sizeof(int));
		memset(&ClientData->SockAddr, 0, sizeof(sockaddr_storage));
		ClientData->Socket = accept(LocalhostData.Socket, (PSOCKADDR)&ClientData->SockAddr, (PINT)&ClientData->AddrLen);
		if (ClientData->Socket == INVALID_SOCKET)
			continue;

	//Check address(es).
		if (ClientData->AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			Addr = &((PSOCKADDR_IN6)&ClientData->SockAddr)->sin6_addr;
			if (CheckEmptyBuffer(Addr, sizeof(in6_addr)) || //Empty address
			//Check Private Mode(IPv6).
				(Parameter.OperationMode == LISTEN_PRIVATEMODE && 
				!(((in6_addr *)Addr)->u.Byte[0] >= 0xFC && ((in6_addr *)Addr)->u.Byte[0] <= 0xFD || //Unique Local Unicast address/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
				((in6_addr *)Addr)->u.Byte[0] == 0xFE && ((in6_addr *)Addr)->u.Byte[1U] >= 0x80 && ((in6_addr *)Addr)->u.Byte[1U] <= 0xBF || //Link-Local Unicast Contrast address(FE80::/10, Section 2.5.6 in RFC 4291)
				((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x0001))) || //Loopback address(::1, Section 2.5.3 in RFC 4291)
			//Check Custom Mode(IPv6).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET6)))
/* Old version(2015-03-13)
			//Check Server Mode(IPv6).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.OperationMode == LISTEN_SERVERMODE) && 
				CheckSpecialAddress(Addr, AF_INET6, nullptr))
*/
			{
				shutdown(LocalhostData.Socket, SD_BOTH);
				closesocket(ClientData->Socket);
				continue;
			}
		}
		else { //IPv4
			Addr = &((PSOCKADDR_IN)&ClientData->SockAddr)->sin_addr;
			if ((*(in_addr *)Addr).S_un.S_addr == 0 || //Empty address
			//Check Private Mode(IPv4).
				(Parameter.OperationMode == LISTEN_PRIVATEMODE && 
				!(((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0x0A || //Private class A address(10.0.0.0/8, Section 3 in RFC 1918)
				((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
				((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xAC && ((in_addr *)Addr)->S_un.S_un_b.s_b2 >= 0x10 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 <= 0x1F || //Private class B address(172.16.0.0/16, Section 3 in RFC 1918)
				((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xC0 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 == 0xA8)) || //Private class C address(192.168.0.0/24, Section 3 in RFC 1918)
			//Check Custom Mode(IPv4).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET)))
/* Old version(2015-03-13)
			//Check Server Mode(IPv4).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.OperationMode == LISTEN_SERVERMODE) && 
				CheckSpecialAddress(Addr, AF_INET, nullptr))
*/
			{
				shutdown(LocalhostData.Socket, SD_BOTH);
				closesocket(ClientData->Socket);
				continue;
			}
		}

	//Accept process.
		TCPMonitorIndexMutex.lock();
		std::thread TCPReceiveThread(TCPReceiveProcess, *ClientData, TCPMonitorIndex);
		TCPReceiveThread.detach();

		TCPMonitorIndex = (TCPMonitorIndex + 1U) % QUEUE_MAXLEN;
		TCPMonitorIndexMutex.unlock();

//		Index = (Index + 1U) % QUEUE_MAXLEN;
	}

	shutdown(LocalhostData.Socket, SD_BOTH);
	closesocket(LocalhostData.Socket);
	PrintError(LOG_ERROR_SYSTEM, L"TCP listening module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//TCP protocol receive process
size_t __fastcall TCPReceiveProcess(const SOCKET_DATA TargetData, const size_t ListIndex)
{
	std::shared_ptr<char> Buffer(new char[LARGE_PACKET_MAXSIZE]());
	memset(Buffer.get(), 0, LARGE_PACKET_MAXSIZE);
	size_t InnerIndex = 0;
	SSIZE_T RecvLen = 0;

//Receive
	if (Parameter.EDNS0Label) //EDNS0 Label
		RecvLen = recv(TargetData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE - sizeof(dns_record_opt), 0);
	else 
		RecvLen = recv(TargetData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE, 0);
	if (RecvLen == (SSIZE_T)sizeof(uint16_t)) //TCP segment of a reassembled PDU
	{
	//Receive without PDU.
		uint16_t PDU_Len = ntohs(((uint16_t *)Buffer.get())[0]);
		memset(Buffer.get(), 0, RecvLen);
		if (Parameter.EDNS0Label) //EDNS0 Label
			RecvLen = recv(TargetData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE - sizeof(dns_record_opt), 0);
		else 
			RecvLen = recv(TargetData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE, 0);

	//Receive packet.
		if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && (SSIZE_T)PDU_Len >= RecvLen)
		{
		//Check requesting.
			auto DNS_Header = (pdns_hdr)Buffer.get();
			if (DNS_Header->Questions != htons(U16_NUM_ONE) || ntohs(DNS_Header->Flags) >> 15U > 0 || 
				DNS_Header->Answer > 0 || ntohs(DNS_Header->Additional) > U16_NUM_ONE || DNS_Header->Authority > 0)
			{
				shutdown(TargetData.Socket, SD_BOTH);
				closesocket(TargetData.Socket);
				return EXIT_FAILURE;
			}
			for (InnerIndex = sizeof(dns_hdr);InnerIndex < DNS_PACKET_QUERY_LOCATE(Buffer.get());InnerIndex++)
			{
				if (*(Buffer.get() + InnerIndex) == '\xC0')
					break;
			}
			if (InnerIndex != DNS_PACKET_QUERY_LOCATE(Buffer.get()))
			{
				DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8001); //Set 10000000000000001, DNS_SQR_FE
				send(TargetData.Socket, Buffer.get(), (int)RecvLen, 0);

				shutdown(TargetData.Socket, SD_BOTH);
				closesocket(TargetData.Socket);
				return EXIT_FAILURE;
			}

		//EDNS0 Label
			if (Parameter.EDNS0Label)
			{
				pdns_record_opt DNS_Record_OPT = nullptr;

			//No additional
				if (DNS_Header->Additional == 0)
				{
					DNS_Header->Additional = htons(U16_NUM_ONE);
					DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + PDU_Len);
					DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
					DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					PDU_Len += sizeof(dns_record_opt);
				}
			//Already have Additional Resource Records
				else {
					DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + PDU_Len - sizeof(dns_record_opt));
					if (DNS_Record_OPT->Type == htons(DNS_RECORD_OPT))
						DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				}

			//DNSSEC
				if (Parameter.DNSSECRequest && DNS_Record_OPT->Type == htons(DNS_RECORD_OPT))
				{
					DNS_Header->FlagsBits.AD = ~DNS_Header->FlagsBits.AD; //Local DNSSEC Server validate
					DNS_Header->FlagsBits.CD = ~DNS_Header->FlagsBits.CD; //Client validate
					DNS_Record_OPT->Z_Bits.DO = ~DNS_Record_OPT->Z_Bits.DO; //Accepts DNSSEC security Resource Records
				}
			}

			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				EnterRequestProcess(Buffer.get(), PDU_Len, TargetData, IPPROTO_TCP, ListIndex + QUEUE_MAXLEN * (QUEUE_PARTNUM - 2U));
			else //IPv4
				EnterRequestProcess(Buffer.get(), PDU_Len, TargetData, IPPROTO_TCP, ListIndex + QUEUE_MAXLEN * (QUEUE_PARTNUM - 1U));
		}
		else {
			shutdown(TargetData.Socket, SD_BOTH);
			closesocket(TargetData.Socket);
			return EXIT_FAILURE;
		}
	}
	else if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && (SSIZE_T)htons(((uint16_t *)Buffer.get())[0]) <= RecvLen)
	{
		RecvLen = htons(((uint16_t *)Buffer.get())[0]);

	//Check requesting.
		auto DNS_Header = (pdns_hdr)(Buffer.get() + sizeof(uint16_t));
		if (DNS_Header->Questions != htons(U16_NUM_ONE) || ntohs(DNS_Header->Flags) >> 15U > 0 || 
			DNS_Header->Answer > 0 || ntohs(DNS_Header->Additional) > U16_NUM_ONE || DNS_Header->Authority > 0)
		{
			shutdown(TargetData.Socket, SD_BOTH);
			closesocket(TargetData.Socket);
			return EXIT_FAILURE;
		}
		for (InnerIndex = sizeof(dns_tcp_hdr);InnerIndex < DNS_TCP_PACKET_QUERY_LOCATE(Buffer.get());InnerIndex++)
		{
			if (*(Buffer.get() + InnerIndex) == '\xC0')
				break;
		}
		if (InnerIndex != DNS_TCP_PACKET_QUERY_LOCATE(Buffer.get()))
		{
			DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | 0x8001); //Set 10000000000000001, DNS_SQR_FE
			send(TargetData.Socket, Buffer.get(), (int)RecvLen + sizeof(uint16_t), 0);

			shutdown(TargetData.Socket, SD_BOTH);
			closesocket(TargetData.Socket);
			return EXIT_FAILURE;
		}

	//EDNS0 Label
		if (Parameter.EDNS0Label)
		{
			pdns_record_opt DNS_Record_OPT = nullptr;

		//No additional
			if (DNS_Header->Additional == 0)
			{
				DNS_Header->Additional = htons(U16_NUM_ONE);
				DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + sizeof(uint16_t) + RecvLen);
				DNS_Record_OPT->Type = htons(DNS_RECORD_OPT);
				DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				RecvLen += sizeof(dns_record_opt);
			}
		//Already have Additional Resource Records
			else {
				DNS_Record_OPT = (pdns_record_opt)(Buffer.get() + sizeof(uint16_t) + RecvLen - sizeof(dns_record_opt));
				if (DNS_Record_OPT->Type == htons(DNS_RECORD_OPT))
					DNS_Record_OPT->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
			}

		//DNSSEC
			if (Parameter.DNSSECRequest && DNS_Record_OPT->Type == htons(DNS_RECORD_OPT))
			{
				DNS_Header->FlagsBits.AD = ~DNS_Header->FlagsBits.AD; //Local DNSSEC Server validate
				DNS_Header->FlagsBits.CD = ~DNS_Header->FlagsBits.CD; //Client validate
				DNS_Record_OPT->Z_Bits.DO = ~DNS_Record_OPT->Z_Bits.DO; //Accepts DNSSEC security Resource Records
			}
		}

	//Request process
		if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			EnterRequestProcess(Buffer.get() + sizeof(uint16_t), RecvLen, TargetData, IPPROTO_TCP, ListIndex + QUEUE_MAXLEN * (QUEUE_PARTNUM - 2U));
		else //IPv4
			EnterRequestProcess(Buffer.get() + sizeof(uint16_t), RecvLen, TargetData, IPPROTO_TCP, ListIndex + QUEUE_MAXLEN * (QUEUE_PARTNUM - 1U));
	}
	else {
		shutdown(TargetData.Socket, SD_BOTH);
		closesocket(TargetData.Socket);
		return EXIT_FAILURE;
	}

//Block Port Unreachable messages of system.
	shutdown(TargetData.Socket, SD_BOTH);
	Sleep(Parameter.ReliableSocketTimeout);
	closesocket(TargetData.Socket);
	return EXIT_SUCCESS;
}

//Alternate DNS servers switcher
void __fastcall AlternateServerMonitor(void)
{
	size_t Index = 0, RangeTimer[ALTERNATE_SERVERNUM] = {0}, SwapTimer[ALTERNATE_SERVERNUM] = {0};

//Switcher
//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
	for (;;)
	{
	//Pcap Requesting check
		for (Index = 0;Index < QUEUE_MAXLEN * QUEUE_PARTNUM;Index++)
		{
			if (AlternateSwapList.PcapAlternateTimeout[Index] != 0)
			{
#ifdef _WIN64
				if (GetTickCount64() >= /* Parameter.ReliableSocketTimeout + */ AlternateSwapList.PcapAlternateTimeout[Index]) //Check timeout.
#else //x86
			//Check timeout.
				if (Parameter.GetTickCount64PTR != nullptr && (*Parameter.GetTickCount64PTR)() >= /* Parameter.ReliableSocketTimeout + */ AlternateSwapList.PcapAlternateTimeout[Index] || 
					GetTickCount() >= /* Parameter.ReliableSocketTimeout + */ AlternateSwapList.PcapAlternateTimeout[Index])
#endif
				{
					AlternateSwapList.PcapAlternateTimeout[Index] = 0;
					if (AlternateSwapList.IsSwap[2U] == false && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 && 
						Index >= 0 && Index < QUEUE_MAXLEN * (QUEUE_PARTNUM - 3U) || Index >= QUEUE_MAXLEN * (QUEUE_PARTNUM - 2U) && Index < QUEUE_MAXLEN * (QUEUE_PARTNUM - 1U)) //IPv6
							AlternateSwapList.TimeoutTimes[2U]++;
					else if (AlternateSwapList.IsSwap[3U] == false && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0) //IPv4
						AlternateSwapList.TimeoutTimes[3U]++;
				}
			}
		}

	//Complete Requesting check
		for (Index = 0;Index < ALTERNATE_SERVERNUM;Index++)
		{
		//Reset TimeoutTimes out of alternate time range.
		#ifdef _WIN64
			if (GetTickCount64() >= RangeTimer[Index])
			{
				RangeTimer[Index] = GetTickCount64() + Parameter.AlternateTimeRange;
		#else //x86
			if (Parameter.GetTickCount64PTR != nullptr && (*Parameter.GetTickCount64PTR)() >= RangeTimer[Index] || GetTickCount() >= RangeTimer[Index])
			{
				if (Parameter.GetTickCount64PTR != nullptr)
					RangeTimer[Index] = (size_t)((*Parameter.GetTickCount64PTR)() + Parameter.AlternateTimeRange);
				else
					RangeTimer[Index] = GetTickCount() + Parameter.AlternateTimeRange;

		#endif
				AlternateSwapList.TimeoutTimes[Index] = 0;
				continue;
			}

		//Reset alternate switching.
			if (AlternateSwapList.IsSwap[Index])
			{
			#ifdef _WIN64
				if (GetTickCount64() >= SwapTimer[Index])
			#else //x86
				if (Parameter.GetTickCount64PTR != nullptr && (*Parameter.GetTickCount64PTR)() >= SwapTimer[Index] || GetTickCount() >= SwapTimer[Index])
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
				#ifdef _WIN64
					SwapTimer[Index] = GetTickCount64() + Parameter.AlternateResetTime;
				#else //x86
					if (Parameter.GetTickCount64PTR != nullptr)
						SwapTimer[Index] = (size_t)((*Parameter.GetTickCount64PTR)() + Parameter.AlternateResetTime);
					else 
						SwapTimer[Index] = GetTickCount() + Parameter.AlternateResetTime;
				#endif
				}
			}
		}

		Sleep(MONITOR_LOOP_INTERVAL_TIME); //Time between checking.
	}

	PrintError(LOG_ERROR_SYSTEM, L"Alternate Server module Monitor terminated", 0, nullptr, 0);
	return;
}

//DNS Cache timers monitor
void __fastcall DNSCacheTimerMonitor(void)
{
	std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	DNSCacheListMutex.unlock();
	for (;;)
	{
	//Minimum supported system of GetTickCount64() is Windows Vista(Windows XP with SP3 support).
		DNSCacheListMutex.lock();
	#ifdef _WIN64
		while (!DNSCacheList.empty() && GetTickCount64() >= DNSCacheList.front().ClearTime)
	#else //x86
		while (!DNSCacheList.empty() && (Parameter.GetTickCount64PTR != nullptr && (*Parameter.GetTickCount64PTR)() >= DNSCacheList.front().ClearTime || 
			GetTickCount() >= DNSCacheList.front().ClearTime))
	#endif
			DNSCacheList.pop_front();

		DNSCacheList.shrink_to_fit();
		DNSCacheListMutex.unlock();

		Sleep(MONITOR_LOOP_INTERVAL_TIME); //Time between checking.
	}

	PrintError(LOG_ERROR_SYSTEM, L"DNS Cache Timer module Monitor terminated", 0, nullptr, 0);
	return;
}
