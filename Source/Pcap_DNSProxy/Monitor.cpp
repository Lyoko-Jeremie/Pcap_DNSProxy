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

/* Old version(2015-05-20)
//Running Log writing Monitor
size_t __fastcall RunningLogWriteMonitor(void)
{
//Initialization
	FILE *Output = nullptr;
	std::shared_ptr<tm> TimeStructure(new tm());
	memset(TimeStructure.get(), 0, sizeof(tm));
#if defined(PLATFORM_WIN)
	std::shared_ptr<LARGE_INTEGER> RunningFileSize(new LARGE_INTEGER());
	std::shared_ptr<WIN32_FILE_ATTRIBUTE_DATA> File_WIN32_FILE_ATTRIBUTE_DATA(new WIN32_FILE_ATTRIBUTE_DATA());
	memset(RunningFileSize.get(), 0, sizeof(LARGE_INTEGER));
	memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	std::shared_ptr<struct stat> FileStat(new struct stat());
	memset(FileStat.get(), 0, sizeof(struct stat));
#endif
	std::unique_lock<std::mutex> RunningLogMutex(RunningLogLock);
	RunningLogMutex.unlock();

//Write messages into file.
	for (;;)
	{
		RunningLogMutex.lock();

	//Check whole file size.
	#if defined(PLATFORM_WIN)
		memset(File_WIN32_FILE_ATTRIBUTE_DATA.get(), 0, sizeof(WIN32_FILE_ATTRIBUTE_DATA));
		if (GetFileAttributesExW(Parameter.RunningLogPath->c_str(), GetFileExInfoStandard, File_WIN32_FILE_ATTRIBUTE_DATA.get()) != FALSE)
		{
			memset(RunningFileSize.get(), 0, sizeof(LARGE_INTEGER));
			RunningFileSize->HighPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeHigh;
			RunningFileSize->LowPart = File_WIN32_FILE_ATTRIBUTE_DATA->nFileSizeLow;
			if (RunningFileSize->QuadPart > 0 && (size_t)RunningFileSize->QuadPart >= Parameter.LogMaxSize && 
				DeleteFileW(Parameter.RunningLogPath->c_str()) != 0)
					PrintError(LOG_ERROR_SYSTEM, L"Old Running Log file was deleted", 0, nullptr, 0);
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		memset(FileStat.get(), 0, sizeof(struct stat));
		if (stat(Parameter.sRunningLogPath->c_str(), FileStat.get()) == 0 && FileStat->st_size >= (off_t)Parameter.LogMaxSize && 
			remove(Parameter.sRunningLogPath->c_str()) == 0)
				PrintError(LOG_ERROR_SYSTEM, L"Old Running Log file was deleted", 0, nullptr, 0);
	#endif

	//Write all messages to file.
	#if defined(PLATFORM_WIN)
		_wfopen_s(&Output, Parameter.RunningLogPath->c_str(), L"a,ccs=UTF-8");
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		Output = fopen(Parameter.sRunningLogPath->c_str(), "a");
	#endif
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
		Sleep(Parameter.RunningLogRefreshTime); //Time between writing.
	}

	return EXIT_SUCCESS;
}
*/

//Local DNS server initialization
size_t __fastcall MonitorInit(void)
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
				std::thread ICMPv6Thread(ICMPEcho, AF_INET6);
				ICMPv6Thread.detach();
			}

		//ICMP
			if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family > 0)
			{
				std::thread ICMPThread(ICMPEcho, AF_INET);
				ICMPThread.detach();
			}
		}
	}
#endif

//Set Preferred DNS servers switcher.
	if (!Parameter.AlternateMultiRequest && 
		Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0 || 
		Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family > 0 || Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family > 0
	#if defined(ENABLE_LIBSODIUM)
		|| DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family > 0 || DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family > 0
	#endif
		)
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
	if (Parameter.ListenProtocol_NetworkLayer == LISTEN_IPV6_IPV4 || Parameter.ListenProtocol_NetworkLayer == LISTEN_IPV6)
	{
		if (Parameter.ListenProtocol_TransportLayer == LISTEN_TCP_UDP || Parameter.ListenProtocol_TransportLayer == LISTEN_UDP)
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
						MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
						++MonitorThreadIndex;
						LocalSocketData->Socket = 0;
					}
				}
				else {
				//Proxy Mode
					if (Parameter.OperationMode == LISTEN_PROXYMODE)
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
							MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
							++MonitorThreadIndex;
							LocalSocketData->Socket = 0;
						}
					}
				}
			}

			memset(LocalSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Set localhost socket(IPv6/TCP).
		if (Parameter.ListenProtocol_TransportLayer == LISTEN_TCP_UDP || Parameter.ListenProtocol_TransportLayer == LISTEN_TCP)
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
						MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
						++MonitorThreadIndex;
						LocalSocketData->Socket = 0;
					}
				}
				else {
				//Proxy Mode
					if (Parameter.OperationMode == LISTEN_PROXYMODE)
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
							MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
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
	if (Parameter.ListenProtocol_NetworkLayer == LISTEN_IPV6_IPV4 || Parameter.ListenProtocol_NetworkLayer == LISTEN_IPV4)
	{
		if (Parameter.ListenProtocol_TransportLayer == LISTEN_TCP_UDP || Parameter.ListenProtocol_TransportLayer == LISTEN_UDP)
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
						MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
						++MonitorThreadIndex;
						LocalSocketData->Socket = 0;
					}
				}
				else {
				//Proxy Mode
					if (Parameter.OperationMode == LISTEN_PROXYMODE)
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
							MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
							++MonitorThreadIndex;
							LocalSocketData->Socket = 0;
						}
					}
				}
			}

			memset(LocalSocketData.get(), 0, sizeof(SOCKET_DATA));
		}

	//Set localhost socket(IPv4/TCP).
		if (Parameter.ListenProtocol_TransportLayer == LISTEN_TCP_UDP || Parameter.ListenProtocol_TransportLayer == LISTEN_TCP)
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
						MonitorThread[MonitorThreadIndex].swap(MonitorThreadTemp);
						++MonitorThreadIndex;
						LocalSocketData->Socket = 0;
					}
				}
				else {
				//Proxy Mode
					if (Parameter.OperationMode == LISTEN_PROXYMODE)
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
							MonitorThread[MonitorThreadIndex].swap(InnerMonitorThreadTemp);
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
		if (MonitorThread[Index].joinable())
			MonitorThread[Index].join();
	}

	return EXIT_SUCCESS;
}

//Local DNS server with UDP protocol
size_t __fastcall UDPMonitor(const SOCKET_DATA LocalSocketData)
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

		return EXIT_FAILURE;
	}
#endif

//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return EXIT_FAILURE;
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

		return EXIT_FAILURE;
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Socket reuse setting
	int SetVal = 1;
/*	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket enable reusing error", errno, nullptr, 0);
		close(LocalSocketData.Socket);

		return EXIT_FAILURE;
	}
*/
//Set an IPv6 server socket that cannot accept IPv4 connections on Linux.
//	SetVal = 1;
	if (LocalSocketData.SockAddr.ss_family == AF_INET6 && Parameter.OperationMode != LISTEN_PROXYMODE && 
		setsockopt(LocalSocketData.Socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set UDP socket treating wildcard bind error", errno, nullptr, 0);
		close(LocalSocketData.Socket);

		return EXIT_FAILURE;
	}
#endif

//Bind socket to port.
	if (bind(LocalSocketData.Socket, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Bind UDP Monitor socket error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return EXIT_FAILURE;
	}

//Start Monitor.
	std::shared_ptr<char> Buffer(new char[PACKET_MAXSIZE * BUFFER_RING_MAXNUM]());
	memset(Buffer.get(), 0, PACKET_MAXSIZE * BUFFER_RING_MAXNUM);
	void *Addr = nullptr;
	pdns_hdr DNS_Header = nullptr;
	size_t Index[] = {0, 0};
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);
		memset(Buffer.get() + PACKET_MAXSIZE * Index[0], 0, PACKET_MAXSIZE);
		if (Parameter.EDNS0Label) //EDNS0 Label
			RecvLen = recvfrom(LocalSocketData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], PACKET_MAXSIZE - sizeof(dns_record_opt), 0, (PSOCKADDR)&LocalSocketData.SockAddr, (socklen_t *)&LocalSocketData.AddrLen);
		else 
			RecvLen = recvfrom(LocalSocketData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], PACKET_MAXSIZE, 0, (PSOCKADDR)&LocalSocketData.SockAddr, (socklen_t *)&LocalSocketData.AddrLen);

	//Check address(es).
		if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			Addr = &((PSOCKADDR_IN6)&LocalSocketData.SockAddr)->sin6_addr;
			if (CheckEmptyBuffer(Addr, sizeof(in6_addr)) || //Empty address
			//Check Private Mode(IPv6).
				(Parameter.OperationMode == LISTEN_PRIVATEMODE && 
				!(((in6_addr *)Addr)->s6_bytes[0] >= 0xFC && ((in6_addr *)Addr)->s6_bytes[0] <= 0xFD || //Unique Local Unicast address/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
				((in6_addr *)Addr)->s6_bytes[0] == 0xFE && ((in6_addr *)Addr)->s6_bytes[1U] >= 0x80 && ((in6_addr *)Addr)->s6_bytes[1U] <= 0xBF || //Link-Local Unicast Contrast address(FE80::/10, Section 2.5.6 in RFC 4291)
				((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x0001))) || //Loopback address(::1, Section 2.5.3 in RFC 4291)
			//Check Custom Mode(IPv6).
				Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET6))
					continue;
		}
		else { //IPv4
			Addr = &((PSOCKADDR_IN)&LocalSocketData.SockAddr)->sin_addr;
			if ((*(in_addr *)Addr).s_addr == 0 || //Empty address
			//Check Private Mode(IPv4).
				(Parameter.OperationMode == LISTEN_PRIVATEMODE && 
				!(((in_addr *)Addr)->s_net == 0x0A || //Private class A address(10.0.0.0/8, Section 3 in RFC 1918)
				((in_addr *)Addr)->s_net == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
				((in_addr *)Addr)->s_net == 0xAC && ((in_addr *)Addr)->s_host >= 0x10 && ((in_addr *)Addr)->s_host <= 0x1F || //Private class B address(172.16.0.0/16, Section 3 in RFC 1918)
				((in_addr *)Addr)->s_net == 0xC0 && ((in_addr *)Addr)->s_host == 0xA8)) || //Private class C address(192.168.0.0/24, Section 3 in RFC 1918)
			//Check Custom Mode(IPv4).
				Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET))
					continue;
		}

	//UDP Truncated check
		if (RecvLen > (SSIZE_T)(Parameter.EDNS0PayloadSize - sizeof(dns_record_opt)))
		{
			if (Parameter.EDNS0Label || //EDNS0 Lebal
				RecvLen > (SSIZE_T)Parameter.EDNS0PayloadSize)
			{
			//Make packets with EDNS0 Lebal.
				DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_RTC);
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
				sendto(LocalSocketData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], (int)RecvLen, 0, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen);
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
			for (Index[1U] = sizeof(dns_hdr);Index[1U] < DNS_PACKET_QUERY_LOCATE(Buffer.get() + PACKET_MAXSIZE * Index[0]);++Index[1U])
			{
				if (*(Buffer.get() + PACKET_MAXSIZE * Index[0] + Index[1U]) == '\xC0')
					continue;
			}
			if (Index[1U] != DNS_PACKET_QUERY_LOCATE(Buffer.get() + PACKET_MAXSIZE * Index[0]))
			{
				DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R_FE);
				sendto(LocalSocketData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], (int)RecvLen, 0, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen);
				continue;
			}

		//EDNS0 Label
			if (Parameter.EDNS0Label)
			{
				pdns_record_opt DNS_Record_OPT = nullptr;

			//Not any Additional Resource Records
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
			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				std::thread RequestProcessThread(EnterRequestProcess, Buffer.get() + PACKET_MAXSIZE * Index[0], RecvLen, LocalSocketData, IPPROTO_UDP);
				RequestProcessThread.detach();
			}
			else { //IPv4
				std::thread RequestProcessThread(EnterRequestProcess, Buffer.get() + PACKET_MAXSIZE * Index[0], RecvLen, LocalSocketData, IPPROTO_UDP);
				RequestProcessThread.detach();
			}

			Index[0] = (Index[0] + 1U) % BUFFER_RING_MAXNUM;
		}
		else { //Incorrect packets
			continue;
		}
	}

	shutdown(LocalSocketData.Socket, SD_BOTH);
	closesocket(LocalSocketData.Socket);
	PrintError(LOG_ERROR_SYSTEM, L"UDP listening module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Local DNS server with TCP protocol
size_t __fastcall TCPMonitor(const SOCKET_DATA LocalSocketData)
{
//Set socket timeout.
#if defined(PLATFORM_WIN)
	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_SNDTIMEO, (const char *)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
#endif
	{
		PrintError(LOG_ERROR_NETWORK, L"Set TCP socket timeout error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return EXIT_FAILURE;
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

		return EXIT_FAILURE;
	}
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Socket reuse setting
	int SetVal = 1;
/*	if (setsockopt(LocalSocketData.Socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set TCP socket enable reusing error", errno, nullptr, 0);
		close(LocalSocketData.Socket);

		return EXIT_FAILURE;
	}
*/
//Create an IPv6 server socket that can also accept IPv4 connections on Linux.
//	SetVal = 1;
	if (LocalSocketData.SockAddr.ss_family == AF_INET6 && Parameter.OperationMode != LISTEN_PROXYMODE && 
		setsockopt(LocalSocketData.Socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&SetVal, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Set TCP socket treating wildcard bind error", errno, nullptr, 0);
		close(LocalSocketData.Socket);

		return EXIT_FAILURE;
	}
#endif

//Bind socket to port.
	if (bind(LocalSocketData.Socket, (PSOCKADDR)&LocalSocketData.SockAddr, LocalSocketData.AddrLen) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"Bind TCP Monitor socket error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return EXIT_FAILURE;
	}

//Listen requesting from socket.
	if (listen(LocalSocketData.Socket, SOMAXCONN) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_NETWORK, L"TCP Monitor socket listening initialization error", WSAGetLastError(), nullptr, 0);
		closesocket(LocalSocketData.Socket);

		return EXIT_FAILURE;
	}

//Start Monitor.
	std::shared_ptr<SOCKET_DATA> ClientData(new SOCKET_DATA());
	void *Addr = nullptr;
	ClientData->AddrLen = LocalSocketData.AddrLen;
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME);
		memset(&ClientData->SockAddr, 0, sizeof(sockaddr_storage));
		ClientData->Socket = accept(LocalSocketData.Socket, (PSOCKADDR)&ClientData->SockAddr, &ClientData->AddrLen);
		if (ClientData->Socket == INVALID_SOCKET)
			continue;

	//Check address(es).
		if (ClientData->AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			Addr = &((PSOCKADDR_IN6)&ClientData->SockAddr)->sin6_addr;
			if (CheckEmptyBuffer(Addr, sizeof(in6_addr)) || //Empty address
			//Check Private Mode(IPv6).
				(Parameter.OperationMode == LISTEN_PRIVATEMODE && 
				!(((in6_addr *)Addr)->s6_bytes[0] >= 0xFC && ((in6_addr *)Addr)->s6_bytes[0] <= 0xFD || //Unique Local Unicast address/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
				((in6_addr *)Addr)->s6_bytes[0] == 0xFE && ((in6_addr *)Addr)->s6_bytes[1U] >= 0x80 && ((in6_addr *)Addr)->s6_bytes[1U] <= 0xBF || //Link-Local Unicast Contrast address(FE80::/10, Section 2.5.6 in RFC 4291)
				((in6_addr *)Addr)->s6_words[6U] == 0 && ((in6_addr *)Addr)->s6_words[7U] == htons(0x0001))) || //Loopback address(::1, Section 2.5.3 in RFC 4291)
			//Check Custom Mode(IPv6).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET6)))
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
				(Parameter.OperationMode == LISTEN_PRIVATEMODE && 
				!(((in_addr *)Addr)->s_net == 0x0A || //Private class A address(10.0.0.0/8, Section 3 in RFC 1918)
				((in_addr *)Addr)->s_net == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
				((in_addr *)Addr)->s_net == 0xAC && ((in_addr *)Addr)->s_host >= 0x10 && ((in_addr *)Addr)->s_host <= 0x1F || //Private class B address(172.16.0.0/16, Section 3 in RFC 1918)
				((in_addr *)Addr)->s_net == 0xC0 && ((in_addr *)Addr)->s_host == 0xA8)) || //Private class C address(192.168.0.0/24, Section 3 in RFC 1918)
			//Check Custom Mode(IPv4).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET)))
			{
				shutdown(LocalSocketData.Socket, SD_BOTH);
				closesocket(ClientData->Socket);
				continue;
			}
		}

	//Accept process.
		std::thread TCPReceiveThread(TCPReceiveProcess, *ClientData);
		TCPReceiveThread.detach();
	}

	shutdown(LocalSocketData.Socket, SD_BOTH);
	closesocket(LocalSocketData.Socket);
	PrintError(LOG_ERROR_SYSTEM, L"TCP listening module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//TCP protocol receive process
size_t __fastcall TCPReceiveProcess(const SOCKET_DATA LocalSocketData)
{
	std::shared_ptr<char> Buffer(new char[LARGE_PACKET_MAXSIZE]());
	memset(Buffer.get(), 0, LARGE_PACKET_MAXSIZE);
	size_t InnerIndex = 0;
	SSIZE_T RecvLen = 0;

//Receive
	if (Parameter.EDNS0Label) //EDNS0 Label
		RecvLen = recv(LocalSocketData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE - sizeof(dns_record_opt), 0);
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
			return EXIT_FAILURE;
		}
		memset(Buffer.get(), 0, RecvLen);
		if (Parameter.EDNS0Label) //EDNS0 Label
			RecvLen = recv(LocalSocketData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE - sizeof(dns_record_opt), 0);
		else 
			RecvLen = recv(LocalSocketData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE, 0);

	//Receive packet.
		if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && RecvLen >= (SSIZE_T)PDU_Len)
		{
		//Check requesting.
			auto DNS_Header = (pdns_hdr)Buffer.get();
			if (DNS_Header->Questions != htons(U16_NUM_ONE) || ntohs(DNS_Header->Flags) >> 15U > 0 || 
				DNS_Header->Answer > 0 || ntohs(DNS_Header->Additional) > U16_NUM_ONE || DNS_Header->Authority > 0)
			{
				shutdown(LocalSocketData.Socket, SD_BOTH);
				closesocket(LocalSocketData.Socket);
				return EXIT_FAILURE;
			}
			for (InnerIndex = sizeof(dns_hdr);InnerIndex < DNS_PACKET_QUERY_LOCATE(Buffer.get());++InnerIndex)
			{
				if (*(Buffer.get() + InnerIndex) == '\xC0')
					break;
			}
			if (InnerIndex != DNS_PACKET_QUERY_LOCATE(Buffer.get()))
			{
				DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R_FE);
				send(LocalSocketData.Socket, Buffer.get(), (int)RecvLen, 0);

				shutdown(LocalSocketData.Socket, SD_BOTH);
				closesocket(LocalSocketData.Socket);
				return EXIT_FAILURE;
			}

		//EDNS0 Label
			if (Parameter.EDNS0Label)
			{
				pdns_record_opt DNS_Record_OPT = nullptr;

			//Not any Additional Resource Records
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

			if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				EnterRequestProcess(Buffer.get(), PDU_Len, LocalSocketData, IPPROTO_TCP);
			else //IPv4
				EnterRequestProcess(Buffer.get(), PDU_Len, LocalSocketData, IPPROTO_TCP);
		}
		else {
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
			return EXIT_FAILURE;
		}
	}
	else if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && RecvLen >= (SSIZE_T)htons(((uint16_t *)Buffer.get())[0]) && htons(((uint16_t *)Buffer.get())[0]) < LARGE_PACKET_MAXSIZE)
	{
		RecvLen = htons(((uint16_t *)Buffer.get())[0]);

	//Check requesting.
		auto DNS_Header = (pdns_hdr)(Buffer.get() + sizeof(uint16_t));
		if (DNS_Header->Questions != htons(U16_NUM_ONE) || ntohs(DNS_Header->Flags) >> 15U > 0 || 
			DNS_Header->Answer > 0 || ntohs(DNS_Header->Additional) > U16_NUM_ONE || DNS_Header->Authority > 0)
		{
			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
			return EXIT_FAILURE;
		}
		for (InnerIndex = sizeof(dns_tcp_hdr);InnerIndex < DNS_TCP_PACKET_QUERY_LOCATE(Buffer.get());++InnerIndex)
		{
			if (*(Buffer.get() + InnerIndex) == '\xC0')
				break;
		}
		if (InnerIndex != DNS_TCP_PACKET_QUERY_LOCATE(Buffer.get()))
		{
			DNS_Header->Flags = htons(ntohs(DNS_Header->Flags) | DNS_SET_R_FE);
			send(LocalSocketData.Socket, Buffer.get(), (int)RecvLen + sizeof(uint16_t), 0);

			shutdown(LocalSocketData.Socket, SD_BOTH);
			closesocket(LocalSocketData.Socket);
			return EXIT_FAILURE;
		}

	//EDNS0 Label
		if (Parameter.EDNS0Label)
		{
			pdns_record_opt DNS_Record_OPT = nullptr;

		//Not any Additional Resource Records
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
		if (LocalSocketData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			EnterRequestProcess(Buffer.get() + sizeof(uint16_t), RecvLen, LocalSocketData, IPPROTO_TCP);
		else //IPv4
			EnterRequestProcess(Buffer.get() + sizeof(uint16_t), RecvLen, LocalSocketData, IPPROTO_TCP);
	}
	else {
		shutdown(LocalSocketData.Socket, SD_BOTH);
		closesocket(LocalSocketData.Socket);
		return EXIT_FAILURE;
	}

//Block Port Unreachable messages of system.
	shutdown(LocalSocketData.Socket, SD_BOTH);
#if defined(PLATFORM_WIN)
	Sleep(Parameter.ReliableSocketTimeout);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	usleep(Parameter.ReliableSocketTimeout.tv_sec * SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND + Parameter.ReliableSocketTimeout.tv_usec);
#endif
	closesocket(LocalSocketData.Socket);
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
	//Complete Requesting check
		for (Index = 0;Index < ALTERNATE_SERVERNUM;++Index)
		{
		//Reset TimeoutTimes out of alternate time range.
		#if (defined(PLATFORM_WIN32) && !defined(PLATFORM_WIN64))
			if (Parameter.GetTickCount64PTR != nullptr && (*Parameter.GetTickCount64PTR)() >= RangeTimer[Index] || GetTickCount() >= RangeTimer[Index])
			{
				if (Parameter.GetTickCount64PTR != nullptr)
					RangeTimer[Index] = (size_t)((*Parameter.GetTickCount64PTR)() + Parameter.AlternateTimeRange);
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
				if (Parameter.GetTickCount64PTR != nullptr && (*Parameter.GetTickCount64PTR)() >= SwapTimer[Index] || GetTickCount() >= SwapTimer[Index])
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
					if (Parameter.GetTickCount64PTR != nullptr)
						SwapTimer[Index] = (size_t)((*Parameter.GetTickCount64PTR)() + Parameter.AlternateResetTime);
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

#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Flush DNS cache FIFO Monitor
size_t FlushDNSFIFOMonitor(void)
{
//Initialization
	unlink(FIFO_PATH_NAME);
	std::shared_ptr<char> Buffer(new char[PACKET_MAXSIZE]());
	memset(Buffer.get(), 0, PACKET_MAXSIZE);
	int FIFO_FD = 0;

//Create FIFO.
	if (mkfifo(FIFO_PATH_NAME, O_CREAT) < 0 || chmod(FIFO_PATH_NAME, S_IRUSR|S_IWUSR|S_IWGRP|S_IWOTH) < 0)
	{
		PrintError(LOG_ERROR_SYSTEM, L"Create FIFO error", errno, nullptr, 0);

		unlink(FIFO_PATH_NAME);
		return EXIT_FAILURE;
	}

//Open FIFO.
	FIFO_FD = open(FIFO_PATH_NAME, O_RDONLY, 0);
	if (FIFO_FD < 0)
	{
		PrintError(LOG_ERROR_SYSTEM, L"Create FIFO error", errno, nullptr, 0);

		unlink(FIFO_PATH_NAME);
		return EXIT_FAILURE;
	}

//FIFO Monitor
	for (;;)
	{
		if (read(FIFO_FD, Buffer.get(), PACKET_MAXSIZE) > 0 && 
			memcmp(Buffer.get(), FIFO_MESSAGE_FLUSH_DNS, strlen(FIFO_MESSAGE_FLUSH_DNS)) == 0)
				FlushSystemDNSCache();

		memset(Buffer.get(), 0, PACKET_MAXSIZE);
		Sleep(MONITOR_LOOP_INTERVAL_TIME);
	}

	close(FIFO_FD);
	unlink(FIFO_PATH_NAME);
	PrintError(LOG_ERROR_SYSTEM, L"FIFO module Monitor terminated", 0, nullptr, 0);
	return EXIT_SUCCESS;
}

//Flush DNS cache FIFO sender
size_t FlushDNSFIFOSender(void)
{
	int FIFO_FD = open(FIFO_PATH_NAME, O_WRONLY|O_TRUNC|O_NONBLOCK, 0);
	if (FIFO_FD > 0 && write(FIFO_FD, FIFO_MESSAGE_FLUSH_DNS, strlen(FIFO_MESSAGE_FLUSH_DNS)) > 0)
	{
		wprintf(L"Flush DNS cache message was sent successfully.\n");
		close(FIFO_FD);
	}
	else {
		PrintError(LOG_ERROR_SYSTEM, L"FIFO write messages error", GetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
#endif
