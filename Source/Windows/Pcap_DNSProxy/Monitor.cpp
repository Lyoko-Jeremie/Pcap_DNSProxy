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


#include "Pcap_DNSProxy.h"

extern ConfigurationTable Parameter;
extern DNSCurveConfigurationTable DNSCurveParameter;
extern AlternateSwapTable AlternateSwapList;
extern std::deque<DNSCacheData> DNSCacheList;
extern std::mutex DNSCacheListLock;

//Local DNS server initialization
size_t __fastcall MonitorInit()
{
//Capture initialization
	if (Parameter.PcapCapture && !Parameter.HostsOnly && !(Parameter.DNSCurve && DNSCurveParameter.IsEncryption && DNSCurveParameter.IsEncryptionOnly))
	{
		std::thread CaptureInitializationThread(CaptureInit);
		CaptureInitializationThread.detach();

	//Get Hop Limits/TTL with normal DNS request.
		if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL)
		{
			std::thread IPv6TestDoaminThread(DomainTestRequest, AF_INET6); //Get Hop Limits.
			IPv6TestDoaminThread.detach();
		}

		if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL) //Get TTL.
		{
			std::thread IPv4TestDoaminThread(DomainTestRequest, AF_INET);
			IPv4TestDoaminThread.detach();
		}

		//Get Hop Limits/TTL with ICMP Echo.
		if (Parameter.ICMPSpeed > 0)
		{
			//ICMPv6
			if (Parameter.DNSTarget.IPv6.AddressData.Storage.ss_family != NULL)
			{
				std::thread ICMPv6Thread(ICMPv6Echo);
				ICMPv6Thread.detach();
			}

			//ICMP
			if (Parameter.DNSTarget.IPv4.AddressData.Storage.ss_family != NULL)
			{
				std::thread ICMPThread(ICMPEcho);
				ICMPThread.detach();
			}
		}
	}

//Set Preferred DNS servers switcher.
	if (!Parameter.AlternateMultiRequest && 
		Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL || Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL || 
		Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family != NULL || Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family != NULL || 
		DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL || DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
	{
		std::thread AlternateServerMonitorThread(AlternateServerMonitor);
		AlternateServerMonitorThread.detach();
	}

	std::shared_ptr<SOCKET_DATA> LocalhostData(new SOCKET_DATA());
	std::thread IPv6UDPMonitorThread, IPv4UDPMonitorThread, IPv6TCPMonitorThread, IPv4TCPMonitorThread;
//Set localhost socket(IPv6/UDP).
	LocalhostData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (LocalhostData->Socket == INVALID_SOCKET || Parameter.ListenProtocol == LISTEN_IPV4)
	{
		if ( /* IsWindowsVistaOrGreater() || */ WSAGetLastError() != 0 && WSAGetLastError() != WSAEAFNOSUPPORT)
			PrintError(LOG_ERROR_WINSOCK, L"IPv6 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, NULL);
	}
	else {
		Parameter.LocalSocket[0] = LocalhostData->Socket;
		if (Parameter.OperationMode == LISTEN_PROXYMODE) //Proxy Mode
			((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_addr = in6addr_loopback;
		else //Server Mode, Priavte Mode and Custom Mode
			((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_addr = in6addr_any;
		LocalhostData->SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_port = Parameter.ListenPort;
		LocalhostData->AddrLen = sizeof(sockaddr_in6);

		std::thread MonitorThreadTemp(UDPMonitor, *LocalhostData);
		IPv6UDPMonitorThread.swap(MonitorThreadTemp);
	}
	memset(LocalhostData.get(), 0, sizeof(SOCKET_DATA));

//Set localhost socket(IPv6/TCP).
	LocalhostData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (LocalhostData->Socket == INVALID_SOCKET || Parameter.ListenProtocol == LISTEN_IPV4)
	{
		if ( /* IsWindowsVistaOrGreater() || */ WSAGetLastError() != 0 && WSAGetLastError() != WSAEAFNOSUPPORT)
			PrintError(LOG_ERROR_WINSOCK, L"IPv6 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, NULL);
	}
	else {
		Parameter.LocalSocket[2U] = LocalhostData->Socket;
		if (Parameter.OperationMode == LISTEN_PROXYMODE) //Proxy Mode
			((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_addr = in6addr_loopback;
		else //Server Mode, Priavte Mode and Custom Mode
			((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_addr = in6addr_any;
		LocalhostData->SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&LocalhostData->SockAddr)->sin6_port = Parameter.ListenPort;
		LocalhostData->AddrLen = sizeof(sockaddr_in6);

		std::thread MonitorThreadTemp(TCPMonitor, *LocalhostData);
		IPv6TCPMonitorThread.swap(MonitorThreadTemp);
	}
	memset(LocalhostData.get(), 0, sizeof(SOCKET_DATA));

//Set localhost socket(IPv4/UDP).
	LocalhostData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (LocalhostData->Socket == INVALID_SOCKET || Parameter.ListenProtocol == LISTEN_IPV6)
	{
		PrintError(LOG_ERROR_WINSOCK, L"IPv4 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, NULL);
	}
	else {
		Parameter.LocalSocket[1U] = LocalhostData->Socket;
		if (Parameter.OperationMode == LISTEN_PROXYMODE) //Proxy Mode
			((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
		else //Server Mode, Priavte Mode and Custom Mode
			((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_addr.S_un.S_addr = INADDR_ANY;
		LocalhostData->SockAddr.ss_family = AF_INET;
		((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_port = Parameter.ListenPort;
		LocalhostData->AddrLen = sizeof(sockaddr_in);

		std::thread MonitorThreadTemp(UDPMonitor, *LocalhostData);
		IPv4UDPMonitorThread.swap(MonitorThreadTemp);
	}
	memset(LocalhostData.get(), 0, sizeof(SOCKET_DATA));

//Set localhost socket(IPv4/TCP).
	LocalhostData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (LocalhostData->Socket == INVALID_SOCKET || Parameter.ListenProtocol == LISTEN_IPV6)
	{
		PrintError(LOG_ERROR_WINSOCK, L"IPv4 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, NULL);
	}
	else {
		Parameter.LocalSocket[3U] = LocalhostData->Socket;
		if (Parameter.OperationMode == LISTEN_PROXYMODE) //Proxy Mode
			((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
		else //Server Mode, Priavte Mode and Custom Mode
			((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_addr.S_un.S_addr = INADDR_ANY;
		LocalhostData->SockAddr.ss_family = AF_INET;
		((PSOCKADDR_IN)&LocalhostData->SockAddr)->sin_port = Parameter.ListenPort;
		LocalhostData->AddrLen = sizeof(sockaddr_in);

		std::thread MonitorThreadTemp(TCPMonitor, *LocalhostData);
		IPv4TCPMonitorThread.swap(MonitorThreadTemp);
	}
	LocalhostData.reset();

//Join threads.
	if (IPv6UDPMonitorThread.joinable())
		IPv6UDPMonitorThread.join();
	if (IPv4UDPMonitorThread.joinable())
		IPv4UDPMonitorThread.join();
	if (IPv6TCPMonitorThread.joinable())
		IPv6TCPMonitorThread.join();
	if (IPv4TCPMonitorThread.joinable())
		IPv4TCPMonitorThread.join();

	return EXIT_SUCCESS;
}

//Local DNS server with UDP protocol
size_t __fastcall UDPMonitor(const SOCKET_DATA LocalhostData)
{
//Block WSAECONNRESET error of UDP Monitor.
	DWORD BytesReturned = 0;
	BOOL NewBehavior = FALSE;
	SSIZE_T RecvLen = WSAIoctl(LocalhostData.Socket, SIO_UDP_CONNRESET, &NewBehavior, sizeof(BOOL), NULL, 0, &BytesReturned, NULL, NULL);
	if (RecvLen == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket SIO_UDP_CONNRESET error", WSAGetLastError(), nullptr, NULL);
		closesocket(LocalhostData.Socket);

		return EXIT_FAILURE;
	}

//Set socket timeout.
	if (setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, NULL);
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
		PrintError(LOG_ERROR_WINSOCK, L"Bind UDP Monitor socket error", WSAGetLastError(), nullptr, NULL);
		closesocket(LocalhostData.Socket);

		return EXIT_FAILURE;
	}

//Start Monitor.
	std::shared_ptr<char> Buffer(new char[PACKET_MAXSIZE * BUFFER_RING_MAXNUM]());
	size_t Index[] = {0, 0, 0};

	void *Addr = nullptr;
	dns_hdr *pdns_hdr = nullptr;
	for (;;)
	{
		memset(Buffer.get() + PACKET_MAXSIZE * Index[0], 0, PACKET_MAXSIZE);
		if (Parameter.EDNS0Label) //EDNS0 Label
			RecvLen = recvfrom(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], PACKET_MAXSIZE - sizeof(dns_opt_record), NULL, (PSOCKADDR)&LocalhostData.SockAddr, (PINT)&LocalhostData.AddrLen);
		else 
			RecvLen = recvfrom(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], PACKET_MAXSIZE, NULL, (PSOCKADDR)&LocalhostData.SockAddr, (PINT)&LocalhostData.AddrLen);

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
				(Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET6)) ||
			//Check Server Mode(IPv6).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.OperationMode == LISTEN_SERVERMODE) &&
				CheckSpecialAddress(Addr, AF_INET6, nullptr) // || 
/* Old version(2014-12-28)
			//Target DNS Server check
				memcmp(Addr, &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 ||
				memcmp(Addr, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 ||
				memcmp(Addr, &Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 ||
				memcmp(Addr, &Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0
*/
				)
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
				(Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET)) ||
			//Check Server Mode(IPv4).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.OperationMode == LISTEN_SERVERMODE) &&
				CheckSpecialAddress(Addr, AF_INET, nullptr) // || 
/* Old version(2014-12-28)
			//Target DNS Server check
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr.S_un.S_addr ||
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr ||
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr ||
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr
*/
				)
					continue;
		}

	//UDP Truncated check
		if (RecvLen > (SSIZE_T)(Parameter.EDNS0PayloadSize - sizeof(dns_opt_record)))
		{
			if (Parameter.EDNS0Label || //EDNS0 Lebal
				RecvLen > (SSIZE_T)Parameter.EDNS0PayloadSize)
			{
			//Make packets with EDNS0 Lebal.
//				pdns_hdr->Flags = htons(DNS_SQR_NETC);
				pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8200); //Set 1000001000000000, DNS_SQR_NETC
				dns_opt_record *pdns_opt_record = nullptr;
				if (pdns_hdr->Additional == 0)
				{
					pdns_hdr->Additional = htons(U16_NUM_ONE);
					pdns_opt_record = (dns_opt_record *)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen);
					pdns_opt_record->Type = htons(DNS_RECORD_OPT);
					pdns_opt_record->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					RecvLen += sizeof(dns_opt_record);
				}
				else if (pdns_hdr->Additional == htons(U16_NUM_ONE))
				{
					pdns_opt_record = (dns_opt_record *)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen - sizeof(dns_opt_record));
					if (pdns_opt_record->Type == htons(DNS_RECORD_OPT))
						pdns_opt_record->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				}
				else {
					continue;
				}

			//Send requesting.
				sendto(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], (int)RecvLen, NULL, (PSOCKADDR)&LocalhostData.SockAddr, LocalhostData.AddrLen);
				continue;
			}
		}

	//Receive process.
		if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
		{
		//Check requesting.
			pdns_hdr = (dns_hdr *)(Buffer.get() + PACKET_MAXSIZE * Index[0]);
			if (pdns_hdr->Questions != htons(U16_NUM_ONE) || pdns_hdr->Answer > 0 || ntohs(pdns_hdr->Additional) > U16_NUM_ONE || pdns_hdr->Authority > 0)
				continue;
			for (Index[2U] = sizeof(dns_hdr);Index[2U] < DNS_PACKET_QUERY_LOCATE(Buffer.get() + PACKET_MAXSIZE * Index[0]);Index[2U]++)
			{
				if (*(Buffer.get() + PACKET_MAXSIZE * Index[0] + Index[2U]) == '\xC0')
					continue;
			}
			if (Index[2U] != DNS_PACKET_QUERY_LOCATE(Buffer.get() + PACKET_MAXSIZE * Index[0]))
			{
//				pdns_hdr->Flags = htons(DNS_SQR_FE);
				pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8001); //Set 10000000000000001, DNS_SQR_FE
				sendto(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], (int)RecvLen, NULL, (PSOCKADDR)&LocalhostData.SockAddr, LocalhostData.AddrLen);
				continue;
			}

		//EDNS0 Label
			if (Parameter.EDNS0Label)
			{
				dns_opt_record *pdns_opt_record = nullptr;

			//No additional
				if (pdns_hdr->Additional == 0)
				{
					pdns_hdr->Additional = htons(U16_NUM_ONE);
					pdns_opt_record = (dns_opt_record *)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen);
					pdns_opt_record->Type = htons(DNS_RECORD_OPT);
					pdns_opt_record->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					RecvLen += sizeof(dns_opt_record);
				}
			//Already have Additional Resource Records
				else {
					pdns_opt_record = (dns_opt_record *)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen - sizeof(dns_opt_record));
					if (pdns_opt_record->Type == htons(DNS_RECORD_OPT))
						pdns_opt_record->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				}

			//DNSSEC
				if (Parameter.DNSSECRequest && pdns_opt_record->Type == htons(DNS_RECORD_OPT))
				{
					pdns_hdr->FlagsBits.AD = ~pdns_hdr->FlagsBits.AD; //Local DNSSEC Server validate
					pdns_hdr->FlagsBits.CD = ~pdns_hdr->FlagsBits.CD; //Client validate
					pdns_opt_record->Z_Bits.DO = ~pdns_opt_record->Z_Bits.DO; //Accepts DNSSEC security Resource Records
				}
			}

		//Request process
			if (LocalhostData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				std::thread RequestProcessThread(EnterRequestProcess, Buffer.get() + PACKET_MAXSIZE * Index[0], RecvLen, LocalhostData, IPPROTO_UDP, Index[1U]);
				RequestProcessThread.detach();
			}
			else { //IPv4
				std::thread RequestProcessThread(EnterRequestProcess, Buffer.get() + PACKET_MAXSIZE * Index[0], RecvLen, LocalhostData, IPPROTO_UDP, Index[1U] + QUEUE_MAXLEN);
				RequestProcessThread.detach();
			}

			Index[0] = (Index[0] + 1U) % BUFFER_RING_MAXNUM;
			Index[1U] = (Index[1U] + 1U) % QUEUE_MAXLEN;
		}
/*		else if (RecvLen == 0)
		{
			continue;
		}
		else if (RecvLen < 0) //SOCKET_ERROR
		{
			if (WSAGetLastError() != 0 && WSAGetLastError() != WSAETIMEDOUT)
			{
				PrintError(LOG_ERROR_WINSOCK, L"UDP Monitor socket listening error", WSAGetLastError(), nullptr, NULL);
				closesocket(LocalhostData.Socket);

				return EXIT_FAILURE;
			}
			else {
				continue;
			}
		}
*/
		else { //Incorrect packets
//			pdns_hdr->Flags = htons(DNS_SQR_FE);
//			sendto(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], (int)RecvLen, NULL, (PSOCKADDR)&LocalhostData.SockAddr, LocalhostData.AddrLen);
			Sleep(LOOP_INTERVAL_TIME);
			continue;
		}
	}

	closesocket(LocalhostData.Socket);
	PrintError(LOG_ERROR_SYSTEM, L"UDP listening module Monitor terminated", NULL, nullptr, NULL);
	return EXIT_SUCCESS;
}

//Local DNS server with TCP protocol
size_t __fastcall TCPMonitor(const SOCKET_DATA LocalhostData)
{
//Set socket timeout.
	if (setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket timeout error", WSAGetLastError(), nullptr, NULL);
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
		PrintError(LOG_ERROR_WINSOCK, L"Bind TCP Monitor socket error", WSAGetLastError(), nullptr, NULL);
		closesocket(LocalhostData.Socket);

		return EXIT_FAILURE;
	}

//Listen request from socket.
	if (listen(LocalhostData.Socket, SOMAXCONN) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"TCP Monitor socket listening initialization error", WSAGetLastError(), nullptr, NULL);
		closesocket(LocalhostData.Socket);

		return EXIT_FAILURE;
	}

//Start Monitor.
	std::shared_ptr<SOCKET_DATA> ClientData(new SOCKET_DATA());
	void *Addr = nullptr;
	size_t Index = 0;
	ClientData->AddrLen = LocalhostData.AddrLen;
	for (;;)
	{
		memset(ClientData.get(), 0, sizeof(SOCKET_DATA) - sizeof(int));
		ClientData->Socket = accept(LocalhostData.Socket, (PSOCKADDR)&ClientData->SockAddr, (PINT)&ClientData->AddrLen);
		if (ClientData->Socket == INVALID_SOCKET)
		{
			Sleep(LOOP_INTERVAL_TIME);
			continue;
		}

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
				(Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET6)) || 
			//Check Server Mode(IPv6).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.OperationMode == LISTEN_SERVERMODE) && 
				CheckSpecialAddress(Addr, AF_INET6, nullptr) // || 
/* Old version(2014-12-28)
			//Target DNS Server check
				memcmp(Addr, &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 || 
				memcmp(Addr, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 || 
				memcmp(Addr, &Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 || 
				memcmp(Addr, &Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0
*/
				)
			{
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
				(Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET)) || 
			//Check Server Mode(IPv4).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.OperationMode == LISTEN_SERVERMODE) && 
				CheckSpecialAddress(Addr, AF_INET, nullptr) // || 
/* Old version(2014-12-28)
			//Target DNS Server check
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr.S_un.S_addr || 
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr || 
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr || 
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr
*/
				)
			{
				closesocket(ClientData->Socket);
				continue;
			}
		}

	//Accept process.
		std::thread TCPReceiveThread(TCPReceiveProcess, *ClientData, Index);
		TCPReceiveThread.detach();

		Index = (Index + 1U) % QUEUE_MAXLEN;
	}

	closesocket(LocalhostData.Socket);
	PrintError(LOG_ERROR_SYSTEM, L"TCP listening module Monitor terminated", NULL, nullptr, NULL);
	return EXIT_SUCCESS;
}

//TCP protocol receive process
size_t __fastcall TCPReceiveProcess(const SOCKET_DATA TargetData, const size_t ListIndex)
{
	std::shared_ptr<char> Buffer(new char[LARGE_PACKET_MAXSIZE]());
	size_t InnerIndex = 0;
	SSIZE_T RecvLen = 0;

//Receive
	if (Parameter.EDNS0Label) //EDNS0 Label
		RecvLen = recv(TargetData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE - sizeof(dns_opt_record), NULL);
	else 
		RecvLen = recv(TargetData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE, NULL);
	if (RecvLen == (SSIZE_T)sizeof(uint16_t)) //TCP segment of a reassembled PDU
	{
	//Receive without PDU.
		uint16_t PDU_Len = ntohs(((uint16_t *)Buffer.get())[0]);
		memset(Buffer.get(), 0, RecvLen);
		if (Parameter.EDNS0Label) //EDNS0 Label
			RecvLen = recv(TargetData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE - sizeof(dns_opt_record), NULL);
		else 
			RecvLen = recv(TargetData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE, NULL);

	//Receive packet.
		if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && (SSIZE_T)PDU_Len >= RecvLen)
		{
		//Check requesting.
			auto pdns_hdr = (dns_hdr *)Buffer.get();
			if (pdns_hdr->Questions != htons(U16_NUM_ONE) || ntohs(pdns_hdr->Flags) >> 15U > 0 || 
				pdns_hdr->Answer > 0 || ntohs(pdns_hdr->Additional) > U16_NUM_ONE || pdns_hdr->Authority > 0)
			{
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
//				pdns_hdr->Flags = htons(DNS_SQR_FE);
				pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8001); //Set 10000000000000001, DNS_SQR_FE
				send(TargetData.Socket, Buffer.get(), (int)RecvLen, NULL);

				closesocket(TargetData.Socket);
				return EXIT_FAILURE;
			}

		//EDNS0 Label
			if (Parameter.EDNS0Label)
			{
				dns_opt_record *pdns_opt_record = nullptr;

			//No additional
				if (pdns_hdr->Additional == 0)
				{
					pdns_hdr->Additional = htons(U16_NUM_ONE);
					pdns_opt_record = (dns_opt_record *)(Buffer.get() + PDU_Len);
					pdns_opt_record->Type = htons(DNS_RECORD_OPT);
					pdns_opt_record->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					PDU_Len += sizeof(dns_opt_record);
				}
			//Already have Additional Resource Records
				else {
					pdns_opt_record = (dns_opt_record *)(Buffer.get() + PDU_Len - sizeof(dns_opt_record));
					if (pdns_opt_record->Type == htons(DNS_RECORD_OPT))
						pdns_opt_record->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				}

			//DNSSEC
				if (Parameter.DNSSECRequest && pdns_opt_record->Type == htons(DNS_RECORD_OPT))
				{
					pdns_hdr->FlagsBits.AD = ~pdns_hdr->FlagsBits.AD; //Local DNSSEC Server validate
					pdns_hdr->FlagsBits.CD = ~pdns_hdr->FlagsBits.CD; //Client validate
					pdns_opt_record->Z_Bits.DO = ~pdns_opt_record->Z_Bits.DO; //Accepts DNSSEC security Resource Records
				}
			}

			if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				EnterRequestProcess(Buffer.get(), PDU_Len, TargetData, IPPROTO_TCP, ListIndex + QUEUE_MAXLEN * (QUEUE_PARTNUM - 2U));
			else //IPv4
				EnterRequestProcess(Buffer.get(), PDU_Len, TargetData, IPPROTO_TCP, ListIndex + QUEUE_MAXLEN * (QUEUE_PARTNUM - 1U));
		}
		else {
			closesocket(TargetData.Socket);
			return EXIT_FAILURE;
		}
	}
	else if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && (SSIZE_T)htons(((uint16_t *)Buffer.get())[0]) <= RecvLen)
	{
		RecvLen = htons(((uint16_t *)Buffer.get())[0]);

	//Check requesting.
		auto pdns_hdr = (dns_hdr *)(Buffer.get() + sizeof(uint16_t));
		if (pdns_hdr->Questions != htons(U16_NUM_ONE) || ntohs(pdns_hdr->Flags) >> 15U > 0 || 
			pdns_hdr->Answer > 0 || ntohs(pdns_hdr->Additional) > U16_NUM_ONE || pdns_hdr->Authority > 0)
		{
			closesocket(TargetData.Socket);
			return EXIT_FAILURE;
		}
		for (InnerIndex = sizeof(tcp_dns_hdr);InnerIndex < DNS_TCP_PACKET_QUERY_LOCATE(Buffer.get());InnerIndex++)
		{
			if (*(Buffer.get() + InnerIndex) == '\xC0')
				break;
		}
		if (InnerIndex != DNS_TCP_PACKET_QUERY_LOCATE(Buffer.get()))
		{
//			pdns_hdr->Flags = htons(DNS_SQR_FE);
			pdns_hdr->Flags = htons(ntohs(pdns_hdr->Flags) | 0x8001); //Set 10000000000000001, DNS_SQR_FE
			send(TargetData.Socket, Buffer.get(), (int)RecvLen + sizeof(uint16_t), NULL);

			closesocket(TargetData.Socket);
			return EXIT_FAILURE;
		}

	//EDNS0 Label
		if (Parameter.EDNS0Label)
		{
			dns_opt_record *pdns_opt_record = nullptr;

		//No additional
			if (pdns_hdr->Additional == 0)
			{
				pdns_hdr->Additional = htons(U16_NUM_ONE);
				pdns_opt_record = (dns_opt_record *)(Buffer.get() + sizeof(uint16_t) + RecvLen);
				pdns_opt_record->Type = htons(DNS_RECORD_OPT);
				pdns_opt_record->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				RecvLen += sizeof(dns_opt_record);
			}
		//Already have Additional Resource Records
			else {
				pdns_opt_record = (dns_opt_record *)(Buffer.get() + sizeof(uint16_t) + RecvLen - sizeof(dns_opt_record));
				if (pdns_opt_record->Type == htons(DNS_RECORD_OPT))
					pdns_opt_record->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
			}

		//DNSSEC
			if (Parameter.DNSSECRequest && pdns_opt_record->Type == htons(DNS_RECORD_OPT))
			{
				pdns_hdr->FlagsBits.AD = ~pdns_hdr->FlagsBits.AD; //Local DNSSEC Server validate
				pdns_hdr->FlagsBits.CD = ~pdns_hdr->FlagsBits.CD; //Client validate
				pdns_opt_record->Z_Bits.DO = ~pdns_opt_record->Z_Bits.DO; //Accepts DNSSEC security Resource Records
			}
		}

	//Request process
		if (TargetData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			EnterRequestProcess(Buffer.get() + sizeof(uint16_t), RecvLen, TargetData, IPPROTO_TCP, ListIndex + QUEUE_MAXLEN * (QUEUE_PARTNUM - 2U));
		else //IPv4
			EnterRequestProcess(Buffer.get() + sizeof(uint16_t), RecvLen, TargetData, IPPROTO_TCP, ListIndex + QUEUE_MAXLEN * (QUEUE_PARTNUM - 1U));
	}
	else {
		closesocket(TargetData.Socket);
		return EXIT_FAILURE;
	}

//Block Port Unreachable messages of system.
	Sleep(Parameter.ReliableSocketTimeout);
	closesocket(TargetData.Socket);
	return EXIT_SUCCESS;
}

//Alternate DNS servers switcher
inline void __fastcall AlternateServerMonitor(void)
{
	size_t Index = 0, RangeTimer[ALTERNATE_SERVERNUM] = {0}, SwapTimer[ALTERNATE_SERVERNUM] = {0};

//Switcher
//Minimum supported system of GetTickCount64() is Windows Vista.
	for (;;)
	{
	//Pcap Requesting check
		for (Index = 0;Index < QUEUE_MAXLEN * QUEUE_PARTNUM;Index++)
		{
			if (AlternateSwapList.PcapAlternateTimeout[Index] != 0 && 
			#ifdef _WIN64
				GetTickCount64() >= /* Parameter.ReliableSocketTimeout + */ AlternateSwapList.PcapAlternateTimeout[Index]) //Check timeout.
			#else //x86
				GetTickCount() >= /* Parameter.ReliableSocketTimeout + */ AlternateSwapList.PcapAlternateTimeout[Index]) //Check timeout.
			#endif
			{
				AlternateSwapList.PcapAlternateTimeout[Index] = 0;
				if (AlternateSwapList.IsSwap[2U] == false && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL &&
					Index >= 0 && Index < QUEUE_MAXLEN * (QUEUE_PARTNUM - 3U) || Index >= QUEUE_MAXLEN * (QUEUE_PARTNUM - 2U) && Index < QUEUE_MAXLEN * (QUEUE_PARTNUM - 1U)) //IPv6
						AlternateSwapList.TimeoutTimes[2U]++;
				else if (AlternateSwapList.IsSwap[3U] == false && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL) //IPv4
					AlternateSwapList.TimeoutTimes[3U]++;
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
			if (GetTickCount() >= RangeTimer[Index])
			{
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
				if (GetTickCount() >= SwapTimer[Index])
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
					SwapTimer[Index] = GetTickCount() + Parameter.AlternateResetTime;
				#endif
				}
			}
		}

		Sleep(STANDARD_TIMEOUT); //Time between checks.
	}

	PrintError(LOG_ERROR_SYSTEM, L"Alternate Server module Monitor terminated", NULL, nullptr, NULL);
	return;
}

//DNS Cache timers monitor
void __fastcall DNSCacheTimerMonitor(void)
{
	std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	DNSCacheListMutex.unlock();
	for (;;)
	{
	//Minimum supported system of GetTickCount64() is Windows Vista.
		DNSCacheListMutex.lock();
	#ifdef _WIN64
		while (!DNSCacheList.empty() && GetTickCount64() >= DNSCacheList.front().ClearTime)
	#else //x86
		while (!DNSCacheList.empty() && GetTickCount() >= DNSCacheList.front().ClearTime)
	#endif
			DNSCacheList.pop_front();

		DNSCacheList.shrink_to_fit();
		DNSCacheListMutex.unlock();

		Sleep(STANDARD_TIMEOUT); //Time between checks.
	}

	PrintError(LOG_ERROR_SYSTEM, L"DNS Cache Timer module Monitor terminated", NULL, nullptr, NULL);
	return;
}
