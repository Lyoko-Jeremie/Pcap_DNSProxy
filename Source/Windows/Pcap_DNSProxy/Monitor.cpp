// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
// Copyright (C) 2012-2014 Chengr28
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

extern Configuration Parameter;
extern std::deque<DNSCacheData> DNSCacheList;
extern std::mutex DNSCacheListLock;
extern DNSCurveConfiguration DNSCurveParameter;
extern AlternateSwapTable AlternateSwapList;

//Local DNS server initialization
size_t __fastcall MonitorInit()
{
//Capture initialization
	if (Parameter.PcapCapture && !Parameter.HostsOnly && !(Parameter.DNSCurve && DNSCurveParameter.Encryption && DNSCurveParameter.EncryptionOnly))
	{
		std::thread CaptureInitializationThread(CaptureInit);
		CaptureInitializationThread.detach();
	}

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
	if (Parameter.ICMPOptions.ICMPSpeed > 0)
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

//Set Preferred DNS servers switcher.
	if (Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL || Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL || 
		Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.Storage.ss_family != NULL || Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.Storage.ss_family != NULL || 
		DNSCurveParameter.DNSCurveTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL || DNSCurveParameter.DNSCurveTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL)
	{
		std::thread AlternateServerSwitcherThread(AlternateServerSwitcher);
		AlternateServerSwitcherThread.detach();
	}

	SOCKET_DATA LocalhostData = {0};
	std::thread IPv6UDPMonitorThread, IPv4UDPMonitorThread, IPv6TCPMonitorThread, IPv4TCPMonitorThread;
//Set localhost socket(IPv6/UDP).
	LocalhostData.Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (LocalhostData.Socket == INVALID_SOCKET || Parameter.ListenProtocol == LISTEN_IPV4)
	{
		if ( /* IsWindowsVistaOrGreater() || */ WSAGetLastError() != 0 && WSAGetLastError() != WSAEAFNOSUPPORT)
			PrintError(LOG_ERROR_WINSOCK, L"IPv6 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, NULL);
	}
	else {
		Parameter.LocalSocket[0] = LocalhostData.Socket;
		if (Parameter.OperationMode == LISTEN_PROXYMODE) //Proxy Mode
			((PSOCKADDR_IN6)&LocalhostData.SockAddr)->sin6_addr = in6addr_loopback;
		else //Server Mode, Priavte Mode and Custom Mode
			((PSOCKADDR_IN6)&LocalhostData.SockAddr)->sin6_addr = in6addr_any;
		LocalhostData.SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&LocalhostData.SockAddr)->sin6_port = Parameter.ListenPort;
		LocalhostData.AddrLen = sizeof(sockaddr_in6);

		std::thread MonitorTempThread(UDPMonitor, LocalhostData);
		IPv6UDPMonitorThread.swap(MonitorTempThread);
	}
	memset(&LocalhostData, 0, sizeof(SOCKET_DATA));

//Set localhost socket(IPv6/TCP).
	LocalhostData.Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (LocalhostData.Socket == INVALID_SOCKET || Parameter.ListenProtocol == LISTEN_IPV4)
	{
		if ( /* IsWindowsVistaOrGreater() || */ WSAGetLastError() != 0 && WSAGetLastError() != WSAEAFNOSUPPORT)
			PrintError(LOG_ERROR_WINSOCK, L"IPv6 TCP Monitor socket initialization error", WSAGetLastError(), nullptr, NULL);
	}
	else {
		Parameter.LocalSocket[2U] = LocalhostData.Socket;
		if (Parameter.OperationMode == LISTEN_PROXYMODE) //Proxy Mode
			((PSOCKADDR_IN6)&LocalhostData.SockAddr)->sin6_addr = in6addr_loopback;
		else //Server Mode, Priavte Mode and Custom Mode
			((PSOCKADDR_IN6)&LocalhostData.SockAddr)->sin6_addr = in6addr_any;
		LocalhostData.SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&LocalhostData.SockAddr)->sin6_port = Parameter.ListenPort;
		LocalhostData.AddrLen = sizeof(sockaddr_in6);

		std::thread MonitorTempThread(TCPMonitor, LocalhostData);
		IPv6TCPMonitorThread.swap(MonitorTempThread);
	}
	memset(&LocalhostData, 0, sizeof(SOCKET_DATA));

//Set localhost socket(IPv4/UDP).
	LocalhostData.Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (LocalhostData.Socket == INVALID_SOCKET || Parameter.ListenProtocol == LISTEN_IPV6)
	{
		PrintError(LOG_ERROR_WINSOCK, L"IPv4 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, NULL);
	}
	else {
		Parameter.LocalSocket[1U] = LocalhostData.Socket;
		if (Parameter.OperationMode == LISTEN_PROXYMODE) //Proxy Mode
			((PSOCKADDR_IN)&LocalhostData.SockAddr)->sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
		else //Server Mode, Priavte Mode and Custom Mode
			((PSOCKADDR_IN)&LocalhostData.SockAddr)->sin_addr.S_un.S_addr = INADDR_ANY;
		LocalhostData.SockAddr.ss_family = AF_INET;
		((PSOCKADDR_IN)&LocalhostData.SockAddr)->sin_port = Parameter.ListenPort;
		LocalhostData.AddrLen = sizeof(sockaddr_in);

		std::thread MonitorTempThread(UDPMonitor, LocalhostData);
		IPv4UDPMonitorThread.swap(MonitorTempThread);
	}
	memset(&LocalhostData, 0, sizeof(SOCKET_DATA));

//Set localhost socket(IPv4/TCP).
	LocalhostData.Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (LocalhostData.Socket == INVALID_SOCKET || Parameter.ListenProtocol == LISTEN_IPV6)
	{
		PrintError(LOG_ERROR_WINSOCK, L"IPv4 UDP Monitor socket initialization error", WSAGetLastError(), nullptr, NULL);
	}
	else {
		Parameter.LocalSocket[3U] = LocalhostData.Socket;
		if (Parameter.OperationMode == LISTEN_PROXYMODE) //Proxy Mode
			((PSOCKADDR_IN)&LocalhostData.SockAddr)->sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
		else //Server Mode, Priavte Mode and Custom Mode
			((PSOCKADDR_IN)&LocalhostData.SockAddr)->sin_addr.S_un.S_addr = INADDR_ANY;
		LocalhostData.SockAddr.ss_family = AF_INET;
		((PSOCKADDR_IN)&LocalhostData.SockAddr)->sin_port = Parameter.ListenPort;
		LocalhostData.AddrLen = sizeof(sockaddr_in);

		std::thread MonitorTempThread(TCPMonitor, LocalhostData);
		IPv4TCPMonitorThread.swap(MonitorTempThread);
	}
	memset(&LocalhostData, 0, sizeof(SOCKET_DATA));

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
/* Old version(2014-07-22)
	if (setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
	if (setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.UnreliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set UDP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(LocalhostData.Socket);

		return EXIT_FAILURE;
	}
/*
//Unblocking Mode
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

	std::shared_ptr<char> Buffer(new char[PACKET_MAXSIZE * BUFFER_RING_MAXNUM]());
	size_t Index[] = {0, 0};
//Start Monitor.
	void *Addr = nullptr;
	dns_hdr *pdns_hdr = nullptr;
	while (true)
	{
		memset(Buffer.get() + PACKET_MAXSIZE * Index[0], 0, PACKET_MAXSIZE);
		if (Parameter.EDNS0Label) //EDNS0 Label
			RecvLen = recvfrom(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], PACKET_MAXSIZE - sizeof(dns_edns0_label), NULL, (PSOCKADDR)&LocalhostData.SockAddr, (PINT)&LocalhostData.AddrLen);
		else 
			RecvLen = recvfrom(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], PACKET_MAXSIZE, NULL, (PSOCKADDR)&LocalhostData.SockAddr, (PINT)&LocalhostData.AddrLen);

	//Check address(es).
		if (LocalhostData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			Addr = &((PSOCKADDR_IN6)&LocalhostData.SockAddr)->sin6_addr;
		//Check Private Mode(IPv6).
			if ((Parameter.OperationMode == LISTEN_PRIVATEMODE && 
				!(((in6_addr *)Addr)->u.Byte[0] >= 0xFC && ((in6_addr *)Addr)->u.Byte[0] <= 0xFD || //Unique Local Unicast address/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
				((in6_addr *)Addr)->u.Byte[0] == 0xFE && ((in6_addr *)Addr)->u.Byte[1U] >= 0x80 && ((in6_addr *)Addr)->u.Byte[1U] <= 0xBF || //Link-Local Unicast Contrast address(FE80::/10, Section 2.5.6 in RFC 4291)
				((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x0001))) || //Loopback address(::1, Section 2.5.3 in RFC 4291)
		//Check Custom Mode(IPv6).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET6)) || 
		//Check Server Mode(IPv6).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.OperationMode == LISTEN_SERVERMODE) && 
				(CheckSpecialAddress(Addr, AF_INET6, nullptr) || 
				memcmp(Addr, &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 || 
				memcmp(Addr, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 || 
				memcmp(Addr, &Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 || 
				memcmp(Addr, &Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0))
					continue;
		}
		else { //IPv4
			Addr = &((PSOCKADDR_IN)&LocalhostData.SockAddr)->sin_addr;
		//Check Private Mode(IPv4).
			if ((Parameter.OperationMode == LISTEN_PRIVATEMODE && 
				!(((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0x0A || //Private class A address(10.0.0.0/8, Section 3 in RFC 1918)
				((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
				((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xAC && ((in_addr *)Addr)->S_un.S_un_b.s_b2 >= 0x10 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 <= 0x1F || //Private class B address(172.16.0.0/16, Section 3 in RFC 1918)
				((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xC0 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 == 0xA8)) || //Private class C address(192.168.0.0/24, Section 3 in RFC 1918)
		//Check Custom Mode(IPv4).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET)) || 
		//Check Server Mode(IPv4).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.OperationMode == LISTEN_SERVERMODE) && 
				(CheckSpecialAddress(Addr, AF_INET, nullptr) || 
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr.S_un.S_addr || 
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr || 
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr || 
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr))
					continue;
		}

	//UDP Truncated check
		if (RecvLen > (SSIZE_T)(Parameter.EDNS0PayloadSize - sizeof(dns_edns0_label)))
		{
			if (Parameter.EDNS0Label || //EDNS0 Lebal
				RecvLen > (SSIZE_T)Parameter.EDNS0PayloadSize)
			{
			//Make packet(s) with EDNS0 Lebal.
				pdns_hdr = (dns_hdr *)(Buffer.get() + PACKET_MAXSIZE * Index[0]);
				pdns_hdr->Flags = htons(DNS_SQRNE_TC);
				dns_edns0_label *EDNS0 = nullptr;
			
				if (pdns_hdr->Additional == 0)
				{
					pdns_hdr->Additional = htons(U16_NUM_1);
					EDNS0 = (dns_edns0_label *)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen);
					EDNS0->Type = htons(DNS_EDNS0_RECORDS);
					EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					RecvLen += sizeof(dns_edns0_label);
				}
				else {
					EDNS0 = (dns_edns0_label *)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen - sizeof(dns_edns0_label));
					if (EDNS0->Type == htons(DNS_EDNS0_RECORDS))
						EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				}

			//Send request.
				sendto(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], (int)RecvLen, NULL, (PSOCKADDR)&LocalhostData.SockAddr, LocalhostData.AddrLen);
				continue;
			}
		}

	//Receive process.
		if (RecvLen > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
		{
			pdns_hdr = (dns_hdr *)(Buffer.get() + PACKET_MAXSIZE * Index[0]);

		//EDNS0 Label
			if (Parameter.EDNS0Label)
			{
				dns_edns0_label *EDNS0 = nullptr;

			//No additional
				if (pdns_hdr->Additional == 0)
				{
					pdns_hdr->Additional = htons(U16_NUM_1);
					EDNS0 = (dns_edns0_label *)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen);
					EDNS0->Type = htons(DNS_EDNS0_RECORDS);
					EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					RecvLen += sizeof(dns_edns0_label);
				}
			//Already EDNS0 Lebal
				else {
					EDNS0 = (dns_edns0_label *)(Buffer.get() + PACKET_MAXSIZE * Index[0] + RecvLen - sizeof(dns_edns0_label));
					EDNS0->Type = htons(DNS_EDNS0_RECORDS);
					EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				}

			//DNSSEC
				if (Parameter.DNSSECRequest)
				{
					pdns_hdr->FlagsBits.AD = ~pdns_hdr->FlagsBits.AD; //Local DNSSEC Server validate
					pdns_hdr->FlagsBits.CD = ~pdns_hdr->FlagsBits.CD; //Client validate
					EDNS0->Z_Bits.DO = ~EDNS0->Z_Bits.DO; //Accepts DNSSEC security RRs
				}
			}

		//Request process
			if (LocalhostData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			{
				std::thread RequestProcessThread(RequestProcess, Buffer.get() + PACKET_MAXSIZE * Index[0], RecvLen, LocalhostData, IPPROTO_UDP, Index[1U]);
				RequestProcessThread.detach();
			}
			else { //IPv4
				std::thread RequestProcessThread(RequestProcess, Buffer.get() + PACKET_MAXSIZE * Index[0], RecvLen, LocalhostData, IPPROTO_UDP, Index[1U] + QUEUE_MAXLEN);
				RequestProcessThread.detach();
			}

			Index[0] = (Index[0] + 1U) % BUFFER_RING_MAXNUM;
			Index[1U] = (Index[1U] + 1U) % QUEUE_MAXLEN;
		}
		else if (RecvLen == 0)
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
		else { //Incorrect packets
			pdns_hdr = (dns_hdr *)(Buffer.get() + PACKET_MAXSIZE * Index[0]);
			pdns_hdr->Flags = htons(DNS_SQRNE_SF);
			sendto(LocalhostData.Socket, Buffer.get() + PACKET_MAXSIZE * Index[0], (int)RecvLen, NULL, (PSOCKADDR)&LocalhostData.SockAddr, LocalhostData.AddrLen);
		}
	}

	closesocket(LocalhostData.Socket);
	return EXIT_SUCCESS;
}

//Local DNS server with TCP protocol
size_t __fastcall TCPMonitor(const SOCKET_DATA LocalhostData)
{
//Set socket timeout.
/* Old version(2014-07-22)
	if (setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR || 
		setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(timeval)) == SOCKET_ERROR)
*/
	if (setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_SNDTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR || 
		setsockopt(LocalhostData.Socket, SOL_SOCKET, SO_RCVTIMEO, (PSTR)&Parameter.ReliableSocketTimeout, sizeof(int)) == SOCKET_ERROR)
	{
		PrintError(LOG_ERROR_WINSOCK, L"Set TCP socket timeout error", WSAGetLastError(), nullptr, NULL);
		closesocket(LocalhostData.Socket);

		return EXIT_FAILURE;
	}
/*
//Unblocking Mode
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
	SOCKET_DATA ClientData = {0};
	void *Addr = nullptr;
	size_t Index = 0;
	ClientData.AddrLen = LocalhostData.AddrLen;
	while (true)
	{
		memset(&ClientData, 0, sizeof(SOCKET_DATA) - sizeof(int));
		ClientData.Socket = accept(LocalhostData.Socket, (PSOCKADDR)&ClientData.SockAddr, (PINT)&(ClientData.AddrLen));
		if (ClientData.Socket == INVALID_SOCKET)
			continue;

	//Check address(es).
		if (ClientData.AddrLen == sizeof(sockaddr_in6)) //IPv6
		{
			Addr = &((PSOCKADDR_IN6)&LocalhostData.SockAddr)->sin6_addr;
		//Check Private Mode(IPv6).
			if ((Parameter.OperationMode == LISTEN_PRIVATEMODE && 
				!(((in6_addr *)Addr)->u.Byte[0] >= 0xFC && ((in6_addr *)Addr)->u.Byte[0] <= 0xFD || //Unique Local Unicast address/ULA(FC00::/7, Section 2.5.7 in RFC 4193)
				((in6_addr *)Addr)->u.Byte[0] == 0xFE && ((in6_addr *)Addr)->u.Byte[1U] >= 0x80 && ((in6_addr *)Addr)->u.Byte[1U] <= 0xBF || //Link-Local Unicast Contrast address(FE80::/10, Section 2.5.6 in RFC 4291)
				((in6_addr *)Addr)->u.Word[6U] == 0 && ((in6_addr *)Addr)->u.Word[7U] == htons(0x0001))) || //Loopback address(::1, Section 2.5.3 in RFC 4291)
		//Check Custom Mode(IPv6).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET6)) || 
		//Check Server Mode(IPv6).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.OperationMode == LISTEN_SERVERMODE) && 
				(CheckSpecialAddress(Addr, AF_INET6, nullptr) || 
				memcmp(Addr, &Parameter.DNSTarget.IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 || 
				memcmp(Addr, &Parameter.DNSTarget.Alternate_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 || 
				memcmp(Addr, &Parameter.DNSTarget.Local_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0 || 
				memcmp(Addr, &Parameter.DNSTarget.Alternate_Local_IPv6.AddressData.IPv6.sin6_addr, sizeof(in6_addr)) == 0))
			{
				closesocket(ClientData.Socket);
				continue;
			}
		}
		else { //IPv4
			Addr = &((PSOCKADDR_IN)&LocalhostData.SockAddr)->sin_addr;
		//Check Private Mode(IPv4).
			if ((Parameter.OperationMode == LISTEN_PRIVATEMODE && 
				!(((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0x0A || //Private class A address(10.0.0.0/8, Section 3 in RFC 1918)
				((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0x7F || //Loopback address(127.0.0.0/8, Section 3.2.1.3 in RFC 1122)
				((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xAC && ((in_addr *)Addr)->S_un.S_un_b.s_b2 >= 0x10 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 <= 0x1F || //Private class B address(172.16.0.0/16, Section 3 in RFC 1918)
				((in_addr *)Addr)->S_un.S_un_b.s_b1 == 0xC0 && ((in_addr *)Addr)->S_un.S_un_b.s_b2 == 0xA8)) || //Private class C address(192.168.0.0/24, Section 3 in RFC 1918)
		//Check Custom Mode(IPv4).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE && !CustomModeFilter(Addr, AF_INET)) || 
		//Check Server Mode(IPv4).
				(Parameter.OperationMode == LISTEN_CUSTOMMODE || Parameter.OperationMode == LISTEN_SERVERMODE) && 
				(CheckSpecialAddress(Addr, AF_INET, nullptr) || 
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.IPv4.AddressData.IPv4.sin_addr.S_un.S_addr || 
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.Alternate_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr || 
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.Local_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr || 
				((in_addr *)Addr)->S_un.S_addr == Parameter.DNSTarget.Alternate_Local_IPv4.AddressData.IPv4.sin_addr.S_un.S_addr))
			{
				closesocket(ClientData.Socket);
				continue;
			}
		}

	//Accept process.
		std::thread TCPReceiveThread(TCPReceiveProcess, ClientData, Index);
		TCPReceiveThread.detach();

		Index = (Index + 1U) % QUEUE_MAXLEN;
	}

	closesocket(LocalhostData.Socket);
	return EXIT_SUCCESS;
}

//TCP protocol receive process
size_t __fastcall TCPReceiveProcess(const SOCKET_DATA FunctionData, const size_t Index)
{
	std::shared_ptr<char> Buffer(new char[LARGE_PACKET_MAXSIZE]());

//Receive
	SSIZE_T RecvLen = 0;
	if (Parameter.EDNS0Label) //EDNS0 Label
		RecvLen = recv(FunctionData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE - sizeof(dns_edns0_label), NULL);
	else 
		RecvLen = recv(FunctionData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE, NULL);
	if (RecvLen == (SSIZE_T)sizeof(uint16_t)) //TCP segment of a reassembled PDU
	{
		uint16_t PDU_Len = ntohs(((uint16_t *)Buffer.get())[0]);
		RecvLen = recv(FunctionData.Socket, Buffer.get(), LARGE_PACKET_MAXSIZE, NULL); //Receive without PDU.
		if ((SSIZE_T)PDU_Len >= RecvLen && RecvLen > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry)))
		{
		//EDNS0 Label
			if (Parameter.EDNS0Label)
			{
				auto pdns_hdr = (dns_hdr *)Buffer.get();
				dns_edns0_label *EDNS0 = nullptr;

			//No additional
				if (pdns_hdr->Additional == 0)
				{
					pdns_hdr->Additional = htons(U16_NUM_1);
					EDNS0 = (dns_edns0_label *)(Buffer.get() + PDU_Len);
					EDNS0->Type = htons(DNS_EDNS0_RECORDS);
					EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
					PDU_Len += sizeof(dns_edns0_label);
				}
			//Already EDNS0 Lebal
				else {
					EDNS0 = (dns_edns0_label *)(Buffer.get() + PDU_Len - sizeof(dns_edns0_label));
					EDNS0->Type = htons(DNS_EDNS0_RECORDS);
					EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				}

			//DNSSEC
				if (Parameter.DNSSECRequest)
				{
					pdns_hdr->FlagsBits.AD = ~pdns_hdr->FlagsBits.AD; //Local DNSSEC Server validate
					pdns_hdr->FlagsBits.CD = ~pdns_hdr->FlagsBits.CD; //Client validate
					EDNS0->Z_Bits.DO = ~EDNS0->Z_Bits.DO; //Accepts DNSSEC security RRs
				}
			}

			if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
				RequestProcess(Buffer.get(), PDU_Len, FunctionData, IPPROTO_TCP, Index + QUEUE_MAXLEN * (QUEUE_PARTNUM - 2U));
			else //IPv4
				RequestProcess(Buffer.get(), PDU_Len, FunctionData, IPPROTO_TCP, Index + QUEUE_MAXLEN * (QUEUE_PARTNUM - 1U));
		}
		else {
			closesocket(FunctionData.Socket);
			return EXIT_FAILURE;
		}
	}
	else if (RecvLen > (SSIZE_T)(sizeof(dns_hdr) + 1U + sizeof(dns_qry)) && (SSIZE_T)htons(((uint16_t *)Buffer.get())[0]) <= RecvLen)
	{
		RecvLen = htons(((uint16_t *)Buffer.get())[0]);

	//EDNS0 Label
		if (Parameter.EDNS0Label)
		{
			auto pdns_hdr = (dns_hdr *)(Buffer.get() + sizeof(uint16_t));
			dns_edns0_label *EDNS0 = nullptr;

		//No additional
			if (pdns_hdr->Additional == 0)
			{
				pdns_hdr->Additional = htons(U16_NUM_1);
				EDNS0 = (dns_edns0_label *)(Buffer.get() + sizeof(uint16_t) + RecvLen);
				EDNS0->Type = htons(DNS_EDNS0_RECORDS);
				EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
				RecvLen += sizeof(dns_edns0_label);
			}
		//Already EDNS0 Lebal
			else {
				EDNS0 = (dns_edns0_label *)(Buffer.get() + sizeof(uint16_t) + RecvLen - sizeof(dns_edns0_label));
				EDNS0->Type = htons(DNS_EDNS0_RECORDS);
				EDNS0->UDPPayloadSize = htons((uint16_t)Parameter.EDNS0PayloadSize);
			}

		//DNSSEC
			if (Parameter.DNSSECRequest)
			{
				pdns_hdr->FlagsBits.AD = ~pdns_hdr->FlagsBits.AD; //Local DNSSEC Server validate
				pdns_hdr->FlagsBits.CD = ~pdns_hdr->FlagsBits.CD; //Client validate
				EDNS0->Z_Bits.DO = ~EDNS0->Z_Bits.DO; //Accepts DNSSEC security RRs
			}
		}

	//Request process
		if (FunctionData.AddrLen == sizeof(sockaddr_in6)) //IPv6
			RequestProcess(Buffer.get() + sizeof(uint16_t), RecvLen, FunctionData, IPPROTO_TCP, Index + QUEUE_MAXLEN * (QUEUE_PARTNUM - 2U));
		else //IPv4
			RequestProcess(Buffer.get() + sizeof(uint16_t), RecvLen, FunctionData, IPPROTO_TCP, Index + QUEUE_MAXLEN * (QUEUE_PARTNUM - 1U));
	}
	else {
		closesocket(FunctionData.Socket);
		return EXIT_FAILURE;
	}

//Block Port Unreachable messages of system.
	Sleep(RELIABLE_SOCKET_TIMEOUT);
	closesocket(FunctionData.Socket);
	return EXIT_SUCCESS;
}

//Alternate DNS servers switcher
inline void __fastcall AlternateServerSwitcher(void)
{
	size_t Index = 0, RangeTimer[ALTERNATE_SERVERNUM] = {0}, SwapTimer[ALTERNATE_SERVERNUM] = {0};

//Switcher
//Minimum supported system of GetTickCount64() is Windows Vista.
	while (true)
	{
	//Pcap Requesting check
		for (Index = 0;Index < QUEUE_MAXLEN * QUEUE_PARTNUM;Index++)
		{
			if (AlternateSwapList.PcapAlternateTimeout[Index] != 0 && 
			#ifdef _WIN64
				GetTickCount64() > RELIABLE_SOCKET_TIMEOUT + AlternateSwapList.PcapAlternateTimeout[Index]) //Check timeout.
			#else //x86
				GetTickCount() > RELIABLE_SOCKET_TIMEOUT + AlternateSwapList.PcapAlternateTimeout[Index]) //Check timeout.
			#endif
			{
				AlternateSwapList.PcapAlternateTimeout[Index] = 0;
				if (AlternateSwapList.Swap[2U] == false && Parameter.DNSTarget.Alternate_IPv6.AddressData.Storage.ss_family != NULL && 
					Index >= 0 && Index < QUEUE_MAXLEN * (QUEUE_PARTNUM - 3U) || Index >= QUEUE_MAXLEN * (QUEUE_PARTNUM - 2U) && Index < QUEUE_MAXLEN * (QUEUE_PARTNUM - 1U)) //IPv6
						AlternateSwapList.TimeoutTimes[2U]++;
				else if (AlternateSwapList.Swap[3U] == false && Parameter.DNSTarget.Alternate_IPv4.AddressData.Storage.ss_family != NULL) //IPv4
					AlternateSwapList.TimeoutTimes[3U]++;
			}
		}

	//Complete Requesting check
		for (Index = 0;Index < ALTERNATE_SERVERNUM;Index++)
		{
		//Reset TimeoutTimes out of alternate time range.
		#ifdef _WIN64
			if (GetTickCount64() >= Parameter.AlternateOptions.AlternateTimeRange + RangeTimer[Index])
			{
				RangeTimer[Index] = GetTickCount64();
		#else //x86
			if (GetTickCount() >= Parameter.AlternateOptions.AlternateTimeRange + RangeTimer[Index])
			{
				RangeTimer[Index] = GetTickCount();
		#endif
				AlternateSwapList.TimeoutTimes[Index] = 0;
				continue;
			}

		//Reset alternate switching.
			if (AlternateSwapList.Swap[Index])
			{
			#ifdef _WIN64
				if (GetTickCount64() >= Parameter.AlternateOptions.AlternateResetTime + SwapTimer[Index])
			#else //x86
				if (GetTickCount() >= Parameter.AlternateOptions.AlternateResetTime + SwapTimer[Index])
			#endif
				{
					AlternateSwapList.Swap[Index] = false;
					AlternateSwapList.TimeoutTimes[Index] = 0;
					SwapTimer[Index] = 0;
				}
			}
			else {
			//Mark alternate switching.
				if (AlternateSwapList.TimeoutTimes[Index] >= Parameter.AlternateOptions.AlternateTimes)
				{
					AlternateSwapList.Swap[Index] = true;
					AlternateSwapList.TimeoutTimes[Index] = 0;
				#ifdef _WIN64
					SwapTimer[Index] = GetTickCount64();
				#else //x86
					SwapTimer[Index] = GetTickCount();
				#endif
				}
			}
		}

		Sleep(STANDARD_TIMEOUT); //Time between checks.
	}

	return;
}

//DNS Cache timers monitor
void __fastcall DNSCacheTimerMonitor(const size_t CacheType)
{
	size_t Time = 0;
	while (true)
	{
	//Minimum supported system of GetTickCount64() is Windows Vista.
	#ifdef _WIN64
		Time = GetTickCount64();
	#else //x86
		Time = GetTickCount();
	#endif

		if (CacheType == CACHE_TIMER)
		{
			std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
			while (!DNSCacheList.empty() && Time >= Parameter.CacheParameter + DNSCacheList.front().Time)
				DNSCacheList.pop_front();
			DNSCacheList.shrink_to_fit();
		}
		else { //CACHE_QUEUE
			std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
			while (!DNSCacheList.empty() && Time >= DNSCacheList.front().Time + Parameter.HostsDefaultTTL * SECOND_TO_MILLISECOND)
				DNSCacheList.pop_front();
			DNSCacheList.shrink_to_fit();
		}

		Sleep(STANDARD_TIMEOUT); //Time between checks.
	}

	return;
}
