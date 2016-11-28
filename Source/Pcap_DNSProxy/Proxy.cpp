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


#include "Proxy.h"

/* SOCKS Protocol version 4
** Client -> Server: TCP CONNECT command request
  *  1 bytes: SOCKS version
  *  1 bytes: Command code
  *  2 bytes: Remote port
  *  4 bytes: Remote IPv4 address
  * Variable: UserID
** Server -> Client: Server command response
  *  1 bytes: SOCKS version
  *  1 bytes: Status code
  *  2 bytes: Remote port(Ignored)
  *  4 bytes: Remote IPv4 address(Ignored)
** Client <-> Server: Data stream...

* SOCKS Protocol version 4a
** Client -> Server(1): TCP CONNECT command request
  *  1 bytes: SOCKS version
  *  1 bytes: Command code
  *  2 bytes: Remote port
  *  4 bytes: Remote IPv4 address(Must set to 0.0.0.x and x is not 0)
  * Variable: UserID
  * Variable: Remote domain
** Server -> Client(1): Server command response
  *  1 bytes: SOCKS version
  *  1 bytes: Status code
  *  2 bytes: Remote port(Ignored)
  *  4 bytes: Remote IPv4 address(Ignored)
** Client <-> Server: Data stream...

* SOCKS Protocol version 5
** Client authentication
*** Client -> Server(1): Client authentication request
  *  1 bytes: SOCKS version
  *  1 bytes: Number of authentication methods supported
  * Variable: Authentication methods
*** Server -> Client(1): Server authentication choice
  *  1 bytes: SOCKS version
  *  1 bytes: Chosen authentication method
*** Client -> Server(2): Username/password authentication request
  *  1 bytes: SOCKS Username/password authentication version
  *  1 bytes: Username length
  * Variable: Username
  *  1 bytes: Password length
  * Variable: Password
*** Server -> Client(2): Server authentication response
  *  1 bytes: SOCKS Username/password authentication version
  *  1 bytes: Status code

** TCP CONNECT mode
*** Client -> Server(1): TCP CONNECT command request
  *  1 bytes: SOCKS version
  *  1 bytes: Command code
  *  1 bytes: Reserved
  *  1 bytes: Address type
  * Variable: Remote address
  *  2 bytes: Remote port
*** Server -> Client(1): Server command response
  *  1 bytes: SOCKS version
  *  1 bytes: Status code
  *  1 bytes: Reserved
  *  1 bytes: Address type
  * Variable: Remote address(Not necessary)
  *  2 bytes: Remote port(Not necessary)
*** Client <-> Server: Data stream...

** UDP ASSOCIATE mode
*** Client -> Server(1): UDP ASSOCIATE command request, with TCP
  *  1 bytes: SOCKS version
  *  1 bytes: Command code
  *  1 bytes: Reserved
  *  1 bytes: Address type
  * Variable: Local listening address(Not necessary)
  *  2 bytes: Local UDP listening port
*** Server -> Client(1): Server command response, with TCP
  *  1 bytes: SOCKS version
  *  1 bytes: Status code
  *  1 bytes: Reserved
  *  1 bytes: Address type
  * Variable: Server listening address
  *  2 bytes: Server listening port
*** Client -> Server(2): UDP datagram, with UDP
  *  2 bytes: Reserved
  *  1 bytes: Fragment number
  *  1 bytes: Address type
  * Variable: Remote address
  *  2 bytes: Remote port
  * Variable: UDP datagram...
*** Server -> Client(2): UDP datagram, with UDP
  *  2 bytes: Reserved
  *  1 bytes: Fragment number
  *  1 bytes: Address type
  * Variable: Remote address
  *  2 bytes: Remote port
  * Variable: UDP datagram...
*** Client <-> Server: UDP datagram...
*** TCP connection between client and server must be kept alive until UDP transmission is finished.

* HTTP CONNECT tunnel
** TLS connection handshake
** Client -> Server: HTTP CONNECT method request
  * CONNECT TargetDomain:Port HTTP/version\r\n
  * Host: TargetDomain:Port\r\n
  * Other HTTP headers...\r\n
  * Proxy-Authentication: Basic "Base64 of Username:Password"\r\n
  * \r\n
** Server -> Client: Server HTTP CONNECT response
  * HTTP/version 200 ...\r\n
  * Other HTTP headers...\r\n
  * \r\n
** Client <-> Server: Data stream...
** TLS connection shutdown

*/

//Transmission and reception of SOCKS protocol(TCP)
size_t SOCKS_TCP_Request(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	std::shared_ptr<uint8_t> &OriginalRecv, 
	size_t &RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> SocketDataList(1U);
	std::vector<SOCKET_SELECTING_SERIAL_DATA> SocketSelectingDataList(1U);
	std::vector<ssize_t> ErrorCodeList(1U);
	memset(&SocketDataList.front(), 0, sizeof(SocketDataList.front()));
	memset(&SocketSelectingDataList.front(), 0, sizeof(SocketSelectingDataList.front()));
	ErrorCodeList.front() = 0;

//Socket initialization
	if (Parameter.SOCKS_Address_IPv6.Storage.ss_family != 0 && //IPv6
		((Parameter.SOCKS_Protocol_Network == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV6 || //IPv6
		(Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV4 && Parameter.SOCKS_Address_IPv4.Storage.ss_family == 0))) //Non-IPv4
	{
		SocketDataList.front().SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&SocketDataList.front().SockAddr)->sin6_addr = Parameter.SOCKS_Address_IPv6.IPv6.sin6_addr;
		((PSOCKADDR_IN6)&SocketDataList.front().SockAddr)->sin6_port = Parameter.SOCKS_Address_IPv6.IPv6.sin6_port;
		SocketDataList.front().AddrLen = sizeof(sockaddr_in6);
		SocketDataList.front().Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	}
	else if (Parameter.SOCKS_Address_IPv4.Storage.ss_family != 0 && //IPv4
		((Parameter.SOCKS_Protocol_Network == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV4 || //IPv4
		(Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV6 && Parameter.SOCKS_Address_IPv6.Storage.ss_family == 0))) //Non-IPv6
	{
		SocketDataList.front().SockAddr.ss_family = AF_INET;
		((PSOCKADDR_IN)&SocketDataList.front().SockAddr)->sin_addr = Parameter.SOCKS_Address_IPv4.IPv4.sin_addr;
		((PSOCKADDR_IN)&SocketDataList.front().SockAddr)->sin_port = Parameter.SOCKS_Address_IPv4.IPv4.sin_port;
		SocketDataList.front().AddrLen = sizeof(sockaddr_in);
		SocketDataList.front().Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check
	if (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
	{
		PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"SOCKS socket initialization error", 0, nullptr, 0);
		return EXIT_FAILURE;
	}

//Socket attribute settings
	if (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr) || 
		!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr) || 
		(SocketDataList.front().SockAddr.ss_family == AF_INET6 && !SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr)) || 
		(SocketDataList.front().SockAddr.ss_family == AF_INET && !SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr)) || 
		!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
	{
		SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Selection exchange process
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5 && !SOCKS_SelectionExchange(SocketDataList, SocketSelectingDataList, ErrorCodeList))
	{
		SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Client command request process
	if (!SOCKS_ClientCommandRequest(IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList, nullptr))
	{
		SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Add length of request packet(It must be written in header when transport with TCP protocol).
	if (SocketSelectingDataList.front().SendSize < SendSize + sizeof(uint16_t))
	{
		std::shared_ptr<uint8_t> SendBuffer(new uint8_t[SendSize + sizeof(uint16_t)]());
		memset(SendBuffer.get(), 0, SendSize + sizeof(uint16_t));
		memcpy_s(SendBuffer.get(), SendSize + sizeof(uint16_t), OriginalSend, SendSize);
		SocketSelectingDataList.front().SendBuffer.swap(SendBuffer);
		SocketSelectingDataList.front().SendSize = SendSize + sizeof(uint16_t);
		SocketSelectingDataList.front().SendLen = SendSize;
	}
	auto RecvLen = AddLengthDataToHeader(SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendLen, SocketSelectingDataList.front().SendSize);
	if (RecvLen < DNS_PACKET_MINSIZE)
	{
		SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}
	else {
		SocketSelectingDataList.front().SendLen = RecvLen;
	}

//Request exchange and response check
	SocketSelectingDataList.front().RecvBuffer.reset();
	SocketSelectingDataList.front().RecvSize = 0;
	SocketSelectingDataList.front().RecvLen = 0;
	RecvLen = SocketSelectingSerial(REQUEST_PROCESS_SOCKS_MAIN, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
	SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
	SocketSelectingDataList.front().SendBuffer.reset();
	SocketSelectingDataList.front().SendSize = 0;
	SocketSelectingDataList.front().SendLen = 0;
	if (RecvLen != EXIT_FAILURE && 
		SocketSelectingDataList.front().RecvLen >= DNS_PACKET_MINSIZE && ntohs(((uint16_t *)SocketSelectingDataList.front().RecvBuffer.get())[0]) >= DNS_PACKET_MINSIZE && 
		SocketSelectingDataList.front().RecvLen >= ntohs(((uint16_t *)SocketSelectingDataList.front().RecvBuffer.get())[0]))
	{
		RecvLen = ntohs(((uint16_t *)SocketSelectingDataList.front().RecvBuffer.get())[0]);
		memmove_s(SocketSelectingDataList.front().RecvBuffer.get(), SocketSelectingDataList.front().RecvSize, SocketSelectingDataList.front().RecvBuffer.get() + sizeof(uint16_t), RecvLen);
		memset(SocketSelectingDataList.front().RecvBuffer.get() + RecvLen, 0, SocketSelectingDataList.front().RecvSize - RecvLen);

	//Response check
		RecvLen = CheckResponseData(
			REQUEST_PROCESS_SOCKS_MAIN, 
			SocketSelectingDataList.front().RecvBuffer.get(), 
			RecvLen, 
			SocketSelectingDataList.front().RecvSize, 
			nullptr);
		if (RecvLen < DNS_PACKET_MINSIZE)
			return EXIT_FAILURE;

	//Mark DNS cache.
		if (Parameter.CacheType != CACHE_TYPE_NONE)
			MarkDomainCache(SocketSelectingDataList.front().RecvBuffer.get(), RecvLen);

	//Swap buffer.
		OriginalRecv.swap(SocketSelectingDataList.front().RecvBuffer);
		RecvSize = SocketSelectingDataList.front().RecvSize;
		return RecvLen;
	}

	return EXIT_FAILURE;
}

//Transmission and reception of SOCKS protocol(UDP)
size_t SOCKS_UDP_Request(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	std::shared_ptr<uint8_t> &OriginalRecv, 
	size_t &RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> TCPSocketDataList(1U), UDPSocketDataList(1U), LocalSocketDataList(1U);
	std::vector<SOCKET_SELECTING_SERIAL_DATA> TCPSocketSelectingDataList(1U), UDPSocketSelectingDataList(1U), LocalSocketSelectingDataList(1U);
	std::vector<ssize_t> TCPErrorCodeList(1U), UDPErrorCodeList(1U), LocalErrorCodeList(1U);
	memset(&TCPSocketDataList.front(), 0, sizeof(TCPSocketDataList.front()));
	memset(&UDPSocketDataList.front(), 0, sizeof(UDPSocketDataList.front()));
	memset(&LocalSocketDataList.front(), 0, sizeof(LocalSocketDataList.front()));
	memset(&TCPSocketSelectingDataList.front(), 0, sizeof(TCPSocketSelectingDataList.front()));
	memset(&UDPSocketSelectingDataList.front(), 0, sizeof(UDPSocketSelectingDataList.front()));
	memset(&LocalSocketSelectingDataList.front(), 0, sizeof(LocalSocketSelectingDataList.front()));
	TCPErrorCodeList.front() = 0;
	UDPErrorCodeList.front() = 0;
	LocalErrorCodeList.front() = 0;

//Socket initialization
	if (Parameter.SOCKS_Address_IPv6.Storage.ss_family != 0 && //IPv6
		((Parameter.SOCKS_Protocol_Network == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV6 || //IPv6
		(Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV4 && Parameter.SOCKS_Address_IPv4.Storage.ss_family == 0))) //Non-IPv4
	{
		if (!Parameter.SOCKS_UDP_NoHandshake)
		{
		//TCP process
			TCPSocketDataList.front().SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&TCPSocketDataList.front().SockAddr)->sin6_addr = Parameter.SOCKS_Address_IPv6.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&TCPSocketDataList.front().SockAddr)->sin6_port = Parameter.SOCKS_Address_IPv6.IPv6.sin6_port;
			TCPSocketDataList.front().AddrLen = sizeof(sockaddr_in6);
			TCPSocketDataList.front().Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

		//Local process
			LocalSocketDataList.front().SockAddr.ss_family = AF_INET6;
			LocalSocketDataList.front().AddrLen = sizeof(sockaddr_in6);
		}

	//UDP process
		UDPSocketDataList.front().SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&UDPSocketDataList.front().SockAddr)->sin6_addr = Parameter.SOCKS_Address_IPv6.IPv6.sin6_addr;
		if (Parameter.SOCKS_UDP_NoHandshake)
			((PSOCKADDR_IN6)&UDPSocketDataList.front().SockAddr)->sin6_port = Parameter.SOCKS_Address_IPv6.IPv6.sin6_port;
		UDPSocketDataList.front().AddrLen = sizeof(sockaddr_in6);
		UDPSocketDataList.front().Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else if (Parameter.SOCKS_Address_IPv4.Storage.ss_family != 0 && //IPv4
		((Parameter.SOCKS_Protocol_Network == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV4 || //IPv4
		(Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV6 && Parameter.SOCKS_Address_IPv6.Storage.ss_family == 0))) //Non-IPv6
	{
		if (!Parameter.SOCKS_UDP_NoHandshake)
		{
		//TCP process
			TCPSocketDataList.front().SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&TCPSocketDataList.front().SockAddr)->sin_addr = Parameter.SOCKS_Address_IPv4.IPv4.sin_addr;
			((PSOCKADDR_IN)&TCPSocketDataList.front().SockAddr)->sin_port = Parameter.SOCKS_Address_IPv4.IPv4.sin_port;
			TCPSocketDataList.front().AddrLen = sizeof(sockaddr_in);
			TCPSocketDataList.front().Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		//Local process
			LocalSocketDataList.front().SockAddr.ss_family = AF_INET;
			LocalSocketDataList.front().AddrLen = sizeof(sockaddr_in);
		}

	//UDP process
		UDPSocketDataList.front().SockAddr.ss_family = AF_INET;
		((PSOCKADDR_IN)&UDPSocketDataList.front().SockAddr)->sin_addr = Parameter.SOCKS_Address_IPv4.IPv4.sin_addr;
		if (Parameter.SOCKS_UDP_NoHandshake)
			((PSOCKADDR_IN)&UDPSocketDataList.front().SockAddr)->sin_port = Parameter.SOCKS_Address_IPv4.IPv4.sin_port;
		UDPSocketDataList.front().AddrLen = sizeof(sockaddr_in);
		UDPSocketDataList.front().Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket attribute settings
	if (!(Parameter.SOCKS_UDP_NoHandshake || SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr)) || 
		!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr) || 
		(TCPSocketDataList.front().SockAddr.ss_family == AF_INET6 && !SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr)) || 
		(TCPSocketDataList.front().SockAddr.ss_family == AF_INET && !SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr)) || 
		!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr) || 
		!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_INVALID_CHECK, true, nullptr) || 
		(UDPSocketDataList.front().SockAddr.ss_family == AF_INET6 && !SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr)) || 
		(UDPSocketDataList.front().SockAddr.ss_family == AF_INET && !SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr)) || 
		!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		if (!Parameter.SOCKS_UDP_NoHandshake)
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}
	
//Socket attribute setting(Non-blocking mode)
	if (!(Parameter.SOCKS_UDP_NoHandshake || SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr)) || 
		!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr))
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		if (!Parameter.SOCKS_UDP_NoHandshake)
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//UDP transmission of standard SOCKS protocol must connect with TCP to server at first.
	if (!Parameter.SOCKS_UDP_NoHandshake)
	{
	//Selection exchange process
		if (!SOCKS_SelectionExchange(TCPSocketDataList, TCPSocketSelectingDataList, TCPErrorCodeList))
		{
			SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

			return EXIT_FAILURE;
		}

	//UDP connecting and get UDP socket infomation.
		if (SocketConnecting(IPPROTO_UDP, UDPSocketDataList.front().Socket, (PSOCKADDR)&UDPSocketDataList.front().SockAddr, UDPSocketDataList.front().AddrLen, nullptr, 0) == EXIT_FAILURE || 
			getsockname(UDPSocketDataList.front().Socket, (PSOCKADDR)&LocalSocketDataList.front().SockAddr, &LocalSocketDataList.front().AddrLen) == SOCKET_ERROR)
		{
			SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"SOCKS connecting error", 0, nullptr, 0);

			return EXIT_FAILURE;
		}

	//Client command request process
	//IPPROTO_UDP means UDP ASSOCIATE process, this part must transport with TCP protocol.
		if (!SOCKS_ClientCommandRequest(IPPROTO_UDP, TCPSocketDataList, TCPSocketSelectingDataList, TCPErrorCodeList, &LocalSocketDataList.front()))
		{
			SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

			return EXIT_FAILURE;
		}
		else {
		//Copy network infomation from server message.
			if (UDPSocketDataList.front().SockAddr.ss_family == AF_INET6) //IPv6
				((PSOCKADDR_IN6)&UDPSocketDataList.front().SockAddr)->sin6_port = ((PSOCKADDR_IN6)&LocalSocketDataList.front().SockAddr)->sin6_port;
			else if (UDPSocketDataList.front().SockAddr.ss_family == AF_INET) //IPv4
				((PSOCKADDR_IN)&UDPSocketDataList.front().SockAddr)->sin_port = ((PSOCKADDR_IN)&LocalSocketDataList.front().SockAddr)->sin_port;
		}
	}

//UDP connecting again to bind new socket data.
	if (SocketConnecting(IPPROTO_UDP, UDPSocketDataList.front().Socket, (PSOCKADDR)&UDPSocketDataList.front().SockAddr, UDPSocketDataList.front().AddrLen, nullptr, 0) == EXIT_FAILURE)
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		if (!Parameter.SOCKS_UDP_NoHandshake)
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"SOCKS connecting error", 0, nullptr, 0);
		return EXIT_FAILURE;
	}

//Buffer initialization(Part 1)
	if (UDPSocketSelectingDataList.front().SendSize < Parameter.LargeBufferSize)
	{
		std::shared_ptr<uint8_t> SendBuffer(new uint8_t[Parameter.LargeBufferSize]());
		memset(SendBuffer.get(), 0, Parameter.LargeBufferSize);
		UDPSocketSelectingDataList.front().SendBuffer.swap(SendBuffer);
		UDPSocketSelectingDataList.front().SendSize = Parameter.LargeBufferSize;
		UDPSocketSelectingDataList.front().SendLen = 0;
	}

//SOCKS UDP relay header
	size_t RecvLen = 0;
	if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET6) //IPv6
	{
	//Address type
		((psocks_udp_relay_request)UDPSocketSelectingDataList.front().SendBuffer.get())->Address_Type = SOCKS5_ADDRESS_IPV6;
		RecvLen = sizeof(socks_udp_relay_request);

	//Address
		*(in6_addr *)(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv6.sin6_addr;
		RecvLen += sizeof(in6_addr);

	//Port
		*(uint16_t *)(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv6.sin6_port;
		RecvLen += sizeof(uint16_t);
	}
	else if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET) //IPv4
	{
	//Address type
		((psocks_udp_relay_request)UDPSocketSelectingDataList.front().SendBuffer.get())->Address_Type = SOCKS5_ADDRESS_IPV4;
		RecvLen = sizeof(socks_udp_relay_request);

	//Address
		*(in_addr *)(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv4.sin_addr;
		RecvLen += sizeof(in_addr);

	//Port
		*(uint16_t *)(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv4.sin_port;
		RecvLen += sizeof(uint16_t);
	}
	else if (Parameter.SOCKS_TargetDomain != nullptr && !Parameter.SOCKS_TargetDomain->empty()) //Domain
	{
	//Address type
		((psocks_udp_relay_request)UDPSocketSelectingDataList.front().SendBuffer.get())->Address_Type = SOCKS5_ADDRESS_DOMAIN;
		RecvLen = sizeof(socks_udp_relay_request);

	//Domain
		*(uint8_t *)(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen) = (uint8_t)Parameter.SOCKS_TargetDomain->length();
		RecvLen += sizeof(uint8_t);
		memcpy_s(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen, UDPSocketSelectingDataList.front().SendSize - RecvLen, Parameter.SOCKS_TargetDomain->c_str(), Parameter.SOCKS_TargetDomain->length());
		RecvLen += Parameter.SOCKS_TargetDomain->length();
		
	//Port
		*(uint16_t *)(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetDomain_Port;
		RecvLen += sizeof(uint16_t);
	}
	else {
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		if (!Parameter.SOCKS_UDP_NoHandshake)
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Buffer initialization(Part 2)
	memcpy_s(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen, UDPSocketSelectingDataList.front().SendSize - RecvLen, OriginalSend, SendSize);
	RecvLen += SendSize;
	UDPSocketSelectingDataList.front().SendLen = RecvLen;

//Request exchange and response check
	TCPSocketSelectingDataList.front().RecvBuffer.reset();
	UDPSocketSelectingDataList.front().RecvBuffer.reset();
	LocalSocketSelectingDataList.front().RecvBuffer.reset();
	TCPSocketSelectingDataList.front().RecvSize = 0;
	UDPSocketSelectingDataList.front().RecvSize = 0;
	LocalSocketSelectingDataList.front().RecvSize = 0;
	TCPSocketSelectingDataList.front().RecvLen = 0;
	UDPSocketSelectingDataList.front().RecvLen = 0;
	LocalSocketSelectingDataList.front().RecvLen = 0;
	RecvLen = SocketSelectingSerial(REQUEST_PROCESS_SOCKS_MAIN, IPPROTO_UDP, UDPSocketDataList, UDPSocketSelectingDataList, UDPErrorCodeList);
	SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
	if (!Parameter.SOCKS_UDP_NoHandshake)
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
	UDPSocketSelectingDataList.front().SendBuffer.reset();
	UDPSocketSelectingDataList.front().SendSize = 0;
	UDPSocketSelectingDataList.front().SendLen = 0;
	if (RecvLen != EXIT_FAILURE && UDPSocketSelectingDataList.front().RecvLen >= sizeof(socks_udp_relay_request) + DNS_PACKET_MINSIZE)
	{
	//Remove SOCKS UDP relay header
		if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET6 && //IPv6
			((psocks_udp_relay_request)UDPSocketSelectingDataList.front().RecvBuffer.get())->Address_Type == SOCKS5_ADDRESS_IPV6 && //Address type
			UDPSocketSelectingDataList.front().RecvLen >= sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t) + DNS_PACKET_MINSIZE && //IPv6 address length check
			memcmp((in6_addr *)(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request)), &Parameter.SOCKS_TargetServer.IPv6.sin6_addr, sizeof(in6_addr)) == 0 && //Address
			*(uint16_t *)(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(in6_addr)) == Parameter.SOCKS_TargetServer.IPv6.sin6_port) //Port
		{
			memmove_s(UDPSocketSelectingDataList.front().RecvBuffer.get(), UDPSocketSelectingDataList.front().RecvSize, UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t), UDPSocketSelectingDataList.front().RecvLen - (sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t)));
			UDPSocketSelectingDataList.front().RecvLen -= sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t);
		}
		else if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET && //IPv4
			((psocks_udp_relay_request)UDPSocketSelectingDataList.front().RecvBuffer.get())->Address_Type == SOCKS5_ADDRESS_IPV4 && //Address type
			UDPSocketSelectingDataList.front().RecvLen >= sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t) + DNS_PACKET_MINSIZE && //IPv4 address length check
			(*(in_addr *)(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request))).s_addr == Parameter.SOCKS_TargetServer.IPv4.sin_addr.s_addr && //Address
			*(uint16_t *)(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(in_addr)) == Parameter.SOCKS_TargetServer.IPv4.sin_port) //Port
		{
			memmove_s(UDPSocketSelectingDataList.front().RecvBuffer.get(), UDPSocketSelectingDataList.front().RecvSize, UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t), UDPSocketSelectingDataList.front().RecvLen - (sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t)));
			UDPSocketSelectingDataList.front().RecvLen -= sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t);
		}
		else if (Parameter.SOCKS_TargetDomain != nullptr && !Parameter.SOCKS_TargetDomain->empty() //Domain
/* SOCKS server will reply IPv4/IPv6 address of domain.
			((psocks_udp_relay_request)UDPSocketSelectingDataList.front().RecvBuffer.get())->Address_Type == SOCKS5_ADDRESS_DOMAIN && //Address type
			UDPSocketSelectingDataList.front().RecvLen >= sizeof(socks_udp_relay_request) + sizeof(uint8_t) + Parameter.SOCKS_TargetDomain->length() + sizeof(uint16_t) + DNS_PACKET_MINSIZE && //Domain length check
			*(uint8_t *)(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request)) == Parameter.SOCKS_TargetDomain->length() && 
			memcmp(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(uint8_t), Parameter.SOCKS_TargetDomain->c_str(), Parameter.SOCKS_TargetDomain->length()) == 0 && //Domain
			*(uint16_t *)(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(uint8_t) + Parameter.SOCKS_TargetDomain->length()) == Parameter.SOCKS_TargetDomain_Port //Port
*/
			)
		{
		//IPv6
			if (((psocks_udp_relay_request)UDPSocketSelectingDataList.front().RecvBuffer.get())->Address_Type == SOCKS5_ADDRESS_IPV6 && //Address type
				UDPSocketSelectingDataList.front().RecvLen >= sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t) + DNS_PACKET_MINSIZE) //Length check
			{
				memmove_s(UDPSocketSelectingDataList.front().RecvBuffer.get(), UDPSocketSelectingDataList.front().RecvSize, UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t), UDPSocketSelectingDataList.front().RecvLen - (sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t)));
				UDPSocketSelectingDataList.front().RecvLen -= sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t);
			}
		//IPv4
			else if (((psocks_udp_relay_request)UDPSocketSelectingDataList.front().RecvBuffer.get())->Address_Type == SOCKS5_ADDRESS_IPV4 && //Address type
				UDPSocketSelectingDataList.front().RecvLen >= sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t) + DNS_PACKET_MINSIZE) //Length check
			{
				memmove_s(UDPSocketSelectingDataList.front().RecvBuffer.get(), UDPSocketSelectingDataList.front().RecvSize, UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t), UDPSocketSelectingDataList.front().RecvLen - (sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t)));
				UDPSocketSelectingDataList.front().RecvLen -= sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t);
			}

/* SOCKS server will reply IPv4/IPv6 address of domain.
			memmove_s(UDPSocketSelectingDataList.front().RecvBuffer.get(), UDPSocketSelectingDataList.front().RecvSize, UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(uint8_t) + Parameter.SOCKS_TargetDomain->length() + sizeof(uint16_t), UDPSocketSelectingDataList.front().RecvLen - (sizeof(socks_udp_relay_request) + sizeof(uint8_t) + Parameter.SOCKS_TargetDomain->length() + sizeof(uint16_t)));
			UDPSocketSelectingDataList.front().RecvLen -= sizeof(socks_udp_relay_request) + sizeof(uint8_t) + Parameter.SOCKS_TargetDomain->length() + sizeof(uint16_t);
*/
		}

	//Response check
		RecvLen = CheckResponseData(
			REQUEST_PROCESS_HTTP_CONNECT, 
			UDPSocketSelectingDataList.front().RecvBuffer.get(), 
			UDPSocketSelectingDataList.front().RecvLen, 
			UDPSocketSelectingDataList.front().RecvSize, 
			nullptr);
		if (RecvLen < DNS_PACKET_MINSIZE)
			return EXIT_FAILURE;

	//Mark DNS cache.
		if (Parameter.CacheType != CACHE_TYPE_NONE)
			MarkDomainCache(UDPSocketSelectingDataList.front().RecvBuffer.get(), RecvLen);

	//Swap buffer.
		OriginalRecv.swap(UDPSocketSelectingDataList.front().RecvBuffer);
		RecvSize = UDPSocketSelectingDataList.front().RecvSize;
		return RecvLen;
	}

	return EXIT_FAILURE;
}

//SOCKS selection exchange process
bool SOCKS_SelectionExchange(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList)
{
//Buffer initialization
	if (SocketSelectingDataList.front().SendSize < sizeof(socks_client_selection))
	{
		std::shared_ptr<uint8_t> SendBuffer(new uint8_t[sizeof(socks_client_selection)]());
		memset(SendBuffer.get(), 0, sizeof(socks_client_selection));
		SocketSelectingDataList.front().SendBuffer.swap(SendBuffer);
		SocketSelectingDataList.front().SendSize = sizeof(socks_client_selection);
		SocketSelectingDataList.front().SendLen = 0;
	}

//Client selection packet
	((psocks_client_selection)SocketSelectingDataList.front().SendBuffer.get())->Version = SOCKS_VERSION_5;
	((psocks_client_selection)SocketSelectingDataList.front().SendBuffer.get())->Methods_A = SOCKS_METHOD_NO_AUTHENTICATION_REQUIRED;
	if (Parameter.SOCKS_Username != nullptr && !Parameter.SOCKS_Username->empty() && 
		Parameter.SOCKS_Password != nullptr && !Parameter.SOCKS_Password->empty())
	{
		((psocks_client_selection)SocketSelectingDataList.front().SendBuffer.get())->Methods_Number = SOCKS_METHOD_SUPPORT_NUM;
		((psocks_client_selection)SocketSelectingDataList.front().SendBuffer.get())->Methods_B = SOCKS_METHOD_USERNAME_PASSWORD;
		SocketSelectingDataList.front().SendLen = sizeof(socks_client_selection);
	}
	else {
		((psocks_client_selection)SocketSelectingDataList.front().SendBuffer.get())->Methods_Number = SOCKS_METHOD_NO_AUTHENTICATION_NUM;
		SocketSelectingDataList.front().SendLen = sizeof(socks_client_selection) - sizeof(uint8_t);
	}

//TCP connecting
	auto RecvLen = SocketConnecting(IPPROTO_TCP, SocketDataList.front().Socket, (PSOCKADDR)&SocketDataList.front().SockAddr, SocketDataList.front().AddrLen, SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendSize);
	if (RecvLen == EXIT_FAILURE)
	{
		PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"SOCKS connecting error", 0, nullptr, 0);
		return false;
	}
	else if (RecvLen >= DNS_PACKET_MINSIZE)
	{
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
	}

//Client selection exchange
	SocketSelectingDataList.front().RecvBuffer.reset();
	SocketSelectingDataList.front().RecvSize = 0;
	SocketSelectingDataList.front().RecvLen = 0;
	RecvLen = SocketSelectingSerial(REQUEST_PROCESS_SOCKS_CLIENT_SELECTION, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
	SocketSelectingDataList.front().SendBuffer.reset();
	SocketSelectingDataList.front().SendSize = 0;
	SocketSelectingDataList.front().SendLen = 0;
	if (RecvLen == EXIT_FAILURE || SocketSelectingDataList.front().RecvLen < sizeof(socks_server_selection))
	{
		PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"SOCKS request error", ErrorCodeList.front(), nullptr, 0);
		return false;
	}
	else {
	//Server server selection version check
		if (((psocks_server_selection)SocketSelectingDataList.front().RecvBuffer.get())->Version != SOCKS_VERSION_5)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_SOCKS, L"Server SOCKS protocol version error", 0, nullptr, 0);
			return false;
		}
		
	//Server server selection method check
		switch (((psocks_server_selection)SocketSelectingDataList.front().RecvBuffer.get())->Method)
		{
		//No authentication
			case SOCKS_METHOD_NO_AUTHENTICATION_REQUIRED:
			{
				break;
			}break;
		//Require username or password authentication
			case SOCKS_METHOD_USERNAME_PASSWORD:
			{
			//Username or password authentication process
				if (Parameter.SOCKS_Username != nullptr && !Parameter.SOCKS_Username->empty() && 
					Parameter.SOCKS_Password != nullptr && !Parameter.SOCKS_Password->empty())
				{
					if (!SOCKS_AuthenticationExchange(SocketDataList, SocketSelectingDataList, ErrorCodeList))
					{
						PrintError(LOG_LEVEL_3, LOG_ERROR_SOCKS, L"Username or Password incorrect", 0, nullptr, 0);
						return false;
					}
				}
				else {
					PrintError(LOG_LEVEL_3, LOG_ERROR_SOCKS, L"Server require username and password authentication", 0, nullptr, 0);
					return false;
				}
			}break;
		//Not support or error
			default:
			{
				PrintError(LOG_LEVEL_3, LOG_ERROR_SOCKS, L"Authentication method not support", 0, nullptr, 0);
				return false;
			}
		}
	}

	return true;
}

//SOCKS username/password authentication process
bool SOCKS_AuthenticationExchange(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList)
{
//Buffer initialization
	if (SocketSelectingDataList.front().SendSize < sizeof(socks_client_user_authentication) + sizeof(uint8_t) * 2U + Parameter.SOCKS_Username->length() + Parameter.SOCKS_Password->length())
	{
		std::shared_ptr<uint8_t> SendBuffer(new uint8_t[sizeof(socks_client_user_authentication) + sizeof(uint8_t) * 2U + Parameter.SOCKS_Username->length() + Parameter.SOCKS_Password->length()]());
		memset(SendBuffer.get(), 0, sizeof(socks_client_user_authentication) + sizeof(uint8_t) * 2U + Parameter.SOCKS_Username->length() + Parameter.SOCKS_Password->length());
		SocketSelectingDataList.front().SendBuffer.swap(SendBuffer);
		SocketSelectingDataList.front().SendSize = sizeof(socks_client_user_authentication) + sizeof(uint8_t) * 2U + Parameter.SOCKS_Username->length() + Parameter.SOCKS_Password->length();
		SocketSelectingDataList.front().SendLen = 0;
	}

//Username/password authentication packet
	size_t RecvLen = 0;
	((psocks_client_user_authentication)SocketSelectingDataList.front().SendBuffer.get())->Version = SOCKS_USERNAME_PASSWORD_VERSION;
	RecvLen += sizeof(socks_client_user_authentication);
	*((uint8_t *)(SocketSelectingDataList.front().SendBuffer.get() + RecvLen)) = (uint8_t)Parameter.SOCKS_Username->length();
	RecvLen += sizeof(uint8_t);
	memcpy_s(SocketSelectingDataList.front().SendBuffer.get() + RecvLen, SocketSelectingDataList.front().SendSize - RecvLen, Parameter.SOCKS_Username->c_str(), Parameter.SOCKS_Username->length());
	RecvLen += Parameter.SOCKS_Username->length();
	*((uint8_t *)(SocketSelectingDataList.front().SendBuffer.get() + RecvLen)) = (uint8_t)Parameter.SOCKS_Password->length();
	RecvLen += sizeof(uint8_t);
	memcpy_s(SocketSelectingDataList.front().SendBuffer.get() + RecvLen, SocketSelectingDataList.front().SendSize - RecvLen, Parameter.SOCKS_Password->c_str(), Parameter.SOCKS_Password->length());
	RecvLen += Parameter.SOCKS_Password->length();

//Username/password authentication exchange and server reply check
	SocketSelectingDataList.front().RecvBuffer.reset();
	SocketSelectingDataList.front().RecvSize = 0;
	SocketSelectingDataList.front().RecvLen = 0;
	RecvLen = SocketSelectingSerial(REQUEST_PROCESS_SOCKS_USER_AUTHENTICATION, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
	SocketSelectingDataList.front().SendBuffer.reset();
	SocketSelectingDataList.front().SendSize = 0;
	SocketSelectingDataList.front().SendLen = 0;
	if (RecvLen == EXIT_FAILURE || SocketSelectingDataList.front().RecvLen < sizeof(socks_server_user_authentication) || 
		((psocks_server_user_authentication)SocketSelectingDataList.front().RecvBuffer.get())->Version != SOCKS_USERNAME_PASSWORD_VERSION || 
		((psocks_server_user_authentication)SocketSelectingDataList.front().RecvBuffer.get())->Status != SOCKS_USERNAME_PASSWORD_SUCCESS)
			return false;

	return true;
}

//SOCKS client command request process
bool SOCKS_ClientCommandRequest(
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList, 
	SOCKET_DATA * const UDP_ASSOCIATE_Address)
{
//Buffer initialization
	if (SocketSelectingDataList.front().SendSize < Parameter.LargeBufferSize)
	{
		std::shared_ptr<uint8_t> SendBuffer(new uint8_t[Parameter.LargeBufferSize]());
		memset(SendBuffer.get(), 0, Parameter.LargeBufferSize);
		SocketSelectingDataList.front().SendBuffer.swap(SendBuffer);
		SocketSelectingDataList.front().SendSize = Parameter.LargeBufferSize;
		SocketSelectingDataList.front().SendLen = 0;
	}

//Client command request packet
	size_t RecvLen = 0;
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5) //SOCKS version 5
	{
	//Command request header
		((psocks5_client_command_request)SocketSelectingDataList.front().SendBuffer.get())->Version = SOCKS_VERSION_5;
		if (Protocol == IPPROTO_TCP) //TCP CONNECT
			((psocks5_client_command_request)SocketSelectingDataList.front().SendBuffer.get())->Command = SOCKS_COMMAND_CONNECT;
		else if (Protocol == IPPROTO_UDP) //UDP ASSOCIATE
			((psocks5_client_command_request)SocketSelectingDataList.front().SendBuffer.get())->Command = SOCKS_COMMAND_UDP_ASSOCIATE;
		else 
			return false;
		RecvLen = sizeof(socks5_client_command_request);

	//Write address.
		if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET6) //IPv6
		{
		//Address type
			((psocks5_client_command_request)SocketSelectingDataList.front().SendBuffer.get())->Address_Type = SOCKS5_ADDRESS_IPV6;

		//Address
			if (Protocol == IPPROTO_TCP) //Empty address in UDP ASSOCIATE
				*(in6_addr *)(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv6.sin6_addr;
			RecvLen += sizeof(in6_addr);

		//Port
			if (Protocol == IPPROTO_TCP) //TCP CONNECT
				*(uint16_t *)(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv6.sin6_port;
			else if (UDP_ASSOCIATE_Address != nullptr) //UDP ASSOCIATE
				*(uint16_t *)(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = ((PSOCKADDR_IN6)&UDP_ASSOCIATE_Address->SockAddr)->sin6_port;
			else 
				return false;
			RecvLen += sizeof(uint16_t);
		}
		else if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET || //IPv4
			Protocol == IPPROTO_UDP) //UDP ASSOCIATE
		{
		//Address type
			((psocks5_client_command_request)SocketSelectingDataList.front().SendBuffer.get())->Address_Type = SOCKS5_ADDRESS_IPV4;
		
		//Address
			if (Protocol == IPPROTO_TCP) //Empty address in UDP ASSOCIATE
				*(in_addr *)(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv4.sin_addr;
			RecvLen += sizeof(in_addr);

		//Port
			if (Protocol == IPPROTO_TCP) //TCP CONNECT
				*(uint16_t *)(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv4.sin_port;
			else if (UDP_ASSOCIATE_Address != nullptr) //UDP ASSOCIATE
				*(uint16_t *)(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = ((PSOCKADDR_IN)&UDP_ASSOCIATE_Address->SockAddr)->sin_port;
			RecvLen += sizeof(uint16_t);
		}
		else if (Parameter.SOCKS_TargetDomain != nullptr && !Parameter.SOCKS_TargetDomain->empty()) //Domain
		{
		//Address type
			((psocks5_client_command_request)SocketSelectingDataList.front().SendBuffer.get())->Address_Type = SOCKS5_ADDRESS_DOMAIN;

		//Domain
			*(uint8_t *)(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = (uint8_t)Parameter.SOCKS_TargetDomain->length();
			RecvLen += sizeof(uint8_t);
			memcpy_s(SocketSelectingDataList.front().SendBuffer.get() + RecvLen, SocketSelectingDataList.front().SendSize - RecvLen, Parameter.SOCKS_TargetDomain->c_str(), Parameter.SOCKS_TargetDomain->length());
			RecvLen += Parameter.SOCKS_TargetDomain->length();
			
		//Port
			*(uint16_t *)(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetDomain_Port;
			RecvLen += sizeof(uint16_t);
		}
		else {
			return false;
		}
	}
	else if (Parameter.SOCKS_Version == SOCKS_VERSION_4 || Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A) //SOCKS version 4 or 4a
	{
		((psocks4_client_command_request)SocketSelectingDataList.front().SendBuffer.get())->Version = SOCKS_VERSION_4; //Same value in version byte(4/4a)
		((psocks4_client_command_request)SocketSelectingDataList.front().SendBuffer.get())->Command = SOCKS_COMMAND_CONNECT;
		((psocks4_client_command_request)SocketSelectingDataList.front().SendBuffer.get())->Remote_Port = Parameter.SOCKS_TargetServer.IPv4.sin_port;
		((psocks4_client_command_request)SocketSelectingDataList.front().SendBuffer.get())->Remote_Address.s_addr = Parameter.SOCKS_TargetServer.IPv4.sin_addr.s_addr;
		RecvLen = sizeof(socks4_client_command_request);

	//Write UserID.
		if (Parameter.SOCKS_Username != nullptr && !Parameter.SOCKS_Username->empty())
		{
			memcpy_s(SocketSelectingDataList.front().SendBuffer.get() + (RecvLen - sizeof(uint8_t)), SocketSelectingDataList.front().SendSize - (RecvLen - sizeof(uint8_t)), Parameter.SOCKS_Username->c_str(), Parameter.SOCKS_Username->length());
			RecvLen += Parameter.SOCKS_Username->length();
		}

	//Write target domain.
		if (Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A && Parameter.SOCKS_TargetDomain != nullptr && !Parameter.SOCKS_TargetDomain->empty())
		{
			((psocks4_client_command_request)SocketSelectingDataList.front().SendBuffer.get())->Remote_Port = Parameter.SOCKS_TargetDomain_Port;
			((psocks4_client_command_request)SocketSelectingDataList.front().SendBuffer.get())->Remote_Address.s_addr = htonl(SOCKS4_ADDRESS_DOMAIN_ADDRESS);
			memcpy_s(SocketSelectingDataList.front().SendBuffer.get() + RecvLen, SocketSelectingDataList.front().SendSize - RecvLen, Parameter.SOCKS_TargetDomain->c_str(), Parameter.SOCKS_TargetDomain->length());
			RecvLen += Parameter.SOCKS_TargetDomain->length() + sizeof(uint8_t);
		}
	}

//Client command request exchange
	SocketSelectingDataList.front().SendLen = RecvLen;
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5) //SOCKS version 5
	{
		SocketSelectingDataList.front().RecvBuffer.reset();
		SocketSelectingDataList.front().RecvSize = 0;
		SocketSelectingDataList.front().RecvLen = 0;
		RecvLen = SocketSelectingSerial(REQUEST_PROCESS_SOCKS_5_COMMAND_REPLY, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
		if (RecvLen == EXIT_FAILURE || SocketSelectingDataList.front().RecvLen < sizeof(socks5_server_command_reply))
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"SOCKS request error", ErrorCodeList.front(), nullptr, 0);
			return false;
		}
	}
	else if (Parameter.SOCKS_Version == SOCKS_VERSION_4 || Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A) //SOCKS version 4 or 4a
	{
	//TCP connecting
		RecvLen = SocketConnecting(IPPROTO_TCP, SocketDataList.front().Socket, (PSOCKADDR)&SocketDataList.front().SockAddr, SocketDataList.front().AddrLen, SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendSize);
		if (RecvLen == EXIT_FAILURE)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"SOCKS connecting error", 0, nullptr, 0);
			return false;
		}
		else if (RecvLen >= DNS_PACKET_MINSIZE)
		{
			SocketSelectingDataList.front().SendBuffer.reset();
			SocketSelectingDataList.front().SendSize = 0;
			SocketSelectingDataList.front().SendLen = 0;
		}

	//Client command request process
		SocketSelectingDataList.front().RecvBuffer.reset();
		SocketSelectingDataList.front().RecvSize = 0;
		SocketSelectingDataList.front().RecvLen = 0;
		RecvLen = SocketSelectingSerial(REQUEST_PROCESS_SOCKS_4_COMMAND_REPLY, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
		if (RecvLen == EXIT_FAILURE || SocketSelectingDataList.front().RecvLen < sizeof(socks4_server_command_reply))
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"SOCKS request error", ErrorCodeList.front(), nullptr, 0);
			return false;
		}
	}
	else {
		return false;
	}

//Server command request check
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5) //SOCKS version 5
	{
		if (((psocks5_server_command_reply)SocketSelectingDataList.front().RecvBuffer.get())->Version != SOCKS_VERSION_5 || 
			((psocks5_server_command_reply)SocketSelectingDataList.front().RecvBuffer.get())->Reserved != 0)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_SOCKS, L"Server SOCKS protocol version error", 0, nullptr, 0);
			return false;
		}
		else if (((psocks5_server_command_reply)SocketSelectingDataList.front().RecvBuffer.get())->Reply != SOCKS5_REPLY_SUCCESS)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_SOCKS, L"Client command request error", ((psocks5_server_command_reply)SocketSelectingDataList.front().RecvBuffer.get())->Reply, nullptr, 0);
			return false;
		}
		else if (UDP_ASSOCIATE_Address != nullptr) //UDP ASSOCIATE
		{
		//IPv6
			if (((psocks5_server_command_reply)SocketSelectingDataList.front().RecvBuffer.get())->Bind_Address_Type == SOCKS5_ADDRESS_IPV6 && 
				SocketSelectingDataList.front().RecvLen >= sizeof(socks5_server_command_reply) + sizeof(in6_addr) + sizeof(uint16_t) && 
				UDP_ASSOCIATE_Address->SockAddr.ss_family == AF_INET6)
			{
			//Address
				((PSOCKADDR_IN6)&UDP_ASSOCIATE_Address->SockAddr)->sin6_addr = *(in6_addr *)(SocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks5_server_command_reply));

			//Port
				((PSOCKADDR_IN6)&UDP_ASSOCIATE_Address->SockAddr)->sin6_port = *(uint16_t *)(SocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks5_server_command_reply) + sizeof(in6_addr));
			}
		//IPv4
			else if (((psocks5_server_command_reply)SocketSelectingDataList.front().RecvBuffer.get())->Bind_Address_Type == SOCKS5_ADDRESS_IPV4 && 
				SocketSelectingDataList.front().RecvLen >= sizeof(socks5_server_command_reply) + sizeof(in_addr) + sizeof(uint16_t) && 
				UDP_ASSOCIATE_Address->SockAddr.ss_family == AF_INET)
			{
			//Address
				((PSOCKADDR_IN)&UDP_ASSOCIATE_Address->SockAddr)->sin_addr = *(in_addr *)(SocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks5_server_command_reply));

			//Port
				((PSOCKADDR_IN)&UDP_ASSOCIATE_Address->SockAddr)->sin_port = *(uint16_t *)(SocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks5_server_command_reply) + sizeof(in_addr));
			}
			else {
				PrintError(LOG_LEVEL_3, LOG_ERROR_SOCKS, L"Client command request error", 0, nullptr, 0);
				return false;
			}
		}
	}
	else if (Parameter.SOCKS_Version == SOCKS_VERSION_4 || Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A) //SOCKS version 4 or 4a
	{
		if (((psocks4_server_command_reply)SocketSelectingDataList.front().RecvBuffer.get())->Version != SOCKS4_VERSION_BYTES)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_SOCKS, L"Server SOCKS protocol version error", 0, nullptr, 0);
			return false;
		}
		else if (((psocks4_server_command_reply)SocketSelectingDataList.front().RecvBuffer.get())->Command != SOCKS4_REPLY_GRANTED)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_SOCKS, L"Client command request error", ((psocks4_server_command_reply)SocketSelectingDataList.front().RecvBuffer.get())->Command, nullptr, 0);
			return false;
		}
	}

	return true;
}

//Transmission and reception of HTTP CONNECT protocol
size_t HTTP_CONNECT_Request(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	std::shared_ptr<uint8_t> &OriginalRecv, 
	size_t &RecvSize)
{
//Initialization
	std::vector<SOCKET_DATA> SocketDataList(1U);
	std::vector<SOCKET_SELECTING_SERIAL_DATA> SocketSelectingDataList(1U);
	std::vector<ssize_t> ErrorCodeList(1U);
	memset(&SocketDataList.front(), 0, sizeof(SocketDataList.front()));
	memset(&SocketSelectingDataList.front(), 0, sizeof(SocketSelectingDataList.front()));
	ErrorCodeList.front() = 0;

//TLS initialization
	void *TLS_Context = nullptr;
#if defined(ENABLE_TLS)
	#if defined(PLATFORM_WIN)
		SSPI_HANDLE_TABLE SSPI_Handle;
		if (Parameter.HTTP_CONNECT_TLS_Handshake)
			TLS_Context = &SSPI_Handle;
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		OPENSSL_CONTEXT_TABLE OpenSSL_CTX;
		if (Parameter.HTTP_CONNECT_TLS_Handshake)
			TLS_Context = &OpenSSL_CTX;
	#endif
#endif

//HTTP CONNECT handshake
	if (!HTTP_CONNECT_Handshake(SocketDataList, SocketSelectingDataList, ErrorCodeList, TLS_Context))
		return EXIT_FAILURE;

//Buffer initialization
	if (SocketSelectingDataList.front().SendSize < SendSize + sizeof(uint16_t))
	{
		std::shared_ptr<uint8_t> SendBuffer(new uint8_t[SendSize + sizeof(uint16_t)]());
		memset(SendBuffer.get(), 0, SendSize + sizeof(uint16_t));
		memcpy_s(SendBuffer.get(), SendSize + sizeof(uint16_t), OriginalSend, SendSize);
		SocketSelectingDataList.front().SendBuffer.swap(SendBuffer);
		SocketSelectingDataList.front().SendSize = SendSize + sizeof(uint16_t);
		SocketSelectingDataList.front().SendLen = SendSize;
	}

//Add length of request packet(It must be written in header when transport with TCP protocol).
	auto RecvLen = AddLengthDataToHeader(SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendLen, SocketSelectingDataList.front().SendSize);
	if (RecvLen < DNS_PACKET_MINSIZE)
	{
	#if defined(ENABLE_TLS)
		if (TLS_Context != nullptr)
	#if defined(PLATFORM_WIN)
			SSPI_ShutdownConnection(*(SSPI_HANDLE_TABLE *)TLS_Context, SocketDataList, ErrorCodeList);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			OpenSSL_ShutdownConnection(*(OPENSSL_CONTEXT_TABLE *)TLS_Context);
		else 
	#endif
	#endif
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}
	else {
		SocketSelectingDataList.front().SendLen = RecvLen;
	}

//HTTP CONNECT exchange
	RecvLen = HTTP_CONNECT_Transport(SocketDataList, SocketSelectingDataList, ErrorCodeList, TLS_Context);
	if (RecvLen >= DNS_PACKET_MINSIZE)
	{
	//Mark DNS cache.
		if (Parameter.CacheType != CACHE_TYPE_NONE)
			MarkDomainCache(SocketSelectingDataList.front().RecvBuffer.get(), RecvLen);

	//Swap buffer.
		OriginalRecv.swap(SocketSelectingDataList.front().RecvBuffer);
		RecvSize = SocketSelectingDataList.front().RecvSize;
		return RecvLen;
	}
	else {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

//Handshake of HTTP CONNECT protocol
bool HTTP_CONNECT_Handshake(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList, 
	void *TLS_Context)
{
//Socket initialization
	if (Parameter.HTTP_CONNECT_Address_IPv6.Storage.ss_family != 0 && //IPv6
		((Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
		Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_IPV6 || //IPv6
		(Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_IPV4 && Parameter.HTTP_CONNECT_Address_IPv4.Storage.ss_family == 0))) //Non-IPv4
	{
	#if defined(ENABLE_TLS)
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (TLS_Context != nullptr)
			{
				if (Parameter.HTTP_CONNECT_TLS_AddressString_IPv6 != nullptr && !Parameter.HTTP_CONNECT_TLS_AddressString_IPv6->empty())
					((OPENSSL_CONTEXT_TABLE *)TLS_Context)->AddressString = *Parameter.HTTP_CONNECT_TLS_AddressString_IPv6;
				else 
					return false;
			}
			else {
		#endif
	#endif
			SocketDataList.front().SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&SocketDataList.front().SockAddr)->sin6_addr = Parameter.HTTP_CONNECT_Address_IPv6.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&SocketDataList.front().SockAddr)->sin6_port = Parameter.HTTP_CONNECT_Address_IPv6.IPv6.sin6_port;
			SocketDataList.front().AddrLen = sizeof(sockaddr_in6);
			SocketDataList.front().Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	#if defined(ENABLE_TLS)
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			}
		#endif
	#endif
	}
	else if (Parameter.HTTP_CONNECT_Address_IPv4.Storage.ss_family != 0 && //IPv4
		((Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
		Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_IPV4 || //IPv4
		(Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_IPV6 && Parameter.HTTP_CONNECT_Address_IPv6.Storage.ss_family == 0))) //Non-IPv6
	{
	#if defined(ENABLE_TLS)
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (TLS_Context != nullptr)
			{
				if (Parameter.HTTP_CONNECT_TLS_AddressString_IPv4 != nullptr && !Parameter.HTTP_CONNECT_TLS_AddressString_IPv4->empty())
					((OPENSSL_CONTEXT_TABLE *)TLS_Context)->AddressString = *Parameter.HTTP_CONNECT_TLS_AddressString_IPv4;
				else 
					return false;
			}
			else {
		#endif
	#endif
			SocketDataList.front().SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&SocketDataList.front().SockAddr)->sin_addr = Parameter.HTTP_CONNECT_Address_IPv4.IPv4.sin_addr;
			((PSOCKADDR_IN)&SocketDataList.front().SockAddr)->sin_port = Parameter.HTTP_CONNECT_Address_IPv4.IPv4.sin_port;
			SocketDataList.front().AddrLen = sizeof(sockaddr_in);
			SocketDataList.front().Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	#if defined(ENABLE_TLS)
		#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			}
		#endif
	#endif
	}
	else {
		return false;
	}

//Socket attribute settings
#if defined(ENABLE_TLS)
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (TLS_Context == nullptr)
		{
	#endif
#endif
	//Socket check
		if (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_INVALID_CHECK, false, nullptr))
		{
			PrintError(LOG_LEVEL_2, LOG_ERROR_NETWORK, L"HTTP CONNECT socket initialization error", 0, nullptr, 0);
			return false;
		}

	//Socket attribute settings
		if (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TCP_FAST_OPEN, true, nullptr) || 
			(SocketDataList.front().SockAddr.ss_family == AF_INET6 && !SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_HOP_LIMITS_IPV6, true, nullptr)) || 
			(SocketDataList.front().SockAddr.ss_family == AF_INET && !SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_HOP_LIMITS_IPV4, true, nullptr)) || 
			!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_DO_NOT_FRAGMENT, true, nullptr))
		{
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			return false;
		}

	//Socket attribute setting(Non-blocking mode)
		if (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_NON_BLOCKING_MODE, true, nullptr))
		{
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			return false;
		}

#if defined(ENABLE_TLS)
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		}
	#endif
#endif

//TLS handshake
#if defined(ENABLE_TLS)
	if (TLS_Context != nullptr)
	{
	#if defined(PLATFORM_WIN)
		if (!SSPI_SChannelInitializtion(*(SSPI_HANDLE_TABLE *)TLS_Context))
		{
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			return false;
		}
		else if (!SSPI_Handshake(*(SSPI_HANDLE_TABLE *)TLS_Context, SocketDataList, SocketSelectingDataList, ErrorCodeList))
		{
			SSPI_ShutdownConnection(*(SSPI_HANDLE_TABLE *)TLS_Context, SocketDataList, ErrorCodeList);
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

			return false;
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (!OpenSSL_CTX_Initializtion(*(OPENSSL_CONTEXT_TABLE *)TLS_Context) || !OpenSSL_BIO_Initializtion(*(OPENSSL_CONTEXT_TABLE *)TLS_Context))
		{
			return false;
		}
		else if (!OpenSSL_Handshake(*(OPENSSL_CONTEXT_TABLE *)TLS_Context))
		{
			OpenSSL_ShutdownConnection(*(OPENSSL_CONTEXT_TABLE *)TLS_Context);
			return false;
		}
	#endif
	}
#endif

//HTTP CONNECT exchange
	if (Parameter.HTTP_CONNECT_TargetDomain == nullptr || Parameter.HTTP_CONNECT_Version == nullptr || 
		!HTTP_CONNECT_Exchange(SocketDataList, SocketSelectingDataList, ErrorCodeList, TLS_Context))
	{
	#if defined(ENABLE_TLS)
		if (TLS_Context != nullptr)
	#if defined(PLATFORM_WIN)
			SSPI_ShutdownConnection(*(SSPI_HANDLE_TABLE *)TLS_Context, SocketDataList, ErrorCodeList);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			OpenSSL_ShutdownConnection(*(OPENSSL_CONTEXT_TABLE *)TLS_Context);
		else 
	#endif
	#endif
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

		return false;
	}

	return true;
}

//HTTP CONNECT request exchange process
bool HTTP_CONNECT_Exchange(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList, 
	void *TLS_Context)
{
//HTTP CONNECT packet
	std::string HTTPString("CONNECT ");
	HTTPString.append(*Parameter.HTTP_CONNECT_TargetDomain);
	HTTPString.append(" HTTP/");
	HTTPString.append(*Parameter.HTTP_CONNECT_Version);
	HTTPString.append("\r\nHost: ");
	HTTPString.append(*Parameter.HTTP_CONNECT_TargetDomain);
	HTTPString.append("\r\n");
	if (Parameter.HTTP_CONNECT_HeaderField != nullptr && !Parameter.HTTP_CONNECT_HeaderField->empty())
		HTTPString.append(*Parameter.HTTP_CONNECT_HeaderField);
	if (Parameter.HTTP_CONNECT_ProxyAuthorization != nullptr && !Parameter.HTTP_CONNECT_ProxyAuthorization->empty())
		HTTPString.append(*Parameter.HTTP_CONNECT_ProxyAuthorization);
	HTTPString.append("\r\n");

//Buffer initialization
	if (SocketSelectingDataList.front().SendSize < HTTPString.length())
	{
		std::shared_ptr<uint8_t> SendBuffer(new uint8_t[HTTPString.length()]());
		memset(SendBuffer.get(), 0, HTTPString.length());
		memcpy_s(SendBuffer.get(), HTTPString.length(), HTTPString.c_str(), HTTPString.length());
		SocketSelectingDataList.front().SendBuffer.swap(SendBuffer);
		SocketSelectingDataList.front().SendSize = HTTPString.length();
		SocketSelectingDataList.front().SendLen = HTTPString.length();
	}

//TLS encryption process
	if (TLS_Context != nullptr)
	{
	#if defined(ENABLE_TLS)
	#if defined(PLATFORM_WIN)
		if (!TLS_TransportSerial(HTTP_RESPONSE_MINSIZE, *(SSPI_HANDLE_TABLE *)TLS_Context, SocketDataList, SocketSelectingDataList, ErrorCodeList))
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (!TLS_TransportSerial(REQUEST_PROCESS_HTTP_CONNECT, HTTP_RESPONSE_MINSIZE, *(OPENSSL_CONTEXT_TABLE *)TLS_Context, SocketSelectingDataList))
	#endif
			return false;
	#endif
	}
//Normal process
	else {
	//TCP connecting
		auto RecvLen = SocketConnecting(IPPROTO_TCP, SocketDataList.front().Socket, (PSOCKADDR)&SocketDataList.front().SockAddr, SocketDataList.front().AddrLen, (const uint8_t *)SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendSize);
		if (RecvLen == EXIT_FAILURE)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"HTTP CONNECT connecting error", 0, nullptr, 0);
			return false;
		}
		else if (RecvLen >= DNS_PACKET_MINSIZE)
		{
			SocketSelectingDataList.front().SendBuffer.reset();
			SocketSelectingDataList.front().SendSize = 0;
			SocketSelectingDataList.front().SendLen = 0;
		}

	//HTTP CONNECT request
		SocketSelectingDataList.front().RecvBuffer.reset();
		SocketSelectingDataList.front().RecvSize = 0;
		SocketSelectingDataList.front().RecvLen = 0;
		RecvLen = SocketSelectingSerial(REQUEST_PROCESS_HTTP_CONNECT, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
		if (RecvLen == EXIT_FAILURE || SocketSelectingDataList.front().RecvLen < HTTP_RESPONSE_MINSIZE)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"HTTP CONNECT request error", ErrorCodeList.front(), nullptr, 0);
			return false;
		}
	}

//Buffer initialization
	if (SocketSelectingDataList.front().RecvLen == SocketSelectingDataList.front().RecvSize)
	{
		std::shared_ptr<uint8_t> RecvBuffer(new uint8_t[SocketSelectingDataList.front().RecvSize + PADDING_RESERVED_BYTES]());
		memset(RecvBuffer.get(), 0, SocketSelectingDataList.front().RecvSize + PADDING_RESERVED_BYTES);
		SocketSelectingDataList.front().RecvSize += PADDING_RESERVED_BYTES;
		memcpy_s(RecvBuffer.get(), SocketSelectingDataList.front().RecvSize, SocketSelectingDataList.front().RecvBuffer.get(), SocketSelectingDataList.front().RecvLen);
		SocketSelectingDataList.front().RecvBuffer.swap(RecvBuffer);
	}

//Build HTTP string.
	HTTPString.clear();
	HTTPString = (const char *)SocketSelectingDataList.front().RecvBuffer.get();

//HTTP CONNECT response check
	if (CheckConnectionStreamFin(REQUEST_PROCESS_HTTP_CONNECT, (const uint8_t *)HTTPString.c_str(), HTTPString.length()))
	{
		return true;
	}
	else if (HTTPString.find("HTTP/") == 0 && HTTPString.find(ASCII_SPACE) != std::string::npos && HTTPString.find("\r\n\r\n") != std::string::npos)
	{
		if (HTTPString.find("\r\n") != std::string::npos)
			HTTPString.erase(HTTPString.find("\r\n"), HTTPString.length() - HTTPString.find("\r\n"));
		else 
			HTTPString.erase(HTTPString.find("\r\n\r\n"), HTTPString.length() - HTTPString.find("\r\n"));
		std::wstring Message;
		if (!MBS_To_WCS_String((const uint8_t *)HTTPString.c_str(), HTTPString.length(), Message))
			PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);
		else 
			PrintError(LOG_LEVEL_3, LOG_ERROR_HTTP_CONNECT, Message.c_str(), 0, nullptr, 0);
	}
	else {
		PrintError(LOG_LEVEL_3, LOG_ERROR_HTTP_CONNECT, L"HTTP CONNECT server response error", 0, nullptr, 0);
	}
	
	return false;
}

//Transmission and reception of HTTP CONNECT protocol
size_t HTTP_CONNECT_Transport(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList, 
	void *TLS_Context)
{
	size_t RecvLen = 0;

//Request exchange
	if (TLS_Context != nullptr)
	{
	#if defined(ENABLE_TLS)
		#if defined(PLATFORM_WIN)
			if (!TLS_TransportSerial(DNS_PACKET_MINSIZE, *(SSPI_HANDLE_TABLE *)TLS_Context, SocketDataList, SocketSelectingDataList, ErrorCodeList))
			{
				SSPI_ShutdownConnection(*(SSPI_HANDLE_TABLE *)TLS_Context, SocketDataList, ErrorCodeList);
				SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);

				return EXIT_FAILURE;
			}
			else {
				SSPI_ShutdownConnection(*(SSPI_HANDLE_TABLE *)TLS_Context, SocketDataList, ErrorCodeList);
				SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
			}
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if (!TLS_TransportSerial(REQUEST_PROCESS_TCP, DNS_PACKET_MINSIZE, *(OPENSSL_CONTEXT_TABLE *)TLS_Context, SocketSelectingDataList))
			{
				OpenSSL_ShutdownConnection(*(OPENSSL_CONTEXT_TABLE *)TLS_Context);
				return EXIT_FAILURE;
			}
			else {
				OpenSSL_ShutdownConnection(*(OPENSSL_CONTEXT_TABLE *)TLS_Context);
			}
		#endif
	#endif
	}
	else {
		SocketSelectingDataList.front().RecvBuffer.reset();
		SocketSelectingDataList.front().RecvSize = 0;
		SocketSelectingDataList.front().RecvLen = 0;
		RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TCP, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_CLOSE, false, nullptr);
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
		if (RecvLen == EXIT_FAILURE || SocketSelectingDataList.front().RecvLen < DNS_PACKET_MINSIZE)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_NETWORK, L"HTTP CONNECT request error", ErrorCodeList.front(), nullptr, 0);
			return EXIT_FAILURE;
		}
	}

//HTTP CONNECT response check
	if (SocketSelectingDataList.front().RecvLen >= DNS_PACKET_MINSIZE && ntohs(((uint16_t *)SocketSelectingDataList.front().RecvBuffer.get())[0]) >= DNS_PACKET_MINSIZE && 
		SocketSelectingDataList.front().RecvLen >= ntohs(((uint16_t *)SocketSelectingDataList.front().RecvBuffer.get())[0]))
	{
		RecvLen = ntohs(((uint16_t *)SocketSelectingDataList.front().RecvBuffer.get())[0]);
		memmove_s(SocketSelectingDataList.front().RecvBuffer.get(), SocketSelectingDataList.front().RecvSize, SocketSelectingDataList.front().RecvBuffer.get() + sizeof(uint16_t), RecvLen);
		memset(SocketSelectingDataList.front().RecvBuffer.get() + RecvLen, 0, SocketSelectingDataList.front().RecvSize - RecvLen);

	//Response check
		RecvLen = CheckResponseData(
			REQUEST_PROCESS_HTTP_CONNECT, 
			SocketSelectingDataList.front().RecvBuffer.get(), 
			RecvLen, 
			SocketSelectingDataList.front().RecvSize, 
			nullptr);
		if (RecvLen >= DNS_PACKET_MINSIZE)
			return RecvLen;
	}

	return EXIT_FAILURE;
}
