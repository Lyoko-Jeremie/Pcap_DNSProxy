// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2018 Chengr28
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
** Client <-> Server: Data stream..

* SOCKS Protocol version 4a
** Client -> Server(1): TCP CONNECT command request
  *  1 bytes: SOCKS version
  *  1 bytes: Command code
  *  2 bytes: Remote port
  *  4 bytes: Remote IPv4 address(Must set to 0.0.0.x and x must not be 0)
  * Variable: UserID
  * Variable: Remote domain
** Server -> Client(1): Server command response
  *  1 bytes: SOCKS version
  *  1 bytes: Status code
  *  2 bytes: Remote port(Ignored)
  *  4 bytes: Remote IPv4 address(Ignored)
** Client <-> Server: Data stream..

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
*** Client <-> Server: Data stream..

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
  * Variable: UDP datagram..
*** Server -> Client(2): UDP datagram, with UDP
  *  2 bytes: Reserved
  *  1 bytes: Fragment number
  *  1 bytes: Address type
  * Variable: Remote address
  *  2 bytes: Remote port
  * Variable: UDP datagram..
*** Client <-> Server: UDP datagram..
*** TCP connection between client and server must be kept alive until UDP transmission is finished.

* HTTP version 1.x CONNECT tunnel
** TLS connection handshake
** Client -> Server: HTTP CONNECT method request
  * CONNECT TargetDomain:Port HTTP/version\r\n
  * Host: TargetDomain:Port\r\n
  * Other HTTP headers..\r\n
  * Proxy-Authentication: Basic "Base64 of Username:Password"\r\n
  * \r\n
** Server -> Client: Server HTTP CONNECT response
  * HTTP/1.0 200 Connection established\r\n or HTTP/1.1 200 Connection established\r\n
  * Other HTTP headers..\r\n
  * \r\n
** Client <-> Server: Data stream..
** TLS connection shutdown

* HTTP version 2 CONNECT tunnel
** TLS connection handshake
  * Must be includeing ALPN extension "h2"
** Client -> Server: HTTP CONNECT method request
  * Magic frame: PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
  * SETTINGS frame: 
    * Max concurrent streams: 100
  * HEADERS frame: 
    * :method CONNECT
    * :authority TargetDomain:Port
    * Other HTTP headers..
    * proxy-authentication: Basic "Base64 of Username:Password"
** Server -> Client: Server HTTP CONNECT response
  * SETTINGS frame: Server settings
  * SETTINGS frame: Client SETTINGS frame ACK
  * HEADERS frame: 
    * :status: 200
    * Other HTTP headers..
** Client -> Server: Client HTTP CONNECT response
  * SETTINGS frame: Server SETTINGS frame ACK
** Client <-> Server: Data stream..
  * DATA frame
** Client -> Server: Client HTTP CONNECT shutdown notify
  * GOAWAY frame
** TLS connection shutdown
*/

//Transmission and reception of SOCKS protocol(TCP)
size_t SOCKS_TCP_Request(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	std::unique_ptr<uint8_t[]> &OriginalRecv, 
	size_t &RecvSize, 
	const SOCKET_DATA &LocalSocketData)
{
//Initialization
	std::vector<SOCKET_DATA> SocketDataList(1U);
	std::vector<SOCKET_SELECTING_SERIAL_DATA> SocketSelectingDataList(1U);
	std::vector<ssize_t> ErrorCodeList(1U);
	memset(&SocketDataList.front(), 0, sizeof(SocketDataList.front()));
	SocketDataList.front().Socket = INVALID_SOCKET;
	ErrorCodeList.front() = 0;

//Socket initialization
	if (Parameter.SOCKS_Address_IPv6.Storage.ss_family != 0 && //IPv6
		((Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::IPV6 || //IPv6
		(Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::IPV4 && Parameter.SOCKS_Address_IPv4.Storage.ss_family == 0))) //Non-IPv4
	{
		SocketDataList.front().SockAddr.ss_family = AF_INET6;
		reinterpret_cast<sockaddr_in6 *>(&SocketDataList.front().SockAddr)->sin6_addr = Parameter.SOCKS_Address_IPv6.IPv6.sin6_addr;
		reinterpret_cast<sockaddr_in6 *>(&SocketDataList.front().SockAddr)->sin6_port = Parameter.SOCKS_Address_IPv6.IPv6.sin6_port;
		SocketDataList.front().AddrLen = sizeof(sockaddr_in6);
		SocketDataList.front().Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	}
	else if (Parameter.SOCKS_Address_IPv4.Storage.ss_family != 0 && //IPv4
		((Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::IPV4 || //IPv4
		(Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::IPV6 && Parameter.SOCKS_Address_IPv6.Storage.ss_family == 0))) //Non-IPv6
	{
		SocketDataList.front().SockAddr.ss_family = AF_INET;
		reinterpret_cast<sockaddr_in *>(&SocketDataList.front().SockAddr)->sin_addr = Parameter.SOCKS_Address_IPv4.IPv4.sin_addr;
		reinterpret_cast<sockaddr_in *>(&SocketDataList.front().SockAddr)->sin_port = Parameter.SOCKS_Address_IPv4.IPv4.sin_port;
		SocketDataList.front().AddrLen = sizeof(sockaddr_in);
		SocketDataList.front().Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check
	if (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"SOCKS socket initialization error", 0, nullptr, 0);
		return EXIT_FAILURE;
	}

//Socket attribute settings
	if (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr) || 
		!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr) || 
		(SocketDataList.front().SockAddr.ss_family == AF_INET6 && !SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr)) || 
		(SocketDataList.front().SockAddr.ss_family == AF_INET && (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr)))) // || 
//		!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))))
	{
		SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Selection exchange process
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5 && !SOCKS_SelectionExchange(SocketDataList, SocketSelectingDataList, ErrorCodeList))
	{
		SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Client command request process
	if (!SOCKS_ClientCommandRequest(IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList, nullptr))
	{
		SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}

//Add length of request packet.
	if (SocketSelectingDataList.front().SendSize <= SendSize + sizeof(uint16_t))
	{
		auto SendBuffer = std::make_unique<uint8_t[]>(SendSize + sizeof(uint16_t) + PADDING_RESERVED_BYTES);
		memset(SendBuffer.get(), 0, SendSize + sizeof(uint16_t) + PADDING_RESERVED_BYTES);
		memcpy_s(SendBuffer.get(), SendSize + sizeof(uint16_t), OriginalSend, SendSize);
		std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
		SocketSelectingDataList.front().SendSize = SendSize + sizeof(uint16_t);
		SocketSelectingDataList.front().SendLen = SendSize;
	}
	auto RecvLen = AddLengthDataToHeader(SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendLen, SocketSelectingDataList.front().SendSize);
	if (RecvLen < DNS_PACKET_MINSIZE)
	{
		SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		return EXIT_FAILURE;
	}
	else {
		SocketSelectingDataList.front().SendLen = RecvLen;
	}

//Request exchange and response check
	SocketSelectingDataList.front().RecvBuffer.reset();
	SocketSelectingDataList.front().RecvSize = 0;
	SocketSelectingDataList.front().RecvLen = 0;
	RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TYPE::SOCKS_MAIN, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
	SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	SocketSelectingDataList.front().SendBuffer.reset();
	SocketSelectingDataList.front().SendSize = 0;
	SocketSelectingDataList.front().SendLen = 0;
	if (RecvLen != EXIT_FAILURE && 
		SocketSelectingDataList.front().RecvLen >= DNS_PACKET_MINSIZE && 
		ntohs((reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().RecvBuffer.get()))[0]) >= DNS_PACKET_MINSIZE && 
		SocketSelectingDataList.front().RecvLen >= sizeof(uint16_t) + ntohs((reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().RecvBuffer.get()))[0]))
	{
		RecvLen = ntohs((reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().RecvBuffer.get()))[0]);
		memmove_s(SocketSelectingDataList.front().RecvBuffer.get(), SocketSelectingDataList.front().RecvSize, SocketSelectingDataList.front().RecvBuffer.get() + sizeof(uint16_t), RecvLen);
		memset(SocketSelectingDataList.front().RecvBuffer.get() + RecvLen, 0, SocketSelectingDataList.front().RecvSize - RecvLen);

	//Response check
		RecvLen = CheckResponseData(
			REQUEST_PROCESS_TYPE::SOCKS_MAIN, 
			SocketSelectingDataList.front().RecvBuffer.get(), 
			RecvLen, 
			SocketSelectingDataList.front().RecvSize, 
			nullptr, 
			nullptr);
		if (RecvLen < DNS_PACKET_MINSIZE)
			return EXIT_FAILURE;

	//Mark DNS cache.
		if (Parameter.DNS_CacheType != DNS_CACHE_TYPE::NONE)
			MarkDomainCache(SocketSelectingDataList.front().RecvBuffer.get(), RecvLen, &LocalSocketData);

	//Swap buffer.
		std::swap(OriginalRecv, SocketSelectingDataList.front().RecvBuffer);
		RecvSize = SocketSelectingDataList.front().RecvSize;
		return RecvLen;
	}

	return EXIT_FAILURE;
}

//Transmission and reception of SOCKS protocol(UDP)
size_t SOCKS_UDP_Request(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	std::unique_ptr<uint8_t[]> &OriginalRecv, 
	size_t &RecvSize, 
	const SOCKET_DATA &LocalSocketData)
{
//Initialization
	std::vector<SOCKET_DATA> TCPSocketDataList(1U), UDPSocketDataList(1U), LocalSocketDataList(1U);
	std::vector<SOCKET_SELECTING_SERIAL_DATA> TCPSocketSelectingDataList(1U), UDPSocketSelectingDataList(1U), LocalSocketSelectingDataList(1U);
	std::vector<ssize_t> TCPErrorCodeList(1U), UDPErrorCodeList(1U), LocalErrorCodeList(1U);
	memset(&TCPSocketDataList.front(), 0, sizeof(TCPSocketDataList.front()));
	memset(&UDPSocketDataList.front(), 0, sizeof(UDPSocketDataList.front()));
	memset(&LocalSocketDataList.front(), 0, sizeof(LocalSocketDataList.front()));
	TCPSocketDataList.front().Socket = INVALID_SOCKET;
	UDPSocketDataList.front().Socket = INVALID_SOCKET;
	LocalSocketDataList.front().Socket = INVALID_SOCKET;
	TCPErrorCodeList.front() = 0;
	UDPErrorCodeList.front() = 0;
	LocalErrorCodeList.front() = 0;

//Socket initialization
	if (Parameter.SOCKS_Address_IPv6.Storage.ss_family != 0 && //IPv6
		((Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::IPV6 || //IPv6
		(Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::IPV4 && Parameter.SOCKS_Address_IPv4.Storage.ss_family == 0))) //Non-IPv4
	{
		if (!Parameter.SOCKS_UDP_NoHandshake)
		{
		//TCP process
			TCPSocketDataList.front().SockAddr.ss_family = AF_INET6;
			reinterpret_cast<sockaddr_in6 *>(&TCPSocketDataList.front().SockAddr)->sin6_addr = Parameter.SOCKS_Address_IPv6.IPv6.sin6_addr;
			reinterpret_cast<sockaddr_in6 *>(&TCPSocketDataList.front().SockAddr)->sin6_port = Parameter.SOCKS_Address_IPv6.IPv6.sin6_port;
			TCPSocketDataList.front().AddrLen = sizeof(sockaddr_in6);
			TCPSocketDataList.front().Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

		//Local process
			LocalSocketDataList.front().SockAddr.ss_family = AF_INET6;
			LocalSocketDataList.front().AddrLen = sizeof(sockaddr_in6);
		}

	//UDP process
		UDPSocketDataList.front().SockAddr.ss_family = AF_INET6;
		reinterpret_cast<sockaddr_in6 *>(&UDPSocketDataList.front().SockAddr)->sin6_addr = Parameter.SOCKS_Address_IPv6.IPv6.sin6_addr;
		if (Parameter.SOCKS_UDP_NoHandshake)
			reinterpret_cast<sockaddr_in6 *>(&UDPSocketDataList.front().SockAddr)->sin6_port = Parameter.SOCKS_Address_IPv6.IPv6.sin6_port;
		UDPSocketDataList.front().AddrLen = sizeof(sockaddr_in6);
		UDPSocketDataList.front().Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else if (Parameter.SOCKS_Address_IPv4.Storage.ss_family != 0 && //IPv4
		((Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::IPV4 || //IPv4
		(Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK::IPV6 && Parameter.SOCKS_Address_IPv6.Storage.ss_family == 0))) //Non-IPv6
	{
		if (!Parameter.SOCKS_UDP_NoHandshake)
		{
		//TCP process
			TCPSocketDataList.front().SockAddr.ss_family = AF_INET;
			reinterpret_cast<sockaddr_in *>(&TCPSocketDataList.front().SockAddr)->sin_addr = Parameter.SOCKS_Address_IPv4.IPv4.sin_addr;
			reinterpret_cast<sockaddr_in *>(&TCPSocketDataList.front().SockAddr)->sin_port = Parameter.SOCKS_Address_IPv4.IPv4.sin_port;
			TCPSocketDataList.front().AddrLen = sizeof(sockaddr_in);
			TCPSocketDataList.front().Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		//Local process
			LocalSocketDataList.front().SockAddr.ss_family = AF_INET;
			LocalSocketDataList.front().AddrLen = sizeof(sockaddr_in);
		}

	//UDP process
		UDPSocketDataList.front().SockAddr.ss_family = AF_INET;
		reinterpret_cast<sockaddr_in *>(&UDPSocketDataList.front().SockAddr)->sin_addr = Parameter.SOCKS_Address_IPv4.IPv4.sin_addr;
		if (Parameter.SOCKS_UDP_NoHandshake)
			reinterpret_cast<sockaddr_in *>(&UDPSocketDataList.front().SockAddr)->sin_port = Parameter.SOCKS_Address_IPv4.IPv4.sin_port;
		UDPSocketDataList.front().AddrLen = sizeof(sockaddr_in);
		UDPSocketDataList.front().Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket attribute settings
	if (!(Parameter.SOCKS_UDP_NoHandshake || SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr)) || 
		!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr) || 
		(TCPSocketDataList.front().SockAddr.ss_family == AF_INET6 && !SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr)) || 
		(TCPSocketDataList.front().SockAddr.ss_family == AF_INET && (!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
		!SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))) || 
		!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, true, nullptr) || 
		(UDPSocketDataList.front().SockAddr.ss_family == AF_INET6 && !SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr)) || 
		(UDPSocketDataList.front().SockAddr.ss_family == AF_INET && (!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr) || 
		!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))))
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		if (!Parameter.SOCKS_UDP_NoHandshake)
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Socket attribute setting(Non-blocking mode)
	if (!(Parameter.SOCKS_UDP_NoHandshake || SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr)) || 
		!SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr))
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		if (!Parameter.SOCKS_UDP_NoHandshake)
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//UDP transmission of standard SOCKS protocol must connect with TCP to server at first.
	if (!Parameter.SOCKS_UDP_NoHandshake)
	{
	//Selection exchange process
		if (!SOCKS_SelectionExchange(TCPSocketDataList, TCPSocketSelectingDataList, TCPErrorCodeList))
		{
			SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

			return EXIT_FAILURE;
		}

	//UDP connecting and get UDP socket infomation.
		if (SocketConnecting(IPPROTO_UDP, UDPSocketDataList.front().Socket, reinterpret_cast<sockaddr *>(&UDPSocketDataList.front().SockAddr), UDPSocketDataList.front().AddrLen, nullptr, 0) == EXIT_FAILURE || 
			getsockname(UDPSocketDataList.front().Socket, reinterpret_cast<sockaddr *>(&LocalSocketDataList.front().SockAddr), &LocalSocketDataList.front().AddrLen) == SOCKET_ERROR)
		{
			SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"SOCKS connecting error", 0, nullptr, 0);

			return EXIT_FAILURE;
		}

	//Client command request process
	//IPPROTO_UDP means UDP ASSOCIATE process, this part must transport with TCP protocol.
		if (!SOCKS_ClientCommandRequest(IPPROTO_UDP, TCPSocketDataList, TCPSocketSelectingDataList, TCPErrorCodeList, &LocalSocketDataList.front()))
		{
			SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

			return EXIT_FAILURE;
		}
		else {
		//Copy network infomation from server message.
			if (UDPSocketDataList.front().SockAddr.ss_family == AF_INET6) //IPv6
				reinterpret_cast<sockaddr_in6 *>(&UDPSocketDataList.front().SockAddr)->sin6_port = reinterpret_cast<sockaddr_in6 *>(&LocalSocketDataList.front().SockAddr)->sin6_port;
			else if (UDPSocketDataList.front().SockAddr.ss_family == AF_INET) //IPv4
				reinterpret_cast<sockaddr_in *>(&UDPSocketDataList.front().SockAddr)->sin_port = reinterpret_cast<sockaddr_in *>(&LocalSocketDataList.front().SockAddr)->sin_port;
		}
	}

//UDP connecting again to bind a new socket data.
	if (SocketConnecting(IPPROTO_UDP, UDPSocketDataList.front().Socket, reinterpret_cast<sockaddr *>(&UDPSocketDataList.front().SockAddr), UDPSocketDataList.front().AddrLen, nullptr, 0) == EXIT_FAILURE)
	{
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		if (!Parameter.SOCKS_UDP_NoHandshake)
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"SOCKS connecting error", 0, nullptr, 0);
		return EXIT_FAILURE;
	}

//Buffer initialization(Part 1)
	if (UDPSocketSelectingDataList.front().SendSize <= Parameter.LargeBufferSize)
	{
		auto SendBuffer = std::make_unique<uint8_t[]>(Parameter.LargeBufferSize + PADDING_RESERVED_BYTES);
		memset(SendBuffer.get(), 0, Parameter.LargeBufferSize + PADDING_RESERVED_BYTES);
		std::swap(UDPSocketSelectingDataList.front().SendBuffer, SendBuffer);
		UDPSocketSelectingDataList.front().SendSize = Parameter.LargeBufferSize;
		UDPSocketSelectingDataList.front().SendLen = 0;
	}

//SOCKS UDP relay header
	size_t RecvLen = 0;
	if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET6) //IPv6
	{
	//Address type
		reinterpret_cast<socks_udp_relay_request *>(UDPSocketSelectingDataList.front().SendBuffer.get())->Address_Type = SOCKS_5_ADDRESS_IPV6;
		RecvLen = sizeof(socks_udp_relay_request);

	//Address
		*reinterpret_cast<in6_addr *>(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv6.sin6_addr;
		RecvLen += sizeof(in6_addr);

	//Port
		*reinterpret_cast<uint16_t *>(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv6.sin6_port;
		RecvLen += sizeof(uint16_t);
	}
	else if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET) //IPv4
	{
	//Address type
		reinterpret_cast<socks_udp_relay_request *>(UDPSocketSelectingDataList.front().SendBuffer.get())->Address_Type = SOCKS_5_ADDRESS_IPV4;
		RecvLen = sizeof(socks_udp_relay_request);

	//Address
		*reinterpret_cast<in_addr *>(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv4.sin_addr;
		RecvLen += sizeof(in_addr);

	//Port
		*reinterpret_cast<uint16_t *>(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv4.sin_port;
		RecvLen += sizeof(uint16_t);
	}
	else if (Parameter.SOCKS_TargetDomain != nullptr && !Parameter.SOCKS_TargetDomain->empty()) //Domain
	{
	//Address type
		reinterpret_cast<socks_udp_relay_request *>(UDPSocketSelectingDataList.front().SendBuffer.get())->Address_Type = SOCKS_5_ADDRESS_DOMAIN;
		RecvLen = sizeof(socks_udp_relay_request);

	//Domain
		*reinterpret_cast<uint8_t *>(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen) = static_cast<uint8_t>(Parameter.SOCKS_TargetDomain->length());
		RecvLen += sizeof(uint8_t);
		memcpy_s(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen, UDPSocketSelectingDataList.front().SendSize - RecvLen, Parameter.SOCKS_TargetDomain->c_str(), Parameter.SOCKS_TargetDomain->length());
		RecvLen += Parameter.SOCKS_TargetDomain->length();

	//Port
		*reinterpret_cast<uint16_t *>(UDPSocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetDomain_Port;
		RecvLen += sizeof(uint16_t);
	}
	else {
		SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		if (!Parameter.SOCKS_UDP_NoHandshake)
			SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

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
	RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TYPE::SOCKS_MAIN, IPPROTO_UDP, UDPSocketDataList, UDPSocketSelectingDataList, UDPErrorCodeList);
	SocketSetting(UDPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	if (!Parameter.SOCKS_UDP_NoHandshake)
		SocketSetting(TCPSocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
	UDPSocketSelectingDataList.front().SendBuffer.reset();
	UDPSocketSelectingDataList.front().SendSize = 0;
	UDPSocketSelectingDataList.front().SendLen = 0;
	if (RecvLen != EXIT_FAILURE && UDPSocketSelectingDataList.front().RecvLen >= sizeof(socks_udp_relay_request) + DNS_PACKET_MINSIZE)
	{
	//Remove SOCKS UDP relay header
		if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET6 && //IPv6
			reinterpret_cast<socks_udp_relay_request *>(UDPSocketSelectingDataList.front().RecvBuffer.get())->Address_Type == SOCKS_5_ADDRESS_IPV6 && //Address type
			UDPSocketSelectingDataList.front().RecvLen >= sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t) + DNS_PACKET_MINSIZE && //IPv6 address length check
			memcmp(reinterpret_cast<in6_addr *>(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request)), &Parameter.SOCKS_TargetServer.IPv6.sin6_addr, sizeof(in6_addr)) == 0 && //Address
			*reinterpret_cast<uint16_t *>(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(in6_addr)) == Parameter.SOCKS_TargetServer.IPv6.sin6_port) //Port
		{
			memmove_s(UDPSocketSelectingDataList.front().RecvBuffer.get(), UDPSocketSelectingDataList.front().RecvSize, UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t), UDPSocketSelectingDataList.front().RecvLen - (sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t)));
			UDPSocketSelectingDataList.front().RecvLen -= sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t);
		}
		else if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET && //IPv4
			reinterpret_cast<socks_udp_relay_request *>(UDPSocketSelectingDataList.front().RecvBuffer.get())->Address_Type == SOCKS_5_ADDRESS_IPV4 && //Address type
			UDPSocketSelectingDataList.front().RecvLen >= sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t) + DNS_PACKET_MINSIZE && //IPv4 address length check
			(*reinterpret_cast<in_addr *>(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request))).s_addr == Parameter.SOCKS_TargetServer.IPv4.sin_addr.s_addr && //Address
			*reinterpret_cast<uint16_t *>(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(in_addr)) == Parameter.SOCKS_TargetServer.IPv4.sin_port) //Port
		{
			memmove_s(UDPSocketSelectingDataList.front().RecvBuffer.get(), UDPSocketSelectingDataList.front().RecvSize, UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t), UDPSocketSelectingDataList.front().RecvLen - (sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t)));
			UDPSocketSelectingDataList.front().RecvLen -= sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t);
		}
		else if (Parameter.SOCKS_TargetDomain != nullptr && !Parameter.SOCKS_TargetDomain->empty() //Domain
/* SOCKS server will reply IPv4/IPv6 address of domain.
			reinterpret_cast<socks_udp_relay_request *>(UDPSocketSelectingDataList.front().RecvBuffer.get())->Address_Type == SOCKS_5_ADDRESS_DOMAIN && //Address type
			UDPSocketSelectingDataList.front().RecvLen >= sizeof(socks_udp_relay_request) + sizeof(uint8_t) + Parameter.SOCKS_TargetDomain->length() + sizeof(uint16_t) + DNS_PACKET_MINSIZE && //Domain length check
			*reinterpret_cast<uint8_t *>(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request)) == Parameter.SOCKS_TargetDomain->length() && 
			memcmp(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(uint8_t), Parameter.SOCKS_TargetDomain->c_str(), Parameter.SOCKS_TargetDomain->length()) == 0 && //Domain
			*reinterpret_cast<uint16_t *>(UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(uint8_t) + Parameter.SOCKS_TargetDomain->length()) == Parameter.SOCKS_TargetDomain_Port //Port
*/
			)
		{
		//IPv6
			if (reinterpret_cast<socks_udp_relay_request *>(UDPSocketSelectingDataList.front().RecvBuffer.get())->Address_Type == SOCKS_5_ADDRESS_IPV6 && //Address type
				UDPSocketSelectingDataList.front().RecvLen >= sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t) + DNS_PACKET_MINSIZE) //Length check
			{
				memmove_s(UDPSocketSelectingDataList.front().RecvBuffer.get(), UDPSocketSelectingDataList.front().RecvSize, UDPSocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t), UDPSocketSelectingDataList.front().RecvLen - (sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t)));
				UDPSocketSelectingDataList.front().RecvLen -= sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t);
			}
		//IPv4
			else if (reinterpret_cast<socks_udp_relay_request *>(UDPSocketSelectingDataList.front().RecvBuffer.get())->Address_Type == SOCKS_5_ADDRESS_IPV4 && //Address type
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
			REQUEST_PROCESS_TYPE::SOCKS_MAIN, 
			UDPSocketSelectingDataList.front().RecvBuffer.get(), 
			UDPSocketSelectingDataList.front().RecvLen, 
			UDPSocketSelectingDataList.front().RecvSize, 
			nullptr, 
			nullptr);
		if (RecvLen < DNS_PACKET_MINSIZE)
			return EXIT_FAILURE;

	//Mark DNS cache.
		if (Parameter.DNS_CacheType != DNS_CACHE_TYPE::NONE)
			MarkDomainCache(UDPSocketSelectingDataList.front().RecvBuffer.get(), RecvLen, &LocalSocketData);

	//Swap buffer.
		std::swap(OriginalRecv, UDPSocketSelectingDataList.front().RecvBuffer);
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
//Socket data check
	if (SocketDataList.empty() || SocketSelectingDataList.empty() || ErrorCodeList.empty())
		return false;

//Buffer initialization
	if (SocketSelectingDataList.front().SendSize <= sizeof(socks_client_selection))
	{
		auto SendBuffer = std::make_unique<uint8_t[]>(sizeof(socks_client_selection));
		memset(SendBuffer.get(), 0, sizeof(socks_client_selection));
		std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
		SocketSelectingDataList.front().SendSize = sizeof(socks_client_selection);
		SocketSelectingDataList.front().SendLen = 0;
	}

//Client selection packet
	reinterpret_cast<socks_client_selection *>(SocketSelectingDataList.front().SendBuffer.get())->Version = SOCKS_VERSION_5;
	reinterpret_cast<socks_client_selection *>(SocketSelectingDataList.front().SendBuffer.get())->Methods_1 = SOCKS_METHOD_NO_AUTHENTICATION_REQUIRED;
	if (Parameter.SOCKS_Username != nullptr && !Parameter.SOCKS_Username->empty() && 
		Parameter.SOCKS_Password != nullptr && !Parameter.SOCKS_Password->empty())
	{
		reinterpret_cast<socks_client_selection *>(SocketSelectingDataList.front().SendBuffer.get())->Methods_Number = SOCKS_METHOD_SUPPORT_NUM;
		reinterpret_cast<socks_client_selection *>(SocketSelectingDataList.front().SendBuffer.get())->Methods_2 = SOCKS_METHOD_USERNAME_PASSWORD;
		SocketSelectingDataList.front().SendLen = sizeof(socks_client_selection);
	}
	else {
		reinterpret_cast<socks_client_selection *>(SocketSelectingDataList.front().SendBuffer.get())->Methods_Number = SOCKS_METHOD_NO_AUTHENTICATION_NUM;
		SocketSelectingDataList.front().SendLen = sizeof(socks_client_selection) - sizeof(uint8_t);
	}

//TCP connecting
	auto RecvLen = SocketConnecting(IPPROTO_TCP, SocketDataList.front().Socket, reinterpret_cast<sockaddr *>(&SocketDataList.front().SockAddr), SocketDataList.front().AddrLen, SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendSize);
	if (RecvLen == EXIT_FAILURE)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"SOCKS connecting error", 0, nullptr, 0);
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
	RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TYPE::SOCKS_CLIENT_SELECTION, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
	SocketSelectingDataList.front().SendBuffer.reset();
	SocketSelectingDataList.front().SendSize = 0;
	SocketSelectingDataList.front().SendLen = 0;
	if (RecvLen == EXIT_FAILURE || SocketSelectingDataList.front().RecvLen < sizeof(socks_server_selection))
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"SOCKS request error", ErrorCodeList.front(), nullptr, 0);
		return false;
	}
	else {
	//Server server selection version check
		if (reinterpret_cast<socks_server_selection *>(SocketSelectingDataList.front().RecvBuffer.get())->Version != SOCKS_VERSION_5)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SOCKS, L"Server SOCKS protocol version error", 0, nullptr, 0);
			return false;
		}

	//Server server selection method check
		switch (reinterpret_cast<socks_server_selection *>(SocketSelectingDataList.front().RecvBuffer.get())->Method)
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
						PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SOCKS, L"Username or Password incorrect", 0, nullptr, 0);
						return false;
					}
				}
				else {
					PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SOCKS, L"Server require username and password authentication", 0, nullptr, 0);
					return false;
				}
			}break;
		//Not support or error
			default:
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SOCKS, L"Authentication method is not supported", 0, nullptr, 0);
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
//Socket data check
	if (SocketDataList.empty() || SocketSelectingDataList.empty() || ErrorCodeList.empty())
		return false;

//Buffer initialization
	if (SocketSelectingDataList.front().SendSize <= sizeof(socks_client_user_authentication) + sizeof(uint8_t) * 2U + Parameter.SOCKS_Username->length() + Parameter.SOCKS_Password->length())
	{
		auto SendBuffer = std::make_unique<uint8_t[]>(sizeof(socks_client_user_authentication) + sizeof(uint8_t) * 2U + Parameter.SOCKS_Username->length() + Parameter.SOCKS_Password->length() + PADDING_RESERVED_BYTES);
		memset(SendBuffer.get(), 0, sizeof(socks_client_user_authentication) + sizeof(uint8_t) * 2U + Parameter.SOCKS_Username->length() + Parameter.SOCKS_Password->length() + PADDING_RESERVED_BYTES);
		std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
		SocketSelectingDataList.front().SendSize = sizeof(socks_client_user_authentication) + sizeof(uint8_t) * 2U + Parameter.SOCKS_Username->length() + Parameter.SOCKS_Password->length();
		SocketSelectingDataList.front().SendLen = 0;
	}

//Username/password authentication packet
	size_t RecvLen = 0;
	reinterpret_cast<socks_client_user_authentication *>(SocketSelectingDataList.front().SendBuffer.get())->Version = SOCKS_USERNAME_PASSWORD_VERSION;
	RecvLen += sizeof(socks_client_user_authentication);
	*(reinterpret_cast<uint8_t *>(SocketSelectingDataList.front().SendBuffer.get() + RecvLen)) = static_cast<uint8_t>(Parameter.SOCKS_Username->length());
	RecvLen += sizeof(uint8_t);
	memcpy_s(SocketSelectingDataList.front().SendBuffer.get() + RecvLen, SocketSelectingDataList.front().SendSize - RecvLen, Parameter.SOCKS_Username->c_str(), Parameter.SOCKS_Username->length());
	RecvLen += Parameter.SOCKS_Username->length();
	*(reinterpret_cast<uint8_t *>(SocketSelectingDataList.front().SendBuffer.get() + RecvLen)) = static_cast<uint8_t>(Parameter.SOCKS_Password->length());
	RecvLen += sizeof(uint8_t);
	memcpy_s(SocketSelectingDataList.front().SendBuffer.get() + RecvLen, SocketSelectingDataList.front().SendSize - RecvLen, Parameter.SOCKS_Password->c_str(), Parameter.SOCKS_Password->length());
	RecvLen += Parameter.SOCKS_Password->length();

//Username/password authentication exchange and server reply check
	SocketSelectingDataList.front().RecvBuffer.reset();
	SocketSelectingDataList.front().RecvSize = 0;
	SocketSelectingDataList.front().RecvLen = 0;
	RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TYPE::SOCKS_USER_AUTH, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
	SocketSelectingDataList.front().SendBuffer.reset();
	SocketSelectingDataList.front().SendSize = 0;
	SocketSelectingDataList.front().SendLen = 0;
	if (RecvLen == EXIT_FAILURE || SocketSelectingDataList.front().RecvLen < sizeof(socks_server_user_authentication) || 
		reinterpret_cast<socks_server_user_authentication *>(SocketSelectingDataList.front().RecvBuffer.get())->Version != SOCKS_USERNAME_PASSWORD_VERSION || 
		reinterpret_cast<socks_server_user_authentication *>(SocketSelectingDataList.front().RecvBuffer.get())->Status != SOCKS_USERNAME_PASSWORD_SUCCESS)
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
//Socket data check
	if (SocketDataList.empty() || SocketSelectingDataList.empty() || ErrorCodeList.empty())
		return false;

//Buffer initialization
	if (SocketSelectingDataList.front().SendSize <= Parameter.LargeBufferSize)
	{
		auto SendBuffer = std::make_unique<uint8_t[]>(Parameter.LargeBufferSize + PADDING_RESERVED_BYTES);
		memset(SendBuffer.get(), 0, Parameter.LargeBufferSize + PADDING_RESERVED_BYTES);
		std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
		SocketSelectingDataList.front().SendSize = Parameter.LargeBufferSize;
		SocketSelectingDataList.front().SendLen = 0;
	}

//Client command request packet
	size_t RecvLen = 0;
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5) //SOCKS version 5
	{
	//Command request header
		reinterpret_cast<socks5_client_command_request *>(SocketSelectingDataList.front().SendBuffer.get())->Version = SOCKS_VERSION_5;
		if (Protocol == IPPROTO_TCP) //TCP CONNECT
			reinterpret_cast<socks5_client_command_request *>(SocketSelectingDataList.front().SendBuffer.get())->Command = SOCKS_COMMAND_CONNECT;
		else if (Protocol == IPPROTO_UDP) //UDP ASSOCIATE
			reinterpret_cast<socks5_client_command_request *>(SocketSelectingDataList.front().SendBuffer.get())->Command = SOCKS_COMMAND_UDP_ASSOCIATE;
		else 
			return false;
		RecvLen = sizeof(socks5_client_command_request);

	//Write address.
		if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET6) //IPv6
		{
		//Address type
			reinterpret_cast<socks5_client_command_request *>(SocketSelectingDataList.front().SendBuffer.get())->Address_Type = SOCKS_5_ADDRESS_IPV6;

		//Address
			if (Protocol == IPPROTO_TCP) //Empty address in UDP ASSOCIATE
				*reinterpret_cast<in6_addr *>(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv6.sin6_addr;
			RecvLen += sizeof(in6_addr);

		//Port
			if (Protocol == IPPROTO_TCP) //TCP CONNECT
				*reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv6.sin6_port;
			else if (UDP_ASSOCIATE_Address != nullptr) //UDP ASSOCIATE
				*reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = reinterpret_cast<sockaddr_in6 *>(&UDP_ASSOCIATE_Address->SockAddr)->sin6_port;
			else 
				return false;
			RecvLen += sizeof(uint16_t);
		}
		else if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET || //IPv4
			Protocol == IPPROTO_UDP) //UDP ASSOCIATE
		{
		//Address type
			reinterpret_cast<socks5_client_command_request *>(SocketSelectingDataList.front().SendBuffer.get())->Address_Type = SOCKS_5_ADDRESS_IPV4;

		//Address
			if (Protocol == IPPROTO_TCP) //Empty address in UDP ASSOCIATE
				*reinterpret_cast<in_addr *>(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv4.sin_addr;
			RecvLen += sizeof(in_addr);

		//Port
			if (Protocol == IPPROTO_TCP) //TCP CONNECT
				*reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetServer.IPv4.sin_port;
			else if (UDP_ASSOCIATE_Address != nullptr) //UDP ASSOCIATE
				*reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = reinterpret_cast<sockaddr_in *>(&UDP_ASSOCIATE_Address->SockAddr)->sin_port;
			RecvLen += sizeof(uint16_t);
		}
		else if (Parameter.SOCKS_TargetDomain != nullptr && !Parameter.SOCKS_TargetDomain->empty()) //Domain
		{
		//Address type
			reinterpret_cast<socks5_client_command_request *>(SocketSelectingDataList.front().SendBuffer.get())->Address_Type = SOCKS_5_ADDRESS_DOMAIN;

		//Domain
			*reinterpret_cast<uint8_t *>(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = static_cast<uint8_t>(Parameter.SOCKS_TargetDomain->length());
			RecvLen += sizeof(uint8_t);
			memcpy_s(SocketSelectingDataList.front().SendBuffer.get() + RecvLen, SocketSelectingDataList.front().SendSize - RecvLen, Parameter.SOCKS_TargetDomain->c_str(), Parameter.SOCKS_TargetDomain->length());
			RecvLen += Parameter.SOCKS_TargetDomain->length();

		//Port
			*reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().SendBuffer.get() + RecvLen) = Parameter.SOCKS_TargetDomain_Port;
			RecvLen += sizeof(uint16_t);
		}
		else {
			return false;
		}
	}
	else if (Parameter.SOCKS_Version == SOCKS_VERSION_4 || Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A) //SOCKS version 4 or 4a
	{
		reinterpret_cast<socks4_client_command_request *>(SocketSelectingDataList.front().SendBuffer.get())->Version = SOCKS_VERSION_4; //Same value in version byte(4/4a)
		reinterpret_cast<socks4_client_command_request *>(SocketSelectingDataList.front().SendBuffer.get())->Command = SOCKS_COMMAND_CONNECT;
		reinterpret_cast<socks4_client_command_request *>(SocketSelectingDataList.front().SendBuffer.get())->Remote_Port = Parameter.SOCKS_TargetServer.IPv4.sin_port;
		reinterpret_cast<socks4_client_command_request *>(SocketSelectingDataList.front().SendBuffer.get())->Remote_Address.s_addr = Parameter.SOCKS_TargetServer.IPv4.sin_addr.s_addr;
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
			reinterpret_cast<socks4_client_command_request *>(SocketSelectingDataList.front().SendBuffer.get())->Remote_Port = Parameter.SOCKS_TargetDomain_Port;
			reinterpret_cast<socks4_client_command_request *>(SocketSelectingDataList.front().SendBuffer.get())->Remote_Address.s_addr = htonl(SOCKS_4_ADDRESS_DOMAIN_ADDRESS);
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
		RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TYPE::SOCKS_5_COMMAND_REPLY, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
		if (RecvLen == EXIT_FAILURE || SocketSelectingDataList.front().RecvLen < sizeof(socks5_server_command_reply))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"SOCKS request error", ErrorCodeList.front(), nullptr, 0);
			return false;
		}
	}
	else if (Parameter.SOCKS_Version == SOCKS_VERSION_4 || Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A) //SOCKS version 4 or 4a
	{
	//TCP connecting
		RecvLen = SocketConnecting(IPPROTO_TCP, SocketDataList.front().Socket, reinterpret_cast<sockaddr *>(&SocketDataList.front().SockAddr), SocketDataList.front().AddrLen, SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendSize);
		if (RecvLen == EXIT_FAILURE)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"SOCKS connecting error", 0, nullptr, 0);
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
		RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TYPE::SOCKS_4_COMMAND_REPLY, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
		if (RecvLen == EXIT_FAILURE || SocketSelectingDataList.front().RecvLen < sizeof(socks4_server_command_reply))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"SOCKS request error", ErrorCodeList.front(), nullptr, 0);
			return false;
		}
	}
	else {
		return false;
	}

//Server command request check
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5) //SOCKS version 5
	{
		if (reinterpret_cast<socks5_server_command_reply *>(SocketSelectingDataList.front().RecvBuffer.get())->Version != SOCKS_VERSION_5 || 
			reinterpret_cast<socks5_server_command_reply *>(SocketSelectingDataList.front().RecvBuffer.get())->Reserved > 0)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SOCKS, L"Server SOCKS protocol version error", 0, nullptr, 0);
			return false;
		}
		else if (reinterpret_cast<socks5_server_command_reply *>(SocketSelectingDataList.front().RecvBuffer.get())->Reply != SOCKS_5_REPLY_SUCCESS)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SOCKS, L"Client command request error", reinterpret_cast<socks5_server_command_reply *>(SocketSelectingDataList.front().RecvBuffer.get())->Reply, nullptr, 0);
			return false;
		}
		else if (UDP_ASSOCIATE_Address != nullptr) //UDP ASSOCIATE
		{
		//IPv6
			if (reinterpret_cast<socks5_server_command_reply *>(SocketSelectingDataList.front().RecvBuffer.get())->Bind_Address_Type == SOCKS_5_ADDRESS_IPV6 && 
				SocketSelectingDataList.front().RecvLen >= sizeof(socks5_server_command_reply) + sizeof(in6_addr) + sizeof(uint16_t) && 
				UDP_ASSOCIATE_Address->SockAddr.ss_family == AF_INET6)
			{
			//Address
				reinterpret_cast<sockaddr_in6 *>(&UDP_ASSOCIATE_Address->SockAddr)->sin6_addr = *reinterpret_cast<in6_addr *>(SocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks5_server_command_reply));

			//Port
				reinterpret_cast<sockaddr_in6 *>(&UDP_ASSOCIATE_Address->SockAddr)->sin6_port = *reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks5_server_command_reply) + sizeof(in6_addr));
			}
		//IPv4
			else if (reinterpret_cast<socks5_server_command_reply *>(SocketSelectingDataList.front().RecvBuffer.get())->Bind_Address_Type == SOCKS_5_ADDRESS_IPV4 && 
				SocketSelectingDataList.front().RecvLen >= sizeof(socks5_server_command_reply) + sizeof(in_addr) + sizeof(uint16_t) && 
				UDP_ASSOCIATE_Address->SockAddr.ss_family == AF_INET)
			{
			//Address
				reinterpret_cast<sockaddr_in *>(&UDP_ASSOCIATE_Address->SockAddr)->sin_addr = *reinterpret_cast<in_addr *>(SocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks5_server_command_reply));

			//Port
				reinterpret_cast<sockaddr_in *>(&UDP_ASSOCIATE_Address->SockAddr)->sin_port = *reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().RecvBuffer.get() + sizeof(socks5_server_command_reply) + sizeof(in_addr));
			}
			else {
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SOCKS, L"Client command request error", 0, nullptr, 0);
				return false;
			}
		}
	}
	else if (Parameter.SOCKS_Version == SOCKS_VERSION_4 || Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A) //SOCKS version 4 or 4a
	{
		if (reinterpret_cast<socks4_server_command_reply *>(SocketSelectingDataList.front().RecvBuffer.get())->Version != SOCKS_4_VERSION_BYTES)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SOCKS, L"Server SOCKS protocol version error", 0, nullptr, 0);
			return false;
		}
		else if (reinterpret_cast<socks4_server_command_reply *>(SocketSelectingDataList.front().RecvBuffer.get())->Command != SOCKS_4_REPLY_GRANTED)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SOCKS, L"Client command request error", reinterpret_cast<socks4_server_command_reply *>(SocketSelectingDataList.front().RecvBuffer.get())->Command, nullptr, 0);
			return false;
		}
	}

	return true;
}

//HTTP version 2 SETTINGS frame write bytes
void HTTP_CONNECT_2_SETTINGS_WriteBytes(
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	const uint16_t Identifier, 
	const uint32_t Value)
{
	reinterpret_cast<http2_settings_frame *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)->Identifier = htons(Identifier);
	reinterpret_cast<http2_settings_frame *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)->Value = htonl(Value);
	SocketSelectingDataList.front().SendLen += sizeof(http2_settings_frame);

	return;
}

//HTTP version 2 HPACK Header Compression integer representation encoding
void HTTP_CONNECT_2_IntegerEncoding(
	std::vector<uint8_t> &BytesList, 
	size_t IntegerValue)
{
//N is 7 when disable huffman coding, so the highest bit is 0.
//Pseudocode to represent an integer I is as follows:
//	if I < 2 ^ N(7) - 1, encode I on N(7) bits
//	else 
//		encode (2 ^ N(7) - 1) on N(7) bits
//		I = I - (2 ^ N(7) - 1)
//		while I >= 128
//			encode (I % 128 + 128) on 8 bits
//			I = I / 128
//		encode I on 8 bits
	BytesList.clear();
	if (IntegerValue < HTTP_2_HEADERS_INTEGER_LOW_7_BITS)
	{
		BytesList.push_back(static_cast<uint8_t>(IntegerValue));
	}
	else {
		uint8_t ValueBytes = HTTP_2_HEADERS_INTEGER_LOW_7_BITS;
		BytesList.push_back(ValueBytes);
		IntegerValue -= HTTP_2_HEADERS_INTEGER_LOW_7_BITS;

		while (IntegerValue >= HTTP_2_HEADERS_INTEGER_HIGH_1_BITS)
		{
			ValueBytes = IntegerValue % HTTP_2_HEADERS_INTEGER_HIGH_1_BITS + HTTP_2_HEADERS_INTEGER_HIGH_1_BITS;
			BytesList.push_back(ValueBytes);
			IntegerValue /= HTTP_2_HEADERS_INTEGER_HIGH_1_BITS;
		}

		ValueBytes = static_cast<uint8_t>(IntegerValue);
		BytesList.push_back(ValueBytes);
	}

	return;
}

//HTTP version 2 HPACK Header Compression write bytes
bool HTTP_CONNECT_2_HEADERS_WriteBytes(
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	const uint8_t *Buffer, 
	const size_t Length, 
	const bool IsLiteralFlag)
{
//Buffer initialization
	size_t ExtendedSize = DEFAULT_LARGE_BUFFER_SIZE;
	if (Length >= DEFAULT_LARGE_BUFFER_SIZE)
		ExtendedSize += Length + DEFAULT_LARGE_BUFFER_SIZE;
	if (SocketSelectingDataList.front().SendSize <= SocketSelectingDataList.front().SendLen + ExtendedSize)
	{
		auto SendBuffer = std::make_unique<uint8_t[]>(SocketSelectingDataList.front().SendSize + ExtendedSize + PADDING_RESERVED_BYTES);
		memset(SendBuffer.get(), 0, SocketSelectingDataList.front().SendSize + ExtendedSize + PADDING_RESERVED_BYTES);
		memcpy_s(SendBuffer.get(), SocketSelectingDataList.front().SendSize + ExtendedSize, SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendLen);
		std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
		SocketSelectingDataList.front().SendSize += ExtendedSize;
	}

//Write literal header field flags.
	if (IsLiteralFlag)
	{
		*(reinterpret_cast<uint8_t *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)) = HTTP_2_HEADERS_LITERAL_NEVER_INDEXED;
		SocketSelectingDataList.front().SendLen += sizeof(uint8_t);
	}

//Write length bytes.
	std::vector<uint8_t> IntegerList;
	HTTP_CONNECT_2_IntegerEncoding(IntegerList, Length);
	if (!IntegerList.empty() && IntegerList.size() <= sizeof(uint8_t) + sizeof(uint16_t)) //The integer value is small enough, or extend more 8 or 16 bits to store.
	{
		for (const auto &IntegerIter:IntegerList)
		{
			*(reinterpret_cast<uint8_t *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)) = IntegerIter;
			SocketSelectingDataList.front().SendLen += sizeof(uint8_t);
		}
	}
	else {
		PrintError(LOG_LEVEL_TYPE::LEVEL_1, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP CONNECT header field data error", 0, nullptr, 0);
		return false;
	}

//Write value bytes.
	memcpy_s(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen, SocketSelectingDataList.front().SendSize - SocketSelectingDataList.front().SendLen, Buffer, Length);
	SocketSelectingDataList.front().SendLen += Length;
	return true;
}

//HTTP version 2 HPACK Header Compression integer representation decoding
size_t HTTP_CONNECT_2_IntegerDecoding(
	const uint8_t *Buffer, 
	const size_t Length, 
	const uint8_t PrefixSize, 
	size_t &IntegerValue)
{
//Pseudocode to decode an integer I is as follows:
//Decode I from the next N bits
//	if I < 2 ^ N - 1, return I
//	else 
//		M = 0
//		repeat
//			B = next octet
//			I = I + (B & 127) * 2 ^ M
//			M = M + 7
//		while B & 128 == 128
//		return I
	IntegerValue = ((*Buffer) & PrefixSize);
	if (IntegerValue < PrefixSize)
	{
		return sizeof(uint8_t);
	}
	else {
		size_t IntegerSize = sizeof(uint8_t), Shift = 0;
		IntegerValue = PrefixSize;
		for (;;)
		{
			if (IntegerSize >= Length)
				return 0;
			auto BytesData = *(Buffer + IntegerSize);
			IntegerSize += sizeof(uint8_t);
			if ((BytesData & HTTP_2_HEADERS_INTEGER_HIGH_1_BITS) != 0)
			{
				IntegerValue += static_cast<size_t>(BytesData & HTTP_2_HEADERS_INTEGER_LOW_7_BITS) << Shift;
				Shift += 7U;
			}
			else {
				IntegerValue += static_cast<size_t>(BytesData) << Shift;
				break;
			}
		}

		return IntegerSize;
	}

	return 0;
}

//HTTP version 2 HPACK Header Compression header table decoding
/* Static Table Entries
          +-------+-----------------------------+---------------+
          | Index | Header Name                 | Header Value  |
          +-------+-----------------------------+---------------+
          | 1     | :authority                  |               |
          | 2     | :method                     | GET           |
          | 3     | :method                     | POST          |
          | 4     | :path                       | /             |
          | 5     | :path                       | /index.html   |
          | 6     | :scheme                     | http          |
          | 7     | :scheme                     | https         |
          | 8     | :status                     | 200           |
          | 9     | :status                     | 204           |
          | 10    | :status                     | 206           |
          | 11    | :status                     | 304           |
          | 12    | :status                     | 400           |
          | 13    | :status                     | 404           |
          | 14    | :status                     | 500           |
          | 15    | accept-charset              |               |
          | 16    | accept-encoding             | gzip, deflate |
          | 17    | accept-language             |               |
          | 18    | accept-ranges               |               |
          | 19    | accept                      |               |
          | 20    | access-control-allow-origin |               |
          | 21    | age                         |               |
          | 22    | allow                       |               |
          | 23    | authorization               |               |
          | 24    | cache-control               |               |
          | 25    | content-disposition         |               |
          | 26    | content-encoding            |               |
          | 27    | content-language            |               |
          | 28    | content-length              |               |
          | 29    | content-location            |               |
          | 30    | content-range               |               |
          | 31    | content-type                |               |
          | 32    | cookie                      |               |
          | 33    | date                        |               |
          | 34    | etag                        |               |
          | 35    | expect                      |               |
          | 36    | expires                     |               |
          | 37    | from                        |               |
          | 38    | host                        |               |
          | 39    | if-match                    |               |
          | 40    | if-modified-since           |               |
          | 41    | if-none-match               |               |
          | 42    | if-range                    |               |
          | 43    | if-unmodified-since         |               |
          | 44    | last-modified               |               |
          | 45    | link                        |               |
          | 46    | location                    |               |
          | 47    | max-forwards                |               |
          | 48    | proxy-authenticate          |               |
          | 49    | proxy-authorization         |               |
          | 50    | range                       |               |
          | 51    | referer                     |               |
          | 52    | refresh                     |               |
          | 53    | retry-after                 |               |
          | 54    | server                      |               |
          | 55    | set-cookie                  |               |
          | 56    | strict-transport-security   |               |
          | 57    | transfer-encoding           |               |
          | 58    | user-agent                  |               |
          | 59    | vary                        |               |
          | 60    | via                         |               |
          | 61    | www-authenticate            |               |
          +-------+-----------------------------+---------------+
*/
size_t HTTP_CONNECT_2_HeaderTableDecoding(
	std::vector<std::string> &HeaderList, 
	const uint8_t *Buffer, 
	const size_t Length, 
	const uint8_t PrefixSize)
{
//Integer and literal size check
	size_t IndexNumber = 0;
	const auto IntegerSize = HTTP_CONNECT_2_IntegerDecoding(const_cast<uint8_t *>(Buffer), Length, PrefixSize, IndexNumber);
	if (IntegerSize == 0 || IntegerSize > Length)
		return 0;

//Table index entries list
	switch (IndexNumber)
	{
	//Static table check
		case 1U:
		{
			HeaderList.push_back(":authority");
		}break;
		case 2U:
		{
			HeaderList.push_back(":method");
			HeaderList.push_back("GET");
		}break;
		case 3U:
		{
			HeaderList.push_back(":method");
			HeaderList.push_back("POST");
		}break;
		case 4U:
		{
			HeaderList.push_back(":path");
			HeaderList.push_back("/");
		}break;
		case 5U:
		{
			HeaderList.push_back(":path");
			HeaderList.push_back("/index.html");
		}break;
		case 6U:
		{
			HeaderList.push_back(":scheme");
			HeaderList.push_back("http");
		}break;
		case 7U:
		{
			HeaderList.push_back(":scheme");
			HeaderList.push_back("https");
		}break;
		case 8U:
		{
			HeaderList.push_back(":status");
			HeaderList.push_back("200");
		}break;
		case 9U:
		{
			HeaderList.push_back(":status");
			HeaderList.push_back("204");
		}break;
		case 10U:
		{
			HeaderList.push_back(":status");
			HeaderList.push_back("206");
		}break;
		case 11U:
		{
			HeaderList.push_back(":status");
			HeaderList.push_back("304");
		}break;
		case 12U:
		{
			HeaderList.push_back(":status");
			HeaderList.push_back("400");
		}break;
		case 13U:
		{
			HeaderList.push_back(":status");
			HeaderList.push_back("404");
		}break;
		case 14U:
		{
			HeaderList.push_back(":status");
			HeaderList.push_back("500");
		}break;
		case 15U:
		{
			HeaderList.push_back("accept-charset");
		}break;
		case 16U:
		{
			HeaderList.push_back("accept-encoding");
			HeaderList.push_back("gzip, deflate");
		}break;
		case 17U:
		{
			HeaderList.push_back("accept-language");
		}break;
		case 18U:
		{
			HeaderList.push_back("accept-ranges");
		}break;
		case 19U:
		{
			HeaderList.push_back("accept");
		}break;
		case 20U:
		{
			HeaderList.push_back("access-control-allow-origin");
		}break;
		case 21U:
		{
			HeaderList.push_back("age");
		}break;
		case 22U:
		{
			HeaderList.push_back("allow");
		}break;
		case 23U:
		{
			HeaderList.push_back("authorization");
		}break;
		case 24U:
		{
			HeaderList.push_back("cache-control");
		}break;
		case 25U:
		{
			HeaderList.push_back("content-disposition");
		}break;
		case 26U:
		{
			HeaderList.push_back("content-encoding");
		}break;
		case 27U:
		{
			HeaderList.push_back("content-language");
		}break;
		case 28U:
		{
			HeaderList.push_back("content-length");
		}break;
		case 29U:
		{
			HeaderList.push_back("content-location");
		}break;
		case 30U:
		{
			HeaderList.push_back("content-range");
		}break;
		case 31U:
		{
			HeaderList.push_back("content-type");
		}break;
		case 32U:
		{
			HeaderList.push_back("cookie");
		}break;
		case 33U:
		{
			HeaderList.push_back("date");
		}break;
		case 34U:
		{
			HeaderList.push_back("etag");
		}break;
		case 35U:
		{
			HeaderList.push_back("expect");
		}break;
		case 36U:
		{
			HeaderList.push_back("expires");
		}break;
		case 37U:
		{
			HeaderList.push_back("from");
		}break;
		case 38U:
		{
			HeaderList.push_back("host");
		}break;
		case 39U:
		{
			HeaderList.push_back("if-match");
		}break;
		case 40U:
		{
			HeaderList.push_back("if-modified-since");
		}break;
		case 41U:
		{
			HeaderList.push_back("if-none-match");
		}break;
		case 42U:
		{
			HeaderList.push_back("if-range");
		}break;
		case 43U:
		{
			HeaderList.push_back("if-unmodified-since");
		}break;
		case 44U:
		{
			HeaderList.push_back("last-modified");
		}break;
		case 45U:
		{
			HeaderList.push_back("link");
		}break;
		case 46U:
		{
			HeaderList.push_back("location");
		}break;
		case 47U:
		{
			HeaderList.push_back("max-forwards");
		}break;
		case 48U:
		{
			HeaderList.push_back("proxy-authenticate");
		}break;
		case 49U:
		{
			HeaderList.push_back("proxy-authorization");
		}break;
		case 50U:
		{
			HeaderList.push_back("range");
		}break;
		case 51U:
		{
			HeaderList.push_back("referer");
		}break;
		case 52U:
		{
			HeaderList.push_back("refresh");
		}break;
		case 53U:
		{
			HeaderList.push_back("retry-after");
		}break;
		case 54U:
		{
			HeaderList.push_back("server");
		}break;
		case 55U:
		{
			HeaderList.push_back("set-cookie");
		}break;
		case 56U:
		{
			HeaderList.push_back("strict-transport-security");
		}break;
		case 57U:
		{
			HeaderList.push_back("transfer-encoding");
		}break;
		case 58U:
		{
			HeaderList.push_back("user-agent");
		}break;
		case 59U:
		{
			HeaderList.push_back("vary");
		}break;
		case 60U:
		{
			HeaderList.push_back("via");
		}break;
		case 61U:
		{
			HeaderList.push_back("www-authenticate");
		}break;
	//Dynamic table is not supported.
		default:
		{
			return 0;
		}
	}

	return IntegerSize;
}

//HTTP version 2 HPACK Header Compression read bytes
bool HTTP_CONNECT_2_HEADERS_ReadBytes(
	std::vector<std::string> &HeaderList, 
	const uint8_t *Buffer, 
	const size_t Length)
{
	size_t IntegerSize = 0, LiteralSize = 0;
	uint8_t PrefixSize = 0;
	auto IsNamedField = false;
	for (size_t Index = 0;Index < Length;)
	{
	//String literal type check
		IsNamedField = !IsNamedField;
		if (IsNamedField)
		{
		//Indexed Header Field
			if (((*(Buffer + Index)) & HTTP_2_HEADERS_INTEGER_HIGH_1_BITS) != 0)
			{
				PrefixSize = HTTP_2_HEADERS_LITERAL_LOW_7_BITS;
				IntegerSize = HTTP_CONNECT_2_HeaderTableDecoding(HeaderList, Buffer + Index, Length - Index, PrefixSize);
				if (IntegerSize == 0)
				{
					return false;
				}
				else {
					Index += IntegerSize;
					IsNamedField = false;

					continue;
				}
			}
		//Literal Header Field with Incremental Indexing
			else if (((*(Buffer + Index)) & HTTP_2_HEADERS_LITERAL_HIGH_2_BITS) == HTTP_2_HEADERS_LITERAL_INCREMENTAL_INDEXED)
			{
				PrefixSize = HTTP_2_HEADERS_LITERAL_LOW_6_BITS;

			//Literal Header Field with Incremental Indexing -- Indexed Name
				if (((*(Buffer + Index)) & PrefixSize) != 0)
				{
					IntegerSize = HTTP_CONNECT_2_HeaderTableDecoding(HeaderList, Buffer + Index, Length - Index, PrefixSize);
					if (IntegerSize == 0)
					{
						return false;
					}
					else {
						Index += IntegerSize;
						IsNamedField = false;
					}
				}
			//Literal Header Field with Incremental Indexing -- New Name
				else {
					Index += sizeof(uint8_t);
				}
			}
		//Dynamic Table Size Update
			else if (((*(Buffer + Index)) & HTTP_2_HEADERS_LITERAL_HIGH_3_BITS) == HTTP_2_HEADERS_LITERAL_TABLE_SIZE_UPDATE)
			{
				if (((*(Buffer + Index)) & HTTP_2_HEADERS_LITERAL_LOW_5_BITS) != 0) //Dynamic table size must be set to 0.
				{
					return false;
				}
				else {
					Index += sizeof(uint8_t);
					IsNamedField = false;

					continue;
				}
			}
		//Literal Header Field without Indexing and Literal Header Field Never Indexed
			else if (((*(Buffer + Index)) & HTTP_2_HEADERS_LITERAL_HIGH_4_BITS) == HTTP_2_HEADERS_LITERAL_WITHOUT_INDEXED || 
				((*(Buffer + Index)) & HTTP_2_HEADERS_LITERAL_HIGH_4_BITS) == HTTP_2_HEADERS_LITERAL_NEVER_INDEXED)
			{
				PrefixSize = HTTP_2_HEADERS_LITERAL_LOW_4_BITS;

			//Literal Header Field without Indexing and Literal Header Field Never Indexed -- Indexed Name
				if (((*(Buffer + Index)) & PrefixSize) != 0)
				{
					IntegerSize = HTTP_CONNECT_2_HeaderTableDecoding(HeaderList, Buffer + Index, Length - Index, PrefixSize);
					if (IntegerSize == 0)
					{
						return false;
					}
					else {
						Index += IntegerSize;
						IsNamedField = false;
					}
				}
			//Literal Header Field without Indexing and Literal Header Field Never Indexed -- New Name
				else {
					Index += sizeof(uint8_t);
				}
			}
			else {
				return false;
			}
		}

	//Huffman coding
		if (*(Buffer + Index) > HTTP_2_HEADERS_INTEGER_LOW_7_BITS)
		{
		//Integer and literal size check
			IntegerSize = HTTP_CONNECT_2_IntegerDecoding(const_cast<uint8_t *>(Buffer + Index), Length - Index, HTTP_2_HEADERS_INTEGER_LOW_7_BITS, LiteralSize);
			if (IntegerSize == 0 || IntegerSize + Index > Length || LiteralSize + IntegerSize + Index > Length)
				return false;
			else 
				Index += IntegerSize;

		//Read huffman coding.
			std::unique_ptr<uint8_t[]> HeaderBuffer(nullptr);
			size_t HeaderBufferSize = 0, HeaderBufferLen = 0;
			for (;;)
			{
			//Buffer initializtion
				auto HuffmanBuffer = std::make_unique<uint8_t[]>(HeaderBufferSize + DEFAULT_LARGE_BUFFER_SIZE);
				memset(HuffmanBuffer.get(), 0, HeaderBufferSize + DEFAULT_LARGE_BUFFER_SIZE);
				std::swap(HeaderBuffer, HuffmanBuffer);
				HuffmanBuffer.reset();
				HeaderBufferSize += DEFAULT_LARGE_BUFFER_SIZE;

			//Huffman decoding
				const auto Result = HPACK_HuffmanDecoding(const_cast<uint8_t *>(Buffer + Index), LiteralSize, &HeaderBufferLen, HeaderBuffer.get(), HeaderBufferSize, nullptr);
				if (Result == HUFFMAN_RETURN_TYPE::NONE)
				{
					HeaderList.push_back(reinterpret_cast<char *>(HeaderBuffer.get()));
					Index += HeaderBufferLen;

					break;
				}
				else if (Result != HUFFMAN_RETURN_TYPE::ERROR_OVERFLOW)
				{
					return false;
				}
			}
		}
	//Normal string literal coding
		else {
		//Integer and literal size check
			IntegerSize = HTTP_CONNECT_2_IntegerDecoding(const_cast<uint8_t *>(Buffer + Index), Length - Index, PrefixSize, LiteralSize);
			if (IntegerSize == 0 || IntegerSize + Index > Length || LiteralSize + IntegerSize + Index > Length)
				return false;
			else 
				Index += IntegerSize;

		//Read Names and Values.
			const auto HeaderBuffer = std::make_unique<uint8_t[]>(LiteralSize + PADDING_RESERVED_BYTES);
			memset(HeaderBuffer.get(), 0, LiteralSize + PADDING_RESERVED_BYTES);
			memcpy_s(HeaderBuffer.get(), LiteralSize + PADDING_RESERVED_BYTES, Buffer + Index, LiteralSize);
			HeaderList.push_back(reinterpret_cast<char *>(HeaderBuffer.get()));
			Index += LiteralSize;
		}
	}

	return true;
}

//HTTP CONNECT response bytes check
bool HTTP_CONNECT_ResponseBytesCheck(
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	const bool IsPrintError)
{
	auto IsGotResponseResult = false;

//HTTP version 1.x response check
	if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_1)
	{
	//Length check
		if (strnlen_s(reinterpret_cast<const char *>(SocketSelectingDataList.front().RecvBuffer.get()), SocketSelectingDataList.front().RecvLen + PADDING_RESERVED_BYTES) > SocketSelectingDataList.front().RecvLen)
			goto PrintDataFormatError;

	//HTTP version 1.x response
		std::string HTTP_String(reinterpret_cast<const char *>(SocketSelectingDataList.front().RecvBuffer.get()));
		if (CheckConnectionStreamFin(REQUEST_PROCESS_TYPE::HTTP_CONNECT_1, reinterpret_cast<const uint8_t *>(HTTP_String.c_str()), HTTP_String.length()))
		{
			IsGotResponseResult = true;
		}
		else if (HTTP_String.compare(0, strlen("HTTP/"), ("HTTP/")) == 0 && 
			HTTP_String.find(ASCII_SPACE) != std::string::npos && HTTP_String.find("\r\n\r\n") != std::string::npos)
		{
			if (HTTP_String.find("\r\n") != std::string::npos)
				HTTP_String.erase(HTTP_String.find("\r\n"), HTTP_String.length() - HTTP_String.find("\r\n"));
			else 
				HTTP_String.erase(HTTP_String.find("\r\n\r\n"), HTTP_String.length() - HTTP_String.find("\r\n"));
			std::wstring Message;
			if (!MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(HTTP_String.c_str()), HTTP_String.length(), Message))
				PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);
			else 
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::HTTP_CONNECT, Message.c_str(), 0, nullptr, 0);

			return false;
		}
	}
//HTTP version 2 response check
	else if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
	{
	//HTTP version 1.x response and HTTP version 2 large length are not supported.
		if (*SocketSelectingDataList.front().RecvBuffer.get() > 0)
		{
		//Length check
			if (strnlen_s(reinterpret_cast<const char *>(SocketSelectingDataList.front().RecvBuffer.get()), SocketSelectingDataList.front().RecvLen + PADDING_RESERVED_BYTES) > SocketSelectingDataList.front().RecvLen)
				goto PrintDataFormatError;

		//HTTP version 1.x response
			std::string HTTP_String(reinterpret_cast<const char *>(SocketSelectingDataList.front().RecvBuffer.get()));
			if (HTTP_String.compare(0, strlen("HTTP/"), ("HTTP/")) == 0 && 
				HTTP_String.find(ASCII_SPACE) != std::string::npos && HTTP_String.find("\r\n\r\n") != std::string::npos)
			{
				if (HTTP_String.find("\r\n") != std::string::npos)
					HTTP_String.erase(HTTP_String.find("\r\n"), HTTP_String.length() - HTTP_String.find("\r\n"));
				else 
					HTTP_String.erase(HTTP_String.find("\r\n\r\n"), HTTP_String.length() - HTTP_String.find("\r\n"));
				std::wstring InnerMessage;
				if (!MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(HTTP_String.c_str()), HTTP_String.length(), InnerMessage))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);
				}
				else {
					std::wstring Message(L"HTTP version is not supported: ");
					Message.append(InnerMessage);
					PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::HTTP_CONNECT, Message.c_str(), 0, nullptr, 0);
				}

				return false;
			}
			else {
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP version is not supported", 0, nullptr, 0);
				return false;
			}
		}
		else if (SocketSelectingDataList.front().RecvLen < sizeof(http2_frame_hdr))
		{
			goto PrintDataFormatError;
		}

	//Initialization
		std::unique_ptr<uint8_t[]> HeaderBlockBuffer(nullptr);
		std::vector<std::string> HeaderList;
		size_t HeaderBlockSize = 0, HeaderBlockLength = 0;
		uint32_t HeaderIdentifier = 0;

	//HTTP version 2 response
		for (size_t Index = 0;Index < SocketSelectingDataList.front().RecvLen;)
		{
		//Frame check
			const auto FrameHeader = reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().RecvBuffer.get() + Index);
			if (Index + sizeof(http2_frame_hdr) + ntohs(FrameHeader->Length_Low) > SocketSelectingDataList.front().RecvLen || 
			//DATA frame is not support PADDED flag.
				(FrameHeader->Type == HTTP_2_FRAME_TYPE_DATA && 
				((FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_PADDED) != 0 || (FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_END_STREAM) != 0)) || 
			//HEADERS frame is not support PADDED or PRIORITY flag and END_STREAM flag check.
				(FrameHeader->Type == HTTP_2_FRAME_TYPE_HEADERS && 
				((FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_PADDED) != 0 || (FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_PRIORITY) != 0 || (FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_END_STREAM) != 0)) || 
			//PRIORITY frame is not supported.
				FrameHeader->Type == HTTP_2_FRAME_TYPE_PRIORITY || 
			//RST_STREAM frame is in the next step.
			//SETTINGS frame is in the next step.
			//PUSH_PROMISE frame is not supported.
				FrameHeader->Type == HTTP_2_FRAME_TYPE_PUSH_PROMISE
			//PING frame is in the next step.
			//GOAWAY frame is in the next step.
			//WINDOW_UPDATE frame is ignored.
			//CONTINUATION frame is in the next step.
				)
					goto PrintDataFormatError;
			else 
				Index += sizeof(http2_frame_hdr);

		//Frame process
			if (FrameHeader->Type == HTTP_2_FRAME_TYPE_DATA || FrameHeader->Type == HTTP_2_FRAME_TYPE_WINDOW_UPDATE) //DATA and WINDOW_UPDATE frame are ignored.
			{
				; //Do nothing.
			}
			else if (FrameHeader->Type == HTTP_2_FRAME_TYPE_HEADERS || FrameHeader->Type == HTTP_2_FRAME_TYPE_CONTINUATION) //HEADERS and CONTINUATION frame
			{
			//Header identifier check
				if (FrameHeader->Type == HTTP_2_FRAME_TYPE_HEADERS && HeaderIdentifier == 0)
					HeaderIdentifier = ntohl(FrameHeader->StreamIdentifier);
				else if (HeaderIdentifier != ntohl(FrameHeader->StreamIdentifier))
					goto PrintDataFormatError;

			//Header process
				if (FrameHeader->Length_Low > 0)
				{
				//Buffer initialization
					if (HeaderBlockSize <= HeaderBlockLength + ntohs(FrameHeader->Length_Low))
					{
						auto HeaderBuffer = std::make_unique<uint8_t[]>(HeaderBlockSize + ntohs(FrameHeader->Length_Low) + PADDING_RESERVED_BYTES);
						memset(HeaderBuffer.get(), 0, HeaderBlockSize + ntohs(FrameHeader->Length_Low) + PADDING_RESERVED_BYTES);
						if (HeaderBlockBuffer)
							memcpy_s(HeaderBuffer.get(), HeaderBlockSize + ntohs(FrameHeader->Length_Low) + PADDING_RESERVED_BYTES, HeaderBlockBuffer.get(), HeaderBlockLength);
						std::swap(HeaderBlockBuffer, HeaderBuffer);
						HeaderBlockSize += ntohs(FrameHeader->Length_Low) + PADDING_RESERVED_BYTES;
					}

				//Write to buffer.
					if (HeaderBlockBuffer)
					{
						memcpy_s(HeaderBlockBuffer.get() + HeaderBlockLength, HeaderBlockSize - HeaderBlockLength, reinterpret_cast<const uint8_t *>(FrameHeader) + sizeof(http2_frame_hdr), ntohs(FrameHeader->Length_Low));
						HeaderBlockLength += ntohs(FrameHeader->Length_Low);
					}
					else {
						goto PrintDataFormatError;
					}

				//Header whole packet
					if ((FrameHeader->Flags & HTTP_2_HEADERS_FLAGS_END_HEADERS) != 0)
					{
						if (HTTP_CONNECT_2_HEADERS_ReadBytes(HeaderList, HeaderBlockBuffer.get(), HeaderBlockLength) && !HeaderList.empty())
						{
							auto IsStatusField = false;
							for (const auto &StringIter:HeaderList)
							{
							//Fixed header :status field
								if (StringIter == (":status"))
								{
									IsStatusField = true;
								}
								else if (IsStatusField)
								{
								//Status code 200
									if (StringIter == ("200"))
									{
										IsGotResponseResult = true;
										break;
									}
								//Other status code
									else {
										std::wstring InnerMessage;
										if (!MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(StringIter.c_str()), StringIter.length(), InnerMessage))
										{
											PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);
										}
										else {
											std::wstring Message(L"HTTP CONNECT server response error: ");
											Message.append(InnerMessage);
											PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::HTTP_CONNECT, Message.c_str(), 0, nullptr, 0);
										}
									}

									return false;
								}
							}
						}

					//Get HTTP response status code 200.
						if (!IsGotResponseResult)
							goto PrintDataFormatError;
					}
				}
			}
			else if (FrameHeader->Type == HTTP_2_FRAME_TYPE_RST_STREAM && Index + sizeof(http2_rst_stream_frame) <= SocketSelectingDataList.front().RecvLen) //RST_STREAM frame
			{
				std::wstring Message(L"HTTP CONNECT server response error");
				HTTP_CONNECT_2_PrintLog(ntohl(reinterpret_cast<http2_rst_stream_frame *>(SocketSelectingDataList.front().RecvBuffer.get() + Index)->ErrorCode), Message);
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::HTTP_CONNECT, Message.c_str(), 0, nullptr, 0);

				return false;
			}
			else if (FrameHeader->Type == HTTP_2_FRAME_TYPE_SETTINGS && Index + sizeof(http2_settings_frame) <= SocketSelectingDataList.front().RecvLen) //SETTINGS frame
			{
				if ((FrameHeader->Flags & HTTP_2_SETTINGS_FLAGS_ACK) == 0) //Server SETTINGS frame with ACK flag is ignored.
				{
				//Buffer initialization
					if (SocketSelectingDataList.front().SendSize <= SocketSelectingDataList.front().SendLen + DEFAULT_LARGE_BUFFER_SIZE)
					{
						auto SendBuffer = std::make_unique<uint8_t[]>(SocketSelectingDataList.front().SendSize + DEFAULT_LARGE_BUFFER_SIZE);
						memset(SendBuffer.get(), 0, SocketSelectingDataList.front().SendSize + DEFAULT_LARGE_BUFFER_SIZE);
						memcpy_s(SendBuffer.get(), SocketSelectingDataList.front().SendSize + DEFAULT_LARGE_BUFFER_SIZE, SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendLen);
						std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
						SocketSelectingDataList.front().SendSize += DEFAULT_LARGE_BUFFER_SIZE;
					}

				//SETTINGS frame response
					memcpy_s(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen, SocketSelectingDataList.front().SendSize - SocketSelectingDataList.front().SendLen, FrameHeader, sizeof(http2_frame_hdr));
					reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)->Length_Low = 0;
					reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)->Flags = HTTP_2_SETTINGS_FLAGS_ACK;
					SocketSelectingDataList.front().SendLen += sizeof(http2_frame_hdr);
				}
			}
			else if (FrameHeader->Type == HTTP_2_FRAME_TYPE_PING && Index + sizeof(http2_ping_frame) <= SocketSelectingDataList.front().RecvLen) //PING frame
			{
				if ((FrameHeader->Flags & HTTP_2_PING_FLAGS_ACK) == 0) //Server PING frame with ACK flag is ignored.
				{
				//Buffer initialization
					if (SocketSelectingDataList.front().SendSize <= SocketSelectingDataList.front().SendLen + DEFAULT_LARGE_BUFFER_SIZE)
					{
						auto SendBuffer = std::make_unique<uint8_t[]>(SocketSelectingDataList.front().SendSize + DEFAULT_LARGE_BUFFER_SIZE);
						memset(SendBuffer.get(), 0, SocketSelectingDataList.front().SendSize + DEFAULT_LARGE_BUFFER_SIZE);
						memcpy_s(SendBuffer.get(), SocketSelectingDataList.front().SendSize + DEFAULT_LARGE_BUFFER_SIZE, SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendLen);
						std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
						SocketSelectingDataList.front().SendSize += DEFAULT_LARGE_BUFFER_SIZE;
					}

				//PING frame response
					memcpy_s(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen, SocketSelectingDataList.front().SendSize - SocketSelectingDataList.front().SendLen, FrameHeader, sizeof(http2_frame_hdr) + sizeof(http2_ping_frame));
					reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)->Flags = HTTP_2_PING_FLAGS_ACK;
					SocketSelectingDataList.front().SendLen += sizeof(http2_frame_hdr) + sizeof(http2_ping_frame);
				}
			}
			else if (FrameHeader->Type == HTTP_2_FRAME_TYPE_GOAWAY && Index + sizeof(http2_goaway_frame) <= SocketSelectingDataList.front().RecvLen) //GOAWAY frame
			{
				std::wstring Message(L"HTTP CONNECT server response error");
				HTTP_CONNECT_2_PrintLog(ntohl(reinterpret_cast<http2_goaway_frame *>(SocketSelectingDataList.front().RecvBuffer.get() + Index)->ErrorCode), Message);
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::HTTP_CONNECT, Message.c_str(), 0, nullptr, 0);

				return false;
			}
			else { //Other unknown frame
				goto PrintDataFormatError;
			}

		//Length check
			if (Index + ntohs(FrameHeader->Length_Low) == SocketSelectingDataList.front().RecvLen)
				break;
			else 
				Index += ntohs(FrameHeader->Length_Low);
		}
	}

//Get HTTP response status code 200.
	if (IsGotResponseResult)
		return true;

//Jump here to print server response error.
PrintDataFormatError:
	if (IsPrintError)
		PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::HTTP_CONNECT, L"HTTP CONNECT server response error", 0, nullptr, 0);

	return false;
}

//HTTP CONNECT shutdown HTTP version 2 connection
bool HTTP_CONNECT_2_ShutdownConnection(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<ssize_t> &ErrorCodeList, 
	const size_t Type, 
	const size_t ErrorCode, 
	void *TLS_Context)
{
//Socket data check
	if (SocketDataList.empty() || ErrorCodeList.empty() || !SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
		return false;

//Initializtion
	std::vector<SOCKET_SELECTING_SERIAL_DATA> SocketSelectingDataList(1U);
	if (Type == HTTP_2_FRAME_TYPE_RST_STREAM) //RST_STREAM frame
	{
	//Buffer initializtion
		auto SendBuffer = std::make_unique<uint8_t[]>(sizeof(http2_frame_hdr) + sizeof(http2_rst_stream_frame));
		memset(SendBuffer.get(), 0, sizeof(http2_frame_hdr) + sizeof(http2_rst_stream_frame));
		std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
		SocketSelectingDataList.front().SendSize = sizeof(http2_frame_hdr) + sizeof(http2_rst_stream_frame);

	//RST_STREAM frames MUST be associated with a stream.
	//If a RST_STREAM frame is received with a stream identifier of 0x0, the recipient MUST treat this as a connection error of type PROTOCOL_ERROR.
		reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get())->Length_Low = htons(sizeof(http2_rst_stream_frame));
		reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get())->Type = HTTP_2_FRAME_TYPE_RST_STREAM;
		reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get())->StreamIdentifier = htonl(HTTP_2_FRAME_INIT_STREAM_ID);
		SocketSelectingDataList.front().SendLen = sizeof(http2_frame_hdr);
		reinterpret_cast<http2_rst_stream_frame *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)->ErrorCode = htonl(static_cast<uint32_t>(ErrorCode));
		SocketSelectingDataList.front().SendLen += sizeof(http2_rst_stream_frame);
	}
	else if (Type == HTTP_2_FRAME_TYPE_GOAWAY) //GOAWAY frame
	{
	//Buffer initializtion
		auto SendBuffer = std::make_unique<uint8_t[]>(sizeof(http2_frame_hdr) + sizeof(http2_goaway_frame));
		memset(SendBuffer.get(), 0, sizeof(http2_frame_hdr) + sizeof(http2_goaway_frame));
		std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
		SocketSelectingDataList.front().SendSize = sizeof(http2_frame_hdr) + sizeof(http2_goaway_frame);

	//GOAWAY frame
		reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get())->Length_Low = htons(sizeof(http2_goaway_frame));
		reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get())->Type = HTTP_2_FRAME_TYPE_GOAWAY;
		SocketSelectingDataList.front().SendLen = sizeof(http2_frame_hdr);
		reinterpret_cast<http2_goaway_frame *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)->ErrorCode = htonl(static_cast<uint32_t>(ErrorCode));
		SocketSelectingDataList.front().SendLen += sizeof(http2_goaway_frame);
	}
	else {
		return false;
	}

//Request exchange
	if (TLS_Context != nullptr)
	{
	#if defined(ENABLE_TLS)
	#if defined(PLATFORM_WIN)
		if (!TLS_TransportSerial(REQUEST_PROCESS_TYPE::HTTP_CONNECT_SHUTDOWN, 0, *static_cast<SSPI_HANDLE_TABLE *>(TLS_Context), SocketDataList, SocketSelectingDataList, ErrorCodeList))
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (!TLS_TransportSerial(REQUEST_PROCESS_TYPE::HTTP_CONNECT_SHUTDOWN, 0, *static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context), SocketSelectingDataList))
	#endif
			return false;
	#endif
	}
	else {
		SocketSelectingDataList.front().RecvBuffer.reset();
		SocketSelectingDataList.front().RecvSize = 0;
		SocketSelectingDataList.front().RecvLen = 0;
		const auto RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TYPE::HTTP_CONNECT_SHUTDOWN, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
		if (RecvLen == EXIT_FAILURE)
			return false;
	}

	return true;
}

//Transmission and reception of HTTP CONNECT protocol
size_t HTTP_CONNECT_Request(
	const uint8_t * const OriginalSend, 
	const size_t SendSize, 
	std::unique_ptr<uint8_t[]> &OriginalRecv, 
	size_t &RecvSize, 
	const SOCKET_DATA &LocalSocketData)
{
//HTTP CONNECT target domain check
	if (Parameter.HTTP_CONNECT_TargetDomain == nullptr)
		return EXIT_FAILURE;

//Initialization
	std::vector<SOCKET_DATA> SocketDataList(1U);
	std::vector<SOCKET_SELECTING_SERIAL_DATA> SocketSelectingDataList(1U);
	std::vector<ssize_t> ErrorCodeList(1U);
	memset(&SocketDataList.front(), 0, sizeof(SocketDataList.front()));
	SocketDataList.front().Socket = INVALID_SOCKET;
	ErrorCodeList.front() = 0;
	size_t RecvLen = 0;

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

//HTTP version 1.x packet
	if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_1)
	{
	//Buffer initialization
		if (SocketSelectingDataList.front().SendSize <= SendSize + sizeof(uint16_t))
		{
			auto SendBuffer = std::make_unique<uint8_t[]>(SendSize + sizeof(uint16_t) + PADDING_RESERVED_BYTES);
			memset(SendBuffer.get(), 0, SendSize + sizeof(uint16_t) + PADDING_RESERVED_BYTES);
			memcpy_s(SendBuffer.get(), SendSize + sizeof(uint16_t), OriginalSend, SendSize);
			std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
			SocketSelectingDataList.front().SendSize = SendSize + sizeof(uint16_t);
		}

	//Write request to buffer.
		RecvLen = AddLengthDataToHeader(SocketSelectingDataList.front().SendBuffer.get(), SendSize, SocketSelectingDataList.front().SendSize);
	}
//HTTP version 2 packet
	else if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
	{
	//Buffer initialization
		if (SocketSelectingDataList.front().SendSize <= SocketSelectingDataList.front().SendLen + sizeof(http2_frame_hdr) + sizeof(uint16_t) + SendSize)
		{
			auto SendBuffer = std::make_unique<uint8_t[]>(SocketSelectingDataList.front().SendLen + sizeof(http2_frame_hdr) + sizeof(uint16_t) + SendSize + PADDING_RESERVED_BYTES);
			memset(SendBuffer.get(), 0, SocketSelectingDataList.front().SendLen + sizeof(http2_frame_hdr) + sizeof(uint16_t) + SendSize + PADDING_RESERVED_BYTES);
			memcpy_s(SendBuffer.get(), SocketSelectingDataList.front().SendLen + sizeof(http2_frame_hdr) + sizeof(uint16_t) + SendSize, SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendLen);
			std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
			SocketSelectingDataList.front().SendSize = SocketSelectingDataList.front().SendLen + sizeof(http2_frame_hdr) + sizeof(uint16_t) + SendSize;
		}

	//DATA frame
		reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)->Length_Low = htons(static_cast<uint16_t>(SendSize + sizeof(uint16_t)));
		reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)->Type = HTTP_2_FRAME_TYPE_DATA;
		reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)->Flags = HTTP_2_DATA_FLAGS_END_STREAM;
		reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen)->StreamIdentifier = htonl(HTTP_2_FRAME_INIT_STREAM_ID);
		SocketSelectingDataList.front().SendLen += sizeof(http2_frame_hdr);

	//Write request to buffer.
		memcpy_s(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen, SocketSelectingDataList.front().SendSize - SocketSelectingDataList.front().SendLen, OriginalSend, SendSize);
		RecvLen = AddLengthDataToHeader(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen, SendSize, SocketSelectingDataList.front().SendSize - SocketSelectingDataList.front().SendLen);
	}
	else {
		return EXIT_FAILURE;
	}

//Add length of request packet.
	if (RecvLen < DNS_PACKET_MINSIZE)
	{
	//HTTP version 2 shutdown connection.
		if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
			HTTP_CONNECT_2_ShutdownConnection(SocketDataList, ErrorCodeList, HTTP_2_FRAME_TYPE_RST_STREAM, HTTP_2_ERROR_INTERNAL_ERROR, TLS_Context);

	//TLS shutdown connection.
	#if defined(ENABLE_TLS)
		if (TLS_Context != nullptr)
	#if defined(PLATFORM_WIN)
			SSPI_ShutdownConnection(*static_cast<SSPI_HANDLE_TABLE *>(TLS_Context), SocketDataList, ErrorCodeList);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			OpenSSL_ShutdownConnection(*static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context));
		else 
	#endif
	#endif
	//Normal shutdown connection.
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}
	else {
		SocketSelectingDataList.front().SendLen += RecvLen;
	}

//HTTP CONNECT exchange
	RecvLen = HTTP_CONNECT_Transport(SocketDataList, SocketSelectingDataList, ErrorCodeList, TLS_Context);
	if (RecvLen >= DNS_PACKET_MINSIZE)
	{
	//Mark DNS cache.
		if (Parameter.DNS_CacheType != DNS_CACHE_TYPE::NONE)
			MarkDomainCache(SocketSelectingDataList.front().RecvBuffer.get(), RecvLen, &LocalSocketData);

	//Swap buffer.
		std::swap(OriginalRecv, SocketSelectingDataList.front().RecvBuffer);
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
//Socket data check
	if (SocketDataList.empty() || SocketSelectingDataList.empty() || ErrorCodeList.empty())
		return false;

//Socket initialization
	if (Parameter.HTTP_CONNECT_Address_IPv6.Storage.ss_family != 0 && //IPv6
		((Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv6) || //Auto select
		Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_NETWORK::IPV6 || //IPv6
		(Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_NETWORK::IPV4 && Parameter.HTTP_CONNECT_Address_IPv4.Storage.ss_family == 0))) //Non-IPv4
	{
	#if defined(ENABLE_TLS)
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (TLS_Context != nullptr)
		{
			if (Parameter.HTTP_CONNECT_TLS_AddressString_IPv6 != nullptr && !Parameter.HTTP_CONNECT_TLS_AddressString_IPv6->empty())
			{
				static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context)->Protocol_Network = AF_INET6;
				static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context)->Protocol_Transport = IPPROTO_TCP;
				static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context)->AddressString = *Parameter.HTTP_CONNECT_TLS_AddressString_IPv6;
			}
			else {
				return false;
			}
		}
		else {
	#endif
	#endif
			SocketDataList.front().SockAddr.ss_family = AF_INET6;
			reinterpret_cast<sockaddr_in6 *>(&SocketDataList.front().SockAddr)->sin6_addr = Parameter.HTTP_CONNECT_Address_IPv6.IPv6.sin6_addr;
			reinterpret_cast<sockaddr_in6 *>(&SocketDataList.front().SockAddr)->sin6_port = Parameter.HTTP_CONNECT_Address_IPv6.IPv6.sin6_port;
			SocketDataList.front().AddrLen = sizeof(sockaddr_in6);
			SocketDataList.front().Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	#if defined(ENABLE_TLS)
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		}
	#endif
	#endif
	}
	else if (Parameter.HTTP_CONNECT_Address_IPv4.Storage.ss_family != 0 && //IPv4
		((Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_NETWORK::BOTH && GlobalRunningStatus.GatewayAvailable_IPv4) || //Auto select
		Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_NETWORK::IPV4 || //IPv4
		(Parameter.HTTP_CONNECT_Protocol == REQUEST_MODE_NETWORK::IPV6 && Parameter.HTTP_CONNECT_Address_IPv6.Storage.ss_family == 0))) //Non-IPv6
	{
	#if defined(ENABLE_TLS)
	#if (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (TLS_Context != nullptr)
		{
			if (Parameter.HTTP_CONNECT_TLS_AddressString_IPv4 != nullptr && !Parameter.HTTP_CONNECT_TLS_AddressString_IPv4->empty())
			{
				static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context)->Protocol_Network = AF_INET;
				static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context)->Protocol_Transport = IPPROTO_TCP;
				static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context)->AddressString = *Parameter.HTTP_CONNECT_TLS_AddressString_IPv4;
			}
			else {
				return false;
			}
		}
		else {
	#endif
	#endif
			SocketDataList.front().SockAddr.ss_family = AF_INET;
			reinterpret_cast<sockaddr_in *>(&SocketDataList.front().SockAddr)->sin_addr = Parameter.HTTP_CONNECT_Address_IPv4.IPv4.sin_addr;
			reinterpret_cast<sockaddr_in *>(&SocketDataList.front().SockAddr)->sin_port = Parameter.HTTP_CONNECT_Address_IPv4.IPv4.sin_port;
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
		if (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::INVALID_CHECK, false, nullptr))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::NETWORK, L"HTTP CONNECT socket initialization error", 0, nullptr, 0);
			return false;
		}

	//Socket attribute settings
		if (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::TCP_FAST_OPEN, true, nullptr) || 
			(SocketDataList.front().SockAddr.ss_family == AF_INET6 && !SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV6, true, nullptr)) || 
			(SocketDataList.front().SockAddr.ss_family == AF_INET && (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::HOP_LIMITS_IPV4, true, nullptr)))) // || 
//			!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::DO_NOT_FRAGMENT, true, nullptr))))
		{
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			return false;
		}

	//Socket attribute setting(Non-blocking mode)
		if (!SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::NON_BLOCKING_MODE, true, nullptr))
		{
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
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
		if (!SSPI_SChannelInitializtion(*static_cast<SSPI_HANDLE_TABLE *>(TLS_Context)))
		{
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
			return false;
		}
		else if (!SSPI_Handshake(*static_cast<SSPI_HANDLE_TABLE *>(TLS_Context), SocketDataList, SocketSelectingDataList, ErrorCodeList))
		{
			SSPI_ShutdownConnection(*static_cast<SSPI_HANDLE_TABLE *>(TLS_Context), SocketDataList, ErrorCodeList);
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

			return false;
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (!OpenSSL_CTX_Initializtion(*static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context)) || 
			!OpenSSL_BIO_Initializtion(*static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context)))
		{
			return false;
		}
		else if (!OpenSSL_Handshake(*static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context)))
		{
			OpenSSL_ShutdownConnection(*static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context));
			return false;
		}
	#endif
	}
#endif

//HTTP CONNECT exchange
	if (!HTTP_CONNECT_Exchange(SocketDataList, SocketSelectingDataList, ErrorCodeList, TLS_Context))
	{
	//HTTP version 2 shutdown connection.
		if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
			HTTP_CONNECT_2_ShutdownConnection(SocketDataList, ErrorCodeList, HTTP_2_FRAME_TYPE_RST_STREAM, HTTP_2_ERROR_INTERNAL_ERROR, TLS_Context);

	//TLS shutdown connection.
	#if defined(ENABLE_TLS)
		if (TLS_Context != nullptr)
	#if defined(PLATFORM_WIN)
			SSPI_ShutdownConnection(*static_cast<SSPI_HANDLE_TABLE *>(TLS_Context), SocketDataList, ErrorCodeList);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			OpenSSL_ShutdownConnection(*static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context));
		else 
	#endif
	#endif
	//Normal shutdown connection.
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

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
//Socket data check
	if (SocketDataList.empty() || SocketSelectingDataList.empty() || ErrorCodeList.empty())
		return false;

//HTTP CONNECT version 1.x packet
	if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_1)
	{
	//Fixed header CONNECT field
		std::string HTTP_String("CONNECT ");
		HTTP_String.append(*Parameter.HTTP_CONNECT_TargetDomain);
		HTTP_String.append(" HTTP/1.1\r\nHost: ");
		HTTP_String.append(*Parameter.HTTP_CONNECT_TargetDomain);
		HTTP_String.append("\r\n");

	//Extended header list field
		if (Parameter.HTTP_CONNECT_HeaderField != nullptr && !Parameter.HTTP_CONNECT_HeaderField->empty())
		{
			auto IsLiteralFlag = true;
			for (const auto &StringIter:*Parameter.HTTP_CONNECT_HeaderField)
			{
				HTTP_String.append(StringIter);
				if (IsLiteralFlag)
					HTTP_String.append(": ");
				else 
					HTTP_String.append("\r\n");
				IsLiteralFlag = !IsLiteralFlag;
			}
		}

	//Extended header Proxy-Authorization field
		if (Parameter.HTTP_CONNECT_ProxyAuthorization != nullptr && !Parameter.HTTP_CONNECT_ProxyAuthorization->empty())
		{
			HTTP_String.append("Proxy-Authorization: ");
			HTTP_String.append(*Parameter.HTTP_CONNECT_ProxyAuthorization);
			HTTP_String.append("\r\n");
		}

	//End of header
		HTTP_String.append("\r\n");

	//Buffer initialization
		if (SocketSelectingDataList.front().SendSize <= HTTP_String.length())
		{
			auto SendBuffer = std::make_unique<uint8_t[]>(HTTP_String.length() + PADDING_RESERVED_BYTES);
			memset(SendBuffer.get(), 0, HTTP_String.length() + PADDING_RESERVED_BYTES);
			memcpy_s(SendBuffer.get(), HTTP_String.length(), HTTP_String.c_str(), HTTP_String.length());
			std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
			SocketSelectingDataList.front().SendSize = HTTP_String.length();
			SocketSelectingDataList.front().SendLen = HTTP_String.length();
		}
	}
//HTTP CONNECT version 2 packet
	else if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
	{
	//Buffer initialization
		if (SocketSelectingDataList.front().SendSize <= DEFAULT_LARGE_BUFFER_SIZE)
		{
			auto SendBuffer = std::make_unique<uint8_t[]>(SocketSelectingDataList.front().SendSize + DEFAULT_LARGE_BUFFER_SIZE);
			memset(SendBuffer.get(), 0, SocketSelectingDataList.front().SendSize + DEFAULT_LARGE_BUFFER_SIZE);
			std::swap(SocketSelectingDataList.front().SendBuffer, SendBuffer);
			SocketSelectingDataList.front().SendSize += DEFAULT_LARGE_BUFFER_SIZE;
			SocketSelectingDataList.front().SendLen = 0;
		}

	//Packet initialization(Magic header)
		memcpy_s(SocketSelectingDataList.front().SendBuffer.get(), SocketSelectingDataList.front().SendSize - SocketSelectingDataList.front().SendLen, HTTP_2_CONNECTION_CLIENT_PREFACE, strlen(HTTP_2_CONNECTION_CLIENT_PREFACE));
		SocketSelectingDataList.front().SendLen += strlen(HTTP_2_CONNECTION_CLIENT_PREFACE);

	//Packet initialization(SETTINGS frame)
		auto FrameHeader = reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen);
		FrameHeader->Type = HTTP_2_FRAME_TYPE_SETTINGS;
		SocketSelectingDataList.front().SendLen += sizeof(http2_frame_hdr);
		auto LengthInterval = SocketSelectingDataList.front().SendLen;
		HTTP_CONNECT_2_SETTINGS_WriteBytes(SocketSelectingDataList, HTTP_2_SETTINGS_TYPE_HEADERS_TABLE_SIZE, 0); //Set header table size to 0 to disable header frame dynamic table compression.
		HTTP_CONNECT_2_SETTINGS_WriteBytes(SocketSelectingDataList, HTTP_2_SETTINGS_TYPE_ENABLE_PUSH, 0); //Disable server push.
		HTTP_CONNECT_2_SETTINGS_WriteBytes(SocketSelectingDataList, HTTP_2_SETTINGS_TYPE_MAX_CONCURRENT_STREAMS, HTTP_2_SETTINGS_INIT_MAX_CONCURRENT_STREAMS); //Set max concurrent streams to 100(RFC 7540 recommoned).
		HTTP_CONNECT_2_SETTINGS_WriteBytes(SocketSelectingDataList, HTTP_2_SETTINGS_TYPE_INITIAL_WINDOW_SIZE, HTTP_2_SETTINGS_INIT_INITIAL_WINDOW_SIZE); //Set window size to 65535(RFC 7540 recommoned).
		if (LengthInterval >= SocketSelectingDataList.front().SendLen)
			return false;
		else 
			FrameHeader->Length_Low = htons(static_cast<uint16_t>(SocketSelectingDataList.front().SendLen - LengthInterval));

	//Packet initialization(HEADERS frame, part 1)
		FrameHeader = reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen);
		FrameHeader->Type = HTTP_2_FRAME_TYPE_HEADERS;
		FrameHeader->Flags = HTTP_2_HEADERS_FLAGS_END_HEADERS;
		FrameHeader->StreamIdentifier = htonl(HTTP_2_FRAME_INIT_STREAM_ID);
		SocketSelectingDataList.front().SendLen += sizeof(http2_frame_hdr);
		LengthInterval = SocketSelectingDataList.front().SendLen;

	//Header table size update(HEADERS frame)
		*(SocketSelectingDataList.front().SendBuffer.get() + SocketSelectingDataList.front().SendLen) = HTTP_2_HEADERS_LITERAL_TABLE_SIZE_UPDATE;
		SocketSelectingDataList.front().SendLen += sizeof(uint8_t);

	//Fixed header :method and :authority field(HEADERS frame)
		if (!HTTP_CONNECT_2_HEADERS_WriteBytes(SocketSelectingDataList, reinterpret_cast<const uint8_t *>(":method"), strlen(":method"), true) || 
			!HTTP_CONNECT_2_HEADERS_WriteBytes(SocketSelectingDataList, reinterpret_cast<const uint8_t *>("CONNECT"), strlen("CONNECT"), false) || 
			!HTTP_CONNECT_2_HEADERS_WriteBytes(SocketSelectingDataList, reinterpret_cast<const uint8_t *>(":authority"), strlen(":authority"), true) || 
			!HTTP_CONNECT_2_HEADERS_WriteBytes(SocketSelectingDataList, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(Parameter.HTTP_CONNECT_TargetDomain->c_str())), Parameter.HTTP_CONNECT_TargetDomain->length(), false))
				return false;

	//Extended header list field(HEADERS frame)
		if (Parameter.HTTP_CONNECT_HeaderField != nullptr && !Parameter.HTTP_CONNECT_HeaderField->empty())
		{
			auto IsLiteralFlag = true;
			for (const auto &StringIter:*Parameter.HTTP_CONNECT_HeaderField)
			{
				if (!HTTP_CONNECT_2_HEADERS_WriteBytes(SocketSelectingDataList, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(StringIter.c_str())), StringIter.length(), IsLiteralFlag))
					return false;
				else 
					IsLiteralFlag = !IsLiteralFlag;
			}
		}

	//Extended header proxy-authorization field(HEADERS frame)
		if (Parameter.HTTP_CONNECT_ProxyAuthorization != nullptr && !Parameter.HTTP_CONNECT_ProxyAuthorization->empty() && 
			(!HTTP_CONNECT_2_HEADERS_WriteBytes(SocketSelectingDataList, reinterpret_cast<const uint8_t *>("proxy-authorization"), strlen("proxy-authorization"), true) || 
			!HTTP_CONNECT_2_HEADERS_WriteBytes(SocketSelectingDataList, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(Parameter.HTTP_CONNECT_ProxyAuthorization->c_str())), Parameter.HTTP_CONNECT_ProxyAuthorization->length(), false)))
				return false;

	//Packet initialization(HEADERS frame, part 2)
		FrameHeader = reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().SendBuffer.get() + LengthInterval - sizeof(http2_frame_hdr));
		FrameHeader->Length_Low = htons(static_cast<uint16_t>(SocketSelectingDataList.front().SendLen - LengthInterval));
		if (ntohs(FrameHeader->Length_Low) >= HTTP_2_FREAM_MAXSIZE)
			return false;
	}
	else {
		return false;
	}

//TLS encryption process
	if (TLS_Context != nullptr)
	{
	#if defined(ENABLE_TLS)
		for (size_t Index = 0;Index < LOOP_MAX_LITTLE_TIMES;++Index)
		{
		#if defined(PLATFORM_WIN)
			if ((Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_1 && !TLS_TransportSerial(REQUEST_PROCESS_TYPE::HTTP_CONNECT_1, HTTP1_RESPONSE_MINSIZE, *static_cast<SSPI_HANDLE_TABLE *>(TLS_Context), SocketDataList, SocketSelectingDataList, ErrorCodeList)) || 
				(Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2 && !TLS_TransportSerial(REQUEST_PROCESS_TYPE::HTTP_CONNECT_2, sizeof(http2_frame_hdr), *static_cast<SSPI_HANDLE_TABLE *>(TLS_Context), SocketDataList, SocketSelectingDataList, ErrorCodeList)))
		#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			if ((Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_1 && !TLS_TransportSerial(REQUEST_PROCESS_TYPE::HTTP_CONNECT_1, HTTP1_RESPONSE_MINSIZE, *static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context), SocketSelectingDataList)) || 
				(Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2 && !TLS_TransportSerial(REQUEST_PROCESS_TYPE::HTTP_CONNECT_2, sizeof(http2_frame_hdr), *static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context), SocketSelectingDataList)))
		#endif
					return false;

		//Buffer initialization
			if (SocketSelectingDataList.front().RecvSize <= SocketSelectingDataList.front().RecvLen)
			{
				auto RecvBuffer = std::make_unique<uint8_t[]>(SocketSelectingDataList.front().RecvSize + PADDING_RESERVED_BYTES);
				memset(RecvBuffer.get(), 0, SocketSelectingDataList.front().RecvSize + PADDING_RESERVED_BYTES);
				SocketSelectingDataList.front().RecvSize += PADDING_RESERVED_BYTES;
				memcpy_s(RecvBuffer.get(), SocketSelectingDataList.front().RecvSize, SocketSelectingDataList.front().RecvBuffer.get(), SocketSelectingDataList.front().RecvLen);
				std::swap(SocketSelectingDataList.front().RecvBuffer, RecvBuffer);
			}

		//HTTP CONNECT response check
			if (HTTP_CONNECT_ResponseBytesCheck(SocketSelectingDataList, false))
				return true;
			else if (Index + 1U == LOOP_MAX_LITTLE_TIMES)
				return false;
		}
	#endif
	}
//Normal process
	else {
	//TCP connecting
		auto RecvLen = SocketConnecting(IPPROTO_TCP, SocketDataList.front().Socket, reinterpret_cast<sockaddr *>(&SocketDataList.front().SockAddr), SocketDataList.front().AddrLen, reinterpret_cast<const uint8_t *>(SocketSelectingDataList.front().SendBuffer.get()), SocketSelectingDataList.front().SendSize);
		if (RecvLen == EXIT_FAILURE)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"HTTP CONNECT connecting error", 0, nullptr, 0);
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
		if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_1)
			RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TYPE::HTTP_CONNECT_1, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		else if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
			RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TYPE::HTTP_CONNECT_2, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		else 
			return false;
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
		if (RecvLen == EXIT_FAILURE || 
			(Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_1 && SocketSelectingDataList.front().RecvLen < HTTP1_RESPONSE_MINSIZE) || 
			(Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2 && SocketSelectingDataList.front().RecvLen < sizeof(http2_frame_hdr)))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"HTTP CONNECT request error", ErrorCodeList.front(), nullptr, 0);
			return false;
		}
	}

//Buffer initialization
	if (SocketSelectingDataList.front().RecvSize <= SocketSelectingDataList.front().RecvLen)
	{
		auto RecvBuffer = std::make_unique<uint8_t[]>(SocketSelectingDataList.front().RecvSize + PADDING_RESERVED_BYTES);
		memset(RecvBuffer.get(), 0, SocketSelectingDataList.front().RecvSize + PADDING_RESERVED_BYTES);
		SocketSelectingDataList.front().RecvSize += PADDING_RESERVED_BYTES;
		memcpy_s(RecvBuffer.get(), SocketSelectingDataList.front().RecvSize, SocketSelectingDataList.front().RecvBuffer.get(), SocketSelectingDataList.front().RecvLen);
		std::swap(SocketSelectingDataList.front().RecvBuffer, RecvBuffer);
	}

//HTTP CONNECT response check
	return HTTP_CONNECT_ResponseBytesCheck(SocketSelectingDataList, true);
}

//Transmission and reception of HTTP CONNECT protocol
size_t HTTP_CONNECT_Transport(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList, 
	void *TLS_Context)
{
//Socket data check
	if (SocketDataList.empty())
	{
		return EXIT_FAILURE;
	}
	if (SocketSelectingDataList.empty() || ErrorCodeList.empty())
	{
	//HTTP version 2 shutdown connection.
		if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
			HTTP_CONNECT_2_ShutdownConnection(SocketDataList, ErrorCodeList, HTTP_2_FRAME_TYPE_RST_STREAM, HTTP_2_ERROR_INTERNAL_ERROR, TLS_Context);

	//TLS shutdown connection.
	#if defined(ENABLE_TLS)
		if (TLS_Context != nullptr)
	#if defined(PLATFORM_WIN)
			SSPI_ShutdownConnection(*static_cast<SSPI_HANDLE_TABLE *>(TLS_Context), SocketDataList, ErrorCodeList);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			OpenSSL_ShutdownConnection(*static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context));
		else 
	#endif
	#endif
	//Normal shutdown connection.
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

		return EXIT_FAILURE;
	}

//Request exchange
	size_t RecvLen = 0;
	if (TLS_Context != nullptr)
	{
	//Request type and packet minimum size initialization
		auto RequestType = REQUEST_PROCESS_TYPE::NONE;
		size_t PacketMinSize = DNS_PACKET_MINSIZE;
		if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_1)
		{
			RequestType = REQUEST_PROCESS_TYPE::TCP_NORMAL;
		}
		else if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
		{
			RequestType = REQUEST_PROCESS_TYPE::HTTP_CONNECT_2;
			PacketMinSize += sizeof(http2_frame_hdr);
		}
		else {
			return EXIT_FAILURE;
		}

	//TLS process
	#if defined(ENABLE_TLS)
	#if defined(PLATFORM_WIN)
		if (!TLS_TransportSerial(RequestType, PacketMinSize, *static_cast<SSPI_HANDLE_TABLE *>(TLS_Context), SocketDataList, SocketSelectingDataList, ErrorCodeList))
		{
		//HTTP version 2 shutdown connection.
			if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
				HTTP_CONNECT_2_ShutdownConnection(SocketDataList, ErrorCodeList, HTTP_2_FRAME_TYPE_RST_STREAM, HTTP_2_ERROR_INTERNAL_ERROR, TLS_Context);

		//TLS shutdown connection.
			SSPI_ShutdownConnection(*static_cast<SSPI_HANDLE_TABLE *>(TLS_Context), SocketDataList, ErrorCodeList);

		//Normal shutdown connection.
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

			return EXIT_FAILURE;
		}
		else {
		//HTTP version 2 shutdown connection.
			if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
				HTTP_CONNECT_2_ShutdownConnection(SocketDataList, ErrorCodeList, HTTP_2_FRAME_TYPE_GOAWAY, HTTP_2_ERROR_NO_ERROR, TLS_Context);

		//TLS shutdown connection.
			SSPI_ShutdownConnection(*static_cast<SSPI_HANDLE_TABLE *>(TLS_Context), SocketDataList, ErrorCodeList);

		//Normal shutdown connection.
			SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);
		}
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (!TLS_TransportSerial(RequestType, PacketMinSize, *static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context), SocketSelectingDataList))
		{
		//HTTP version 2 shutdown connection.
			if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
				HTTP_CONNECT_2_ShutdownConnection(SocketDataList, ErrorCodeList, HTTP_2_FRAME_TYPE_RST_STREAM, HTTP_2_ERROR_INTERNAL_ERROR, TLS_Context);

		//TLS shutdown connection.
			OpenSSL_ShutdownConnection(*static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context));

			return EXIT_FAILURE;
		}
		else {
		//HTTP version 2 shutdown connection.
			if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
				HTTP_CONNECT_2_ShutdownConnection(SocketDataList, ErrorCodeList, HTTP_2_FRAME_TYPE_GOAWAY, HTTP_2_ERROR_NO_ERROR, TLS_Context);

		//TLS shutdown connection.
			OpenSSL_ShutdownConnection(*static_cast<OPENSSL_CONTEXT_TABLE *>(TLS_Context));
		}
	#endif
	#endif
	}
	else {
	//Send process.
		SocketSelectingDataList.front().RecvBuffer.reset();
		SocketSelectingDataList.front().RecvSize = 0;
		SocketSelectingDataList.front().RecvLen = 0;
		if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
		{
			RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TYPE::HTTP_CONNECT_2, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);

		//HTTP version 2 shutdown connection.
			HTTP_CONNECT_2_ShutdownConnection(SocketDataList, ErrorCodeList, HTTP_2_FRAME_TYPE_GOAWAY, HTTP_2_ERROR_NO_ERROR, TLS_Context);
		}
		else if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_1)
		{
			RecvLen = SocketSelectingSerial(REQUEST_PROCESS_TYPE::TCP_NORMAL, IPPROTO_TCP, SocketDataList, SocketSelectingDataList, ErrorCodeList);
		}
		else {
			return EXIT_FAILURE;
		}

	//Normal shutdown connection.
		SocketSetting(SocketDataList.front().Socket, SOCKET_SETTING_TYPE::CLOSE, false, nullptr);

	//Receive process
		SocketSelectingDataList.front().SendBuffer.reset();
		SocketSelectingDataList.front().SendSize = 0;
		SocketSelectingDataList.front().SendLen = 0;
		if (RecvLen == EXIT_FAILURE || 
			(Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_1 && SocketSelectingDataList.front().RecvLen < DNS_PACKET_MINSIZE) || 
			(Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2 && SocketSelectingDataList.front().RecvLen < sizeof(http2_frame_hdr) + DNS_PACKET_MINSIZE))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"HTTP CONNECT request error", ErrorCodeList.front(), nullptr, 0);
			return EXIT_FAILURE;
		}
	}

//HTTP version 2 response check
	auto IsGotResponseResult = true;
	if (Parameter.HTTP_CONNECT_Version == HTTP_VERSION_SELECTION::VERSION_2)
	{
	//Initialization
		std::unique_ptr<uint8_t[]> DataBlockBuffer(nullptr);
		size_t DataBlockSize = 0, DataBlockLength = 0;
		uint32_t DataIdentifier = 0;
		IsGotResponseResult = false;

	//HTTP version 2 response
		for (size_t Index = 0;Index < SocketSelectingDataList.front().RecvLen;)
		{
		//Frame check
			const auto FrameHeader = reinterpret_cast<http2_frame_hdr *>(SocketSelectingDataList.front().RecvBuffer.get() + Index);
			if (Index + sizeof(http2_frame_hdr) + ntohs(FrameHeader->Length_Low) > SocketSelectingDataList.front().RecvLen)
			{
				PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"HTTP CONNECT response error", ErrorCodeList.front(), nullptr, 0);
				return EXIT_FAILURE;
			}

		//DATA frame
			if (FrameHeader->Type == HTTP_2_FRAME_TYPE_DATA)
			{
			//Data identifier check
				if (DataIdentifier == 0)
				{
					DataIdentifier = ntohl(FrameHeader->StreamIdentifier);
				}
				else if (DataIdentifier != ntohl(FrameHeader->StreamIdentifier))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"HTTP CONNECT response error", ErrorCodeList.front(), nullptr, 0);
					return EXIT_FAILURE;
				}

			//Data process
				if (FrameHeader->Length_Low > 0)
				{
				//Buffer initialization
					if (DataBlockSize <= DataBlockLength + ntohs(FrameHeader->Length_Low))
					{
						auto DataBuffer = std::make_unique<uint8_t[]>(DataBlockSize + ntohs(FrameHeader->Length_Low) + PADDING_RESERVED_BYTES);
						memset(DataBuffer.get(), 0, DataBlockSize + ntohs(FrameHeader->Length_Low) + PADDING_RESERVED_BYTES);
						if (DataBlockBuffer)
							memcpy_s(DataBuffer.get(), DataBlockSize + ntohs(FrameHeader->Length_Low) + PADDING_RESERVED_BYTES, DataBlockBuffer.get(), DataBlockLength);
						std::swap(DataBlockBuffer, DataBuffer);
						DataBlockSize += ntohs(FrameHeader->Length_Low) + PADDING_RESERVED_BYTES;
					}

				//Write to buffer.
					if (DataBlockBuffer)
					{
						memcpy_s(DataBlockBuffer.get() + DataBlockLength, DataBlockSize - DataBlockLength, reinterpret_cast<const uint8_t *>(FrameHeader) + sizeof(http2_frame_hdr), ntohs(FrameHeader->Length_Low));
						DataBlockLength += ntohs(FrameHeader->Length_Low);

					//Whole packet check
//						if ((FrameHeader->Flags & HTTP_2_DATA_FLAGS_END_STREAM) != 0) //It seems that proxy server is not set END_STREAM flag although transmission has been completed.
						if (DataBlockLength >= sizeof(uint16_t) && 
							ntohs(*reinterpret_cast<uint16_t *>(DataBlockBuffer.get())) >= DNS_PACKET_MINSIZE && 
							sizeof(uint16_t) + ntohs(*reinterpret_cast<uint16_t *>(DataBlockBuffer.get())) <= DataBlockLength)
						{
							if (DataBlockLength <= SocketSelectingDataList.front().RecvSize)
							{
								memset(SocketSelectingDataList.front().RecvBuffer.get(), 0, SocketSelectingDataList.front().RecvSize);
								memcpy_s(SocketSelectingDataList.front().RecvBuffer.get(), SocketSelectingDataList.front().RecvSize, DataBlockBuffer.get(), DataBlockLength);
								IsGotResponseResult = true;
							}

							break;
						}
					}
					else {
						PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::NETWORK, L"HTTP CONNECT response error", ErrorCodeList.front(), nullptr, 0);
						return EXIT_FAILURE;
					}
				}
			}

		//Length check
			if (Index + ntohs(FrameHeader->Length_Low) == SocketSelectingDataList.front().RecvLen)
				break;
			else 
				Index += ntohs(FrameHeader->Length_Low);
		}
	}

//HTTP CONNECT response check
	if (IsGotResponseResult && 
		SocketSelectingDataList.front().RecvLen >= DNS_PACKET_MINSIZE && ntohs((reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().RecvBuffer.get()))[0]) >= DNS_PACKET_MINSIZE && 
		SocketSelectingDataList.front().RecvLen >= sizeof(uint16_t) + ntohs((reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().RecvBuffer.get()))[0]))
	{
		RecvLen = ntohs((reinterpret_cast<uint16_t *>(SocketSelectingDataList.front().RecvBuffer.get()))[0]);
		memmove_s(SocketSelectingDataList.front().RecvBuffer.get(), SocketSelectingDataList.front().RecvSize, SocketSelectingDataList.front().RecvBuffer.get() + sizeof(uint16_t), RecvLen);
		memset(SocketSelectingDataList.front().RecvBuffer.get() + RecvLen, 0, SocketSelectingDataList.front().RecvSize - RecvLen);

	//Response check
		RecvLen = CheckResponseData(
			REQUEST_PROCESS_TYPE::HTTP_CONNECT_MAIN, 
			SocketSelectingDataList.front().RecvBuffer.get(), 
			RecvLen, 
			SocketSelectingDataList.front().RecvSize, 
			nullptr, 
			nullptr);
		if (RecvLen >= DNS_PACKET_MINSIZE)
			return RecvLen;
	}

	return EXIT_FAILURE;
}
