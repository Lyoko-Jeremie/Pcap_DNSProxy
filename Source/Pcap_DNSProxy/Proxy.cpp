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


#include "Proxy.h"

/* SOCKS Protocol version 4

* Client -> Server: TCP CONNECT command request
  *  1 bytes: SOCKS version
  *  1 bytes: Command code
  *  2 bytes: Remote port
  *  4 bytes: Remote IPv4 address
  * Variable: UserID
* Server -> Client: Server command response
  *  1 bytes: SOCKS version
  *  1 bytes: Status code
  *  2 bytes: Remote port(Ignored)
  *  4 bytes: Remote IPv4 address(Ignored)
* Client <-> Server: Data stream...

/* SOCKS Protocol version 4a

* Client -> Server(1): TCP CONNECT command request
  *  1 bytes: SOCKS version
  *  1 bytes: Command code
  *  2 bytes: Remote port
  *  4 bytes: Remote IPv4 address(Must set to 0.0.0.x and x != 0)
  * Variable: UserID
  * Variable: Remote domain
* Server -> Client(1): Server command response
  *  1 bytes: SOCKS version
  *  1 bytes: Status code
  *  2 bytes: Remote port(Ignored)
  *  4 bytes: Remote IPv4 address(Ignored)
* Client <-> Server: Data stream...

/* SOCKS Protocol version 5

Client authentication:
* Client -> Server(1): Client authentication request
  *  1 bytes: SOCKS version
  *  1 bytes: Number of authentication methods supported
  * Variable: Authentication methods
* Server -> Client(1): Server authentication choice
  *  1 bytes: SOCKS version
  *  1 bytes: Chosen authentication method
* Client -> Server(2): Username/password authentication request
  *  1 bytes: SOCKS Username/password authentication version
  *  1 bytes: Username length
  * Variable: Username
  *  1 bytes: Password length
  * Variable: Password
* Server -> Client(2): Server authentication response
  *  1 bytes: SOCKS Username/password authentication version
  *  1 bytes: Status code

TCP CONNECT mode:
* Client -> Server(1): TCP CONNECT command request
  *  1 bytes: SOCKS version
  *  1 bytes: Command code
  *  1 bytes: Reserved
  *  1 bytes: Address type
  * Variable: Remote address
  *  2 bytes: Remote port
* Server -> Client(1): Server command response
  *  1 bytes: SOCKS version
  *  1 bytes: Status code
  *  1 bytes: Reserved
  *  1 bytes: Address type
  * Variable: Remote address(Not necessary)
  *  2 bytes: Remote port(Not necessary)
* Client <-> Server: Data stream...

UDP ASSOCIATE mode:
* Client -> Server(1): UDP ASSOCIATE command request, with TCP
  *  1 bytes: SOCKS version
  *  1 bytes: Command code
  *  1 bytes: Reserved
  *  1 bytes: Address type
  * Variable: Local listening address(Not necessary)
  *  2 bytes: Local UDP listening port
* Server -> Client(1): Server command response, with TCP
  *  1 bytes: SOCKS version
  *  1 bytes: Status code
  *  1 bytes: Reserved
  *  1 bytes: Address type
  * Variable: Server listening address
  *  2 bytes: Server listening port
* Client -> Server(2): UDP datagram, with UDP
  *  2 bytes: Reserved
  *  1 bytes: Fragment number
  *  1 bytes: Address type
  * Variable: Remote address
  *  2 bytes: Remote port
  * Variable: UDP datagram...
* Server -> Client(2): UDP datagram, with UDP
  *  2 bytes: Reserved
  *  1 bytes: Fragment number
  *  1 bytes: Address type
  * Variable: Remote address
  *  2 bytes: Remote port
  * Variable: UDP datagram...
* Client <-> Server: UDP datagram...
* TCP connection between client and server must be kept alive until UDP transmission is finished.

/* HTTP CONNECT tunnel

* Client -> Server: HTTP CONNECT method request
  * CONNECT TargetDomain:Port HTTP/version\r\n
  * Host: TargetDomain:Port\r\n
  * Other HTTP headers...\r\n
  * Proxy-Authentication: Basic "Base64 of Username:Password"\r\n
  * \r\n
* Server -> Client: Server HTTP CONNECT response
  * HTTP/version 200 ...\r\n
  * Other HTTP headers...\r\n
  * \r\n
* Client <-> Server: Data stream...

*/

//Proxy non-blocking mode selecting
SSIZE_T __fastcall ProxySocketSelecting(
	_In_ SYSTEM_SOCKET Socket, 
	_In_ fd_set *ReadFDS, 
	_In_ fd_set *WriteFDS, 
	_In_ timeval *Timeout, 
	_In_opt_ const char *SendBuffer, 
	_In_ const size_t SendSize, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize, 
	_In_ const size_t MinLen, 
	_Out_opt_ SSIZE_T *ErrorCode)
{
//Initialization
	SSIZE_T RecvLen = 0, SelectResult = 0;
	memset(OriginalRecv, 0, RecvSize);
	if (ErrorCode != nullptr)
		*ErrorCode = 0;
	FD_ZERO(ReadFDS);
	FD_ZERO(WriteFDS);
	if (SendBuffer != nullptr)
		FD_SET(Socket, WriteFDS);

//Selecting process
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME_NO_DELAY);

	//Wait for system calling.
	#if defined(PLATFORM_WIN)
		SelectResult = select(0, ReadFDS, WriteFDS, nullptr, Timeout);
	#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
		SelectResult = select(Socket + 1U, ReadFDS, WriteFDS, nullptr, Timeout);
	#endif
		if (SelectResult > 0)
		{
		//Receive process
			if (FD_ISSET(Socket, ReadFDS))
			{
			//Receive from selecting.
				RecvLen = recv(Socket, OriginalRecv, (int)RecvSize, 0);

			//Connection closed or SOCKET_ERROR
				if (RecvLen < (SSIZE_T)MinLen)
					break;
				else 
					return RecvLen;
			}

		//Send process
			if (SendBuffer != nullptr && FD_ISSET(Socket, WriteFDS))
			{
				if (send(Socket, SendBuffer, (int)SendSize, 0) < 0)
				{
					break;
				}
				else {
					FD_ZERO(ReadFDS);
					FD_ZERO(WriteFDS);
					FD_SET(Socket, ReadFDS);

					continue;
				}
			}
		}
		else { //Timeout or SOCKET_ERROR
			if (ErrorCode != nullptr)
				*ErrorCode = WSAGetLastError();
			break;
		}
	}

	return EXIT_FAILURE;
}

//SOCKS selection exchange process
bool __fastcall SOCKSSelectionExchange(
	_In_ SOCKET_DATA *SOCKSSocketData, 
	_In_ fd_set *ReadFDS, 
	_In_ fd_set *WriteFDS, 
	_In_ timeval *Timeout, 
	_Inout_ char *SendBuffer, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize)
{
//Initialization
	size_t Length = 0;
	void *SOCKS_Pointer = SendBuffer;
	((psocks_client_selection)SOCKS_Pointer)->Version = SOCKS_VERSION_5;
	((psocks_client_selection)SOCKS_Pointer)->Methods_A = SOCKS_METHOD_NO_AUTHENTICATION_REQUIRED;
	if (Parameter.SOCKS_Username != nullptr && !Parameter.SOCKS_Username->empty() && 
		Parameter.SOCKS_Password != nullptr && !Parameter.SOCKS_Password->empty())
	{
		((psocks_client_selection)SOCKS_Pointer)->Methods_Number = SOCKS_METHOD_SUPPORT_NUM;
		((psocks_client_selection)SOCKS_Pointer)->Methods_B = SOCKS_METHOD_USERNAME_PASSWORD;
		Length = sizeof(socks_client_selection);
	}
	else {
		((psocks_client_selection)SOCKS_Pointer)->Methods_Number = SOCKS_METHOD_NO_AUTHENTICATION_NUM;
		Length = sizeof(socks_client_selection) - sizeof(uint8_t);
	}
	memset(OriginalRecv, 0, RecvSize);

//Socket timeout setting
#if defined(PLATFORM_WIN)
	Timeout->tv_sec = Parameter.SOCKS_SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
	Timeout->tv_usec = Parameter.SOCKS_SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Timeout->tv_sec = Parameter.SOCKS_SocketTimeout_Reliable.tv_sec;
	Timeout->tv_usec = Parameter.SOCKS_SocketTimeout_Reliable.tv_usec;
#endif

//TCP connecting
	SSIZE_T RecvLen = SocketConnecting(IPPROTO_TCP, SOCKSSocketData->Socket, (PSOCKADDR)&SOCKSSocketData->SockAddr, SOCKSSocketData->AddrLen, SendBuffer, Length);
	if (RecvLen == EXIT_FAILURE)
	{
		PrintError(LOG_ERROR_NETWORK, L"SOCKS connecting error", 0, nullptr, 0);
		return false;
	}
//Client selection exchange
	else if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		RecvLen = ProxySocketSelecting(SOCKSSocketData->Socket, ReadFDS, WriteFDS, Timeout, nullptr, 0, OriginalRecv, RecvSize, sizeof(socks_server_selection), nullptr);
	}
	else {
		RecvLen = ProxySocketSelecting(SOCKSSocketData->Socket, ReadFDS, WriteFDS, Timeout, SendBuffer, Length, OriginalRecv, RecvSize, sizeof(socks_server_selection), nullptr);
	}
	if (RecvLen < (SSIZE_T)sizeof(socks_server_selection))
	{
		PrintError(LOG_ERROR_NETWORK, L"SOCKS request error", 0, nullptr, 0);
		return false;
	}
	else {
		memset(SendBuffer, 0, LARGE_PACKET_MAXSIZE);
		Length = 0;
	}

//Server selection check
	SOCKS_Pointer = OriginalRecv;
	if (((psocks_server_selection)SOCKS_Pointer)->Version != SOCKS_VERSION_5)
	{
		PrintError(LOG_ERROR_SOCKS, L"Server SOCKS protocol version error", 0, nullptr, 0);
		return false;
	}

//Method check
	switch (((psocks_server_selection)SOCKS_Pointer)->Method)
	{
	//No authentication
		case SOCKS_METHOD_NO_AUTHENTICATION_REQUIRED:
		{
			break;
		}break;
	//Require username/password authentication
		case SOCKS_METHOD_USERNAME_PASSWORD:
		{
			if (Parameter.SOCKS_Username != nullptr && !Parameter.SOCKS_Username->empty() && 
				Parameter.SOCKS_Password != nullptr && !Parameter.SOCKS_Password->empty())
			{
				if (!SOCKSAuthenticationUsernamePassword(SOCKSSocketData->Socket, ReadFDS, WriteFDS, Timeout, SendBuffer, OriginalRecv, RecvSize))
				{
					PrintError(LOG_ERROR_SOCKS, L"Username or Password incorrect", 0, nullptr, 0);
					return false;
				}
				else {
					memset(SendBuffer, 0, LARGE_PACKET_MAXSIZE);
				}
			}
			else {
				PrintError(LOG_ERROR_SOCKS, L"Server require username and password authentication", 0, nullptr, 0);
				return false;
			}
		}break;
	//Not support or error
		default:
		{
			PrintError(LOG_ERROR_SOCKS, L"Authentication method not support", 0, nullptr, 0);
			return false;
		}
	}

	return true;
}

//SOCKS username/password authentication process
bool __fastcall SOCKSAuthenticationUsernamePassword(
	_In_ SYSTEM_SOCKET Socket, 
	_In_ fd_set *ReadFDS, 
	_In_ fd_set *WriteFDS, 
	_In_ timeval *Timeout, 
	_Inout_ char *SendBuffer, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize)
{
//Initialization
	size_t Length = sizeof(uint8_t) * 2U;
	memset(OriginalRecv, 0, RecvSize);

//Username/password authentication packet
	SendBuffer[0] = SOCKS_USERNAME_PASSWORD_VERSION;
	SendBuffer[1U] = (uint8_t)Parameter.SOCKS_Username->length();
	memcpy_s(SendBuffer + Length, LARGE_PACKET_MAXSIZE, Parameter.SOCKS_Username->c_str(), Parameter.SOCKS_Username->length());
	Length += Parameter.SOCKS_Username->length();
	SendBuffer[Length] = (uint8_t)Parameter.SOCKS_Password->length();
	Length += sizeof(uint8_t);
	memcpy_s(SendBuffer + Length, LARGE_PACKET_MAXSIZE - Length, Parameter.SOCKS_Password->c_str(), Parameter.SOCKS_Password->length());
	Length += Parameter.SOCKS_Password->length();

//Socket timeout setting
#if defined(PLATFORM_WIN)
	Timeout->tv_sec = Parameter.SOCKS_SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
	Timeout->tv_usec = Parameter.SOCKS_SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Timeout->tv_sec = Parameter.SOCKS_SocketTimeout_Reliable.tv_sec;
	Timeout->tv_usec = Parameter.SOCKS_SocketTimeout_Reliable.tv_usec;
#endif

//Username/password authentication exchange
	if (ProxySocketSelecting(Socket, ReadFDS, WriteFDS, Timeout, SendBuffer, Length, OriginalRecv, RecvSize, sizeof(socks_server_user_authentication), nullptr) < (SSIZE_T)sizeof(socks_server_user_authentication))
		return false;

//Server reply check
	if (((psocks_server_user_authentication)OriginalRecv)->Version != SOCKS_USERNAME_PASSWORD_VERSION || 
		((psocks_server_user_authentication)OriginalRecv)->Status != SOCKS_USERNAME_PASSWORD_SUCCESS)
			return false;

	return true;
}

//SOCKS client command request process
bool __fastcall SOCKSClientCommandRequest(
	_In_ const uint16_t Protocol, 
	_In_ SYSTEM_SOCKET Socket, 
	_In_ fd_set *ReadFDS, 
	_In_ fd_set *WriteFDS, 
	_In_ timeval *Timeout, 
	_Inout_ char *SendBuffer, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize, 
	_In_opt_ SOCKET_DATA *UDP_ASSOCIATE_TCP_Connecting_Address)
{
//Initialization
	size_t Length = 0;
	memset(OriginalRecv, 0, RecvSize);

//Client command request packet
	void *SOCKS_Pointer = SendBuffer;
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5) //SOCKS version 5
	{
		((psocks5_client_command_request)SOCKS_Pointer)->Version = SOCKS_VERSION_5;
		if (Protocol == IPPROTO_TCP) //TCP CONNECT
			((psocks5_client_command_request)SOCKS_Pointer)->Command = SOCKS_COMMAND_CONNECT;
		else //UDP ASSOCIATE
			((psocks5_client_command_request)SOCKS_Pointer)->Command = SOCKS_COMMAND_UDP_ASSOCIATE;
		Length = sizeof(socks5_client_command_request);

	//Write address.
		if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET6) //IPv6
		{
			((psocks5_client_command_request)SOCKS_Pointer)->Address_Type = SOCKS5_ADDRESS_IPV6;
			SOCKS_Pointer = SendBuffer + Length;
			if (Protocol == IPPROTO_TCP) //Empty address in UDP ASSOCIATE
				*(in6_addr *)SOCKS_Pointer = Parameter.SOCKS_TargetServer.IPv6.sin6_addr;
			Length += sizeof(in6_addr);
			SOCKS_Pointer = SendBuffer + Length;
			if (Protocol == IPPROTO_TCP) //TCP CONNECT
				*(uint16_t *)SOCKS_Pointer = Parameter.SOCKS_TargetServer.IPv6.sin6_port;
			else if (UDP_ASSOCIATE_TCP_Connecting_Address != nullptr) //UDP ASSOCIATE
				*(uint16_t *)SOCKS_Pointer = ((PSOCKADDR_IN6)&UDP_ASSOCIATE_TCP_Connecting_Address->SockAddr)->sin6_port;
			Length += sizeof(uint16_t);
		}
		else if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET || //IPv4
			Protocol == IPPROTO_UDP) //UDP ASSOCIATE
		{
			((psocks5_client_command_request)SOCKS_Pointer)->Address_Type = SOCKS5_ADDRESS_IPV4;
			SOCKS_Pointer = SendBuffer + Length;
			if (Protocol == IPPROTO_TCP) //Empty address in UDP ASSOCIATE
				*(in_addr *)SOCKS_Pointer = Parameter.SOCKS_TargetServer.IPv4.sin_addr;
			Length += sizeof(in_addr);
			SOCKS_Pointer = SendBuffer + Length;
			if (Protocol == IPPROTO_TCP) //TCP CONNECT
				*(uint16_t *)SOCKS_Pointer = Parameter.SOCKS_TargetServer.IPv4.sin_port;
			else if (UDP_ASSOCIATE_TCP_Connecting_Address != nullptr) //UDP ASSOCIATE
				*(uint16_t *)SOCKS_Pointer = ((PSOCKADDR_IN)&UDP_ASSOCIATE_TCP_Connecting_Address->SockAddr)->sin_port;
			Length += sizeof(uint16_t);
		}
		else if (Parameter.SOCKS_TargetDomain != nullptr && !Parameter.SOCKS_TargetDomain->empty()) //Domain
		{
			((psocks5_client_command_request)SOCKS_Pointer)->Address_Type = SOCKS5_ADDRESS_DOMAIN;
			SOCKS_Pointer = SendBuffer + Length;
			*(uint8_t *)SOCKS_Pointer = (uint8_t)Parameter.SOCKS_TargetDomain->length();
			Length += sizeof(uint8_t);
			memcpy_s(SendBuffer + Length, LARGE_PACKET_MAXSIZE - Length, Parameter.SOCKS_TargetDomain->c_str(), Parameter.SOCKS_TargetDomain->length());
			Length += Parameter.SOCKS_TargetDomain->length();
			SOCKS_Pointer = SendBuffer + Length;
			*(uint16_t *)SOCKS_Pointer = Parameter.SOCKS_TargetDomain_Port;
			Length += sizeof(uint16_t);
		}
		else {
			return false;
		}
	}
	else if (Parameter.SOCKS_Version == SOCKS_VERSION_4 || Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A) //SOCKS version 4 or 4a
	{
		((psocks4_client_command_request)SOCKS_Pointer)->Version = SOCKS_VERSION_4; //Same value in version byte(4/4a)
		((psocks4_client_command_request)SOCKS_Pointer)->Command = SOCKS_COMMAND_CONNECT;
		((psocks4_client_command_request)SOCKS_Pointer)->Remote_Port = Parameter.SOCKS_TargetServer.IPv4.sin_port;
		((psocks4_client_command_request)SOCKS_Pointer)->Remote_Address.s_addr = Parameter.SOCKS_TargetServer.IPv4.sin_addr.s_addr;
		Length = sizeof(socks4_client_command_request);

	//Write UserID.
		if (Parameter.SOCKS_Username != nullptr && !Parameter.SOCKS_Username->empty())
		{
			memcpy_s(SendBuffer + (Length - sizeof(uint8_t)), LARGE_PACKET_MAXSIZE - (Length - sizeof(uint8_t)), Parameter.SOCKS_Username->c_str(), Parameter.SOCKS_Username->length());
			Length += Parameter.SOCKS_Username->length();
		}

	//Write target domain.
		if (Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A && Parameter.SOCKS_TargetDomain != nullptr && !Parameter.SOCKS_TargetDomain->empty())
		{
			((psocks4_client_command_request)SOCKS_Pointer)->Remote_Port = Parameter.SOCKS_TargetDomain_Port;
			((psocks4_client_command_request)SOCKS_Pointer)->Remote_Address.s_addr = htonl(SOCKS4_ADDRESS_DOMAIN_ADDRESS);
			memcpy_s(SendBuffer + Length, LARGE_PACKET_MAXSIZE - Length, Parameter.SOCKS_TargetDomain->c_str(), Parameter.SOCKS_TargetDomain->length());
			Length += Parameter.SOCKS_TargetDomain->length() + sizeof(uint8_t);
		}
	}

//Socket timeout setting
#if defined(PLATFORM_WIN)
	Timeout->tv_sec = Parameter.SOCKS_SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
	Timeout->tv_usec = Parameter.SOCKS_SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Timeout->tv_sec = Parameter.SOCKS_SocketTimeout_Reliable.tv_sec;
	Timeout->tv_usec = Parameter.SOCKS_SocketTimeout_Reliable.tv_usec;
#endif

//Client command request exchange
	SSIZE_T RecvLen = 0;
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5) //SOCKS version 5
	{
		RecvLen = ProxySocketSelecting(Socket, ReadFDS, WriteFDS, Timeout, SendBuffer, Length, OriginalRecv, RecvSize, sizeof(socks5_server_command_reply), nullptr);
		if (RecvLen < (SSIZE_T)sizeof(socks5_server_command_reply))
		{
			PrintError(LOG_ERROR_NETWORK, L"SOCKS request error", 0, nullptr, 0);
			return false;
		}
	}
	else if ((Parameter.SOCKS_Version == SOCKS_VERSION_4 || Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A) && //SOCKS version 4 or 4a
		UDP_ASSOCIATE_TCP_Connecting_Address != nullptr)
	{
	//TCP connecting
		RecvLen = SocketConnecting(IPPROTO_TCP, Socket, (PSOCKADDR)&UDP_ASSOCIATE_TCP_Connecting_Address->SockAddr, UDP_ASSOCIATE_TCP_Connecting_Address->AddrLen, SendBuffer, Length);
		if (RecvLen == EXIT_FAILURE)
		{
			PrintError(LOG_ERROR_NETWORK, L"SOCKS connecting error", 0, nullptr, 0);
			return false;
		}
	//Client command request process
		else if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
		{
			RecvLen = ProxySocketSelecting(Socket, ReadFDS, WriteFDS, Timeout, nullptr, 0, OriginalRecv, RecvSize, sizeof(socks4_server_command_reply), nullptr);
		}
		else {
			RecvLen = ProxySocketSelecting(Socket, ReadFDS, WriteFDS, Timeout, SendBuffer, Length, OriginalRecv, RecvSize, sizeof(socks4_server_command_reply), nullptr);
		}
		if (RecvLen < (SSIZE_T)sizeof(socks4_server_command_reply))
		{
			PrintError(LOG_ERROR_NETWORK, L"SOCKS request error", 0, nullptr, 0);
			return false;
		}
	}
	else {
		return false;
	}

//Server command request check
	SOCKS_Pointer = OriginalRecv;
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5) //SOCKS version 5
	{
		if (((psocks5_server_command_reply)SOCKS_Pointer)->Version != SOCKS_VERSION_5 || ((psocks5_server_command_reply)SOCKS_Pointer)->Reserved != 0)
		{
			PrintError(LOG_ERROR_SOCKS, L"Server SOCKS protocol version error", 0, nullptr, 0);
			return false;
		}
		else if (((psocks5_server_command_reply)SOCKS_Pointer)->Reply != SOCKS5_REPLY_SUCCESS)
		{
			PrintError(LOG_ERROR_SOCKS, L"Client command request error", ((psocks5_server_command_reply)SOCKS_Pointer)->Reply, nullptr, 0);
			return false;
		}
		else if (Protocol == IPPROTO_UDP && UDP_ASSOCIATE_TCP_Connecting_Address != nullptr) //UDP ASSOCIATE
		{
		//IPv6
			if (((psocks5_server_command_reply)SOCKS_Pointer)->Bind_Address_Type == SOCKS5_ADDRESS_IPV6 && 
				RecvLen >= (SSIZE_T)(sizeof(socks5_server_command_reply) + sizeof(in6_addr) + sizeof(uint16_t)) && 
				UDP_ASSOCIATE_TCP_Connecting_Address->SockAddr.ss_family == AF_INET6)
			{
			//Address
				SOCKS_Pointer = OriginalRecv + sizeof(socks5_server_command_reply);
				((PSOCKADDR_IN6)&UDP_ASSOCIATE_TCP_Connecting_Address->SockAddr)->sin6_addr = *(in6_addr *)SOCKS_Pointer;

			//Port
				SOCKS_Pointer = OriginalRecv + sizeof(socks5_server_command_reply) + sizeof(in6_addr);
				((PSOCKADDR_IN6)&UDP_ASSOCIATE_TCP_Connecting_Address->SockAddr)->sin6_port = *(uint16_t *)SOCKS_Pointer;
			}
		//IPv4
			else if (((psocks5_server_command_reply)SOCKS_Pointer)->Bind_Address_Type == SOCKS5_ADDRESS_IPV4 && 
				RecvLen >= (SSIZE_T)(sizeof(socks5_server_command_reply) + sizeof(in_addr) + sizeof(uint16_t)) && 
				UDP_ASSOCIATE_TCP_Connecting_Address->SockAddr.ss_family == AF_INET)
			{
			//Address
				SOCKS_Pointer = OriginalRecv + sizeof(socks5_server_command_reply);
				((PSOCKADDR_IN)&UDP_ASSOCIATE_TCP_Connecting_Address->SockAddr)->sin_addr = *(in_addr *)SOCKS_Pointer;

			//Port
				SOCKS_Pointer = OriginalRecv + sizeof(socks5_server_command_reply) + sizeof(in_addr);
				((PSOCKADDR_IN)&UDP_ASSOCIATE_TCP_Connecting_Address->SockAddr)->sin_port = *(uint16_t *)SOCKS_Pointer;
			}
			else {
				PrintError(LOG_ERROR_SOCKS, L"Client command request error", 0, nullptr, 0);
				return false;
			}
		}
	}
	else if (Parameter.SOCKS_Version == SOCKS_VERSION_4 || Parameter.SOCKS_Version == SOCKS_VERSION_CONFIG_4A) //SOCKS version 4 or 4a
	{
		if (((psocks4_server_command_reply)SOCKS_Pointer)->Version != SOCKS_VERSION_4)
		{
			PrintError(LOG_ERROR_SOCKS, L"Server SOCKS protocol version error", 0, nullptr, 0);
			return false;
		}
		else if (((psocks4_server_command_reply)SOCKS_Pointer)->Command != SOCKS4_REPLY_GRANTED)
		{
			PrintError(LOG_ERROR_SOCKS, L"Client command request error", ((psocks4_server_command_reply)SOCKS_Pointer)->Command, nullptr, 0);
			return false;
		}
	}

	return true;
}

//Transmission and reception of SOCKS protocol(TCP)
size_t __fastcall SOCKSTCPRequest(
	_In_ const char *OriginalSend, 
	_In_ const size_t SendSize, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[LARGE_PACKET_MAXSIZE]());
	std::shared_ptr<SOCKET_DATA> TCPSocketData(new SOCKET_DATA());
	memset(SendBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
	memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
	memset(OriginalRecv, 0, RecvSize);

//Socket initialization
	if (Parameter.SOCKS_Address_IPv6.Storage.ss_family > 0 && //IPv6
		(Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6 || //Auto select
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV6 || //IPv6
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV4 && Parameter.SOCKS_Address_IPv4.Storage.ss_family == 0)) //Non-IPv4
	{
		TCPSocketData->SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&TCPSocketData->SockAddr)->sin6_addr = Parameter.SOCKS_Address_IPv6.IPv6.sin6_addr;
		((PSOCKADDR_IN6)&TCPSocketData->SockAddr)->sin6_port = Parameter.SOCKS_Address_IPv6.IPv6.sin6_port;
		TCPSocketData->AddrLen = sizeof(sockaddr_in6);
		TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	}
	else if (Parameter.SOCKS_Address_IPv4.Storage.ss_family > 0 && //IPv4
		(Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4 || //Auto select
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV4 || //IPv4
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV6 && Parameter.SOCKS_Address_IPv6.Storage.ss_family == 0)) //Non-IPv6
	{
		TCPSocketData->SockAddr.ss_family = AF_INET;
		((PSOCKADDR_IN)&TCPSocketData->SockAddr)->sin_addr = Parameter.SOCKS_Address_IPv4.IPv4.sin_addr;
		((PSOCKADDR_IN)&TCPSocketData->SockAddr)->sin_port = Parameter.SOCKS_Address_IPv4.IPv4.sin_port;
		TCPSocketData->AddrLen = sizeof(sockaddr_in);
		TCPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check 
	if (!SocketSetting(TCPSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
	{
		PrintError(LOG_ERROR_NETWORK, L"SOCKS socket initialization error", 0, nullptr, 0);
		return EXIT_FAILURE;
	}

//Non-blocking mode setting
	if (!SocketSetting(TCPSocketData->Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
	{
		shutdown(TCPSocketData->Socket, SD_BOTH);
		closesocket(TCPSocketData->Socket);
		PrintError(LOG_ERROR_NETWORK, L"Socket non-blocking mode setting error", 0, nullptr, 0);

		return EXIT_FAILURE;
	}

//Selecting structure setting
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));

//Selection exchange process
	if (Parameter.SOCKS_Version == SOCKS_VERSION_5)
	{
		if (!SOCKSSelectionExchange(TCPSocketData.get(), ReadFDS.get(), WriteFDS.get(), Timeout.get(), SendBuffer.get(), OriginalRecv, RecvSize))
		{
			shutdown(TCPSocketData->Socket, SD_BOTH);
			closesocket(TCPSocketData->Socket);

			return EXIT_FAILURE;
		}
		else {
			memset(SendBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
		}
	}

//Client command request process
	if (!SOCKSClientCommandRequest(IPPROTO_TCP, TCPSocketData->Socket, ReadFDS.get(), WriteFDS.get(), Timeout.get(), SendBuffer.get(), OriginalRecv, RecvSize, TCPSocketData.get()))
	{
		shutdown(TCPSocketData->Socket, SD_BOTH);
		closesocket(TCPSocketData->Socket);

		return EXIT_FAILURE;
	}
	else {
		memset(SendBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
	}

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	memcpy_s(SendBuffer.get(), RecvSize, OriginalSend, SendSize);
	SSIZE_T RecvLen = AddLengthDataToHeader(SendBuffer.get(), SendSize, RecvSize);
	if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		shutdown(TCPSocketData->Socket, SD_BOTH);
		closesocket(TCPSocketData->Socket);

		return EXIT_FAILURE;
	}

//Socket timeout setting
#if defined(PLATFORM_WIN)
	Timeout->tv_sec = Parameter.SOCKS_SocketTimeout_Reliable / SECOND_TO_MILLISECOND;
	Timeout->tv_usec = Parameter.SOCKS_SocketTimeout_Reliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Timeout->tv_sec = Parameter.SOCKS_SocketTimeout_Reliable.tv_sec;
	Timeout->tv_usec = Parameter.SOCKS_SocketTimeout_Reliable.tv_usec;
#endif

//Data exchange
	RecvLen = ProxySocketSelecting(TCPSocketData->Socket, ReadFDS.get(), WriteFDS.get(), Timeout.get(), SendBuffer.get(), RecvLen, OriginalRecv, RecvSize, DNS_PACKET_MINSIZE, nullptr);
	shutdown(TCPSocketData->Socket, SD_BOTH);
	closesocket(TCPSocketData->Socket);

//Server response check
	if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && ntohs(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE && 
		RecvLen >= ntohs(((uint16_t *)OriginalRecv)[0]))
	{
		RecvLen = ntohs(((uint16_t *)OriginalRecv)[0]);
		memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(uint16_t), RecvLen);

	//Responses check
		RecvLen = CheckResponseData(OriginalRecv, RecvLen, false, nullptr);
		if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
			return EXIT_FAILURE;

	//Mark DNS cache.
		if (Parameter.CacheType > 0)
			MarkDomainCache(OriginalRecv, RecvLen);

		return RecvLen;
	}

	return EXIT_FAILURE;
}

//Transmission and reception of SOCKS protocol(UDP)
size_t __fastcall SOCKSUDPRequest(
	_In_ const char *OriginalSend, 
	_In_ const size_t SendSize, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize)
{
//Initialization
	std::shared_ptr<char> SendBuffer(new char[LARGE_PACKET_MAXSIZE]());
	std::shared_ptr<SOCKET_DATA> TCPSocketData, UDPSocketData(new SOCKET_DATA()), LocalSocketData;
	memset(SendBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
	memset(UDPSocketData.get(), 0, sizeof(SOCKET_DATA));
	memset(OriginalRecv, 0, RecvSize);
	if (!Parameter.SOCKS_UDP_NoHandshake)
	{
		std::shared_ptr<SOCKET_DATA> TCPSocketDataTemp(new SOCKET_DATA()), LocalSocketDataTemp(new SOCKET_DATA());
		TCPSocketDataTemp.swap(TCPSocketData);
		LocalSocketDataTemp.swap(LocalSocketData);
		memset(TCPSocketData.get(), 0, sizeof(SOCKET_DATA));
		memset(LocalSocketData.get(), 0, sizeof(SOCKET_DATA));
	}

//Socket initialization
	if (Parameter.SOCKS_Address_IPv6.Storage.ss_family > 0 && //IPv6
		(Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6 || //Auto select
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV6 || //IPv6
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV4 && Parameter.SOCKS_Address_IPv4.Storage.ss_family == 0)) //Non-IPv4
	{
		if (!Parameter.SOCKS_UDP_NoHandshake)
		{
		//TCP process
			TCPSocketData->SockAddr.ss_family = AF_INET6;
			((PSOCKADDR_IN6)&TCPSocketData->SockAddr)->sin6_addr = Parameter.SOCKS_Address_IPv6.IPv6.sin6_addr;
			((PSOCKADDR_IN6)&TCPSocketData->SockAddr)->sin6_port = Parameter.SOCKS_Address_IPv6.IPv6.sin6_port;
			TCPSocketData->AddrLen = sizeof(sockaddr_in6);
			TCPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

		//Local process
			LocalSocketData->SockAddr.ss_family = AF_INET6;
			LocalSocketData->AddrLen = sizeof(sockaddr_in6);
		}

	//UDP process
		UDPSocketData->SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&UDPSocketData->SockAddr)->sin6_addr = Parameter.SOCKS_Address_IPv6.IPv6.sin6_addr;
		if (Parameter.SOCKS_UDP_NoHandshake)
			((PSOCKADDR_IN6)&UDPSocketData->SockAddr)->sin6_port = Parameter.SOCKS_Address_IPv6.IPv6.sin6_port;
		UDPSocketData->AddrLen = sizeof(sockaddr_in6);
		UDPSocketData->Socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	}
	else if (Parameter.SOCKS_Address_IPv4.Storage.ss_family > 0 && //IPv4
		(Parameter.SOCKS_Protocol_Network == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4 || //Auto select
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV4 || //IPv4
		Parameter.SOCKS_Protocol_Network == REQUEST_MODE_IPV6 && Parameter.SOCKS_Address_IPv6.Storage.ss_family == 0)) //Non-IPv6
	{
		if (!Parameter.SOCKS_UDP_NoHandshake)
		{
		//TCP process
			TCPSocketData->SockAddr.ss_family = AF_INET;
			((PSOCKADDR_IN)&TCPSocketData->SockAddr)->sin_addr = Parameter.SOCKS_Address_IPv4.IPv4.sin_addr;
			((PSOCKADDR_IN)&TCPSocketData->SockAddr)->sin_port = Parameter.SOCKS_Address_IPv4.IPv4.sin_port;
			TCPSocketData->AddrLen = sizeof(sockaddr_in);
			TCPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		//Local process
			LocalSocketData->SockAddr.ss_family = AF_INET;
			LocalSocketData->AddrLen = sizeof(sockaddr_in);
		}

	//UDP process
		UDPSocketData->SockAddr.ss_family = AF_INET;
		((PSOCKADDR_IN)&UDPSocketData->SockAddr)->sin_addr = Parameter.SOCKS_Address_IPv4.IPv4.sin_addr;
		if (Parameter.SOCKS_UDP_NoHandshake)
			((PSOCKADDR_IN)&UDPSocketData->SockAddr)->sin_port = Parameter.SOCKS_Address_IPv4.IPv4.sin_port;
		UDPSocketData->AddrLen = sizeof(sockaddr_in);
		UDPSocketData->Socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check 
	if (!Parameter.SOCKS_UDP_NoHandshake && !SocketSetting(TCPSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr) || 
		!SocketSetting(UDPSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
	{
		closesocket(UDPSocketData->Socket);
		if (!Parameter.SOCKS_UDP_NoHandshake)
			closesocket(TCPSocketData->Socket);
		PrintError(LOG_ERROR_NETWORK, L"SOCKS socket initialization error", 0, nullptr, 0);

		return EXIT_FAILURE;
	}

//Non-blocking mode setting
	if (!Parameter.SOCKS_UDP_NoHandshake && !SocketSetting(TCPSocketData->Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr) || 
		!SocketSetting(UDPSocketData->Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
	{
		closesocket(UDPSocketData->Socket);
		if (!Parameter.SOCKS_UDP_NoHandshake)
			closesocket(TCPSocketData->Socket);
		PrintError(LOG_ERROR_NETWORK, L"Socket non-blocking mode setting error", 0, nullptr, 0);

		return EXIT_FAILURE;
	}

//Selecting structure setting
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));

//UDP transmission of standard SOCKS protocol must connect with TCP to server first.
	if (!Parameter.SOCKS_UDP_NoHandshake)
	{
	//Selection exchange process
		if (!SOCKSSelectionExchange(TCPSocketData.get(), ReadFDS.get(), WriteFDS.get(), Timeout.get(), SendBuffer.get(), OriginalRecv, RecvSize))
		{
			shutdown(UDPSocketData->Socket, SD_BOTH);
			shutdown(TCPSocketData->Socket, SD_BOTH);
			closesocket(UDPSocketData->Socket);
			closesocket(TCPSocketData->Socket);

			return EXIT_FAILURE;
		}
		else {
			memset(SendBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
		}

	//UDP connecting and get UDP socket infomation.
		if (SocketConnecting(IPPROTO_UDP, UDPSocketData->Socket, (PSOCKADDR)&UDPSocketData->SockAddr, UDPSocketData->AddrLen, nullptr, 0) == EXIT_FAILURE || 
			getsockname(UDPSocketData->Socket, (PSOCKADDR)&LocalSocketData->SockAddr, &LocalSocketData->AddrLen) == SOCKET_ERROR)
		{
			shutdown(UDPSocketData->Socket, SD_BOTH);
			shutdown(TCPSocketData->Socket, SD_BOTH);
			closesocket(UDPSocketData->Socket);
			closesocket(TCPSocketData->Socket);
			PrintError(LOG_ERROR_NETWORK, L"SOCKS connecting error", 0, nullptr, 0);

			return EXIT_FAILURE;
		}

	//Client command request process
		if (!SOCKSClientCommandRequest(IPPROTO_UDP, TCPSocketData->Socket, ReadFDS.get(), WriteFDS.get(), Timeout.get(), SendBuffer.get(), OriginalRecv, RecvSize, LocalSocketData.get()))
		{
			shutdown(UDPSocketData->Socket, SD_BOTH);
			shutdown(TCPSocketData->Socket, SD_BOTH);
			closesocket(UDPSocketData->Socket);
			closesocket(TCPSocketData->Socket);

			return EXIT_FAILURE;
		}
		else {
			memset(SendBuffer.get(), 0, LARGE_PACKET_MAXSIZE);

		//Copy network infomation from server message.
			if (UDPSocketData->SockAddr.ss_family == AF_INET6)
				((PSOCKADDR_IN6)&UDPSocketData->SockAddr)->sin6_port = ((PSOCKADDR_IN6)&LocalSocketData->SockAddr)->sin6_port;
			else 
				((PSOCKADDR_IN)&UDPSocketData->SockAddr)->sin_port = ((PSOCKADDR_IN)&LocalSocketData->SockAddr)->sin_port;
		}
	}

//UDP connecting again
	if (SocketConnecting(IPPROTO_UDP, UDPSocketData->Socket, (PSOCKADDR)&UDPSocketData->SockAddr, UDPSocketData->AddrLen, nullptr, 0) == EXIT_FAILURE)
	{
		if (!Parameter.SOCKS_UDP_NoHandshake)
		{
			shutdown(TCPSocketData->Socket, SD_BOTH);
			closesocket(TCPSocketData->Socket);
		}

		PrintError(LOG_ERROR_NETWORK, L"SOCKS connecting error", 0, nullptr, 0);
		return EXIT_FAILURE;
	}

//SOCKS UDP relay header
	SSIZE_T RecvLen = sizeof(socks_udp_relay_request);
	void *SOCKS_Pointer = SendBuffer.get();
	if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET6) //IPv6
	{
		((psocks_udp_relay_request)SOCKS_Pointer)->Address_Type = SOCKS5_ADDRESS_IPV6;
		SOCKS_Pointer = SendBuffer.get() + RecvLen;
		RecvLen += (SSIZE_T)sizeof(in6_addr);
		*(in6_addr *)SOCKS_Pointer = Parameter.SOCKS_TargetServer.IPv6.sin6_addr;
		SOCKS_Pointer = SendBuffer.get() + RecvLen;
		RecvLen += (SSIZE_T)sizeof(uint16_t);
		*(uint16_t *)SOCKS_Pointer = Parameter.SOCKS_TargetServer.IPv6.sin6_port;
	}
	else if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET) //IPv4
	{
		((psocks_udp_relay_request)SOCKS_Pointer)->Address_Type = SOCKS5_ADDRESS_IPV4;
		SOCKS_Pointer = SendBuffer.get() + RecvLen;
		RecvLen += (SSIZE_T)sizeof(in_addr);
		*(in_addr *)SOCKS_Pointer = Parameter.SOCKS_TargetServer.IPv4.sin_addr;
		SOCKS_Pointer = SendBuffer.get() + RecvLen;
		RecvLen += (SSIZE_T)sizeof(uint16_t);
		*(uint16_t *)SOCKS_Pointer = Parameter.SOCKS_TargetServer.IPv4.sin_port;
	}
	else if (Parameter.SOCKS_TargetDomain != nullptr && !Parameter.SOCKS_TargetDomain->empty()) //Damain
	{
		((psocks_udp_relay_request)SOCKS_Pointer)->Address_Type = SOCKS5_ADDRESS_DOMAIN;
		SOCKS_Pointer = SendBuffer.get() + RecvLen;
		RecvLen += (SSIZE_T)sizeof(uint8_t);
		*(uint8_t *)SOCKS_Pointer = (uint8_t)Parameter.SOCKS_TargetDomain->length();
		SOCKS_Pointer = SendBuffer.get() + RecvLen;
		memcpy_s(SOCKS_Pointer, (SSIZE_T)LARGE_PACKET_MAXSIZE - ((SSIZE_T)sizeof(socks_udp_relay_request) + RecvLen), Parameter.SOCKS_TargetDomain->c_str(), Parameter.SOCKS_TargetDomain->length());
		RecvLen += (SSIZE_T)Parameter.SOCKS_TargetDomain->length();
		SOCKS_Pointer = SendBuffer.get() + RecvLen;
		*(uint16_t *)SOCKS_Pointer = Parameter.SOCKS_TargetDomain_Port;
		RecvLen += (SSIZE_T)sizeof(uint16_t);
	}
	else {
		shutdown(UDPSocketData->Socket, SD_BOTH);
		closesocket(UDPSocketData->Socket);
		if (!Parameter.SOCKS_UDP_NoHandshake)
		{
			shutdown(TCPSocketData->Socket, SD_BOTH);
			closesocket(TCPSocketData->Socket);
		}

		return EXIT_FAILURE;
	}

	memcpy_s(SendBuffer.get() + RecvLen, RecvSize, OriginalSend, SendSize);
	RecvLen += (SSIZE_T)SendSize;

//Socket timeout setting
#if defined(PLATFORM_WIN)
	Timeout->tv_sec = Parameter.SOCKS_SocketTimeout_Unreliable / SECOND_TO_MILLISECOND;
	Timeout->tv_usec = Parameter.SOCKS_SocketTimeout_Unreliable % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Timeout->tv_sec = Parameter.SOCKS_SocketTimeout_Reliable.tv_sec;
	Timeout->tv_usec = Parameter.SOCKS_SocketTimeout_Reliable.tv_usec;
#endif

//Data exchange
	RecvLen = ProxySocketSelecting(UDPSocketData->Socket, ReadFDS.get(), WriteFDS.get(), Timeout.get(), SendBuffer.get(), RecvLen, OriginalRecv, RecvSize, sizeof(socks_udp_relay_request) + DNS_PACKET_MINSIZE, nullptr);
	shutdown(UDPSocketData->Socket, SD_BOTH);
	closesocket(UDPSocketData->Socket);
	if (!Parameter.SOCKS_UDP_NoHandshake)
	{
		shutdown(TCPSocketData->Socket, SD_BOTH);
		closesocket(TCPSocketData->Socket);
	}
	if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		SSIZE_T OriginalRecvLen = RecvLen;

	//Remove SOCKS UDP relay header
		SOCKS_Pointer = OriginalRecv;
		if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET6 && //IPv6
			((psocks_udp_relay_request)SOCKS_Pointer)->Address_Type == SOCKS5_ADDRESS_IPV6 && 
			RecvLen >= (SSIZE_T)(sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t) + DNS_PACKET_MINSIZE) && 
			memcmp((in6_addr *)(OriginalRecv + sizeof(socks_udp_relay_request)), &Parameter.SOCKS_TargetServer.IPv6.sin6_addr, sizeof(in6_addr)) == 0 && 
			*(uint16_t *)(OriginalRecv + sizeof(socks_udp_relay_request) + sizeof(in6_addr)) == Parameter.SOCKS_TargetServer.IPv6.sin6_port)
		{
			memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t), RecvLen - (SSIZE_T)(sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t)));
			RecvLen -= sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t);
		}
		else if (Parameter.SOCKS_TargetServer.Storage.ss_family == AF_INET && //IPv4
			((psocks_udp_relay_request)SOCKS_Pointer)->Address_Type == SOCKS5_ADDRESS_IPV4 && 
			RecvLen >= (SSIZE_T)(sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t) + DNS_PACKET_MINSIZE) && 
			(*(in_addr *)(OriginalRecv + sizeof(socks_udp_relay_request))).s_addr == Parameter.SOCKS_TargetServer.IPv4.sin_addr.s_addr && 
			*(uint16_t *)(OriginalRecv + sizeof(socks_udp_relay_request) + sizeof(in_addr)) == Parameter.SOCKS_TargetServer.IPv4.sin_port)
		{
			memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t), RecvLen - (SSIZE_T)(sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t)));
			RecvLen -= sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t);
		}
		else if (Parameter.SOCKS_TargetDomain != nullptr && !Parameter.SOCKS_TargetDomain->empty()) //Domain
/* SOCKS server will reply IPv4/IPv6 address of domain.
			((psocks_udp_relay_request)SOCKS_Pointer)->Address_Type == SOCKS5_ADDRESS_DOMAIN && 
			RecvLen >= (SSIZE_T)(sizeof(socks_udp_relay_request) + sizeof(uint8_t) + Parameter.SOCKS_TargetDomain->length() + sizeof(uint16_t) + DNS_PACKET_MINSIZE) && 
			*(uint8_t *)(OriginalRecv + sizeof(socks_udp_relay_request)) == Parameter.SOCKS_TargetDomain->length() && 
			memcmp(OriginalRecv + sizeof(socks_udp_relay_request) + sizeof(uint8_t), Parameter.SOCKS_TargetDomain->c_str(), Parameter.SOCKS_TargetDomain->length()) == 0 && 
			*(uint16_t *)(OriginalRecv + sizeof(socks_udp_relay_request) + sizeof(uint8_t) + Parameter.SOCKS_TargetDomain->length()) == Parameter.SOCKS_TargetDomain_Port)
*/
		{
		//IPv6
			if (((psocks_udp_relay_request)SOCKS_Pointer)->Address_Type == SOCKS5_ADDRESS_IPV6 && 
				RecvLen >= (SSIZE_T)(sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t) + DNS_PACKET_MINSIZE))
			{
				memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t), RecvLen - (SSIZE_T)(sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t)));
				RecvLen -= sizeof(socks_udp_relay_request) + sizeof(in6_addr) + sizeof(uint16_t);
			}
		//IPv4
			else if (((psocks_udp_relay_request)SOCKS_Pointer)->Address_Type == SOCKS5_ADDRESS_IPV4 && 
				RecvLen >= (SSIZE_T)(sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t) + DNS_PACKET_MINSIZE))
			{
				memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t), RecvLen - (SSIZE_T)(sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t)));
				RecvLen -= sizeof(socks_udp_relay_request) + sizeof(in_addr) + sizeof(uint16_t);
			}

/* SOCKS server will reply IPv4/IPv6 address of domain.
			memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(socks_udp_relay_request) + sizeof(uint8_t) + Parameter.SOCKS_TargetDomain->length() + sizeof(uint16_t), RecvLen - (SSIZE_T)(sizeof(socks_udp_relay_request) + sizeof(uint8_t) + Parameter.SOCKS_TargetDomain->length() + sizeof(uint16_t)));
			return RecvLen - (SSIZE_T)(sizeof(socks_udp_relay_request) + sizeof(uint8_t) + Parameter.SOCKS_TargetDomain->length() + sizeof(uint16_t));
*/
		}

	//Server response check
		if (OriginalRecvLen != RecvLen)
		{
		//Responses check
			RecvLen = CheckResponseData(OriginalRecv, RecvLen, false, nullptr);
			if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
				return EXIT_FAILURE;

		//Mark DNS cache.
			if (Parameter.CacheType > 0)
				MarkDomainCache(OriginalRecv, RecvLen);

			return RecvLen;
		}
	}

	return EXIT_FAILURE;
}

//Transmission and reception of HTTP protocol
size_t __fastcall HTTPRequest(
	_In_ const char *OriginalSend, 
	_In_ const size_t SendSize, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize)
{
//Initialization
	std::shared_ptr<SOCKET_DATA> HTTPSocketData(new SOCKET_DATA());
	memset(HTTPSocketData.get(), 0, sizeof(SOCKET_DATA));
	memset(OriginalRecv, 0, RecvSize);

//Socket initialization
	if (Parameter.HTTP_Address_IPv6.Storage.ss_family > 0 && //IPv6
		(Parameter.HTTP_Protocol == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv6 || //Auto select
		Parameter.HTTP_Protocol == REQUEST_MODE_IPV6 || //IPv6
		Parameter.HTTP_Protocol == REQUEST_MODE_IPV4 && Parameter.HTTP_Address_IPv4.Storage.ss_family == 0)) //Non-IPv4
	{
		HTTPSocketData->SockAddr.ss_family = AF_INET6;
		((PSOCKADDR_IN6)&HTTPSocketData->SockAddr)->sin6_addr = Parameter.HTTP_Address_IPv6.IPv6.sin6_addr;
		((PSOCKADDR_IN6)&HTTPSocketData->SockAddr)->sin6_port = Parameter.HTTP_Address_IPv6.IPv6.sin6_port;
		HTTPSocketData->AddrLen = sizeof(sockaddr_in6);
		HTTPSocketData->Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	}
	else if (Parameter.HTTP_Address_IPv4.Storage.ss_family > 0 && //IPv4
		(Parameter.HTTP_Protocol == REQUEST_MODE_NETWORK_BOTH && GlobalRunningStatus.GatewayAvailable_IPv4 || //Auto select
		Parameter.HTTP_Protocol == REQUEST_MODE_IPV4 || //IPv4
		Parameter.HTTP_Protocol == REQUEST_MODE_IPV6 && Parameter.HTTP_Address_IPv6.Storage.ss_family == 0)) //Non-IPv6
	{
		HTTPSocketData->SockAddr.ss_family = AF_INET;
		((PSOCKADDR_IN)&HTTPSocketData->SockAddr)->sin_addr = Parameter.HTTP_Address_IPv4.IPv4.sin_addr;
		((PSOCKADDR_IN)&HTTPSocketData->SockAddr)->sin_port = Parameter.HTTP_Address_IPv4.IPv4.sin_port;
		HTTPSocketData->AddrLen = sizeof(sockaddr_in);
		HTTPSocketData->Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}
	else {
		return EXIT_FAILURE;
	}

//Socket check 
	if (!SocketSetting(HTTPSocketData->Socket, SOCKET_SETTING_INVALID_CHECK, nullptr))
	{
		PrintError(LOG_ERROR_NETWORK, L"HTTP socket initialization error", 0, nullptr, 0);
		return EXIT_FAILURE;
	}

//Non-blocking mode setting
	if (!SocketSetting(HTTPSocketData->Socket, SOCKET_SETTING_NON_BLOCKING_MODE, nullptr))
	{
		shutdown(HTTPSocketData->Socket, SD_BOTH);
		closesocket(HTTPSocketData->Socket);
		PrintError(LOG_ERROR_NETWORK, L"Socket non-blocking mode setting error", 0, nullptr, 0);

		return EXIT_FAILURE;
	}

//Selecting structure setting
	std::shared_ptr<fd_set> ReadFDS(new fd_set()), WriteFDS(new fd_set());
	std::shared_ptr<timeval> Timeout(new timeval());
	memset(ReadFDS.get(), 0, sizeof(fd_set));
	memset(WriteFDS.get(), 0, sizeof(fd_set));
	memset(Timeout.get(), 0, sizeof(timeval));

//HTTP CONNECT request
	if (Parameter.HTTP_TargetDomain == nullptr || Parameter.HTTP_Version == nullptr || 
		!HTTP_CONNECTRequest(HTTPSocketData.get(), ReadFDS.get(), WriteFDS.get(), Timeout.get(), OriginalRecv, RecvSize))
	{
		shutdown(HTTPSocketData->Socket, SD_BOTH);
		closesocket(HTTPSocketData->Socket);

		return EXIT_FAILURE;
	}

//Add length of request packet(It must be written in header when transpot with TCP protocol).
	std::shared_ptr<char> SendBuffer(new char[LARGE_PACKET_MAXSIZE]());
	memset(SendBuffer.get(), 0, LARGE_PACKET_MAXSIZE);
	memcpy_s(SendBuffer.get(), RecvSize, OriginalSend, SendSize);
	SSIZE_T RecvLen = AddLengthDataToHeader(SendBuffer.get(), SendSize, RecvSize);
	if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		shutdown(HTTPSocketData->Socket, SD_BOTH);
		closesocket(HTTPSocketData->Socket);

		return EXIT_FAILURE;
	}

//Socket timeout setting
#if defined(PLATFORM_WIN)
	Timeout->tv_sec = Parameter.HTTP_SocketTimeout / SECOND_TO_MILLISECOND;
	Timeout->tv_usec = Parameter.HTTP_SocketTimeout % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Timeout->tv_sec = Parameter.HTTP_SocketTimeout.tv_sec;
	Timeout->tv_usec = Parameter.HTTP_SocketTimeout.tv_usec;
#endif

//Data exchange
	RecvLen = ProxySocketSelecting(HTTPSocketData->Socket, ReadFDS.get(), WriteFDS.get(), Timeout.get(), SendBuffer.get(), RecvLen, OriginalRecv, RecvSize, DNS_PACKET_MINSIZE, nullptr);
	shutdown(HTTPSocketData->Socket, SD_BOTH);
	closesocket(HTTPSocketData->Socket);

//Server response check
	if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE && ntohs(((uint16_t *)OriginalRecv)[0]) >= DNS_PACKET_MINSIZE && 
		RecvLen >= ntohs(((uint16_t *)OriginalRecv)[0]))
	{
		RecvLen = ntohs(((uint16_t *)OriginalRecv)[0]);
		memmove_s(OriginalRecv, RecvSize, OriginalRecv + sizeof(uint16_t), RecvLen);

	//Responses check
		RecvLen = CheckResponseData(OriginalRecv, RecvLen, false, nullptr);
		if (RecvLen < (SSIZE_T)DNS_PACKET_MINSIZE)
			return EXIT_FAILURE;

	//Mark DNS cache.
		if (Parameter.CacheType > 0)
			MarkDomainCache(OriginalRecv, RecvLen);

		return RecvLen;
	}

	return EXIT_FAILURE;
}

//HTTP CONNECT request exchange process
bool __fastcall HTTP_CONNECTRequest(
	_In_ SOCKET_DATA *HTTPSocketData, 
	_In_ fd_set *ReadFDS, 
	_In_ fd_set *WriteFDS, 
	_In_ timeval *Timeout, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize)
{
//Initialization
	memset(OriginalRecv, 0, RecvSize);
	std::string HTTPString;
	HTTPString.append("CONNECT ");
	HTTPString.append(*Parameter.HTTP_TargetDomain);
	HTTPString.append(" HTTP/");
	HTTPString.append(*Parameter.HTTP_Version);
	HTTPString.append("\r\nHost: ");
	HTTPString.append(*Parameter.HTTP_TargetDomain);
	HTTPString.append("\r\n");
	if (Parameter.HTTP_HeaderField != nullptr && !Parameter.HTTP_HeaderField->empty())
		HTTPString.append(*Parameter.HTTP_HeaderField);
	if (Parameter.HTTP_ProxyAuthorization != nullptr && !Parameter.HTTP_ProxyAuthorization->empty())
		HTTPString.append(*Parameter.HTTP_ProxyAuthorization);
	HTTPString.append("\r\n");

//Socket timeout setting
#if defined(PLATFORM_WIN)
	Timeout->tv_sec = Parameter.HTTP_SocketTimeout / SECOND_TO_MILLISECOND;
	Timeout->tv_usec = Parameter.HTTP_SocketTimeout % SECOND_TO_MILLISECOND * MICROSECOND_TO_MILLISECOND;
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
	Timeout->tv_sec = Parameter.HTTP_SocketTimeout.tv_sec;
	Timeout->tv_usec = Parameter.HTTP_SocketTimeout.tv_usec;
#endif

//TCP connecting
	SSIZE_T RecvLen = SocketConnecting(IPPROTO_TCP, HTTPSocketData->Socket, (PSOCKADDR)&HTTPSocketData->SockAddr, HTTPSocketData->AddrLen, HTTPString.c_str(), HTTPString.length());
	if (RecvLen == EXIT_FAILURE)
	{
		PrintError(LOG_ERROR_NETWORK, L"HTTP connecting error", 0, nullptr, 0);
		return false;
	}
//HTTP CONNECT request exchange
	else if (RecvLen >= (SSIZE_T)DNS_PACKET_MINSIZE)
	{
		RecvLen = ProxySocketSelecting(HTTPSocketData->Socket, ReadFDS, WriteFDS, Timeout, nullptr, 0, OriginalRecv, RecvSize, HTTP_RESPONSE_MINSIZE, nullptr);
	}
	else {
		RecvLen = ProxySocketSelecting(HTTPSocketData->Socket, ReadFDS, WriteFDS, Timeout, HTTPString.c_str(), HTTPString.length(), OriginalRecv, RecvSize, HTTP_RESPONSE_MINSIZE, nullptr);
	}
	if (RecvLen < (SSIZE_T)HTTP_RESPONSE_MINSIZE)
	{
		PrintError(LOG_ERROR_NETWORK, L"HTTP request error", 0, nullptr, 0);
		return false;
	}
	else {
		OriginalRecv[RecvSize - 1U] = 0;
		HTTPString.clear();
		HTTPString = OriginalRecv;
	}

//HTTP CONNECT response check
	if (HTTPString.find("\r\n") == std::string::npos || HTTPString.find("HTTP/") == std::string::npos)
	{
		PrintError(LOG_ERROR_HTTP, L"HTTP server response error", 0, nullptr, 0);
		return false;
	}
	else if (HTTPString.find(" 200 ") == std::string::npos || HTTPString.find(" 200 ") >= HTTPString.find("\r\n")) //Not HTTP status code 200: OK
	{
		std::wstring wErrBuffer;
		HTTPString.erase(HTTPString.find("\r\n"), HTTPString.length() - HTTPString.find("\r\n"));
		MBSToWCSString(HTTPString.c_str(), HTTPString.length(), wErrBuffer);
		PrintError(LOG_ERROR_HTTP, wErrBuffer.c_str(), 0, nullptr, 0);

		return false;
	}

	return true;
}
