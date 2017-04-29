// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2017 Chengr28
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


#ifndef PCAP_DNSPROXY_PROXY_H
#define PCAP_DNSPROXY_PROXY_H

#include "Base.h"

//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;

//Length definitions
#define HTTP1_RESPONSE_MINSIZE              (strlen(" HTTP/") + HTTP_VERSION_MAXSIZE + HTTP_STATUS_CODE_SIZE)

//Functions
bool SOCKS_SelectionExchange(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList);
bool SOCKS_AuthenticationExchange(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList);
bool SOCKS_ClientCommandRequest(
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList, 
	SOCKET_DATA * const UDP_ASSOCIATE_Address);
void HTTP_CONNECT_2_IntegerEncoding(
	std::vector<uint8_t> &BytesList, 
	size_t IntegerValue);
void HTTP_CONNECT_2_SETTINGS_WriteBytes(
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	const uint16_t Identifier, 
	const uint32_t Value);
size_t HTTP_CONNECT_2_IntegerDecoding(
	uint8_t *Buffer, 
	const size_t Length, 
	size_t &IntegerValue);
bool HTTP_CONNECT_2_HEADERS_WriteBytes(
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	const uint8_t *Buffer, 
	const size_t Length, 
	const bool IsLiteralFlag);
bool HTTP_CONNECT_2_HEADERS_ReadBytes(
	std::vector<std::string> &HeaderList, 
	const uint8_t *Buffer, 
	const size_t Length);
bool HTTP_CONNECT_ResponseBytesCheck(
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList);
bool HTTP_CONNECT_2_ShutdownConnection(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<ssize_t> &ErrorCodeList, 
	const size_t Type, 
	const size_t ErrorCode, 
	void *TLS_Context);
bool HTTP_CONNECT_Handshake(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList, 
	void *TLS_Context);
bool HTTP_CONNECT_Exchange(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList, 
	void *TLS_Context);
size_t HTTP_CONNECT_Transport(
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList, 
	void *TLS_Context);
#endif
