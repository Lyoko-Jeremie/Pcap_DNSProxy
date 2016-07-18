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


#include "Base.h"

//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;

//Functions
ssize_t ProxySocketSelecting(
	SYSTEM_SOCKET Socket, 
	fd_set *ReadFDS, 
	fd_set *WriteFDS, 
	timeval *Timeout, 
	const uint8_t *SendBuffer, 
	const size_t SendSize, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize, 
	const size_t MinLen, 
	ssize_t *ErrorCode);
bool SOCKSSelectionExchange(
	SOCKET_DATA *SOCKSSocketData, 
	fd_set *ReadFDS, 
	fd_set *WriteFDS, 
	timeval *Timeout, 
	uint8_t *SendBuffer, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize);
bool SOCKSAuthenticationUsernamePassword(
	SYSTEM_SOCKET Socket, 
	fd_set *ReadFDS, 
	fd_set *WriteFDS, 
	timeval *Timeout, 
	uint8_t *SendBuffer, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize);
bool SOCKSClientCommandRequest(
	const uint16_t Protocol, 
	SYSTEM_SOCKET Socket, 
	fd_set *ReadFDS, 
	fd_set *WriteFDS, 
	timeval *Timeout, 
	uint8_t *SendBuffer, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize, 
	SOCKET_DATA *UDP_ASSOCIATE_TCP_Connecting_Address);
bool HTTP_CONNECTRequest(
	SOCKET_DATA *HTTPSocketData, 
	fd_set *ReadFDS, 
	fd_set *WriteFDS, 
	timeval *Timeout, 
	uint8_t *OriginalRecv, 
	const size_t RecvSize);
