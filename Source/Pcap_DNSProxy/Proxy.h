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


#include "Base.h"

//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;

//Functions
SSIZE_T __fastcall SOCKSSocketSelecting(
	SYSTEM_SOCKET Socket, 
	fd_set *ReadFDS, 
	fd_set *WriteFDS, 
	timeval *Timeout, 
	const char *SendBuffer, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const size_t MinLen);
bool __fastcall SOCKSSelectionExchange(
	SOCKET_DATA *SOCKSSocketData, 
	fd_set *ReadFDS, 
	fd_set *WriteFDS, 
	timeval *Timeout, 
	PSTR SendBuffer, 
	PSTR OriginalRecv, 
	const size_t RecvSize);
bool __fastcall SOCKSAuthenticationUsernamePassword(
	SYSTEM_SOCKET Socket, 
	fd_set *ReadFDS, 
	fd_set *WriteFDS, 
	timeval *Timeout, 
	PSTR SendBuffer, 
	PSTR OriginalRecv, 
	const size_t RecvSize);
bool __fastcall SOCKSClientCommandRequest(
	const uint16_t Protocol, 
	SYSTEM_SOCKET Socket, 
	fd_set *ReadFDS, 
	fd_set *WriteFDS, 
	timeval *Timeout, 
	PSTR SendBuffer, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	PSOCKET_DATA UDP_ASSOCIATE_TCP_Connecting_Address);
