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
	_In_ SYSTEM_SOCKET Socket, 
	_In_ fd_set *ReadFDS, 
	_In_ fd_set *WriteFDS, 
	_In_ timeval *Timeout, 
	_In_opt_ const char *SendBuffer, 
	_In_ const size_t SendSize, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize, 
	_In_ const size_t MinLen);
bool __fastcall SOCKSSelectionExchange(
	_In_ SOCKET_DATA *SOCKSSocketData, 
	_In_ fd_set *ReadFDS, 
	_In_ fd_set *WriteFDS, 
	_In_ timeval *Timeout, 
	_Inout_ char *SendBuffer, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize);
bool __fastcall SOCKSAuthenticationUsernamePassword(
	_In_ SYSTEM_SOCKET Socket, 
	_In_ fd_set *ReadFDS, 
	_In_ fd_set *WriteFDS, 
	_In_ timeval *Timeout, 
	_Inout_ char *SendBuffer, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize);
bool __fastcall SOCKSClientCommandRequest(
	_In_ const uint16_t Protocol, 
	_In_ SYSTEM_SOCKET Socket, 
	_In_ fd_set *ReadFDS, 
	_In_ fd_set *WriteFDS, 
	_In_ timeval *Timeout, 
	_Inout_ char *SendBuffer, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize, 
	_In_opt_ SOCKET_DATA *UDP_ASSOCIATE_TCP_Connecting_Address);
