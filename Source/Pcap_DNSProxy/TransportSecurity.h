// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2019 Chengr28
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


#ifndef PCAP_DNSPROXY_TRANSPORTSECURITY_H
#define PCAP_DNSPROXY_TRANSPORTSECURITY_H

#include "Include.h"

#if defined(ENABLE_TLS)
//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;

//Local variables
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
static unsigned char HTTP_1_ALPN_List[] = HTTP_1_TLS_ALPN_STRING;
static unsigned char HTTP_2_ALPN_List[] = HTTP_2_TLS_ALPN_STRING;
#endif

#if defined(PLATFORM_WIN)
//Functions
bool SSPI_HandshakeLoop(
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList, 
	std::vector<ssize_t> &ErrorCodeList);
bool SSPI_GetStreamSize(
	SSPI_HANDLE_TABLE &SSPI_Handle);
bool SSPI_EncryptPacket(
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList);
bool SSPI_DecryptPacket(
	SSPI_HANDLE_TABLE &SSPI_Handle, 
	std::vector<SOCKET_SELECTING_SERIAL_DATA> &SocketSelectingDataList);
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool OpenSSL_PrintError(
	const uint8_t *OpenSSL_ErrorMessage, 
	const wchar_t *ErrorMessage);
#endif
#endif
#endif
