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
#if defined(ENABLE_LIBSODIUM)
	extern DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter;
#endif
extern std::vector<DIFFERNET_HOSTS_FILE_SET> *HostsFileSetUsing, *HostsFileSetModificating;
extern std::deque<DNSCACHE_DATA> DNSCacheList;
extern std::mutex LocalAddressLock[NETWORK_LAYER_PARTNUM], HostsFileLock, DNSCacheListLock;

//Functions
bool __fastcall LocalRequestProcess(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t Protocol, 
	const SOCKET_DATA &LocalSocketData);
bool __fastcall SOCKSRequestProcess(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t Protocol, 
	const SOCKET_DATA &LocalSocketData);
bool __fastcall DirectRequestProcess(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t Protocol, 
	const bool DirectRequest, 
	const SOCKET_DATA &LocalSocketData);
#if defined(ENABLE_LIBSODIUM)
bool __fastcall DNSCurveRequestProcess(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t Protocol, 
	const SOCKET_DATA &LocalSocketData);
#endif
bool __fastcall TCPRequestProcess(
	const char *OriginalSend, 
	const size_t SendSize, 
	PSTR OriginalRecv, 
	const size_t RecvSize, 
	const uint16_t Protocol, 
	const SOCKET_DATA &LocalSocketData);
#if defined(ENABLE_PCAP)
void __fastcall UDPRequestProcess(
	const char *OriginalSend, 
	const size_t SendSize, 
	const SOCKET_DATA &LocalSocketData, 
	const uint16_t Protocol);
#endif
uint16_t __fastcall SelectNetworkProtocol(
	void);
