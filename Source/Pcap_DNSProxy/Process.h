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
#if defined(ENABLE_LIBSODIUM)
	extern DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter;
#endif
extern std::vector<DIFFERNET_FILE_SET_HOSTS> *HostsFileSetUsing, *HostsFileSetModificating;
extern std::list<DNS_CACHE_DATA> DNSCacheList;
extern std::mutex LocalAddressLock[NETWORK_LAYER_PARTNUM], HostsFileLock, DNSCacheListLock;

//Functions
bool __fastcall LocalRequestProcess(
	const DNS_PACKET_DATA &Packet, 
	char *OriginalRecv, 
	const size_t RecvSize, 
	const SOCKET_DATA &LocalSocketData);
bool __fastcall SOCKSRequestProcess(
	const DNS_PACKET_DATA &Packet, 
	char *OriginalRecv, 
	const size_t RecvSize, 
	const SOCKET_DATA &LocalSocketData);
bool __fastcall HTTPRequestProcess(
	const DNS_PACKET_DATA &Packet, 
	char *OriginalRecv, 
	const size_t RecvSize, 
	const SOCKET_DATA &LocalSocketData);
bool __fastcall DirectRequestProcess(
	const DNS_PACKET_DATA &Packet, 
	char *OriginalRecv, 
	const size_t RecvSize, 
	const bool DirectRequest, 
	const SOCKET_DATA &LocalSocketData);
#if defined(ENABLE_LIBSODIUM)
bool __fastcall DNSCurveRequestProcess(
	const DNS_PACKET_DATA &Packet, 
	char *OriginalRecv, 
	const size_t RecvSize, 
	const SOCKET_DATA &LocalSocketData);
#endif
bool __fastcall TCPRequestProcess(
	const DNS_PACKET_DATA &Packet, 
	char *OriginalRecv, 
	const size_t RecvSize, 
	const SOCKET_DATA &LocalSocketData);
#if defined(ENABLE_PCAP)
void __fastcall UDPRequestProcess(
	const DNS_PACKET_DATA &Packet, 
	const SOCKET_DATA &LocalSocketData);
#endif
uint16_t __fastcall SelectNetworkProtocol(
	void);
