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


#ifndef PCAP_DNSPROXY_MONITOR_H
#define PCAP_DNSPROXY_MONITOR_H

#include "Base.h"

//Global variables
extern CONFIGURATION_TABLE Parameter, ParameterModificating;
extern GLOBAL_STATUS GlobalRunningStatus;
extern ALTERNATE_SWAP_TABLE AlternateSwapList;
#if defined(ENABLE_LIBSODIUM)
extern DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter, DNSCurveParameterModificating;
#endif
extern std::deque<SOCKET_MARKING_DATA> SocketMarkingList;
extern std::mutex LocalAddressLock[], SocketMarkingLock;

//Functions
bool UDP_Monitor(
	const SOCKET_DATA LocalSocketData, 
	bool * const Result);
bool TCP_Monitor(
	const SOCKET_DATA LocalSocketData, 
	bool * const Result);
#if defined(PLATFORM_WIN)
addrinfo *GetLocalAddressList(
	const uint16_t Protocol, 
	uint8_t * const HostName);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool GetBestInterfaceAddress(
	const uint16_t Protocol, 
	const sockaddr_storage * const OriginalSockAddr);
#endif
void GetGatewayInformation(
	const uint16_t Protocol);
#endif
