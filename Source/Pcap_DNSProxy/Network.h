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


#ifndef PCAP_DNSPROXY_NETWORK_H
#define PCAP_DNSPROXY_NETWORK_H

#include "Include.h"

//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;
extern ALTERNATE_SWAP_TABLE AlternateSwapList;
#if defined(ENABLE_LIBSODIUM)
extern DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter;
#endif
extern std::deque<SOCKET_REGISTER_DATA> SocketRegisterList;
#if defined(ENABLE_PCAP)
extern std::deque<OUTPUT_PACKET_TABLE> OutputPacketList;
extern std::mutex OutputPacketListLock;
#endif
extern std::mutex SocketRegisterLock;

//Functions
ssize_t SelectingResultOnce(
	const REQUEST_PROCESS_TYPE RequestType, 
	const uint16_t Protocol, 
	std::vector<SOCKET_DATA> &SocketDataList, 
	std::vector<SOCKET_SELECTING_ONCE_TABLE> *SocketSelectingDataList, 
	void * const OriginalDNSCurveSocketSelectingDataList, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	const SOCKET_DATA * const LocalSocketData);
#endif
