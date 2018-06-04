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


#ifndef PCAP_DNSPROXY_DNSCURVE_H
#define PCAP_DNSPROXY_DNSCURVE_H

#include "Include.h"

#if defined(ENABLE_LIBSODIUM)
//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;
extern ALTERNATE_SWAP_TABLE AlternateSwapList;
extern DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter;
extern std::deque<SOCKET_REGISTER_DATA> SocketRegisterList;
extern std::mutex SocketRegisterLock;

//Functions
size_t DNSCurvePaddingData(
	const bool IsSetPadding, 
	uint8_t * const Buffer, 
	const size_t Length, 
	const size_t BufferSize);
uint16_t DNSCurveSelectTargetSocket(
	const uint16_t Protocol, 
	const uint16_t QueryType, 
	const SOCKET_DATA &LocalSocketData, 
	bool ** const IsAlternate);
#endif
#endif
