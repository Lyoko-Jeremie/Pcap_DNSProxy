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


#ifndef PCAP_DNSPROXY_REQUEST_H
#define PCAP_DNSPROXY_REQUEST_H

#include "Include.h"

//Structure definitions
#if defined(ENABLE_PCAP)
//Internet Control Message Protocol/ICMP echo request(Ping) event argument structure
typedef struct _icmp_event_argument_
{
	uint16_t                                  Protocol;
	timeval                                   SocketTimeout;
	timeval                                   IntervalTimeout;
	event_base                                *EventBase;
	std::vector<event *>                      *EventList;
	std::vector<SOCKET_DATA>                  *SocketData;
	uint8_t                                   *SendBuffer;
	uint8_t                                   *RecvBuffer;
	size_t                                    SendSize;
	size_t                                    RecvSize;
	size_t                                    TotalSleepTime;
	size_t                                    OnceTimes;
	size_t                                    RetestTimes;
	uint64_t                                  FileModifiedTime;
#if defined(PLATFORM_LINUX)
#if !defined(ENABLE_LIBSODIUM)
	std::uniform_int_distribution<uint32_t>   *RandomDistribution;
#endif
#endif
}ICMP_EventArgument, ICMP_EVENT_ARGUMENT;
#endif

//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;
extern ALTERNATE_SWAP_TABLE AlternateSwapList;

//Functions
#if defined(ENABLE_PCAP)
void ICMP_TestReadCallback(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument);
void ICMP_TestWriteCallback(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument);
void ICMP_TestTimerCallback(
	evutil_socket_t Socket, 
	short EventType, 
	void *Argument);
#endif
#endif
