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


#ifndef PCAP_DNSPROXY_PROCESS_H
#define PCAP_DNSPROXY_PROCESS_H

#include "Include.h"

//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;
extern BLOCKING_QUEUE<MONITOR_QUEUE_DATA> MonitorBlockingQueue;
#if defined(ENABLE_LIBSODIUM)
extern DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter;
#endif
extern std::vector<DIFFERNET_FILE_SET_HOSTS> *HostsFileSetUsing, *HostsFileSetModificating;
extern std::mutex LocalAddressLock[], HostsFileLock;

//Functions
bool LocalRequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	std::unique_ptr<uint8_t[]> &EDNS_Buffer, 
	const REQUEST_PROCESS_TYPE RequestType);
bool SOCKS_RequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData, 
	std::unique_ptr<uint8_t[]> &EDNS_Buffer);
bool HTTP_CONNECT_RequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData, 
	std::unique_ptr<uint8_t[]> &EDNS_Buffer);
bool DirectRequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	std::unique_ptr<uint8_t[]> &EDNS_Buffer, 
	const bool IsAutomatic);
#if defined(ENABLE_LIBSODIUM)
bool DNSCurveRequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	std::unique_ptr<uint8_t[]> &EDNS_Buffer);
#endif
bool TCP_RequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData, 
	uint8_t * const OriginalRecv, 
	const size_t RecvSize, 
	std::unique_ptr<uint8_t[]> &EDNS_Buffer);
#if defined(ENABLE_PCAP)
void UDP_RequestProcess(
	MONITOR_QUEUE_DATA &MonitorQueryData, 
	std::unique_ptr<uint8_t[]> &EDNS_Buffer);
#endif
uint16_t SelectDirectProtocol(
	void);
#endif
