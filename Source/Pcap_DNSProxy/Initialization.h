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


#ifndef PCAP_DNSPROXY_INITIALIZATION_H
#define PCAP_DNSPROXY_INITIALIZATION_H

#include "Include.h"

//Global variables
CONFIGURATION_TABLE Parameter, ParameterModificating;
GLOBAL_STATUS GlobalRunningStatus;
ALTERNATE_SWAP_TABLE AlternateSwapList;
BLOCKING_QUEUE<MONITOR_QUEUE_DATA> MonitorBlockingQueue;
#if defined(ENABLE_LIBSODIUM)
DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter, DNSCurveParameterModificating;
#endif
std::vector<FILE_DATA> FileList_Config, FileList_IPFilter, FileList_Hosts;
#if defined(ENABLE_LIBSODIUM)
std::vector<FILE_DATA> FileList_DNSCurveDatabase;
#endif
std::array<std::vector<DIFFERNET_FILE_SET_IPFILTER>, DIFFERNET_FILE_SET_NUM> IPFilterFileSet;
std::vector<DIFFERNET_FILE_SET_IPFILTER> *IPFilterFileSetUsing = &IPFilterFileSet.at(0), *IPFilterFileSetModificating = &IPFilterFileSet.at(1U);
std::array<std::vector<DIFFERNET_FILE_SET_HOSTS>, DIFFERNET_FILE_SET_NUM> HostsFileSet;
std::vector<DIFFERNET_FILE_SET_HOSTS> *HostsFileSetUsing = &HostsFileSet.at(0), *HostsFileSetModificating = &HostsFileSet.at(1U);
std::deque<SOCKET_REGISTER_DATA> SocketRegisterList;
#if defined(ENABLE_PCAP)
std::deque<OUTPUT_PACKET_TABLE> OutputPacketList;
std::mutex CaptureLock, OutputPacketListLock;
#endif
std::list<DNS_CACHE_DATA> DNSCacheList;
std::unordered_multimap<std::string, std::list<DNS_CACHE_DATA>::iterator> DNSCacheIndexList;
std::mutex ScreenLock, SocketRegisterLock, DNSCacheListLock, IPFilterFileLock, HostsFileLock;
std::array<std::mutex, NETWORK_LAYER_PARTNUM> LocalAddressLock;

//Functions
void ConfigurationTableSetting(
	CONFIGURATION_TABLE * const ConfigurationParameter);
void GlobalStatusSetting(
	GLOBAL_STATUS * const GlobalRunningStatusParameter);
#if defined(ENABLE_LIBSODIUM)
void DNSCurveConfigurationTableSetting(
	DNSCURVE_CONFIGURATION_TABLE * const DNSCurveConfigurationParameter);
#endif
#endif
