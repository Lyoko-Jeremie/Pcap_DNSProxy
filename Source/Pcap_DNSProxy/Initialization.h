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
CONFIGURATION_TABLE Parameter, ParameterModificating;
GLOBAL_STATUS GlobalRunningStatus;
ALTERNATE_SWAP_TABLE AlternateSwapList;
BLOCKING_QUEUE<MONITOR_QUEUE_DATA> MonitorBlockingQueue;
#if defined(ENABLE_LIBSODIUM)
DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter, DNSCurveParameterModificating;
#endif
std::vector<FILE_DATA> FileList_Config, FileList_IPFilter, FileList_Hosts;
std::vector<DIFFERNET_FILE_SET_IPFILTER> IPFilterFileSet[2U], *IPFilterFileSetUsing = &IPFilterFileSet[0], *IPFilterFileSetModificating = &IPFilterFileSet[1U];
std::vector<DIFFERNET_FILE_SET_HOSTS> HostsFileSet[2U], *HostsFileSetUsing = &HostsFileSet[0], *HostsFileSetModificating = &HostsFileSet[1U];
#if defined(ENABLE_PCAP)
std::deque<OUTPUT_PACKET_TABLE> OutputPacketList;
std::mutex OutputPacketListLock;
#endif
std::list<DNS_CACHE_DATA> DNSCacheList;
std::mutex ScreenLock, ErrorLogLock, CaptureLock, LocalAddressLock[NETWORK_LAYER_PARTNUM], DNSCacheListLock, IPFilterFileLock, HostsFileLock;

//Functions
void ConfigurationTableSetting(
	CONFIGURATION_TABLE *ConfigurationParameter);
void GlobalStatusSetting(
	GLOBAL_STATUS *GlobalRunningStatusParameter);
#if defined(ENABLE_LIBSODIUM)
void DNSCurveConfigurationTableSetting(
	DNSCURVE_CONFIGURATION_TABLE *DNSCurveConfigurationParameter);
#endif
