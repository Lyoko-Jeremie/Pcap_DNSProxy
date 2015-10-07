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
CONFIGURATION_TABLE Parameter, ParameterModificating;
GLOBAL_STATUS GlobalRunningStatus;
ALTERNATE_SWAP_TABLE AlternateSwapList;
#if defined(ENABLE_LIBSODIUM)
	DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter, DNSCurveParameterModificating;
#endif
std::vector<FILE_DATA> FileList_Config, FileList_IPFilter, FileList_Hosts;
std::vector<DIFFERNET_IPFILTER_FILE_SET> IPFilterFileSet[2U], *IPFilterFileSetUsing = &IPFilterFileSet[0], *IPFilterFileSetModificating = &IPFilterFileSet[1U];
std::vector<DIFFERNET_HOSTS_FILE_SET> HostsFileSet[2U], *HostsFileSetUsing = &HostsFileSet[0], *HostsFileSetModificating = &HostsFileSet[1U];
#if defined(ENABLE_PCAP)
	std::deque<OUTPUT_PACKET_TABLE> OutputPacketList;
#endif
std::deque<DNSCACHE_DATA> DNSCacheList;
std::mutex ErrorLogLock, CaptureLock, LocalAddressLock[NETWORK_LAYER_PARTNUM], DNSCacheListLock, IPFilterFileLock, HostsFileLock;
#if defined(ENABLE_PCAP)
	std::mutex OutputPacketListLock;
#endif

//Functions
void __fastcall ConfigurationTableSetting(
	ConfigurationTable *ConfigurationParameter);
void __fastcall GlobalStatusSetting(
	GlobalStatus *GlobalRunningStatusParameter);
