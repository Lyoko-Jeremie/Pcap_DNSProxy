// This code is part of Pcap_DNSProxy
// A local DNS server base on WinPcap and LibPcap.
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
CONFIGURATION_TABLE Parameter;
time_t StartTime, RunningLogStartTime;
ALTERNATE_SWAP_TABLE AlternateSwapList;
//PORT_TABLE PortList;
DNSCURVE_CONFIGURATON_TABLE DNSCurveParameter;
std::vector<std::wstring> ConfigFileList;
#if defined(PLATFORM_LINUX)
	extern std::vector<std::string> sConfigFileList;
#endif
std::vector<FILE_DATA> IPFilterFileList, HostsFileList;
std::vector<ADDRESS_RANGE_TABLE> AddressRangeList[2U], *AddressRangeUsing = &AddressRangeList[0], *AddressRangeModificating = &AddressRangeList[1U];
std::vector<HOSTS_TABLE> HostsList[2U], *HostsListUsing = &HostsList[0], *HostsListModificating = &HostsList[1U];
std::vector<RESULT_BLACKLIST_TABLE> ResultBlacklistList[2U], *ResultBlacklistUsing = &ResultBlacklistList[0], *ResultBlacklistModificating = &ResultBlacklistList[1U];
std::vector<ADDRESS_HOSTS_TABLE> AddressHostsList[2U], *AddressHostsListUsing = &AddressHostsList[0], *AddressHostsListModificating = &AddressHostsList[1U];
std::vector<ADDRESS_ROUTING_TABLE_IPV6> LocalRoutingList_IPv6[2U], *LocalRoutingList_IPv6_Using = &LocalRoutingList_IPv6[0], *LocalRoutingList_IPv6_Modificating = &LocalRoutingList_IPv6[1U];
std::vector<ADDRESS_ROUTING_TABLE_IPV4> LocalRoutingList_IPv4[2U], *LocalRoutingList_IPv4_Using = &LocalRoutingList_IPv4[0], *LocalRoutingList_IPv4_Modificating = &LocalRoutingList_IPv4[1U];
std::deque<PORT_TABLE> PortList;
std::deque<DNSCACHE_DATA> DNSCacheList;
std::mutex ErrLogLock, RunningLogLock, CaptureLock, PortListLock, LocalAddressLock[NETWORK_LAYER_PARTNUM], HostsListLock, DNSCacheListLock, AddressRangeLock, ResultBlacklistLock, AddressHostsListLock, LocalRoutingListLock;
