// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
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
std::vector<std::wstring> ConfigFileList;
std::vector<FILE_DATA> IPFilterFileList, HostsFileList;
PORT_TABLE PortList;
ALTERNATE_SWAP_TABLE AlternateSwapList;
DNSCURVE_CONFIGURATON_TABLE DNSCurveParameter;
std::vector<HOSTS_TABLE> HostsList[2U], *HostsListUsing = &HostsList[0], *HostsListModificating = &HostsList[1U];
std::vector<ADDRESS_RANGE_TABLE> AddressRangeList[2U], *AddressRangeUsing = &AddressRangeList[0], *AddressRangeModificating = &AddressRangeList[1U];
std::vector<RESULT_BLACKLIST_TABLE> ResultBlacklistList[2U], *ResultBlacklistUsing = &ResultBlacklistList[0], *ResultBlacklistModificating = &ResultBlacklistList[1U];
std::vector<ADDRESS_PREFIX_BLOCK> LocalRoutingList[2U], *LocalRoutingListUsing = &LocalRoutingList[0], *LocalRoutingListModificating = &LocalRoutingList[1U];
std::vector<ADDRESS_HOSTS_TABLE> AddressHostsList[2U], *AddressHostsListUsing = &AddressHostsList[0], *AddressHostsListModificating = &AddressHostsList[1U];
std::deque<DNSCACHE_DATA> DNSCacheList;
std::mutex ErrLogLock, RunningLogLock, CaptureLock, PortListLock, LocalAddressLock[QUEUE_PARTNUM / 2U], HostsListLock, DNSCacheListLock, AddressRangeLock, ResultBlacklistLock, AddressHostsListLock, LocalRoutingListLock;
