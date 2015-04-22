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
extern CONFIGURATION_TABLE Parameter;
extern DNSCURVE_CONFIGURATON_TABLE DNSCurveParameter;
extern std::vector<ADDRESS_RANGE_TABLE> *AddressRangeUsing;
extern std::vector<RESULT_BLACKLIST_TABLE> *ResultBlacklistUsing;
extern std::vector<ADDRESS_ROUTING_TABLE_IPV6> *LocalRoutingList_IPv6_Using;
extern std::vector<ADDRESS_ROUTING_TABLE_IPV4> *LocalRoutingList_IPv4_Using;
extern std::vector<ADDRESS_HOSTS_TABLE> *AddressHostsListUsing;
extern std::mutex LocalAddressLock[NETWORK_LAYER_PARTNUM], AddressRangeLock, LocalRoutingListLock, ResultBlacklistLock, AddressHostsListLock;

//Functions
#if defined(PLATFORM_LINUX)
	size_t GetBestInterfaceAddress(const uint16_t Protocol, const sockaddr_storage *OriginalSockAddr);
#endif
void __fastcall GetGatewayInformation(const uint16_t Protocol);
