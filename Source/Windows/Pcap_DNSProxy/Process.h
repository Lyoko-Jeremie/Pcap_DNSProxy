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
extern ConfigurationTable Parameter;
extern PortTable PortList;
extern AlternateSwapTable AlternateSwapList;
extern DNSCurveConfigurationTable DNSCurveParameter;
extern std::vector<HostsTable> *HostsListUsing;
extern std::deque<DNSCacheData> DNSCacheList;
extern std::mutex LocalAddressLock[QUEUE_PARTNUM / 2U], HostsListLock, DNSCacheListLock;
/* Old version(2014-09-13)
static const std::regex IPv4PrivateB(".(1[6-9]|2[0-9]|3[01]).172.in-addr.arpa", std::regex_constants::extended);
static const std::regex IPv6ULA(".f.[cd].([0-9]|[a-f]).([0-9]|[a-f]).ip6.arpa", std::regex_constants::extended);
static const std::regex IPv6LUC(".f.f.([89]|[ab]).([0-9]|[a-f]).ip6.arpa", std::regex_constants::extended);
*/

//Functions
size_t __fastcall CheckHosts(PSTR OriginalRequest, const size_t Length, PSTR Result, const size_t ResultSize, bool &IsLocal);
size_t __fastcall LocalRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA TargetData);
size_t __fastcall DirectRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA TargetData);
size_t __fastcall DNSCurveRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA TargetData);
size_t __fastcall TCPRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA TargetData);
size_t __fastcall UDPRequestProcess(const PSTR OriginalSend, const size_t SendSize, const uint16_t Protocol, const SOCKET_DATA TargetData, const size_t ListIndex);
size_t __fastcall SendToRequester(PSTR RecvBuffer, const size_t RecvSize, const uint16_t Protocol, const SOCKET_DATA TargetData);
