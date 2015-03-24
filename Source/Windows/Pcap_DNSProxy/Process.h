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
extern CONFIGURATION_TABLE Parameter;
//extern ALTERNATE_SWAP_TABLE AlternateSwapList;
extern DNSCURVE_CONFIGURATON_TABLE DNSCurveParameter;
extern std::vector<HOSTS_TABLE> *HostsListUsing;
//extern std::deque<PORT_TABLE> PortList;
extern std::deque<DNSCACHE_DATA> DNSCacheList;
extern std::mutex LocalAddressLock[NETWORK_LAYER_PARTNUM], HostsListLock, DNSCacheListLock;

//Functions
size_t __fastcall CheckHosts(PSTR OriginalRequest, const size_t Length, PSTR Result, const size_t ResultSize, bool &IsLocal);
size_t __fastcall LocalRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA LocalSocketData);
size_t __fastcall DirectRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA LocalSocketData);
size_t __fastcall DNSCurveRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA LocalSocketData);
size_t __fastcall TCPRequestProcess(const PSTR OriginalSend, const size_t SendSize, PSTR OriginalRecv, const uint16_t Protocol, const SOCKET_DATA LocalSocketData);
size_t __fastcall UDPRequestProcess(const PSTR OriginalSend, const size_t SendSize, const SOCKET_DATA LocalSocketData, const uint16_t Protocol /* , const size_t ListIndex */ );
size_t __fastcall SendToRequester(PSTR RecvBuffer, const size_t RecvSize, const uint16_t Protocol, const SOCKET_DATA LocalSocketData);
