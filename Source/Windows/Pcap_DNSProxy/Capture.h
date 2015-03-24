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
extern ALTERNATE_SWAP_TABLE AlternateSwapList;
extern std::deque<PORT_TABLE> PortList;
//extern std::deque<DNSCACHE_DATA> DNSCacheList;
extern std::mutex CaptureLock, PortListLock;
std::string PcapFilterRules;
std::vector<std::string> PcapRunning;

//Functions
void __fastcall FilterRulesInit(std::string &FilterRules);
size_t __fastcall Capture(const pcap_if *pDrive, const bool IsCaptureList);
size_t __fastcall NetworkLayer(const PSTR Recv, const size_t Length, const uint16_t Protocol);
bool __fastcall ICMPCheck(const PSTR Buffer, const size_t Length, const uint16_t Protocol);
bool __fastcall TCPCheck(const PSTR Buffer);
//size_t __fastcall DNSMethod(const PSTR Recv, const size_t Length, const uint16_t Protocol);
size_t __fastcall MatchPortToSend(const PSTR Buffer, const size_t Length, const uint16_t Protocol, const uint16_t Port);
