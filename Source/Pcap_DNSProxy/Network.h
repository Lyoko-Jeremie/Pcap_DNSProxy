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
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;
extern ALTERNATE_SWAP_TABLE AlternateSwapList;
#if defined(ENABLE_PCAP)
	extern std::deque<OUTPUT_PACKET_TABLE> OutputPacketList;
	extern std::mutex OutputPacketListLock;
#endif

//Functions
bool __fastcall SelectTargetSocket(
	_In_ const size_t RequestType, 
	_Out_ SOCKET_DATA *TargetSocketData, 
	_Outptr_opt_ bool **IsAlternate, 
	_Outptr_opt_ size_t **AlternateTimeoutTimes, 
	_In_ const uint16_t Protocol);
bool __fastcall SelectTargetSocketMulti(
	_Inout_ std::vector<SOCKET_DATA> &TargetSocketDataList, 
	_In_ const uint16_t Protocol);
SSIZE_T __fastcall SelectingResult(
	_In_ const size_t RequestType, 
	_In_ const uint16_t Protocol, 
	_Inout_ std::vector<SOCKET_DATA> &SocketDataList, 
	_Inout_ std::vector<SOCKET_SELECTING_DATA> &SocketSelectingList, 
	_Out_ char *OriginalRecv, 
	_In_ const size_t RecvSize);
void __fastcall MarkPortToList(
	_In_ const uint16_t Protocol, 
	_In_opt_ const SOCKET_DATA *LocalSocketData, 
	_In_ std::vector<SOCKET_DATA> &SocketDataList);
