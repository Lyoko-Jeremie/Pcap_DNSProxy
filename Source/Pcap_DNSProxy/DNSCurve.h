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
#if defined(ENABLE_LIBSODIUM)
//Global variables
	extern CONFIGURATION_TABLE Parameter;
	extern ALTERNATE_SWAP_TABLE AlternateSwapList;
	extern DNSCURVE_CONFIGURATON_TABLE DNSCurveParameter;

//Functions
	size_t DNSCurveSignatureRequest(const char *OriginalSend, const size_t SendSize, PSTR OriginalRecv, const size_t RecvSize);
	size_t __fastcall SelectTargetSocket(SOCKET_DATA *SockData, PDNSCURVE_SERVER_DATA &PacketTarget, bool *&IsAlternate, size_t *&AlternateTimeoutTimes, const uint16_t Protocol);
	bool __fastcall SelectTargetSocketMulti(bool &IsIPv6, bool *&IsAlternate, const uint16_t Protocol);
	bool __fastcall DNSCurveTCPSignatureRequest(const uint16_t Protocol, const bool IsAlternate);
	bool __fastcall DNSCurveUDPSignatureRequest(const uint16_t Protocol, const bool IsAlternate);
	bool __fastcall DNSCruveGetSignatureData(const char *Buffer, const size_t ServerType);
#endif
