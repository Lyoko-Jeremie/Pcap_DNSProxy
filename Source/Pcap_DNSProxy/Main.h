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
extern CONFIGURATION_TABLE Parameter, ParameterModificating;
extern GLOBAL_STATUS GlobalRunningStatus;
#if defined(ENABLE_LIBSODIUM)
	extern DNSCURVE_CONFIGURATION_TABLE DNSCurveParameter, DNSCurveParameterModificating;
#endif

//Functions
#if defined(PLATFORM_WIN)
bool __fastcall ReadCommand(
	int argc, 
	wchar_t *argv[]);
bool __fastcall FileNameInit(
	const wchar_t *OriginalPath);
bool __fastcall FirewallTest(
	const uint16_t Protocol);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
bool ReadCommand(
	int argc, 
	char *argv[]);
bool FileNameInit(
	const char *OriginalPath);
#endif
