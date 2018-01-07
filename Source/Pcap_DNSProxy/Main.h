// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2018 Chengr28
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


#ifndef PCAP_DNSPROXY_MAIN_H
#define PCAP_DNSPROXY_MAIN_H

#include "Base.h"

//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;
extern std::mutex ScreenLock;

//Functions in ReadCommand.cpp
#if defined(PLATFORM_WIN)
bool ReadCommand(
	int argc, 
	wchar_t *argv[]);
bool FileNameInit(
	const std::wstring &OriginalPath);
#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
bool ReadCommand(
	int argc, 
	char *argv[]);
bool FileNameInit(
	const std::string &OriginalPath);
#endif
#endif
