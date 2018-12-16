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


#ifndef PCAP_DNSPROXY_SERVICE_H
#define PCAP_DNSPROXY_SERVICE_H

#include "Include.h"

//Global variables
extern CONFIGURATION_TABLE Parameter;
extern GLOBAL_STATUS GlobalRunningStatus;
extern std::list<DNS_CACHE_DATA> DNSCacheList;
extern std::unordered_multimap<std::string, std::list<DNS_CACHE_DATA>::iterator> DNSCacheIndexList;
extern std::mutex ScreenLock, DNSCacheListLock;

//Local variables
#if defined(PLATFORM_WIN)
static DWORD ServiceCurrentStatus = 0;
static auto IsServiceRunning = false;
SERVICE_STATUS_HANDLE ServiceStatusHandle = nullptr;
HANDLE ServiceEvent = nullptr;
#endif
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
uint64_t LastFlushCacheTime = 0;
#endif

//Functions
#if defined(PLATFORM_WIN)
bool SystemSecurityInit(
	const ACL * const ACL_Buffer, 
	SECURITY_ATTRIBUTES &SecurityAttributes, 
	SECURITY_DESCRIPTOR &SecurityDescriptor, 
	PSID &SID_Value);
DWORD WINAPI ServiceControl(
	const DWORD ControlCode, 
	const DWORD EventType, 
	const LPVOID EventData, 
	const LPVOID Context);
HANDLE WINAPI ExecuteService(
	void);
void WINAPI TerminateService(
	void);
DWORD WINAPI ServiceProc(
	PVOID ProcParameter);
bool WINAPI UpdateServiceStatus(
	const DWORD CurrentState, 
	const DWORD ExitCode, 
	const DWORD ServiceSpecificExitCode, 
	const DWORD CheckPoint, 
	const DWORD WaitHint);
#endif
#endif
