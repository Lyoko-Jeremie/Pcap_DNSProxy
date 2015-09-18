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
#if defined(PLATFORM_WIN)
	extern CONFIGURATION_TABLE Parameter;
	extern GLOBAL_STATUS GlobalRunningStatus;
#endif
extern std::deque<DNSCACHE_DATA> DNSCacheList;
extern std::mutex DNSCacheListLock;

#if defined(PLATFORM_WIN)
//Local variables
static DWORD ServiceCurrentStatus = 0;
static BOOL IsServiceRunning = FALSE;
SERVICE_STATUS_HANDLE ServiceStatusHandle = nullptr;
HANDLE ServiceEvent = nullptr;

//Functions
size_t WINAPI ServiceControl(
	const DWORD dwControlCode);
BOOL WINAPI ExecuteService(
	void);
void WINAPI TerminateService(
	void);
DWORD WINAPI ServiceProc(
	PVOID lpParameter);
BOOL WINAPI UpdateServiceStatus(
	const DWORD dwCurrentState, 
	const DWORD dwWin32ExitCode, 
	const DWORD dwServiceSpecificExitCode, 
	const DWORD dwCheckPoint, 
	const DWORD dwWaitHint);
#endif
