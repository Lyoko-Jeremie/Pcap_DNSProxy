// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on packet capturing
// Copyright (C) 2012-2019 Chengr28
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

//Global variable
extern GLOBAL_STATUS GlobalRunningStatus;

//Localization variable
#if defined(PLATFORM_WIN)
static DWORD ServiceCurrentStatus = 0;
static auto IsServiceRunning = false;
SERVICE_STATUS_HANDLE ServiceStatusHandle = nullptr;
HANDLE ServiceEvent = nullptr;

//Localization function
VOID WINAPI ServiceMain(
	DWORD argc, 
	LPTSTR * argv);
DWORD WINAPI ServiceController(
	const DWORD ControlCode, 
	const DWORD EventType, 
	const LPVOID EventData, 
	const LPVOID Context);
HANDLE WINAPI ExecuteService(
	void);
DWORD WINAPI ServiceProcThread(
	PVOID ProcParameter);
bool WINAPI UpdateServiceStatus(
	const DWORD CurrentState, 
	const DWORD ExitCode, 
	const DWORD ServiceSpecificExitCode, 
	const DWORD CheckPoint, 
	const DWORD WaitHint);
void WINAPI TerminateService(
	void);
#endif
#endif
