// This code is part of Pcap_DNSProxy(Windows)
// Pcap_DNSProxy, A local DNS server base on WinPcap and LibPcap.
// Copyright (C) 2012-2014 Chengr28
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


#include "Pcap_DNSProxy.h"

static DWORD ServiceCurrentStatus = 0;
static BOOL ServiceRunning = false;
SERVICE_STATUS_HANDLE ServiceStatusHandle = nullptr; 
HANDLE ServiceEvent = nullptr;

//Service Main function
size_t WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	ServiceStatusHandle = RegisterServiceCtrlHandlerW(DEFAULT_LOCAL_SERVICENAME, (LPHANDLER_FUNCTION)ServiceControl);
	if (!ServiceStatusHandle || !UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 0, 1U, UPDATESERVICE_TIME * SECOND_TO_MILLISECOND))
		return FALSE;

	ServiceEvent = CreateEventW(0, TRUE, FALSE, 0);
	if (!ServiceEvent || !UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 0, 2U, STANDARD_TIMEOUT) || !ExecuteService())
		return FALSE;

	ServiceCurrentStatus = SERVICE_RUNNING;
	if (!UpdateServiceStatus(SERVICE_RUNNING, NO_ERROR, 0, 0, 0))
		return FALSE;

	WaitForSingleObject(ServiceEvent, INFINITE);
	CloseHandle(ServiceEvent);
	return EXIT_SUCCESS;
}

//Service controller
size_t WINAPI ServiceControl(const DWORD dwControlCode)
{
	switch(dwControlCode)
	{
		case SERVICE_CONTROL_SHUTDOWN:
		{
			WSACleanup();
			TerminateService();

			return EXIT_SUCCESS;
		}
		case SERVICE_CONTROL_STOP:
		{
			ServiceCurrentStatus = SERVICE_STOP_PENDING;
			UpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0, 1U, UPDATESERVICE_TIME * SECOND_TO_MILLISECOND);
			WSACleanup();
			TerminateService();

			return EXIT_SUCCESS;
		}
		default:
		{
			break;
		}
	}

	UpdateServiceStatus(ServiceCurrentStatus, NO_ERROR, 0, 0, 0);
	return 0;
}

//Start Main process
BOOL WINAPI ExecuteService(void)
{
	DWORD dwThreadID = 0;
	HANDLE hServiceThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ServiceProc, NULL, 0, &dwThreadID);

	if (hServiceThread != nullptr)
	{
		ServiceRunning = TRUE;
		return TRUE;
	}

	return FALSE;
}

//Service Main process thread
DWORD WINAPI ServiceProc(LPVOID lpParameter)
{
	if (!ServiceRunning || MonitorInit() == EXIT_FAILURE)
	{
		WSACleanup();
		TerminateService();
		return FALSE;
	}

	WSACleanup();
	TerminateService();
	return EXIT_SUCCESS;
}

//Change status of service
BOOL WINAPI UpdateServiceStatus(const DWORD dwCurrentState, const DWORD dwWin32ExitCode, const DWORD dwServiceSpecificExitCode, const DWORD dwCheckPoint, const DWORD dwWaitHint)
{
	SERVICE_STATUS ServiceStatus = {0};
	ServiceStatus.dwServiceType = SERVICE_WIN32;
	ServiceStatus.dwCurrentState = dwCurrentState;

	if (dwCurrentState == SERVICE_START_PENDING)
		ServiceStatus.dwControlsAccepted = 0;
	else
		ServiceStatus.dwControlsAccepted = (SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN);

	if (dwServiceSpecificExitCode == 0)
		ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
	else
		ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;

	ServiceStatus.dwServiceSpecificExitCode = dwServiceSpecificExitCode;
	ServiceStatus.dwCheckPoint = dwCheckPoint;
	ServiceStatus.dwWaitHint = dwWaitHint;

	if (!SetServiceStatus(ServiceStatusHandle, &ServiceStatus))
	{
		WSACleanup();
		TerminateService();
		return FALSE;
 	}

	return TRUE;
}

//Terminate service
void WINAPI TerminateService(void)
{
	ServiceRunning = FALSE;
	SetEvent(ServiceEvent);
	UpdateServiceStatus(SERVICE_STOPPED, NO_ERROR, 0, 0, 0);

	return;
}
