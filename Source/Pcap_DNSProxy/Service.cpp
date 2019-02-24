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


#include "Service.h"

#if defined(PLATFORM_WIN)
//Load system service and connect to service manager
bool LoadService(
	void)
{
//Service initialization
	std::array<SERVICE_TABLE_ENTRYW, SERVICE_TABLE_ENTRY_NUM> ServiceTable{};
	ServiceTable.at(0).lpServiceName = const_cast<const LPWSTR>(PROGRAM_SERVICE_NAME);
	ServiceTable.at(0).lpServiceProc = reinterpret_cast<const LPSERVICE_MAIN_FUNCTIONW>(ServiceMain);
	ServiceTable.at(1U).lpServiceName = nullptr;
	ServiceTable.at(1U).lpServiceProc = nullptr;

//Dispatch service.
	if (StartServiceCtrlDispatcherW(ServiceTable.data()) == 0)
	{
	//Print error message to screen.
		std::wstring Message(L"[System Error] Service start error");
		if (GetLastError() == 0)
		{
			Message.append(L".\n");
			std::lock_guard<std::mutex> ScreenMutex((*GlobalRunningStatus.ScreenLock));
			PrintToScreen(false, false, Message.c_str());
			PrintToScreen(false, false, L"[Notice] Program will continue to run in console mode.\n");
			PrintToScreen(false, false, L"[Notice] Please ignore these error messages if you want to run in console mode.\n\n");
		}
		else {
			ErrorCodeToMessage(LOG_ERROR_TYPE::SYSTEM, GetLastError(), Message);
			Message.append(L".\n");
			std::lock_guard<std::mutex> ScreenMutex((*GlobalRunningStatus.ScreenLock));
			PrintToScreen(false, false, Message.c_str(), GetLastError());
			PrintToScreen(false, false, L"[Notice] Program will continue to run in console mode.\n");
			PrintToScreen(false, false, L"[Notice] Please ignore these error messages if you want to run in console mode.\n\n");
		}

	//Try load directly.
		return true;
	}

	return false;
}

//Service main function
VOID WINAPI ServiceMain(
	DWORD argc, 
	LPTSTR * argv)
{
//Disable console mode printing.
	GlobalRunningStatus.IsConsole = false;

//Service initialization
	ServiceStatusHandle = RegisterServiceCtrlHandlerExW(
		PROGRAM_SERVICE_NAME, 
		reinterpret_cast<LPHANDLER_FUNCTION_EX>(ServiceController), 
		nullptr);
	if (ServiceStatusHandle == nullptr)
		return;

//Update service to PENDING status(Update service timeout).
	if (!UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 0, 1U, UPDATE_SERVICE_TIME))
	{
		CloseHandle(
			ServiceStatusHandle);
		return;
	}

//Create service event.
	ServiceEvent = CreateEventW(
		nullptr, 
		TRUE, 
		FALSE, 
		nullptr);
	if (ServiceEvent == nullptr)
	{
		CloseHandle(
			ServiceStatusHandle);
		return;
	}

//Update service to PENDING status(Standard timeout).
	if (!UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 0, 2U, STANDARD_TIMEOUT))
	{
		CloseHandle(
			ServiceStatusHandle);
		CloseHandle(
			ServiceEvent);

		return;
	}

//Create thread.
	const auto ServiceThread = ExecuteService();
	if (ServiceThread == nullptr)
	{
		CloseHandle(
			ServiceStatusHandle);
		CloseHandle(
			ServiceEvent);

		return;
	}

//Update service to RUNNING status.
	ServiceCurrentStatus = SERVICE_RUNNING;
	if (!UpdateServiceStatus(SERVICE_RUNNING, NO_ERROR, 0, 0, 0))
	{
		CloseHandle(
			ServiceStatusHandle);
		CloseHandle(
			ServiceEvent);
		CloseHandle(
			ServiceThread);

		return;
	}

//Wait signal to shutdown.
	WaitForSingleObject(
		ServiceEvent, 
		INFINITE);
	CloseHandle(
		ServiceStatusHandle);
	CloseHandle(
		ServiceEvent);
	CloseHandle(
		ServiceThread);

	return;
}

//Service controller
DWORD WINAPI ServiceController(
	const DWORD ControlCode, 
	const DWORD EventType, 
	const LPVOID EventData, 
	const LPVOID Context)
{
	switch(ControlCode)
	{
	//Handle the will be shutdown signal.
	#if !defined(PLATFORM_WIN_XP)
		case SERVICE_CONTROL_PRESHUTDOWN:
		{
			TerminateService();
			return EXIT_SUCCESS;
		}
	#endif
	//Handle the shutdown signal.
		case SERVICE_CONTROL_SHUTDOWN:
		{
			TerminateService();
			return EXIT_SUCCESS;
		}
	//Handle the stop signal.
		case SERVICE_CONTROL_STOP:
		{
			ServiceCurrentStatus = SERVICE_STOP_PENDING;
			UpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0, 1U, UPDATE_SERVICE_TIME);
			TerminateService();

			return EXIT_SUCCESS;
		}
	//Handle other signals.
		default:
		{
			break;
		}
	}

//Update service status and return.
	UpdateServiceStatus(ServiceCurrentStatus, NO_ERROR, 0, 0, 0);
	return EXIT_SUCCESS;
}

//Execute main process
HANDLE WINAPI ExecuteService(
	void)
{
	DWORD ThreadID = 0;
	const auto ServiceThread = CreateThread(
		nullptr, 
		0, 
		reinterpret_cast<PTHREAD_START_ROUTINE>(ServiceProcThread), 
		nullptr, 
		0, 
		&ThreadID);
	if (ServiceThread != nullptr)
	{
		IsServiceRunning = true;
		return ServiceThread;
	}

	return nullptr;
}

//Service main process thread
DWORD WINAPI ServiceProcThread(
	PVOID ProcParameter)
{
//Start main process.
//Temporary Disabled
	if (!IsServiceRunning /* || !LoadMainProcess() */ )
	{
		TerminateService();
		return 0;
	}

//Update service status and return.
	TerminateService();
	return EXIT_SUCCESS;
}

//Change status of service
bool WINAPI UpdateServiceStatus(
	const DWORD CurrentState, 
	const DWORD ExitCode, 
	const DWORD ServiceSpecificExitCode, 
	const DWORD CheckPoint, 
	const DWORD WaitHint)
{
//Initialization
	SERVICE_STATUS ServiceStatus;
	memset(&ServiceStatus, 0, sizeof(ServiceStatus));
	ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	ServiceStatus.dwCurrentState = CurrentState;
	if (CurrentState == SERVICE_START_PENDING)
		ServiceStatus.dwControlsAccepted = 0;
	else 
		ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	if (ServiceSpecificExitCode == 0)
		ServiceStatus.dwWin32ExitCode = ExitCode;
	else 
		ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
	ServiceStatus.dwServiceSpecificExitCode = ServiceSpecificExitCode;
	ServiceStatus.dwCheckPoint = CheckPoint;
	ServiceStatus.dwWaitHint = WaitHint;

//Service status setting
	if (SetServiceStatus(
			ServiceStatusHandle, 
			&ServiceStatus) == 0)
	{
		TerminateService();
		return false;
	}

	return true;
}

//Terminate service
void WINAPI TerminateService(
	void)
{
	IsServiceRunning = false;
	SetEvent(
		ServiceEvent);
	UpdateServiceStatus(SERVICE_STOPPED, NO_ERROR, 0, 0, 0);

	return;
}
#endif
