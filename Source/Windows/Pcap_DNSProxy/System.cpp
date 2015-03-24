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


#include "System.h"

//Windows XP with SP3 support
#ifdef _WIN64
#else //x86
//Verify version of system(Greater than Windows Vista)
BOOL WINAPI IsGreaterThanVista(void)
{
	std::shared_ptr<OSVERSIONINFOEXW> OSVI(new OSVERSIONINFOEXW());
	memset(OSVI.get(), 0, sizeof(OSVERSIONINFOEXW));
	DWORDLONG dwlConditionMask = 0;

//Initialization
	ZeroMemory(OSVI.get(), sizeof(OSVERSIONINFOEXW));
	OSVI->dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	OSVI->dwMajorVersion = 6U; //Greater than Windows Vista.
	OSVI->dwMinorVersion = 0;

//System Major version > dwMajorVersion
	VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_GREATER);
	if (VerifyVersionInfoW(OSVI.get(), VER_MAJORVERSION, dwlConditionMask))
		return TRUE;

//Sytem Major version = dwMajorVersion and Minor version > dwMinorVersion
	VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_EQUAL);
	VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_GREATER);
	return VerifyVersionInfoW(OSVI.get(), VER_MAJORVERSION|VER_MINORVERSION, dwlConditionMask);
}

//Try to load library to get pointers of functions
BOOL WINAPI GetFunctionPointer(const size_t FunctionType)
{
//GetTickCount64() function
	if (FunctionType == FUNCTION_GETTICKCOUNT64)
	{
		Parameter.GetTickCount64DLL = LoadLibraryW(L"Kernel32.dll");
		if (Parameter.GetTickCount64DLL != nullptr)
		{
			Parameter.GetTickCount64PTR = (GetTickCount64Function)GetProcAddress(Parameter.GetTickCount64DLL, "GetTickCount64");
			if (Parameter.GetTickCount64PTR == nullptr)
			{
				FreeLibrary(Parameter.GetTickCount64DLL);
				return FALSE;
			}
		}
	}
//inet_ntop() function
	else if (FunctionType == FUNCTION_INET_NTOP)
	{
		Parameter.Inet_Ntop_DLL = LoadLibraryW(L"ws2_32.dll");
		if (Parameter.Inet_Ntop_DLL != nullptr)
		{
			Parameter.Inet_Ntop_PTR = (Inet_Ntop_Function)GetProcAddress(Parameter.Inet_Ntop_DLL, "inet_ntop");
			if (Parameter.Inet_Ntop_PTR == nullptr)
			{
				FreeLibrary(Parameter.Inet_Ntop_DLL);
				return FALSE;
			}
		}
	}

	return TRUE;
}
#endif

//Catch Control-C exception from keyboard.
BOOL WINAPI CtrlHandler(const DWORD fdwCtrlType)
{
/*
	switch (fdwCtrlType)
	{
	//Handle the CTRL-C signal.
		case CTRL_C_EVENT:
		{
			if (Parameter.Console)
				wprintf_s(L"Get Control-C.\n");
			return FALSE;
		}
	//Handle the CTRL-Break signal.
		case CTRL_BREAK_EVENT:
		{
			if (Parameter.Console)
				wprintf_s(L"Get Control-Break.\n");
			return FALSE;
		}
	//Handle the Closing program signal.
		case CTRL_CLOSE_EVENT:
		{
			return FALSE;
		}
	//Handle the Closing program signal.
		case CTRL_LOGOFF_EVENT:
		{
			return FALSE;
		}
	//Handle the shutdown signal.
		case CTRL_SHUTDOWN_EVENT:
		{
			return FALSE;
		}
//		default: {
//			return FALSE;
//		}
	}
*/
//Print to screen.
	if (Parameter.Console)
	{
	//Handle the CTRL-C signal.
		if (fdwCtrlType == CTRL_C_EVENT)
			wprintf_s(L"Get Control-C.\n");
	//Handle the CTRL-Break signal.
		else if (fdwCtrlType == CTRL_BREAK_EVENT)
			wprintf_s(L"Get Control-Break.\n");
	}

	return FALSE;
}

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
	return EXIT_SUCCESS;
}

//Start Main process
BOOL WINAPI ExecuteService(void)
{
	DWORD dwThreadID = 0;
	HANDLE hServiceThread = CreateThread(0, 0, (PTHREAD_START_ROUTINE)ServiceProc, nullptr, 0, &dwThreadID);
	if (hServiceThread != nullptr)
	{
		ServiceRunning = TRUE;
		return TRUE;
	}

	return FALSE;
}

//Service Main process thread
DWORD WINAPI ServiceProc(PVOID lpParameter)
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
	std::shared_ptr<SERVICE_STATUS> ServiceStatus(new SERVICE_STATUS());
	memset(ServiceStatus.get(), 0, sizeof(SERVICE_STATUS));
	ServiceStatus->dwServiceType = SERVICE_WIN32;
	ServiceStatus->dwCurrentState = dwCurrentState;

	if (dwCurrentState == SERVICE_START_PENDING)
		ServiceStatus->dwControlsAccepted = 0;
	else
		ServiceStatus->dwControlsAccepted = (SERVICE_ACCEPT_STOP|SERVICE_ACCEPT_SHUTDOWN);

	if (dwServiceSpecificExitCode == 0)
		ServiceStatus->dwWin32ExitCode = dwWin32ExitCode;
	else
		ServiceStatus->dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;

	ServiceStatus->dwServiceSpecificExitCode = dwServiceSpecificExitCode;
	ServiceStatus->dwCheckPoint = dwCheckPoint;
	ServiceStatus->dwWaitHint = dwWaitHint;

	if (!SetServiceStatus(ServiceStatusHandle, ServiceStatus.get()))
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
