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


#include "WindowsService.h"

//Catch Control-C exception from keyboard.
BOOL WINAPI CtrlHandler(const DWORD fdwCtrlType)
{
//Print to screen.
	if (Parameter.Console)
	{
	//Handle the CTRL-C signal.
		if (fdwCtrlType == CTRL_C_EVENT)
			wprintf_s(L"Get Control-C.\n");
	//Handle the CTRL-Break signal.
		else if (fdwCtrlType == CTRL_BREAK_EVENT)
			wprintf_s(L"Get Control-Break.\n");
	//Handle other signals.
		else 
			wprintf_s(L"Get closing signal.\n");
	}

	return FALSE;
}

//Service Main function
size_t WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
	ServiceStatusHandle = RegisterServiceCtrlHandlerW(DEFAULT_LOCAL_SERVICENAME, (LPHANDLER_FUNCTION)ServiceControl);
	if (!ServiceStatusHandle || !UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 0, 1U, UPDATE_SERVICE_TIME * SECOND_TO_MILLISECOND))
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
			UpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0, 1U, UPDATE_SERVICE_TIME * SECOND_TO_MILLISECOND);
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
		IsServiceRunning = TRUE;
		return TRUE;
	}

	return FALSE;
}

//Service Main process thread
DWORD WINAPI ServiceProc(PVOID lpParameter)
{
	if (!IsServiceRunning || MonitorInit() == EXIT_FAILURE)
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
	IsServiceRunning = FALSE;
	SetEvent(ServiceEvent);
	UpdateServiceStatus(SERVICE_STOPPED, NO_ERROR, 0, 0, 0);

	return;
}

//MailSlot of flush DNS cache Monitor
size_t WINAPI FlushDNSMailSlotMonitor(void)
{
//System security setting
	std::shared_ptr<SECURITY_ATTRIBUTES> SecurityAttributes(new SECURITY_ATTRIBUTES());
	std::shared_ptr<SECURITY_DESCRIPTOR> SecurityDescriptor(new SECURITY_DESCRIPTOR());
	std::shared_ptr<char> ACL_Buffer(new char[PACKET_MAXSIZE]());
	memset(ACL_Buffer.get(), 0, PACKET_MAXSIZE);
	PSID SID_Value = nullptr;

	InitializeSecurityDescriptor(SecurityDescriptor.get(), SECURITY_DESCRIPTOR_REVISION);
	InitializeAcl((PACL)ACL_Buffer.get(), PACKET_MAXSIZE, ACL_REVISION);
	ConvertStringSidToSidW(SID_ADMINISTRATORS_GROUP, &SID_Value);
	AddAccessAllowedAce((PACL)ACL_Buffer.get(), ACL_REVISION, GENERIC_ALL, SID_Value);
	SetSecurityDescriptorDacl(SecurityDescriptor.get(), true, (PACL)ACL_Buffer.get(), false);
	SecurityAttributes->lpSecurityDescriptor = SecurityDescriptor.get();
	SecurityAttributes->bInheritHandle = true;

//Create mailslot.
	HANDLE hSlot = CreateMailslotW(MAILSLOT_NAME, PACKET_MAXSIZE - 1U, MAILSLOT_WAIT_FOREVER, SecurityAttributes.get());
	if (hSlot == INVALID_HANDLE_VALUE)
	{
		LocalFree(SID_Value);

		PrintError(LOG_ERROR_SYSTEM, L"Create mailslot error", GetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

	ACL_Buffer.reset();
	LocalFree(SID_Value);

//Initialization
	BOOL Result = false, FlushDNS = false;
	DWORD cbMessage = 0, cMessage = 0, cAllMessages = 0, cbRead = 0;
	std::shared_ptr<wchar_t> lpszBuffer(new wchar_t[PACKET_MAXSIZE]());
	memset(lpszBuffer.get(), 0, PACKET_MAXSIZE);

//MailSlot Monitor
	for (;;)
	{
		FlushDNS = false;

	//Get mailslot messages.
		Result = GetMailslotInfo(hSlot, nullptr, &cbMessage, &cMessage, nullptr);
		if (!Result)
		{
			PrintError(LOG_ERROR_SYSTEM, L"Get mailslot error", GetLastError(), nullptr, 0);
			
			CloseHandle(hSlot);
			return EXIT_FAILURE;
		}

	//Wait for messages.
		if (cbMessage == MAILSLOT_NO_MESSAGE)
		{
			Sleep(MONITOR_LOOP_INTERVAL_TIME);
			continue;
		}

	//Got messages.
		cAllMessages = cMessage;
		while (cMessage > 0)
		{
			Result = ReadFile(hSlot, lpszBuffer.get(), cbMessage, &cbRead, nullptr);
			if (!Result)
			{
				PrintError(LOG_ERROR_SYSTEM, L"MailSlot read messages error", GetLastError(), nullptr, 0);
				
				CloseHandle(hSlot);
				return EXIT_FAILURE;
			}

			if (!FlushDNS && memcmp(lpszBuffer.get(), MAILSLOT_MESSAGE_FLUSH_DNS, wcslen(MAILSLOT_MESSAGE_FLUSH_DNS)) == 0)
			{
				FlushDNS = true;
				FlushSystemDNSCache();
			}
			memset(lpszBuffer.get(), 0, PACKET_MAXSIZE);

		//Get other mailslot messages.
			Result = GetMailslotInfo(hSlot, nullptr, &cbMessage, &cMessage, nullptr);
			if (!Result)
			{
				PrintError(LOG_ERROR_SYSTEM, L"Get mailslot error", GetLastError(), nullptr, 0);
				
				CloseHandle(hSlot);
				return EXIT_FAILURE;
			}
		}
	}

	CloseHandle(hSlot);
	PrintError(LOG_ERROR_SYSTEM, L"MailSlot module Monitor terminated", 0, nullptr, 0);
	return EXIT_FAILURE;
}

//MailSlot of flush DNS cache sender
size_t WINAPI FlushDNSMailSlotSender(void)
{
//Initialization
	BOOL Result = false;
	DWORD cbWritten = 0;

//Create mailslot.
	HANDLE hFile = CreateFileW(MAILSLOT_NAME, GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		PrintError(LOG_ERROR_SYSTEM, L"Create mailslot error", GetLastError(), nullptr, 0);
		return EXIT_FAILURE;
	}

//Write into mailslot.
	Result = WriteFile(hFile, MAILSLOT_MESSAGE_FLUSH_DNS, (DWORD)(lstrlenW(MAILSLOT_MESSAGE_FLUSH_DNS) + 1U) * sizeof(wchar_t), &cbWritten, nullptr);
	if (!Result)
	{
		PrintError(LOG_ERROR_SYSTEM, L"MailSlot write messages error", GetLastError(), nullptr, 0);

		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	CloseHandle(hFile);
	wprintf(L"Flush DNS cache message was sent successfully.\n");
	return EXIT_SUCCESS;
}
