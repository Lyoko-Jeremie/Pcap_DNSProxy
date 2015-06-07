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


#include "Service.h"

#if defined(PLATFORM_WIN)
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
	ServiceStatusHandle = RegisterServiceCtrlHandlerW(DEFAULT_LOCAL_SERVICE_NAME, (LPHANDLER_FUNCTION)ServiceControl);
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
	if (!IsServiceRunning || !MonitorInit())
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
bool WINAPI FlushDNSMailSlotMonitor(void)
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
		return false;
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
			return false;
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
				return false;
			}

			if (!FlushDNS && memcmp(lpszBuffer.get(), MAILSLOT_MESSAGE_FLUSH_DNS, wcslen(MAILSLOT_MESSAGE_FLUSH_DNS)) == 0)
			{
				FlushDNS = true;
				FlushAllDNSCache();
			}
			memset(lpszBuffer.get(), 0, PACKET_MAXSIZE);

		//Get other mailslot messages.
			Result = GetMailslotInfo(hSlot, nullptr, &cbMessage, &cMessage, nullptr);
			if (!Result)
			{
				PrintError(LOG_ERROR_SYSTEM, L"Get mailslot error", GetLastError(), nullptr, 0);
				
				CloseHandle(hSlot);
				return false;
			}
		}
	}

	CloseHandle(hSlot);
	PrintError(LOG_ERROR_SYSTEM, L"MailSlot module Monitor terminated", 0, nullptr, 0);
	return false;
}

//MailSlot of flush DNS cache sender
bool WINAPI FlushDNSMailSlotSender(void)
{
//Initialization
	DWORD cbWritten = 0;

//Create mailslot.
	HANDLE hFile = CreateFileW(MAILSLOT_NAME, GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		wprintf_s(L"Create mailslot error, error code is %lu.\n", GetLastError());
		return false;
	}

//Write into mailslot.
	if (!WriteFile(hFile, MAILSLOT_MESSAGE_FLUSH_DNS, (DWORD)(lstrlenW(MAILSLOT_MESSAGE_FLUSH_DNS) + 1U) * sizeof(wchar_t), &cbWritten, nullptr))
	{
		wprintf_s(L"MailSlot write messages error, error code is %lu.\n", GetLastError());

		CloseHandle(hFile);
		return false;
	}

	CloseHandle(hFile);
	wprintf_s(L"Flush DNS cache message was sent successfully.\n");
	return true;
}

#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Flush DNS cache FIFO Monitor
bool FlushDNSFIFOMonitor(void)
{
//Initialization
	unlink(FIFO_PATH_NAME);
	std::shared_ptr<char> Buffer(new char[PACKET_MAXSIZE]());
	memset(Buffer.get(), 0, PACKET_MAXSIZE);
	int FIFO_FD = 0;

//Create FIFO.
	if (mkfifo(FIFO_PATH_NAME, O_CREAT) < 0 || chmod(FIFO_PATH_NAME, S_IRUSR|S_IWUSR|S_IWGRP|S_IWOTH) < 0)
	{
		PrintError(LOG_ERROR_SYSTEM, L"Create FIFO error", errno, nullptr, 0);

		unlink(FIFO_PATH_NAME);
		return false;
	}

//Open FIFO.
	FIFO_FD = open(FIFO_PATH_NAME, O_RDONLY, 0);
	if (FIFO_FD < 0)
	{
		PrintError(LOG_ERROR_SYSTEM, L"Create FIFO error", errno, nullptr, 0);

		unlink(FIFO_PATH_NAME);
		return false;
	}

//FIFO Monitor
	for (;;)
	{
		if (read(FIFO_FD, Buffer.get(), PACKET_MAXSIZE) > 0 && 
			memcmp(Buffer.get(), FIFO_MESSAGE_FLUSH_DNS, strlen(FIFO_MESSAGE_FLUSH_DNS)) == 0)
				FlushAllDNSCache();

		memset(Buffer.get(), 0, PACKET_MAXSIZE);
		Sleep(MONITOR_LOOP_INTERVAL_TIME);
	}

	close(FIFO_FD);
	unlink(FIFO_PATH_NAME);
	PrintError(LOG_ERROR_SYSTEM, L"FIFO module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Flush DNS cache FIFO sender
bool FlushDNSFIFOSender(void)
{
	int FIFO_FD = open(FIFO_PATH_NAME, O_WRONLY|O_TRUNC|O_NONBLOCK, 0);
	if (FIFO_FD > 0 && write(FIFO_FD, FIFO_MESSAGE_FLUSH_DNS, strlen(FIFO_MESSAGE_FLUSH_DNS)) > 0)
	{
		wprintf(L"Flush DNS cache message was sent successfully.\n");
		close(FIFO_FD);
	}
	else {
		wprintf(L"FIFO write messages error, error code is %d.\n", errno);
		return false;
	}

	return true;
}
#endif

//Flush DNS cache
void __fastcall FlushAllDNSCache(void)
{
//Flush DNS cache in program.
	std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	DNSCacheList.clear();
	DNSCacheList.shrink_to_fit();
	DNSCacheListMutex.unlock();

//Flush DNS cache in system.
#if defined(PLATFORM_WIN)
	system("ipconfig /flushdns");
#elif defined(PLATFORM_LINUX)
	system("service nscd restart"); //Name Service Cache Daemon service
	system("service dnsmasq restart"); //Dnsmasq service
	system("rndc restart"); //Name server control utility or BIND DNS service
#elif defined(PLATFORM_MACX)
//	system("lookupd -flushcache"); //Less than Mac OS X Tiger(10.4)
//	system("dscacheutil -flushcache"); //Mac OS X Leopard(10.5) and Snow Leopard(10.6)
	system("killall -HUP mDNSResponder"); //Mac OS X Lion(10.7), Mountain Lion(10.8) and Mavericks(10.9)
	system("discoveryutil mdnsflushcache"); //Mac OS X Yosemite(10.10) and other latest version
#endif

	return;
}
