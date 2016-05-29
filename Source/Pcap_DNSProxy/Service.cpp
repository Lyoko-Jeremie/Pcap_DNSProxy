// This code is part of Pcap_DNSProxy
// A local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2016 Chengr28
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
BOOL WINAPI CtrlHandler(
	const DWORD fdwCtrlType)
{
//Print to screen.
	if (GlobalRunningStatus.Console)
	{
		std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
		switch (fdwCtrlType)
		{
			case CTRL_C_EVENT: //Handle the CTRL-C signal.
			{
				fwprintf_s(stderr, L"Get Control-C.\n");
			}break;
			case CTRL_BREAK_EVENT: //Handle the CTRL-Break signal.
			{
				fwprintf_s(stderr, L"Get Control-Break.\n");
			}break;
			default: //Handle other signals.
			{
				fwprintf_s(stderr, L"Get closing signal.\n");
			}break;
		}
	}

	return FALSE;
}

//Service Main function
size_t WINAPI ServiceMain(
	DWORD argc, 
	LPTSTR *argv)
{
	ServiceStatusHandle = RegisterServiceCtrlHandlerW(SYSTEM_SERVICE_NAME, (LPHANDLER_FUNCTION)ServiceControl);
	if (!ServiceStatusHandle || !UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 0, 1U, UPDATE_SERVICE_TIME))
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
size_t WINAPI ServiceControl(
	const DWORD dwControlCode)
{
	switch(dwControlCode)
	{
		case SERVICE_CONTROL_SHUTDOWN:
		{
			TerminateService();
			return EXIT_SUCCESS;
		}
		case SERVICE_CONTROL_STOP:
		{
			ServiceCurrentStatus = SERVICE_STOP_PENDING;
			UpdateServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, 0, 1U, UPDATE_SERVICE_TIME);
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
BOOL WINAPI ExecuteService(
	void)
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
DWORD WINAPI ServiceProc(
	PVOID lpParameter)
{
	if (!IsServiceRunning || !MonitorInit())
	{
		TerminateService();
		return FALSE;
	}

	TerminateService();
	return EXIT_SUCCESS;
}

//Change status of service
BOOL WINAPI UpdateServiceStatus(
	const DWORD dwCurrentState, 
	const DWORD dwWin32ExitCode, 
	const DWORD dwServiceSpecificExitCode, 
	const DWORD dwCheckPoint, 
	const DWORD dwWaitHint)
{
	SERVICE_STATUS ServiceStatus;
	memset(&ServiceStatus, 0, sizeof(SERVICE_STATUS));
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
		TerminateService();
		return FALSE;
	}

	return TRUE;
}

//Terminate service
void WINAPI TerminateService(
	void)
{
	IsServiceRunning = FALSE;
	SetEvent(ServiceEvent);
	UpdateServiceStatus(SERVICE_STOPPED, NO_ERROR, 0, 0, 0);

	return;
}

//MailSlot of flush DNS cache Monitor
bool __fastcall FlushDNSMailSlotMonitor(
	void)
{
//System security setting
	std::shared_ptr<char> ACL_Buffer(new char[FILE_BUFFER_SIZE]());
	memset(ACL_Buffer.get(), 0, FILE_BUFFER_SIZE);
	SECURITY_ATTRIBUTES SecurityAttributes;
	SECURITY_DESCRIPTOR SecurityDescriptor;
	memset(&SecurityAttributes, 0, sizeof(SECURITY_ATTRIBUTES));
	memset(&SecurityDescriptor, 0, sizeof(SECURITY_DESCRIPTOR));
	PSID SID_Value = nullptr;

	InitializeSecurityDescriptor(&SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
	InitializeAcl((PACL)ACL_Buffer.get(), FILE_BUFFER_SIZE, ACL_REVISION);
	ConvertStringSidToSidW(SID_ADMINISTRATORS_GROUP, &SID_Value);
	AddAccessAllowedAce((PACL)ACL_Buffer.get(), ACL_REVISION, GENERIC_ALL, SID_Value);
	SetSecurityDescriptorDacl(&SecurityDescriptor, true, (PACL)ACL_Buffer.get(), false);
	SecurityAttributes.lpSecurityDescriptor = &SecurityDescriptor;
	SecurityAttributes.bInheritHandle = true;

//Create mailslot.
	HANDLE hSlot = CreateMailslotW(MAILSLOT_NAME, FILE_BUFFER_SIZE - 1U, MAILSLOT_WAIT_FOREVER, &SecurityAttributes);
	if (hSlot == INVALID_HANDLE_VALUE)
	{
		LocalFree(SID_Value);

		PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Create mailslot error", GetLastError(), nullptr, 0);
		return false;
	}

	ACL_Buffer.reset();
	LocalFree(SID_Value);

//Initialization
	std::shared_ptr<wchar_t> lpszBuffer(new wchar_t[FILE_BUFFER_SIZE]());
	wmemset(lpszBuffer.get(), 0, FILE_BUFFER_SIZE);
	DWORD cbMessage = 0;
	BOOL Result = 0;

//MailSlot monitor
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME_NO_DELAY);

	//Reset parameters.
		wmemset(lpszBuffer.get(), 0, FILE_BUFFER_SIZE);
		cbMessage = 0;

	//Read message from mailslot.
		Result = ReadFile(hSlot, lpszBuffer.get(), FILE_BUFFER_SIZE, &cbMessage, nullptr);
		if (Result == FALSE)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_SYSTEM, L"MailSlot read messages error", GetLastError(), nullptr, 0);

			CloseHandle(hSlot);
			return false;
		}
		else if (memcmp(lpszBuffer.get(), MAILSLOT_MESSAGE_FLUSH_DNS, sizeof(wchar_t) * wcslen(MAILSLOT_MESSAGE_FLUSH_DNS)) == 0)
		{
			FlushAllDNSCache();
		}
		else {
			Sleep(LOOP_INTERVAL_TIME_MONITOR);
		}
	}

//Monitor terminated
	CloseHandle(hSlot);
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"MailSlot module Monitor terminated", 0, nullptr, 0);
	return false;
}

//MailSlot of flush DNS cache sender
bool WINAPI FlushDNSMailSlotSender(
	void)
{
//Create mailslot.
	HANDLE hFile = CreateFileW(MAILSLOT_NAME, GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
		fwprintf_s(stderr, L"Create mailslot error, error code is %lu.\n", GetLastError());

		return false;
	}

//Write into mailslot.
	DWORD cbWritten = 0;
	if (!WriteFile(hFile, MAILSLOT_MESSAGE_FLUSH_DNS, (DWORD)(sizeof(wchar_t) * lstrlenW(MAILSLOT_MESSAGE_FLUSH_DNS) + 1U), &cbWritten, nullptr))
	{
		std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
		fwprintf_s(stderr, L"MailSlot write messages error, error code is %lu.\n", GetLastError());

		CloseHandle(hFile);
		return false;
	}

	CloseHandle(hFile);
	std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
	fwprintf_s(stderr, L"Flush DNS cache message was sent successfully.\n");
	return true;
}

#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Flush DNS cache FIFO Monitor
bool FlushDNSFIFOMonitor(
	void)
{
//Initialization
	unlink(FIFO_PATH_NAME);
	std::shared_ptr<char> Buffer(new char[FILE_BUFFER_SIZE]());
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	int FileFIFO = 0;

//Create FIFO and create its notify monitor.
	if (mkfifo(FIFO_PATH_NAME, O_CREAT) == RETURN_ERROR || 
		chmod(FIFO_PATH_NAME, S_IRUSR|S_IWUSR|S_IWGRP|S_IWOTH) == RETURN_ERROR)
	{
		PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Create FIFO error", errno, nullptr, 0);

		unlink(FIFO_PATH_NAME);
		return false;
	}

//FIFO Monitor
	for (;;)
	{
		Sleep(LOOP_INTERVAL_TIME_NO_DELAY);

	//Open FIFO.
		FileFIFO = open(FIFO_PATH_NAME, O_RDONLY, 0);
		if (FileFIFO == RETURN_ERROR)
		{
			PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Create FIFO error", errno, nullptr, 0);

			unlink(FIFO_PATH_NAME);
			return false;
		}

	//Read file data.
		memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
		if (read(FileFIFO, Buffer.get(), FILE_BUFFER_SIZE) >= (SSIZE_T)strlen(FIFO_MESSAGE_FLUSH_DNS) && 
			memcmp(Buffer.get(), FIFO_MESSAGE_FLUSH_DNS, strlen(FIFO_MESSAGE_FLUSH_DNS)) == 0)
				FlushAllDNSCache();

	//Close FIFO.
		close(FileFIFO);
		FileFIFO = 0;
	}

//Monitor terminated
	close(FileFIFO);
	unlink(FIFO_PATH_NAME);
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"FIFO module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Flush DNS cache FIFO sender
bool FlushDNSFIFOSender(
	void)
{
	errno = 0;
	int FileFIFO = open(FIFO_PATH_NAME, O_WRONLY|O_TRUNC|O_NONBLOCK, 0);
	if (FileFIFO > 0 && write(FileFIFO, FIFO_MESSAGE_FLUSH_DNS, strlen(FIFO_MESSAGE_FLUSH_DNS) + 1U) > 0)
	{
		std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
		fwprintf(stderr, L"Flush DNS cache message was sent successfully.\n");
		close(FileFIFO);
	}
	else {
		if (errno > 0)
		{
			std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
			fwprintf(stderr, L"FIFO write messages error, error code is %d.\n", errno);
		}

		return false;
	}

	return true;
}
#endif

//Flush DNS cache
void __fastcall FlushAllDNSCache(
	void)
{
//Flush DNS cache in program.
	std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	DNSCacheList.clear();
	DNSCacheListMutex.unlock();

//Flush DNS cache in system.
	std::lock_guard<std::mutex> ScreenMutex(ScreenLock);

#if defined(PLATFORM_WIN)
	system("ipconfig /flushdns 2>nul"); //All Windows version
	fwprintf_s(stderr, L"\n");
#elif defined(PLATFORM_LINUX)
	#if defined(PLATFORM_OPENWRT)
		system("/etc/init.d/dnsmasq restart 2>/dev/null"); //Dnsmasq manage DNS cache on OpenWrt
	#else
		auto Result = system("service nscd restart 2>/dev/null"); //Name Service Cache Daemon service
		Result = system("service dnsmasq restart 2>/dev/null"); //Dnsmasq service
		Result = system("rndc restart 2>/dev/null"); //Name server control utility of BIND(9.1.3 and older version)
		Result = system("rndc flush 2>/dev/null"); //Name server control utility of BIND(9.2.0 and newer version)
	#endif
#elif defined(PLATFORM_MACX)
//	system("lookupd -flushcache 2>/dev/null"); //Less than Mac OS X Tiger(10.4)
//	system("dscacheutil -flushcache 2>/dev/null"); //Mac OS X Leopard(10.5) and Snow Leopard(10.6)
	system("killall -HUP mDNSResponder 2>/dev/null"); //Mac OS X Lion(10.7), Mountain Lion(10.8) and Mavericks(10.9)
	system("discoveryutil mdnsflushcache 2>/dev/null"); //Mac OS X Yosemite(10.10) and newer version
#endif

	return;
}
