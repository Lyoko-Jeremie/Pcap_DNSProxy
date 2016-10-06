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
//Catch Control-C exception from keyboard
BOOL WINAPI CtrlHandler(
	const DWORD fdwCtrlType)
{
//Print to screen.
	if (GlobalRunningStatus.IsConsole)
	{
		switch (fdwCtrlType)
		{
		//Handle the CTRL-C signal.
			case CTRL_C_EVENT:
			{
				PrintToScreen(true, L"[Notice] Get Control-C.\n");
			}break;
		//Handle the CTRL-Break signal.
			case CTRL_BREAK_EVENT:
			{
				PrintToScreen(true, L"[Notice] Get Control-Break.\n");
			}break;
		//Handle other signals.
			default:
			{
				PrintToScreen(true, L"[Notice] Get closing signal.\n");
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
//Disable console mode printing.
	GlobalRunningStatus.IsConsole = false;

//Service initialization
	ServiceStatusHandle = RegisterServiceCtrlHandlerW(
		SYSTEM_SERVICE_NAME, 
		(LPHANDLER_FUNCTION)ServiceControl);
	if (!ServiceStatusHandle || UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 0, 1U, UPDATE_SERVICE_TIME) == FALSE)
		return FALSE;

	ServiceEvent = CreateEventW(
		0, 
		TRUE, 
		FALSE, 
		0);
	if (!ServiceEvent || UpdateServiceStatus(SERVICE_START_PENDING, NO_ERROR, 0, 2U, STANDARD_TIMEOUT) == FALSE || ExecuteService() == FALSE)
		return FALSE;

	ServiceCurrentStatus = SERVICE_RUNNING;
	if (UpdateServiceStatus(SERVICE_RUNNING, NO_ERROR, 0, 0, 0) == FALSE)
		return FALSE;

	WaitForSingleObject(
		ServiceEvent, 
		INFINITE);
	CloseHandle(
		ServiceEvent);
	return EXIT_SUCCESS;
}

//Service controller
size_t WINAPI ServiceControl(
	const DWORD dwControlCode)
{
	switch(dwControlCode)
	{
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

	UpdateServiceStatus(ServiceCurrentStatus, NO_ERROR, 0, 0, 0);
	return EXIT_SUCCESS;
}

//Start Main process
BOOL WINAPI ExecuteService(
	void)
{
	DWORD dwThreadID = 0;
	HANDLE hServiceThread = CreateThread(
		0, 
		0, 
		(PTHREAD_START_ROUTINE)ServiceProc, 
		nullptr, 
		0, 
		&dwThreadID);
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
//Start main process.
	if (IsServiceRunning == FALSE || !MonitorInit())
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
	memset(&ServiceStatus, 0, sizeof(ServiceStatus));
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

	if (SetServiceStatus(
			ServiceStatusHandle, 
			&ServiceStatus) == 0)
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

//Mailslot of flush DNS cache Monitor
bool FlushDNSMailSlotMonitor(
	void)
{
//System security initialization
	std::shared_ptr<uint8_t> ACL_Buffer(new uint8_t[FILE_BUFFER_SIZE]());
	memset(ACL_Buffer.get(), 0, FILE_BUFFER_SIZE);
	SECURITY_ATTRIBUTES SecurityAttributes;
	SECURITY_DESCRIPTOR SecurityDescriptor;
	memset(&SecurityAttributes, 0, sizeof(SecurityAttributes));
	memset(&SecurityDescriptor, 0, sizeof(SecurityDescriptor));
	PSID SID_Value = nullptr;

//System security setting
	if (InitializeSecurityDescriptor(
			&SecurityDescriptor, 
			SECURITY_DESCRIPTOR_REVISION) == 0 || 
		InitializeAcl(
			(PACL)ACL_Buffer.get(), 
			FILE_BUFFER_SIZE, 
			ACL_REVISION) == 0 || 
		ConvertStringSidToSidW(
			SID_ADMINISTRATORS_GROUP, 
			&SID_Value) == 0 || 
		AddAccessAllowedAce(
			(PACL)ACL_Buffer.get(), 
			ACL_REVISION, 
			GENERIC_ALL, 
			SID_Value) == 0 || 
		SetSecurityDescriptorDacl(
			&SecurityDescriptor, 
			true, 
			(PACL)ACL_Buffer.get(), 
			false) == 0)
	{
		if (SID_Value != nullptr)
			LocalFree(SID_Value);

		PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Create mailslot error", GetLastError(), nullptr, 0);
		return false;
	}
	SecurityAttributes.lpSecurityDescriptor = &SecurityDescriptor;
	SecurityAttributes.bInheritHandle = true;

//Create mailslot.
	HANDLE hSlot = CreateMailslotW(
		MAILSLOT_NAME, FILE_BUFFER_SIZE - 1U, 
		MAILSLOT_WAIT_FOREVER, 
		&SecurityAttributes);
	if (hSlot == INVALID_HANDLE_VALUE)
	{
		if (SID_Value != nullptr)
			LocalFree(SID_Value);

		PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Create mailslot error", GetLastError(), nullptr, 0);
		return false;
	}

	ACL_Buffer.reset();
	LocalFree(
		SID_Value);

//Initialization
	std::shared_ptr<wchar_t> lpszBuffer(new wchar_t[FILE_BUFFER_SIZE]());
	wmemset(lpszBuffer.get(), 0, FILE_BUFFER_SIZE);
	std::wstring Message;
	std::string Domain; 
	DWORD cbMessage = 0;
	BOOL Result = 0;

//Mailslot monitor
	for (;;)
	{
	//Reset parameters.
		wmemset(lpszBuffer.get(), 0, FILE_BUFFER_SIZE);
		cbMessage = 0;

	//Read message from mailslot.
		Result = ReadFile(
			hSlot, 
			lpszBuffer.get(), 
			FILE_BUFFER_SIZE, 
			&cbMessage, 
			nullptr);
		if (Result == FALSE)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_SYSTEM, L"Mailslot read messages error", GetLastError(), nullptr, 0);

			CloseHandle(hSlot);
			return false;
		}
		else {
			Message = lpszBuffer.get();
			Domain.clear();

		//Read message.
			if (Message == MAILSLOT_MESSAGE_FLUSH_DNS) //Flush all DNS cache.
			{
				FlushDNSCache(nullptr);
			}
			else if (Message.find(MAILSLOT_MESSAGE_FLUSH_DNS_DOMAIN) == 0 && //Flush single domain cache.
				Message.length() > wcslen(MAILSLOT_MESSAGE_FLUSH_DNS_DOMAIN) + DOMAIN_MINSIZE && //Domain length check
				Message.length() < wcslen(MAILSLOT_MESSAGE_FLUSH_DNS_DOMAIN) + DOMAIN_MAXSIZE)
			{
				if (WCSToMBSString(Message.c_str() + wcslen(MAILSLOT_MESSAGE_FLUSH_DNS_DOMAIN), DOMAIN_MAXSIZE, Domain) && 
					Domain.length() > DOMAIN_MINSIZE && Domain.length() < DOMAIN_MAXSIZE)
						FlushDNSCache((const uint8_t *)Domain.c_str());
				else 
					PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);
			}
			else {
				Sleep(Parameter.FileRefreshTime);
			}
		}
	}

//Monitor terminated
	CloseHandle(hSlot);
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Mailslot module Monitor terminated", 0, nullptr, 0);
	return false;
}

//Mailslot of flush DNS cache sender
bool WINAPI FlushDNSMailSlotSender(
	const wchar_t *Domain)
{
//Mailslot initialization
	HANDLE hFile = CreateFileW(
		MAILSLOT_NAME, 
		GENERIC_WRITE, 
		FILE_SHARE_READ, 
		nullptr, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		std::wstring InnerMessage(L"[System Error] Create mailslot error");
		if (GetLastError() == 0)
		{
			InnerMessage.append(L".\n");
			PrintToScreen(true, InnerMessage.c_str());
		}
		else {
			ErrorCodeToMessage(GetLastError(), InnerMessage);
			InnerMessage.append(L".\n");
			PrintToScreen(true, InnerMessage.c_str(), GetLastError());
		}

		return false;
	}

//Message initialization
	std::wstring Message(MAILSLOT_MESSAGE_FLUSH_DNS);
	if (Domain != nullptr)
	{
		Message.append(L": ");
		Message.append(Domain);
	}

//Write into mailslot.
	DWORD cbWritten = 0;
	if (WriteFile(
			hFile, 
			Message.c_str(), 
			(DWORD)(sizeof(wchar_t) * Message.length() + 1U), 
			&cbWritten, 
			nullptr) == 0)
	{
		CloseHandle(hFile);
		std::wstring InnerMessage(L"[System Error] Mailslot write messages error");
		if (GetLastError() == 0)
		{
			InnerMessage.append(L".\n");
			PrintToScreen(true, InnerMessage.c_str());
		}
		else {
			ErrorCodeToMessage(GetLastError(), InnerMessage);
			InnerMessage.append(L".\n");
			PrintToScreen(true, InnerMessage.c_str(), GetLastError());
		}

		return false;
	}
	else {
		CloseHandle(hFile);
		PrintToScreen(true, L"[Notice] Flush DNS cache message was sent successfully.\n");
	}

	return true;
}

#elif (defined(PLATFORM_LINUX) || defined(PLATFORM_MACX))
//Flush DNS cache FIFO Monitor
bool FlushDNSFIFOMonitor(
	void)
{
//Initialization
	std::shared_ptr<uint8_t> Buffer(new uint8_t[FILE_BUFFER_SIZE]());
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
	std::string Message;
	int FIFO_Handle = 0;
	ssize_t Length = 0;

//FIFO Monitor
	for (;;)
	{
	//Create FIFO and create its notify monitor.
		unlink(FIFO_PATH_NAME);
		errno = 0;
		if (mkfifo(FIFO_PATH_NAME, O_CREAT) == RETURN_ERROR || 
			chmod(FIFO_PATH_NAME, S_IRUSR|S_IWUSR|S_IWGRP|S_IWOTH) == RETURN_ERROR)
		{
			PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Create FIFO error", errno, nullptr, 0);

			unlink(FIFO_PATH_NAME);
			return false;
		}

	//Open FIFO.
		errno = 0;
		FIFO_Handle = open(FIFO_PATH_NAME, O_RDONLY, 0);
		if (FIFO_Handle == RETURN_ERROR)
		{
			PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"Create FIFO error", errno, nullptr, 0);

			unlink(FIFO_PATH_NAME);
			return false;
		}

	//Read file data.
		errno = 0;
		memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
		Length = read(FIFO_Handle, Buffer.get(), FILE_BUFFER_SIZE);
		if (Length == RETURN_ERROR || Length < (ssize_t)DOMAIN_MINSIZE || Length > (ssize_t)DOMAIN_MAXSIZE)
		{
			PrintError(LOG_LEVEL_3, LOG_ERROR_SYSTEM, L"FIFO read messages error", errno, nullptr, 0);
		}
		else {
			Message = (const char *)Buffer.get();

		//Read message.
			if (Message == FIFO_MESSAGE_FLUSH_DNS) //Flush all DNS cache.
				FlushDNSCache(nullptr);
			else if (Message.find(FIFO_MESSAGE_FLUSH_DNS_DOMAIN) == 0 && //Flush single domain cache.
				Message.length() > strlen(FIFO_MESSAGE_FLUSH_DNS_DOMAIN) + DOMAIN_MINSIZE && //Domain length check
				Message.length() < strlen(FIFO_MESSAGE_FLUSH_DNS_DOMAIN) + DOMAIN_MAXSIZE)
					FlushDNSCache((const uint8_t *)Message.c_str() + strlen(FIFO_MESSAGE_FLUSH_DNS_DOMAIN));
			else 
				Sleep(Parameter.FileRefreshTime);
		}

	//Close FIFO.
		close(FIFO_Handle);
		FIFO_Handle = 0;
	}

//Monitor terminated
	close(FIFO_Handle);
	unlink(FIFO_PATH_NAME);
	PrintError(LOG_LEVEL_2, LOG_ERROR_SYSTEM, L"FIFO module Monitor terminated", 0, nullptr, 0);
	return true;
}

//Flush DNS cache FIFO sender
bool FlushDNSFIFOSender(
	const uint8_t *Domain)
{
//Message initialization
	std::string Message(FIFO_MESSAGE_FLUSH_DNS);
	if (Domain != nullptr)
	{
		Message.append(": ");
		Message.append((const char *)Domain);
	}

//Write into FIFO file.
	errno = 0;
	int FIFO_Handle = open(FIFO_PATH_NAME, O_WRONLY|O_TRUNC|O_NONBLOCK, 0);
	if (FIFO_Handle > 0)
	{
		if (write(FIFO_Handle, Message.c_str(), Message.length() + 1U) > 0)
		{
			close(FIFO_Handle);
			PrintToScreen(true, L"[Notice] Flush DNS cache message was sent successfully.\n");

			return true;
		}
		else {
			close(FIFO_Handle);
		}
	}

//Print error log.
	std::wstring InnerMessage(L"[System Error] FIFO write messages error");
	if (errno == 0)
	{
		InnerMessage.append(L".\n");
		PrintToScreen(true, InnerMessage.c_str());
	}
	else {
		ErrorCodeToMessage(errno, InnerMessage);
		InnerMessage.append(L".\n");
		PrintToScreen(true, InnerMessage.c_str(), errno);
	}

	return false;
}
#endif

//Flush DNS cache
void FlushDNSCache(
	const uint8_t *Domain)
{
//Flush DNS cache in process.
	std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	if (Domain == nullptr) //Flush all DNS cache.
	{
		DNSCacheList.clear();
	}
//Flush single domain cache.
	else {
		for (auto DNSCacheDataIter = DNSCacheList.begin();DNSCacheDataIter != DNSCacheList.end();)
		{
			if (DNSCacheDataIter->Domain == (const char *)Domain)
				DNSCacheDataIter = DNSCacheList.erase(DNSCacheDataIter);
			else 
				++DNSCacheDataIter;
		}
	}
	DNSCacheListMutex.unlock();

//Flush system DNS interval time check
	if (LastFlushDNSTime > 0 && LastFlushDNSTime < GetCurrentSystemTime() + FLUSH_DNS_CACHE_INTERVAL_TIME * SECOND_TO_MILLISECOND)
		return;
	else 
		LastFlushDNSTime = GetCurrentSystemTime();

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
