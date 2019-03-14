// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
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
//Security attributes and descriptor initialization
bool SystemSecurityInit(
	const ACL * const ACL_Buffer, 
	SECURITY_ATTRIBUTES &SecurityAttributes, 
	SECURITY_DESCRIPTOR &SecurityDescriptor, 
	PSID &SID_Value)
{
//Initialize security descriptor.
	if (InitializeSecurityDescriptor(
			&SecurityDescriptor, 
			SECURITY_DESCRIPTOR_REVISION) == 0 || 
		InitializeAcl(
			const_cast<ACL *>(ACL_Buffer), 
			FILE_BUFFER_SIZE, 
			ACL_REVISION) == 0 || 
		ConvertStringSidToSidW(
			SID_ADMINISTRATORS_GROUP, 
			&SID_Value) == 0 || 
		AddAccessAllowedAce(
			const_cast<ACL *>(ACL_Buffer), 
			ACL_REVISION, 
			GENERIC_ALL, 
			SID_Value) == 0 || 
		SetSecurityDescriptorDacl(
			&SecurityDescriptor, 
			true, 
			const_cast<ACL *>(ACL_Buffer), 
			false) == 0)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Security attributes and descriptor initialization error", GetLastError(), nullptr, 0);
		if (SID_Value != nullptr)
			LocalFree(SID_Value);

		return false;
	}
	else {
		SecurityAttributes.lpSecurityDescriptor = &SecurityDescriptor;
		SecurityAttributes.bInheritHandle = true;
	}

	return true;
}

//Process already exists check
bool CheckProcessExists(
	void)
{
//System security initialization
	const auto ACL_Buffer = std::make_unique<uint8_t[]>(FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	memset(ACL_Buffer.get(), 0, FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	memset(&GlobalRunningStatus.Initialized_MutexSecurityAttributes, 0, sizeof(GlobalRunningStatus.Initialized_MutexSecurityAttributes));
	memset(&GlobalRunningStatus.Initialized_MutexSecurityDescriptor, 0, sizeof(GlobalRunningStatus.Initialized_MutexSecurityDescriptor));
	PSID SID_Value = nullptr;
	if (!SystemSecurityInit(reinterpret_cast<const ACL *>(ACL_Buffer.get()), GlobalRunningStatus.Initialized_MutexSecurityAttributes, GlobalRunningStatus.Initialized_MutexSecurityDescriptor, SID_Value))
	{
		if (SID_Value != nullptr)
			LocalFree(SID_Value);

		return false;
	}

//Create mutex handle.
	GlobalRunningStatus.Initialized_MutexHandle = CreateMutexW(
		&GlobalRunningStatus.Initialized_MutexSecurityAttributes, 
		FALSE, 
		MUTEX_EXISTS_NAME);
	if (GlobalRunningStatus.Initialized_MutexHandle != nullptr)
	{
		if (GetLastError() == ERROR_ALREADY_EXISTS)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Process already exists error", ERROR_ALREADY_EXISTS, nullptr, 0);
			CloseHandle(
				GlobalRunningStatus.Initialized_MutexHandle);
			GlobalRunningStatus.Initialized_MutexHandle = nullptr;
			if (SID_Value != nullptr)
				LocalFree(SID_Value);

			return false;
		}
	}
	else {
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Process already exists error", GetLastError(), nullptr, 0);
		if (SID_Value != nullptr)
			LocalFree(SID_Value);

		return false;
	}

//Free pointer.
	if (SID_Value != nullptr)
		LocalFree(SID_Value);

	return true;
}

//Catch system signal
BOOL WINAPI SignalHandler(
	const DWORD ControlType)
{
//Set need exit signal.
	GlobalRunningStatus.IsNeedExit = true;

//Print to screen.
	if (GlobalRunningStatus.IsConsole)
	{
		switch (ControlType)
		{
		//Handle the CTRL-C signal.
			case CTRL_C_EVENT:
			{
				PrintToScreen(true, false, L"[Notice] Get Control-C.\n");
			}break;
		//Handle the CTRL-Break signal.
			case CTRL_BREAK_EVENT:
			{
				PrintToScreen(true, false, L"[Notice] Get Control-Break.\n");
			}break;
		//Handle other signals which are all closing signal.
			default:
			{
				PrintToScreen(true, false, L"[Notice] Get closing signal.\n");
			}break;
		}
	}

//Mutex handle cleanup
	if (GlobalRunningStatus.Initialized_MutexHandle != nullptr)
	{
		ReleaseMutex(
			GlobalRunningStatus.Initialized_MutexHandle);
		CloseHandle(
			GlobalRunningStatus.Initialized_MutexHandle);
		GlobalRunningStatus.Initialized_MutexHandle = nullptr;
	}

//WinSock cleanup
	if (GlobalRunningStatus.IsInitialized_WinSock)
	{
		WSACleanup();
		GlobalRunningStatus.IsInitialized_WinSock = false;
	}

//Close all file handles.
	_fcloseall();

//Exit process.
	Sleep(STANDARD_THREAD_TIMEOUT);
	return FALSE;
}

//Service Main function
VOID WINAPI ServiceMain(
	DWORD argc, 
	LPTSTR *argv)
{
//Disable console mode printing.
	GlobalRunningStatus.IsConsole = false;

//Service initialization
	ServiceStatusHandle = RegisterServiceCtrlHandlerExW(
		SYSTEM_SERVICE_NAME, 
		reinterpret_cast<LPHANDLER_FUNCTION_EX>(ServiceControl), 
		nullptr);
	if (ServiceStatusHandle == nullptr)
		return;

//Update service status(Part 1).
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

//Update service status(Part 2).
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

//Update service status.
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
DWORD WINAPI ServiceControl(
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

	UpdateServiceStatus(ServiceCurrentStatus, NO_ERROR, 0, 0, 0);
	return EXIT_SUCCESS;
}

//Start Main process
HANDLE WINAPI ExecuteService(
	void)
{
	DWORD ThreadID = 0;
	const auto ServiceThread = CreateThread(
		nullptr, 
		0, 
		reinterpret_cast<PTHREAD_START_ROUTINE>(ServiceProc), 
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

//Service Main process thread
DWORD WINAPI ServiceProc(
	PVOID ProcParameter)
{
//Start main process.
	if (!IsServiceRunning || 
		!MonitorInit())
	{
		TerminateService();
		return 0;
	}

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

//Mailslot listener of flush domain cache
bool FlushDomainCache_MailslotListener(
	void)
{
//System security initialization
	auto ACL_Buffer = std::make_unique<uint8_t[]>(FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	memset(ACL_Buffer.get(), 0, FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	SECURITY_ATTRIBUTES SecurityAttributes;
	SECURITY_DESCRIPTOR SecurityDescriptor;
	memset(&SecurityAttributes, 0, sizeof(SecurityAttributes));
	memset(&SecurityDescriptor, 0, sizeof(SecurityDescriptor));
	PSID SID_Value = nullptr;
	if (!SystemSecurityInit(reinterpret_cast<const ACL *>(ACL_Buffer.get()), SecurityAttributes, SecurityDescriptor, SID_Value))
	{
		if (SID_Value != nullptr)
			LocalFree(SID_Value);

		return false;
	}

//Create mailslot.
	const auto MailslotHandle = CreateMailslotW(
		FLUSH_DOMAIN_MAILSLOT_NAME, 
		FILE_BUFFER_SIZE - 1U, 
		MAILSLOT_WAIT_FOREVER, 
		&SecurityAttributes);
	if (MailslotHandle == INVALID_HANDLE_VALUE)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Create mailslot error", GetLastError(), nullptr, 0);
		if (SID_Value != nullptr)
			LocalFree(SID_Value);

		return false;
	}
//Free pointer.
	else {
		ACL_Buffer.reset();
		if (SID_Value != nullptr)
			LocalFree(SID_Value);
	}

//Initialization
	const auto Buffer = std::make_unique<wchar_t[]>(FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	wmemset(Buffer.get(), 0, FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	std::vector<std::wstring> MessageList;
	std::vector<std::string> DomainList;
	std::wstring Message;
	std::string DomainString;
	DWORD MessageLength = 0;
	size_t Index = 0;

//Start Mailslot Listener.
	while (!GlobalRunningStatus.IsNeedExit)
	{
	//Reset parameters.
		wmemset(Buffer.get(), 0, FILE_BUFFER_SIZE);
		MessageLength = 0;

	//Read message from mailslot.
		if (ReadFile(
				MailslotHandle, 
				Buffer.get(), 
				FILE_BUFFER_SIZE, 
				&MessageLength, 
				nullptr) == FALSE)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SYSTEM, L"Mailslot read messages error", GetLastError(), nullptr, 0);
			Sleep(Parameter.FileRefreshTime);

			continue;
		}

	//List all messages.
		MessageList.clear();
		Message = Buffer.get();
		if (Message.find(FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL) != Message.rfind(FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL))
		{
			for (Index = 0;Index < Message.length();++Index)
			{
			//Copy first item to list.
				if (Index == 0)
				{
					if (Message.compare(Index, wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL), FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL) == 0)
					{
						MessageList.push_back(FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL);
						Index += wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL) - 1U;
					}
					else {
						PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SYSTEM, L"Mailslot read messages error", GetLastError(), nullptr, 0);
						break;
					}
				}
			//Copy last item to list.
				else if (Index + wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL) >= Message.length())
				{
					MessageList.back().append(Message, Index, Message.length() - Index);
					break;
				}
			//Create a new item.
				else if (Message.compare(Index, wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL), FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL) == 0)
				{
					MessageList.push_back(FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL);
					Index += wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL) - 1U;
				}
			//Copy items to list.
				else {
					MessageList.back().append(1U, Message.at(Index));
				}
			}
		}
		else {
			MessageList.push_back(Message);
		}

	//Read all message.
		for (Index = 0;Index < MessageList.size();++Index)
		{
			if (MessageList.at(Index) == FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL) //Flush all domain cache.
			{
				FlushDomainCache_Main(nullptr);
			}
			else if (MessageList.at(Index).compare(0, wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_SPECIFIC), FLUSH_DOMAIN_MAILSLOT_MESSAGE_SPECIFIC) == 0 && //Flush domain cache.
				MessageList.at(Index).length() > wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_SPECIFIC) + DOMAIN_MINSIZE) //Message length check
			{
				DomainString.clear();

			//Convert to C-Style string.
				if (!WCS_To_MBS_String(MessageList.at(Index).c_str() + wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_SPECIFIC), MessageList.at(Index).length() - wcslen(FLUSH_DOMAIN_MAILSLOT_MESSAGE_SPECIFIC), DomainString))
				{
					PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Convert multiple byte or wide char string error", 0, nullptr, 0);
					continue;
				}

			//List all domain name.
				DomainList.clear();
				if (DomainString.find(ASCII_VERTICAL) != std::string::npos)
				{
				//Add items to list.
					DomainList.push_back("");
					for (const auto StringIter:DomainString)
					{
						if (StringIter == ASCII_VERTICAL)
							DomainList.push_back("");
						else 
							DomainList.back().append(1U, StringIter);
					}

				//Remove last item if it's empty.
					while (!DomainList.empty() && DomainList.back().empty())
						DomainList.pop_back();
				}

			//Flush listed domain cache.
				if (DomainList.empty())
				{
					FlushDomainCache_Main(reinterpret_cast<const uint8_t *>(DomainString.c_str()));
				}
				else {
					for (const auto &StringIter:DomainList)
					{
						if (!StringIter.empty())
							FlushDomainCache_Main(reinterpret_cast<const uint8_t *>(StringIter.c_str()));
					}
				}
			}
			else if (Index + 1U >= MessageList.size())
			{
				Sleep(Parameter.FileRefreshTime);
			}
		}
	}

//Listener terminated
	CloseHandle(
		MailslotHandle);
	if (!GlobalRunningStatus.IsNeedExit)
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Mailslot module listener terminated", 0, nullptr, 0);
	return false;
}

//Mailslot sender of flush domain cache
bool WINAPI FlushDomainCache_MailslotSender(
	const wchar_t * const Domain)
{
//Mailslot initialization
	std::wstring Message(L"[System Error] Create mailslot error");
	const auto FileHandle = CreateFileW(
		FLUSH_DOMAIN_MAILSLOT_NAME, 
		GENERIC_WRITE, 
		FILE_SHARE_READ, 
		nullptr, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		nullptr);
	if (FileHandle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == 0)
		{
			Message.append(L".\n");
			PrintToScreen(true, false, Message.c_str());
		}
		else {
			ErrorCodeToMessage(LOG_ERROR_TYPE::SYSTEM, GetLastError(), Message);
			Message.append(L".\n");
			PrintToScreen(true, false, Message.c_str(), GetLastError());
		}

		return false;
	}

//Message initialization
	Message = FLUSH_DOMAIN_MAILSLOT_MESSAGE_ALL;
	if (Domain != nullptr)
	{
		Message.append(L": ");
		Message.append(Domain);
		if (Message.length() + NULL_TERMINATE_LENGTH >= FILE_BUFFER_SIZE || 
			Message.find(L"||") != std::string::npos)
		{
			PrintToScreen(true, false, L"[System Error] Mailslot write messages error.\n");
			return false;
		}
	}

//Write into mailslot.
	DWORD WrittenBytes = 0;
	if (WriteFile(
			FileHandle, 
			Message.c_str(), 
			static_cast<DWORD>(sizeof(wchar_t) * Message.length() + NULL_TERMINATE_LENGTH), 
			&WrittenBytes, 
			nullptr) == 0)
	{
		CloseHandle(
			FileHandle);
		Message = L"[System Error] Mailslot write messages error";
		if (GetLastError() == 0)
		{
			Message.append(L".\n");
			PrintToScreen(true, false, Message.c_str());
		}
		else {
			ErrorCodeToMessage(LOG_ERROR_TYPE::SYSTEM, GetLastError(), Message);
			Message.append(L".\n");
			PrintToScreen(true, false, Message.c_str(), GetLastError());
		}

		return false;
	}
	else {
		CloseHandle(
			FileHandle);
		PrintToScreen(true, false, L"[Notice] Flush domain cache message was sent successfully.\n");
	}

	return true;
}
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
//Process already exists check
bool CheckProcessExists(
	void)
{
//Open current dectory to make a file mutex handle.
	GlobalRunningStatus.Initialized_MutexHandle = open(GlobalRunningStatus.Path_Global_MBS->front().c_str(), O_RDONLY | O_NONBLOCK);
	if (GlobalRunningStatus.Initialized_MutexHandle == RETURN_ERROR)
	{
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Process already exists error", errno, nullptr, 0);
		return false;
	}

//Set file mutex handle.
	if (flock(GlobalRunningStatus.Initialized_MutexHandle, LOCK_EX | LOCK_NB) == RETURN_ERROR)
	{
		close(GlobalRunningStatus.Initialized_MutexHandle);
		GlobalRunningStatus.Initialized_MutexHandle = RETURN_ERROR;
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Process already exists error", errno, nullptr, 0);

		return false;
	}

	return true;
}

//Handle the system signal.
void SignalHandler(
	const int Signal)
{
//Mutex handle cleanup
	if (GlobalRunningStatus.Initialized_MutexHandle != 0 && GlobalRunningStatus.Initialized_MutexHandle != RETURN_ERROR)
	{
		flock(GlobalRunningStatus.Initialized_MutexHandle, LOCK_UN);
		close(GlobalRunningStatus.Initialized_MutexHandle);
		GlobalRunningStatus.Initialized_MutexHandle = 0;
	}

//Free all OpenSSL libraries.
#if defined(ENABLE_TLS)
	if (GlobalRunningStatus.IsInitialized_OpenSSL)
	{
		OpenSSL_LibraryInit(false);
		GlobalRunningStatus.IsInitialized_OpenSSL = false;
	}
#endif

//Print to screen.
	PrintToScreen(true, false, L"[Notice] Get closing signal.\n");

//Close all file handles.
#if (defined(PLATFORM_FREEBSD) || (defined(PLATFORM_LINUX) && !defined(PLATFORM_OPENWRT)))
	fcloseall();
#endif

//Exit process.
	exit(EXIT_SUCCESS);
	return;
}

//FIFO pipe listener of flush domain cache
bool FlushDomainCache_PipeListener(
	void)
{
//Initialization
	const auto Buffer = std::make_unique<uint8_t[]>(FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	memset(Buffer.get(), 0, FILE_BUFFER_SIZE + MEMORY_RESERVED_BYTES);
	std::vector<std::string> MessageList, DomainList;
	std::string Message, DomainString;
	int PipeHandle = 0;
	ssize_t MessageLength = 0;
	size_t Index = 0;

//Start FIFO pipe Listener.
	while (!GlobalRunningStatus.IsNeedExit)
	{
	//Create FIFO pipe and create its notify listener.
		unlink(FLUSH_DOMAIN_PIPE_PATH_NAME);
		errno = 0;
		if (mkfifo(FLUSH_DOMAIN_PIPE_PATH_NAME, O_CREAT) == RETURN_ERROR || 
			chmod(FLUSH_DOMAIN_PIPE_PATH_NAME, S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH) == RETURN_ERROR)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Create FIFO pipe error", errno, nullptr, 0);
			Sleep(Parameter.FileRefreshTime);

			continue;
		}

	//Open FIFO pipe.
		errno = 0;
		PipeHandle = open(FLUSH_DOMAIN_PIPE_PATH_NAME, O_RDONLY, 0);
		if (PipeHandle == RETURN_ERROR)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"Create FIFO pipe error", errno, nullptr, 0);
			Sleep(Parameter.FileRefreshTime);

			continue;
		}

	//Read file data.
		memset(Buffer.get(), 0, FILE_BUFFER_SIZE);
		errno = 0;
		MessageLength = read(PipeHandle, Buffer.get(), FILE_BUFFER_SIZE);
		if (MessageLength == RETURN_ERROR || 
			MessageLength < static_cast<ssize_t>(strlen(FLUSH_DOMAIN_PIPE_MESSAGE_ALL)) || 
			MessageLength >= static_cast<ssize_t>(FILE_BUFFER_SIZE))
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SYSTEM, L"FIFO pipe read messages error", errno, nullptr, 0);
		}

	//List all messages.
		MessageList.clear();
		Message = reinterpret_cast<const char *>(Buffer.get());
		if (Message.find(FLUSH_DOMAIN_PIPE_MESSAGE_ALL) != Message.rfind(FLUSH_DOMAIN_PIPE_MESSAGE_ALL))
		{
			for (Index = 0;Index < Message.length();++Index)
			{
			//Copy first item to list.
				if (Index == 0)
				{
					if (Message.compare(Index, strlen(FLUSH_DOMAIN_PIPE_MESSAGE_ALL), FLUSH_DOMAIN_PIPE_MESSAGE_ALL) == 0)
					{
						MessageList.push_back(FLUSH_DOMAIN_PIPE_MESSAGE_ALL);
						Index += strlen(FLUSH_DOMAIN_PIPE_MESSAGE_ALL) - 1U;
					}
					else {
						PrintError(LOG_LEVEL_TYPE::LEVEL_3, LOG_ERROR_TYPE::SYSTEM, L"FIFO pipe read messages error", errno, nullptr, 0);
						break;
					}
				}
			//Copy last item to list.
				else if (Index + strlen(FLUSH_DOMAIN_PIPE_MESSAGE_ALL) >= Message.length())
				{
					MessageList.back().append(Message, Index, Message.length() - Index);
					break;
				}
			//Create a new item.
				else if (Message.compare(Index, strlen(FLUSH_DOMAIN_PIPE_MESSAGE_ALL), FLUSH_DOMAIN_PIPE_MESSAGE_ALL) == 0)
				{
					MessageList.push_back(FLUSH_DOMAIN_PIPE_MESSAGE_ALL);
					Index += strlen(FLUSH_DOMAIN_PIPE_MESSAGE_ALL) - 1U;
				}
			//Copy items to list.
				else {
					MessageList.back().append(1U, Message.at(Index));
				}
			}
		}
		else {
			MessageList.push_back(Message);
		}

	//Read all message.
		for (Index = 0;Index < MessageList.size();++Index)
		{
			if (MessageList.at(Index) == FLUSH_DOMAIN_PIPE_MESSAGE_ALL) //Flush all domain cache.
			{
				FlushDomainCache_Main(nullptr);
			}
			else if (MessageList.at(Index).compare(0, strlen(FLUSH_DOMAIN_PIPE_MESSAGE_SPECIFIC), FLUSH_DOMAIN_PIPE_MESSAGE_SPECIFIC) == 0 && //Flush domain cache.
				MessageList.at(Index).length() > strlen(FLUSH_DOMAIN_PIPE_MESSAGE_SPECIFIC) + DOMAIN_MINSIZE) //Message length check
			{
				DomainString.clear();
				DomainString.append(MessageList.at(Index), strlen(FLUSH_DOMAIN_PIPE_MESSAGE_SPECIFIC), MessageList.at(Index).length() - strlen(FLUSH_DOMAIN_PIPE_MESSAGE_SPECIFIC));

			//List all domain name.
				DomainList.clear();
				if (DomainString.find(ASCII_VERTICAL) != std::string::npos)
				{
				//Add items to list.
					DomainList.push_back("");
					for (const auto StringIter:DomainString)
					{
						if (StringIter == ASCII_VERTICAL)
							DomainList.push_back("");
						else 
							DomainList.back().append(1U, StringIter);
					}

				//Remove last item if it's empty.
					while (!DomainList.empty() && DomainList.back().empty())
						DomainList.pop_back();
				}

			//Flush listed domain cache.
				if (DomainList.empty())
				{
					FlushDomainCache_Main(reinterpret_cast<const uint8_t *>(DomainString.c_str()));
				}
				else {
					for (const auto &StringIter:DomainList)
					{
						if (!StringIter.empty())
							FlushDomainCache_Main(reinterpret_cast<const uint8_t *>(StringIter.c_str()));
					}
				}
			}
			else if (Index + 1U >= MessageList.size())
			{
				Sleep(Parameter.FileRefreshTime);
			}
		}

	//Close FIFO pipe.
		close(PipeHandle);
		PipeHandle = 0;
	}

//Listener terminated
	close(PipeHandle);
	unlink(FLUSH_DOMAIN_PIPE_PATH_NAME);
	if (!GlobalRunningStatus.IsNeedExit)
		PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::SYSTEM, L"FIFO pipe module listener terminated", 0, nullptr, 0);
	return true;
}

//Flush domain cache FIFO pipe sender
bool FlushDomainCache_PipeSender(
	const uint8_t * const Domain)
{
//Message initialization
	std::string Message(FLUSH_DOMAIN_PIPE_MESSAGE_ALL);
	if (Domain != nullptr)
	{
		Message.append(": ");
		Message.append(reinterpret_cast<const char *>(Domain));
		if (Message.length() + NULL_TERMINATE_LENGTH >= FILE_BUFFER_SIZE || 
			Message.find("||") != std::string::npos)
		{
			PrintToScreen(true, false, L"[System Error] FIFO pipe write messages error.\n");
			return false;
		}
	}

//Write into FIFO pipe.
	errno = 0;
	const int PipeHandle = open(FLUSH_DOMAIN_PIPE_PATH_NAME, O_WRONLY | O_TRUNC | O_NONBLOCK, 0);
	if (PipeHandle > 0)
	{
		if (write(PipeHandle, Message.c_str(), Message.length() + NULL_TERMINATE_LENGTH) > 0)
		{
			close(PipeHandle);
			PrintToScreen(true, false, L"[Notice] Flush domain cache message was sent successfully.\n");

			return true;
		}
		else {
			close(PipeHandle);
		}
	}

//Print error log.
	std::wstring InnerMessage(L"[System Error] FIFO pipe write messages error");
	if (errno == 0)
	{
		InnerMessage.append(L".\n");
		PrintToScreen(true, false, InnerMessage.c_str());
	}
	else {
		ErrorCodeToMessage(LOG_ERROR_TYPE::SYSTEM, errno, InnerMessage);
		InnerMessage.append(L".\n");
		PrintToScreen(true, false, InnerMessage.c_str(), errno);
	}

	return false;
}
#endif

//Flush domain cache
void FlushDomainCache_Main(
	const uint8_t * const Domain)
{
//Flush domain cache in program.
	std::unique_lock<std::mutex> DNSCacheListMutex(DNSCacheListLock);
	if (Domain == nullptr || //Flush all domain cache.
		strnlen_s(reinterpret_cast<const char *>(Domain), DOMAIN_MAXSIZE + MEMORY_RESERVED_BYTES) >= DOMAIN_MAXSIZE)
	{
	//Remove from cache index list.
		DNSCacheIndexList.clear();

	//Remove from cache data list.
		DNSCacheList.clear();
	}
	else { //Flush single domain cache.
	//Make insensitive domain.
		std::string DomainString(reinterpret_cast<const char *>(Domain));
		CaseConvert(DomainString, false);
		
	//Scan domain cache list.
		if (DNSCacheIndexList.find(DomainString) != DNSCacheIndexList.end())
		{
		//Remove from cache data list.
			const auto CacheMapRange = DNSCacheIndexList.equal_range(DomainString);
			for (auto CacheMapItem = CacheMapRange.DNS_CACHE_INDEX_LIST_DOMAIN;CacheMapItem != CacheMapRange.DNS_CACHE_INDEX_LIST_POINTER;++CacheMapItem)
				DNSCacheList.erase(CacheMapItem->second);

		//Remove from cache index list.
			while (DNSCacheIndexList.find(DomainString) != DNSCacheIndexList.end())
				DNSCacheIndexList.erase(DNSCacheIndexList.find(DomainString));
		}
	}

	DNSCacheListMutex.unlock();

//Flush system domain cache interval time check
#if (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (LastFlushCacheTime == 0 || LastFlushCacheTime >= GetCurrentSystemTime() + FLUSH_DOMAIN_CACHE_INTERVAL_TIME * SECOND_TO_MILLISECOND)
		LastFlushCacheTime = GetCurrentSystemTime();
	else 
		return;
#endif

//Flush domain cache in system.
	std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
#if defined(PLATFORM_WIN)
	system("ipconfig /flushdns 2>nul"); //All Windows version
	fwprintf_s(stderr, L"\n");
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX))
#if defined(PLATFORM_OPENWRT)
	auto ResultValue = system("/etc/init.d/dnsmasq restart 2>/dev/null"); //Dnsmasq manage domain cache on OpenWrt
#else
	auto ResultValue = system("service nscd restart 2>/dev/null"); //Name Service Cache Daemon service
	ResultValue = system("service dnsmasq restart 2>/dev/null"); //Dnsmasq service
	ResultValue = system("rndc restart 2>/dev/null"); //Name server control utility of BIND(9.1.3 and older version)
	ResultValue = system("rndc flush 2>/dev/null"); //Name server control utility of BIND(9.2.0 and later)
#endif
#elif defined(PLATFORM_MACOS)
//	system("lookupd -flushcache 2>/dev/null"); //Less than Mac OS X Tiger(10.4)
//	system("dscacheutil -flushcache 2>/dev/null"); //Mac OS X Leopard(10.5) and Snow Leopard(10.6)
//	system("killall -HUP mDNSResponder 2>/dev/null"); //Mac OS X Lion(10.7), Mountain Lion(10.8) and Mavericks(10.9)
	system("discoveryutil udnsflushcaches 2>/dev/null"); //Mac OS X Yosemite(10.10 - 10.10.3)
	system("discoveryutil mdnsflushcache 2>/dev/null"); //Mac OS X Yosemite(10.10 - 10.10.3)
	system("dscacheutil -flushcache 2>/dev/null"); //Mac OS X Yosemite(10.10.4 - 10.10.5)
	system("killall -HUP mDNSResponder 2>/dev/null"); //Mac OS X El Capitan(10.11) and later
#endif

	return;
}
