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


#include "PrintLog.h"

//Print message to screen
void PrintToScreen(
	const bool IsInnerLock, 
	const bool IsStandardOut, 
	const wchar_t * const Format, 
	...
)
{
//Initialization
	va_list ArgList;
	va_start(ArgList, Format);

//Print data to screen.
	if (IsInnerLock)
	{
		std::lock_guard<std::mutex> ScreenMutex((*GlobalRunningStatus.ScreenLock));
		if (IsStandardOut)
			vfwprintf_s(stdout, Format, ArgList);
		else 
			vfwprintf_s(stderr, Format, ArgList);
	}
	else {
		if (IsStandardOut)
			vfwprintf_s(stdout, Format, ArgList);
		else 
			vfwprintf_s(stderr, Format, ArgList);
	}

//Variable arguments cleanup
	va_end(ArgList);
	return;
}

//Print more details about error code
void ErrorCodeToMessage(
	const LOG_ERROR_TYPE ErrorType, 
	const ssize_t ErrorCode, 
	std::wstring &Message)
{
//Finish the message when there are no error codes.
	if (ErrorCode == 0)
		return;

//Convert error code to error messages.
	Message.append(L": ");
#if defined(PLATFORM_WIN)
	wchar_t *InnerMessage = nullptr;
	if (FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK, 
		nullptr, 
		static_cast<const DWORD>(ErrorCode), 
		MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), 
		reinterpret_cast<LPWSTR>(&InnerMessage), 
		0, 
		nullptr) == 0)
	{
	//Define error code format.
	#if defined(ENABLE_TLS)
	#if defined(PLATFORM_WIN)
		if (ErrorType == LOG_ERROR_TYPE::TLS)
			Message.append(L"0x%x");
		else 
	#endif
	#endif
		if (ErrorType == LOG_ERROR_TYPE::NOTICE || ErrorType == LOG_ERROR_TYPE::SYSTEM || ErrorType == LOG_ERROR_TYPE::SOCKS || ErrorType == LOG_ERROR_TYPE::HTTP_CONNECT)
			Message.append(L"%u");
		else 
			Message.append(L"%d");

	//Free pointer.
		if (InnerMessage != nullptr)
		{
			LocalFree(InnerMessage);
			InnerMessage = nullptr;
		}
	}
	else {
	//Write error code message.
		Message.append(InnerMessage);
		while (!Message.empty() && Message.back() == ASCII_SPACE)
			Message.pop_back(); //Remove space.
		while (!Message.empty() && Message.back() == ASCII_PERIOD)
			Message.pop_back(); //Remove period.

	//Define error code format.
	#if defined(ENABLE_TLS)
	#if defined(PLATFORM_WIN)
		if (ErrorType == LOG_ERROR_TYPE::TLS)
			Message.append(L"[0x%x]");
		else 
	#endif
	#endif
		if (ErrorType == LOG_ERROR_TYPE::SYSTEM || ErrorType == LOG_ERROR_TYPE::SOCKS || ErrorType == LOG_ERROR_TYPE::HTTP_CONNECT)
			Message.append(L"[%u]");
		else 
			Message.append(L"[%d]");

	//Free pointer.
		LocalFree(InnerMessage);
		InnerMessage = nullptr;
	}
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	std::wstring InnerMessage;
	const auto ErrorMessage = strerror(static_cast<const int>(ErrorCode));
	if (ErrorMessage == nullptr || !MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(ErrorMessage), strnlen(ErrorMessage, ERROR_MESSAGE_MAXSIZE), InnerMessage))
	{
		Message.append(L"%d");
	}
	else {
		Message.append(InnerMessage);
		Message.append(L"[%d]");
	}
#endif

	return;
}

//Print error to log file
bool PrintError(
	const LOG_LEVEL_TYPE ErrorLevel, 
	const LOG_ERROR_TYPE ErrorType, 
	const wchar_t * const Message, 
	const ssize_t ErrorCode, 
	const wchar_t * const FileName, 
	const size_t Line)
{
//Print log level check, parameter check
	if (Message == nullptr || 
		GlobalRunningStatus.IsNeedExit == nullptr || GlobalRunningStatus.IsNeedExit->load() || 
		GlobalConfiguration.PrintLogLevel == LOG_LEVEL_TYPE::LEVEL_0 || ErrorLevel > GlobalConfiguration.PrintLogLevel)
			return false;

//Message check.
	if (wcsnlen_s(Message, ERROR_MESSAGE_MAXSIZE) < ERROR_MESSAGE_MINSIZE)
		return false;

//Match log type.
	std::wstring ErrorMessage;
	switch (ErrorType)
	{
	//Message Notice
		case LOG_ERROR_TYPE::NOTICE:
		{
			ErrorMessage.append(L"[Notice] ");
		}break;
	//System Error
	//About System Error Codes, please visit https://msdn.microsoft.com/en-us/library/windows/desktop/ms681381(v=vs.85).aspx.
		case LOG_ERROR_TYPE::SYSTEM:
		{
			ErrorMessage.append(L"[System Error] ");
		}break;
	//Parameter Error
		case LOG_ERROR_TYPE::PARAMETER:
		{
			ErrorMessage.append(L"[Parameter Error] ");
		}break;
	//IPFilter Error
		case LOG_ERROR_TYPE::IPFILTER:
		{
			ErrorMessage.append(L"[IPFilter Error] ");
		}break;
	//Hosts Error
		case LOG_ERROR_TYPE::HOSTS:
		{
			ErrorMessage.append(L"[Hosts Error] ");
		}break;
	//Network Error
	//About Windows Sockets error codes, please visit https://msdn.microsoft.com/en-us/library/windows/desktop/ms740668(v=vs.85).aspx.
		case LOG_ERROR_TYPE::NETWORK:
		{
		//Block error messages when getting Network Unreachable and Host Unreachable error.
			if ((GlobalConfiguration.PrintLogLevel == LOG_LEVEL_TYPE::LEVEL_1 || 
				GlobalConfiguration.PrintLogLevel == LOG_LEVEL_TYPE::LEVEL_2) && 
				(ErrorCode == WSAENETUNREACH || ErrorCode == WSAEHOSTUNREACH))
					return true;
			else 
				ErrorMessage.append(L"[Network Error] ");
		}break;
	//Npcap or LibPcap Error
	//About Npcap or LibPcap error codes, please visit https://www.winpcap.org/docs/docs_40_2/html/group__wpcapfunc.html.
	#if defined(ENABLE_PCAP)
		case LOG_ERROR_TYPE::PCAP:
		{
		//There are no any error codes or file names to be reported in LOG_ERROR_TYPE::PCAP.
			ErrorMessage.append(L"[Pcap Error] ");
			ErrorMessage.append(Message);
			ErrorMessage.append(L"\n");

			return WriteMessageToStream(ErrorMessage, ErrorCode, Line);
		}break;
	#endif
	//DNSCrypt Error
	#if defined(ENABLE_LIBSODIUM)
		case LOG_ERROR_TYPE::DNSCRYPT:
		{
			ErrorMessage.append(L"[DNSCrypt Error] ");
		}break;
	#endif
	//SOCKS Error
		case LOG_ERROR_TYPE::SOCKS:
		{
			ErrorMessage.append(L"[SOCKS Error] ");
		}break;
	//HTTP CONNECT Error
	//About HTTP status codes, vitis https://en.wikipedia.org/wiki/List_of_HTTP_status_codes.
		case LOG_ERROR_TYPE::HTTP_CONNECT:
		{
			ErrorMessage.append(L"[HTTP CONNECT Error] ");
		}break;
	//TLS Error
	//About SSPI/SChannel error codes, please visit https://msdn.microsoft.com/en-us/library/windows/desktop/aa380499(v=vs.85).aspx and https://msdn.microsoft.com/en-us/library/windows/desktop/dd721886(v=vs.85).aspx.
	//About OpenSSL error codes, please visit https://www.openssl.org/docs/manmaster/man3/ERR_get_error.html.
	#if defined(ENABLE_TLS)
		case LOG_ERROR_TYPE::TLS:
		{
			ErrorMessage.append(L"[TLS Error] ");
		}break;
	#endif
		default:
		{
			return false;
		}
	}

//Add error message, error code details, and line number.
	ErrorMessage.append(Message);
	ErrorCodeToMessage(ErrorType, ErrorCode, ErrorMessage);

//Convert and add file name.
	if (FileName != nullptr)
	{
	//FileName length check
		std::wstring FileNameString(FileName);
		if (FileNameString.empty())
			return false;
		else 
			FileNameString.clear();

	//Add file name.
		FileNameString.append(L" in ");
		FileNameString.append(FileName);

	//Remove double backslash.
	#if defined(PLATFORM_WIN)
		while (FileNameString.find(L"\\\\") != std::wstring::npos)
			FileNameString.erase(FileNameString.find(L"\\\\"), wcslen(L"\\"));
	#endif

	//Add line number.
		if (Line > 0)
			FileNameString.append(L"(Line %u)");

	//Add file name to string.
		ErrorMessage.append(FileNameString);
	}

//Print error log.
	ErrorMessage.append(L".\n");
	return WriteMessageToStream(ErrorMessage, ErrorCode, Line);
}

//Write message to stream
bool WriteMessageToStream(
	const std::wstring &Message, 
	const ssize_t ErrorCode, 
	const size_t Line)
{
//Buffer initialization
	auto MessageBuffer = std::make_unique<wchar_t[]>(ERROR_MESSAGE_MAXSIZE + MEMORY_RESERVED_BYTES);
	memset(MessageBuffer.get(), 0, ERROR_MESSAGE_MAXSIZE + MEMORY_RESERVED_BYTES);

//Get current date and time.
	std::wstring CurrentTimeString;
	if (CurrentTimeString.empty())
	{
	//Get current time.
		const auto TimeValue = time(nullptr);
		tm TimeStructure;
		memset(&TimeStructure, 0, sizeof(TimeStructure));
		if (TimeValue <= 0
		#if defined(PLATFORM_WIN)
			|| localtime_s(&TimeStructure, &TimeValue) != 0
		#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
			|| localtime_r(&TimeValue, &TimeStructure) == nullptr
		#endif
		)
			return false;

	//Convert time structure to string.
		if (swprintf(MessageBuffer.get(), ERROR_MESSAGE_MAXSIZE, L"[%d-%02d-%02d %02d:%02d:%02d] -> ", 
				TimeStructure.tm_year + 1900, 
				TimeStructure.tm_mon + 1, 
				TimeStructure.tm_mday, 
				TimeStructure.tm_hour, 
				TimeStructure.tm_min, 
				TimeStructure.tm_sec) < 0)
		{
			return false;
		}
		else {
			CurrentTimeString.append(MessageBuffer.get());
			memset(MessageBuffer.get(), 0, ERROR_MESSAGE_MAXSIZE + MEMORY_RESERVED_BYTES);
		}
	}
	else {
		return false;
	}

//Get startup time at first printing.
	std::wstring LogStartupTimeString;
	if (GlobalRunningStatus.StartupTime > 0)
	{
	//Copy startup time and reset global value.
		const auto TimeValue = GlobalRunningStatus.StartupTime;
		GlobalRunningStatus.StartupTime = 0;

	//Get log startup time.
		tm TimeStructure;
		memset(&TimeStructure, 0, sizeof(TimeStructure));
	#if defined(PLATFORM_WIN)
		if (localtime_s(&TimeStructure, &TimeValue) != 0)
	#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (localtime_r(&TimeValue, &TimeStructure) == nullptr)
	#endif
			return false;

	//Convert time structure to string.
		if (swprintf(MessageBuffer.get(), ERROR_MESSAGE_MAXSIZE, L"[%d-%02d-%02d %02d:%02d:%02d] -> [Notice] Pcap_DNSProxy started.\n", 
				TimeStructure.tm_year + 1900, 
				TimeStructure.tm_mon + 1, 
				TimeStructure.tm_mday, 
				TimeStructure.tm_hour, 
				TimeStructure.tm_min, 
				TimeStructure.tm_sec) < 0)
		{
					return false;
		}
		else {
			LogStartupTimeString.append(MessageBuffer.get());
			memset(MessageBuffer.get(), 0, ERROR_MESSAGE_MAXSIZE + MEMORY_RESERVED_BYTES);
		}
	}

//Prepare the whole error message.
	std::wstring OutputString(CurrentTimeString);
	if (OutputString.empty())
	{
		return false;
	}
	else {
	//Convert message to string.
		if (Line > 0 && ErrorCode != 0)
		{
			if (swprintf(MessageBuffer.get(), ERROR_MESSAGE_MAXSIZE, Message.c_str(), ErrorCode, Line) < 0)
				return false;
			else 
				OutputString.append(MessageBuffer.get());
		}
		else if (Line > 0)
		{
			if (swprintf(MessageBuffer.get(), ERROR_MESSAGE_MAXSIZE, Message.c_str(), Line) < 0)
				return false;
			else 
				OutputString.append(MessageBuffer.get());
		}
		else if (ErrorCode != 0)
		{
			if (swprintf(MessageBuffer.get(), ERROR_MESSAGE_MAXSIZE, Message.c_str(), ErrorCode) < 0)
				return false;
			else 
				OutputString.append(MessageBuffer.get());
		}
		else {
			OutputString.append(Message);
		}
	}

//Reset buffer pointer.
	MessageBuffer.reset();

//Print to screen.
	if (*GlobalRunningStatus.Path_ErrorLog_WCS == L"stderr" || *GlobalRunningStatus.Path_ErrorLog_WCS == L"stdout"
	#if defined(PLATFORM_WIN)
		|| GlobalRunningStatus.IsConsole
	#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX))
		|| !GlobalRunningStatus.IsDaemon
	#endif
		)
	{
	//Print log startup time first.
		if (!LogStartupTimeString.empty())
		{
			if (*GlobalRunningStatus.Path_ErrorLog_WCS == L"stdout")
				PrintToScreen(true, true, L"%ls", LogStartupTimeString.c_str());
			else 
				PrintToScreen(true, false, L"%ls", LogStartupTimeString.c_str());
		}

	//Print message.
		if (*GlobalRunningStatus.Path_ErrorLog_WCS == L"stdout")
			PrintToScreen(true, true, L"%ls", OutputString.c_str());
		else 
			PrintToScreen(true, false, L"%ls", OutputString.c_str());

	//Print to screen only.
		if (*GlobalRunningStatus.Path_ErrorLog_WCS == L"stderr" || *GlobalRunningStatus.Path_ErrorLog_WCS == L"stdout")
			return true;
	}

//Delete full log file.
	auto IsFileDeleted = false;
	std::lock_guard<std::mutex> ErrorLogMutex(ErrorLogLock);
#if defined(PLATFORM_WIN)
	if (DeleteFullSizeFile(*GlobalRunningStatus.Path_ErrorLog_WCS, GlobalConfiguration.LogMaxSize, &IsFileDeleted) != EXIT_SUCCESS)
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	if (DeleteFullSizeFile(*GlobalRunningStatus.Path_ErrorLog_MBS, GlobalConfiguration.LogMaxSize, &IsFileDeleted) != EXIT_SUCCESS)
#endif
		return false;

//Write to file.
#if defined(PLATFORM_WIN)
	FILE *FileHandle = nullptr;
	if (_wfopen_s(&FileHandle, GlobalRunningStatus.Path_ErrorLog_WCS->c_str(), L"a,ccs=UTF-8") == 0 && FileHandle != nullptr)
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	auto FileHandle = fopen(GlobalRunningStatus.Path_ErrorLog_MBS->c_str(), "a");
	if (FileHandle != nullptr)
#endif
	{
	//Print log startup time first.
		if (!LogStartupTimeString.empty())
			fwprintf_s(FileHandle, L"%ls", LogStartupTimeString.c_str());

	//Print old file removed message.
		if (IsFileDeleted)
			fwprintf_s(FileHandle, L"%ls[Notice] Old log file was removed.\n", CurrentTimeString.c_str());

	//Print main message.
		fwprintf_s(FileHandle, L"%ls", OutputString.c_str());

	//Close file handle.
		fclose(FileHandle);
	}
	else {
		return false;
	}

	return true;
}
