// This code is part of Pcap_DNSProxy
// Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
// Copyright (C) 2012-2018 Chengr28
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

//Print errors to log file
bool PrintError(
	const LOG_LEVEL_TYPE ErrorLevel, 
	const LOG_ERROR_TYPE ErrorType, 
	const wchar_t * const Message, 
	const ssize_t ErrorCode, 
	const wchar_t * const FileName, 
	const size_t Line)
{
//Print log level check, parameter check, message check and file name check
	if (Parameter.PrintLogLevel == LOG_LEVEL_TYPE::LEVEL_0 || Message == nullptr || ErrorLevel > Parameter.PrintLogLevel)
		return false;
	std::wstring ErrorMessage(Message);
	if (ErrorMessage.length() >= ERROR_MESSAGE_MINSIZE)
		ErrorMessage.clear();
	else 
		return false;

//Log type
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
			if ((Parameter.PrintLogLevel == LOG_LEVEL_TYPE::LEVEL_1 || Parameter.PrintLogLevel == LOG_LEVEL_TYPE::LEVEL_2) && 
				(ErrorCode == WSAENETUNREACH || ErrorCode == WSAEHOSTUNREACH))
					return true;
			else 
				ErrorMessage.append(L"[Network Error] ");
		}break;
	//WinPcap and LibPcap Error
	//About WinPcap/LibPcap error codes, please visit https://www.winpcap.org/docs/docs_40_2/html/group__wpcapfunc.html.
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
	//DNSCurve Error
	#if defined(ENABLE_LIBSODIUM)
		case LOG_ERROR_TYPE::DNSCURVE:
		{
			ErrorMessage.append(L"[DNSCurve Error] ");
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
	#if defined(PLATFORM_WIN)
		if (TimeValue <= 0 || localtime_s(&TimeStructure, &TimeValue) != 0)
	#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
		if (TimeValue <= 0 || localtime_r(&TimeValue, &TimeStructure) == nullptr)
	#endif
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
	if (*GlobalRunningStatus.Path_ErrorLog == L"stderr" || *GlobalRunningStatus.Path_ErrorLog == L"stdout"
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
			if (*GlobalRunningStatus.Path_ErrorLog == L"stdout")
				PrintToScreen(true, true, L"%ls", LogStartupTimeString.c_str());
			else 
				PrintToScreen(true, false, L"%ls", LogStartupTimeString.c_str());
		}

	//Print message.
		if (*GlobalRunningStatus.Path_ErrorLog == L"stdout")
			PrintToScreen(true, true, L"%ls", OutputString.c_str());
		else 
			PrintToScreen(true, false, L"%ls", OutputString.c_str());

	//Print to screen only.
		if (*GlobalRunningStatus.Path_ErrorLog == L"stderr" || *GlobalRunningStatus.Path_ErrorLog == L"stdout")
			return true;
	}

//Check whole file size.
	auto IsFileDeleted = false;
#if defined(PLATFORM_WIN)
	WIN32_FILE_ATTRIBUTE_DATA FileAttributeData;
	memset(&FileAttributeData, 0, sizeof(FileAttributeData));
	std::lock_guard<std::mutex> ErrorLogMutex(ErrorLogLock);
	if (GetFileAttributesExW(
		GlobalRunningStatus.Path_ErrorLog->c_str(), 
		GetFileExInfoStandard, 
		&FileAttributeData) != 0)
	{
		LARGE_INTEGER ErrorFileSize;
		memset(&ErrorFileSize, 0, sizeof(ErrorFileSize));
		ErrorFileSize.HighPart = FileAttributeData.nFileSizeHigh;
		ErrorFileSize.LowPart = FileAttributeData.nFileSizeLow;
		if (ErrorFileSize.QuadPart > 0 && static_cast<const uint64_t>(ErrorFileSize.QuadPart) >= Parameter.LogMaxSize)
		{
			if (DeleteFileW(
				GlobalRunningStatus.Path_ErrorLog->c_str()) != 0)
					IsFileDeleted = true;
			else 
				return false;
		}
	}
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	struct stat FileStatData;
	memset(&FileStatData, 0, sizeof(FileStatData));
	std::lock_guard<std::mutex> ErrorLogMutex(ErrorLogLock);
	if (stat(GlobalRunningStatus.Path_ErrorLog_MBS->c_str(), &FileStatData) == 0 && FileStatData.st_size >= static_cast<const off_t>(Parameter.LogMaxSize))
	{
		if (remove(GlobalRunningStatus.Path_ErrorLog_MBS->c_str()) == 0)
			IsFileDeleted = true;
		else 
			return false;
	}
#endif

//Write to file.
#if defined(PLATFORM_WIN)
	FILE *FileHandle = nullptr;
	if (_wfopen_s(&FileHandle, GlobalRunningStatus.Path_ErrorLog->c_str(), L"a,ccs=UTF-8") == 0 && FileHandle != nullptr)
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

//Print words to screen
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
		std::lock_guard<std::mutex> ScreenMutex(ScreenLock);
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
	else 
		Message.append(L": ");

//Convert error code to error messages.
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
			LocalFree(InnerMessage);
	}
	else {
	//Write error code message.
		Message.append(InnerMessage);
		if (Message.back() == ASCII_SPACE)
			Message.pop_back(); //Remove space.
		if (Message.back() == ASCII_PERIOD)
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
	}
#elif (defined(PLATFORM_FREEBSD) || defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS))
	std::wstring InnerMessage;
	const auto ErrorMessage = strerror(static_cast<const int>(ErrorCode));
	if (ErrorMessage == nullptr || !MBS_To_WCS_String(reinterpret_cast<const uint8_t *>(ErrorMessage), strnlen(ErrorMessage, FILE_BUFFER_SIZE), InnerMessage))
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

//Print error of reading text
void PrintLog_ReadText(
	const READ_TEXT_TYPE InputType, 
	const size_t FileIndex, 
	const size_t Line)
{
	switch (InputType)
	{
		case READ_TEXT_TYPE::HOSTS: //ReadHosts
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::HOSTS, L"Data of a line is too short", 0, FileList_Hosts.at(FileIndex).FileName.c_str(), Line);
		}break;
		case READ_TEXT_TYPE::IPFILTER: //ReadIPFilter
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::IPFILTER, L"Data of a line is too short", 0, FileList_IPFilter.at(FileIndex).FileName.c_str(), Line);
		}break;
		case READ_TEXT_TYPE::PARAMETER_NORMAL: //ReadParameter
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::PARAMETER, L"Data of a line is too short", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		}break;
		case READ_TEXT_TYPE::PARAMETER_MONITOR: //ReadParameter(Monitor mode)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::PARAMETER, L"Data of a line is too short", 0, FileList_Config.at(FileIndex).FileName.c_str(), Line);
		}break;
	#if defined(ENABLE_LIBSODIUM)
		case READ_TEXT_TYPE::DNSCURVE_DATABASE: //ReadDNSCurveDatabase
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::DNSCURVE, L"Data of a line is too short", 0, FileList_DNSCurveDatabase.at(FileIndex).FileName.c_str(), Line);
		}break;
		case READ_TEXT_TYPE::DNSCURVE_MONITOR: //ReadDNSCurveDatabase(Monitor mode)
		{
			PrintError(LOG_LEVEL_TYPE::LEVEL_2, LOG_ERROR_TYPE::DNSCURVE, L"Data of a line is too short", 0, FileList_DNSCurveDatabase.at(FileIndex).FileName.c_str(), Line);
		}break;
	#endif
	}

	return;
}

//Print error of HTTP CONNECT
void PrintLog_HTTP_CONNECT_2(
	const uint32_t ErrorCode, 
	std::wstring &Message)
{
	switch (ErrorCode)
	{
		case HTTP_2_ERROR_NO_ERROR:
		{
			Message.append(L": NO_ERROR");
		}break;
		case HTTP_2_ERROR_PROTOCOL_ERROR:
		{
			Message.append(L": PROTOCOL_ERROR");
		}break;
		case HTTP_2_ERROR_INTERNAL_ERROR:
		{
			Message.append(L": INTERNAL_ERROR");
		}break;
		case HTTP_2_ERROR_FLOW_CONTROL_ERROR:
		{
			Message.append(L": FLOW_CONTROL_ERROR");
		}break;
		case HTTP_2_ERROR_SETTINGS_TIMEOUT:
		{
			Message.append(L": SETTINGS_TIMEOUT");
		}break;
		case HTTP_2_ERROR_STREAM_CLOSED:
		{
			Message.append(L": STREAM_CLOSED");
		}break;
		case HTTP_2_ERROR_FRAME_SIZE_ERROR:
		{
			Message.append(L": FRAME_SIZE_ERROR");
		}break;
		case HTTP_2_ERROR_REFUSED_STREAM:
		{
			Message.append(L": REFUSED_STREAM");
		}break;
		case HTTP_2_ERROR_CANCEL:
		{
			Message.append(L": CANCEL");
		}break;
		case HTTP_2_ERROR_COMPRESSION_ERROR:
		{
			Message.append(L": COMPRESSION_ERROR");
		}break;
		case HTTP_2_ERROR_CONNECT_ERROR:
		{
			Message.append(L": CONNECT_ERROR");
		}break;
		case HTTP_2_ERROR_ENHANCE_YOUR_CALM:
		{
			Message.append(L": ENHANCE_YOUR_CALM");
		}break;
		case HTTP_2_ERROR_INADEQUATE_SECURITY:
		{
			Message.append(L": INADEQUATE_SECURITY");
		}break;
		case HTTP_2_ERROR_HTTP_1_1_REQUIRED:
		{
			Message.append(L": HTTP_1_1_REQUIRED");
		}break;
		default:
		{
			Message.append(L": UNKNOWN_ERROR");
		}
	}

	return;
}

#if defined(ENABLE_LIBSODIUM)
//DNSCurve print error of servers
void PrintLog_DNSCurve(
	const DNSCURVE_SERVER_TYPE ServerType, 
	std::wstring &Message)
{
	switch (ServerType)
	{
		case DNSCURVE_SERVER_TYPE::MAIN_IPV6:
		{
			Message = L"IPv6 Main Server ";
		}break;
		case DNSCURVE_SERVER_TYPE::ALTERNATE_IPV6:
		{
			Message = L"IPv6 Alternate Server ";
		}break;
		case DNSCURVE_SERVER_TYPE::MAIN_IPV4:
		{
			Message = L"IPv4 Main Server ";
		}break;
		case DNSCURVE_SERVER_TYPE::ALTERNATE_IPV4:
		{
			Message = L"IPv4 Alternate Server ";
		}break;
		default:
		{
			Message.clear();
		}
	}

	return;
}
#endif
